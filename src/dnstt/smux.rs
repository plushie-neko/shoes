use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

#[allow(dead_code)]
pub const SMUX_VERSION_1: u8 = 1;
pub const SMUX_VERSION_2: u8 = 2;

pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;
pub const CMD_UPD: u8 = 4;

pub const HEADER_SIZE: usize = 8;
pub const DEFAULT_MAX_FRAME_SIZE: usize = 32768;
pub const INITIAL_PEER_WINDOW: u32 = 262144; // 256KB
pub const MAX_STREAM_BUFFER: u32 = 1024 * 1024; // 1MB
pub const WINDOW_UPDATE_THRESHOLD: u32 = 262144; // 256KB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmuxHeader {
    pub version: u8,
    pub cmd: u8,
    pub length: u16,
    pub stream_id: u32,
}

impl SmuxHeader {
    pub fn new(cmd: u8, stream_id: u32, length: u16) -> Self {
        Self {
            version: SMUX_VERSION_2,
            cmd,
            length,
            stream_id,
        }
    }

    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u8(self.version);
        out.put_u8(self.cmd);
        out.put_u16_le(self.length);
        out.put_u32_le(self.stream_id);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        let version = buf[0];
        let cmd = buf[1];
        let length = u16::from_le_bytes([buf[2], buf[3]]);
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(Self {
            version,
            cmd,
            length,
            stream_id,
        })
    }
}

pub struct Frame {
    pub header: SmuxHeader,
    pub data: Option<Bytes>,
}

pub struct StreamState {
    pub recv_tx: mpsc::Sender<Bytes>,
    pub num_read: AtomicU32,
    pub incr: AtomicU32,
    pub num_written: AtomicU32,
    pub peer_consumed: AtomicU32,
    pub peer_window: AtomicU32,
    pub write_waker: Mutex<Option<std::task::Waker>>,
}

pub struct SmuxSession {
    next_stream_id: AtomicU32,
    frame_tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u32, Arc<StreamState>>>>,
    closed: Arc<AtomicBool>,
}

impl SmuxSession {
    /// Starts a client Smux session over the underlying transport.
    pub fn client<T>(transport: T) -> Arc<Self>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(transport);
        let (frame_tx, frame_rx) = mpsc::channel::<Frame>(512);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        let session = Arc::new(Self {
            next_stream_id: AtomicU32::new(1), // Client uses odd stream IDs (1, 3, 5, ...)
            frame_tx: frame_tx.clone(),
            streams: streams.clone(),
            closed: closed.clone(),
        });

        // Spawn write loop
        tokio::spawn(Self::write_loop(writer, frame_rx, closed.clone()));

        // Spawn read loop
        tokio::spawn(Self::read_loop(reader, streams, frame_tx, closed.clone()));

        session
    }

    /// Opens a new logical multiplexed stream.
    pub async fn open_stream(&self) -> io::Result<SmuxStream> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "Smux session is closed",
            ));
        }

        let stream_id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let (recv_tx, recv_rx) = mpsc::channel(128);

        let state = Arc::new(StreamState {
            recv_tx,
            num_read: AtomicU32::new(0),
            incr: AtomicU32::new(0),
            num_written: AtomicU32::new(0),
            peer_consumed: AtomicU32::new(0),
            peer_window: AtomicU32::new(INITIAL_PEER_WINDOW),
            write_waker: Mutex::new(None),
        });

        {
            let mut streams = self.streams.lock();
            streams.insert(stream_id, state.clone());
        }

        // Send SYN frame
        let syn_frame = Frame {
            header: SmuxHeader::new(CMD_SYN, stream_id, 0),
            data: None,
        };

        if self.frame_tx.send(syn_frame).await.is_err() {
            let mut streams = self.streams.lock();
            streams.remove(&stream_id);
            return Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "Failed to send SYN frame",
            ));
        }

        Ok(SmuxStream {
            stream_id,
            frame_tx: self.frame_tx.clone(),
            recv_rx,
            current_chunk: None,
            state,
            streams: self.streams.clone(),
            closed: AtomicBool::new(false),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let mut streams = self.streams.lock();
        streams.clear();
    }

    async fn write_loop<W>(
        mut writer: W,
        mut frame_rx: mpsc::Receiver<Frame>,
        closed: Arc<AtomicBool>,
    ) where
        W: AsyncWrite + Unpin,
    {
        let mut encode_buf = BytesMut::with_capacity(DEFAULT_MAX_FRAME_SIZE + HEADER_SIZE);

        while let Some(frame) = frame_rx.recv().await {
            encode_buf.clear();
            frame.header.encode(&mut encode_buf);

            if let Err(e) = writer.write_all(&encode_buf).await {
                log::debug!("Smux write_loop header error: {}", e);
                break;
            }

            if let Some(data) = frame.data {
                if let Err(e) = writer.write_all(&data).await {
                    log::debug!("Smux write_loop data error: {}", e);
                    break;
                }
            }

            if let Err(e) = writer.flush().await {
                log::debug!("Smux write_loop flush error: {}", e);
                break;
            }
        }

        closed.store(true, Ordering::Relaxed);
    }

    async fn read_loop<R>(
        mut reader: R,
        streams: Arc<Mutex<HashMap<u32, Arc<StreamState>>>>,
        _frame_tx: mpsc::Sender<Frame>,
        closed: Arc<AtomicBool>,
    ) where
        R: AsyncRead + Unpin,
    {
        let mut header_buf = [0u8; HEADER_SIZE];

        loop {
            if let Err(_) = reader.read_exact(&mut header_buf).await {
                break;
            }

            let header = match SmuxHeader::decode(&header_buf) {
                Some(h) => h,
                None => break,
            };

            let data = if header.length > 0 {
                let mut data_buf = vec![0u8; header.length as usize];
                if let Err(_) = reader.read_exact(&mut data_buf).await {
                    break;
                }
                Some(Bytes::from(data_buf))
            } else {
                None
            };

            match header.cmd {
                CMD_PSH => {
                    if let Some(data) = data {
                        let stream_tx = {
                            let streams_guard = streams.lock();
                            streams_guard.get(&header.stream_id).map(|s| s.recv_tx.clone())
                        };
                        if let Some(tx) = stream_tx {
                            let _ = tx.send(data).await;
                        }
                    }
                }
                CMD_UPD => {
                    if let Some(ref data) = data {
                        if data.len() >= 8 {
                            let peer_consumed = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                            let peer_window = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                            let stream_state = {
                                let streams_guard = streams.lock();
                                streams_guard.get(&header.stream_id).cloned()
                            };
                            if let Some(state) = stream_state {
                                state.peer_consumed.store(peer_consumed, Ordering::Release);
                                state.peer_window.store(peer_window, Ordering::Release);
                                if let Some(waker) = state.write_waker.lock().take() {
                                    waker.wake();
                                }
                            }
                        }
                    }
                }
                CMD_FIN => {
                    let stream_state = {
                        let mut streams_guard = streams.lock();
                        streams_guard.remove(&header.stream_id)
                    };
                    if let Some(state) = stream_state {
                        if let Some(waker) = state.write_waker.lock().take() {
                            waker.wake();
                        }
                    }
                }
                CMD_NOP => {
                    // Keepalive ping, respond with NOP if needed or ignore
                }
                CMD_SYN => {
                    // Server-initiated stream, ignore
                }
                _ => {
                    log::debug!("Unknown Smux command: {}", header.cmd);
                }
            }
        }

        closed.store(true, Ordering::Relaxed);
        let mut streams_guard = streams.lock();
        for (_, state) in streams_guard.drain() {
            if let Some(waker) = state.write_waker.lock().take() {
                waker.wake();
            }
        }
    }
}

pub struct SmuxStream {
    stream_id: u32,
    frame_tx: mpsc::Sender<Frame>,
    recv_rx: mpsc::Receiver<Bytes>,
    current_chunk: Option<Bytes>,
    state: Arc<StreamState>,
    streams: Arc<Mutex<HashMap<u32, Arc<StreamState>>>>,
    closed: AtomicBool,
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) && self.current_chunk.is_none() {
            return Poll::Ready(Ok(()));
        }

        loop {
            if let Some(mut chunk) = self.current_chunk.take() {
                if chunk.has_remaining() {
                    let to_read = std::cmp::min(buf.remaining(), chunk.remaining());
                    buf.put_slice(&chunk[..to_read]);
                    chunk.advance(to_read);

                    if chunk.has_remaining() {
                        self.current_chunk = Some(chunk);
                    }

                    // Flow control update
                    let old_read = self.state.num_read.fetch_add(to_read as u32, Ordering::SeqCst);
                    let new_incr = self.state.incr.fetch_add(to_read as u32, Ordering::SeqCst) + (to_read as u32);
                    if new_incr >= WINDOW_UPDATE_THRESHOLD {
                        self.state.incr.store(0, Ordering::SeqCst);
                        let total_read = old_read + (to_read as u32);
                        let mut upd_bytes = BytesMut::with_capacity(8);
                        upd_bytes.put_u32_le(total_read);
                        upd_bytes.put_u32_le(MAX_STREAM_BUFFER);
                        let frame = Frame {
                            header: SmuxHeader::new(CMD_UPD, self.stream_id, 8),
                            data: Some(upd_bytes.freeze()),
                        };
                        let _ = self.frame_tx.try_send(frame);
                    }

                    return Poll::Ready(Ok(()));
                }
            }

            match self.recv_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    self.current_chunk = Some(data);
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Smux stream is closed",
            )));
        }

        let num_written = self.state.num_written.load(Ordering::Acquire);
        let peer_consumed = self.state.peer_consumed.load(Ordering::Acquire);
        let peer_window = self.state.peer_window.load(Ordering::Acquire);

        let inflight = num_written.wrapping_sub(peer_consumed) as i32;
        let win = (peer_window as i32) - inflight;

        if win <= 0 {
            *self.state.write_waker.lock() = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let to_send = std::cmp::min(buf.len(), std::cmp::min(win as usize, DEFAULT_MAX_FRAME_SIZE));
        let data = Bytes::copy_from_slice(&buf[..to_send]);

        let frame = Frame {
            header: SmuxHeader::new(CMD_PSH, self.stream_id, to_send as u16),
            data: Some(data),
        };

        match self.frame_tx.try_send(frame) {
            Ok(_) => {
                self.state.num_written.fetch_add(to_send as u32, Ordering::Release);
                Poll::Ready(Ok(to_send))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "Smux session write channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let fin_frame = Frame {
                header: SmuxHeader::new(CMD_FIN, self.stream_id, 0),
                data: None,
            };
            let _ = self.frame_tx.try_send(fin_frame);
            let mut streams = self.streams.lock();
            streams.remove(&self.stream_id);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let fin_frame = Frame {
                header: SmuxHeader::new(CMD_FIN, self.stream_id, 0),
                data: None,
            };
            let _ = self.frame_tx.try_send(fin_frame);
            let mut streams = self.streams.lock();
            streams.remove(&self.stream_id);
        }
    }
}

impl crate::async_stream::AsyncPing for SmuxStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncStream for SmuxStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_smux_stream_transfer_with_flow_control() {
        let (client_io, server_io) = duplex(65536);

        let client_sess = SmuxSession::client(client_io);

        tokio::spawn(async move {
            let mut server_reader = server_io;
            let mut buf = vec![0u8; 1024];
            while let Ok(n) = server_reader.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });

        let mut stream = client_sess.open_stream().await.unwrap();
        stream.write_all(b"hello smux flow control").await.unwrap();
        stream.flush().await.unwrap();
    }
}
