use std::io::{self, Cursor, ErrorKind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::crypto::{DnsttCrypto, MAX_CHUNK_SIZE, NOISE_TAG_LEN};
use crate::async_stream::{AsyncPing, AsyncStream};

pub struct NoiseStream {
    send_tx: mpsc::Sender<Bytes>,
    recv_rx: mpsc::Receiver<Bytes>,
    crypto: Arc<Mutex<DnsttCrypto>>,
    read_buf: BytesMut,
    current_plain_chunk: Option<Cursor<Vec<u8>>>,
    closed: Arc<AtomicBool>,
}

impl NoiseStream {
    /// Performs the Noise NK handshake over the KCP channels and creates an encrypted NoiseStream.
    pub async fn handshake(
        server_pubkey: &[u8],
        send_tx: mpsc::Sender<Bytes>,
        mut recv_rx: mpsc::Receiver<Bytes>,
    ) -> io::Result<Self> {
        let mut crypto = DnsttCrypto::new_client(server_pubkey).map_err(|e| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("Failed to initialize Noise client: {}", e),
            )
        })?;

        // 1. Write Handshake Message 1 (48 bytes)
        let mut msg1 = [0u8; 128];
        let len1 = crypto.write_handshake_message(&mut msg1).map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to write handshake message 1: {}", e),
            )
        })?;

        let mut msg1_framed = BytesMut::with_capacity(2 + len1);
        msg1_framed.put_u16(len1 as u16);
        msg1_framed.put_slice(&msg1[..len1]);

        send_tx.send(msg1_framed.freeze()).await.map_err(|_| {
            io::Error::new(ErrorKind::ConnectionReset, "KCP send channel closed")
        })?;

        // 2. Read Handshake Message 2 (48 bytes framed with 2-byte BE length)
        let mut raw_incoming = BytesMut::new();
        let mut msg2 = vec![0u8; 48];

        loop {
            if raw_incoming.len() >= 2 {
                let msg2_len = u16::from_be_bytes([raw_incoming[0], raw_incoming[1]]) as usize;
                if raw_incoming.len() >= 2 + msg2_len {
                    raw_incoming.advance(2);
                    msg2 = raw_incoming.split_to(msg2_len).to_vec();
                    break;
                }
            }

            match tokio::time::timeout(std::time::Duration::from_secs(15), recv_rx.recv()).await {
                Ok(Some(chunk)) => {
                    raw_incoming.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    return Err(io::Error::new(
                        ErrorKind::ConnectionReset,
                        "KCP stream closed during handshake",
                    ));
                }
                Err(_) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "Noise handshake timed out",
                    ));
                }
            }
        }

        // 3. Process Message 2 and transition to Transport mode
        crypto.read_handshake_message(&msg2).map_err(|e| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                format!("Noise handshake authentication failed: {}", e),
            )
        })?;

        Ok(Self {
            send_tx,
            recv_rx,
            crypto: Arc::new(Mutex::new(crypto)),
            read_buf: raw_incoming, // Preserve any remaining bytes received after handshake
            current_plain_chunk: None,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl AsyncRead for NoiseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) && self.current_plain_chunk.is_none() {
            return Poll::Ready(Ok(()));
        }

        loop {
            // 1. Drain any pending decrypted plaintext
            if let Some(mut cursor) = self.current_plain_chunk.take() {
                if cursor.has_remaining() {
                    let to_read = std::cmp::min(buf.remaining(), cursor.remaining());
                    let start = cursor.position() as usize;
                    buf.put_slice(&cursor.get_ref()[start..start + to_read]);
                    cursor.advance(to_read);

                    if cursor.has_remaining() {
                        self.current_plain_chunk = Some(cursor);
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            // 2. Check if we have a full framed ciphertext message in read_buf
            if self.read_buf.len() >= 2 {
                let msg_len = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
                if self.read_buf.len() >= 2 + msg_len {
                    self.read_buf.advance(2);
                    let ciphertext = self.read_buf.split_to(msg_len);

                    let mut plain = vec![0u8; msg_len];
                    let plain_len = {
                        let mut crypto = self.crypto.lock();
                        crypto.decrypt(&ciphertext, &mut plain).map_err(|e| {
                            io::Error::new(
                                ErrorKind::InvalidData,
                                format!("Noise decrypt error: {}", e),
                            )
                        })?
                    };
                    plain.truncate(plain_len);
                    self.current_plain_chunk = Some(Cursor::new(plain));
                    continue;
                }
            }

            // 3. Read more raw encrypted data from KCP receiver
            match self.recv_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    self.read_buf.extend_from_slice(&data);
                }
                Poll::Ready(None) => {
                    self.closed.store(true, Ordering::Relaxed);
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for NoiseStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "NoiseStream is closed",
            )));
        }

        let chunk_size = std::cmp::min(buf.len(), MAX_CHUNK_SIZE);
        let mut cipher = vec![0u8; chunk_size + NOISE_TAG_LEN];

        let cipher_len = {
            let mut crypto = self.crypto.lock();
            crypto
                .encrypt(&buf[..chunk_size], &mut cipher)
                .map_err(|e| {
                    io::Error::new(ErrorKind::Other, format!("Noise encrypt error: {}", e))
                })?
        };

        let mut framed = BytesMut::with_capacity(2 + cipher_len);
        framed.put_u16(cipher_len as u16);
        framed.put_slice(&cipher[..cipher_len]);

        match self.send_tx.try_send(framed.freeze()) {
            Ok(_) => Poll::Ready(Ok(chunk_size)),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "NoiseStream send channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed.store(true, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for NoiseStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for NoiseStream {}
