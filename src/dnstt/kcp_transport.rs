use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use kcp::Kcp;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Instant};

use super::dns::{
    build_encoded_payload, build_txt_query, effective_mtu, parse_txt_response, DEFAULT_EDNS0_SIZE,
};
use super::doh::DohTransport;
use super::encoding::EncodingMode;

pub const INIT_POLL_DELAY: Duration = Duration::from_millis(500);
pub const MAX_POLL_DELAY: Duration = Duration::from_millis(10000);
pub const POLL_DELAY_MULTIPLIER: f64 = 2.0;
pub const POLL_BURST_LIMIT: usize = 10;
pub const KCP_TICK_INTERVAL: Duration = Duration::from_millis(25);

/// Channel writer for outgoing KCP packets.
struct KcpOutputSender {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl io::Write for KcpOutputSender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.tx.send(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct DnsttKcpTransport {
    /// Sender for upper-layer outgoing data (plaintext or Noise frames) into KCP
    pub send_tx: mpsc::Sender<Bytes>,
    /// Receiver for upper-layer incoming data from KCP
    pub recv_rx: mpsc::Receiver<Bytes>,
    #[allow(dead_code)]
    closed: Arc<AtomicBool>,
}

impl DnsttKcpTransport {
    /// Starts the KCP + DNS transport loop connecting to the resolver via UDP or DoH.
    pub async fn connect(
        resolver_addr: Option<SocketAddr>,
        doh_url: Option<String>,
        tunnel_domain: String,
        encoding_mode: EncodingMode,
        custom_mtu: Option<usize>,
    ) -> io::Result<Self> {
        let mtu = effective_mtu(&tunnel_domain, custom_mtu);

        let (send_tx, send_rx) = mpsc::channel::<Bytes>(1024);
        let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(1024);
        let (poll_tx, poll_rx) = mpsc::channel::<()>(POLL_BURST_LIMIT);
        let closed = Arc::new(AtomicBool::new(false));

        let client_id: [u8; 8] = rand::random();

        if let Some(ref url) = doh_url {
            let trimmed = url.trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                log::info!("[kcp_transport] Initializing DoH transport for {}", trimmed);
                let doh = Arc::new(DohTransport::new(trimmed)?);
                let (doh_query_tx, doh_query_rx) = mpsc::channel::<Vec<u8>>(1024);
                let (doh_resp_tx, doh_resp_rx) = mpsc::channel::<Vec<u8>>(1024);

                doh.spawn_workers(doh_query_rx, doh_resp_tx, closed.clone());

                tokio::spawn(Self::transport_loop_doh(
                    doh_query_tx,
                    doh_resp_rx,
                    client_id,
                    tunnel_domain,
                    encoding_mode,
                    mtu,
                    send_rx,
                    recv_tx,
                    poll_tx,
                    poll_rx,
                    closed.clone(),
                ));

                return Ok(Self {
                    send_tx,
                    recv_rx,
                    closed,
                });
            }
        }

        let addr = resolver_addr.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing resolver address for UDP transport")
        })?;

        let socket = crate::socket_util::new_udp_socket(addr.is_ipv6(), None)?;

        // Spawn background UDP I/O worker
        tokio::spawn(Self::transport_loop_udp(
            socket,
            addr,
            client_id,
            tunnel_domain,
            encoding_mode,
            mtu,
            send_rx,
            recv_tx,
            poll_tx,
            poll_rx,
            closed.clone(),
        ));

        Ok(Self {
            send_tx,
            recv_rx,
            closed,
        })
    }

    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    async fn transport_loop_udp(
        socket: UdpSocket,
        resolver_addr: SocketAddr,
        client_id: [u8; 8],
        tunnel_domain: String,
        mode: EncodingMode,
        mtu: usize,
        mut send_rx: mpsc::Receiver<Bytes>,
        recv_tx: mpsc::Sender<Bytes>,
        poll_tx: mpsc::Sender<()>,
        mut poll_rx: mpsc::Receiver<()>,
        closed: Arc<AtomicBool>,
    ) {
        let (kcp_out_tx, mut kcp_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut kcp = Kcp::new_stream(0, KcpOutputSender { tx: kcp_out_tx });
        kcp.input_conv();
        kcp.set_nodelay(false, 20, 0, true);
        kcp.set_wndsize(64, 64);
        let _ = kcp.set_mtu(mtu);

        let mut poll_delay = INIT_POLL_DELAY;
        let mut next_poll_time = Instant::now() + poll_delay;
        let mut tick_timer = interval(KCP_TICK_INTERVAL);

        let mut recv_buf = [0u8; 4096];
        let mut kcp_recv_buf = [0u8; 65536];

        let start_time = std::time::Instant::now();
        let clock = || start_time.elapsed().as_millis() as u32;

        while !closed.load(Ordering::Relaxed) {
            tokio::select! {
                Some(data) = send_rx.recv() => {
                    log::trace!("[kcp_transport_udp] Upper layer send: {} bytes", data.len());
                    let _ = kcp.send(&data);
                    let _ = kcp.update(clock());
                    let _ = kcp.flush();

                    let mut sent_any = false;
                    while let Ok(packet) = kcp_out_rx.try_recv() {
                        sent_any = true;
                        let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = socket.send_to(&query, resolver_addr).await;
                    }

                    if sent_any {
                        let _ = poll_rx.try_recv();
                        poll_delay = INIT_POLL_DELAY;
                        next_poll_time = Instant::now() + poll_delay;
                    }
                }

                Ok((len, _from)) = socket.recv_from(&mut recv_buf) => {
                    let mut packet_buffers = Vec::new();
                    packet_buffers.push(recv_buf[..len].to_vec());

                    while let Ok((extra_len, _)) = socket.try_recv_from(&mut recv_buf) {
                        packet_buffers.push(recv_buf[..extra_len].to_vec());
                    }

                    for buf in packet_buffers {
                        if let Some(packets) = parse_txt_response(&buf) {
                            let any_packets = !packets.is_empty();
                            for packet in packets {
                                let _ = kcp.input(&packet);
                            }

                            let _ = kcp.update(clock());
                            let _ = kcp.flush();

                            while let Ok(packet) = kcp_out_rx.try_recv() {
                                let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                                let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                                let _ = socket.send_to(&query, resolver_addr).await;
                            }

                            while let Ok(n) = kcp.recv(&mut kcp_recv_buf) {
                                if n == 0 {
                                    break;
                                }
                                if recv_tx.send(Bytes::copy_from_slice(&kcp_recv_buf[..n])).await.is_err() {
                                    closed.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }

                            if any_packets {
                                // Pipeline expansion (TCP slow-start style): prompt server for next data chunk
                                let _ = poll_tx.try_send(());
                                poll_delay = INIT_POLL_DELAY;
                                next_poll_time = Instant::now() + poll_delay;
                            }
                        }
                    }
                }

                Some(()) = poll_rx.recv() => {
                    let mut sent_any = false;
                    while let Ok(packet) = kcp_out_rx.try_recv() {
                        sent_any = true;
                        let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = socket.send_to(&query, resolver_addr).await;
                    }

                    if !sent_any {
                        let encoded = build_encoded_payload(&client_id, &[], true, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = socket.send_to(&query, resolver_addr).await;
                    }

                    poll_delay = INIT_POLL_DELAY;
                    next_poll_time = Instant::now() + poll_delay;
                }

                _ = tick_timer.tick() => {
                    let now = Instant::now();
                    let current_clock = clock();

                    let _ = kcp.update(current_clock);
                    let _ = kcp.flush();

                    let mut sent_any = false;
                    while let Ok(packet) = kcp_out_rx.try_recv() {
                        sent_any = true;
                        let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = socket.send_to(&query, resolver_addr).await;
                    }

                    while let Ok(n) = kcp.recv(&mut kcp_recv_buf) {
                        if n == 0 {
                            break;
                        }
                        if recv_tx.send(Bytes::copy_from_slice(&kcp_recv_buf[..n])).await.is_err() {
                            closed.store(true, Ordering::Relaxed);
                            break;
                        }
                    }

                    if sent_any {
                        let _ = poll_rx.try_recv();
                        poll_delay = INIT_POLL_DELAY;
                        next_poll_time = now + poll_delay;
                    } else if now >= next_poll_time {
                        let encoded = build_encoded_payload(&client_id, &[], true, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = socket.send_to(&query, resolver_addr).await;

                        poll_delay = Duration::from_secs_f64(
                            (poll_delay.as_secs_f64() * POLL_DELAY_MULTIPLIER)
                                .min(MAX_POLL_DELAY.as_secs_f64()),
                        );
                        next_poll_time = now + poll_delay;
                    }
                }
            }
        }
    }

    async fn transport_loop_doh(
        doh_query_tx: mpsc::Sender<Vec<u8>>,
        mut doh_resp_rx: mpsc::Receiver<Vec<u8>>,
        client_id: [u8; 8],
        tunnel_domain: String,
        mode: EncodingMode,
        mtu: usize,
        mut send_rx: mpsc::Receiver<Bytes>,
        recv_tx: mpsc::Sender<Bytes>,
        poll_tx: mpsc::Sender<()>,
        mut poll_rx: mpsc::Receiver<()>,
        closed: Arc<AtomicBool>,
    ) {
        let (kcp_out_tx, mut kcp_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut kcp = Kcp::new_stream(0, KcpOutputSender { tx: kcp_out_tx });
        kcp.input_conv();
        kcp.set_nodelay(false, 20, 0, true);
        kcp.set_wndsize(64, 64);
        let _ = kcp.set_mtu(mtu);

        let mut poll_delay = INIT_POLL_DELAY;
        let mut next_poll_time = Instant::now() + poll_delay;
        let mut tick_timer = interval(KCP_TICK_INTERVAL);

        let mut kcp_recv_buf = [0u8; 65536];

        let start_time = std::time::Instant::now();
        let clock = || start_time.elapsed().as_millis() as u32;

        while !closed.load(Ordering::Relaxed) {
            tokio::select! {
                Some(data) = send_rx.recv() => {
                    log::trace!("[kcp_transport_doh] Upper layer send: {} bytes", data.len());
                    let _ = kcp.send(&data);
                    let _ = kcp.update(clock());
                    let _ = kcp.flush();

                    let mut sent_any = false;
                    while let Ok(packet) = kcp_out_rx.try_recv() {
                        sent_any = true;
                        let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = doh_query_tx.send(query).await;
                    }

                    if sent_any {
                        let _ = poll_rx.try_recv();
                        poll_delay = INIT_POLL_DELAY;
                        next_poll_time = Instant::now() + poll_delay;
                    }
                }

                Some(resp) = doh_resp_rx.recv() => {
                    if let Some(packets) = parse_txt_response(&resp) {
                        let any_packets = !packets.is_empty();
                        for packet in packets {
                            let _ = kcp.input(&packet);
                        }

                        let _ = kcp.update(clock());
                        let _ = kcp.flush();

                        while let Ok(packet) = kcp_out_rx.try_recv() {
                            let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                            let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                            let _ = doh_query_tx.send(query).await;
                        }

                        while let Ok(n) = kcp.recv(&mut kcp_recv_buf) {
                            if n == 0 {
                                break;
                            }
                            if recv_tx.send(Bytes::copy_from_slice(&kcp_recv_buf[..n])).await.is_err() {
                                closed.store(true, Ordering::Relaxed);
                                break;
                            }
                        }

                        if any_packets {
                            let _ = poll_tx.try_send(());
                            poll_delay = INIT_POLL_DELAY;
                            next_poll_time = Instant::now() + poll_delay;
                        }
                    }
                }

                Some(()) = poll_rx.recv() => {
                    let mut sent_any = false;
                    while let Ok(packet) = kcp_out_rx.try_recv() {
                        sent_any = true;
                        let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = doh_query_tx.send(query).await;
                    }

                    if !sent_any {
                        let encoded = build_encoded_payload(&client_id, &[], true, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = doh_query_tx.send(query).await;
                    }

                    poll_delay = INIT_POLL_DELAY;
                    next_poll_time = Instant::now() + poll_delay;
                }

                _ = tick_timer.tick() => {
                    let now = Instant::now();
                    let current_clock = clock();

                    let _ = kcp.update(current_clock);
                    let _ = kcp.flush();

                    let mut sent_any = false;
                    while let Ok(packet) = kcp_out_rx.try_recv() {
                        sent_any = true;
                        let encoded = build_encoded_payload(&client_id, &packet, false, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = doh_query_tx.send(query).await;
                    }

                    while let Ok(n) = kcp.recv(&mut kcp_recv_buf) {
                        if n == 0 {
                            break;
                        }
                        if recv_tx.send(Bytes::copy_from_slice(&kcp_recv_buf[..n])).await.is_err() {
                            closed.store(true, Ordering::Relaxed);
                            break;
                        }
                    }

                    if sent_any {
                        let _ = poll_rx.try_recv();
                        poll_delay = INIT_POLL_DELAY;
                        next_poll_time = now + poll_delay;
                    } else if now >= next_poll_time {
                        let encoded = build_encoded_payload(&client_id, &[], true, &mode);
                        let query = build_txt_query(&encoded, &tunnel_domain, DEFAULT_EDNS0_SIZE);
                        let _ = doh_query_tx.send(query).await;

                        poll_delay = Duration::from_secs_f64(
                            (poll_delay.as_secs_f64() * POLL_DELAY_MULTIPLIER)
                                .min(MAX_POLL_DELAY.as_secs_f64()),
                        );
                        next_poll_time = now + poll_delay;
                    }
                }
            }
        }
    }
}
