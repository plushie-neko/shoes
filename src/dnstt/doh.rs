use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Number of concurrent DoH HTTP workers for multiplexing DNS queries.
pub const DOH_NUM_WORKERS: usize = 4;

/// Known DoH host bootstrap IP mappings to avoid circular DNS dependency.
fn get_bootstrap_ips(host: &str) -> Vec<std::net::IpAddr> {
    match host.to_ascii_lowercase().as_str() {
        "1.1.1.1" => vec!["1.1.1.1".parse().unwrap()],
        "1.0.0.1" => vec!["1.0.0.1".parse().unwrap()],
        "cloudflare-dns.com" | "one.one.one.one" => vec![
            "1.1.1.1".parse().unwrap(),
            "1.0.0.1".parse().unwrap(),
            "104.16.249.249".parse().unwrap(),
            "104.16.248.249".parse().unwrap(),
        ],
        "8.8.8.8" => vec!["8.8.8.8".parse().unwrap()],
        "8.8.4.4" => vec!["8.8.4.4".parse().unwrap()],
        "dns.google" => vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
        ],
        "9.9.9.9" => vec!["9.9.9.9".parse().unwrap()],
        "dns.quad9.net" => vec![
            "9.9.9.9".parse().unwrap(),
            "149.112.112.112".parse().unwrap(),
        ],
        "doh.opendns.com" => vec![
            "208.67.222.222".parse().unwrap(),
            "208.67.220.220".parse().unwrap(),
        ],
        "doh.adguard-dns.com" => vec![
            "94.140.14.14".parse().unwrap(),
            "94.140.15.15".parse().unwrap(),
        ],
        "doh.mullvad.net" => vec![
            "194.242.2.2".parse().unwrap(),
        ],
        _ => Vec::new(),
    }
}

pub struct DohTransport {
    url_string: String,
    host: String,
    port: u16,
    path_and_query: String,
    bootstrap_addrs: Vec<SocketAddr>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl DohTransport {
    pub fn new(doh_url: &str) -> io::Result<Self> {
        let url = Url::parse(doh_url)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid doh_url: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host in doh_url"))?
            .to_string();

        let port = url.port().unwrap_or(if url.scheme() == "http" { 80 } else { 443 });
        let path = url.path();
        let path_and_query = match url.query() {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };

        let mut bootstrap_addrs = Vec::new();
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            bootstrap_addrs.push(SocketAddr::new(ip, port));
        } else {
            for ip in get_bootstrap_ips(&host) {
                bootstrap_addrs.push(SocketAddr::new(ip, port));
            }
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut client_config = rustls::ClientConfig::builder_with_provider(
            crate::rustls_config_util::get_crypto_provider(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_config = Arc::new(client_config);

        Ok(Self {
            url_string: doh_url.to_string(),
            host,
            port,
            path_and_query,
            bootstrap_addrs,
            tls_config,
        })
    }

    /// Spawns the DoH worker pool that handles DNS query POSTs.
    pub fn spawn_workers(
        self: Arc<Self>,
        query_rx: mpsc::Receiver<Vec<u8>>,
        resp_tx: mpsc::Sender<Vec<u8>>,
        closed: Arc<AtomicBool>,
    ) {
        let shared_rx = Arc::new(tokio::sync::Mutex::new(query_rx));

        // Spawn workers
        for worker_id in 0..DOH_NUM_WORKERS {
            let transport = self.clone();
            let rx = shared_rx.clone();
            let tx = resp_tx.clone();
            let is_closed = closed.clone();

            tokio::spawn(async move {
                log::info!("[doh_worker_{}] Starting DoH worker for {}", worker_id, transport.url_string);
                transport.worker_loop(worker_id, rx, tx, is_closed).await;
            });
        }
    }

    async fn worker_loop(
        &self,
        worker_id: usize,
        query_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
        resp_tx: mpsc::Sender<Vec<u8>>,
        closed: Arc<AtomicBool>,
    ) {
        let mut conn: Option<TlsStream<TcpStream>> = None;

        while !closed.load(Ordering::Relaxed) {
            let query = {
                let mut lock = query_rx.lock().await;
                match lock.recv().await {
                    Some(q) => q,
                    None => break,
                }
            };

            // Attempt request, retrying with a fresh connection if existing fails
            let mut succeeded = false;
            for attempt in 0..2 {
                if conn.is_none() {
                    match self.connect_tls().await {
                        Ok(c) => {
                            conn = Some(c);
                        }
                        Err(e) => {
                            log::warn!("[doh_worker_{}] TLS connection failed (attempt {}): {}", worker_id, attempt, e);
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                    }
                }

                if let Some(ref mut stream) = conn {
                    match Self::send_doh_request(stream, &self.host, &self.path_and_query, &query).await {
                        Ok(resp_bytes) => {
                            log::trace!("[doh_worker_{}] Received DoH response: {} bytes", worker_id, resp_bytes.len());
                            let _ = resp_tx.send(resp_bytes).await;
                            succeeded = true;
                            break;
                        }
                        Err(e) => {
                            log::warn!("[doh_worker_{}] DoH POST error (attempt {}): {}", worker_id, attempt, e);
                            conn = None; // Reset broken connection
                        }
                    }
                }
            }

            if !succeeded {
                log::warn!("[doh_worker_{}] Failed to execute DoH query after retries", worker_id);
            }
        }
    }

    async fn connect_tls(&self) -> io::Result<TlsStream<TcpStream>> {
        let target_addr = if !self.bootstrap_addrs.is_empty() {
            self.bootstrap_addrs[(rand::random::<u32>() as usize) % self.bootstrap_addrs.len()]
        } else {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", self.host, self.port))
                .await?
                .collect();
            if addrs.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "could not resolve DoH host"));
            }
            addrs[0]
        };

        let socket = crate::socket_util::new_tcp_socket(None, target_addr.is_ipv6())?;
        let tcp_stream = socket.connect(target_addr).await?;
        let _ = tcp_stream.set_nodelay(true);

        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("TLS error: {}", e)))?;

        Ok(tls_stream)
    }

    async fn send_doh_request(
        stream: &mut TlsStream<TcpStream>,
        host: &str,
        path: &str,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let req_header = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             User-Agent: \r\n\
             Connection: keep-alive\r\n\r\n",
            path,
            host,
            query.len()
        );

        stream.write_all(req_header.as_bytes()).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        // Read HTTP response
        let mut header_buf = Vec::with_capacity(512);
        let mut byte_buf = [0u8; 1];

        // Read headers byte by byte until \r\n\r\n
        while header_buf.len() < 4096 {
            let n = stream.read(&mut byte_buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF while reading DoH response headers"));
            }
            header_buf.push(byte_buf[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let header_str = String::from_utf8_lossy(&header_buf);
        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().unwrap_or("");

        if !status_line.contains("200") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("DoH server returned status: {}", status_line),
            ));
        }

        let mut content_length: Option<usize> = None;
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                if let Some(val) = line.split(':').nth(1) {
                    content_length = val.trim().parse::<usize>().ok();
                }
            }
        }

        let content_len = content_length.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length in DoH response")
        })?;

        if content_len > 65536 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DoH response too large"));
        }

        let mut body = vec![0u8; content_len];
        stream.read_exact(&mut body).await?;

        Ok(body)
    }
}
