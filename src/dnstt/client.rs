use std::fmt::Debug;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::config::DnsttConfig;
use super::encoding::EncodingMode;
use super::kcp_transport::DnsttKcpTransport;
use super::noise_stream::NoiseStream;
use super::smux::SmuxSession;
use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

pub struct DnsttClient {
    pub config: DnsttConfig,
    pub inner_handler: Box<dyn TcpClientHandler>,
    session: Arc<Mutex<Option<Arc<SmuxSession>>>>,
}

impl DnsttClient {
    pub fn new(config: DnsttConfig, inner_handler: Box<dyn TcpClientHandler>) -> Self {
        Self {
            config,
            inner_handler,
            session: Arc::new(Mutex::new(None)),
        }
    }

    /// Obtains an active Smux session, creating and handshaking a new one if necessary.
    async fn get_or_create_session(&self) -> io::Result<Arc<SmuxSession>> {
        let mut session_guard = self.session.lock().await;

        if let Some(ref session) = *session_guard {
            if !session.is_closed() {
                return Ok(session.clone());
            }
        }

        // Decode hex public key (32 bytes)
        let pubkey_clean = self.config.pubkey.trim();
        let pubkey_bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(pubkey_clean.as_bytes())
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid DNSTT public key hex '{}': {}", pubkey_clean, e),
                )
            })?;

        if pubkey_bytes.len() != 32 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Invalid DNSTT public key length: expected 32 bytes, got {}",
                    pubkey_bytes.len()
                ),
            ));
        }

        // Parse resolver socket address if provided
        let resolver_addr: Option<SocketAddr> = if self.config.resolver.trim().is_empty() {
            None
        } else {
            self.config.resolver.parse().ok()
        };

        let doh_url = self.config.doh_url.clone();

        // Determine encoding mode (dnstt-server uses standard Base32 on the wire)
        let encoding_mode = match self.config.mode.to_lowercase().as_str() {
            "base36" => EncodingMode::Base36,
            _ => EncodingMode::Base32,
        };

        log::info!(
            "Starting DNSTT tunnel to domain={} resolver={:?} doh_url={:?} mode={:?}",
            self.config.domain,
            resolver_addr,
            doh_url,
            encoding_mode
        );

        // 1. Establish KCP over DNS transport
        let transport = DnsttKcpTransport::connect(
            resolver_addr,
            doh_url,
            self.config.domain.clone(),
            encoding_mode,
            self.config.mtu,
        )
        .await?;

        // 2. Perform Noise NK handshake over KCP
        let noise_stream = NoiseStream::handshake(
            &pubkey_bytes,
            transport.send_tx,
            transport.recv_rx,
        )
        .await?;

        log::info!(
            "Noise NK handshake completed for domain={}",
            self.config.domain
        );

        // 3. Start Smux multiplexer session on top of Noise channel
        let smux_session = SmuxSession::client(noise_stream);
        *session_guard = Some(smux_session.clone());

        Ok(smux_session)
    }
}

impl Debug for DnsttClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsttClient")
            .field("domain", &self.config.domain)
            .field("resolver", &self.config.resolver)
            .field("mode", &self.config.mode)
            .field("inner_handler", &self.inner_handler)
            .finish()
    }
}

#[async_trait]
impl TcpClientHandler for DnsttClient {
    async fn setup_client_tcp_stream(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let session = self.get_or_create_session().await?;
        let smux_stream = session.open_stream().await?;

        self.inner_handler
            .setup_client_tcp_stream(Box::new(smux_stream), remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.inner_handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let session = self.get_or_create_session().await?;
        let smux_stream = session.open_stream().await?;

        self.inner_handler
            .setup_client_udp_bidirectional(Box::new(smux_stream), target)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_dnstt_client_e2e_against_server_binary() {
        let server_bin = "../dnstt-server-linux-amd64";
        let key_file = "../server.key";
        if !std::path::Path::new(server_bin).exists() || !std::path::Path::new(key_file).exists() {
            println!("Skipping e2e test: server binary or key file not found");
            return;
        }

        println!("[test] Starting TCP echo server on 127.0.0.1:18081");
        let echo_listener = TcpListener::bind("127.0.0.1:18081").await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = socket.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        println!("[test] Spawning dnstt-server process");
        let mut server_proc = Command::new(server_bin)
            .args(&[
                "-privkey-file",
                key_file,
                "t.example.com",
                "127.0.0.1:15353",
                "127.0.0.1:18081",
            ])
            .spawn()
            .expect("Failed to start dnstt-server");

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let config = DnsttConfig {
            domain: "t.example.com".to_string(),
            resolver: "127.0.0.1:15353".to_string(),
            pubkey: "de5dcc01dbef40ef3b9f12fd884724db78d0f78fce2ef53265df73db2e3e9925".to_string(),
            mode: "dnstt".to_string(),
            doh_url: None,
            mtu: None,
        };

        println!("[test] Creating DnsttClient");
        let client = DnsttClient::new(config, Box::new(crate::port_forward_handler::PortForwardClientHandler));

        let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dummy_addr = dummy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = dummy_listener.accept().await;
        });
        let dummy_client_conn = tokio::net::TcpStream::connect(dummy_addr).await.unwrap();
        let dummy_stream = Box::new(dummy_client_conn);
        let dummy_loc = ResolvedLocation::from(
            crate::address::NetLocation::from_str("127.0.0.1:18081", None).unwrap(),
        );

        println!("[test] Calling setup_client_tcp_stream");
        let setup_res = client
            .setup_client_tcp_stream(dummy_stream, dummy_loc)
            .await;

        let mut stream = match setup_res {
            Ok(res) => {
                println!("[test] setup_client_tcp_stream succeeded!");
                res.client_stream
            }
            Err(e) => {
                let _ = server_proc.kill();
                panic!("setup_client_tcp_stream failed: {}", e);
            }
        };

        let test_message = b"hello from shoes client to dnstt-server over DNS!";
        println!("[test] Writing test message");
        if let Err(e) = stream.write_all(test_message).await {
            let _ = server_proc.kill();
            panic!("stream write failed: {}", e);
        }
        let _ = stream.flush().await;

        println!("[test] Reading echo response");
        let mut recv_buf = vec![0u8; test_message.len()];
        let read_res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut recv_buf),
        )
        .await;

        match read_res {
            Ok(Ok(_)) => {
                println!("[test] Echo response received: {:?}", std::str::from_utf8(&recv_buf));
                assert_eq!(&recv_buf, test_message);
            }
            Ok(Err(e)) => {
                let _ = server_proc.kill();
                panic!("stream read error: {}", e);
            }
            Err(_) => {
                let _ = server_proc.kill();
                panic!("stream read TIMED OUT after 5s");
            }
        }

        // Clean up server process
        let _ = server_proc.kill();
        println!("[test] Test finished successfully!");
    }
}
