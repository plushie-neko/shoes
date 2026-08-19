use std::fmt::Debug;
use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::info;
use rand::{Rng, RngExt};
use tokio::sync::Mutex;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_addresses};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::new_udp_socket;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

pub struct Hysteria2Session {
    pub connection: quinn::Connection,
    pub endpoint: quinn::Endpoint,
}

pub struct Hysteria2Client {
    pub server_location: NetLocation,
    pub password: String,
    pub udp_enabled: bool,
    pub sni_hostname: Option<String>,
    pub verify: bool,
    pub alpn: Vec<String>,
    pub ports: Option<String>,
    pub hop_interval_sec: Option<u64>,
    pub resolver: Arc<dyn Resolver>,
    session: Arc<Mutex<Option<Arc<Hysteria2Session>>>>,
}

impl Debug for Hysteria2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Client")
            .field("server_location", &self.server_location)
            .field("udp_enabled", &self.udp_enabled)
            .field("sni_hostname", &self.sni_hostname)
            .field("verify", &self.verify)
            .field("alpn", &self.alpn)
            .finish()
    }
}

impl Hysteria2Client {
    pub fn new(
        server_location: NetLocation,
        password: String,
        udp_enabled: bool,
        sni_hostname: Option<String>,
        verify: bool,
        alpn: Option<String>,
        ports: Option<String>,
        hop_interval_sec: Option<u64>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let alpn_list = alpn
            .map(|a| a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_else(|| vec!["h3".to_string()]);

        Self {
            server_location,
            password,
            udp_enabled,
            sni_hostname,
            verify,
            alpn: alpn_list,
            ports,
            hop_interval_sec,
            resolver,
            session: Arc::new(Mutex::new(None)),
        }
    }

    async fn get_or_create_session(&self) -> io::Result<Arc<Hysteria2Session>> {
        let mut session_guard = self.session.lock().await;

        if let Some(ref session) = *session_guard {
            // Check if connection is still alive
            if session.connection.close_reason().is_none() {
                return Ok(session.clone());
            }
        }

        let session = self.connect_session().await?;
        let session_arc = Arc::new(session);
        *session_guard = Some(session_arc.clone());
        Ok(session_arc)
    }

    async fn connect_session(&self) -> io::Result<Hysteria2Session> {
        let resolved_addrs = resolve_addresses(
            &self.resolver,
            &self.server_location,
        )
        .await?;

        if resolved_addrs.is_empty() {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                format!("Failed to resolve Hysteria2 server address: {}", self.server_location),
            ));
        }

        let target_sockaddr = resolved_addrs[0];

        let default_sni = self.server_location.address().hostname().map(ToString::to_string);
        let sni = self.sni_hostname.as_ref().or(default_sni.as_ref()).cloned()
            .unwrap_or_else(|| target_sockaddr.ip().to_string());

        info!(
            "Connecting to Hysteria2 server {} ({}) with SNI={}",
            self.server_location, target_sockaddr, sni
        );

        let tls13_suite = match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            rustls::SupportedCipherSuite::Tls13(t) => t,
            _ => panic!("Could not retrieve Tls13CipherSuite"),
        };

        let rustls_client_config = create_client_config(
            self.verify,
            vec![],
            self.alpn.clone(),
            true,
            None,
            false,
        );

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
            Arc::new(rustls_client_config),
            tls13_suite.quic_suite().unwrap(),
        )
        .map_err(|e| io::Error::other(format!("Failed to create QuicClientConfig: {e}")))?;

        let mut quinn_client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(1024_u32.into())
            .max_concurrent_uni_streams(1024_u32.into())
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

        quinn_client_config.transport_config(Arc::new(transport_config));

        let udp_socket = new_udp_socket(target_sockaddr.is_ipv6(), None)?;
        let udp_socket = udp_socket.into_std()?;

        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp_socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn_client_config);

        let connection = endpoint
            .connect(target_sockaddr, &sni)
            .map_err(|e| io::Error::other(format!("QUIC endpoint connect error: {e}")))?
            .await
            .map_err(|e| io::Error::other(format!("QUIC connection handshake failed: {e}")))?;

        // Perform HTTP/3 authentication
        let h3_quinn_conn = h3_quinn::Connection::new(connection.clone());
        let (driver, mut send_request) = h3::client::new(h3_quinn_conn)
            .await
            .map_err(|e| io::Error::other(format!("H3 client setup failed: {e}")))?;

        let padding_str: String = {
            let mut rng = rand::rng();
            let length = rng.random_range(16..64);
            rng.sample_iter(rand::distr::Alphanumeric)
                .take(length)
                .map(char::from)
                .collect()
        };

        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", &self.password)
            .header("hysteria-udp", if self.udp_enabled { "true" } else { "false" })
            .header("hysteria-cc-rx", "0")
            .header("hysteria-padding", padding_str)
            .body(())
            .map_err(|e| io::Error::other(format!("Failed to construct H3 auth request: {e}")))?;

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| io::Error::other(format!("H3 send_request failed: {e}")))?;

        stream
            .finish()
            .await
            .map_err(|e| io::Error::other(format!("H3 auth stream finish failed: {e}")))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| io::Error::other(format!("H3 auth response recv failed: {e}")))?;

        let status = response.status().as_u16();
        if status != 233 && status != 200 && !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Hysteria2 auth rejected by server: status {}",
                response.status()
            )));
        }

        // h3 connection wrapper closes the underlying quinn connection when dropped.
        // Forget driver and send_request so the underlying QUIC session remains open
        // for subsequent raw QUIC bidirectional streams (TCP proxying) and datagrams.
        std::mem::forget(driver);
        std::mem::forget(send_request);

        info!("Hysteria2 connection and auth successfully established with {}", self.server_location);

        Ok(Hysteria2Session {
            connection,
            endpoint,
        })
    }
}

#[async_trait]
impl TcpClientHandler for Hysteria2Client {
    async fn setup_client_tcp_stream(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let session = self.get_or_create_session().await?;

        let (mut send, mut recv) = session
            .connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("Failed to open QUIC bidi stream: {e}")))?;

        let addr_str = remote_location.location().to_string();
        let addr_bytes = addr_str.as_bytes();

        let padding: Vec<u8> = {
            let mut rng = rand::rng();
            let len: usize = rng.random_range(0..=63);
            let mut p = vec![0u8; len];
            rng.fill_bytes(&mut p);
            p
        };

        let mut header = Vec::with_capacity(32 + addr_bytes.len() + padding.len());
        encode_varint(FRAME_TYPE_TCP_REQUEST, &mut header);
        encode_varint(addr_bytes.len() as u64, &mut header);
        header.extend_from_slice(addr_bytes);
        encode_varint(padding.len() as u64, &mut header);
        header.extend_from_slice(&padding);

        send.write_all(&header)
            .await
            .map_err(|e| io::Error::other(format!("Failed to write Hysteria2 TCP header: {e}")))?;

        // Read response header: [status_u8, varint(msg_len), msg, varint(padding_len), padding]
        let mut stream_reader = StreamReader::new_with_buffer_size(4096);
        let status = stream_reader.read_u8(&mut recv).await?;
        let msg_len = read_varint(&mut recv, &mut stream_reader).await?;
        let msg_bytes = if msg_len > 0 {
            stream_reader.read_slice(&mut recv, msg_len as usize).await?.to_vec()
        } else {
            Vec::new()
        };
        let padding_len = read_varint(&mut recv, &mut stream_reader).await?;
        if padding_len > 0 {
            stream_reader.read_slice(&mut recv, padding_len as usize).await?;
        }

        if status != 0 {
            let msg = String::from_utf8_lossy(&msg_bytes);
            return Err(io::Error::other(format!(
                "Hysteria2 server rejected connection to {}: {}",
                addr_str, msg
            )));
        }

        let quic_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from(send, recv));

        Ok(TcpClientSetupResult {
            client_stream: quic_stream,
            early_data: None,
        })
    }

    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "Direct UDP proxy over Hysteria2 not supported without UOT",
        ))
    }
}

fn encode_varint(val: u64, buf: &mut Vec<u8>) {
    if val <= 63 {
        buf.push(val as u8);
    } else if val <= 16383 {
        buf.push((0b01 << 6) | ((val >> 8) as u8));
        buf.push((val & 0xff) as u8);
    } else if val <= 1073741823 {
        buf.push((0b10 << 6) | ((val >> 24) as u8));
        buf.push(((val >> 16) & 0xff) as u8);
        buf.push(((val >> 8) & 0xff) as u8);
        buf.push((val & 0xff) as u8);
    } else {
        buf.push((0b11 << 6) | ((val >> 56) as u8));
        buf.push(((val >> 48) & 0xff) as u8);
        buf.push(((val >> 40) & 0xff) as u8);
        buf.push(((val >> 32) & 0xff) as u8);
        buf.push(((val >> 24) & 0xff) as u8);
        buf.push(((val >> 16) & 0xff) as u8);
        buf.push(((val >> 8) & 0xff) as u8);
        buf.push((val & 0xff) as u8);
    }
}

async fn read_varint(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> io::Result<u64> {
    let first_byte = stream_reader.read_u8(recv).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(recv, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8;
            value |= *byte as u64;
        }
    }

    Ok(value)
}
