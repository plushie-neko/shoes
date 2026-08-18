use snow::error::StateProblem;
use snow::params::NoiseParams;
use snow::{Builder, Error as SnowError, HandshakeState, TransportState};

pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"dnstt 2020-04-13";
pub const MAX_CHUNK_SIZE: usize = 4096;
pub const NOISE_TAG_LEN: usize = 16;
#[allow(dead_code)]
pub const MAX_CIPHERTEXT_CHUNK_SIZE: usize = MAX_CHUNK_SIZE + NOISE_TAG_LEN;

pub enum DnsttCryptoState {
    Handshake(HandshakeState),
    Transport(TransportState),
    Invalid,
}

pub struct DnsttCrypto {
    state: DnsttCryptoState,
}

impl DnsttCrypto {
    /// Creates a new Noise NK client initiator with the server's 32-byte public key.
    pub fn new_client(server_pubkey: &[u8]) -> Result<Self, SnowError> {
        let params: NoiseParams = NOISE_PATTERN.parse()?;
        let builder = Builder::new(params);

        let handshake = builder
            .prologue(PROLOGUE)?
            .remote_public_key(server_pubkey)?
            .build_initiator()?;

        Ok(Self {
            state: DnsttCryptoState::Handshake(handshake),
        })
    }

    /// Creates a server responder with the 32-byte private key (used for tests/mock server).
    #[cfg(test)]
    pub fn new_server(server_privkey: &[u8]) -> Result<Self, SnowError> {
        let params: NoiseParams = NOISE_PATTERN.parse()?;
        let builder = Builder::new(params);

        let handshake = builder
            .prologue(PROLOGUE)?
            .local_private_key(server_privkey)?
            .build_responder()?;

        Ok(Self {
            state: DnsttCryptoState::Handshake(handshake),
        })
    }

    /// Returns true if the handshake has completed and transport mode is active.
    #[allow(dead_code)]
    pub fn is_transport(&self) -> bool {
        matches!(self.state, DnsttCryptoState::Transport(_))
    }

    /// Generates Handshake Message 1 (Client -> Server).
    /// For NK pattern, this generates a 48-byte message.
    pub fn write_handshake_message(&mut self, out: &mut [u8]) -> Result<usize, SnowError> {
        match &mut self.state {
            DnsttCryptoState::Handshake(hs) => hs.write_message(&[], out),
            _ => Err(SnowError::State(StateProblem::HandshakeAlreadyFinished)),
        }
    }

    /// Processes Handshake Message 2 (Server -> Client) and transitions to Transport mode.
    pub fn read_handshake_message(&mut self, message: &[u8]) -> Result<(), SnowError> {
        let old_state = std::mem::replace(&mut self.state, DnsttCryptoState::Invalid);
        match old_state {
            DnsttCryptoState::Handshake(mut hs) => {
                let mut dummy_payload = [0u8; 128];
                let payload_len = hs.read_message(message, &mut dummy_payload)?;
                if payload_len != 0 {
                    return Err(SnowError::Decrypt);
                }
                let transport = hs.into_transport_mode()?;
                self.state = DnsttCryptoState::Transport(transport);
                Ok(())
            }
            _ => Err(SnowError::State(StateProblem::HandshakeAlreadyFinished)),
        }
    }

    /// Server side: processes handshake message 1 and writes handshake message 2.
    #[cfg(test)]
    pub fn server_handshake_step(
        &mut self,
        msg1: &[u8],
        out_msg2: &mut [u8],
    ) -> Result<usize, SnowError> {
        let old_state = std::mem::replace(&mut self.state, DnsttCryptoState::Invalid);
        match old_state {
            DnsttCryptoState::Handshake(mut hs) => {
                let mut dummy_payload = [0u8; 128];
                let _ = hs.read_message(msg1, &mut dummy_payload)?;
                let len = hs.write_message(&[], out_msg2)?;
                let transport = hs.into_transport_mode()?;
                self.state = DnsttCryptoState::Transport(transport);
                Ok(len)
            }
            _ => Err(SnowError::State(StateProblem::HandshakeAlreadyFinished)),
        }
    }

    /// Encrypts a plaintext chunk (up to 4096 bytes) in transport mode.
    /// Returns the length of the ciphertext written to `out`.
    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, SnowError> {
        match &mut self.state {
            DnsttCryptoState::Transport(ts) => ts.write_message(plaintext, out),
            _ => Err(SnowError::State(StateProblem::HandshakeNotFinished)),
        }
    }

    /// Decrypts a ciphertext chunk in transport mode.
    /// Returns the length of the plaintext written to `out`.
    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, SnowError> {
        match &mut self.state {
            DnsttCryptoState::Transport(ts) => ts.read_message(ciphertext, out),
            _ => Err(SnowError::State(StateProblem::HandshakeNotFinished)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake_and_transport() {
        let params: NoiseParams = NOISE_PATTERN.parse().unwrap();
        let builder = Builder::new(params);
        let keypair = builder.generate_keypair().unwrap();
        let server_pubkey = keypair.public;
        let server_privkey = keypair.private;

        let mut client = DnsttCrypto::new_client(&server_pubkey).unwrap();
        let mut server = DnsttCrypto::new_server(&server_privkey).unwrap();

        // Step 1: Client generates message 1
        let mut msg1 = [0u8; 128];
        let len1 = client.write_handshake_message(&mut msg1).unwrap();
        assert_eq!(len1, 48); // 32 ephemeral + 16 MAC

        // Step 2: Server receives msg 1 and replies with msg 2
        let mut msg2 = [0u8; 128];
        let len2 = server
            .server_handshake_step(&msg1[..len1], &mut msg2)
            .unwrap();
        assert_eq!(len2, 48);

        // Step 3: Client processes msg 2
        client.read_handshake_message(&msg2[..len2]).unwrap();

        assert!(client.is_transport());
        assert!(server.is_transport());

        // Step 4: Transport data client -> server
        let test_data = b"hello encrypted tunnel";
        let mut cipher = [0u8; 256];
        let cipher_len = client.encrypt(test_data, &mut cipher).unwrap();
        assert_eq!(cipher_len, test_data.len() + NOISE_TAG_LEN);

        let mut plain = [0u8; 256];
        let plain_len = server.decrypt(&cipher[..cipher_len], &mut plain).unwrap();
        assert_eq!(&plain[..plain_len], test_data);

        // Step 5: Transport data server -> client
        let reply_data = b"server reply over noise";
        let reply_cipher_len = server.encrypt(reply_data, &mut cipher).unwrap();
        let reply_plain_len = client
            .decrypt(&cipher[..reply_cipher_len], &mut plain)
            .unwrap();
        assert_eq!(&plain[..reply_plain_len], reply_data);
    }
}
