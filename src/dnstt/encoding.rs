use num_bigint::BigUint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingMode {
    Base32,
    Base36,
}

impl Default for EncodingMode {
    fn default() -> Self {
        Self::Base32
    }
}

pub fn encode_payload(data: &[u8], mode: &EncodingMode) -> String {
    match mode {
        EncodingMode::Base32 => {
            let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, data);
            encoded.to_ascii_lowercase()
        }
        EncodingMode::Base36 => {
            let num = BigUint::from_bytes_be(data);
            num.to_str_radix(36)
        }
    }
}

#[allow(dead_code)]
pub fn decode_payload(encoded: &str, mode: &EncodingMode) -> Option<Vec<u8>> {
    match mode {
        EncodingMode::Base32 => {
            base32::decode(
                base32::Alphabet::Rfc4648 { padding: false },
                &encoded.to_ascii_uppercase(),
            )
        }
        EncodingMode::Base36 => {
            let num = BigUint::parse_bytes(encoded.as_bytes(), 36)?;
            Some(num.to_bytes_be())
        }
    }
}

/// Splits an encoded string into labels of at most `max_len` bytes (typically 63).
pub fn chunk_labels(encoded: &str, max_len: usize) -> Vec<&str> {
    let mut labels = Vec::new();
    let mut remaining = encoded;
    while !remaining.is_empty() {
        let chunk_size = std::cmp::min(remaining.len(), max_len);
        labels.push(&remaining[..chunk_size]);
        remaining = &remaining[chunk_size..];
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encoding() {
        let data = b"hello dnstt test";
        let encoded = encode_payload(data, &EncodingMode::Base32);
        assert!(!encoded.contains('='));
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        let decoded = decode_payload(&encoded, &EncodingMode::Base32).expect("decode failed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base36_encoding() {
        let data = b"hello noizdns test";
        let encoded = encode_payload(data, &EncodingMode::Base36);
        let decoded = decode_payload(&encoded, &EncodingMode::Base36).expect("decode failed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_chunk_labels() {
        let text = "a".repeat(150);
        let chunks = chunk_labels(&text, 63);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 63);
        assert_eq!(chunks[1].len(), 63);
        assert_eq!(chunks[2].len(), 24);
    }
}
