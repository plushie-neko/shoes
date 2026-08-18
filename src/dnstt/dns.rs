use bytes::{Buf, BufMut, BytesMut};

use super::encoding::{chunk_labels, encode_payload, EncodingMode};

/// Number of random padding bytes in poll queries.
pub const NUM_PADDING_FOR_POLL: usize = 8;
/// Default EDNS(0) requester's UDP payload size.
pub const DEFAULT_EDNS0_SIZE: u16 = 4096;

/// Calculates the max raw payload capacity in bytes for a given tunnel domain.
/// Matches the Go dnstt implementation.
pub fn dns_name_capacity(tunnel_domain: &str) -> usize {
    // Max DNS name length is 255 bytes (RFC 1035 section 2.3.4)
    let mut capacity: isize = 255 - 1; // null terminator

    for label in tunnel_domain.split('.') {
        if !label.is_empty() {
            capacity -= (label.len() as isize) + 1;
        }
    }

    if capacity <= 0 {
        return 0;
    }

    // Each label is up to 63 bytes + 1 length byte (63/64 ratio)
    capacity = capacity * 63 / 64;
    // Base32 expands every 5 bytes to 8 (5/8 ratio)
    capacity = capacity * 5 / 8;

    capacity.max(0) as usize
}

/// Calculates effective KCP MTU for a given tunnel domain.
pub fn effective_mtu(tunnel_domain: &str, custom_mtu: Option<usize>) -> usize {
    let cap = dns_name_capacity(tunnel_domain);
    let max_mtu = if cap > 10 { cap - 10 } else { 64 };

    if let Some(mtu) = custom_mtu {
        if mtu > 0 && mtu <= max_mtu {
            return mtu;
        }
    }

    max_mtu
}

/// Builds an upstream payload (with ClientID, padding, and optional data) and encodes it into label string.
pub fn build_encoded_payload(
    client_id: &[u8; 8],
    kcp_packet: &[u8],
    is_poll: bool,
    mode: &EncodingMode,
) -> String {
    let mut buf = Vec::with_capacity(256);

    // 1. ClientID (8 bytes)
    buf.extend_from_slice(client_id);

    if is_poll || kcp_packet.is_empty() {
        // Polling query: 1 byte prefix (0xe0 + 8 = 232) + 8 bytes random padding
        buf.push(224 + NUM_PADDING_FOR_POLL as u8);
        let padding: [u8; NUM_PADDING_FOR_POLL] = rand::random();
        buf.extend_from_slice(&padding);
    } else {
        // Data query: 1 byte prefix (0xe0 + 0 = 224) + 1 byte data length + KCP packet data
        buf.push(224); // 0 padding
        buf.push(kcp_packet.len() as u8);
        buf.extend_from_slice(kcp_packet);
    }

    let encoded = encode_payload(&buf, mode);
    let labels = chunk_labels(&encoded, 63);
    labels.join(".")
}

/// Generates a raw DNS query for a given encoded payload and a tunnel domain.
/// The query requests a TXT record and includes an EDNS(0) OPT record.
pub fn build_txt_query(encoded_payload: &str, tunnel_domain: &str, edns0_size: u16) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);

    // DNS Header
    let id: u16 = rand::random();
    buf.put_u16(id);
    buf.put_u16(0x0100); // Flags: standard query, recursion desired (RD=1)
    buf.put_u16(1); // QDCOUNT (1 question)
    buf.put_u16(0); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(1); // ARCOUNT (1 EDNS0 OPT record)

    // DNS Question
    let full_domain = format!("{}.{}", encoded_payload, tunnel_domain);
    for label in full_domain.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0); // Root label

    // QTYPE = 16 (TXT)
    buf.put_u16(16);
    // QCLASS = 1 (IN)
    buf.put_u16(1);

    // EDNS(0) OPT Record (Additional Section)
    buf.put_u8(0); // Root domain name
    buf.put_u16(41); // TYPE = OPT (41)
    buf.put_u16(edns0_size); // CLASS = requester's UDP payload size (e.g. 4096)
    buf.put_u32(0); // TTL = extended RCODE and flags
    buf.put_u16(0); // RDLENGTH = 0 (no options)

    buf.to_vec()
}

/// Parses a raw DNS response and extracts all downstream length-prefixed KCP packets
/// from TXT records.
pub fn parse_txt_response(response: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut buf = std::io::Cursor::new(response);

    if buf.remaining() < 12 {
        log::trace!("[dnstt dns] DNS response too short: {} bytes", buf.remaining());
        return None;
    }

    let _id = buf.get_u16();
    let flags = buf.get_u16();

    // Ensure it's a response (QR=1)
    if (flags & 0x8000) == 0 {
        log::trace!("[dnstt dns] Ignored non-response DNS packet (QR=0)");
        return None;
    }

    let rcode = flags & 0x000f;
    if rcode != 0 {
        log::warn!("[dnstt dns] Resolver returned non-zero RCODE={}", rcode);
        return None;
    }

    let qdcount = buf.get_u16();
    let ancount = buf.get_u16();
    let _nscount = buf.get_u16();
    let _arcount = buf.get_u16();

    // Skip questions
    for _ in 0..qdcount {
        skip_name(&mut buf)?;
        if buf.remaining() < 4 {
            return None;
        }
        buf.advance(4); // QTYPE + QCLASS
    }

    let mut packets = Vec::new();

    // Parse answers
    for _ in 0..ancount {
        skip_name(&mut buf)?;
        if buf.remaining() < 10 {
            return None;
        }
        let qtype = buf.get_u16();
        let _qclass = buf.get_u16();
        let _ttl = buf.get_u32();
        let rdlength = buf.get_u16() as usize;

        if buf.remaining() < rdlength {
            return None;
        }

        if qtype == 16 {
            // TXT
            // TXT records contain one or more character-strings: [1-byte len][chars...]
            let mut txt_data = Vec::with_capacity(rdlength);
            let mut read_bytes = 0;

            while read_bytes < rdlength {
                let len = buf.get_u8() as usize;
                read_bytes += 1;

                if buf.remaining() < len {
                    return None;
                }

                let mut chunk = vec![0u8; len];
                buf.copy_to_slice(&mut chunk);
                txt_data.extend_from_slice(&chunk);
                read_bytes += len;
            }

            // The TXT binary data contains [2-byte BE length][packet] pairs
            let mut r = std::io::Cursor::new(txt_data.as_slice());
            while r.remaining() >= 2 {
                let pkt_len = r.get_u16() as usize;
                if r.remaining() < pkt_len {
                    break;
                }
                let mut pkt = vec![0u8; pkt_len];
                r.copy_to_slice(&mut pkt);
                packets.push(pkt);
            }
        } else {
            buf.advance(rdlength);
        }
    }

    Some(packets)
}

fn skip_name(buf: &mut std::io::Cursor<&[u8]>) -> Option<()> {
    let mut jumps = 0;
    loop {
        if buf.remaining() == 0 {
            return None;
        }
        let len = buf.get_u8();
        if len == 0 {
            return Some(());
        }

        if len & 0xC0 == 0xC0 {
            // Pointer (2 bytes total, 1 already read)
            if buf.remaining() == 0 {
                return None;
            }
            buf.advance(1);
            return Some(());
        } else {
            if buf.remaining() < len as usize {
                return None;
            }
            buf.advance(len as usize);
        }

        jumps += 1;
        if jumps > 255 {
            return None; // Prevent infinite loop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_name_capacity() {
        let domain = "t.example.com";
        let cap = dns_name_capacity(domain);
        assert!(cap > 100);
        let mtu = effective_mtu(domain, None);
        assert!(mtu >= 80);
    }

    #[test]
    fn test_build_txt_query() {
        let client_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let kcp_data = b"kcp-packet-data";
        let encoded =
            build_encoded_payload(&client_id, kcp_data, false, &EncodingMode::Base32);
        let query = build_txt_query(&encoded, "t.example.com", 4096);

        assert!(query.len() > 12);
        // Flags: 0x0100 (RD=1)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);
        // ARCOUNT = 1 (EDNS0)
        assert_eq!(query[10], 0x00);
        assert_eq!(query[11], 0x01);
    }

    #[test]
    fn test_parse_txt_response_multi_packets() {
        // Construct a mock DNS response with 2 packets in TXT RDATA
        let mut msg = BytesMut::new();
        msg.put_u16(0x1234); // ID
        msg.put_u16(0x8180); // Flags: QR=1, RD=1, RA=1, RCODE=0
        msg.put_u16(0); // QDCOUNT
        msg.put_u16(1); // ANCOUNT
        msg.put_u16(0); // NSCOUNT
        msg.put_u16(0); // ARCOUNT

        // Answer 1: name = root (0)
        msg.put_u8(0);
        msg.put_u16(16); // TXT
        msg.put_u16(1); // IN
        msg.put_u32(60); // TTL

        let pkt1 = b"first-packet";
        let pkt2 = b"second-packet-payload";

        let mut rdata_content = BytesMut::new();
        rdata_content.put_u16(pkt1.len() as u16);
        rdata_content.put_slice(pkt1);
        rdata_content.put_u16(pkt2.len() as u16);
        rdata_content.put_slice(pkt2);

        // TXT RDATA length = 1 (char-string len) + rdata_content.len()
        msg.put_u16((1 + rdata_content.len()) as u16);
        msg.put_u8(rdata_content.len() as u8);
        msg.put_slice(&rdata_content);

        let packets = parse_txt_response(&msg).expect("parsing failed");
        assert_eq!(packets.len(), 2);
        assert_eq!(&packets[0], pkt1);
        assert_eq!(&packets[1], pkt2);
    }
}
