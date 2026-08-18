use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsttConfig {
    /// The public key of the DNSTT server (hex string)
    pub pubkey: String,

    /// The tunnel domain (e.g., t.example.com)
    pub domain: String,

    /// The protocol mode: "dnstt" or "noizdns"
    #[serde(default = "default_mode")]
    pub mode: String,

    /// The DNS resolver to use (e.g., 8.8.8.8:53)
    pub resolver: String,

    /// Optional DoH URL to use instead of plain UDP DNS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_url: Option<String>,

    /// The MTU for the payload (default: 1232 for dnstt)
    #[serde(default)]
    pub mtu: Option<usize>,
}

fn default_mode() -> String {
    "dnstt".to_string()
}
