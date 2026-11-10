use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
#[cfg(not(target_arch = "wasm32"))]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
pub const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
];

/// Payload carried inside `ZellijTunnelFrame.payload` for `P2P_OFFER` and `P2P_ANSWER`.
/// Signed end-to-end by the sender node's Ed25519 key (`ZellijTunnelFrame.sender_signature`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pEndpointHandshake {
    /// Direct TCP candidate `ip:port` endpoints (LAN, VPN, IPv6, or STUN-mapped public port)
    pub tcp_candidates: Vec<String>,
    /// UDP candidate `ip:port` endpoints (including STUN reflexive address) for hole-punching
    pub udp_candidates: Vec<String>,
    /// 32-byte random session secret (base64url encoded)
    pub secret_b64: String,
}

impl P2pEndpointHandshake {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(tcp_candidates: Vec<String>, udp_candidates: Vec<String>) -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            tcp_candidates,
            udp_candidates,
            secret_b64: URL_SAFE_NO_PAD.encode(secret),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// Derives mutual 32-byte authentication tokens (`client_to_relay_token`, `relay_to_client_token`)
/// and a 32-byte encryption key from the signed `P2P_OFFER` and `P2P_ANSWER` handshakes.
pub fn derive_p2p_session_keys(
    tunnel_id: &str,
    offer: &P2pEndpointHandshake,
    offer_sig: &[u8],
    answer: &P2pEndpointHandshake,
    answer_sig: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut master = Sha256::new();
    master.update(b"sockcast-zellij-p2p-master-v1\x00");
    master.update(tunnel_id.as_bytes());
    master.update(offer.secret_b64.as_bytes());
    master.update(offer_sig);
    master.update(answer.secret_b64.as_bytes());
    master.update(answer_sig);
    let master_seed: [u8; 32] = master.finalize().into();

    let derive = |label: &[u8]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&master_seed);
        h.update(label);
        h.finalize().into()
    };

    (
        derive(b"client-auth-token"),
        derive(b"relay-auth-token"),
        derive(b"stream-cipher-key"),
    )
}

/// Lightweight counter-mode SHA-256 stream cipher for encrypting direct P2P streams.
#[derive(Clone)]
pub struct P2pStreamCipher {
    key: [u8; 32],
    counter: u64,
    block: [u8; 32],
    block_idx: usize,
}

impl P2pStreamCipher {
    pub fn new(key: [u8; 32], direction_label: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(&key);
        h.update(direction_label);
        let dir_key: [u8; 32] = h.finalize().into();
        Self {
            key: dir_key,
            counter: 0,
            block: [0u8; 32],
            block_idx: 32,
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.block_idx >= 32 {
                let mut h = Sha256::new();
                h.update(&self.key);
                h.update(&self.counter.to_le_bytes());
                self.block = h.finalize().into();
                self.counter = self.counter.wrapping_add(1);
                self.block_idx = 0;
            }
            *b ^= self.block[self.block_idx];
            self.block_idx += 1;
        }
    }
}

/// Builds a 20-byte RFC 5389 STUN Binding Request packet and returns `(packet, transaction_id)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_stun_binding_request() -> ([u8; 20], [u8; 12]) {
    let mut tx_id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut tx_id);

    let mut pkt = [0u8; 20];
    pkt[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // message length = 0
    pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt[8..20].copy_from_slice(&tx_id);
    (pkt, tx_id)
}

/// Parses an RFC 5389 STUN Binding Response packet and extracts the reflexive `SocketAddr`.
pub fn parse_stun_binding_response(pkt: &[u8], expected_tx_id: &[u8; 12]) -> Option<SocketAddr> {
    if pkt.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
    let msg_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if msg_type != STUN_BINDING_RESPONSE || cookie != STUN_MAGIC_COOKIE {
        return None;
    }
    if &pkt[8..20] != expected_tx_id {
        return None;
    }
    if pkt.len() < 20 + msg_len {
        return None;
    }

    let mut attrs = &pkt[20..20 + msg_len];
    let mut mapped_fallback: Option<SocketAddr> = None;

    while attrs.len() >= 4 {
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        attrs = &attrs[4..];
        if attrs.len() < attr_len {
            break;
        }
        let val = &attrs[..attr_len];
        let padded_len = (attr_len + 3) & !3;
        attrs = &attrs[padded_len.min(attrs.len())..];

        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            if let Some(addr) = parse_stun_address_attr(val, true, expected_tx_id) {
                return Some(addr);
            }
        } else if attr_type == STUN_ATTR_MAPPED_ADDRESS && mapped_fallback.is_none() {
            mapped_fallback = parse_stun_address_attr(val, false, expected_tx_id);
        }
    }

    mapped_fallback
}

fn parse_stun_address_attr(
    val: &[u8],
    xor: bool,
    tx_id: &[u8; 12],
) -> Option<SocketAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let raw_port = u16::from_be_bytes([val[2], val[3]]);
    let port = if xor {
        raw_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16)
    } else {
        raw_port
    };

    match family {
        0x01 => {
            // IPv4
            if val.len() < 8 {
                return None;
            }
            let raw_ip = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
            let ip_u32 = if xor {
                raw_ip ^ STUN_MAGIC_COOKIE
            } else {
                raw_ip
            };
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_u32)), port))
        }
        0x02 => {
            // IPv6
            if val.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&val[4..20]);
            if xor {
                let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    ip_bytes[i] ^= cookie_bytes[i];
                }
                for i in 0..12 {
                    ip_bytes[4 + i] ^= tx_id[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => None,
    }
}
