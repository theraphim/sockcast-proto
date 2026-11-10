#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
#[cfg(not(target_arch = "wasm32"))]
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Mutex, OnceLock};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

pub const TXT_SUBDOMAIN_PREFIX: &str = "_sshcast.";
const DNS_TYPE_TXT: u16 = 16;
const DNS_CLASS_IN: u16 = 1;

/// Returns `Some(domain)` if `entry` represents a domain name to be resolved via `_sshcast.<domain>`
/// DNS TXT records (e.g. `"sshcast.net"`, `"dns:sshcast.net"`, or `"_sshcast.sshcast.net"`),
/// or `None` if `entry` is already an explicit `http://` or `https://` coordinator endpoint URL.
pub fn is_dns_discovery_entry(entry: &str) -> Option<String> {
    let trimmed = entry.trim().trim_end_matches('/').trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(rest) = lower
        .strip_prefix("dns:")
        .or_else(|| lower.strip_prefix("txt:"))
    {
        let clean = rest
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .trim_end_matches('.');
        if !clean.is_empty() {
            return Some(clean.to_string());
        }
        return None;
    }
    if let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .or_else(|| lower.strip_prefix("wss://"))
        .or_else(|| lower.strip_prefix("ws://"))
    {
        let host = rest.split('/').next().unwrap_or("").trim_end_matches('.');
        if host.starts_with(TXT_SUBDOMAIN_PREFIX) {
            return Some(host.to_string());
        }
        return None;
    }
    Some(lower)
}

/// Normalizes a domain or `_sshcast.<domain>` string into the exact DNS QNAME to query for TXT records.
pub fn txt_lookup_qname(domain: &str) -> String {
    let cleaned = domain
        .trim()
        .trim_start_matches("dns:")
        .trim_start_matches("DNS:")
        .trim_start_matches("txt:")
        .trim_start_matches("TXT:")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        return String::new();
    }
    if cleaned.starts_with(TXT_SUBDOMAIN_PREFIX) {
        cleaned
    } else {
        format!("{TXT_SUBDOMAIN_PREFIX}{cleaned}")
    }
}

/// Normalizes a coordinator hostname or URL token into an `https://...` (or `http://...`) URL.
pub fn normalize_coordinator_url(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .trim_end_matches('/')
        .trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        Some(trimmed.to_string())
    } else {
        Some(format!("https://{trimmed}"))
    }
}

fn push_unique(out: &mut Vec<String>, url: String) {
    if !out.contains(&url) {
        out.push(url);
    }
}

/// Parses one or more DNS TXT record strings from `_sshcast.<domain>` into a deduplicated list of
/// coordinator server URLs (`https://...`).
///
/// Supported TXT record formats:
/// - Key-value format: `"v=sshcast1; coordinators=c1.sshcast.net,c2.sshcast.net"` or `"servers=https://c1.sshcast.net,https://c2.sshcast.net"`
/// - Space, comma, or semicolon separated list of hostnames or URLs: `"c1.sshcast.net c2.sshcast.net"`
/// - Multiple TXT records, each containing one or more hostnames/URLs.
pub fn parse_txt_coordinator_records(txt_records: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw_record in txt_records {
        let record = raw_record.trim().trim_matches('"').trim();
        if record.is_empty() {
            continue;
        }
        if record.contains('=') {
            for clause in record.split(';') {
                let clause = clause.trim();
                if clause.is_empty() {
                    continue;
                }
                if let Some((k, v)) = clause.split_once('=') {
                    let key = k.trim().to_ascii_lowercase();
                    if matches!(
                        key.as_str(),
                        "servers"
                            | "server"
                            | "coordinators"
                            | "coordinator"
                            | "hosts"
                            | "host"
                            | "urls"
                            | "url"
                    ) {
                        for item in v.split(|c: char| c == ',' || c.is_whitespace()) {
                            if let Some(norm) = normalize_coordinator_url(item) {
                                push_unique(&mut out, norm);
                            }
                        }
                    }
                }
            }
        } else {
            for token in record.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
                if let Some(norm) = normalize_coordinator_url(token) {
                    push_unique(&mut out, norm);
                }
            }
        }
    }
    out
}

/// Builds an RFC 1035 DNS query packet for `QTYPE = TXT (16), QCLASS = IN (1)`.
pub fn build_dns_txt_query(qname: &str, tx_id: u16) -> Result<Vec<u8>, String> {
    let cleaned = qname.trim().trim_end_matches('.');
    if cleaned.is_empty() {
        return Err("empty DNS query name".to_string());
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD (Recursion Desired) = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    for label in cleaned.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("invalid DNS label {label:?} in {qname:?}"));
        }
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0); // Root label terminator
    pkt.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(pkt)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize, String> {
    let mut jumps = 0usize;
    loop {
        if offset >= packet.len() {
            return Err("truncated DNS name".to_string());
        }
        let len = packet[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err("truncated DNS compression pointer".to_string());
            }
            return Ok(offset + 2);
        }
        if (len & 0xC0) != 0 {
            return Err("invalid DNS label length bits".to_string());
        }
        offset += 1 + (len as usize);
        jumps += 1;
        if jumps > 128 {
            return Err("DNS name label limit exceeded".to_string());
        }
    }
}

/// Parses an RFC 1035 DNS response packet and extracts all `TXT` answer strings.
/// Returns `Ok((txt_records, is_truncated))`.
pub fn parse_dns_txt_response(
    packet: &[u8],
    expected_tx_id: u16,
) -> Result<(Vec<String>, bool), String> {
    if packet.len() < 12 {
        return Err("DNS response shorter than 12-byte header".to_string());
    }
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    if tx_id != expected_tx_id {
        return Err(format!(
            "DNS transaction ID mismatch: got {tx_id:#06x}, expected {expected_tx_id:#06x}"
        ));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return Err("DNS packet is not a response".to_string());
    }
    let is_truncated = (flags & 0x0200) != 0;
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS query returned RCODE {rcode}"));
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return Err("truncated DNS question section".to_string());
        }
        offset += 4; // QTYPE + QCLASS
    }

    let mut txt_records = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 10 > packet.len() {
            if is_truncated {
                return Ok((txt_records, true));
            }
            return Err("truncated DNS resource record header".to_string());
        }
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > packet.len() {
            if is_truncated {
                return Ok((txt_records, true));
            }
            return Err("truncated DNS resource record RDATA".to_string());
        }

        if rr_type == DNS_TYPE_TXT && rr_class == DNS_CLASS_IN {
            let rdata = &packet[offset..offset + rdlength];
            let mut pos = 0usize;
            let mut combined = Vec::with_capacity(rdlength);
            while pos < rdata.len() {
                let slen = rdata[pos] as usize;
                pos += 1;
                if pos + slen > rdata.len() {
                    break;
                }
                combined.extend_from_slice(&rdata[pos..pos + slen]);
                pos += slen;
            }
            if let Ok(s) = String::from_utf8(combined) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    txt_records.push(trimmed.to_string());
                }
            }
        }
        offset += rdlength;
    }

    Ok((txt_records, is_truncated))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn parse_resolv_conf_nameservers(resolv_conf: &str) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for line in resolv_conf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(keyword) = parts.next() else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("nameserver") {
            continue;
        }
        let Some(raw_ip) = parts.next() else {
            continue;
        };
        let ip_clean = raw_ip.split('%').next().unwrap_or(raw_ip);
        if let Ok(ip) = ip_clean.parse::<IpAddr>() {
            let sa = SocketAddr::new(ip, 53);
            if !servers.contains(&sa) {
                servers.push(sa);
            }
        }
    }
    servers
}

#[cfg(not(target_arch = "wasm32"))]
pub fn system_nameservers() -> Vec<SocketAddr> {
    let mut servers = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(raw) => parse_resolv_conf_nameservers(&raw),
        Err(_) => Vec::new(),
    };
    for fallback in ["1.1.1.1:53", "8.8.8.8:53"] {
        if let Ok(sa) = fallback.parse::<SocketAddr>() {
            if !servers.contains(&sa) {
                servers.push(sa);
            }
        }
    }
    servers
}

#[cfg(not(target_arch = "wasm32"))]
fn query_dns_txt_tcp(
    ns: SocketAddr,
    query_pkt: &[u8],
    tx_id: u16,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    let mut stream = TcpStream::connect_timeout(&ns, timeout)
        .map_err(|e| format!("TCP connect to {ns} failed: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let len_bytes = (query_pkt.len() as u16).to_be_bytes();
    stream
        .write_all(&len_bytes)
        .and_then(|_| stream.write_all(query_pkt))
        .map_err(|e| format!("TCP write to {ns} failed: {e}"))?;

    let mut resp_len_buf = [0u8; 2];
    stream
        .read_exact(&mut resp_len_buf)
        .map_err(|e| format!("TCP read length from {ns} failed: {e}"))?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| format!("TCP read body from {ns} failed: {e}"))?;

    let (records, _) = parse_dns_txt_response(&resp_buf, tx_id)?;
    Ok(records)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn query_dns_txt(domain_or_qname: &str, timeout: Duration) -> Result<Vec<String>, String> {
    let qname = txt_lookup_qname(domain_or_qname);
    if qname.is_empty() {
        return Err("empty domain for DNS TXT lookup".to_string());
    }
    let tx_id: u16 = rand::random();
    let query_pkt = build_dns_txt_query(&qname, tx_id)?;
    let nameservers = system_nameservers();
    let mut last_err = String::from("no DNS nameservers available");

    for ns in nameservers {
        let bind_addr = if ns.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        if let Ok(sock) = UdpSocket::bind(bind_addr) {
            let _ = sock.set_read_timeout(Some(timeout));
            let _ = sock.set_write_timeout(Some(timeout));
            if sock.send_to(&query_pkt, ns).is_ok() {
                let mut buf = vec![0u8; 4096];
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) => match parse_dns_txt_response(&buf[..n], tx_id) {
                        Ok((records, false)) => return Ok(records),
                        Ok((_, true)) => {
                            if let Ok(tcp_records) =
                                query_dns_txt_tcp(ns, &query_pkt, tx_id, timeout)
                            {
                                return Ok(tcp_records);
                            }
                        }
                        Err(e) => {
                            last_err = e;
                        }
                    },
                    Err(e) => {
                        last_err = format!("UDP recv from {ns} failed: {e}");
                    }
                }
            }
        }
        if let Ok(tcp_records) = query_dns_txt_tcp(ns, &query_pkt, tx_id, timeout) {
            return Ok(tcp_records);
        }
    }

    Err(last_err)
}

#[cfg(not(target_arch = "wasm32"))]
fn dns_cache() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolves a list of configured coordinator server entries (which may mix explicit `https://...`
/// URLs and DNS discovery domains such as `"sshcast.net"` resolved via `_sshcast.sshcast.net` TXT records)
/// into concrete coordinator endpoint URLs.
#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_coordinator_servers(entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        if let Some(domain) = is_dns_discovery_entry(entry) {
            let qname = txt_lookup_qname(&domain);
            match query_dns_txt(&qname, Duration::from_millis(1500)) {
                Ok(txt_records) => {
                    let parsed = parse_txt_coordinator_records(&txt_records);
                    if !parsed.is_empty() {
                        if let Ok(mut guard) = dns_cache().lock() {
                            guard.insert(qname.clone(), parsed.clone());
                        }
                        for url in parsed {
                            push_unique(&mut out, url);
                        }
                        continue;
                    }
                }
                Err(_) => {}
            }
            if let Ok(guard) = dns_cache().lock() {
                if let Some(cached) = guard.get(&qname) {
                    for url in cached {
                        push_unique(&mut out, url.clone());
                    }
                    continue;
                }
            }
            let fallback_host = domain.trim_start_matches(TXT_SUBDOMAIN_PREFIX);
            if let Some(fallback_url) = normalize_coordinator_url(fallback_host) {
                push_unique(&mut out, fallback_url);
            }
        } else if let Some(norm) = normalize_coordinator_url(entry) {
            push_unique(&mut out, norm);
        }
    }
    out
}
