use crate::ssh::{parse_ssh_auth_context, SshKeyError};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256, Sha512};
use std::cmp::Ordering;

pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

// PKCS#1 v1.5 DigestInfo prefixes (RFC 8017 Section 9.2)
const DIGEST_INFO_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    // Little-endian base-2^32 limbs, normalized (no trailing zero limbs).
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut s = bytes;
        while !s.is_empty() && s[0] == 0 {
            s = &s[1..];
        }
        if s.is_empty() {
            return Self::zero();
        }
        let mut limbs = Vec::with_capacity((s.len() + 3) / 4);
        let mut idx = s.len();
        while idx > 0 {
            let start = idx.saturating_sub(4);
            let mut word = 0u32;
            for &b in &s[start..idx] {
                word = (word << 8) | (b as u32);
            }
            limbs.push(word);
            idx = start;
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        for &limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        let first_nz = out.iter().position(|&b| b != 0).unwrap_or(out.len());
        out[first_nz..].to_vec()
    }

    pub fn to_be_bytes_padded(&self, target_len: usize) -> Vec<u8> {
        let raw = self.to_be_bytes();
        if raw.len() >= target_len {
            return raw[raw.len() - target_len..].to_vec();
        }
        let mut out = vec![0u8; target_len - raw.len()];
        out.extend_from_slice(&raw);
        out
    }

    pub fn to_mpint_bytes(&self) -> Vec<u8> {
        let mut raw = self.to_be_bytes();
        if raw.is_empty() {
            return raw;
        }
        if (raw[0] & 0x80) != 0 {
            raw.insert(0, 0x00);
        }
        raw
    }

    pub fn bit_len(&self) -> usize {
        let Some(&top) = self.limbs.last() else {
            return 0;
        };
        (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize)
    }

    pub fn byte_len(&self) -> usize {
        (self.bit_len() + 7) / 8
    }

    pub fn bit(&self, i: usize) -> bool {
        let limb_idx = i / 32;
        if limb_idx >= self.limbs.len() {
            return false;
        }
        ((self.limbs[limb_idx] >> (i % 32)) & 1) != 0
    }

    pub fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (&a, &b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            if a != b {
                return a.cmp(&b);
            }
        }
        Ordering::Equal
    }

    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        for i in 0..max_len {
            let a = *self.limbs.get(i).unwrap_or(&0) as u64;
            let b = *other.limbs.get(i).unwrap_or(&0) as u64;
            let sum = a + b + carry;
            limbs.push(sum as u32);
            carry = sum >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    /// Assumes `self >= other`.
    pub fn sub(&self, other: &Self) -> Self {
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = *other.limbs.get(i).unwrap_or(&0) as i64;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            limbs.push(diff as u32);
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u32; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let prod = (a as u64) * (b as u64) + (limbs[i + j] as u64) + carry;
                limbs[i + j] = prod as u32;
                carry = prod >> 32;
            }
            limbs[i + other.limbs.len()] = carry as u32;
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    fn shl1(&mut self) {
        let mut carry = 0u32;
        for limb in &mut self.limbs {
            let next_carry = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        if self.cmp(modulus) == Ordering::Less {
            return self.clone();
        }
        let mut r = Self::zero();
        for bit_idx in (0..self.bit_len()).rev() {
            r.shl1();
            if self.bit(bit_idx) {
                if r.limbs.is_empty() {
                    r.limbs.push(1);
                } else {
                    r.limbs[0] |= 1;
                }
            }
            if r.cmp(modulus) != Ordering::Less {
                r = r.sub(modulus);
            }
        }
        r
    }

    pub fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        self.mul(other).rem(modulus)
    }

    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        let mut result = Self::one();
        let mut base = self.rem(modulus);
        let bits = exp.bit_len();
        for i in 0..bits {
            if exp.bit(i) {
                result = result.mul_mod(&base, modulus);
            }
            if i + 1 < bits {
                base = base.mul_mod(&base, modulus);
            }
        }
        result
    }
}

#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    pub iqmp: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub dp: Option<BigUint>,
    pub dq: Option<BigUint>,
}

impl RsaPrivateKey {
    pub fn new(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        iqmp: BigUint,
        p: BigUint,
        q: BigUint,
    ) -> Result<Self, SshKeyError> {
        if n.bit_len() < 1024 || e.is_zero() || d.is_zero() {
            return Err(SshKeyError::InvalidFormat(
                "invalid RSA private key parameters".to_string(),
            ));
        }
        let one = BigUint::one();
        let dp = if p.cmp(&one) == Ordering::Greater {
            let p_minus_1 = p.sub(&one);
            Some(d.rem(&p_minus_1))
        } else {
            None
        };
        let dq = if q.cmp(&one) == Ordering::Greater {
            let q_minus_1 = q.sub(&one);
            Some(d.rem(&q_minus_1))
        } else {
            None
        };
        Ok(Self {
            n,
            e,
            d,
            iqmp,
            p,
            q,
            dp,
            dq,
        })
    }

    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        write_ssh_string(&mut blob, "ssh-rsa");
        write_ssh_bytes(&mut blob, &self.e.to_mpint_bytes());
        write_ssh_bytes(&mut blob, &self.n.to_mpint_bytes());
        blob
    }

    pub fn write_openssh_private_fields(&self, buf: &mut Vec<u8>, comment: &str) {
        write_ssh_string(buf, "ssh-rsa");
        write_ssh_bytes(buf, &self.n.to_mpint_bytes());
        write_ssh_bytes(buf, &self.e.to_mpint_bytes());
        write_ssh_bytes(buf, &self.d.to_mpint_bytes());
        write_ssh_bytes(buf, &self.iqmp.to_mpint_bytes());
        write_ssh_bytes(buf, &self.p.to_mpint_bytes());
        write_ssh_bytes(buf, &self.q.to_mpint_bytes());
        write_ssh_string(buf, comment);
    }

    fn raw_private_op(&self, m: &BigUint) -> BigUint {
        // Use Chinese Remainder Theorem when p, q, dp, dq, iqmp are valid
        if let (Some(dp), Some(dq)) = (&self.dp, &self.dq) {
            if !self.p.is_zero() && !self.q.is_zero() && !self.iqmp.is_zero() {
                let m1 = m.mod_pow(dp, &self.p);
                let m2 = m.mod_pow(dq, &self.q);
                let diff = if m1.cmp(&m2) != Ordering::Less {
                    m1.sub(&m2)
                } else {
                    let m1_padded = m1.add(&self.p.mul(&self.p));
                    m1_padded.sub(&m2).rem(&self.p)
                };
                let h = diff.mul_mod(&self.iqmp, &self.p);
                let s = m2.add(&h.mul(&self.q));
                // Verify CRT result with e before returning
                if s.mod_pow(&self.e, &self.n) == *m {
                    return s;
                }
            }
        }
        m.mod_pow(&self.d, &self.n)
    }

    pub fn sign_ssh_data(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, SshKeyError> {
        let (sig_algo, prefix, digest) = if (flags & SSH_AGENT_RSA_SHA2_512) != 0 {
            let mut h = Sha512::new();
            h.update(data);
            ("rsa-sha2-512", DIGEST_INFO_SHA512, h.finalize().to_vec())
        } else if (flags & SSH_AGENT_RSA_SHA2_256) != 0 {
            let mut h = Sha256::new();
            h.update(data);
            ("rsa-sha2-256", DIGEST_INFO_SHA256, h.finalize().to_vec())
        } else {
            let ctx = parse_ssh_auth_context(data);
            match ctx.pubkey_algorithm.as_str() {
                "rsa-sha2-512" => {
                    let mut h = Sha512::new();
                    h.update(data);
                    ("rsa-sha2-512", DIGEST_INFO_SHA512, h.finalize().to_vec())
                }
                "rsa-sha2-256" => {
                    let mut h = Sha256::new();
                    h.update(data);
                    ("rsa-sha2-256", DIGEST_INFO_SHA256, h.finalize().to_vec())
                }
                _ => ("ssh-rsa", DIGEST_INFO_SHA1, sha1_digest(data).to_vec()),
            }
        };

        let k = self.n.byte_len();
        let t_len = prefix.len() + digest.len();
        if k < t_len + 11 {
            return Err(SshKeyError::InvalidFormat(
                "RSA modulus too short for PKCS#1 v1.5 signature".to_string(),
            ));
        }

        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x01);
        em.resize(k - t_len - 1, 0xff);
        em.push(0x00);
        em.extend_from_slice(prefix);
        em.extend_from_slice(&digest);

        let m = BigUint::from_be_bytes(&em);
        let s = self.raw_private_op(&m);
        let sig_bytes = s.to_be_bytes_padded(k);

        let mut sig_blob = Vec::with_capacity(4 + sig_algo.len() + 4 + sig_bytes.len());
        write_ssh_string(&mut sig_blob, sig_algo);
        write_ssh_bytes(&mut sig_blob, &sig_bytes);
        Ok(sig_blob)
    }

    pub fn verify_ssh_signature(
        &self,
        data: &[u8],
        algo: &str,
        raw_sig: &[u8],
    ) -> Result<(), SshKeyError> {
        let (prefix, digest) = match algo {
            "rsa-sha2-512" => {
                let mut h = Sha512::new();
                h.update(data);
                (DIGEST_INFO_SHA512, h.finalize().to_vec())
            }
            "rsa-sha2-256" => {
                let mut h = Sha256::new();
                h.update(data);
                (DIGEST_INFO_SHA256, h.finalize().to_vec())
            }
            "ssh-rsa" => (DIGEST_INFO_SHA1, sha1_digest(data).to_vec()),
            other => {
                return Err(SshKeyError::SignatureVerificationFailed(format!(
                    "unexpected RSA signature algorithm '{other}'"
                )))
            }
        };

        let k = self.n.byte_len();
        let t_len = prefix.len() + digest.len();
        let mut expected_em = Vec::with_capacity(k);
        expected_em.push(0x00);
        expected_em.push(0x01);
        expected_em.resize(k - t_len - 1, 0xff);
        expected_em.push(0x00);
        expected_em.extend_from_slice(prefix);
        expected_em.extend_from_slice(&digest);

        let s = BigUint::from_be_bytes(raw_sig);
        let m = s.mod_pow(&self.e, &self.n);
        let actual_em = m.to_be_bytes_padded(k);
        if actual_em != expected_em {
            return Err(SshKeyError::SignatureVerificationFailed(
                "RSA PKCS#1 v1.5 signature mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn parse_openssh_rsa_private_fields(
    cursor: &mut &[u8],
) -> Result<(RsaPrivateKey, String), SshKeyError> {
    let n = BigUint::from_be_bytes(
        read_bytes(cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa n".to_string()))?,
    );
    let e = BigUint::from_be_bytes(
        read_bytes(cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa e".to_string()))?,
    );
    let d = BigUint::from_be_bytes(
        read_bytes(cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa d".to_string()))?,
    );
    let iqmp = BigUint::from_be_bytes(
        read_bytes(cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa iqmp".to_string()))?,
    );
    let p = BigUint::from_be_bytes(
        read_bytes(cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa p".to_string()))?,
    );
    let q = BigUint::from_be_bytes(
        read_bytes(cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa q".to_string()))?,
    );
    let comment = read_string(cursor)
        .ok_or_else(|| SshKeyError::InvalidFormat("truncated rsa comment".to_string()))?;
    let key = RsaPrivateKey::new(n, e, d, iqmp, p, q)?;
    Ok((key, comment))
}

pub fn parse_classic_rsa_pem(
    pem: &str,
    _passphrase: Option<&str>,
) -> Result<(RsaPrivateKey, String), SshKeyError> {
    let mut header_kind = "";
    let mut b64_body = String::new();
    let mut in_body = false;

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN RSA PRIVATE KEY-----" {
            header_kind = "PKCS1";
            in_body = true;
            continue;
        }
        if trimmed == "-----BEGIN PRIVATE KEY-----" {
            header_kind = "PKCS8";
            in_body = true;
            continue;
        }
        if trimmed.starts_with("-----END ") {
            if in_body {
                break;
            }
        }
        if in_body {
            if trimmed.contains("ENCRYPTED") {
                return Err(SshKeyError::PassphraseRequired);
            }
            if trimmed.contains(':') {
                continue;
            }
            if !trimmed.is_empty() {
                b64_body.push_str(trimmed);
            }
        }
    }

    if header_kind.is_empty() || b64_body.is_empty() {
        return Err(SshKeyError::InvalidFormat(
            "missing PEM private key body".to_string(),
        ));
    }

    let der = STANDARD
        .decode(b64_body.as_bytes())
        .map_err(|e| SshKeyError::InvalidFormat(format!("PEM base64 decode error: {e}")))?;

    let pkcs1_der = if header_kind == "PKCS8" {
        extract_pkcs1_from_pkcs8(&der)?
    } else {
        der.as_slice()
    };

    let rsa = parse_pkcs1_der(pkcs1_der)?;
    Ok((rsa, "rsa-pem-key".to_string()))
}

fn read_asn1_tag_and_value<'a>(cursor: &mut &'a [u8], expected_tag: u8) -> Option<&'a [u8]> {
    if cursor.len() < 2 || cursor[0] != expected_tag {
        return None;
    }
    let len_byte = cursor[1];
    *cursor = &cursor[2..];
    let len = if (len_byte & 0x80) == 0 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || cursor.len() < num_bytes {
            return None;
        }
        let mut l = 0usize;
        for &b in &cursor[..num_bytes] {
            l = (l << 8) | (b as usize);
        }
        *cursor = &cursor[num_bytes..];
        l
    };
    if cursor.len() < len {
        return None;
    }
    let val = &cursor[..len];
    *cursor = &cursor[len..];
    Some(val)
}

fn extract_pkcs1_from_pkcs8(der: &[u8]) -> Result<&[u8], SshKeyError> {
    let mut cur = der;
    let mut seq = read_asn1_tag_and_value(&mut cur, 0x30)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#8 outer SEQUENCE".to_string()))?;
    let _version = read_asn1_tag_and_value(&mut seq, 0x02)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#8 version".to_string()))?;
    let _alg_id = read_asn1_tag_and_value(&mut seq, 0x30)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#8 AlgorithmIdentifier".to_string()))?;
    let priv_octet = read_asn1_tag_and_value(&mut seq, 0x04)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#8 privateKey OCTET STRING".to_string()))?;
    Ok(priv_octet)
}

fn parse_pkcs1_der(der: &[u8]) -> Result<RsaPrivateKey, SshKeyError> {
    let mut cur = der;
    let mut seq = read_asn1_tag_and_value(&mut cur, 0x30)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 SEQUENCE".to_string()))?;
    let _version = read_asn1_tag_and_value(&mut seq, 0x02)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 version".to_string()))?;
    let n = BigUint::from_be_bytes(
        read_asn1_tag_and_value(&mut seq, 0x02)
            .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 modulus n".to_string()))?,
    );
    let e = BigUint::from_be_bytes(
        read_asn1_tag_and_value(&mut seq, 0x02)
            .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 publicExponent e".to_string()))?,
    );
    let d = BigUint::from_be_bytes(
        read_asn1_tag_and_value(&mut seq, 0x02)
            .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 privateExponent d".to_string()))?,
    );
    let p = BigUint::from_be_bytes(
        read_asn1_tag_and_value(&mut seq, 0x02)
            .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 prime1 p".to_string()))?,
    );
    let q = BigUint::from_be_bytes(
        read_asn1_tag_and_value(&mut seq, 0x02)
            .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 prime2 q".to_string()))?,
    );
    let _dp = read_asn1_tag_and_value(&mut seq, 0x02)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 exponent1 dp".to_string()))?;
    let _dq = read_asn1_tag_and_value(&mut seq, 0x02)
        .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 exponent2 dq".to_string()))?;
    let iqmp = BigUint::from_be_bytes(
        read_asn1_tag_and_value(&mut seq, 0x02)
            .ok_or_else(|| SshKeyError::InvalidFormat("invalid PKCS#1 coefficient iqmp".to_string()))?,
    );
    RsaPrivateKey::new(n, e, d, iqmp, p, q)
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdcu32),
                _ => (b ^ c ^ d, 0xca62c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn read_u32(cursor: &mut &[u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Some(val)
}

fn read_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return None;
    }
    let slice = &cursor[..len];
    *cursor = &cursor[len..];
    Some(slice)
}

fn read_string(cursor: &mut &[u8]) -> Option<String> {
    let bytes = read_bytes(cursor)?;
    String::from_utf8(bytes.to_vec()).ok()
}

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn write_ssh_string(buf: &mut Vec<u8>, s: &str) {
    write_ssh_bytes(buf, s.as_bytes());
}
