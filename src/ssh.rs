use crate::openssh_cipher::decrypt_openssh_private_section;
use crate::v1::{PublicKey, SshAuthContext};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(not(target_arch = "wasm32"))]
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const OPENSSH_AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

#[derive(Debug, Error)]
pub enum SshKeyError {
    #[error("SSH private key is encrypted; a passphrase is required")]
    PassphraseRequired,
    #[error("invalid passphrase or corrupted SSH private key (checkint mismatch)")]
    InvalidPassphrase,
    #[error("invalid OpenSSH private key format: {0}")]
    InvalidFormat(String),
    #[error("unsupported OpenSSH cipher '{0}'")]
    UnsupportedCipher(String),
    #[error("unsupported OpenSSH KDF '{0}'")]
    UnsupportedKdf(String),
    #[error("unsupported SSH key type '{0}' (supported: ssh-ed25519)")]
    UnsupportedKeyType(String),
    #[error("SSH signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

/// An in-memory SSH private key capable of advertising its RFC 4253 public key blob
/// and signing `SSH2_AGENTC_SIGN_REQUEST` challenges directly inside `sockcast-client`
/// (native or WASM) without requiring an external OS `ssh-agent`.
#[derive(Clone)]
pub struct LoadedSshKey {
    signing_key: SigningKey,
    public_key: PublicKey,
}

impl std::fmt::Debug for LoadedSshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSshKey")
            .field("key_type", &self.public_key.key_type)
            .field("fingerprint_sha256", &self.public_key.fingerprint_sha256)
            .field("comment", &self.public_key.comment)
            .finish()
    }
}

impl LoadedSshKey {
    /// Creates a `LoadedSshKey` from an `ed25519_dalek::SigningKey` and comment.
    pub fn from_ed25519_signing_key(signing_key: SigningKey, comment: impl Into<String>) -> Self {
        let verifying_key = signing_key.verifying_key();
        let key_blob = encode_ed25519_public_key_blob(&verifying_key);
        let public_key = parse_public_key_blob(key_blob, comment);
        Self {
            signing_key,
            public_key,
        }
    }

    /// Generates a fresh random `ssh-ed25519` private key.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate_ed25519(comment: impl Into<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_ed25519_signing_key(signing_key, comment)
    }

    /// Parses an OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    /// Supports both unencrypted keys (`ciphername = "none"`) and passphrase-encrypted keys
    /// (`kdfname = "bcrypt"` with `aes256-ctr` or `chacha20-poly1305@openssh.com`).
    pub fn parse_openssh_pem(pem: &str, passphrase: Option<&str>) -> Result<Self, SshKeyError> {
        let b64_body = extract_openssh_pem_body(pem)?;
        let raw = STANDARD
            .decode(b64_body.as_bytes())
            .map_err(|e| SshKeyError::InvalidFormat(format!("base64 decode error: {e}")))?;

        if !raw.starts_with(OPENSSH_AUTH_MAGIC) {
            return Err(SshKeyError::InvalidFormat(
                "missing 'openssh-key-v1\\0' magic header".to_string(),
            ));
        }
        let mut cursor = &raw[OPENSSH_AUTH_MAGIC.len()..];

        let ciphername = read_string(&mut cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated ciphername".to_string()))?;
        let kdfname = read_string(&mut cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated kdfname".to_string()))?;
        let kdfoptions = read_bytes(&mut cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated kdfoptions".to_string()))?;
        let num_keys = read_u32(&mut cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated num_keys".to_string()))?;
        if num_keys != 1 {
            return Err(SshKeyError::InvalidFormat(format!(
                "expected 1 key in OpenSSH private key, found {num_keys}"
            )));
        }

        let _pubkey_blob = read_bytes(&mut cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated pubkey_blob".to_string()))?;
        let encrypted_privkey = read_bytes(&mut cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated private key section".to_string()))?;

        let decrypted_privkey = if ciphername == "none" && kdfname == "none" {
            encrypted_privkey.to_vec()
        } else {
            let pass = passphrase
                .filter(|p| !p.is_empty())
                .ok_or(SshKeyError::PassphraseRequired)?;
            if kdfname != "bcrypt" {
                return Err(SshKeyError::UnsupportedKdf(kdfname));
            }
            let mut kdf_cursor = kdfoptions;
            let salt = read_bytes(&mut kdf_cursor)
                .ok_or_else(|| SshKeyError::InvalidFormat("truncated bcrypt salt".to_string()))?;
            let rounds = read_u32(&mut kdf_cursor)
                .ok_or_else(|| SshKeyError::InvalidFormat("truncated bcrypt rounds".to_string()))?;
            decrypt_openssh_private_section(
                &ciphername,
                pass.as_bytes(),
                salt,
                rounds,
                encrypted_privkey,
            )?
        };

        let mut priv_cursor = decrypted_privkey.as_slice();
        let check1 = read_u32(&mut priv_cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated checkint1".to_string()))?;
        let check2 = read_u32(&mut priv_cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated checkint2".to_string()))?;
        if check1 != check2 {
            return Err(SshKeyError::InvalidPassphrase);
        }

        let key_type = read_string(&mut priv_cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated private key_type".to_string()))?;
        if key_type != "ssh-ed25519" {
            return Err(SshKeyError::UnsupportedKeyType(key_type));
        }

        let pub_bytes = read_bytes(&mut priv_cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated ed25519 pubkey".to_string()))?;
        let priv_bytes = read_bytes(&mut priv_cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated ed25519 privkey".to_string()))?;
        let comment = read_string(&mut priv_cursor)
            .ok_or_else(|| SshKeyError::InvalidFormat("truncated key comment".to_string()))?;

        if pub_bytes.len() != 32 || priv_bytes.len() != 64 {
            return Err(SshKeyError::InvalidFormat(format!(
                "invalid ed25519 key lengths (pub={}, priv={})",
                pub_bytes.len(),
                priv_bytes.len()
            )));
        }

        let seed: [u8; 32] = priv_bytes[..32]
            .try_into()
            .expect("slice length checked above");
        let signing_key = SigningKey::from_bytes(&seed);
        let derived_pub = signing_key.verifying_key().to_bytes();
        if derived_pub.as_slice() != pub_bytes || &priv_bytes[32..] != pub_bytes {
            return Err(SshKeyError::InvalidFormat(
                "ed25519 public key does not match private key seed".to_string(),
            ));
        }

        Ok(Self::from_ed25519_signing_key(signing_key, comment))
    }

    /// Serializes this key as an unencrypted OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    pub fn to_openssh_pem(&self) -> String {
        let pub_bytes = self.signing_key.verifying_key().to_bytes();
        let seed_bytes = self.signing_key.to_bytes();
        let mut priv64 = Vec::with_capacity(64);
        priv64.extend_from_slice(&seed_bytes);
        priv64.extend_from_slice(&pub_bytes);

        let checkint: u32 = 0x5343_4b59;
        let mut priv_section = Vec::new();
        priv_section.extend_from_slice(&checkint.to_be_bytes());
        priv_section.extend_from_slice(&checkint.to_be_bytes());
        write_ssh_string(&mut priv_section, "ssh-ed25519");
        write_ssh_bytes(&mut priv_section, &pub_bytes);
        write_ssh_bytes(&mut priv_section, &priv64);
        write_ssh_string(&mut priv_section, &self.public_key.comment);

        let mut pad_byte = 1u8;
        while priv_section.len() % 8 != 0 {
            priv_section.push(pad_byte);
            pad_byte = pad_byte.wrapping_add(1);
        }

        let mut outer = Vec::new();
        outer.extend_from_slice(OPENSSH_AUTH_MAGIC);
        write_ssh_string(&mut outer, "none");
        write_ssh_string(&mut outer, "none");
        write_ssh_bytes(&mut outer, &[]);
        outer.extend_from_slice(&1u32.to_be_bytes());
        write_ssh_bytes(&mut outer, &self.public_key.key_blob);
        write_ssh_bytes(&mut outer, &priv_section);

        let b64 = STANDARD.encode(&outer);
        let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        out
    }

    pub fn public_key_proto(&self) -> PublicKey {
        self.public_key.clone()
    }

    pub fn key_blob(&self) -> &[u8] {
        &self.public_key.key_blob
    }

    pub fn fingerprint_sha256(&self) -> &str {
        &self.public_key.fingerprint_sha256
    }

    pub fn comment(&self) -> &str {
        &self.public_key.comment
    }

    pub fn key_type(&self) -> &str {
        &self.public_key.key_type
    }

    /// Signs `data` according to the SSH agent `SSH2_AGENTC_SIGN_REQUEST` specification
    /// and returns the RFC 4253 signature blob (`string "ssh-ed25519" || string <64-byte-sig>`).
    pub fn sign_ssh_data(&self, data: &[u8], _flags: u32) -> Result<Vec<u8>, SshKeyError> {
        let sig: Signature = self.signing_key.sign(data);
        let mut sig_blob = Vec::with_capacity(4 + 11 + 4 + 64);
        write_ssh_string(&mut sig_blob, "ssh-ed25519");
        write_ssh_bytes(&mut sig_blob, &sig.to_bytes());
        Ok(sig_blob)
    }

    /// Verifies an RFC 4253 `ssh-ed25519` signature blob against `data`.
    pub fn verify_ssh_signature_blob(
        &self,
        data: &[u8],
        sig_blob: &[u8],
    ) -> Result<(), SshKeyError> {
        let mut cursor = sig_blob;
        let algo = read_string(&mut cursor).ok_or_else(|| {
            SshKeyError::SignatureVerificationFailed("truncated signature algorithm".to_string())
        })?;
        if algo != "ssh-ed25519" {
            return Err(SshKeyError::SignatureVerificationFailed(format!(
                "unexpected signature algorithm '{algo}'"
            )));
        }
        let raw_sig = read_bytes(&mut cursor).ok_or_else(|| {
            SshKeyError::SignatureVerificationFailed("truncated signature bytes".to_string())
        })?;
        let sig = Signature::from_slice(raw_sig).map_err(|e| {
            SshKeyError::SignatureVerificationFailed(format!("invalid ed25519 signature: {e}"))
        })?;
        self.signing_key
            .verifying_key()
            .verify(data, &sig)
            .map_err(|e| SshKeyError::SignatureVerificationFailed(e.to_string()))
    }
}

pub fn encode_ed25519_public_key_blob(verifying_key: &VerifyingKey) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    write_ssh_string(&mut blob, "ssh-ed25519");
    write_ssh_bytes(&mut blob, verifying_key.as_bytes());
    blob
}

fn extract_openssh_pem_body(pem: &str) -> Result<String, SshKeyError> {
    const BEGIN_MARKER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const END_MARKER: &str = "-----END OPENSSH PRIVATE KEY-----";

    let start = pem.find(BEGIN_MARKER).ok_or_else(|| {
        SshKeyError::InvalidFormat(
            "missing '-----BEGIN OPENSSH PRIVATE KEY-----' header".to_string(),
        )
    })? + BEGIN_MARKER.len();
    let rest = &pem[start..];
    let end = rest.find(END_MARKER).ok_or_else(|| {
        SshKeyError::InvalidFormat(
            "missing '-----END OPENSSH PRIVATE KEY-----' footer".to_string(),
        )
    })?;
    let body: String = rest[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err(SshKeyError::InvalidFormat("empty PEM body".to_string()));
    }
    Ok(body)
}

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn write_ssh_string(buf: &mut Vec<u8>, s: &str) {
    write_ssh_bytes(buf, s.as_bytes());
}

fn read_u8<'a>(cursor: &mut &'a [u8]) -> Option<u8> {
    if cursor.is_empty() {
        return None;
    }
    let val = cursor[0];
    *cursor = &cursor[1..];
    Some(val)
}

fn read_u32<'a>(cursor: &mut &'a [u8]) -> Option<u32> {
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

fn read_string<'a>(cursor: &mut &'a [u8]) -> Option<String> {
    let bytes = read_bytes(cursor)?;
    std::str::from_utf8(bytes).ok().map(ToOwned::to_owned)
}

/// Parses an RFC 4252 Section 7 `SSH_MSG_USERAUTH_REQUEST` (packet type 50) signing payload
/// from `SSH2_AGENTC_SIGN_REQUEST.data`.
///
/// Format signed by the SSH agent during `publickey` authentication:
/// - `string session_id`
/// - `byte SSH_MSG_USERAUTH_REQUEST (50)`
/// - `string user_name`
/// - `string service_name` (e.g. `"ssh-connection"`)
/// - `string "publickey"`
/// - `boolean TRUE (1)`
/// - `string public_key_algorithm_name`
/// - `string public_key_blob`
pub fn parse_ssh_auth_context(data: &[u8]) -> SshAuthContext {
    let mut cursor = data;
    let Some(session_id) = read_bytes(&mut cursor) else {
        return SshAuthContext::default();
    };
    let Some(msg_type) = read_u8(&mut cursor) else {
        return SshAuthContext::default();
    };
    if msg_type != SSH_MSG_USERAUTH_REQUEST {
        return SshAuthContext::default();
    }
    let Some(target_username) = read_string(&mut cursor) else {
        return SshAuthContext::default();
    };
    let Some(service_name) = read_string(&mut cursor) else {
        return SshAuthContext::default();
    };
    let Some(method_name) = read_string(&mut cursor) else {
        return SshAuthContext::default();
    };
    if method_name != "publickey" {
        return SshAuthContext::default();
    }
    let Some(has_sig) = read_u8(&mut cursor) else {
        return SshAuthContext::default();
    };
    if has_sig == 0 {
        return SshAuthContext::default();
    }
    let Some(pubkey_algorithm) = read_string(&mut cursor) else {
        return SshAuthContext::default();
    };

    SshAuthContext {
        is_userauth_request: true,
        target_username,
        service_name,
        pubkey_algorithm,
        session_id: session_id.to_vec(),
    }
}

/// Computes the standard OpenSSH `SHA256:<base64-no-pad>` fingerprint of a raw SSH public key blob.
pub fn fingerprint_sha256(key_blob: &[u8]) -> String {
    let digest = Sha256::digest(key_blob);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

/// Extracts the SSH key type string (e.g. `"ssh-ed25519"`, `"rsa-sha2-256"`, `"ssh-rsa"`) from a raw key blob.
pub fn extract_key_type(key_blob: &[u8]) -> String {
    let mut cursor = key_blob;
    read_string(&mut cursor).unwrap_or_else(|| "unknown".to_string())
}

/// Constructs a `PublicKey` proto message from a raw SSH public key blob and comment.
pub fn parse_public_key_blob(key_blob: Vec<u8>, comment: impl Into<String>) -> PublicKey {
    let fingerprint = fingerprint_sha256(&key_blob);
    let key_type = extract_key_type(&key_blob);
    PublicKey {
        key_blob,
        comment: comment.into(),
        fingerprint_sha256: fingerprint,
        key_type,
    }
}
