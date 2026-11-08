use crate::v1::{PublicKey, SshAuthContext};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

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
