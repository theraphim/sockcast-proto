use crate::v1::{NodeAuth, NodeGrant, NodeRole, SignRequest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use thiserror::Error;

pub const DOMAIN_NODE_GRANT: &[u8] = b"sockcast-node-grant-v1\x00";
pub const DOMAIN_NODE_AUTH: &[u8] = b"sockcast-rpc-auth-v1\x00";
pub const DOMAIN_SIGN_REQUEST: &[u8] = b"sockcast-sign-request-v1\x00";

pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("missing node grant")]
    MissingGrant,
    #[error("invalid Ed25519 public key (expected 32 bytes)")]
    InvalidPublicKey,
    #[error("invalid Ed25519 signature (expected 64 bytes)")]
    InvalidSignature,
    #[error("user_id or node_id is empty")]
    EmptyIdentity,
    #[error("node role is unspecified")]
    UnspecifiedRole,
    #[error("node grant has expired")]
    GrantExpired,
    #[error("invalid user signature on node grant")]
    InvalidGrantSignature,
    #[error("invalid node signature on RPC auth")]
    InvalidNodeAuthSignature,
    #[error("RPC auth timestamp outside allowed clock skew window")]
    AuthTimestampSkew,
    #[error("node role mismatch: got {got}, expected {expected}")]
    RoleMismatch { got: i32, expected: i32 },
    #[error("process_context.hostname ({hostname:?}) does not match relay grant node_id ({node_id:?})")]
    HostnameMismatch { hostname: String, node_id: String },
    #[error("invalid relay signature on sign request")]
    InvalidRelaySignature,
}

/// Derives a deterministic `user_id` string (`sc_u_<hex16>`) from a 32-byte Ed25519 user public key.
pub fn derive_user_id(user_pubkey: &[u8]) -> String {
    let prefix_len = user_pubkey.len().min(16);
    format!("sc_u_{}", hex::encode(&user_pubkey[..prefix_len]))
}

fn append_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn append_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn append_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn append_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    append_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

fn append_str(buf: &mut Vec<u8>, s: &str) {
    append_bytes(buf, s.as_bytes());
}

/// Returns the deterministic canonical byte representation of a `NodeGrant` for Ed25519 signing.
pub fn canonical_node_grant_bytes(g: &NodeGrant) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(DOMAIN_NODE_GRANT);
    append_str(&mut buf, &g.user_id);
    append_bytes(&mut buf, &g.user_pubkey);
    append_str(&mut buf, &g.node_id);
    append_u32(&mut buf, g.role as u32);
    append_bytes(&mut buf, &g.node_pubkey);
    append_u64(&mut buf, g.issued_at_unix_sec);
    append_u64(&mut buf, g.expires_at_unix_sec);
    buf
}

/// Returns the deterministic canonical byte representation of a `NodeAuth` for Ed25519 signing.
pub fn canonical_node_auth_bytes(a: &NodeAuth) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(DOMAIN_NODE_AUTH);
    let grant_sig = a
        .grant
        .as_ref()
        .map(|g| g.user_signature.as_slice())
        .unwrap_or(&[]);
    append_bytes(&mut buf, grant_sig);
    append_u64(&mut buf, a.timestamp_unix_ms);
    append_bytes(&mut buf, &a.nonce);
    buf
}

/// Returns the deterministic canonical byte representation of a `SignRequest` for end-to-end relay signing.
pub fn canonical_sign_request_bytes(r: &SignRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(DOMAIN_SIGN_REQUEST);
    append_str(&mut buf, &r.request_id);
    append_u64(&mut buf, r.timestamp_unix_ms);
    append_bytes(&mut buf, &r.key_blob);
    append_bytes(&mut buf, &r.data);
    append_u32(&mut buf, r.flags);

    if let Some(pc) = &r.process_context {
        append_str(&mut buf, &pc.hostname);
        append_u32(&mut buf, pc.uid);
        append_u32(&mut buf, pc.pid);
        append_str(&mut buf, &pc.comm);
        append_str(&mut buf, &pc.cmdline);
        append_str(&mut buf, &pc.cwd);
        append_u32(&mut buf, pc.ancestors.len() as u32);
        for anc in &pc.ancestors {
            append_u32(&mut buf, anc.pid);
            append_str(&mut buf, &anc.comm);
            append_str(&mut buf, &anc.cmdline);
        }
    } else {
        append_str(&mut buf, "");
        append_u32(&mut buf, 0);
        append_u32(&mut buf, 0);
        append_str(&mut buf, "");
        append_str(&mut buf, "");
        append_str(&mut buf, "");
        append_u32(&mut buf, 0);
    }

    if let Some(sc) = &r.ssh_auth_context {
        append_u8(&mut buf, u8::from(sc.is_userauth_request));
        append_str(&mut buf, &sc.target_username);
        append_str(&mut buf, &sc.service_name);
        append_str(&mut buf, &sc.pubkey_algorithm);
        append_bytes(&mut buf, &sc.session_id);
    } else {
        append_u8(&mut buf, 0);
        append_str(&mut buf, "");
        append_str(&mut buf, "");
        append_str(&mut buf, "");
        append_bytes(&mut buf, &[]);
    }

    let relay_grant_sig = r
        .relay_grant
        .as_ref()
        .map(|g| g.user_signature.as_slice())
        .unwrap_or(&[]);
    append_bytes(&mut buf, relay_grant_sig);
    buf
}

/// Signs `grant` in-place using the user's root Ed25519 `SigningKey`.
pub fn sign_node_grant(grant: &mut NodeGrant, user_signing_key: &SigningKey) {
    let pubkey_bytes = user_signing_key.verifying_key().to_bytes();
    grant.user_pubkey = pubkey_bytes.to_vec();
    if grant.user_id.is_empty() {
        grant.user_id = derive_user_id(&pubkey_bytes);
    }
    let msg = canonical_node_grant_bytes(grant);
    let sig = user_signing_key.sign(&msg);
    grant.user_signature = sig.to_bytes().to_vec();
}

/// Verifies a `NodeGrant`'s structure, expiration, and user Ed25519 signature.
pub fn verify_node_grant(grant: &NodeGrant, now_unix_sec: u64) -> Result<(), CryptoError> {
    let user_vk_bytes: [u8; 32] = grant
        .user_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let _node_vk_bytes: [u8; 32] = grant
        .node_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let user_vk =
        VerifyingKey::from_bytes(&user_vk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_slice(&grant.user_signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    if grant.user_id.is_empty() || grant.node_id.is_empty() {
        return Err(CryptoError::EmptyIdentity);
    }
    if grant.role == NodeRole::Unspecified as i32 {
        return Err(CryptoError::UnspecifiedRole);
    }
    if grant.expires_at_unix_sec > 0 && now_unix_sec > grant.expires_at_unix_sec {
        return Err(CryptoError::GrantExpired);
    }

    let msg = canonical_node_grant_bytes(grant);
    user_vk
        .verify(&msg, &sig)
        .map_err(|_| CryptoError::InvalidGrantSignature)
}

/// Signs a `NodeAuth` in-place using the node's Ed25519 `SigningKey`.
pub fn sign_node_auth(auth: &mut NodeAuth, node_signing_key: &SigningKey) -> Result<(), CryptoError> {
    if auth.grant.is_none() {
        return Err(CryptoError::MissingGrant);
    }
    let msg = canonical_node_auth_bytes(auth);
    let sig = node_signing_key.sign(&msg);
    auth.node_signature = sig.to_bytes().to_vec();
    Ok(())
}

/// Creates and signs a fresh `NodeAuth` token with a random 16-byte nonce.
pub fn create_node_auth(
    grant: NodeGrant,
    node_signing_key: &SigningKey,
    timestamp_unix_ms: u64,
) -> Result<NodeAuth, CryptoError> {
    let mut nonce = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut auth = NodeAuth {
        grant: Some(grant),
        timestamp_unix_ms,
        nonce,
        node_signature: Vec::new(),
    };
    sign_node_auth(&mut auth, node_signing_key)?;
    Ok(auth)
}

/// Verifies a `NodeAuth` token including its embedded `NodeGrant`, role, timestamp skew, and signature.
pub fn verify_node_auth(
    auth: &NodeAuth,
    expected_role: Option<NodeRole>,
    now_unix_ms: u64,
    max_skew_ms: u64,
) -> Result<(), CryptoError> {
    let grant = auth.grant.as_ref().ok_or(CryptoError::MissingGrant)?;
    verify_node_grant(grant, now_unix_ms / 1000)?;

    if let Some(role) = expected_role {
        if role != NodeRole::Unspecified && grant.role != role as i32 {
            return Err(CryptoError::RoleMismatch {
                got: grant.role,
                expected: role as i32,
            });
        }
    }

    let node_vk_bytes: [u8; 32] = grant
        .node_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let node_vk =
        VerifyingKey::from_bytes(&node_vk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_slice(&auth.node_signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    if max_skew_ms > 0 && now_unix_ms > 0 && max_skew_ms != u64::MAX {
        let diff = now_unix_ms.abs_diff(auth.timestamp_unix_ms);
        if diff > max_skew_ms {
            return Err(CryptoError::AuthTimestampSkew);
        }
    }

    let msg = canonical_node_auth_bytes(auth);
    node_vk
        .verify(&msg, &sig)
        .map_err(|_| CryptoError::InvalidNodeAuthSignature)
}

/// Signs a `SignRequest` in-place using the relay's Ed25519 `SigningKey`.
pub fn sign_sign_request(
    req: &mut SignRequest,
    relay_signing_key: &SigningKey,
) -> Result<(), CryptoError> {
    if req.relay_grant.is_none() {
        return Err(CryptoError::MissingGrant);
    }
    let msg = canonical_sign_request_bytes(req);
    let sig = relay_signing_key.sign(&msg);
    req.relay_signature = sig.to_bytes().to_vec();
    Ok(())
}

/// Verifies a `SignRequest` end-to-end against its `relay_grant` and checks that `process_context.hostname` matches `relay_grant.node_id`.
pub fn verify_sign_request(req: &SignRequest, now_unix_sec: u64) -> Result<(), CryptoError> {
    let grant = req.relay_grant.as_ref().ok_or(CryptoError::MissingGrant)?;
    verify_node_grant(grant, now_unix_sec)?;

    if grant.role != NodeRole::Relay as i32 {
        return Err(CryptoError::RoleMismatch {
            got: grant.role,
            expected: NodeRole::Relay as i32,
        });
    }

    if let Some(pc) = &req.process_context {
        if pc.hostname != grant.node_id {
            return Err(CryptoError::HostnameMismatch {
                hostname: pc.hostname.clone(),
                node_id: grant.node_id.clone(),
            });
        }
    }

    let relay_vk_bytes: [u8; 32] = grant
        .node_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let relay_vk =
        VerifyingKey::from_bytes(&relay_vk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_slice(&req.relay_signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    let msg = canonical_sign_request_bytes(req);
    relay_vk
        .verify(&msg, &sig)
        .map_err(|_| CryptoError::InvalidRelaySignature)
}
