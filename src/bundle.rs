use crate::v1::{NodeGrant, UserCert};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BUNDLE_PREFIX: &str = "sc1_";
pub const USER_CERT_PREFIX: &str = "sc_cert_";

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("enrollment bundle must start with '{BUNDLE_PREFIX}'")]
    InvalidPrefix,
    #[error("user certificate token must start with '{USER_CERT_PREFIX}'")]
    InvalidUserCertPrefix,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protobuf decode error: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("invalid node private key seed (expected 32 bytes)")]
    InvalidPrivateKeySeed,
}

/// Encodes a signed `UserCert` into a compact `sc_cert_<base64url>` token string.
pub fn encode_user_cert_token(cert: &UserCert) -> String {
    let mut bytes = Vec::new();
    cert.encode(&mut bytes)
        .expect("prost encode cannot fail on Vec");
    format!("{USER_CERT_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Decodes an `sc_cert_<base64url>` token string into a `UserCert`.
pub fn decode_user_cert_token(token: &str) -> Result<UserCert, BundleError> {
    let candidate = token
        .split_whitespace()
        .find(|w| w.starts_with(USER_CERT_PREFIX))
        .unwrap_or_else(|| token.trim());
    let cleaned: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();
    let b64_part = cleaned
        .strip_prefix(USER_CERT_PREFIX)
        .ok_or(BundleError::InvalidUserCertPrefix)?;
    let raw = URL_SAFE_NO_PAD.decode(b64_part.trim_end_matches('='))?;
    let cert = UserCert::decode(raw.as_slice())?;
    Ok(cert)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentBundleWire {
    pub servers: Vec<String>,
    /// Base64 URL-safe encoded 32-byte Ed25519 signing key seed for this node.
    pub node_privkey_seed_b64: String,
    /// Base64 URL-safe encoded protobuf `NodeGrant`.
    pub grant_proto_b64: String,
}

#[derive(Debug, Clone)]
pub struct EnrollmentBundle {
    pub servers: Vec<String>,
    pub node_signing_key: SigningKey,
    pub grant: NodeGrant,
}

impl EnrollmentBundle {
    pub fn new(servers: Vec<String>, node_signing_key: SigningKey, grant: NodeGrant) -> Self {
        Self {
            servers,
            node_signing_key,
            grant,
        }
    }

    /// Encodes the enrollment bundle into a compact `sc1_<base64>` token string.
    pub fn encode(&self) -> Result<String, BundleError> {
        let mut grant_bytes = Vec::new();
        self.grant
            .encode(&mut grant_bytes)
            .expect("prost encode cannot fail on Vec");
        let wire = EnrollmentBundleWire {
            servers: self.servers.clone(),
            node_privkey_seed_b64: URL_SAFE_NO_PAD.encode(self.node_signing_key.to_bytes()),
            grant_proto_b64: URL_SAFE_NO_PAD.encode(grant_bytes),
        };
        let json_bytes = serde_json::to_vec(&wire)?;
        Ok(format!(
            "{BUNDLE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(json_bytes)
        ))
    }

    /// Decodes a compact `sc1_<base64>` token string (with optional `.rk_<base64_seed>` suffix)
    /// back into an `EnrollmentBundle`.
    pub fn decode(token: &str) -> Result<Self, BundleError> {
        let candidate = token
            .split_whitespace()
            .find(|w| w.starts_with(BUNDLE_PREFIX))
            .unwrap_or_else(|| token.trim());
        let cleaned: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();
        let base_token = cleaned
            .split_once(".rk_")
            .map(|(b, _)| b)
            .unwrap_or(cleaned.as_str());
        let b64_part = base_token
            .strip_prefix(BUNDLE_PREFIX)
            .ok_or(BundleError::InvalidPrefix)?;
        let json_bytes = URL_SAFE_NO_PAD.decode(b64_part.trim_end_matches('='))?;
        let wire: EnrollmentBundleWire = serde_json::from_slice(&json_bytes)?;

        let seed_vec = URL_SAFE_NO_PAD.decode(&wire.node_privkey_seed_b64)?;
        let seed: [u8; 32] = seed_vec
            .try_into()
            .map_err(|_| BundleError::InvalidPrivateKeySeed)?;
        let node_signing_key = SigningKey::from_bytes(&seed);

        let grant_bytes = URL_SAFE_NO_PAD.decode(&wire.grant_proto_b64)?;
        let grant = NodeGrant::decode(grant_bytes.as_slice())?;

        Ok(Self {
            servers: wire.servers,
            node_signing_key,
            grant,
        })
    }
}
