pub mod v1 {
    include!("pb/sockcast.v1.rs");
}

pub mod bundle;
pub mod crypto;
pub mod ssh;

#[cfg(test)]
mod tests {
    use super::bundle::EnrollmentBundle;
    use super::crypto::{
        derive_user_id, sign_node_auth, sign_node_grant, sign_sign_request, verify_node_auth,
        verify_node_grant, verify_sign_request, CryptoError, DEFAULT_MAX_CLOCK_SKEW_MS,
    };
    use super::ssh::{parse_public_key_blob, parse_ssh_auth_context};
    use super::v1::{
        NodeAuth, NodeGrant, NodeRole, ProcessAncestor, ProcessContext, SignRequest, SshAuthContext,
    };
    use ed25519_dalek::SigningKey;

    fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    #[test]
    fn test_crypto_grant_auth_and_sign_request() {
        let user_sk = SigningKey::from_bytes(&[0x11; 32]);
        let relay_sk = SigningKey::from_bytes(&[0x22; 32]);

        let user_pk = user_sk.verifying_key().to_bytes().to_vec();
        let relay_pk = relay_sk.verifying_key().to_bytes().to_vec();

        let mut grant = NodeGrant {
            user_id: derive_user_id(&user_pk),
            user_pubkey: user_pk,
            node_id: "server-x.infra.local".to_string(),
            role: NodeRole::Relay as i32,
            node_pubkey: relay_pk,
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 1_800_000_000,
            user_signature: Vec::new(),
        };

        sign_node_grant(&mut grant, &user_sk);
        assert!(verify_node_grant(&grant, 1_750_000_000).is_ok());
        assert_eq!(
            verify_node_grant(&grant, 1_800_000_001),
            Err(CryptoError::GrantExpired)
        );

        let mut auth = NodeAuth {
            grant: Some(grant.clone()),
            timestamp_unix_ms: 1_750_000_000_000,
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
            node_signature: Vec::new(),
        };
        sign_node_auth(&mut auth, &relay_sk).unwrap();
        assert!(verify_node_auth(
            &auth,
            Some(NodeRole::Relay),
            1_750_000_010_000,
            DEFAULT_MAX_CLOCK_SKEW_MS
        )
        .is_ok());

        let mut req = SignRequest {
            request_id: "req-001".to_string(),
            timestamp_unix_ms: 1_750_000_000_000,
            key_blob: b"ssh-ed25519-pubkey-blob".to_vec(),
            data: b"challenge-payload".to_vec(),
            flags: 0,
            process_context: Some(ProcessContext {
                hostname: "server-x.infra.local".to_string(),
                uid: 1000,
                pid: 41892,
                comm: "ssh".to_string(),
                cmdline: "ssh server-y scp -t /tmp".to_string(),
                cwd: "/home/pavel/rpmbuild".to_string(),
                ancestors: vec![
                    ProcessAncestor {
                        pid: 41890,
                        comm: "scp".to_string(),
                        cmdline: "scp pkg.rpm server-y:/tmp".to_string(),
                    },
                    ProcessAncestor {
                        pid: 1890,
                        comm: "zsh".to_string(),
                        cmdline: "-zsh".to_string(),
                    },
                ],
            }),
            ssh_auth_context: Some(SshAuthContext {
                is_userauth_request: true,
                target_username: "pavel".to_string(),
                service_name: "ssh-connection".to_string(),
                pubkey_algorithm: "ssh-ed25519".to_string(),
                session_id: vec![0xaa, 0xbb, 0xcc, 0xdd],
            }),
            relay_grant: Some(grant.clone()),
            relay_signature: Vec::new(),
            auth: Some(auth),
        };

        sign_sign_request(&mut req, &relay_sk).unwrap();
        assert!(verify_sign_request(&req, 1_750_000_000).is_ok());

        // Verify byte-for-byte cross-language parity with Go pkg/auth
        assert_eq!(
            hex::encode(&grant.user_signature),
            "536e3952d407c3e13f6dba3fc5802348fd3fba43e2205515276ffff1d0397b053df4bf7e311dfabe50cbf79345a5dcce453a1bcd05cfa4888402eda67cc73b0a"
        );
        assert_eq!(
            hex::encode(&req.auth.as_ref().unwrap().node_signature),
            "9402787885b7cc02998ae7b159b361bcaf226d4f41c7c125ba6e6d6d2a94505d921b546fe6979b653006722d300ad10ccb3d038fce8b95a8fddc2a4ea326dd03"
        );
        assert_eq!(
            hex::encode(&req.relay_signature),
            "6cdcb10b935a6516d377723485df697f87a3f3e7271426fee8443678d6c4ca61e4dbafc619367334ce545c5bb9b8826488c564dee8f291a5d0b60fc3ad5a7901"
        );

        // Tamper with hostname -> must fail
        req.process_context.as_mut().unwrap().hostname = "spoofed.local".to_string();
        assert!(matches!(
            verify_sign_request(&req, 1_750_000_000),
            Err(CryptoError::HostnameMismatch { .. })
        ));
    }

    #[test]
    fn test_rfc4252_ssh_auth_context_parser() {
        let mut payload = Vec::new();
        let session_id = [0x10, 0x20, 0x30, 0x40];
        write_ssh_bytes(&mut payload, &session_id);
        payload.push(50); // SSH_MSG_USERAUTH_REQUEST
        write_ssh_bytes(&mut payload, b"root");
        write_ssh_bytes(&mut payload, b"ssh-connection");
        write_ssh_bytes(&mut payload, b"publickey");
        payload.push(1); // TRUE
        write_ssh_bytes(&mut payload, b"ssh-ed25519");
        write_ssh_bytes(&mut payload, b"dummy-pubkey-blob");

        let parsed = parse_ssh_auth_context(&payload);
        assert!(parsed.is_userauth_request);
        assert_eq!(parsed.target_username, "root");
        assert_eq!(parsed.service_name, "ssh-connection");
        assert_eq!(parsed.pubkey_algorithm, "ssh-ed25519");
        assert_eq!(parsed.session_id, session_id);

        // Non-userauth arbitrary data returns false
        let non_auth = parse_ssh_auth_context(b"arbitrary-sshsig-data");
        assert!(!non_auth.is_userauth_request);
    }

    #[test]
    fn test_parse_public_key_blob() {
        let mut blob = Vec::new();
        write_ssh_bytes(&mut blob, b"ssh-ed25519");
        write_ssh_bytes(&mut blob, &[0x42; 32]);

        let pk = parse_public_key_blob(blob.clone(), "pavel@workstation");
        assert_eq!(pk.key_type, "ssh-ed25519");
        assert_eq!(pk.comment, "pavel@workstation");
        assert!(pk.fingerprint_sha256.starts_with("SHA256:"));
    }

    #[test]
    fn test_enrollment_bundle_roundtrip() {
        let user_sk = SigningKey::from_bytes(&[0x11; 32]);
        let node_sk = SigningKey::from_bytes(&[0x33; 32]);

        let mut grant = NodeGrant {
            user_id: String::new(),
            user_pubkey: Vec::new(),
            node_id: "server-x.infra.local".to_string(),
            role: NodeRole::Relay as i32,
            node_pubkey: node_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
        };
        sign_node_grant(&mut grant, &user_sk);

        let bundle = EnrollmentBundle::new(
            vec!["https://coord1.example.com".to_string()],
            node_sk.clone(),
            grant.clone(),
        );
        let token = bundle.encode().unwrap();
        assert!(token.starts_with("sc1_"));

        let decoded = EnrollmentBundle::decode(&token).unwrap();
        assert_eq!(decoded.servers, bundle.servers);
        assert_eq!(decoded.node_signing_key.to_bytes(), node_sk.to_bytes());
        assert_eq!(decoded.grant, grant);
        assert!(verify_node_grant(&decoded.grant, 1_750_000_000).is_ok());
    }
}
