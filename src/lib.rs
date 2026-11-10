pub mod v1 {
    include!("pb/sockcast.v1.rs");
}

pub mod bundle;
pub mod crypto;
pub(crate) mod des3_pem;
pub(crate) mod openssh_cipher;
pub mod p2p;
pub(crate) mod rsa_ssh;
pub mod ssh;
pub mod wasm;

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

    #[test]
    fn test_zellij_p2p_signing_stun_and_cipher() {
        use super::crypto::{sign_zellij_tunnel_frame, verify_zellij_tunnel_frame};
        use super::p2p::{
            build_stun_binding_request, derive_p2p_session_keys, parse_stun_binding_response,
            P2pEndpointHandshake, P2pStreamCipher, STUN_ATTR_XOR_MAPPED_ADDRESS,
            STUN_BINDING_RESPONSE, STUN_MAGIC_COOKIE,
        };
        use super::v1::{ZellijFrameType, ZellijTunnelFrame};

        let user_sk = SigningKey::from_bytes(&[0x11; 32]);
        let client_sk = SigningKey::from_bytes(&[0x22; 32]);
        let relay_sk = SigningKey::from_bytes(&[0x33; 32]);

        let mut client_grant = NodeGrant {
            user_id: String::new(),
            user_pubkey: Vec::new(),
            node_id: "bandura".to_string(),
            role: NodeRole::Client as i32,
            node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
        };
        sign_node_grant(&mut client_grant, &user_sk);

        let mut relay_grant = NodeGrant {
            user_id: String::new(),
            user_pubkey: Vec::new(),
            node_id: "sunduk.stingr.net".to_string(),
            role: NodeRole::Relay as i32,
            node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
        };
        sign_node_grant(&mut relay_grant, &user_sk);

        let offer_hs = P2pEndpointHandshake::new(
            vec!["192.168.1.10:50001".to_string()],
            vec!["203.0.113.10:50002".to_string()],
        );
        let mut offer_frame = ZellijTunnelFrame {
            tunnel_id: "p2p-1".to_string(),
            relay_node_id: "sunduk.stingr.net".to_string(),
            client_node_id: "bandura".to_string(),
            frame_type: ZellijFrameType::P2pOffer as i32,
            payload: offer_hs.to_bytes(),
            error_message: String::new(),
            sender_grant: Some(client_grant.clone()),
            sender_signature: Vec::new(),
        };
        sign_zellij_tunnel_frame(&mut offer_frame, &client_sk).unwrap();
        assert!(verify_zellij_tunnel_frame(
            &offer_frame,
            NodeRole::Client,
            &relay_grant.user_pubkey,
            1_750_000_000
        )
        .is_ok());

        let answer_hs = P2pEndpointHandshake::new(
            vec!["192.168.1.20:60001".to_string()],
            vec!["198.51.100.20:60002".to_string()],
        );
        let mut answer_frame = ZellijTunnelFrame {
            tunnel_id: "p2p-1".to_string(),
            relay_node_id: "sunduk.stingr.net".to_string(),
            client_node_id: "bandura".to_string(),
            frame_type: ZellijFrameType::P2pAnswer as i32,
            payload: answer_hs.to_bytes(),
            error_message: String::new(),
            sender_grant: Some(relay_grant.clone()),
            sender_signature: Vec::new(),
        };
        sign_zellij_tunnel_frame(&mut answer_frame, &relay_sk).unwrap();
        assert!(verify_zellij_tunnel_frame(
            &answer_frame,
            NodeRole::Relay,
            &client_grant.user_pubkey,
            1_750_000_000
        )
        .is_ok());

        let (c_tok, r_tok, key) = derive_p2p_session_keys(
            "p2p-1",
            &offer_hs,
            &offer_frame.sender_signature,
            &answer_hs,
            &answer_frame.sender_signature,
        );
        assert_ne!(c_tok, r_tok);

        let mut enc = P2pStreamCipher::new(key, b"c2r");
        let mut dec = P2pStreamCipher::new(key, b"c2r");
        let mut buf = b"GET /work HTTP/1.1\r\nHost: 127.0.0.1:8082\r\n\r\n".to_vec();
        let orig = buf.clone();
        enc.apply_keystream(&mut buf);
        assert_ne!(buf, orig);
        dec.apply_keystream(&mut buf);
        assert_eq!(buf, orig);

        // STUN Binding Request + XOR-MAPPED-ADDRESS Response
        let (_req_pkt, tx_id) = build_stun_binding_request();
        let ip_u32 = u32::from_be_bytes([203, 0, 113, 42]) ^ STUN_MAGIC_COOKIE;
        let xport = 54321u16 ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let mut resp = Vec::new();
        resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tx_id);
        resp.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0);
        resp.push(0x01); // IPv4
        resp.extend_from_slice(&xport.to_be_bytes());
        resp.extend_from_slice(&ip_u32.to_be_bytes());

        let parsed_addr = parse_stun_binding_response(&resp, &tx_id).unwrap();
        assert_eq!(parsed_addr.to_string(), "203.0.113.42:54321");
    }

    #[test]
    fn test_openssh_private_key_parse_and_sign() {
        use super::ssh::{LoadedSshKey, SshKeyError};

        // 1. Roundtrip in-memory PEM export + import + sign + verify
        let key = LoadedSshKey::generate_ed25519("pavel@sockcast-test");
        let pem = key.to_openssh_pem();
        let parsed = LoadedSshKey::parse_openssh_pem(&pem, None).unwrap();
        assert_eq!(parsed.key_blob(), key.key_blob());
        assert_eq!(parsed.fingerprint_sha256(), key.fingerprint_sha256());
        assert_eq!(parsed.comment(), "pavel@sockcast-test");
        assert_eq!(parsed.key_type(), "ssh-ed25519");

        let challenge = b"SSH2_AGENTC_SIGN_REQUEST test challenge payload";
        let sig_blob = parsed.sign_ssh_data(challenge, 0).unwrap();
        parsed.verify_ssh_signature_blob(challenge, &sig_blob).unwrap();

        // 2. Test real ssh-keygen output (unencrypted, aes256-ctr, and chacha20-poly1305@openssh.com)
        let tmp_dir = std::env::temp_dir().join(format!("sockcast_ssh_key_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        // 2a. Unencrypted key via ssh-keygen
        let plain_path = tmp_dir.join("id_ed25519_plain");
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "plain@test",
                "-f",
                plain_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let plain_pem = std::fs::read_to_string(&plain_path).unwrap();
        let loaded_plain = LoadedSshKey::parse_openssh_pem(&plain_pem, None).unwrap();
        assert_eq!(loaded_plain.comment(), "plain@test");
        let sig = loaded_plain.sign_ssh_data(challenge, 0).unwrap();
        loaded_plain.verify_ssh_signature_blob(challenge, &sig).unwrap();

        // 2b. Encrypted key with aes256-ctr (default) via ssh-keygen
        let aes_path = tmp_dir.join("id_ed25519_aes");
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-a",
                "4",
                "-Z",
                "aes256-ctr",
                "-N",
                "correct-horse-battery-staple",
                "-C",
                "aes@test",
                "-f",
                aes_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let aes_pem = std::fs::read_to_string(&aes_path).unwrap();
        assert!(matches!(
            LoadedSshKey::parse_openssh_pem(&aes_pem, None),
            Err(SshKeyError::PassphraseRequired)
        ));
        assert!(matches!(
            LoadedSshKey::parse_openssh_pem(&aes_pem, Some("wrong-passphrase")),
            Err(SshKeyError::InvalidPassphrase)
        ));
        let loaded_aes =
            LoadedSshKey::parse_openssh_pem(&aes_pem, Some("correct-horse-battery-staple")).unwrap();
        assert_eq!(loaded_aes.comment(), "aes@test");
        let sig_aes = loaded_aes.sign_ssh_data(challenge, 0).unwrap();
        loaded_aes.verify_ssh_signature_blob(challenge, &sig_aes).unwrap();

        // 2c. Encrypted key with chacha20-poly1305@openssh.com via ssh-keygen
        let chacha_path = tmp_dir.join("id_ed25519_chacha");
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-a",
                "4",
                "-Z",
                "chacha20-poly1305@openssh.com",
                "-N",
                "chacha-passphrase",
                "-C",
                "chacha@test",
                "-f",
                chacha_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let chacha_pem = std::fs::read_to_string(&chacha_path).unwrap();
        let loaded_chacha =
            LoadedSshKey::parse_openssh_pem(&chacha_pem, Some("chacha-passphrase")).unwrap();
        assert_eq!(loaded_chacha.comment(), "chacha@test");
        let sig_chacha = loaded_chacha.sign_ssh_data(challenge, 0).unwrap();
        loaded_chacha
            .verify_ssh_signature_blob(challenge, &sig_chacha)
            .unwrap();

        // 2d. RSA key in OpenSSH format and PKCS#1 PEM format via ssh-keygen
        let rsa_openssh_path = tmp_dir.join("id_rsa_openssh");
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "rsa",
                "-b",
                "2048",
                "-N",
                "",
                "-C",
                "rsa-openssh@test",
                "-f",
                rsa_openssh_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let rsa_openssh_pem = std::fs::read_to_string(&rsa_openssh_path).unwrap();
        let loaded_rsa1 = LoadedSshKey::parse_openssh_pem(&rsa_openssh_pem, None).unwrap();
        assert_eq!(loaded_rsa1.key_type(), "ssh-rsa");
        assert_eq!(loaded_rsa1.comment(), "rsa-openssh@test");
        for flags in [0u32, 2u32, 4u32] {
            let sig = loaded_rsa1.sign_ssh_data(challenge, flags).unwrap();
            loaded_rsa1.verify_ssh_signature_blob(challenge, &sig).unwrap();
        }

        let rsa_pem_path = tmp_dir.join("id_rsa_pem");
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "rsa",
                "-b",
                "2048",
                "-m",
                "PEM",
                "-N",
                "",
                "-C",
                "rsa-pem@test",
                "-f",
                rsa_pem_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let rsa_classic_pem = std::fs::read_to_string(&rsa_pem_path).unwrap();
        assert!(rsa_classic_pem.contains("BEGIN RSA PRIVATE KEY"));
        let loaded_rsa2 = LoadedSshKey::parse_openssh_pem(&rsa_classic_pem, None).unwrap();
        assert_eq!(loaded_rsa2.key_type(), "ssh-rsa");
        let sig_rsa2 = loaded_rsa2.sign_ssh_data(challenge, 4).unwrap();
        loaded_rsa2.verify_ssh_signature_blob(challenge, &sig_rsa2).unwrap();

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_wasm_workstation_engine_flow() {
        use super::ssh::LoadedSshKey;
        use super::v1::{
            client_stream_message, server_stream_message, ClientStreamMessage, ServerStreamMessage,
        };
        use super::wasm::WasmWorkstationEngine;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use prost::Message;
        use serde_json::{json, Value};

        let user_sk = SigningKey::from_bytes(&[0x51; 32]);
        let client_sk = SigningKey::from_bytes(&[0x52; 32]);
        let relay_sk = SigningKey::from_bytes(&[0x53; 32]);
        let ssh_key = LoadedSshKey::from_ed25519_signing_key(
            SigningKey::from_bytes(&[0x66; 32]),
            "browser@chrome",
        );

        let mut client_grant = NodeGrant {
            user_id: derive_user_id(&user_sk.verifying_key().to_bytes()),
            user_pubkey: user_sk.verifying_key().to_bytes().to_vec(),
            node_id: "chrome-workstation".to_string(),
            role: NodeRole::Client as i32,
            node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
        };
        sign_node_grant(&mut client_grant, &user_sk);

        let bundle = EnrollmentBundle::new(
            vec!["https://coord.example.com:8443".to_string()],
            client_sk,
            client_grant,
        );
        let bundle_token = format!("{}.rk_dGVzdC1yb290LWtleS1zdWZmaXg", bundle.encode().unwrap());

        let mut engine = WasmWorkstationEngine::new();

        // 1. Set enrollment bundle
        let r1 = engine.call_value(json!({
            "op": "set_bundle",
            "bundle_str": bundle_token,
            "now_unix_sec": 1_750_000_000u64,
        }));
        assert_eq!(r1["ok"], Value::Bool(true));
        assert_eq!(r1["ws_url"], "wss://coord.example.com:8443/ws/workstation");
        assert_eq!(r1["node_id"], "chrome-workstation");

        // 2. Add OpenSSH key
        let pem = ssh_key.to_openssh_pem();
        let r2 = engine.call_value(json!({
            "op": "add_ssh_key",
            "pem": pem,
        }));
        assert_eq!(r2["ok"], Value::Bool(true));
        assert_eq!(r2["keys"].as_array().unwrap().len(), 1);

        // 3. Build AuthHandshake frame and verify it with verify_node_auth
        let r3 = engine.call_value(json!({
            "op": "build_auth_handshake_frame",
            "now_unix_ms": 1_750_000_000_000u64,
        }));
        assert_eq!(r3["ok"], Value::Bool(true));
        let hs_bytes = STANDARD.decode(r3["frame_b64"].as_str().unwrap()).unwrap();
        let hs_msg = ClientStreamMessage::decode(hs_bytes.as_slice()).unwrap();
        let Some(client_stream_message::Payload::AuthHandshake(node_auth)) = hs_msg.payload else {
            panic!("expected AuthHandshake payload");
        };
        verify_node_auth(
            &node_auth,
            Some(NodeRole::Client),
            1_750_000_000_500,
            DEFAULT_MAX_CLOCK_SKEW_MS,
        )
        .unwrap();

        // 4. Build WorkstationStatus frame
        let r4 = engine.call_value(json!({
            "op": "build_status_frame",
            "last_input_epoch_ms": 1_750_000_000_000u64,
            "force_active": true,
        }));
        assert_eq!(r4["ok"], Value::Bool(true));
        let st_bytes = STANDARD.decode(r4["frame_b64"].as_str().unwrap()).unwrap();
        let st_msg = ClientStreamMessage::decode(st_bytes.as_slice()).unwrap();
        let Some(client_stream_message::Payload::Status(st)) = st_msg.payload else {
            panic!("expected Status payload");
        };
        assert!(st.force_active);
        assert_eq!(st.keys.len(), 1);
        assert_eq!(st.keys[0].comment, "browser@chrome");

        // 5. Decode incoming SignRequest frame from server
        let mut relay_grant = NodeGrant {
            user_id: derive_user_id(&user_sk.verifying_key().to_bytes()),
            user_pubkey: user_sk.verifying_key().to_bytes().to_vec(),
            node_id: "bastion.infra.local".to_string(),
            role: NodeRole::Relay as i32,
            node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
        };
        sign_node_grant(&mut relay_grant, &user_sk);

        let challenge = b"browser-wasm-sign-challenge";
        let mut sign_req = SignRequest {
            request_id: "req-wasm-1".to_string(),
            timestamp_unix_ms: 1_750_000_000_000,
            key_blob: ssh_key.key_blob().to_vec(),
            data: challenge.to_vec(),
            flags: 0,
            process_context: Some(ProcessContext {
                hostname: "bastion.infra.local".to_string(),
                uid: 1000,
                pid: 9001,
                comm: "ssh".to_string(),
                cmdline: "ssh prod-db".to_string(),
                cwd: "/home/pavel".to_string(),
                ancestors: vec![ProcessAncestor {
                    pid: 9000,
                    comm: "git".to_string(),
                    cmdline: "git push origin main".to_string(),
                }],
            }),
            ssh_auth_context: None,
            relay_grant: Some(relay_grant),
            relay_signature: Vec::new(),
            auth: None,
        };
        sign_sign_request(&mut sign_req, &relay_sk).unwrap();

        let srv_frame = ServerStreamMessage {
            payload: Some(server_stream_message::Payload::SignRequest(sign_req)),
        };
        let r5 = engine.call_value(json!({
            "op": "decode_server_frame",
            "frame_b64": STANDARD.encode(srv_frame.encode_to_vec()),
            "now_unix_sec": 1_750_000_000u64,
        }));
        assert_eq!(r5["ok"], Value::Bool(true));
        assert_eq!(r5["frame_type"], "sign_request");
        assert_eq!(r5["request"]["primary_tool"], "git");
        assert_eq!(r5["request"]["has_matching_key"], Value::Bool(true));

        // 6. Approve and verify signature blob
        let r6 = engine.call_value(json!({
            "op": "decide_sign_request",
            "request_id": "req-wasm-1",
            "approved": true,
        }));
        assert_eq!(r6["ok"], Value::Bool(true));
        let resp_bytes = STANDARD.decode(r6["frame_b64"].as_str().unwrap()).unwrap();
        let resp_msg = ClientStreamMessage::decode(resp_bytes.as_slice()).unwrap();
        let Some(client_stream_message::Payload::SignResponse(sr)) = resp_msg.payload else {
            panic!("expected SignResponse payload");
        };
        assert!(sr.approved);
        assert_eq!(sr.handled_by_node_id, "chrome-workstation");
        ssh_key
            .verify_ssh_signature_blob(challenge, &sr.signature_blob)
            .unwrap();
    }

    #[test]
    fn test_des3_encrypted_rsa_pem_key() {
        use super::ssh::{LoadedSshKey, SshKeyError};
        const DES3_RSA_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,01AA5FFFC3713A44

RM9DdIv31APmzuuQMyH3nOOfBglW02vSPg4QoYPIxK+kds1lqSEoCpaPs6hIuGm7
mVD+kL+3Qax9up6uD4Mu4e5KjNqObbJtrrBAJt2UfGe8pwFkvS2u4+/ieYzO6iy3
bD0QoCWCO61iAKf4w3OZOH2NeIffzavjH8gIsS6LxwGFZzSyZNwl8O0KR5szQdSZ
lwQkHnYRS4MdiA7MK1OFlZalHoMkgSbPeOy50g74pwMYpZCp/3Gx1xtCGGPwVBQr
nUGErHN6TaRfqq1jZ380CfxISaAQNQ44NdTwIXeX7c+3Wg5q1cegrg6hIDUSSI6i
Unil9xBxhwfuaDPDz2Z8FDSDExtFGe/xD+KIZnq3Dfe0tJu0Djd7Zpn3EWxEQ1k5
QX0AxYU7qVXxIwX1ZvnUkWN18Zg44uWnbI7VejRuq2OHIUQf6LWe62giJs+acMCT
QwtMI+IyxXIGJFAOuqhPvoN7KPOo6E05j9HVy+eHQlse67/p1XmgWW2punn/lRp8
+0aqO7yfiNPZbURPKB3uXS+MiH89yCDGnxOfCqgKdVk9ZWTbeMkzLF3iS5O5v7yx
+LpaM/zUv5eMXS/1Cl3PqjCkvnPjKWpEP6lWPk7Mlmmo/VCPVgPdGmmPDsE+p71y
YE8bfRhW2pt+fJLu8vg07KdG4AvjgXH1OAA0+agQA7O4pHQ/bGGlx6cICKGvOV3+
dHzsFSX02JICYJ+3xAiZKj8TjmVqhFmWMbyPkhWT4auHGVfcrOhjb3tx1VEVYjsM
tz/jnMhOnAAZ8LfXYe2LujW8mR4jPR5sKBLyBcOhS5PHaS95a7pPfH5YrNDCa+iX
66eitDxco9Ookz1eK5j4wuSwFiGaQYEAvAGptOwnVz+chjegwSnHdoZgZUAM/mWz
rgXPsdymlKYOePbLUeXrZdJ2Mik6ThLWZjcz/hjdrdUaTbHMQkNjmsJCLompMfX+
ZNOnD08karqJj7lfWW2u0y2liuxyYo6ZOk0+J/CbthiuAao3IGLrf9pCD3vFwaS5
yTDuJbFwRN5hWGY9IPNojo2TOHGjJfhOU16OOp+tIoPZzXEXoqePG/F/OX8Ht8Mg
sYvCUf1sa7hPfdZLkhqRdayDqoAv53x1ZX11QXoVg1WOYnwsnyEF5bSl68V8GuuF
SHGQrb1ZP/czgjlZYZiZu4/a+byKsdUqt/Z3LHUm3uHrBDv4Fh3jA+LXimxeZb7d
M3KEhCAj7LnMa74wvQZybAyP+sAaywjdcHa5O+oNM3Bb1mzZcPuTP8gBxTmgzw3L
Df2TTqEVzArTVfjO7kyPDQkXMJDLTPezSUTvkNSieYraIY5VXaTDcaQVo3Vs7TEZ
LnBFAFLOuc1ezW2E2VX1PLC1KIdhbZDuQFztGVjHgPRYg6Oc8Dqc9a79v50Z5Iku
jJjnnEKSNAOdHtA35wLXu54frlvdjX0ke9avrx27/XVGzfPOjN8KVUS1gwmA+BeR
nJGOFJFTXXsIfIvFV4Nrd4iTnkwq6oZaW0yjHk+4UsAJ6xqxCZUE1sQrejKhmigs
O/ovlk9wRix3IoPnrJfrDxYCOePLCipAMH2xbnNOPT+xA2MZg8a/tTAcFM+f9uEq
-----END RSA PRIVATE KEY-----";

        assert!(matches!(
            LoadedSshKey::parse_openssh_pem(DES3_RSA_PEM, None),
            Err(SshKeyError::PassphraseRequired)
        ));
        assert!(matches!(
            LoadedSshKey::parse_openssh_pem(DES3_RSA_PEM, Some("wrong")),
            Err(SshKeyError::InvalidPassphrase)
        ));
        let key = LoadedSshKey::parse_openssh_pem(DES3_RSA_PEM, Some("secret123")).unwrap();
        assert_eq!(key.public_key_proto().key_type, "ssh-rsa");
        let sig = key.sign_ssh_data(b"hello des3 rsa", 4).unwrap();
        key.verify_ssh_signature_blob(b"hello des3 rsa", &sig)
            .unwrap();
    }
}
