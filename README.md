# `sockcast-proto`

Shared Protobuf wire protocol (`sockcast.v1`), Ed25519 zero-trust application cryptography (`NodeGrant`, `NodeAuth`, end-to-end signed `SignRequest`), RFC 4252 `SSH_MSG_USERAUTH_REQUEST` payload parser, and compact `sc1_<base64>` enrollment bundle codec for the **Sockcast** Roaming SSH Agent architecture.

Exported simultaneously as:
1. **Rust crate** (`sockcast-proto`) used by [`sockcast-relay`](https://github.com/theraphim/sockcast-relay) and [`sockcast-client`](https://github.com/theraphim/sockcast-client).
2. **Go module** (`github.com/theraphim/sockcast-proto`) used by [`sockcast-server`](https://github.com/theraphim/sockcast-server).

## Features
- **Zero-Trust Edge Cryptography (`src/crypto.rs` & `pkg/auth/auth.go`):**
  - Byte-for-byte cross-language canonical Ed25519 signatures for `NodeGrant` (signed by the user's root key), `NodeAuth` (per-RPC authentication with replay/skew protection), and `SignRequest` (end-to-end relay signature binding `hostname == node_id`, caller process ancestry, and challenge data).
  - Works transparently behind TLS-terminating proxies such as **Cloudflare** and **Nginx** (`grpc_pass` to `h2c`) without requiring edge mTLS client certificates.
- **RFC 4252 SSH Userauth Parser (`src/ssh.rs`):**
  - Inspects `SSH2_AGENTC_SIGN_REQUEST` payloads to extract `target_username`, `service_name`, `pubkey_algorithm`, and `session_id` when packet type `50` (`SSH_MSG_USERAUTH_REQUEST`) is signed.
- **Compact Enrollment Bundle (`src/bundle.rs`):**
  - Encodes and decodes `sc1_<base64>` tokens containing coordinator URLs, generated node Ed25519 private key seed, and user-signed `NodeGrant`.

## Testing

```bash
# Run Rust unit & cross-language parity tests
cargo test

# Run Go unit & cross-language parity tests
go test ./...
```
