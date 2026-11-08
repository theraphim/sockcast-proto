# sockcast-proto

Shared Protobuf/gRPC wire schema (`sockcast.v1`), canonical Ed25519 `NodeGrant` / `NodeAuth` / `SignRequest` cryptography, RFC 4252 `SSH_MSG_USERAUTH_REQUEST` parser, and compact `sc1_` enrollment bundle codec for **Sockcast**.

This repository serves simultaneously as:
- **A Rust crate (`Cargo.toml`)** consumed by `sockcast-relay` and `sockcast-client`.
- **A Go module (`go.mod`)** consumed by `sockcast-server`.

Both Rust (`src/pb/sockcast.v1.rs`) and Go (`gen/go/sockcast/v1/*.pb.go`) protobuf bindings are pre-generated and committed to the repository so downstream RPM / `tito` / `mock` builds do not require `protoc` at package build time.
