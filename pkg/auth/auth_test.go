package auth

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	sshcastv1 "stingr.net/go/sshcast-proto/gen/go/sshcast/v1"
)

func deterministicKeypair(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func TestNodeGrantAuthAndSignRequest(t *testing.T) {
	userPub, userPriv := deterministicKeypair(0x11)
	relayPub, relayPriv := deterministicKeypair(0x22)

	grant := &sshcastv1.NodeGrant{
		UserId:           DeriveUserID(userPub),
		UserPubkey:       userPub,
		NodeId:           "server-x.infra.local",
		Role:             sshcastv1.NodeRole_NODE_ROLE_RELAY,
		NodePubkey:       relayPub,
		IssuedAtUnixSec:  1700000000,
		ExpiresAtUnixSec: 1800000000,
	}
	if err := SignNodeGrant(grant, userPriv); err != nil {
		t.Fatalf("SignNodeGrant failed: %v", err)
	}
	if err := VerifyNodeGrant(grant, 1750000000); err != nil {
		t.Fatalf("VerifyNodeGrant failed: %v", err)
	}
	if err := VerifyNodeGrant(grant, 1800000001); err != ErrGrantExpired {
		t.Fatalf("expected ErrGrantExpired, got %v", err)
	}

	authMsg := &sshcastv1.NodeAuth{
		Grant:           grant,
		TimestampUnixMs: 1750000000000,
		Nonce:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	if err := SignNodeAuth(authMsg, relayPriv); err != nil {
		t.Fatalf("SignNodeAuth failed: %v", err)
	}
	if err := VerifyNodeAuth(authMsg, sshcastv1.NodeRole_NODE_ROLE_RELAY, 1750000010000, DefaultMaxClockSkewMs); err != nil {
		t.Fatalf("VerifyNodeAuth failed: %v", err)
	}

	req := &sshcastv1.SignRequest{
		RequestId:       "req-001",
		TimestampUnixMs: 1750000000000,
		KeyBlob:         []byte("ssh-ed25519-pubkey-blob"),
		Data:            []byte("challenge-payload"),
		Flags:           0,
		ProcessContext: &sshcastv1.ProcessContext{
			Hostname: "server-x.infra.local",
			Uid:      1000,
			Pid:      41892,
			Comm:     "ssh",
			Cmdline:  "ssh server-y scp -t /tmp",
			Cwd:      "/home/pavel/rpmbuild",
			Ancestors: []*sshcastv1.ProcessAncestor{
				{Pid: 41890, Comm: "scp", Cmdline: "scp pkg.rpm server-y:/tmp"},
				{Pid: 1890, Comm: "zsh", Cmdline: "-zsh"},
			},
		},
		SshAuthContext: &sshcastv1.SshAuthContext{
			IsUserauthRequest: true,
			TargetUsername:    "pavel",
			ServiceName:       "ssh-connection",
			PubkeyAlgorithm:   "ssh-ed25519",
			SessionId:         []byte{0xaa, 0xbb, 0xcc, 0xdd},
		},
		RelayGrant: grant,
		Auth:       authMsg,
	}
	if err := SignSignRequest(req, relayPriv); err != nil {
		t.Fatalf("SignSignRequest failed: %v", err)
	}
	if err := VerifySignRequest(req, 1750000000); err != nil {
		t.Fatalf("VerifySignRequest failed: %v", err)
	}
	t.Logf("grant_sig=%x", grant.UserSignature)
	t.Logf("auth_sig=%x", authMsg.NodeSignature)
	t.Logf("req_sig=%x", req.RelaySignature)

	// Tamper with hostname -> must fail
	req.ProcessContext.Hostname = "spoofed-host.local"
	if err := VerifySignRequest(req, 1750000000); err == nil {
		t.Fatalf("expected hostname mismatch error when hostname is spoofed")
	}
}

func TestUserCertAndNodeGrantRoundtrip(t *testing.T) {
	_, opPriv := deterministicKeypair(0x55)
	userPub, userPriv := deterministicKeypair(0x11)
	nodePub, _ := deterministicKeypair(0x22)

	cert := &sshcastv1.UserCert{
		UserId:           DeriveUserID(userPub),
		UserPubkey:       userPub,
		IssuedAtUnixSec:  1700000000,
		ExpiresAtUnixSec: 1800000000,
	}
	if err := SignUserCert(cert, opPriv); err != nil {
		t.Fatalf("SignUserCert failed: %v", err)
	}
	if err := VerifyUserCert(cert, userPub, 1750000000); err != nil {
		t.Fatalf("VerifyUserCert failed: %v", err)
	}

	tok, err := EncodeUserCertToken(cert)
	if err != nil {
		t.Fatalf("EncodeUserCertToken failed: %v", err)
	}
	decodedCert, err := DecodeUserCertToken(tok)
	if err != nil {
		t.Fatalf("DecodeUserCertToken failed: %v", err)
	}

	grant := &sshcastv1.NodeGrant{
		UserId:           DeriveUserID(userPub),
		UserPubkey:       userPub,
		NodeId:           "macbook",
		Role:             sshcastv1.NodeRole_NODE_ROLE_CLIENT,
		NodePubkey:       nodePub,
		IssuedAtUnixSec:  1700000000,
		ExpiresAtUnixSec: 0,
		UserCert:         decodedCert,
	}
	if err := SignNodeGrant(grant, userPriv); err != nil {
		t.Fatalf("SignNodeGrant failed: %v", err)
	}
	if err := VerifyNodeGrant(grant, 1750000000); err != nil {
		t.Fatalf("VerifyNodeGrant with UserCert failed: %v", err)
	}
}
