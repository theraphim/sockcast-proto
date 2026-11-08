package auth

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
)

const (
	DomainNodeGrant   = "sockcast-node-grant-v1\x00"
	DomainNodeAuth    = "sockcast-rpc-auth-v1\x00"
	DomainSignRequest = "sockcast-sign-request-v1\x00"

	// DefaultMaxClockSkewMs is the default maximum allowed clock skew (5 minutes) for RPC auth tokens.
	DefaultMaxClockSkewMs uint64 = 5 * 60 * 1000
)

var (
	ErrNilGrant             = errors.New("node grant is nil")
	ErrNilAuth              = errors.New("node auth is nil")
	ErrNilSignRequest       = errors.New("sign request is nil")
	ErrInvalidKeyLength     = errors.New("invalid Ed25519 public key length (expected 32 bytes)")
	ErrInvalidSigLength     = errors.New("invalid Ed25519 signature length (expected 64 bytes)")
	ErrEmptyIdentity        = errors.New("user_id or node_id is empty")
	ErrUnspecifiedRole      = errors.New("node role is unspecified")
	ErrGrantExpired         = errors.New("node grant has expired")
	ErrInvalidGrantSig      = errors.New("invalid user signature on node grant")
	ErrInvalidNodeAuthSig   = errors.New("invalid node signature on RPC auth")
	ErrAuthTimestampSkew    = errors.New("RPC auth timestamp outside allowed clock skew window")
	ErrRoleMismatch         = errors.New("node role does not match required role")
	ErrHostnameMismatch     = errors.New("process_context.hostname does not match relay grant node_id")
	ErrInvalidRelayGrantSig = errors.New("invalid relay signature on sign request")
)

// DeriveUserID computes a deterministic user_id from a 32-byte Ed25519 user public key.
func DeriveUserID(userPubkey []byte) string {
	if len(userPubkey) < 16 {
		return "sc_u_" + hex.EncodeToString(userPubkey)
	}
	return "sc_u_" + hex.EncodeToString(userPubkey[:16])
}

func appendU8(buf []byte, v uint8) []byte {
	return append(buf, v)
}

func appendU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func appendU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func appendBytes(buf []byte, data []byte) []byte {
	buf = appendU32(buf, uint32(len(data)))
	return append(buf, data...)
}

func appendString(buf []byte, s string) []byte {
	buf = appendU32(buf, uint32(len(s)))
	return append(buf, s...)
}

// CanonicalNodeGrantBytes returns the deterministic byte representation of a NodeGrant for Ed25519 signing.
func CanonicalNodeGrantBytes(g *sockcastv1.NodeGrant) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, DomainNodeGrant...)
	buf = appendString(buf, g.GetUserId())
	buf = appendBytes(buf, g.GetUserPubkey())
	buf = appendString(buf, g.GetNodeId())
	buf = appendU32(buf, uint32(g.GetRole()))
	buf = appendBytes(buf, g.GetNodePubkey())
	buf = appendU64(buf, g.GetIssuedAtUnixSec())
	buf = appendU64(buf, g.GetExpiresAtUnixSec())
	return buf
}

// CanonicalNodeAuthBytes returns the deterministic byte representation of a NodeAuth for Ed25519 signing.
func CanonicalNodeAuthBytes(a *sockcastv1.NodeAuth) []byte {
	buf := make([]byte, 0, 160)
	buf = append(buf, DomainNodeAuth...)
	var grantSig []byte
	if a.GetGrant() != nil {
		grantSig = a.GetGrant().GetUserSignature()
	}
	buf = appendBytes(buf, grantSig)
	buf = appendU64(buf, a.GetTimestampUnixMs())
	buf = appendBytes(buf, a.GetNonce())
	return buf
}

// CanonicalSignRequestBytes returns the deterministic byte representation of a SignRequest for end-to-end relay signing.
func CanonicalSignRequestBytes(r *sockcastv1.SignRequest) []byte {
	buf := make([]byte, 0, 512)
	buf = append(buf, DomainSignRequest...)
	buf = appendString(buf, r.GetRequestId())
	buf = appendU64(buf, r.GetTimestampUnixMs())
	buf = appendBytes(buf, r.GetKeyBlob())
	buf = appendBytes(buf, r.GetData())
	buf = appendU32(buf, r.GetFlags())

	pc := r.GetProcessContext()
	buf = appendString(buf, pc.GetHostname())
	buf = appendU32(buf, pc.GetUid())
	buf = appendU32(buf, pc.GetPid())
	buf = appendString(buf, pc.GetComm())
	buf = appendString(buf, pc.GetCmdline())
	buf = appendString(buf, pc.GetCwd())
	ancestors := pc.GetAncestors()
	buf = appendU32(buf, uint32(len(ancestors)))
	for _, anc := range ancestors {
		buf = appendU32(buf, anc.GetPid())
		buf = appendString(buf, anc.GetComm())
		buf = appendString(buf, anc.GetCmdline())
	}

	sc := r.GetSshAuthContext()
	var isUserauth uint8
	if sc.GetIsUserauthRequest() {
		isUserauth = 1
	}
	buf = appendU8(buf, isUserauth)
	buf = appendString(buf, sc.GetTargetUsername())
	buf = appendString(buf, sc.GetServiceName())
	buf = appendString(buf, sc.GetPubkeyAlgorithm())
	buf = appendBytes(buf, sc.GetSessionId())

	var relayGrantSig []byte
	if r.GetRelayGrant() != nil {
		relayGrantSig = r.GetRelayGrant().GetUserSignature()
	}
	buf = appendBytes(buf, relayGrantSig)
	return buf
}

// SignNodeGrant signs g in-place using userPrivkey (64-byte Ed25519 private key).
func SignNodeGrant(g *sockcastv1.NodeGrant, userPrivkey ed25519.PrivateKey) error {
	if g == nil {
		return ErrNilGrant
	}
	g.UserPubkey = userPrivkey.Public().(ed25519.PublicKey)
	if g.UserId == "" {
		g.UserId = DeriveUserID(g.UserPubkey)
	}
	msg := CanonicalNodeGrantBytes(g)
	g.UserSignature = ed25519.Sign(userPrivkey, msg)
	return nil
}

// VerifyNodeGrant verifies a NodeGrant's structure, expiration, and user Ed25519 signature.
func VerifyNodeGrant(g *sockcastv1.NodeGrant, nowUnixSec uint64) error {
	if g == nil {
		return ErrNilGrant
	}
	if len(g.GetUserPubkey()) != ed25519.PublicKeySize || len(g.GetNodePubkey()) != ed25519.PublicKeySize {
		return ErrInvalidKeyLength
	}
	if len(g.GetUserSignature()) != ed25519.SignatureSize {
		return ErrInvalidSigLength
	}
	if g.GetUserId() == "" || g.GetNodeId() == "" {
		return ErrEmptyIdentity
	}
	if g.GetRole() == sockcastv1.NodeRole_NODE_ROLE_UNSPECIFIED {
		return ErrUnspecifiedRole
	}
	if g.GetExpiresAtUnixSec() > 0 && nowUnixSec > g.GetExpiresAtUnixSec() {
		return ErrGrantExpired
	}
	msg := CanonicalNodeGrantBytes(g)
	if !ed25519.Verify(ed25519.PublicKey(g.GetUserPubkey()), msg, g.GetUserSignature()) {
		return ErrInvalidGrantSig
	}
	return nil
}

// SignNodeAuth signs a NodeAuth in-place using nodePrivkey.
func SignNodeAuth(a *sockcastv1.NodeAuth, nodePrivkey ed25519.PrivateKey) error {
	if a == nil || a.Grant == nil {
		return ErrNilAuth
	}
	msg := CanonicalNodeAuthBytes(a)
	a.NodeSignature = ed25519.Sign(nodePrivkey, msg)
	return nil
}

// VerifyNodeAuth verifies both the embedded NodeGrant and the RPC caller's NodeAuth signature and timestamp skew.
func VerifyNodeAuth(a *sockcastv1.NodeAuth, expectedRole sockcastv1.NodeRole, nowUnixMs uint64, maxSkewMs uint64) error {
	if a == nil || a.GetGrant() == nil {
		return ErrNilAuth
	}
	if err := VerifyNodeGrant(a.GetGrant(), nowUnixMs/1000); err != nil {
		return err
	}
	if expectedRole != sockcastv1.NodeRole_NODE_ROLE_UNSPECIFIED && a.GetGrant().GetRole() != expectedRole {
		return fmt.Errorf("%w: got %v, want %v", ErrRoleMismatch, a.GetGrant().GetRole(), expectedRole)
	}
	if len(a.GetNodeSignature()) != ed25519.SignatureSize {
		return ErrInvalidSigLength
	}
	if maxSkewMs > 0 && nowUnixMs > 0 {
		var diff uint64
		if nowUnixMs >= a.GetTimestampUnixMs() {
			diff = nowUnixMs - a.GetTimestampUnixMs()
		} else {
			diff = a.GetTimestampUnixMs() - nowUnixMs
		}
		if diff > maxSkewMs && maxSkewMs != math.MaxUint64 {
			return ErrAuthTimestampSkew
		}
	}
	msg := CanonicalNodeAuthBytes(a)
	if !ed25519.Verify(ed25519.PublicKey(a.GetGrant().GetNodePubkey()), msg, a.GetNodeSignature()) {
		return ErrInvalidNodeAuthSig
	}
	return nil
}

// SignSignRequest signs a SignRequest in-place using the relay's nodePrivkey.
func SignSignRequest(r *sockcastv1.SignRequest, relayPrivkey ed25519.PrivateKey) error {
	if r == nil || r.RelayGrant == nil {
		return ErrNilSignRequest
	}
	msg := CanonicalSignRequestBytes(r)
	r.RelaySignature = ed25519.Sign(relayPrivkey, msg)
	return nil
}

// VerifySignRequest verifies the relay's NodeGrant, enforces ProcessContext.Hostname == RelayGrant.NodeId,
// and verifies the end-to-end relay Ed25519 signature over the SignRequest.
func VerifySignRequest(r *sockcastv1.SignRequest, nowUnixSec uint64) error {
	if r == nil || r.GetRelayGrant() == nil {
		return ErrNilSignRequest
	}
	grant := r.GetRelayGrant()
	if err := VerifyNodeGrant(grant, nowUnixSec); err != nil {
		return err
	}
	if grant.GetRole() != sockcastv1.NodeRole_NODE_ROLE_RELAY {
		return fmt.Errorf("%w: sign request grant role is %v", ErrRoleMismatch, grant.GetRole())
	}
	if r.GetProcessContext() != nil && r.GetProcessContext().GetHostname() != grant.GetNodeId() {
		return fmt.Errorf("%w: context=%q vs grant=%q", ErrHostnameMismatch, r.GetProcessContext().GetHostname(), grant.GetNodeId())
	}
	if len(r.GetRelaySignature()) != ed25519.SignatureSize {
		return ErrInvalidSigLength
	}
	msg := CanonicalSignRequestBytes(r)
	if !ed25519.Verify(ed25519.PublicKey(grant.GetNodePubkey()), msg, r.GetRelaySignature()) {
		return ErrInvalidRelayGrantSig
	}
	return nil
}
