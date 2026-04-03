// Package sshsig implements the OpenSSH SSHSIG wire format for Git commit signing.
package sshsig

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/benaskins/axon-sign/keys"
	"golang.org/x/crypto/ssh"
)

const (
	magic     = "SSHSIG"
	sigVer    = uint32(1)
	namespace = "git"
	hashAlg   = "sha512"
	pemType   = "SSH SIGNATURE"
)

// sshString encodes b as an SSH wire-format string: uint32 length followed by bytes.
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// buildToBeSigned constructs the blob that Ed25519 signs, per the SSHSIG spec:
//
//	"SSHSIG" || string(namespace) || string("") || string(hash_alg) || string(SHA-512(data))
func buildToBeSigned(data []byte) []byte {
	h := sha512.Sum512(data)
	var buf []byte
	buf = append(buf, []byte(magic)...)
	buf = append(buf, sshString([]byte(namespace))...)
	buf = append(buf, sshString([]byte{})...)    // reserved
	buf = append(buf, sshString([]byte(hashAlg))...)
	buf = append(buf, sshString(h[:])...)
	return buf
}

// SignCommit signs commitContent with priv using the SSHSIG format and returns
// the signature as an armored PEM block ("-----BEGIN SSH SIGNATURE-----").
func SignCommit(commitContent []byte, priv keys.PrivateKey) ([]byte, error) {
	tbs := buildToBeSigned(commitContent)
	rawSig := ed25519.Sign(ed25519.PrivateKey(priv), tbs)

	// SSH signature wire format: string(format) || string(raw_sig_bytes)
	sshSig := ssh.Signature{
		Format: "ssh-ed25519",
		Blob:   rawSig,
	}
	sigBytes := ssh.Marshal(sshSig)

	// Derive public key from private key for embedding in the blob.
	edPub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	sshPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		return nil, fmt.Errorf("sign commit: marshal public key: %w", err)
	}

	// SSHSIG blob: "SSHSIG" || uint32(version) || string(pubkey) || string(ns) ||
	//              string("") || string(hash_alg) || string(sig)
	var blob []byte
	blob = append(blob, []byte(magic)...)
	vb := make([]byte, 4)
	binary.BigEndian.PutUint32(vb, sigVer)
	blob = append(blob, vb...)
	blob = append(blob, sshString(sshPub.Marshal())...)
	blob = append(blob, sshString([]byte(namespace))...)
	blob = append(blob, sshString([]byte{})...)    // reserved
	blob = append(blob, sshString([]byte(hashAlg))...)
	blob = append(blob, sshString(sigBytes)...)

	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: blob}), nil
}

// VerifyCommit verifies a PEM-encoded SSHSIG signature against commitContent using pub.
// Returns false (not an error) when the signature does not match.
func VerifyCommit(commitContent []byte, sigPEM []byte, pub keys.PublicKey) (bool, error) {
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return false, errors.New("verify commit: invalid PEM data")
	}
	if block.Type != pemType {
		return false, fmt.Errorf("verify commit: unexpected PEM type %q", block.Type)
	}

	b := block.Bytes

	// Magic preamble.
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return false, errors.New("verify commit: invalid magic preamble")
	}
	b = b[len(magic):]

	// Version.
	if len(b) < 4 {
		return false, errors.New("verify commit: truncated version field")
	}
	if v := binary.BigEndian.Uint32(b[:4]); v != sigVer {
		return false, fmt.Errorf("verify commit: unsupported version %d", v)
	}
	b = b[4:]

	// Public key string (embedded — skip over it; verification uses the caller-supplied pub).
	_, rest, err := parseSSHString(b)
	if err != nil {
		return false, fmt.Errorf("verify commit: parse pubkey: %w", err)
	}
	b = rest

	// Namespace.
	ns, rest, err := parseSSHString(b)
	if err != nil {
		return false, fmt.Errorf("verify commit: parse namespace: %w", err)
	}
	if string(ns) != namespace {
		return false, fmt.Errorf("verify commit: unexpected namespace %q", string(ns))
	}
	b = rest

	// Reserved.
	_, rest, err = parseSSHString(b)
	if err != nil {
		return false, fmt.Errorf("verify commit: parse reserved: %w", err)
	}
	b = rest

	// Hash algorithm.
	ha, rest, err := parseSSHString(b)
	if err != nil {
		return false, fmt.Errorf("verify commit: parse hash_alg: %w", err)
	}
	if string(ha) != hashAlg {
		return false, fmt.Errorf("verify commit: unsupported hash algorithm %q", string(ha))
	}
	b = rest

	// Signature string.
	sigBytes, _, err := parseSSHString(b)
	if err != nil {
		return false, fmt.Errorf("verify commit: parse signature: %w", err)
	}

	// Decode SSH signature structure.
	var sshSig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sshSig); err != nil {
		return false, fmt.Errorf("verify commit: decode signature blob: %w", err)
	}

	// Rebuild the to-be-signed blob and verify with the caller-supplied public key.
	// ed25519.Verify uses constant-time comparison internally.
	tbs := buildToBeSigned(commitContent)
	return ed25519.Verify(ed25519.PublicKey(pub), tbs, sshSig.Blob), nil
}

// parseSSHString reads an SSH wire-format string from b, returning the string bytes
// and the remaining buffer.
func parseSSHString(b []byte) (data []byte, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("buffer too short for length prefix")
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint32(len(b)) < n {
		return nil, nil, fmt.Errorf("buffer too short: need %d bytes, have %d", n, len(b))
	}
	return b[:n], b[n:], nil
}
