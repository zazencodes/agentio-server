package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Sealing: every frame between a host and a device is signed, then encrypted for exactly that pair (docs/api.md §6).
// The server relays sealed frames and can neither read nor forge them.

// HKDF info strings for keys derived from the pairing secret K.
const (
	InfoPairName    = "agentio/v1/pair-name"
	InfoPairConfirm = "agentio/v1/pair-confirm"
)

// Frame freshness: a recipient accepts a frame sealed within FrameWindow of its own clock, and only once within
// FrameReplayWindow (which covers the whole window in both directions).
const (
	FrameWindow       = 10 * 60
	FrameReplayWindow = 20 * 60
)

// SealedFrame is a signed Envelope encrypted for one host–device pair.
type SealedFrame struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	To    string `json:"to"`
	Time  int64  `json:"time"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// NewEncKey generates a P-256 encryption (ECDH) key.
func NewEncKey() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// EncodeEncKey returns the base64url uncompressed X9.63 encoding (65 bytes) of a P-256 ECDH public key, the same
// encoding as signing keys.
func EncodeEncKey(pub *ecdh.PublicKey) string {
	return b64.EncodeToString(pub.Bytes())
}

// ParseEncKey parses EncodeEncKey's output.
func ParseEncKey(s string) (*ecdh.PublicKey, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, errors.New("encryption key is not base64url")
	}
	if len(raw) != 65 || raw[0] != 4 {
		return nil, errors.New("not an uncompressed P-256 encryption key")
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("not an uncompressed P-256 encryption key")
	}
	return pub, nil
}

// PairKey derives the AES-256-GCM key a host and a device seal their frames with, from either side's private key and
// the other's public key.
func PairKey(own *ecdh.PrivateKey, peer *ecdh.PublicKey, hostID, deviceID string) ([]byte, error) {
	secret, err := own.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, secret, nil, "agentio/v1/seal\n"+hostID+"\n"+deviceID, 32)
}

func frameAAD(from, to, id string, t int64) []byte {
	return []byte("agentio/v1/seal\n" + from + "\n" + to + "\n" + id + "\n" + strconv.FormatInt(t, 10))
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("sealing keys are 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomNonce() []byte {
	n := make([]byte, 12)
	_, _ = rand.Read(n)
	return n
}

// SealFrame signs nothing: it encrypts an already signed envelope from one side of a pair to the other, as a new
// frame (a new ID, the current time, a random nonce).
func SealFrame(pairKey []byte, from, to string, env *Envelope) (*SealedFrame, error) {
	return sealFrame(pairKey, from, to, NewRandomID("frm_"), time.Now().Unix(), randomNonce(), env)
}

func sealFrame(pairKey []byte, from, to, id string, t int64, nonce []byte, env *Envelope) (*SealedFrame, error) {
	aead, err := gcm(pairKey)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, frameAAD(from, to, id, t))
	return &SealedFrame{ID: id, From: from, To: to, Time: t, Nonce: b64.EncodeToString(nonce), CT: b64.EncodeToString(ct)}, nil
}

// Open decrypts a frame and returns its envelope, whose signer must be the frame's sender. It checks neither the
// time nor replays (see FrameGuard), nor the envelope's signature: callers verify that against the pinned key.
func (f *SealedFrame) Open(pairKey []byte) (*Envelope, error) {
	aead, err := gcm(pairKey)
	if err != nil {
		return nil, err
	}
	nonce, err := b64.DecodeString(f.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("bad nonce")
	}
	ct, err := b64.DecodeString(f.CT)
	if err != nil {
		return nil, errors.New("ciphertext is not base64url")
	}
	plain, err := aead.Open(nil, nonce, ct, frameAAD(f.From, f.To, f.ID, f.Time))
	if err != nil {
		return nil, errors.New("doesn't decrypt")
	}
	var env Envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return nil, errors.New("sealed content is not an envelope")
	}
	if env.Signer != f.From {
		return nil, errors.New("signed by someone other than its sender")
	}
	return &env, nil
}

// FrameGuard enforces frame freshness and single use for one recipient.
type FrameGuard struct {
	mu   sync.Mutex
	seen map[string]int64 // frame ID → when it may be forgotten
	now  func() int64
}

// NewFrameGuard returns a guard that uses the system clock.
func NewFrameGuard() *FrameGuard {
	return &FrameGuard{seen: map[string]int64{}, now: func() int64 { return time.Now().Unix() }}
}

// Check accepts a frame sealed within FrameWindow of now whose ID it hasn't accepted before. Call it only after the
// frame decrypted, so a forged frame can't use up a genuine frame's ID.
func (g *FrameGuard) Check(f *SealedFrame) error {
	now := g.now()
	if f.Time < now-FrameWindow || f.Time > now+FrameWindow {
		return errors.New("sealed too long ago or in the future")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, until := range g.seen {
		if until < now { // kept through its last second, when a frame sealed at the window's far edge is still fresh
			delete(g.seen, id)
		}
	}
	if _, ok := g.seen[f.ID]; ok {
		return errors.New("frame replayed")
	}
	g.seen[f.ID] = now + FrameReplayWindow
	return nil
}

// SecretKey derives a 32-byte key from the pairing secret K for one purpose (InfoPairName, InfoPairConfirm).
func SecretKey(k, info string) ([]byte, error) {
	raw, err := b64.DecodeString(k)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("pairing secret must be 32 bytes, base64url")
	}
	return hkdf.Key(sha256.New, raw, nil, info, 32)
}

// SealSecret encrypts plaintext with AES-256-GCM as base64url(nonce || ciphertext || tag).
func SealSecret(key, plaintext []byte, aad string) (string, error) {
	return sealSecret(key, randomNonce(), plaintext, aad)
}

func sealSecret(key, nonce, plaintext []byte, aad string) (string, error) {
	aead, err := gcm(key)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(aead.Seal(append([]byte{}, nonce...), nonce, plaintext, []byte(aad))), nil
}

// OpenSecret decrypts SealSecret's output.
func OpenSecret(key []byte, sealed, aad string) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	raw, err := b64.DecodeString(sealed)
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("not a sealed value")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(aad))
	if err != nil {
		return nil, errors.New("doesn't decrypt")
	}
	return plain, nil
}

// PairNameAAD and PairConfirmAAD bind sealed pairing values to their pairing.
func PairNameAAD(pairID string) string    { return InfoPairName + "\n" + pairID }
func PairConfirmAAD(pairID string) string { return InfoPairConfirm + "\n" + pairID }
