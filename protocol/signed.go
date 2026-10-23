package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Signed object kinds. A signature for one kind is never valid for another.
const (
	KindPair     = "pair"     // host → device: confirms a pairing
	KindUpdate   = "update"   // host → device: everything the bridge tells a browser (docs/api.md §10.2)
	KindPush     = "push"     // host → device: a Web Push notification
	KindRequest  = "request"  // host → device: an approval or question, inside update items
	KindSync     = "sync"     // device → host: send me what changed since a cursor
	KindTimeline = "timeline" // device → host: send me older items of a session
	KindCommand  = "command"  // device → host
	KindResponse = "response" // device → host
	KindCancel   = "cancel"   // device → host: stop a command that hasn't been delivered
	KindDelete   = "delete"   // device → host: delete a session or project and its history
	KindAway     = "away"     // device → host

	KindSettings       = "settings"        // host → device: the notification settings file, inside updates
	KindSettingsChange = "settings_change" // device → host: the complete desired settings file
)

// Envelope is a signed object. Payload is the signer's JSON, base64url-encoded; verifiers check the signature over
// those exact bytes before parsing them, and nobody re-encodes a payload.
type Envelope struct {
	V        int                `json:"v"`
	Kind     string             `json:"kind"`
	Signer   string             `json:"signer"`
	Payload  string             `json:"payload"`
	Sig      string             `json:"sig"`
	WebAuthn *WebAuthnAssertion `json:"webauthn,omitempty"`
}

// SignedRequest is an approval or question opened by a host.
type SignedRequest struct {
	Prefill   *string  `json:"prefill,omitempty"`
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Session   string   `json:"session"`
	Type      string   `json:"type"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Options   []string `json:"options"`
	Sensitive bool     `json:"sensitive"`
	Created   int64    `json:"created"`
	Expires   int64    `json:"expires"`
}

// SignedCommand is a user's message to an agent session.
type SignedCommand struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Session string `json:"session"`
	Text    string `json:"text"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
}

// SignedResponse answers one request. RequestHash binds it to the exact request payload the user saw.
type SignedResponse struct {
	Request     string `json:"request"`
	RequestHash string `json:"request_hash"`
	Decision    string `json:"decision"`
	Text        string `json:"text"`
	Time        int64  `json:"time"`
}

// SignedAway sets a host's away mode: "auto", "on" or "off".
type SignedAway struct {
	Host string `json:"host"`
	Mode string `json:"mode"`
	Time int64  `json:"time"`
}

// SignedSync asks a host for everything that changed since Since, in its history Epoch.
type SignedSync struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Since int64  `json:"since"`
	Epoch string `json:"epoch"`
	Time  int64  `json:"time"`
}

// SignedTimeline asks a host for the Limit newest items of Session with pos < Before (0: the newest).
type SignedTimeline struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Session string `json:"session"`
	Before  int64  `json:"before"`
	Limit   int    `json:"limit"`
	Time    int64  `json:"time"`
}

// MaxTimelineLimit is the most items one timeline reply carries.
const MaxTimelineLimit = 200

// SignedCancel stops a command that hasn't been delivered yet.
type SignedCancel struct {
	Host    string `json:"host"`
	Command string `json:"command"`
	Time    int64  `json:"time"`
}

// SignedDelete deletes a session, or a project and all its sessions, with their history on the computer.
type SignedDelete struct {
	Host    string `json:"host"`
	Project string `json:"project,omitempty"`
	Session string `json:"session,omitempty"`
	Time    int64  `json:"time"`
}

// SignedPush is the short notification a host attaches to a frame for Web Push.
type SignedPush struct {
	ID      string `json:"id"` // the event or request ID
	Host    string `json:"host"`
	Session string `json:"session"`
	Request string `json:"request,omitempty"` // set for requests
	Title   string `json:"title"`
	Body    string `json:"body"`
	Time    int64  `json:"time"`
}

// MaxPushFrame is the most bytes a sealed push frame's JSON may take, to fit a Web Push payload.
const MaxPushFrame = 3000

// SignedSettings is a snapshot of a host's notification settings file. Revision is the hex sha256 of the file's
// exact bytes; Builtin, Defaults and Values map keys to stored values ("always", "never" or a duration). Projects
// lists only projects with overrides, by ID and display path. Error means the file doesn't parse or validate: the
// snapshot then carries no values. Change is the outcome of the newest device change the host handled.
type SignedSettings struct {
	Host     string            `json:"host"`
	Revision string            `json:"revision"`
	Time     int64             `json:"time"`
	IdleTime bool              `json:"idle_time"` // whether the host can measure keyboard/mouse idle time
	Builtin  map[string]string `json:"builtin"`
	Defaults map[string]string `json:"defaults"`
	Projects []SettingsProject `json:"projects"`
	Change   *SettingsOutcome  `json:"change,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// SettingsProject is one project's overrides. Path (a display path such as ~/pro/x) is only in snapshots.
type SettingsProject struct {
	ID     string            `json:"id"`
	Path   string            `json:"path,omitempty"`
	Values map[string]string `json:"values"`
}

// Settings change outcomes.
const (
	SettingsApplied  = "applied"
	SettingsRejected = "rejected"
)

// SettingsOutcome reports what a host did with a device's settings change.
type SettingsOutcome struct {
	ID     string `json:"id"`
	Result string `json:"result"` // applied or rejected
	Reason string `json:"reason,omitempty"`
}

// SignedSettingsChange is the complete desired settings file, built against the snapshot revision the user saw:
// Defaults replaces [defaults] and Projects replaces every project table (a project left out has no override).
type SignedSettingsChange struct {
	ID       string            `json:"id"`
	Host     string            `json:"host"`
	Revision string            `json:"revision"`
	Defaults map[string]string `json:"defaults"`
	Projects []SettingsProject `json:"projects"`
	Created  int64             `json:"created"`
	Expires  int64             `json:"expires"`
}

// SettingsChangeLifetime is how long a settings change may wait for its host: Expires = Created + this.
const SettingsChangeLifetime = 7 * 24 * 3600

// SignedPair is the host's confirmation of a pairing, over the whole transcript.
type SignedPair struct {
	Pair                  string `json:"pair"`
	Host                  string `json:"host"`
	HostKey               string `json:"host_key"`
	HostEncKey            string `json:"host_enc_key"`
	HostName              string `json:"host_name"`
	Device                string `json:"device"`
	DeviceKey             string `json:"device_key"`
	DeviceSensitiveKey    string `json:"device_sensitive_key"`
	DeviceSensitiveOrigin string `json:"device_sensitive_origin"`
	DeviceEncKey          string `json:"device_enc_key"`
	DeviceName            string `json:"device_name"`
	Time                  int64  `json:"time"`
}

// MaxClockSkew is how far in the future a signed timestamp may be.
const MaxClockSkew = 120

var b64 = base64.RawURLEncoding

// NewKey generates a P-256 signing key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EncodePublicKey returns the base64url uncompressed X9.63 encoding (65 bytes) of a P-256 public key.
func EncodePublicKey(pub *ecdsa.PublicKey) string {
	b, err := pub.Bytes()
	if err != nil {
		panic(err) // only for keys on a curve other than P-256
	}
	return b64.EncodeToString(b)
}

// ParsePublicKey parses EncodePublicKey's output.
func ParsePublicKey(s string) (*ecdsa.PublicKey, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, errors.New("public key is not base64url")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, errors.New("not an uncompressed P-256 public key")
	}
	return pub, nil
}

// KeyID derives a signer ID ("hst_" or "dev_" + 20 base32 chars of sha256) from an encoded public key, so the
// server can neither choose nor change it.
func KeyID(prefix, publicKey string) string {
	raw, _ := b64.DecodeString(publicKey)
	sum := sha256.Sum256(raw)
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])[:20])
}

func signingInput(kind string, payload []byte) []byte {
	return append([]byte("agentio/v1/"+kind+"\n"), payload...)
}

// Sign marshals payload and signs it as kind.
func Sign(key *ecdsa.PrivateKey, signer, kind string, payload any) (*Envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signingInput(kind, data))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, err
	}
	return &Envelope{V: 1, Kind: kind, Signer: signer, Payload: b64.EncodeToString(data), Sig: b64.EncodeToString(sig)}, nil
}

// Open checks that e is a valid signature of kind by pub and decodes its payload into out.
func (e *Envelope) Open(kind string, pub *ecdsa.PublicKey, out any) error {
	if e == nil {
		return errors.New("not signed")
	}
	if e.WebAuthn != nil {
		return errors.New("WebAuthn assertions require origin-bound verification")
	}
	if e.V != 1 {
		return fmt.Errorf("unsupported envelope version %d", e.V)
	}
	if e.Kind != kind {
		return fmt.Errorf("expected a signed %s, got %q", kind, e.Kind)
	}
	data, err := b64.DecodeString(e.Payload)
	if err != nil {
		return errors.New("payload is not base64url")
	}
	sig, err := b64.DecodeString(e.Sig)
	if err != nil {
		return errors.New("signature is not base64url")
	}
	sum := sha256.Sum256(signingInput(kind, data))
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("bad signature")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("signed %s: %w", kind, err)
	}
	return nil
}

// PayloadHash is the hex sha256 of the payload bytes; responses carry it as request_hash.
func (e *Envelope) PayloadHash() string {
	data, _ := b64.DecodeString(e.Payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewSecret returns 32 random bytes, base64url-encoded (pairing secrets K and poll secrets).
func NewSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// NewRandomID returns prefix + 26 lowercase base32 characters (128 random bits), for IDs the signer chooses.
func NewRandomID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// PairMAC is the device's proof that it read the pairing secret K from the terminal's code. It binds every device key
// and the plaintext name and origin.
func PairMAC(k, pairID, hostKey, deviceKey, deviceSensitiveKey, deviceEncKey, deviceName, sensitiveOrigin string) (string, error) {
	key, err := b64.DecodeString(k)
	if err != nil || len(key) != 32 {
		return "", errors.New("pairing secret must be 32 bytes, base64url")
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("agentio/v1/pair\n" + pairID + "\n" + hostKey + "\n" + deviceKey + "\n" + deviceSensitiveKey + "\n" + deviceEncKey + "\n" +
		deviceName + "\n" + sensitiveOrigin))
	return b64.EncodeToString(m.Sum(nil)), nil
}

// CheckPairMAC reports whether mac is PairMAC of the same inputs.
func CheckPairMAC(mac, k, pairID, hostKey, deviceKey, deviceSensitiveKey, deviceEncKey, deviceName, sensitiveOrigin string) bool {
	want, err := PairMAC(k, pairID, hostKey, deviceKey, deviceSensitiveKey, deviceEncKey, deviceName, sensitiveOrigin)
	return err == nil && hmac.Equal([]byte(mac), []byte(want))
}

// Equal compares envelope contents, including the assertion bytes used for idempotent retries.
func (e *Envelope) Equal(other *Envelope) bool {
	if e == nil || other == nil {
		return e == other
	}
	a, b := *e, *other
	a.WebAuthn, b.WebAuthn = nil, nil
	return a == b && ((e.WebAuthn == nil && other.WebAuthn == nil) || (e.WebAuthn != nil && other.WebAuthn != nil && *e.WebAuthn == *other.WebAuthn))
}
