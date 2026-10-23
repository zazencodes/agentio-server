package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
)

// WebAuthnAssertion carries the authenticator's signed data. Sig in the envelope is its DER signature.
// Only sensitive browser responses use this scheme; the origin is pinned by the terminal at pairing.
type WebAuthnAssertion struct {
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
}

func ValidateWebAuthnOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return errors.New("WebAuthn origin must be an HTTPS origin (or localhost for development)")
	}
	return nil
}

// OpenWebAuthn verifies the response challenge, RP binding, origin, user presence and user verification
// before decoding payload. No server-authenticated fact grants authority here.
func (e *Envelope) OpenWebAuthn(pub *ecdsa.PublicKey, origin string, out any) error {
	if e == nil || e.V != 1 || e.Kind != KindResponse || e.WebAuthn == nil {
		return errors.New("expected a WebAuthn response")
	}
	if err := ValidateWebAuthnOrigin(origin); err != nil {
		return err
	}
	payload, err := b64.DecodeString(e.Payload)
	if err != nil {
		return err
	}
	client, err := b64.DecodeString(e.WebAuthn.ClientDataJSON)
	if err != nil {
		return err
	}
	auth, err := b64.DecodeString(e.WebAuthn.AuthenticatorData)
	if err != nil {
		return err
	}
	sig, err := b64.DecodeString(e.Sig)
	if err != nil {
		return err
	}
	var data struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
		TopOrigin   string `json:"topOrigin"`
	}
	if err := json.Unmarshal(client, &data); err != nil {
		return err
	}
	challenge := sha256.Sum256(signingInput(e.Kind, payload))
	if data.Type != "webauthn.get" || data.Challenge != b64.EncodeToString(challenge[:]) || data.Origin != origin || data.CrossOrigin || data.TopOrigin != "" {
		return errors.New("WebAuthn client binding mismatch")
	}
	u, _ := url.Parse(origin)
	rpHash := sha256.Sum256([]byte(u.Hostname()))
	if len(auth) < 37 || !bytes.Equal(auth[:32], rpHash[:]) || auth[32]&0x05 != 0x05 {
		return errors.New("WebAuthn requires matching RP, user presence and user verification")
	}
	clientHash := sha256.Sum256(client)
	input := append(append([]byte{}, auth...), clientHash[:]...)
	sum := sha256.Sum256(input)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("bad WebAuthn signature")
	}
	return json.Unmarshal(payload, out)
}
