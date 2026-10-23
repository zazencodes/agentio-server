package protocol

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func webAssertion(t *testing.T, key *ecdsa.PrivateKey, e *Envelope, origin string, flags byte, mutate func(map[string]any)) *Envelope {
	t.Helper()
	data, _ := b64.DecodeString(e.Payload)
	challenge := sha256.Sum256(signingInput(e.Kind, data))
	client := map[string]any{"type": "webauthn.get", "challenge": b64.EncodeToString(challenge[:]), "origin": origin, "crossOrigin": false}
	if mutate != nil {
		mutate(client)
	}
	clientBytes, _ := json.Marshal(client)
	rp := sha256.Sum256([]byte("app.agentio.sh"))
	auth := append(rp[:], flags, 0, 0, 0, 0)
	hash := sha256.Sum256(clientBytes)
	sum := sha256.Sum256(append(auth, hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	out := *e
	out.Sig = b64.EncodeToString(sig)
	out.WebAuthn = &WebAuthnAssertion{ClientDataJSON: b64.EncodeToString(clientBytes), AuthenticatorData: b64.EncodeToString(auth)}
	return &out
}

func TestWebAuthnResponse(t *testing.T) {
	key, _ := NewKey()
	normal, _ := Sign(key, "dev_browser", KindResponse, SignedResponse{Request: "req_1", RequestHash: "exact-hash", Decision: DecisionApprove, Text: "with a note", Time: 1})
	e := webAssertion(t, key, normal, "https://app.agentio.sh", 5, nil)
	var out SignedResponse
	if err := e.OpenWebAuthn(&key.PublicKey, "https://app.agentio.sh", &out); err != nil {
		t.Fatal(err)
	}
	if out.Text != "with a note" {
		t.Fatal(out)
	}
	if err := e.Open(KindResponse, &key.PublicKey, &out); err == nil {
		t.Fatal("accepted as a plain signature")
	}
	for name, test := range map[string]*Envelope{
		"no assertion":    normal,
		"no verification": webAssertion(t, key, normal, "https://app.agentio.sh", 1, nil),
		"no presence":     webAssertion(t, key, normal, "https://app.agentio.sh", 4, nil),
		"wrong origin":    webAssertion(t, key, normal, "https://evil.example", 5, nil),
		"wrong challenge": webAssertion(t, key, normal, "https://app.agentio.sh", 5, func(c map[string]any) { c["challenge"] = "other" }),
		"cross origin":    webAssertion(t, key, normal, "https://app.agentio.sh", 5, func(c map[string]any) { c["crossOrigin"] = true }),
		"wrong type":      webAssertion(t, key, normal, "https://app.agentio.sh", 5, func(c map[string]any) { c["type"] = "webauthn.create" }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := test.OpenWebAuthn(&key.PublicKey, "https://app.agentio.sh", &out); err == nil {
				t.Fatal("accepted forged assertion")
			}
		})
	}
	tampered := *e
	tampered.Payload = b64.EncodeToString([]byte(`{"decision":"reject"}`))
	if tampered.OpenWebAuthn(&key.PublicKey, "https://app.agentio.sh", &out) == nil {
		t.Fatal("accepted altered response")
	}
	if e.OpenWebAuthn(&key.PublicKey, "https://other.agentio.sh", &out) == nil {
		t.Fatal("accepted altered RP")
	}
	cloned := *e
	assertion := *e.WebAuthn
	cloned.WebAuthn = &assertion
	if !e.Equal(&cloned) {
		t.Fatal("identical retry differs")
	}
	cloned.WebAuthn.AuthenticatorData = "changed"
	if e.Equal(&cloned) {
		t.Fatal("different assertion compares equal")
	}
}

func TestWebPairMACBindsOrigin(t *testing.T) {
	k := NewSecret()
	mac, err := PairMAC(k, "pair_1", "host", "device", "sensitive", "enc", "Browser", "https://app.agentio.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPairMAC(mac, k, "pair_1", "host", "device", "sensitive", "enc", "Browser", "https://app.agentio.sh") {
		t.Fatal("MAC rejected")
	}
	for _, origin := range []string{"", "https://evil.example"} {
		if CheckPairMAC(mac, k, "pair_1", "host", "device", "sensitive", "enc", "Browser", origin) {
			t.Fatal("origin substitution accepted")
		}
	}
}
