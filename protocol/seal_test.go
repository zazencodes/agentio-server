package protocol

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

var updateSealing = flag.Bool("update-sealing", false, "rewrite testdata/sealing-vectors.json")

// sealingVectors are shared with the web tests. Sealing with a fixed nonce is deterministic, so every implementation
// must reproduce each ciphertext exactly and open it.
type sealingVectors struct {
	HostEncPrivate   string `json:"host_enc_private"` // P-256 scalar, hex (test key only)
	HostEncKey       string `json:"host_enc_key"`
	DeviceEncPrivate string `json:"device_enc_private"`
	DeviceEncKey     string `json:"device_enc_key"`
	HostID           string `json:"host_id"`
	DeviceID         string `json:"device_id"`
	PairKey          string `json:"pair_key"` // base64url
	Frames           []struct {
		Nonce    string      `json:"nonce"`    // base64url
		Envelope Envelope    `json:"envelope"` // the plaintext, marshalled as JSON
		Frame    SealedFrame `json:"frame"`
	} `json:"frames"`
	Secret struct {
		K             string `json:"k"`
		PairID        string `json:"pair_id"`
		NameKey       string `json:"name_key"`    // SecretKey(k, InfoPairName), base64url
		ConfirmKey    string `json:"confirm_key"` // SecretKey(k, InfoPairConfirm), base64url
		Name          string `json:"name"`
		NameNonce     string `json:"name_nonce"`
		SealedName    string `json:"sealed_name"`
		Confirm       string `json:"confirm"` // plaintext
		ConfirmNonce  string `json:"confirm_nonce"`
		SealedConfirm string `json:"sealed_confirm"`
	} `json:"secret"`
}

const sealingVectorFile = "testdata/sealing-vectors.json"

func encTestKey(t *testing.T, scalar string) *ecdh.PrivateKey {
	t.Helper()
	d, err := hex.DecodeString(scalar)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealingVectors(t *testing.T) {
	if *updateSealing {
		writeSealingVectors(t)
	}
	data, err := os.ReadFile(sealingVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v sealingVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	host, device := encTestKey(t, v.HostEncPrivate), encTestKey(t, v.DeviceEncPrivate)
	if EncodeEncKey(host.PublicKey()) != v.HostEncKey || EncodeEncKey(device.PublicKey()) != v.DeviceEncKey {
		t.Fatal("public encryption keys differ")
	}
	devicePub, _ := ParseEncKey(v.DeviceEncKey)
	hostPub, _ := ParseEncKey(v.HostEncKey)
	k1, err := PairKey(host, devicePub, v.HostID, v.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := PairKey(device, hostPub, v.HostID, v.DeviceID)
	if b64.EncodeToString(k1) != v.PairKey || b64.EncodeToString(k2) != v.PairKey {
		t.Fatal("pair key differs")
	}
	for i, f := range v.Frames {
		got, err := sealFrame(k1, f.Frame.From, f.Frame.To, f.Frame.ID, f.Frame.Time, mustB64(t, f.Nonce), &f.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		if *got != f.Frame {
			t.Fatalf("frame %d: sealed %+v, want %+v", i, *got, f.Frame)
		}
		env, err := f.Frame.Open(k2)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !env.Equal(&f.Envelope) {
			t.Fatalf("frame %d opened to %+v", i, env)
		}
	}
	s := v.Secret
	nameKey, _ := SecretKey(s.K, InfoPairName)
	confirmKey, _ := SecretKey(s.K, InfoPairConfirm)
	if b64.EncodeToString(nameKey) != s.NameKey || b64.EncodeToString(confirmKey) != s.ConfirmKey {
		t.Fatal("pairing secret keys differ")
	}
	if got, _ := sealSecret(nameKey, mustB64(t, s.NameNonce), []byte(s.Name), PairNameAAD(s.PairID)); got != s.SealedName {
		t.Fatalf("sealed name %s, want %s", got, s.SealedName)
	}
	if got, _ := sealSecret(confirmKey, mustB64(t, s.ConfirmNonce), []byte(s.Confirm), PairConfirmAAD(s.PairID)); got != s.SealedConfirm {
		t.Fatalf("sealed confirmation %s, want %s", got, s.SealedConfirm)
	}
	if name, err := OpenSecret(nameKey, s.SealedName, PairNameAAD(s.PairID)); err != nil || string(name) != s.Name {
		t.Fatalf("open name: %q %v", name, err)
	}
	if _, err := OpenSecret(nameKey, s.SealedName, PairNameAAD("pair_other")); err == nil {
		t.Fatal("a sealed name opened for another pairing")
	}
}

func writeSealingVectors(t *testing.T) {
	v := sealingVectors{
		HostEncPrivate:   "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0",
		DeviceEncPrivate: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		HostID:           "hst_vector",
		DeviceID:         "dev_vector",
	}
	host, device := encTestKey(t, v.HostEncPrivate), encTestKey(t, v.DeviceEncPrivate)
	v.HostEncKey, v.DeviceEncKey = EncodeEncKey(host.PublicKey()), EncodeEncKey(device.PublicKey())
	key, err := PairKey(host, device.PublicKey(), v.HostID, v.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	v.PairKey = b64.EncodeToString(key)
	cmd := Envelope{V: 1, Kind: KindCommand, Signer: v.DeviceID, Payload: b64.EncodeToString([]byte(`{"id":"cmd_vector","text":"Ünïcödé ✓ <&>"}`)), Sig: "MEUCIQ"}
	upd := Envelope{V: 1, Kind: KindUpdate, Signer: v.HostID, Payload: b64.EncodeToString([]byte(`{"host":"hst_vector","time":1760659200,"epoch":"epo_vector"}`)), Sig: "MEQCIA"}
	frames := []struct {
		from, to, id string
		t            int64
		nonce        string
		env          Envelope
	}{
		{v.DeviceID, v.HostID, "frm_vector1", 1760659200, "AAECAwQFBgcICQoL", cmd},
		{v.HostID, v.DeviceID, "frm_vector2", 1760659201, "DA0ODxAREhMUFRYX", upd},
	}
	for _, f := range frames {
		sealed, err := sealFrame(key, f.from, f.to, f.id, f.t, mustB64(t, f.nonce), &f.env)
		if err != nil {
			t.Fatal(err)
		}
		v.Frames = append(v.Frames, struct {
			Nonce    string      `json:"nonce"`
			Envelope Envelope    `json:"envelope"`
			Frame    SealedFrame `json:"frame"`
		}{f.nonce, f.env, *sealed})
	}
	s := &v.Secret
	s.K, s.PairID, s.Name, s.Confirm = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "pair_vector", "Alex's browser ✓", `{"v":1,"kind":"pair"}`
	s.NameNonce, s.ConfirmNonce = "GBkaGxwdHh8gISIj", "JCUmJygpKissLS4v"
	nameKey, _ := SecretKey(s.K, InfoPairName)
	confirmKey, _ := SecretKey(s.K, InfoPairConfirm)
	s.NameKey, s.ConfirmKey = b64.EncodeToString(nameKey), b64.EncodeToString(confirmKey)
	s.SealedName, _ = sealSecret(nameKey, mustB64(t, s.NameNonce), []byte(s.Name), PairNameAAD(s.PairID))
	s.SealedConfirm, _ = sealSecret(confirmKey, mustB64(t, s.ConfirmNonce), []byte(s.Confirm), PairConfirmAAD(s.PairID))
	data, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(sealingVectorFile, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSealOpenRejects(t *testing.T) {
	host, _ := NewEncKey()
	device, _ := NewEncKey()
	other, _ := NewEncKey()
	key, _ := PairKey(host, device.PublicKey(), "hst_a", "dev_a")
	otherKey, _ := PairKey(other, device.PublicKey(), "hst_a", "dev_a")
	env := &Envelope{V: 1, Kind: KindUpdate, Signer: "hst_a", Payload: "e30", Sig: "AA"}
	f, err := SealFrame(key, "hst_a", "dev_a", env)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.Open(key); err != nil || !got.Equal(env) {
		t.Fatalf("open: %v", err)
	}
	mutate := map[string]func(SealedFrame) SealedFrame{
		"tampered ciphertext": func(f SealedFrame) SealedFrame {
			ct := mustB64(t, f.CT)
			ct[0] ^= 1
			f.CT = b64.EncodeToString(ct)
			return f
		},
		"re-addressed":   func(f SealedFrame) SealedFrame { f.To = "dev_b"; return f },
		"swapped from":   func(f SealedFrame) SealedFrame { f.From = "dev_a"; f.To = "hst_a"; return f },
		"changed id":     func(f SealedFrame) SealedFrame { f.ID = "frm_other"; return f },
		"changed time":   func(f SealedFrame) SealedFrame { f.Time++; return f },
		"truncated":      func(f SealedFrame) SealedFrame { f.CT = f.CT[:10]; return f },
		"bad nonce size": func(f SealedFrame) SealedFrame { f.Nonce = "AAAA"; return f },
	}
	for name, m := range mutate {
		g := m(*f)
		if _, err := g.Open(key); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := f.Open(otherKey); err == nil {
		t.Error("opened with another pair's key")
	}
	// The inner signer must be the frame's sender.
	forged, _ := SealFrame(key, "hst_a", "dev_a", &Envelope{V: 1, Kind: KindUpdate, Signer: "hst_b", Payload: "e30", Sig: "AA"})
	if _, err := forged.Open(key); err == nil || !strings.Contains(err.Error(), "someone other") {
		t.Errorf("signer mismatch: %v", err)
	}
	if _, err := ParseEncKey("AAAA"); err == nil {
		t.Error("parsed garbage as an encryption key")
	}
}

func TestFrameGuard(t *testing.T) {
	now := int64(1_000_000)
	g := NewFrameGuard()
	g.now = func() int64 { return now }
	f := &SealedFrame{ID: "frm_1", Time: now}
	if err := g.Check(f); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(f); err == nil {
		t.Fatal("replay accepted")
	}
	for _, at := range []int64{now - FrameWindow - 1, now + FrameWindow + 1} {
		if err := g.Check(&SealedFrame{ID: "frm_old", Time: at}); err == nil {
			t.Fatalf("frame at %d accepted", at)
		}
	}
	if err := g.Check(&SealedFrame{ID: "frm_2", Time: now - FrameWindow}); err != nil {
		t.Fatal(err)
	}
	// A replayed ID stays refused while its time is still acceptable.
	now += FrameWindow
	if err := g.Check(f); err == nil {
		t.Fatal("replay accepted later in the window")
	}
	// A frame sealed at the far future edge stays refused until its time is no longer acceptable.
	edge := &SealedFrame{ID: "frm_edge", Time: now + FrameWindow}
	if err := g.Check(edge); err != nil {
		t.Fatal(err)
	}
	now += 2 * FrameWindow
	if err := g.Check(edge); err == nil {
		t.Fatal("replay accepted at the window's last second")
	}
}
