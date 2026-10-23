package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/config"
	"agentio.sh/server/internal/push"
)

// fakePushService records Web Push requests and answers with status.
type fakePushService struct {
	*httptest.Server
	mu       sync.Mutex
	requests []pushRequest
	status   int
}

type pushRequest struct {
	header http.Header
	body   []byte
}

func newFakePushService(t *testing.T) *fakePushService {
	f := &fakePushService{status: http.StatusCreated}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, pushRequest{header: r.Header, body: body})
		w.WriteHeader(f.status)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakePushService) received() []pushRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pushRequest{}, f.requests...)
}

// browserSubscription is a browser's push subscription keys (RFC 8291).
type browserSubscription struct {
	key  *ecdh.PrivateKey
	auth []byte
}

func newBrowserSubscription(t *testing.T) *browserSubscription {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	return &browserSubscription{key: key, auth: auth}
}

func (b *browserSubscription) body(endpoint string) protocol.WebPushSubscription {
	enc := base64.RawURLEncoding
	return protocol.WebPushSubscription{Endpoint: endpoint, Auth: enc.EncodeToString(b.auth), P256dh: enc.EncodeToString(b.key.PublicKey().Bytes())}
}

// decrypt opens an aes128gcm Web Push message body as the browser would (RFC 8291, RFC 8188).
func (b *browserSubscription) decrypt(t *testing.T, body []byte) []byte {
	t.Helper()
	salt, idLen := body[:16], int(body[20])
	_ = binary.BigEndian.Uint32(body[16:20]) // record size
	serverKey, err := ecdh.P256().NewPublicKey(body[21 : 21+idLen])
	if err != nil {
		t.Fatal(err)
	}
	secret, err := b.key.ECDH(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	info := "WebPush: info\x00" + string(b.key.PublicKey().Bytes()) + string(serverKey.Bytes())
	ikm, _ := hkdf.Key(sha256.New, secret, b.auth, info, 32)
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	aead, _ := cipher.NewGCM(block)
	plain, err := aead.Open(nil, nonce, body[21+idLen:], nil)
	if err != nil {
		t.Fatalf("decrypting the push: %v", err)
	}
	plain = bytes.TrimRight(plain, "\x00")
	if len(plain) == 0 || plain[len(plain)-1] != 2 {
		t.Fatal("push record has no final delimiter")
	}
	return plain[:len(plain)-1]
}

func webPushHarness(t *testing.T) *harness {
	t.Helper()
	private, public, err := push.GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	return newHarness(t, func(c *config.Config) {
		c.WebPushPublicKey, c.WebPushPrivateKey, c.WebPushContact = public, private, "ops@example.test"
	})
}

// A host's push frame goes out as Web Push only for a device with no live socket, and the push service gets exactly
// the sealed push frame, encrypted again for the browser.
func TestWebPushForwarding(t *testing.T) {
	h := webPushHarness(t)
	ps := newFakePushService(t)
	p := h.pairedUser("alex")
	sub := newBrowserSubscription(t)
	h.do(http.MethodPut, "/api/v1/devices/"+p.device.id+"/webpush", sub.body(ps.URL+"/sub/1"), bearer(p.token)).expect(http.StatusOK)
	mustEqual(t, "subscriptions", h.sqlInt(`SELECT COUNT(*) FROM webpush WHERE device_id = ?`, p.device.id), 1)

	send := func() (*protocol.SealedFrame, protocol.RelayMessage) {
		f := sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindUpdate, protocol.Update{Host: p.host.id})
		pf := sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindPush, protocol.SignedPush{ID: "req_1", Host: p.host.id, Title: "Approve?"})
		p.hc.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f, Push: pf})
		return pf, p.hc.relayed(f)
	}

	// Online: the frame is delivered and no push goes out.
	if _, m := send(); m.Result != protocol.RelayDelivered {
		t.Fatalf("relayed %+v", m)
	}
	if m := p.dc.next(); m.Push != nil {
		t.Fatalf("the device was handed the push frame: %+v", m)
	}
	time.Sleep(quietPeriod)
	mustEqual(t, "pushes while online", len(ps.received()), 0)

	// Offline: the push frame goes to the push service.
	p.dc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 0 })
	pf, m := send()
	if m.Result != protocol.RelayOffline {
		t.Fatalf("relayed %+v", m)
	}
	eventually(t, func() bool { return len(ps.received()) == 1 })
	req := ps.received()[0]
	mustEqual(t, "TTL", req.header.Get("TTL"), "43200")
	mustEqual(t, "urgency", req.header.Get("Urgency"), "high")
	mustEqual(t, "encoding", req.header.Get("Content-Encoding"), "aes128gcm")
	want, _ := json.Marshal(pf)
	mustEqual(t, "payload", string(sub.decrypt(t, req.body)), string(want))

	// A push service that no longer knows the subscription deletes it.
	ps.mu.Lock()
	ps.status = http.StatusGone
	ps.mu.Unlock()
	send()
	eventually(t, func() bool { return h.sqlInt(`SELECT COUNT(*) FROM webpush`) == 0 })
	send()
	time.Sleep(quietPeriod)
	mustEqual(t, "pushes", len(ps.received()), 2)
}

func TestWebPushSubscriptions(t *testing.T) {
	h := webPushHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")
	sub := newBrowserSubscription(t)
	path := "/api/v1/devices/" + alex.device.id + "/webpush"
	for _, endpoint := range []string{"ftp://127.0.0.1/x", "http://push.example.test/x", "https://evil.example.com/fcm.googleapis.com", "not a url"} {
		h.do(http.MethodPut, path, sub.body(endpoint), bearer(alex.token)).expectError(ErrBadRequest)
	}
	body := sub.body("https://fcm.googleapis.com/fcm/send/abc")
	h.do(http.MethodPut, path, body, bearer(eve.token)).expectError(ErrNotFound)
	h.do(http.MethodPut, path, protocol.WebPushSubscription{Endpoint: body.Endpoint}, bearer(alex.token)).expectError(ErrBadRequest)
	h.do(http.MethodPut, path, body, bearer(alex.token)).expect(http.StatusOK)
	body.Endpoint = "https://updates.push.services.mozilla.com/wpush/v2/abc"
	h.do(http.MethodPut, path, body, bearer(alex.token)).expect(http.StatusOK)
	mustEqual(t, "one subscription per device", h.sqlInt(`SELECT COUNT(*) FROM webpush`), 1)
	h.do(http.MethodDelete, path, nil, bearer(eve.token)).expectError(ErrNotFound)
	h.do(http.MethodDelete, path, nil, bearer(alex.token)).expect(http.StatusOK)
	mustEqual(t, "subscriptions", h.sqlInt(`SELECT COUNT(*) FROM webpush`), 0)

	off := newHarness(t)
	p := off.pairedUser("alex")
	off.do(http.MethodPut, "/api/v1/devices/"+p.device.id+"/webpush", body, bearer(p.token)).expectError(errPushUnavailable)
}

func TestValidPushEndpoint(t *testing.T) {
	t.Parallel()
	public := &Server{cfg: &config.Config{PublicURL: "https://api.example.com"}}
	local := &Server{cfg: &config.Config{PublicURL: "http://127.0.0.1:2586"}}
	for endpoint, want := range map[string][2]bool{
		"https://fcm.googleapis.com/fcm/send/abc":                {true, true},
		"https://updates.push.services.mozilla.com/wpush/v2/abc": {true, true},
		"https://wns2-par02p.notify.windows.com/w/?token=abc":    {true, true},
		"https://web.push.apple.com/abc":                         {true, true},
		"https://169.254.169.254/latest/meta-data":               {false, false},
		"https://evil.example.com/fcm.googleapis.com":            {false, false},
		"https://fcm.googleapis.com.evil.com/x":                  {false, false},
		"http://fcm.googleapis.com/x":                            {false, false},
		"https://fcm.googleapis.com:8443/x":                      {false, false},
		"https://user@fcm.googleapis.com/x":                      {false, false},
		"http://127.0.0.1:9999/push":                             {false, true},
		"http://localhost:9999/push":                             {false, true},
		"http://10.0.0.1/push":                                   {false, false},
	} {
		if got := [2]bool{public.validPushEndpoint(endpoint), local.validPushEndpoint(endpoint)}; got != want {
			t.Errorf("%s: got %v want %v", endpoint, got, want)
		}
	}
}
