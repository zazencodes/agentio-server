package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/config"
	"agentio.sh/server/internal/push"
)

// subscription is a browser's push subscription (RFC 8291) for endpoint.
func subscription(t *testing.T, endpoint string) protocol.WebPushSubscription {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return protocol.WebPushSubscription{Endpoint: endpoint, Auth: enc.EncodeToString(make([]byte, 16)), P256dh: enc.EncodeToString(key.PublicKey().Bytes())}
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

// A browser subscribes its own device; a host's push frame then goes out as Web Push only while the device has no
// live socket, encrypted again for the browser, and a push service that no longer knows the subscription deletes it.
func TestWebPushForwarding(t *testing.T) {
	h := webPushHarness(t)
	var pushes atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusCreated)
	bodies := make(chan []byte, 8)
	ps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		pushes.Add(1)
		bodies <- body
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(ps.Close)
	p := h.pairedUser("alex")
	_, eve := h.addUser("eve")
	path := "/api/v1/devices/" + p.device.id + "/webpush"
	h.do(http.MethodPut, path, subscription(t, ps.URL+"/sub/1"), bearer(eve)).expectError(ErrNotFound)
	h.do(http.MethodPut, path, subscription(t, ps.URL+"/sub/1"), bearer(p.token)).expect(http.StatusOK)
	send := func(want string) *protocol.SealedFrame {
		f := sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindUpdate, protocol.Update{Host: p.host.id})
		pf := sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindPush, protocol.SignedPush{ID: "req_1", Host: p.host.id, Title: "Approve?"})
		p.hc.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f, Push: pf})
		mustEqual(t, "relayed", p.hc.relayed(f).Result, want)
		return pf
	}

	send(protocol.RelayDelivered)
	if m := p.dc.next(); m.Push != nil {
		t.Fatalf("the device was handed the push frame: %+v", m)
	}
	time.Sleep(quietPeriod)
	mustEqual(t, "pushes while online", pushes.Load(), 0)

	p.dc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 0 })
	pf := send(protocol.RelayOffline)
	select {
	case body := <-bodies:
		if bytes.Contains(body, []byte(pf.CT)) {
			t.Fatal("the push went out without its Web Push encryption")
		}
	case <-time.After(waitTimeout):
		t.Fatal("no push sent")
	}
	status.Store(http.StatusGone)
	send(protocol.RelayOffline)
	eventually(t, func() bool { return h.sqlInt(`SELECT COUNT(*) FROM webpush`) == 0 })
}

// Push endpoints are limited to the browsers' push services over HTTPS, and loopback only for a local server.
func TestValidPushEndpoint(t *testing.T) {
	t.Parallel()
	public := &Server{cfg: &config.Config{PublicURL: "https://api.example.com"}}
	local := &Server{cfg: &config.Config{PublicURL: "http://127.0.0.1:2586"}}
	for endpoint, want := range map[string][2]bool{
		"https://fcm.googleapis.com/fcm/send/abc":     {true, true},
		"https://web.push.apple.com/abc":              {true, true},
		"https://169.254.169.254/latest/meta-data":    {false, false},
		"https://fcm.googleapis.com.evil.com/x":       {false, false},
		"https://evil.example.com/fcm.googleapis.com": {false, false},
		"http://fcm.googleapis.com/x":                 {false, false},
		"http://127.0.0.1:9999/push":                  {false, true},
	} {
		if got := [2]bool{public.validPushEndpoint(endpoint), local.validPushEndpoint(endpoint)}; got != want {
			t.Errorf("%s: got %v want %v", endpoint, got, want)
		}
	}
}
