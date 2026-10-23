package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/store"
)

func TestRelayRoundTrip(t *testing.T) {
	h := newHarness(t)
	p := h.pairedUser("alex")
	if len(p.dc.hello.Hosts) != 1 || p.dc.hello.Hosts[0] != (protocol.HostPresence{Host: p.host.id, Online: true}) {
		t.Fatalf("device hello %+v", p.dc.hello)
	}

	// Host → device: the browser opens and verifies what arrives.
	up := protocol.Update{Host: p.host.id, Time: time.Now().Unix(), Epoch: "epo_1", Machine: &protocol.Machine{Name: "alex-mbp"}}
	f := sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindUpdate, up)
	p.hc.frame(f)
	if m := p.hc.relayed(f); m.Result != protocol.RelayDelivered {
		t.Fatalf("relayed %+v", m)
	}
	m := p.dc.next()
	if m.Type != protocol.RelayFrame || m.Frame == nil || *m.Frame != *f || m.Push != nil {
		t.Fatalf("device got %+v", m)
	}
	env, err := m.Frame.Open(p.pk)
	if err != nil {
		t.Fatal(err)
	}
	var got protocol.Update
	if err := env.Open(protocol.KindUpdate, &p.host.sign.PublicKey, &got); err != nil || got.Machine.Name != "alex-mbp" {
		t.Fatalf("opened update %+v %v", got, err)
	}

	// Device → host, to every tab of nobody else: a second tab doesn't see the device's own frame.
	tab := h.relayDevice(p.device, p.token)
	f = sealFrom(t, p.pk, p.device.sign, p.device.id, p.host.id, protocol.KindSync, protocol.SignedSync{ID: "rpc_1", Host: p.host.id, Time: time.Now().Unix()})
	p.dc.frame(f)
	if m := p.dc.relayed(f); m.Result != protocol.RelayDelivered {
		t.Fatalf("relayed %+v", m)
	}
	if m := p.hc.next(); m.Type != protocol.RelayFrame || *m.Frame != *f {
		t.Fatalf("host got %+v", m)
	}
	tab.none()

	// A host frame reaches every open tab of its device.
	f = sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindUpdate, up)
	p.hc.frame(f)
	p.hc.relayed(f)
	for _, c := range []*relayClient{p.dc, tab} {
		if m := c.next(); m.Type != protocol.RelayFrame || m.Frame.ID != f.ID {
			t.Fatalf("tab got %+v", m)
		}
	}
}

func TestRelayPresence(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th, d := newTestHost(t, "alex-mbp"), newTestDevice(t, "browser")
	h.pair(th, d, token)
	dc := h.relayDevice(d, token)
	if len(dc.hello.Hosts) != 1 || dc.hello.Hosts[0].Online {
		t.Fatalf("hello %+v, want the host offline", dc.hello)
	}
	hc := h.relayHost(th)
	if m := dc.next(); m.Type != protocol.RelayPresence || m.Host != th.id || m.Online == nil || !*m.Online {
		t.Fatalf("presence %+v", m)
	}
	var hosts struct{ Hosts []protocol.HostInfo }
	h.do(http.MethodGet, "/api/v1/hosts", nil, bearer(token)).expect(http.StatusOK).decode(&hosts)
	if len(hosts.Hosts) != 1 || !hosts.Hosts[0].Online {
		t.Fatalf("hosts %+v", hosts)
	}

	// A new connection replaces the old one without the host ever going offline.
	hc2 := h.relayHost(th)
	if ce := hc.waitClosed(); ce.Code != websocket.StatusNormalClosure {
		t.Fatalf("replaced socket closed with %v", ce)
	}
	dc.none()
	hc2.conn.Close(websocket.StatusNormalClosure, "")
	if m := dc.next(); m.Type != protocol.RelayPresence || m.Online == nil || *m.Online {
		t.Fatalf("presence %+v, want offline", m)
	}
}

// Nothing is queued: a frame for a device with no live socket is dropped, and the device never gets it.
func TestRelayOfflineDropsFrames(t *testing.T) {
	h := newHarness(t)
	p := h.pairedUser("alex")
	p.dc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 0 })
	f := sealFrom(t, p.pk, p.host.sign, p.host.id, p.device.id, protocol.KindUpdate, protocol.Update{Host: p.host.id})
	p.hc.frame(f)
	if m := p.hc.relayed(f); m.Result != protocol.RelayOffline {
		t.Fatalf("relayed %+v", m)
	}
	dc := h.relayDevice(p.device, p.token)
	dc.none()

	p.hc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return !h.srv.relay.hostOnline(p.host.id) })
	f = sealFrom(t, p.pk, p.device.sign, p.device.id, p.host.id, protocol.KindSync, protocol.SignedSync{Host: p.host.id})
	dc.next() // presence: offline
	dc.frame(f)
	if m := dc.relayed(f); m.Result != protocol.RelayOffline {
		t.Fatalf("relayed %+v", m)
	}
}

// A connection may only send as itself.
func TestRelaySpoofedFrom(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	other := newTestHost(t, "other")

	// A host claiming to be another host.
	f := sealFrom(t, alex.pk, other.sign, other.id, alex.device.id, protocol.KindUpdate, protocol.Update{Host: other.id})
	alex.hc.frame(f)
	if ce := alex.hc.waitClosed(); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("closed with %v", ce)
	}
	alex.dc.next() // presence: offline

	// A device claiming to be its host, sending to its own host.
	f = sealFrom(t, alex.pk, alex.host.sign, alex.host.id, alex.host.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})
	alex.dc.frame(f)
	if ce := alex.dc.waitClosed(); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("closed with %v", ce)
	}
}

// Frames go only between linked hosts and devices.
func TestRelayUnlinked(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")

	// Alex's machine to Eve's browser, and Eve's browser to Alex's machine.
	f := sealFrom(t, alex.pk, alex.host.sign, alex.host.id, eve.device.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})
	alex.hc.frame(f)
	if m := alex.hc.relayed(f); m.Result != protocol.RelayRefused || m.Code != "not_paired" || m.Error == "" {
		t.Fatalf("relayed %+v", m)
	}
	f = sealFrom(t, eve.pk, eve.device.sign, eve.device.id, alex.host.id, protocol.KindCommand, protocol.SignedCommand{Host: alex.host.id})
	eve.dc.frame(f)
	if m := eve.dc.relayed(f); m.Result != protocol.RelayRefused || m.Code != "not_paired" {
		t.Fatalf("relayed %+v", m)
	}
	eve.dc.none()
	eve.hc.none()
	alex.dc.none()

	// A browser of the same account that isn't paired with this machine, and a device addressing a device.
	second := newTestHost(t, "second")
	h.pair(second, newTestDevice(t, "other browser"), alex.token)
	f = sealFrom(t, alex.pk, alex.device.sign, alex.device.id, second.id, protocol.KindSync, protocol.SignedSync{Host: second.id})
	alex.dc.frame(f)
	if m := alex.dc.relayed(f); m.Result != protocol.RelayRefused || m.Code != "not_paired" {
		t.Fatalf("relayed %+v", m)
	}
	f = sealFrom(t, alex.pk, alex.device.sign, alex.device.id, eve.device.id, protocol.KindSync, protocol.SignedSync{})
	alex.dc.frame(f)
	if m := alex.dc.relayed(f); m.Result != protocol.RelayRefused || m.Code != "not_paired" {
		t.Fatalf("relayed %+v", m)
	}
}

// Push frames come only from machines, for the same device as their frame.
func TestRelayMismatchedPush(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")
	frame := func() *protocol.SealedFrame {
		return sealFrom(t, alex.pk, alex.host.sign, alex.host.id, alex.device.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})
	}
	push := sealFrom(t, alex.pk, alex.host.sign, alex.host.id, eve.device.id, protocol.KindPush, protocol.SignedPush{Host: alex.host.id})
	alex.hc.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: frame(), Push: push})
	if ce := alex.hc.waitClosed(); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("closed with %v", ce)
	}
	alex.dc.next() // presence: offline

	f := sealFrom(t, alex.pk, alex.device.sign, alex.device.id, alex.host.id, protocol.KindSync, protocol.SignedSync{})
	alex.dc.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f, Push: f})
	if ce := alex.dc.waitClosed(); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("closed with %v", ce)
	}
	eve.dc.none()
}

func TestRelaySocketAuth(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")
	dial := func(path string, headers ...hdr) *response { return h.do(http.MethodGet, path, nil, headers...) }
	dial("/api/v1/relay/device?device="+eve.device.id, bearer(alex.token)).expectError(ErrForbidden)
	dial("/api/v1/relay/device?device=dev_nope", bearer(alex.token)).expectError(ErrForbidden)
	dial("/api/v1/relay/device?device="+alex.device.id, bearer(alex.host.token)).expectError(errHostTokenNotAllowed)
	dial("/api/v1/relay/device?device=" + alex.device.id).expectError(ErrUnauthorized)
	dial("/api/v1/relay/host", bearer(alex.token)).expectError(ErrForbidden)
	dial("/api/v1/relay/host").expectError(ErrUnauthorized)
	dial("/api/v1/relay/host", basic("alex", testPassword)).expectError(ErrUnauthorized)

	// Browsers can't set headers on WebSockets: they send the token as a query parameter.
	c := h.relay("/api/v1/relay/device?device="+alex.device.id+"&token="+alex.token, "")
	mustEqual(t, "hello", c.hello.Device, alex.device.id)
}

// The server closes a socket whose token is revoked, whose machine is removed, or whose device is unpaired.
func TestRelayClosesRevokedSockets(t *testing.T) {
	h := newHarness(t)

	t.Run("logout", func(t *testing.T) {
		alex := h.pairedUser("alex")
		h.do(http.MethodDelete, "/api/v1/account/tokens/"+h.tokenID(alex.token), nil, bearer(alex.token)).expect(http.StatusOK)
		alex.dc.waitClosed()
		alex.hc.none()
	})
	t.Run("token revoked", func(t *testing.T) {
		_, admin := h.addUser("bob")
		tab := h.login("bob", testPassword)
		th, d := newTestHost(t, "bob-mbp"), newTestDevice(t, "bob's browser")
		h.pair(th, d, admin)
		dc := h.relayDevice(d, tab)
		h.do(http.MethodDelete, "/api/v1/account/tokens/"+h.tokenID(tab), nil, bearer(admin)).expect(http.StatusOK)
		dc.waitClosed()
	})
	t.Run("machine removed", func(t *testing.T) {
		carol := h.pairedUser("carol")
		h.do(http.MethodDelete, "/api/v1/hosts/"+carol.host.id, nil, bearer(carol.token)).expect(http.StatusOK)
		carol.hc.waitClosed()
		carol.dc.waitClosed()
		h.do(http.MethodGet, "/api/v1/account", nil, bearer(carol.host.token)).expectError(ErrUnauthorized)
	})
	t.Run("machine unpairs itself", func(t *testing.T) {
		dave := h.pairedUser("dave")
		h.do(http.MethodDelete, "/api/v1/hosts/"+dave.host.id, nil, bearer(dave.host.token)).expect(http.StatusOK)
		dave.hc.waitClosed()
		dave.dc.waitClosed()
	})
	t.Run("device unpaired", func(t *testing.T) {
		erin := h.pairedUser("erin")
		h.do(http.MethodDelete, "/api/v1/devices/"+erin.device.id, nil, bearer(erin.token)).expect(http.StatusOK)
		erin.dc.waitClosed()
		erin.hc.none()
		h.do(http.MethodGet, "/api/v1/relay/device?device="+erin.device.id, nil, bearer(erin.token)).expectError(ErrForbidden)
	})
	t.Run("link removed by the machine", func(t *testing.T) {
		fay := h.pairedUser("fay")
		h.do(http.MethodDelete, "/api/v1/hosts/"+fay.host.id+"/devices/"+fay.device.id, nil, bearer(fay.host.token)).expect(http.StatusOK)
		fay.dc.waitClosed()
		dc := h.relayDevice(fay.device, fay.token)
		if len(dc.hello.Hosts) != 0 {
			t.Fatalf("hello %+v after unlinking", dc.hello)
		}
		f := sealFrom(t, fay.pk, fay.host.sign, fay.host.id, fay.device.id, protocol.KindUpdate, protocol.Update{Host: fay.host.id})
		fay.hc.frame(f)
		if m := fay.hc.relayed(f); m.Code != "not_paired" {
			t.Fatalf("relayed %+v", m)
		}
	})
	t.Run("account deleted", func(t *testing.T) {
		gus := h.pairedUser("gus")
		h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(gus.token)).expect(http.StatusOK)
		gus.dc.waitClosed()
		gus.hc.waitClosed()
	})
	t.Run("token expired", func(t *testing.T) {
		h := newHarness(t)
		h.srv.pingInterval = 50 * time.Millisecond
		u, token := h.addUser("hal")
		short := NewToken(u.ID, store.TokenUser, "", time.Now().Unix()+2)
		if err := h.srv.store.AddToken(context.Background(), short); err != nil {
			t.Fatal(err)
		}
		th, d := newTestHost(t, "hal-mbp"), newTestDevice(t, "hal's browser")
		h.pair(th, d, token)
		dc := h.relayDevice(d, short.Token)
		if ce := dc.waitClosed(); ce.Reason != "token expired" {
			t.Fatalf("closed with %v", ce)
		}
	})
}

// A client that stops answering pings is disconnected.
func TestRelayIdleTimeout(t *testing.T) {
	h := newHarness(t)
	h.srv.pingInterval, h.srv.idleTimeout = 20*time.Millisecond, 100*time.Millisecond
	alex := h.pairedUser("alex")
	if ce := alex.hc.waitClosed(); ce.Reason != "no pong" {
		t.Fatalf("closed with %v", ce)
	}
}

// An extension sees every frame before it is relayed, with its account and size, and refuses frames with an error:
// its own API error reaches the sender as the refusal, any other error is an internal one.
func TestRelayFrameHook(t *testing.T) {
	var mu sync.Mutex
	var sizes []int64
	var users []string
	limit := NewError(429, "no_more_frames", "No more frames today")
	h := newExtendedHarness(t, Extension{RelayFrame: func(_ context.Context, u *store.User, size int64) error {
		mu.Lock()
		defer mu.Unlock()
		sizes, users = append(sizes, size), append(users, u.Username)
		switch len(sizes) {
		case 3:
			return limit
		case 4:
			return errors.New("database down")
		}
		return nil
	}})
	alex := h.pairedUser("alex")
	for i := range 4 {
		f := sealFrom(t, alex.pk, alex.host.sign, alex.host.id, alex.device.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})
		alex.hc.frame(f)
		m := alex.hc.relayed(f)
		switch {
		case i < 2 && m.Result != protocol.RelayDelivered,
			i == 2 && (m.Result != protocol.RelayRefused || m.Code != "no_more_frames" || m.Error != limit.Message),
			i == 3 && (m.Result != protocol.RelayRefused || m.Code != ErrInternal.Code):
			t.Fatalf("frame %d: %+v", i, m)
		}
		if i < 2 {
			alex.dc.next()
		}
	}
	alex.dc.none()
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 4 || sizes[0] < 100 || users[0] != "alex" || users[3] != "alex" {
		t.Fatalf("hook saw sizes %v, users %v", sizes, users)
	}
	if !strings.Contains(h.logs.String(), "database down") {
		t.Fatal("the hook's error wasn't logged")
	}
}

func TestRelayProtocolViolations(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		name string
		send func(p *pairedUser)
	}{
		{"not json", func(p *pairedUser) { _ = p.dc.conn.Write(p.dc.ctx, websocket.MessageText, []byte("{")) }},
		{"binary", func(p *pairedUser) { _ = p.dc.conn.Write(p.dc.ctx, websocket.MessageBinary, []byte("{}")) }},
		{"unknown type", func(p *pairedUser) { p.dc.send(protocol.RelayMessage{Type: "publish"}) }},
		{"no frame", func(p *pairedUser) { p.dc.send(protocol.RelayMessage{Type: protocol.RelayFrame}) }},
		{"no ciphertext", func(p *pairedUser) {
			p.dc.frame(&protocol.SealedFrame{ID: "frm_1", From: p.device.id, To: p.host.id, Nonce: "n"})
		}},
		{"too large", func(p *pairedUser) {
			big := make([]byte, protocol.MaxRelayMessage+1)
			for i := range big {
				big[i] = 'a'
			}
			_ = p.dc.conn.Write(p.dc.ctx, websocket.MessageText, big)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := h.pairedUser("u-" + randomString(6))
			tc.send(p)
			p.dc.waitClosed()
			p.hc.none()
		})
	}
}

// A browser and an account hold only so many live sockets; more are refused before the upgrade.
func TestRelaySocketLimits(t *testing.T) {
	oldDevice, oldUser := maxDeviceSocketsPerDevice, maxDeviceSocketsPerUser
	maxDeviceSocketsPerDevice, maxDeviceSocketsPerUser = 2, 3
	t.Cleanup(func() { maxDeviceSocketsPerDevice, maxDeviceSocketsPerUser = oldDevice, oldUser })
	h := newHarness(t)
	p := h.pairedUser("alex") // one socket for p.device
	second := newTestDevice(t, "second browser")
	h.pair(p.host, second, p.token)

	h.relayDevice(p.device, p.token)
	h.do(http.MethodGet, "/api/v1/relay/device?device="+p.device.id, nil, bearer(p.token)).expectError(errTooManySockets)
	h.relayDevice(second, p.token)
	h.do(http.MethodGet, "/api/v1/relay/device?device="+second.id, nil, bearer(p.token)).expectError(errTooManySockets)

	// Another account is unaffected, and closing a tab frees its place.
	h.pairedUser("eve")
	p.dc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 3 })
	h.relayDevice(second, p.token)
}

// A socket that stops reading is closed once its queue fills, instead of holding frames in memory.
func TestRelayClosesSlowReaders(t *testing.T) {
	h := newHarness(t)
	p := h.pairedUser("alex")
	p.dc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 0 })
	// A tab that never reads.
	stalled, _ := h.dialWS("/api/v1/relay/device?device="+p.device.id, bearer(p.token))
	_ = stalled
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 1 })
	ct := strings.Repeat("A", 512<<10)
	for i := 0; h.srv.relay.count(relayDevice) == 1; i++ {
		if i > 400 {
			t.Fatal("the stalled socket was never closed")
		}
		f := &protocol.SealedFrame{ID: protocol.NewRandomID("frm_"), From: p.host.id, To: p.device.id, Time: time.Now().Unix(), Nonce: "bm9uY2Vub25jZQ", CT: ct}
		p.hc.frame(f)
		p.hc.relayed(f)
	}
}
