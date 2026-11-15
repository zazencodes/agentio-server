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
	mustEqual(t, "relayed", p.hc.relayed(f).Result, protocol.RelayDelivered)
	m := p.dc.next()
	if m.Type != protocol.RelayFrame || m.Frame == nil || *m.Frame != *f {
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

	// Device → host.
	f = sealFrom(t, p.pk, p.device.sign, p.device.id, p.host.id, protocol.KindSync, protocol.SignedSync{ID: "rpc_1", Host: p.host.id, Time: time.Now().Unix()})
	p.dc.frame(f)
	mustEqual(t, "relayed", p.dc.relayed(f).Result, protocol.RelayDelivered)
	if m := p.hc.next(); m.Type != protocol.RelayFrame || *m.Frame != *f {
		t.Fatalf("host got %+v", m)
	}
}

// A connection may only send as itself: a frame from anyone else closes the socket.
func TestRelaySpoofedFrom(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	other := newTestHost(t, "other")
	alex.hc.frame(sealFrom(t, alex.pk, other.sign, other.id, alex.device.id, protocol.KindUpdate, protocol.Update{Host: other.id}))
	mustEqual(t, "host closed", alex.hc.waitClosed().Code, websocket.StatusPolicyViolation)
	alex.dc.next() // presence: offline
	alex.dc.frame(sealFrom(t, alex.pk, alex.host.sign, alex.host.id, alex.host.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id}))
	mustEqual(t, "device closed", alex.dc.waitClosed().Code, websocket.StatusPolicyViolation)
}

// Frames go only between linked hosts and devices: not across accounts, nor to a machine of the same account the
// browser isn't paired with.
func TestRelayUnlinked(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")
	second := newTestHost(t, "second")
	h.pair(second, newTestDevice(t, "other browser"), alex.token)
	for _, c := range []struct {
		from *relayClient
		f    *protocol.SealedFrame
	}{
		{alex.hc, sealFrom(t, alex.pk, alex.host.sign, alex.host.id, eve.device.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})},
		{eve.dc, sealFrom(t, eve.pk, eve.device.sign, eve.device.id, alex.host.id, protocol.KindCommand, protocol.SignedCommand{Host: alex.host.id})},
		{alex.dc, sealFrom(t, alex.pk, alex.device.sign, alex.device.id, second.id, protocol.KindSync, protocol.SignedSync{Host: second.id})},
	} {
		c.from.frame(c.f)
		if m := c.from.relayed(c.f); m.Result != protocol.RelayRefused || m.Code != "not_paired" {
			t.Fatalf("relayed %+v", m)
		}
	}
	eve.dc.none()
	alex.hc.none()
}

// A push rides only with a machine's frame, for the same device.
func TestRelayMismatchedPush(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")
	f := sealFrom(t, alex.pk, alex.host.sign, alex.host.id, alex.device.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})
	push := sealFrom(t, alex.pk, alex.host.sign, alex.host.id, eve.device.id, protocol.KindPush, protocol.SignedPush{Host: alex.host.id})
	alex.hc.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f, Push: push})
	mustEqual(t, "closed", alex.hc.waitClosed().Code, websocket.StatusPolicyViolation)
	eve.dc.none()
}

func TestRelaySocketAuth(t *testing.T) {
	h := newHarness(t)
	alex := h.pairedUser("alex")
	eve := h.pairedUser("eve")
	h.do(http.MethodGet, "/api/v1/relay/device?device="+eve.device.id, nil, bearer(alex.token)).expectError(ErrForbidden)
	h.do(http.MethodGet, "/api/v1/relay/device?device="+alex.device.id, nil, bearer(alex.host.token)).expectError(errHostTokenNotAllowed)
	h.do(http.MethodGet, "/api/v1/relay/host", nil, bearer(alex.token)).expectError(ErrForbidden)
	h.do(http.MethodGet, "/api/v1/relay/host?token="+alex.host.token, nil, bearer(alex.host.token)).expectError(ErrUnauthorized)
	// Browsers can't set headers on WebSockets: they send the token as a query parameter.
	c := h.relay("/api/v1/relay/device?device="+alex.device.id+"&token="+alex.token, "")
	mustEqual(t, "hello", c.hello.Device, alex.device.id)
}

// The server closes a socket whose token is revoked, whose machine is removed, whose device is unpaired,
// or whose account is deleted.
func TestRelayClosesRevokedSockets(t *testing.T) {
	h := newHarness(t)
	for name, revoke := range map[string]func(p *pairedUser){
		"token revoked": func(p *pairedUser) {
			h.do(http.MethodDelete, "/api/v1/account/tokens/"+h.tokenID(p.token), nil, bearer(p.token)).expect(http.StatusOK)
		},
		"machine removed": func(p *pairedUser) {
			h.do(http.MethodDelete, "/api/v1/hosts/"+p.host.id, nil, bearer(p.token)).expect(http.StatusOK)
		},
		"device unpaired": func(p *pairedUser) {
			h.do(http.MethodDelete, "/api/v1/devices/"+p.device.id, nil, bearer(p.token)).expect(http.StatusOK)
		},
		"account deleted": func(p *pairedUser) {
			h.do(http.MethodDelete, "/api/v1/account", map[string]string{"password": testPassword}, bearer(p.token)).expect(http.StatusOK)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := h.pairedUser(strings.ReplaceAll(name, " ", "-"))
			revoke(p)
			p.dc.waitClosed()
		})
	}
}

// An extension sees every frame before it is relayed, with its account and size, and refuses frames with an error:
// its own API error reaches the sender as the refusal, any other error is an internal one.
func TestRelayFrameHook(t *testing.T) {
	var mu sync.Mutex
	var sizes []int64
	limit := NewError(429, "no_more_frames", "No more frames today")
	h := newExtendedHarness(t, Extension{RelayFrame: func(_ context.Context, u *store.User, size int64) error {
		mu.Lock()
		defer mu.Unlock()
		if u.Username != "alex" {
			return errors.New("wrong account")
		}
		sizes = append(sizes, size)
		switch len(sizes) {
		case 2:
			return limit
		case 3:
			return errors.New("database down")
		}
		return nil
	}})
	alex := h.pairedUser("alex")
	for i, want := range []string{"", limit.Code, ErrInternal.Code} {
		f := sealFrom(t, alex.pk, alex.host.sign, alex.host.id, alex.device.id, protocol.KindUpdate, protocol.Update{Host: alex.host.id})
		alex.hc.frame(f)
		if m := alex.hc.relayed(f); m.Code != want || (i == 0) != (m.Result == protocol.RelayDelivered) {
			t.Fatalf("frame %d: %+v", i, m)
		}
	}
	alex.dc.next()
	alex.dc.none()
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 3 || sizes[0] < 100 || !strings.Contains(h.logs.String(), "database down") {
		t.Fatalf("hook saw sizes %v, or its error wasn't logged", sizes)
	}
}
