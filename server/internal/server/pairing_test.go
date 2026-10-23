package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"agentio.sh/protocol"
)

// A signed-in browser pairs a new machine: the server relays the sealed name and confirmation it can't read, and on
// confirm records the machine, the device and their link.
func TestPairingNewMachine(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th, d := newTestHost(t, "alex-mbp"), newTestDevice(t, "Alex's browser")
	res := h.pair(th, d, token)
	if res.confirm.HostID != th.id || res.confirm.Username != "alex" || !strings.HasPrefix(res.confirm.Token, "aio_") {
		t.Fatalf("confirm result %+v", res.confirm)
	}
	if res.device.Username != "alex" {
		t.Fatalf("device view %+v", res.device)
	}

	var hosts struct{ Hosts []protocol.HostInfo }
	h.do(http.MethodGet, "/api/v1/hosts", nil, bearer(token)).expect(http.StatusOK).decode(&hosts)
	if len(hosts.Hosts) != 1 || hosts.Hosts[0].ID != th.id || hosts.Hosts[0].Key != th.key || hosts.Hosts[0].EncKey != th.encKey || hosts.Hosts[0].Online {
		t.Fatalf("hosts %+v", hosts)
	}
	var devices struct{ Devices []protocol.DeviceInfo }
	h.do(http.MethodGet, "/api/v1/devices", nil, bearer(token)).expect(http.StatusOK).decode(&devices)
	want := protocol.DeviceInfo{ID: d.id, Key: d.key, SensitiveKey: d.sensitiveKey, EncKey: d.encKey, SensitiveOrigin: testOrigin, Hosts: []string{th.id}}
	if len(devices.Devices) != 1 {
		t.Fatalf("devices %+v", devices)
	}
	got := devices.Devices[0]
	if got.ID != want.ID || got.Key != want.Key || got.SensitiveKey != want.SensitiveKey || got.EncKey != want.EncKey ||
		got.SensitiveOrigin != want.SensitiveOrigin || len(got.Hosts) != 1 || got.Hosts[0] != th.id || got.Created == 0 {
		t.Fatalf("device %+v, want %+v", got, want)
	}
	// Names never reach the database.
	for _, table := range []string{"hosts", "devices", "host_devices", "tokens", "users"} {
		if n := h.sqlInt(`SELECT COUNT(*) FROM ` + table); n == 0 {
			t.Fatalf("%s is empty", table)
		}
	}
	if dump := h.dump(); strings.Contains(dump, "alex-mbp") || strings.Contains(dump, "Alex's browser") {
		t.Fatal("a name reached the database")
	}
	// Pairing again with the machine's own token adds a second browser to the same machine.
	second := newTestDevice(t, "Work browser")
	res = h.pair(th, second, token)
	if res.confirm.Token != "" || res.confirm.HostID != th.id {
		t.Fatalf("devices add result %+v", res.confirm)
	}
	mustEqual(t, "links", h.sqlInt(`SELECT COUNT(*) FROM host_devices WHERE host_id = ?`, th.id), 2)
}

// Claiming a pairing needs a signed-in browser: no pairing creates an account or hands out a user token.
func TestPairingNeedsAccount(t *testing.T) {
	h := newHarness(t)
	th, d := newTestHost(t, "mbp"), newTestDevice(t, "browser")
	p := h.startPairing(th, "")
	h.claim(p, th, d, "").expectError(ErrUnauthorized)
	mustEqual(t, "users", h.sqlInt(`SELECT COUNT(*) FROM users`), 0)
	_, token := h.addUser("alex")
	h.claim(p, th, d, token).expect(http.StatusOK)
}

// `agentio devices add`: the machine's own token starts the pairing, and only a signed-in browser of the machine's
// account can claim it. A pairing never hands out a token for an existing machine's account.
func TestPairingDevicesAdd(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	_, eve := h.addUser("eve")
	th := newTestHost(t, "alex-mbp")
	h.pair(th, newTestDevice(t, "first"), token)

	p := h.startPairing(th, th.token)
	h.claim(p, th, newTestDevice(t, "eve's"), eve).expectError(errOtherAccount)
	res := h.pair(th, newTestDevice(t, "second"), token)
	if res.device.Username != "alex" || res.confirm.Token != "" {
		t.Fatalf("devices add handed out a token: %+v %+v", res.device, res.confirm)
	}
	mustEqual(t, "links", h.sqlInt(`SELECT COUNT(*) FROM host_devices WHERE host_id = ?`, th.id), 2)
}

// A stolen machine token can't be turned into a user token: the thief can start a pairing for that machine, but
// can't claim it without the account's user token, and no pairing for an existing machine issues one.
func TestPairingHostTokenCantBecomeUserToken(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "alex-mbp")
	h.pair(th, newTestDevice(t, "first"), token)
	tokensBefore := h.sqlInt(`SELECT COUNT(*) FROM tokens`)

	thief := newTestDevice(t, "thief")
	p := h.startPairing(th, th.token)
	h.claim(p, th, thief, "").expectError(ErrUnauthorized)
	h.claim(p, th, thief, th.token).expectError(errHostTokenNotAllowed)
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/confirm", protocol.PairConfirm{Secret: p.secret, Confirm: "junk"}).expectError(ErrBadRequest)
	if st := h.pairPoll(p.id, p.secret, ""); st.Status != protocol.PairPending {
		t.Fatalf("pairing %+v after refused claims", st)
	}
	mustEqual(t, "tokens", h.sqlInt(`SELECT COUNT(*) FROM tokens`), tokensBefore)
	mustEqual(t, "thief's device", h.sqlInt(`SELECT COUNT(*) FROM devices WHERE id = ?`, thief.id), 0)
}

// Each client IP holds at most a few unclaimed pairings; a new one replaces its oldest, so one client can't use up
// the pairing table, and a full table makes room by dropping its oldest unclaimed pairing.
func TestPairingLimits(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "mbp")
	started := []*testPairing{h.startPairing(th, "")}
	polled := make(chan protocol.PairStatus)
	go func() { polled <- h.pairPoll(started[0].id, started[0].secret, "&wait=30") }()
	time.Sleep(100 * time.Millisecond)
	for range maxPairingsPerIP {
		started = append(started, h.startPairing(th, ""))
	}
	select {
	case st := <-polled:
		mustEqual(t, "replaced pairing's long poll", st.Status, protocol.PairExpired)
	case <-time.After(waitTimeout):
		t.Fatal("the replaced pairing's long poll didn't wake")
	}
	h.do(http.MethodGet, "/api/v1/pair/"+started[0].id+"?secret="+started[0].secret, nil).expectError(ErrNotFound) // replaced
	for _, p := range started[1:] {
		mustEqual(t, "status", h.pairPoll(p.id, p.secret, "").Status, protocol.PairPending)
	}
	// Claimed pairings don't count against the IP.
	h.claim(started[1], th, newTestDevice(t, "browser"), token).expect(http.StatusOK)
	h.startPairing(th, "")
	mustEqual(t, "claimed pairing", h.pairPoll(started[1].id, started[1].secret, "").Status, protocol.PairClaimed)
	mustEqual(t, "next oldest", h.pairPoll(started[2].id, started[2].secret, "").Status, protocol.PairPending)

	// IPv6 clients are grouped by /64.
	mustEqual(t, "ipv6 key", ipKey("2001:db8:1:2:aaaa::1"), ipKey("2001:db8:1:2:bbbb::9"))
	if ipKey("2001:db8:1:3::1") == ipKey("2001:db8:1:2::1") || ipKey("192.0.2.1") != "192.0.2.1" {
		t.Fatal("ip keys")
	}

	// A full table drops its oldest unclaimed pairing; a table of pairings in progress refuses.
	ps := &pairings{m: map[string]*pairing{}, max: 100}
	now := time.Now()
	add := func(id, ip string, age time.Duration) *pairing {
		p := &pairing{id: id, ipKey: ip, created: now.Add(-age), expires: now.Add(pairingTTL - age), status: protocol.PairPending, changed: make(chan struct{})}
		if err := ps.add(p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for i := range ps.max {
		add(fmt.Sprintf("pair_%d", i), fmt.Sprintf("10.0.0.%d", i), time.Duration(ps.max-i)*time.Millisecond)
	}
	add("pair_new", "192.0.2.9", 0)
	if _, err := ps.get("pair_0"); err == nil {
		t.Fatal("the oldest unclaimed pairing survived a full table")
	}
	mustEqual(t, "pairings", len(ps.m), ps.max)
	for _, p := range ps.m {
		p.status = protocol.PairClaimed
	}
	err := ps.add(&pairing{id: "pair_more", ipKey: "192.0.2.10", created: now, expires: now.Add(pairingTTL), status: protocol.PairPending, changed: make(chan struct{})})
	if err != errTooManyPairings {
		t.Fatalf("full table of claimed pairings: %v", err)
	}
}

// A known machine key starts a pairing only with that machine's token and its pinned encryption key.
func TestPairingKnownMachine(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "alex-mbp")
	h.pair(th, newTestDevice(t, "browser"), token)
	start := func(key, encKey string, headers ...hdr) *response {
		return h.do(http.MethodPost, "/api/v1/pair", protocol.PairStart{ID: protocol.NewRandomID("pair_"), HostKey: key, HostEncKey: encKey}, headers...)
	}
	start(th.key, th.encKey).expectError(errHostPaired)
	start(th.key, th.encKey, bearer(token)).expectError(errHostPaired)
	start(th.key, newTestHost(t, "x").encKey, bearer(th.token)).expectError(errHostKeyChanged)
	start(newTestHost(t, "new").key, th.encKey, bearer(th.token)).expectError(errHostTokenNotAllowed)
	start(th.key, th.encKey, bearer(th.token)).expect(http.StatusOK)
	// The same pairing ID can't be registered twice.
	p := h.startPairing(th, th.token)
	h.do(http.MethodPost, "/api/v1/pair", protocol.PairStart{ID: p.id, HostKey: th.key, HostEncKey: th.encKey}, bearer(th.token)).expectError(errPairingClaimed)
}

func TestPairingClaimedOnce(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "mbp")
	p := h.startPairing(th, "")
	h.claim(p, th, newTestDevice(t, "first"), token).expect(http.StatusOK)
	h.claim(p, th, newTestDevice(t, "second"), token).expectError(errPairingClaimed)
}

// A browser profile belongs to one account and keeps its keys until it is unpaired.
func TestPairingDeviceIdentity(t *testing.T) {
	h := newHarness(t)
	_, alex := h.addUser("alex")
	_, eve := h.addUser("eve")
	d := newTestDevice(t, "browser")
	h.pair(newTestHost(t, "one"), d, alex)

	other := newTestHost(t, "eve-mbp")
	p := h.startPairing(other, "")
	h.claim(p, other, d, eve).expectError(errOtherAccount)

	changed := *d
	changed.enc, _ = protocol.NewEncKey()
	changed.encKey = protocol.EncodeEncKey(changed.enc.PublicKey())
	two := newTestHost(t, "two")
	p = h.startPairing(two, "")
	h.claim(p, two, &changed, alex).expectError(errDeviceKeyChanged)

	h.do(http.MethodDelete, "/api/v1/devices/"+d.id, nil, bearer(alex)).expect(http.StatusOK)
	h.pair(two, &changed, alex)
}

func TestPairingRejected(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th, d := newTestHost(t, "mbp"), newTestDevice(t, "browser")
	p := h.startPairing(th, "")
	var claimed protocol.PairStarted
	h.claim(p, th, d, token).expect(http.StatusOK).decode(&claimed)
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/reject", map[string]string{"secret": "wrong"}).expectError(ErrNotFound)
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/reject", map[string]string{"secret": p.secret}).expect(http.StatusOK)
	if st := h.pairPoll(p.id, claimed.Secret, ""); st.Status != protocol.PairRejected || st.Confirm != "" || st.Host != nil {
		t.Fatalf("device view %+v", st)
	}
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/confirm", protocol.PairConfirm{Secret: p.secret, Confirm: "x"}).expectError(ErrBadRequest)
	mustEqual(t, "hosts", h.sqlInt(`SELECT COUNT(*) FROM hosts`), 0)
}

func TestPairingExpires(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th, d := newTestHost(t, "mbp"), newTestDevice(t, "browser")
	p := h.startPairing(th, "")
	pr, err := h.srv.pairings.get(p.id)
	if err != nil {
		t.Fatal(err)
	}
	pr.mu.Lock()
	pr.expires = time.Now().Add(-time.Second)
	pr.mu.Unlock()
	if st := h.pairPoll(p.id, p.secret, "&wait=30"); st.Status != protocol.PairExpired {
		t.Fatalf("poll %+v", st)
	}
	h.claim(p, th, d, token).expectError(errExpired)
	// Expired pairings are forgotten after a while.
	h.srv.pairings.prune(time.Now().Add(pairingKeep))
	h.do(http.MethodGet, "/api/v1/pair/"+p.id+"?secret="+p.secret, nil).expectError(ErrNotFound)
}

// Long polls return as soon as the other side acts.
func TestPairingLongPollWakes(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th, d := newTestHost(t, "mbp"), newTestDevice(t, "browser")
	p := h.startPairing(th, "")
	done := make(chan protocol.PairStatus)
	go func() { done <- h.pairPoll(p.id, p.secret, "&wait=30") }()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	h.claim(p, th, d, token).expect(http.StatusOK)
	select {
	case st := <-done:
		if st.Status != protocol.PairClaimed || st.Claim == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("woke with %+v", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long poll didn't wake")
	}
	// A wrong secret learns nothing.
	h.do(http.MethodGet, "/api/v1/pair/"+p.id+"?secret=nope", nil).expectError(ErrNotFound)
	h.do(http.MethodGet, "/api/v1/pair/pair_unknown?secret="+p.secret, nil).expectError(ErrNotFound)
}

func TestPairingValidation(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "mbp")
	for name, start := range map[string]protocol.PairStart{
		"id":      {ID: "nope", HostKey: th.key, HostEncKey: th.encKey},
		"key":     {ID: protocol.NewRandomID("pair_"), HostKey: "abc", HostEncKey: th.encKey},
		"enc key": {ID: protocol.NewRandomID("pair_"), HostKey: th.key, HostEncKey: "abc"},
		"no enc":  {ID: protocol.NewRandomID("pair_"), HostKey: th.key},
	} {
		t.Run(name, func(t *testing.T) { h.do(http.MethodPost, "/api/v1/pair", start).expectError(ErrBadRequest) })
	}
	p := h.startPairing(th, "")
	d := newTestDevice(t, "browser")
	for name, mod := range map[string]func(*protocol.PairClaim){
		"device key":     func(c *protocol.PairClaim) { c.DeviceKey = "abc" },
		"sensitive key":  func(c *protocol.PairClaim) { c.DeviceSensitiveKey = c.DeviceKey },
		"enc key":        func(c *protocol.PairClaim) { c.DeviceEncKey = "abc" },
		"no origin":      func(c *protocol.PairClaim) { c.DeviceSensitiveOrigin = "" },
		"bad origin":     func(c *protocol.PairClaim) { c.DeviceSensitiveOrigin = "http://app.example.test" },
		"no sealed name": func(c *protocol.PairClaim) { c.SealedName = "" },
		"long name":      func(c *protocol.PairClaim) { c.SealedName = strings.Repeat("a", protocol.MaxSealedName+1) },
		"no mac":         func(c *protocol.PairClaim) { c.MAC = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := claimBody(t, p, th, d)
			mod(&c)
			h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/claim", c, bearer(token)).expectError(ErrBadRequest)
		})
	}
	h.do(http.MethodPost, "/api/v1/pair/pair_unknown/claim", claimBody(t, p, th, d), bearer(token)).expectError(ErrNotFound)
	// None of that used the pairing up.
	h.claim(p, th, d, token).expect(http.StatusOK)
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/confirm", protocol.PairConfirm{Secret: p.secret}).expectError(ErrBadRequest)
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/confirm", protocol.PairConfirm{Secret: "wrong", Confirm: "x"}).expectError(ErrNotFound)
}

// Pairings live in memory only: a restarted server knows none.
func TestPairingsAreNotStored(t *testing.T) {
	h := newHarness(t)
	th := newTestHost(t, "mbp")
	before := h.dump()
	p := h.startPairing(th, "")
	if h.dump() != before {
		t.Fatal("starting a pairing wrote to the database")
	}
	h.srv.pairings = newPairings() // as after a restart
	h.do(http.MethodGet, "/api/v1/pair/"+p.id+"?secret="+p.secret, nil).expectError(ErrNotFound)
}
