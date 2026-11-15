package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"agentio.sh/protocol"
)

// A signed-in browser pairs a new machine: the server relays the sealed name and confirmation it can't read, and on
// confirm records the machine, the device and their link. The machine's own token then adds more browsers of its
// account, once per pairing.
func TestPairingNewMachine(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	_, eve := h.addUser("eve")
	th, d := newTestHost(t, "alex-mbp"), newTestDevice(t, "Alex's browser")
	res := h.pair(th, d, token)
	if res.HostID != th.id || res.Username != "alex" || !strings.HasPrefix(res.Token, "aio_") {
		t.Fatalf("confirm result %+v", res)
	}
	var devices struct{ Devices []protocol.DeviceInfo }
	h.do(http.MethodGet, "/api/v1/devices", nil, bearer(token)).expect(http.StatusOK).decode(&devices)
	if len(devices.Devices) != 1 || devices.Devices[0].EncKey != d.encKey || devices.Devices[0].Hosts[0] != th.id {
		t.Fatalf("devices %+v", devices)
	}
	if dump := h.dump(); strings.Contains(dump, "alex-mbp") || strings.Contains(dump, "Alex's browser") {
		t.Fatal("a name reached the database")
	}

	res = h.pair(th, newTestDevice(t, "Work browser"), token)
	if res.Token != "" || res.HostID != th.id {
		t.Fatalf("devices add handed out a token: %+v", res)
	}
	mustEqual(t, "links", h.sqlInt(`SELECT COUNT(*) FROM host_devices WHERE host_id = ?`, th.id), 2)
	p := h.startPairing(th, th.token)
	h.claim(p, newTestDevice(t, "eve's"), eve).expectError(errOtherAccount)
	h.claim(p, newTestDevice(t, "third"), token).expect(http.StatusOK)
	h.claim(p, newTestDevice(t, "fourth"), token).expectError(errPairingClaimed)
}

// Claiming a pairing needs a signed-in browser's user token: no pairing creates an account, and a stolen machine
// token can't claim one to become a user token.
func TestPairingNeedsUserToken(t *testing.T) {
	h := newHarness(t)
	th, thief := newTestHost(t, "mbp"), newTestDevice(t, "thief")
	p := h.startPairing(th, "")
	h.claim(p, thief, "").expectError(ErrUnauthorized)
	mustEqual(t, "users", h.sqlInt(`SELECT COUNT(*) FROM users`), 0)

	_, token := h.addUser("alex")
	h.pair(th, newTestDevice(t, "first"), token)
	tokensBefore := h.sqlInt(`SELECT COUNT(*) FROM tokens`)
	p = h.startPairing(th, th.token)
	h.claim(p, thief, th.token).expectError(errHostTokenNotAllowed)
	mustEqual(t, "pairing", h.pairPoll(p.id, p.secret).Status, protocol.PairPending)
	mustEqual(t, "tokens", h.sqlInt(`SELECT COUNT(*) FROM tokens`), tokensBefore)
	mustEqual(t, "thief's device", h.sqlInt(`SELECT COUNT(*) FROM devices WHERE id = ?`, thief.id), 0)
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
	start(th.key, th.encKey, bearer(token)).expectError(errHostPaired)
	start(th.key, newTestHost(t, "x").encKey, bearer(th.token)).expectError(errHostKeyChanged)
	start(newTestHost(t, "new").key, th.encKey, bearer(th.token)).expectError(errHostTokenNotAllowed)
	start(th.key, th.encKey, bearer(th.token)).expect(http.StatusOK)
}

// A browser profile belongs to one account and keeps its keys until it is unpaired.
func TestPairingDeviceIdentity(t *testing.T) {
	h := newHarness(t)
	_, alex := h.addUser("alex")
	_, eve := h.addUser("eve")
	d := newTestDevice(t, "browser")
	h.pair(newTestHost(t, "one"), d, alex)
	h.claim(h.startPairing(newTestHost(t, "eve-mbp"), ""), d, eve).expectError(errOtherAccount)

	changed := *d
	changed.enc, _ = protocol.NewEncKey()
	changed.encKey = protocol.EncodeEncKey(changed.enc.PublicKey())
	two := newTestHost(t, "two")
	h.claim(h.startPairing(two, ""), &changed, alex).expectError(errDeviceKeyChanged)
	h.do(http.MethodDelete, "/api/v1/devices/"+d.id, nil, bearer(alex)).expect(http.StatusOK)
	h.pair(two, &changed, alex)
}

// A rejected pairing records nothing, and an expired one can't be claimed.
func TestPairingRejectedOrExpired(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "mbp")
	p := h.startPairing(th, "")
	var claimed protocol.PairStarted
	h.claim(p, newTestDevice(t, "browser"), token).expect(http.StatusOK).decode(&claimed)
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/reject", map[string]string{"secret": p.secret}).expect(http.StatusOK)
	if st := h.pairPoll(p.id, claimed.Secret); st.Status != protocol.PairRejected || st.Host != nil {
		t.Fatalf("device view %+v", st)
	}
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/confirm", protocol.PairConfirm{Secret: p.secret, Confirm: "x"}).expectError(ErrBadRequest)
	mustEqual(t, "hosts", h.sqlInt(`SELECT COUNT(*) FROM hosts`), 0)

	p = h.startPairing(th, "")
	pr, err := h.srv.pairings.get(p.id)
	if err != nil {
		t.Fatal(err)
	}
	pr.mu.Lock()
	pr.expires = time.Now().Add(-time.Second)
	pr.mu.Unlock()
	mustEqual(t, "expired poll", h.pairPoll(p.id, p.secret).Status, protocol.PairExpired)
	h.claim(p, newTestDevice(t, "late"), token).expectError(errExpired)
}

// A malformed claim is refused without using the pairing up, and a wrong secret learns nothing.
func TestPairingValidation(t *testing.T) {
	h := newHarness(t)
	_, token := h.addUser("alex")
	th := newTestHost(t, "mbp")
	h.do(http.MethodPost, "/api/v1/pair", protocol.PairStart{ID: protocol.NewRandomID("pair_"), HostKey: th.key}).expectError(ErrBadRequest)
	p := h.startPairing(th, "")
	d := newTestDevice(t, "browser")
	for _, mod := range []func(*protocol.PairClaim){
		func(c *protocol.PairClaim) { c.DeviceSensitiveKey = c.DeviceKey },
		func(c *protocol.PairClaim) { c.DeviceSensitiveOrigin = "http://app.example.test" },
		func(c *protocol.PairClaim) { c.MAC = "" },
	} {
		c := claimBody(t, p, d)
		mod(&c)
		h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/claim", c, bearer(token)).expectError(ErrBadRequest)
	}
	h.do(http.MethodGet, "/api/v1/pair/"+p.id+"?secret=nope", nil).expectError(ErrNotFound)
	// None of that used the pairing up.
	h.claim(p, d, token).expect(http.StatusOK)
}

// Pairings live in memory only: a restarted server knows none.
func TestPairingsAreNotStored(t *testing.T) {
	h := newHarness(t)
	before := h.dump()
	p := h.startPairing(newTestHost(t, "mbp"), "")
	if h.dump() != before {
		t.Fatal("starting a pairing wrote to the database")
	}
	h.srv.pairings = newPairings() // as after a restart
	h.do(http.MethodGet, "/api/v1/pair/"+p.id+"?secret="+p.secret, nil).expectError(ErrNotFound)
}
