package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"agentio.sh/protocol"
)

// testOrigin is the app origin test devices bind their sensitive key to.
const testOrigin = "https://app.example.test"

// testHost is a computer's bridge with real keys, as the CLI holds them.
type testHost struct {
	sign   *ecdsa.PrivateKey
	enc    *ecdh.PrivateKey
	key    string
	encKey string
	id     string
	name   string
	token  string // set once paired
}

func newTestHost(t *testing.T, name string) *testHost {
	t.Helper()
	sign, err := protocol.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := protocol.NewEncKey()
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.EncodePublicKey(&sign.PublicKey)
	return &testHost{sign: sign, enc: enc, key: key, encKey: protocol.EncodeEncKey(enc.PublicKey()), id: protocol.KeyID("hst_", key), name: name}
}

// testDevice is a browser profile with real keys, as the web app holds them.
type testDevice struct {
	sign         *ecdsa.PrivateKey
	sensitive    *ecdsa.PrivateKey
	enc          *ecdh.PrivateKey
	key          string
	sensitiveKey string
	encKey       string
	id           string
	name         string
}

func newTestDevice(t *testing.T, name string) *testDevice {
	t.Helper()
	sign, err1 := protocol.NewKey()
	sensitive, err2 := protocol.NewKey()
	enc, err3 := protocol.NewEncKey()
	if err := errors.Join(err1, err2, err3); err != nil {
		t.Fatal(err)
	}
	key := protocol.EncodePublicKey(&sign.PublicKey)
	return &testDevice{sign: sign, sensitive: sensitive, enc: enc, key: key, sensitiveKey: protocol.EncodePublicKey(&sensitive.PublicKey),
		encKey: protocol.EncodeEncKey(enc.PublicKey()), id: protocol.KeyID("dev_", key), name: name}
}

// pairKey is the key a host and a device seal their frames with, derived from either side.
func pairKey(t *testing.T, th *testHost, d *testDevice) []byte {
	t.Helper()
	fromHost, err := protocol.PairKey(th.enc, d.enc.PublicKey(), th.id, d.id)
	if err != nil {
		t.Fatal(err)
	}
	fromDevice, err := protocol.PairKey(d.enc, th.enc.PublicKey(), th.id, d.id)
	if err != nil {
		t.Fatal(err)
	}
	if string(fromHost) != string(fromDevice) {
		t.Fatal("the two sides derive different pair keys")
	}
	return fromHost
}

// sealFrom signs a payload with key as signer and seals it for one peer.
func sealFrom(t *testing.T, pk []byte, key *ecdsa.PrivateKey, from, to, kind string, payload any) *protocol.SealedFrame {
	t.Helper()
	env, err := protocol.Sign(key, from, kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	f, err := protocol.SealFrame(pk, from, to, env)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// pairing is a pairing in progress, from the terminal's side.
type testPairing struct {
	id     string
	k      string
	secret string // the host's poll secret
}

// startPairing registers a pairing for th; hostToken is set for `agentio devices add`.
func (h *harness) startPairing(th *testHost, hostToken string) *testPairing {
	h.t.Helper()
	p := &testPairing{id: protocol.NewRandomID("pair_"), k: protocol.NewSecret()}
	var headers []hdr
	if hostToken != "" {
		headers = append(headers, bearer(hostToken))
	}
	var started protocol.PairStarted
	h.do(http.MethodPost, "/api/v1/pair", protocol.PairStart{ID: p.id, HostKey: th.key, HostEncKey: th.encKey}, headers...).expect(http.StatusOK).decode(&started)
	p.secret = started.Secret
	return p
}

// claimBody is the device's claim for a pairing, sealed and MACed with K.
func claimBody(t *testing.T, p *testPairing, th *testHost, d *testDevice) protocol.PairClaim {
	t.Helper()
	nameKey, err := protocol.SecretKey(p.k, protocol.InfoPairName)
	if err != nil {
		t.Fatal(err)
	}
	sealedName, err := protocol.SealSecret(nameKey, []byte(d.name), protocol.PairNameAAD(p.id))
	if err != nil {
		t.Fatal(err)
	}
	mac, err := protocol.PairMAC(p.k, p.id, th.key, d.key, d.sensitiveKey, d.encKey, d.name, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PairClaim{DeviceKey: d.key, DeviceSensitiveKey: d.sensitiveKey, DeviceSensitiveOrigin: testOrigin, DeviceEncKey: d.encKey,
		SealedName: sealedName, MAC: mac}
}

func (h *harness) claim(p *testPairing, th *testHost, d *testDevice, userToken string) *response {
	h.t.Helper()
	var headers []hdr
	if userToken != "" {
		headers = append(headers, bearer(userToken))
	}
	return h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/claim", claimBody(h.t, p, th, d), headers...)
}

func (h *harness) pairPoll(id, secret, query string) protocol.PairStatus {
	h.t.Helper()
	var st protocol.PairStatus
	h.do(http.MethodGet, "/api/v1/pair/"+id+"?secret="+secret+query, nil).expect(http.StatusOK).decode(&st)
	return st
}

// confirmation checks the claim the server relayed, like the CLI does, and returns the host's signed and sealed
// confirmation.
func confirmation(t *testing.T, p *testPairing, th *testHost, claim *protocol.PairClaim) string {
	t.Helper()
	nameKey, _ := protocol.SecretKey(p.k, protocol.InfoPairName)
	name, err := protocol.OpenSecret(nameKey, claim.SealedName, protocol.PairNameAAD(p.id))
	if err != nil {
		t.Fatalf("opening the sealed name: %v", err)
	}
	if !protocol.CheckPairMAC(claim.MAC, p.k, p.id, th.key, claim.DeviceKey, claim.DeviceSensitiveKey, claim.DeviceEncKey, string(name), claim.DeviceSensitiveOrigin) {
		t.Fatal("the relayed claim's MAC doesn't verify")
	}
	env, err := protocol.Sign(th.sign, th.id, protocol.KindPair, protocol.SignedPair{Pair: p.id, Host: th.id, HostKey: th.key, HostEncKey: th.encKey,
		HostName: th.name, Device: claim.Device, DeviceKey: claim.DeviceKey, DeviceSensitiveKey: claim.DeviceSensitiveKey,
		DeviceSensitiveOrigin: claim.DeviceSensitiveOrigin, DeviceEncKey: claim.DeviceEncKey, DeviceName: string(name), Time: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	confirmKey, _ := protocol.SecretKey(p.k, protocol.InfoPairConfirm)
	b, _ := json.Marshal(env)
	sealed, err := protocol.SealSecret(confirmKey, b, protocol.PairConfirmAAD(p.id))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// pairResult is what a finished pairing hands out.
type pairResult struct {
	confirm   protocol.PairConfirmResult // the terminal's view
	device    protocol.PairStatus        // the browser's view
	userToken string                     // the browser's token: its own, or the one the pairing issued
}

// pair runs a whole pairing through the API: the terminal starts it (with th.token once th is paired), the browser
// claims it (with userToken, or none), the terminal checks and confirms it, and the browser opens the confirmation.
func (h *harness) pair(th *testHost, d *testDevice, userToken string) pairResult {
	h.t.Helper()
	p := h.startPairing(th, th.token)
	var claimed protocol.PairStarted
	h.claim(p, th, d, userToken).expect(http.StatusOK).decode(&claimed)
	st := h.pairPoll(p.id, p.secret, "")
	if st.Status != protocol.PairClaimed || st.Claim == nil || st.Claim.Device != d.id {
		h.t.Fatalf("host poll %+v", st)
	}
	var res pairResult
	h.do(http.MethodPost, "/api/v1/pair/"+p.id+"/confirm", protocol.PairConfirm{Secret: p.secret, Confirm: confirmation(h.t, p, th, st.Claim)}).
		expect(http.StatusOK).decode(&res.confirm)
	if res.confirm.Token != "" {
		th.token = res.confirm.Token
	}
	res.device = h.pairPoll(p.id, claimed.Secret, "")
	if res.device.Status != protocol.PairConfirmed || res.device.Host == nil || *res.device.Host != (protocol.PairHost{ID: th.id, Key: th.key, EncKey: th.encKey}) {
		h.t.Fatalf("device poll %+v", res.device)
	}
	// The browser opens the confirmation and checks it is for its own keys and name.
	confirmKey, _ := protocol.SecretKey(p.k, protocol.InfoPairConfirm)
	b, err := protocol.OpenSecret(confirmKey, res.device.Confirm, protocol.PairConfirmAAD(p.id))
	if err != nil {
		h.t.Fatalf("opening the confirmation: %v", err)
	}
	var env protocol.Envelope
	var signed protocol.SignedPair
	if err := json.Unmarshal(b, &env); err != nil || env.Open(protocol.KindPair, &th.sign.PublicKey, &signed) != nil {
		h.t.Fatalf("confirmation doesn't verify: %v", err)
	}
	if signed.Device != d.id || signed.DeviceEncKey != d.encKey || signed.DeviceName != d.name || signed.HostEncKey != th.encKey || signed.HostName != th.name {
		h.t.Fatalf("confirmation %+v", signed)
	}
	res.userToken = userToken
	return res
}

// relayClient is one relay socket. A background reader collects messages (coder/websocket closes the connection
// when a Read is abandoned).
type relayClient struct {
	t      *testing.T
	conn   *websocket.Conn
	ctx    context.Context
	msgs   chan protocol.RelayMessage
	closed chan struct{}
	err    error // why the reader stopped
	hello  protocol.RelayMessage
}

func (h *harness) relay(path, token string) *relayClient {
	h.t.Helper()
	var headers []hdr
	if token != "" {
		headers = append(headers, bearer(token))
	}
	conn, ctx := h.dialWS(path, headers...)
	c := &relayClient{t: h.t, conn: conn, ctx: ctx, msgs: make(chan protocol.RelayMessage, 256), closed: make(chan struct{})}
	go func() {
		defer close(c.closed)
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				c.err = err
				return
			}
			var m protocol.RelayMessage
			if err := json.Unmarshal(data, &m); err != nil {
				c.err = err
				return
			}
			if m.Type != protocol.RelayPing {
				c.msgs <- m
			}
		}
	}()
	c.hello = c.next()
	if c.hello.Type != protocol.RelayHello {
		h.t.Fatalf("first message %+v, want hello", c.hello)
	}
	return c
}

// relayHost opens a host's relay socket.
func (h *harness) relayHost(th *testHost) *relayClient {
	h.t.Helper()
	c := h.relay("/api/v1/relay/host", th.token)
	mustEqual(h.t, "hello host", c.hello.Host, th.id)
	return c
}

// relayDevice opens a browser tab's relay socket.
func (h *harness) relayDevice(d *testDevice, userToken string) *relayClient {
	h.t.Helper()
	c := h.relay("/api/v1/relay/device?device="+d.id, userToken)
	mustEqual(h.t, "hello device", c.hello.Device, d.id)
	return c
}

func (c *relayClient) send(m protocol.RelayMessage) {
	c.t.Helper()
	b, _ := json.Marshal(m)
	if err := c.conn.Write(c.ctx, websocket.MessageText, b); err != nil {
		c.t.Fatalf("relay write: %v", err)
	}
}

func (c *relayClient) frame(f *protocol.SealedFrame) {
	c.t.Helper()
	c.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f})
}

// next returns the next message that isn't a ping.
func (c *relayClient) next() protocol.RelayMessage {
	c.t.Helper()
	select {
	case m := <-c.msgs:
		return m
	case <-c.closed:
		c.t.Fatalf("relay socket closed: %v", c.err)
	case <-time.After(waitTimeout):
		c.t.Fatal("timed out waiting for a relay message")
	}
	return protocol.RelayMessage{}
}

// relayed returns the next message, which must be the relay's answer to frame f.
func (c *relayClient) relayed(f *protocol.SealedFrame) protocol.RelayMessage {
	c.t.Helper()
	m := c.next()
	if m.Type != protocol.RelayRelayed || m.ID != f.ID || m.To != f.To {
		c.t.Fatalf("got %+v, want the relay's answer to %s", m, f.ID)
	}
	return m
}

// none asserts no message arrives for a short while.
func (c *relayClient) none() {
	c.t.Helper()
	select {
	case m := <-c.msgs:
		c.t.Fatalf("unexpected relay message %+v", m)
	case <-c.closed:
		c.t.Fatalf("relay socket closed: %v", c.err)
	case <-time.After(quietPeriod):
	}
}

// waitClosed waits until the server closes the socket and returns its close status and reason.
func (c *relayClient) waitClosed() websocket.CloseError {
	c.t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case <-c.msgs:
		case <-c.closed:
			var ce websocket.CloseError
			if !errors.As(c.err, &ce) {
				c.t.Fatalf("socket ended without a close frame: %v", c.err)
			}
			return ce
		case <-deadline:
			c.t.Fatal("relay socket not closed")
		}
	}
}

// pairedUser creates a user with a paired machine and browser, both connected to the relay.
type pairedUser struct {
	token  string
	host   *testHost
	device *testDevice
	hc     *relayClient
	dc     *relayClient
	pk     []byte
}

func (h *harness) pairedUser(username string) *pairedUser {
	h.t.Helper()
	_, token := h.addUser(username)
	p := &pairedUser{token: token, host: newTestHost(h.t, username+"-mbp"), device: newTestDevice(h.t, username+"'s browser")}
	h.pair(p.host, p.device, token)
	p.pk = pairKey(h.t, p.host, p.device)
	p.hc = h.relayHost(p.host)
	p.dc = h.relayDevice(p.device, token)
	return p
}
