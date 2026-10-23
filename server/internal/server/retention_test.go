package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"agentio.sh/protocol"
)

// The server stores nothing (spec §2): a machine and a browser with real keys pair through the API, then relay an
// update with a request, a sealed response, a command and its update, and a frame for an offline browser. The
// database is identical before and after the relay traffic except for token last_access, nothing about the content
// reaches the database, and no log line (at debug level) holds any content, ciphertext, nonce, frame ID,
// token or IP address.
func TestZeroRetention(t *testing.T) {
	h := newHarness(t)
	const marker = "MARKER-7f3a"
	_, token := h.addUser("alex")
	th, d := newTestHost(t, marker+"-host-name"), newTestDevice(t, marker+"-device-name")
	h.pair(th, d, token)
	pk := pairKey(t, th, d)
	hc := h.relayHost(th)
	dc := h.relayDevice(d, token)

	skip := []string{"tokens.last_access"}
	before := h.dump(skip...)
	var frames []*protocol.SealedFrame
	relay := func(from, to *relayClient, f *protocol.SealedFrame) *protocol.Envelope {
		t.Helper()
		frames = append(frames, f)
		from.frame(f)
		if m := from.relayed(f); m.Result != protocol.RelayDelivered {
			t.Fatalf("relayed %+v", m)
		}
		m := to.next()
		if m.Type != protocol.RelayFrame || *m.Frame != *f {
			t.Fatalf("received %+v", m)
		}
		env, err := m.Frame.Open(pk)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	now := time.Now().Unix()
	session := protocol.SessionID(th.id, protocol.ProviderCodex, "native-1")

	// The bridge opens an approval.
	reqEnv, err := protocol.Sign(th.sign, th.id, protocol.KindRequest, protocol.SignedRequest{ID: "req_1", Host: th.id, Session: session,
		Type: protocol.RequestApproval, Title: marker + "-request-title", Body: marker + "-request-body", Options: []string{},
		Created: now, Expires: now + 600})
	if err != nil {
		t.Fatal(err)
	}
	update := protocol.Update{Host: th.id, Time: now, Epoch: "epo_1",
		Machine:  &protocol.Machine{Name: marker + "-machine", OS: "darwin", Arch: "arm64", Version: "0.4.0"},
		Projects: []protocol.Project{{ID: "prj_1", Name: marker + "-project", Path: "~/pro/" + marker, Seq: 1}},
		Sessions: []protocol.Session{{ID: session, Project: "prj_1", Provider: protocol.ProviderCodex, NativeID: "native-1", Title: marker + "-session", Seq: 2}},
		Items: []protocol.Item{{ID: "req_1", Session: session, Type: protocol.ItemRequest, Time: now, Pos: 3, Seq: 3,
			Request: &protocol.RequestItem{Envelope: reqEnv, Status: protocol.RequestPending}}}}
	env := relay(hc, dc, sealFrom(t, pk, th.sign, th.id, d.id, protocol.KindUpdate, update))
	var got protocol.Update
	if err := env.Open(protocol.KindUpdate, &th.sign.PublicKey, &got); err != nil || got.Items[0].Request.Envelope.PayloadHash() != reqEnv.PayloadHash() {
		t.Fatalf("browser's update %+v %v", got, err)
	}

	// The browser approves it and replies.
	response := protocol.SignedResponse{Request: "req_1", RequestHash: reqEnv.PayloadHash(), Decision: protocol.DecisionApprove, Text: marker + "-reason", Time: now}
	env = relay(dc, hc, sealFrom(t, pk, d.sign, d.id, th.id, protocol.KindResponse, response))
	var gotResponse protocol.SignedResponse
	if err := env.Open(protocol.KindResponse, &d.sign.PublicKey, &gotResponse); err != nil || gotResponse != response {
		t.Fatalf("bridge's response %+v %v", gotResponse, err)
	}
	command := protocol.SignedCommand{ID: "cmd_1", Host: th.id, Session: session, Text: marker + "-command-text", Created: now, Expires: now + 86400}
	env = relay(dc, hc, sealFrom(t, pk, d.sign, d.id, th.id, protocol.KindCommand, command))
	var gotCommand protocol.SignedCommand
	if err := env.Open(protocol.KindCommand, &d.sign.PublicKey, &gotCommand); err != nil || gotCommand != command {
		t.Fatalf("bridge's command %+v %v", gotCommand, err)
	}

	// The bridge reports both.
	update = protocol.Update{Host: th.id, Time: now, Epoch: "epo_1", Items: []protocol.Item{
		{ID: "req_1", Session: session, Type: protocol.ItemRequest, Time: now, Pos: 3, Seq: 4, Request: &protocol.RequestItem{Envelope: reqEnv,
			Status: protocol.RequestApproved, Response: &protocol.ResponseRecord{Decision: protocol.DecisionApprove, Text: response.Text, Time: now, Signer: d.id, Device: d.name}}},
		{ID: "cmd_1", Session: session, Type: protocol.ItemCommand, Time: now, Pos: 4, Seq: 5, Command: &protocol.CommandItem{Text: command.Text,
			Created: now, Expires: command.Expires, Signer: d.id, Device: d.name, State: protocol.CommandDelivered, Updated: now}},
	}}
	relay(hc, dc, sealFrom(t, pk, th.sign, th.id, d.id, protocol.KindUpdate, update))

	// A frame and push for a browser that has gone away are dropped, not kept.
	dc.conn.Close(websocket.StatusNormalClosure, "")
	eventually(t, func() bool { return h.srv.relay.count(relayDevice) == 0 })
	f := sealFrom(t, pk, th.sign, th.id, d.id, protocol.KindUpdate, update)
	pf := sealFrom(t, pk, th.sign, th.id, d.id, protocol.KindPush, protocol.SignedPush{ID: "evt_1", Host: th.id, Session: session, Title: marker + "-push", Time: now})
	frames = append(frames, f, pf)
	hc.send(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f, Push: pf})
	if m := hc.relayed(f); m.Result != protocol.RelayOffline {
		t.Fatalf("relayed %+v", m)
	}

	if after := h.dump(skip...); after != before {
		t.Fatalf("relaying changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if all := h.dump(); strings.Contains(all, marker) {
		t.Fatalf("content reached the database:\n%s", all)
	}

	logs := h.logs.String()
	if !strings.Contains(logs, `"route":"GET /api/v1/relay/device"`) || !strings.Contains(logs, `"level":"DEBUG"`) {
		t.Fatalf("expected debug request logs, got:\n%s", logs)
	}
	secrets := []string{marker, token, th.token, "127.0.0.1", "secret="}
	for _, f := range frames {
		raw, _ := json.Marshal(f)
		secrets = append(secrets, f.ID, f.Nonce, f.CT, string(raw))
	}
	for _, line := range strings.Split(logs, "\n") {
		for _, s := range secrets {
			if s != "" && strings.Contains(line, s) {
				t.Fatalf("log line holds %q: %s", s, line)
			}
		}
	}
}

// Request logs name the route template, never the path, query string or credentials.
func TestRequestLogsNameRoutesOnly(t *testing.T) {
	h := newHarness(t)
	p := h.pairedUser("alex")
	h.do(http.MethodDelete, "/api/v1/hosts/"+p.host.id+"/devices/"+p.device.id+"?auth=zz9qq&note=private", nil, bearer(p.token)).expect(http.StatusOK)
	h.do(http.MethodGet, "/no/such/path/private", nil).expectError(ErrNotFound)
	logs := h.logs.String()
	if !strings.Contains(logs, `"route":"DELETE /api/v1/hosts/{id}/devices/{device}"`) {
		t.Fatalf("no route template in logs:\n%s", logs)
	}
	for _, s := range []string{p.host.id, p.device.id, "private", p.token, "zz9qq"} {
		if strings.Contains(logs, s) {
			t.Fatalf("logs hold %q:\n%s", s, logs)
		}
	}
}
