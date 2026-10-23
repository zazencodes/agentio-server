package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/push"
	"agentio.sh/server/internal/store"
)

// The relay passes sealed frames between a host's bridge and its paired browsers while both are connected
// (docs/api.md §7). It checks who may talk to whom and counts frames; it never reads, stores or logs one.

const (
	relayPingInterval = 30 * time.Second
	relayIdleTimeout  = 75 * time.Second // no message (not even a pong) for this long closes the socket

	// relaySendQueue is how many messages (each up to 1 MiB) a socket may have waiting; one that falls further
	// behind is closed.
	relaySendQueue = 16
	webPushTTL     = 12 * time.Hour
)

// Live device sockets (browser tabs) an account and a device may hold at once.
var (
	maxDeviceSocketsPerUser   = 32
	maxDeviceSocketsPerDevice = 8
)

const (
	relayHost   = "host"
	relayDevice = "device"
)

// relayConn is one live relay socket.
type relayConn struct {
	kind         string // relayHost or relayDevice
	id           string // the host or device ID
	userID       string
	tokenID      string
	tokenExpires int64
	send         chan []byte
	done         chan struct{}
	lastRead     atomic.Int64 // Unix nanoseconds

	once        sync.Once
	closeStatus websocket.StatusCode
	closeReason string
	stalled     chan struct{} // closed when the socket can't keep up: it is dropped without waiting for its writes
	stallOnce   sync.Once
}

// close ends the socket with a status and a reason for the client.
func (c *relayConn) close(status websocket.StatusCode, reason string) {
	c.once.Do(func() {
		c.closeStatus, c.closeReason = status, reason
		close(c.done)
	})
}

func (c *relayConn) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// enqueue queues a message without blocking; a connection too slow to keep up is closed.
func (c *relayConn) enqueue(msg []byte) bool {
	if c.closed() {
		return false
	}
	select {
	case c.send <- msg:
		return true
	default:
		c.close(websocket.StatusTryAgainLater, "too slow")
		c.stallOnce.Do(func() { close(c.stalled) })
		return false
	}
}

// relayHub tracks live relay sockets: one per host (a new one replaces the old), any number per device (browser tabs).
type relayHub struct {
	mu          sync.RWMutex
	hosts       map[string]*relayConn
	devices     map[string]map[*relayConn]bool
	userDevices map[string]int // live device sockets per account
}

func newRelayHub() *relayHub {
	return &relayHub{hosts: map[string]*relayConn{}, devices: map[string]map[*relayConn]bool{}, userDevices: map[string]int{}}
}

// addHost registers a host's socket, closing the one it replaces, and reports whether the host just came online.
func (h *relayHub) addHost(c *relayConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.hosts[c.id]
	if old != nil {
		old.close(websocket.StatusNormalClosure, "replaced by a new connection")
	}
	h.hosts[c.id] = c
	return old == nil
}

// removeHost unregisters a host's socket and reports whether the host went offline.
func (h *relayHub) removeHost(c *relayConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hosts[c.id] != c {
		return false
	}
	delete(h.hosts, c.id)
	return true
}

// addDevice registers a device's socket unless the device or its account already has as many as allowed; hello is
// queued first, under the lock, so no presence change can overtake it.
func (h *relayHub) addDevice(c *relayConn, linked []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.devices[c.id]) >= maxDeviceSocketsPerDevice || h.userDevices[c.userID] >= maxDeviceSocketsPerUser {
		return errTooManySockets
	}
	hosts := []protocol.HostPresence{}
	for _, id := range linked {
		hosts = append(hosts, protocol.HostPresence{Host: id, Online: h.hosts[id] != nil})
	}
	c.enqueue(relayMessage(protocol.RelayMessage{Type: protocol.RelayHello, Device: c.id, Hosts: hosts}))
	if h.devices[c.id] == nil {
		h.devices[c.id] = map[*relayConn]bool{}
	}
	h.devices[c.id][c] = true
	h.userDevices[c.userID]++
	return nil
}

func (h *relayHub) removeDevice(c *relayConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.devices[c.id][c] {
		return
	}
	delete(h.devices[c.id], c)
	if len(h.devices[c.id]) == 0 {
		delete(h.devices, c.id)
	}
	if h.userDevices[c.userID]--; h.userDevices[c.userID] == 0 {
		delete(h.userDevices, c.userID)
	}
}

func (h *relayHub) hostOnline(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hosts[id] != nil
}

// deliver queues a message on every live socket of a host or device and reports whether any took it.
func (h *relayHub) deliver(to string, msg []byte) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	delivered := false
	if c := h.hosts[to]; c != nil {
		delivered = c.enqueue(msg)
	}
	for c := range h.devices[to] {
		if c.enqueue(msg) {
			delivered = true
		}
	}
	return delivered
}

// closeWhere closes every socket matching f.
func (h *relayHub) closeWhere(reason string, f func(*relayConn) bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.hosts {
		if f(c) {
			c.close(websocket.StatusPolicyViolation, reason)
		}
	}
	for _, conns := range h.devices {
		for c := range conns {
			if f(c) {
				c.close(websocket.StatusPolicyViolation, reason)
			}
		}
	}
}

func (h *relayHub) closeToken(id string) {
	h.closeWhere("token revoked", func(c *relayConn) bool { return c.tokenID == id })
}

func (h *relayHub) closeUser(userID string) {
	h.closeWhere("account deleted", func(c *relayConn) bool { return c.userID == userID })
}

func (h *relayHub) closeHost(id string) {
	h.closeWhere("machine removed", func(c *relayConn) bool { return c.kind == relayHost && c.id == id })
}

func (h *relayHub) closeDevices(reason string, ids ...string) {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	h.closeWhere(reason, func(c *relayConn) bool { return c.kind == relayDevice && set[c.id] })
}

func (h *relayHub) count(kind string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if kind == relayHost {
		return len(h.hosts)
	}
	n := 0
	for _, conns := range h.devices {
		n += len(conns)
	}
	return n
}

func relayMessage(m protocol.RelayMessage) []byte {
	b, _ := json.Marshal(m)
	return b
}

// handleRelayHost is the bridge's socket (host token).
func (s *Server) handleRelayHost(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if v.token == nil {
		return ErrUnauthorized
	}
	if !v.isHost() {
		return ErrForbidden.Wrap("the host relay needs a machine's token")
	}
	h, err := s.store.Host(r.Context(), v.token.HostID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrUnauthorized
	} else if err != nil {
		return err
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	c := s.newRelayConn(relayHost, h.ID, v)
	c.enqueue(relayMessage(protocol.RelayMessage{Type: protocol.RelayHello, Host: h.ID}))
	if s.relay.addHost(c) {
		s.presence(h.ID, true)
	}
	defer func() {
		if s.relay.removeHost(c) {
			s.presence(h.ID, false)
		}
	}()
	s.runRelay(r.Context(), ws, c)
	return nil
}

// handleRelayDevice is a browser tab's socket (user token); the device must be the token's user's.
func (s *Server) handleRelayDevice(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if v.token == nil {
		return ErrUnauthorized
	}
	if v.isHost() {
		return errHostTokenNotAllowed
	}
	ctx := r.Context()
	d, err := s.store.Device(ctx, r.URL.Query().Get("device"))
	if errors.Is(err, store.ErrNotFound) || err == nil && d.UserID != v.user.ID {
		return ErrForbidden.Wrap("that device isn't paired with this account")
	} else if err != nil {
		return err
	}
	linked, err := s.store.DeviceHosts(ctx, d.ID)
	if err != nil {
		return err
	}
	c := s.newRelayConn(relayDevice, d.ID, v)
	if err := s.relay.addDevice(c, linked); err != nil {
		return err
	}
	defer s.relay.removeDevice(c)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	s.runRelay(ctx, ws, c)
	return nil
}

func (s *Server) newRelayConn(kind, id string, v *Caller) *relayConn {
	c := &relayConn{kind: kind, id: id, userID: v.user.ID, tokenID: v.token.ID, tokenExpires: v.token.Expires,
		send: make(chan []byte, relaySendQueue), done: make(chan struct{}), stalled: make(chan struct{})}
	c.lastRead.Store(time.Now().UnixNano())
	return c
}

// presence tells a host's linked devices that it came online or went offline.
func (s *Server) presence(hostID string, online bool) {
	devices, err := s.store.HostDevices(context.Background(), hostID)
	if err != nil {
		s.log.Error("loading a machine's devices for presence", "error", err)
		return
	}
	msg := relayMessage(protocol.RelayMessage{Type: protocol.RelayPresence, Host: hostID, Online: &online})
	for _, d := range devices {
		s.relay.deliver(d, msg)
	}
}

// runRelay serves one socket until either side closes it: a reader handles the client's messages, this goroutine
// writes queued messages and pings.
func (s *Server) runRelay(ctx context.Context, ws *websocket.Conn, c *relayConn) {
	defer ws.CloseNow()
	ws.SetReadLimit(protocol.MaxRelayMessage)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-c.stalled:
			ws.CloseNow()
		case <-ctx.Done():
		}
	}()
	go func() {
		defer cancel()
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			c.lastRead.Store(time.Now().UnixNano())
			if typ != websocket.MessageText {
				c.close(websocket.StatusUnsupportedData, "messages are JSON text")
				return
			}
			s.handleRelayMessage(ctx, c, data)
		}
	}()
	write := func(msg []byte) bool {
		wctx, wcancel := context.WithTimeout(ctx, 15*time.Second)
		defer wcancel()
		return ws.Write(wctx, websocket.MessageText, msg) == nil
	}
	ping := time.NewTicker(s.pingInterval)
	defer ping.Stop()
	pingMsg := relayMessage(protocol.RelayMessage{Type: protocol.RelayPing})
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			// Flush what was queued before the close, so replies arrive before the reason.
		flush:
			for {
				select {
				case msg := <-c.send:
					if !write(msg) {
						return
					}
				default:
					break flush
				}
			}
			ws.Close(c.closeStatus, c.closeReason)
			return
		case msg := <-c.send:
			if !write(msg) {
				return
			}
		case now := <-ping.C:
			if c.tokenExpires > 0 && c.tokenExpires <= now.Unix() {
				c.close(websocket.StatusPolicyViolation, "token expired")
				continue
			}
			if now.Sub(time.Unix(0, c.lastRead.Load())) > s.idleTimeout {
				c.close(websocket.StatusPolicyViolation, "no pong")
				continue
			}
			if !write(pingMsg) {
				return
			}
		}
	}
}

// handleRelayMessage checks and relays one client message. A client that breaks the protocol is disconnected; a frame
// that may not be relayed is refused.
func (s *Server) handleRelayMessage(ctx context.Context, c *relayConn, data []byte) {
	var m protocol.RelayMessage
	if json.Unmarshal(data, &m) != nil {
		c.close(websocket.StatusPolicyViolation, "not a relay message")
		return
	}
	switch m.Type {
	case protocol.RelayPong:
		return
	case protocol.RelayFrame:
	default:
		c.close(websocket.StatusPolicyViolation, "unknown message type")
		return
	}
	f := m.Frame
	if !wellFormed(f) {
		c.close(websocket.StatusPolicyViolation, "malformed frame")
		return
	}
	if f.From != c.id {
		c.close(websocket.StatusPolicyViolation, "frame.from must be this connection's own ID")
		return
	}
	if m.Push != nil && (c.kind != relayHost || !wellFormed(m.Push) || m.Push.From != f.From || m.Push.To != f.To) {
		c.close(websocket.StatusPolicyViolation, "push must come from a machine, for the same device as its frame")
		return
	}
	reply := func(result string, refusal *APIError) {
		r := protocol.RelayMessage{Type: protocol.RelayRelayed, ID: f.ID, To: f.To, Result: result}
		if refusal != nil {
			r.Code, r.Error = refusal.Code, refusal.Message
		}
		c.enqueue(relayMessage(r))
	}
	hostID, deviceID := c.id, f.To
	if c.kind == relayDevice {
		hostID, deviceID = f.To, c.id
	}
	linked, err := s.store.Linked(ctx, hostID, deviceID)
	if err != nil {
		s.log.Error("checking a relay link", "error", err)
		reply(protocol.RelayRefused, ErrInternal)
		return
	}
	if !linked {
		reply(protocol.RelayRefused, errNotPaired)
		return
	}
	u, err := s.store.UserByID(ctx, c.userID)
	if errors.Is(err, store.ErrNotFound) {
		c.close(websocket.StatusPolicyViolation, "account deleted")
		return
	} else if err != nil {
		s.log.Error("loading a relay account", "error", err)
		reply(protocol.RelayRefused, ErrInternal)
		return
	}
	if s.ext.RelayFrame != nil {
		if err := s.ext.RelayFrame(ctx, u, int64(len(data))); err != nil {
			var refusal *APIError
			if !errors.As(err, &refusal) {
				s.log.Error("checking a relay frame", "error", err)
				refusal = ErrInternal
			}
			reply(protocol.RelayRefused, refusal)
			return
		}
	}
	if s.relay.deliver(f.To, relayMessage(protocol.RelayMessage{Type: protocol.RelayFrame, Frame: f})) {
		reply(protocol.RelayDelivered, nil)
		return
	}
	if m.Push != nil {
		s.forwardPush(deviceID, m.Push)
	}
	reply(protocol.RelayOffline, nil)
}

// wellFormed checks a sealed frame's shape: the server can't check more.
func wellFormed(f *protocol.SealedFrame) bool {
	return f != nil && f.ID != "" && len(f.ID) <= 64 && f.From != "" && f.To != "" && len(f.To) <= 64 && f.Nonce != "" && f.CT != ""
}

// forwardPush sends a push frame as the payload of a Web Push to an offline device, if it has a subscription, and
// forgets it. A subscription the push service no longer knows is deleted.
func (s *Server) forwardPush(deviceID string, frame *protocol.SealedFrame) {
	if s.webpush == nil {
		return
	}
	sub, err := s.store.WebPushFor(context.Background(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return
	} else if err != nil {
		s.log.Error("loading a push subscription", "error", err)
		return
	}
	payload, _ := json.Marshal(frame)
	s.wg.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := s.webpush.Send(ctx, sub.Endpoint, sub.Auth, sub.P256dh, payload, webPushTTL)
		switch {
		case errors.Is(err, push.ErrUnregistered):
			if err := s.store.DeleteWebPush(ctx, sub.DeviceID, sub.Endpoint); err != nil {
				s.log.Error("deleting an expired push subscription", "error", err)
			}
		case err != nil:
			// The endpoint is a capability URL: log the cause, never the URL.
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			s.log.Warn("web push failed", "error", err)
		}
	})
}
