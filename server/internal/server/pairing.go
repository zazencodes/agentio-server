package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/store"
)

// Pairing exchanges the host's and the device's public keys over the terminal's code (docs/api.md §5). The server
// relays the claim and the sealed confirmation; it never sees the secret K, so it can neither forge a claim nor
// swap a key, and it can't read the names. Pairings live only in memory: a restart loses them.

const (
	pairingTTL = 10 * time.Minute
	// pairingKeep is how long a finished or expired pairing stays, so pollers still learn how it ended.
	pairingKeep = 10 * time.Minute
	// maxPairings bounds the pairings in memory; when full, a new pairing evicts the oldest unclaimed one.
	maxPairings = 10000
	// maxPairingsPerIP bounds the unclaimed pairings of one client IP (IPv6: one /64); a new one evicts its oldest.
	maxPairingsPerIP = 5
	// maxSealedConfirm bounds the sealed confirmation.
	maxSealedConfirm = 16 << 10
)

// pairing is one pairing in flight. Fields after mu are guarded by it.
type pairing struct {
	id         string
	secretHash string // the host's poll secret
	hostKey    string
	hostEncKey string
	hostID     string
	userID     string // the account of an already paired machine (`agentio devices add`)
	ipKey      string // the starting client's IP, or its /64 for IPv6
	created    time.Time

	mu              sync.Mutex
	expires         time.Time
	status          string
	claim           *protocol.PairClaim
	claimSecretHash string
	claimUserID     string
	confirm         string
	username        string
	changed         chan struct{}
}

// wake wakes everyone long-polling the pairing. Callers hold mu.
func (p *pairing) wake() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// currentStatus returns the pairing's status as pollers see it. Callers hold mu.
func (p *pairing) currentStatus(now time.Time) string {
	if (p.status == protocol.PairPending || p.status == protocol.PairClaimed) && !now.Before(p.expires) {
		return protocol.PairExpired
	}
	return p.status
}

// pairings holds the pairings in flight.
type pairings struct {
	mu  sync.Mutex
	m   map[string]*pairing
	max int
}

func newPairings() *pairings { return &pairings{m: map[string]*pairing{}, max: maxPairings} }

// add registers a pairing. An IP holding maxPairingsPerIP unclaimed pairings loses its oldest one, and a full table
// loses its oldest unclaimed (or expired, or rejected) pairing, so nobody can lock others out of pairing.
func (ps *pairings) add(p *pairing) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.m[p.id] != nil {
		return errPairingClaimed
	}
	now := time.Now()
	var mine []*pairing
	for _, o := range ps.m {
		if o.ipKey == p.ipKey && o.unclaimed(now) {
			mine = append(mine, o)
		}
	}
	if len(mine) >= maxPairingsPerIP {
		ps.evict(oldest(mine), now)
	}
	if len(ps.m) >= ps.max {
		var evictable []*pairing
		for _, o := range ps.m {
			if o.evictable(now) {
				evictable = append(evictable, o)
			}
		}
		if len(evictable) == 0 {
			return errTooManyPairings
		}
		ps.evict(oldest(evictable), now)
	}
	ps.m[p.id] = p
	return nil
}

// evict forgets a pairing; its pollers see it expire. Callers hold ps.mu.
func (ps *pairings) evict(p *pairing, now time.Time) {
	delete(ps.m, p.id)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.expires.After(now) {
		p.expires = now
	}
	p.wake()
}

func oldest(list []*pairing) *pairing {
	o := list[0]
	for _, p := range list[1:] {
		if p.created.Before(o.created) {
			o = p
		}
	}
	return o
}

// unclaimed reports whether nobody has claimed the pairing and it hasn't expired.
func (p *pairing) unclaimed(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentStatus(now) == protocol.PairPending
}

// evictable reports whether forgetting the pairing loses nothing in progress: it is unclaimed, expired or rejected.
func (p *pairing) evictable(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.currentStatus(now) {
	case protocol.PairPending, protocol.PairExpired, protocol.PairRejected:
		return true
	}
	return false
}

// ipKey groups client IPs for pairing limits: an IPv4 address, or the /64 of an IPv6 address.
func ipKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (ps *pairings) get(id string) (*pairing, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if p := ps.m[id]; p != nil {
		return p, nil
	}
	return nil, ErrNotFound
}

// prune forgets pairings that expired at least pairingKeep ago.
func (ps *pairings) prune(now time.Time) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for id, p := range ps.m {
		p.mu.Lock()
		forget := now.Sub(p.expires) >= pairingKeep
		p.mu.Unlock()
		if forget {
			delete(ps.m, id)
		}
	}
}

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request, v *Caller) error {
	ctx := r.Context()
	var req protocol.PairStart
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	if !strings.HasPrefix(req.ID, "pair_") || len(req.ID) > 64 {
		return ErrBadRequest.Wrap("id must be a pair_ ID")
	}
	if _, err := protocol.ParsePublicKey(req.HostKey); err != nil {
		return ErrBadRequest.Wrap("host_key: %v", err)
	}
	if _, err := protocol.ParseEncKey(req.HostEncKey); err != nil {
		return ErrBadRequest.Wrap("host_enc_key: %v", err)
	}
	now := time.Now()
	p := &pairing{id: req.ID, hostKey: req.HostKey, hostEncKey: req.HostEncKey, hostID: protocol.KeyID("hst_", req.HostKey),
		ipKey: ipKey(v.ip), created: now, expires: now.Add(pairingTTL), status: protocol.PairPending, changed: make(chan struct{})}
	h, err := s.store.Host(ctx, p.hostID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if v.isHost() {
			return errHostTokenNotAllowed.Wrap("this token belongs to another machine")
		}
	case err != nil:
		return err
	case !v.isHost() || v.token.HostID != h.ID:
		return errHostPaired
	case h.EncKey != req.HostEncKey:
		return errHostKeyChanged
	default:
		p.userID = h.UserID // adding a device to a paired machine
	}
	secret := randomString(32)
	p.secretHash = sha256Hex(secret)
	expires := p.expires.Unix()
	if err := s.pairings.add(p); err != nil {
		return err
	}
	WriteJSON(w, http.StatusOK, protocol.PairStarted{ID: p.id, Secret: secret, Expires: expires})
	return nil
}

func (s *Server) handlePairClaim(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if v.isHost() {
		return errHostTokenNotAllowed
	}
	ctx := r.Context()
	var req protocol.PairClaim
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	for _, k := range []string{req.DeviceKey, req.DeviceSensitiveKey} {
		if _, err := protocol.ParsePublicKey(k); err != nil {
			return ErrBadRequest.Wrap("device keys: %v", err)
		}
	}
	if _, err := protocol.ParseEncKey(req.DeviceEncKey); err != nil {
		return ErrBadRequest.Wrap("device_enc_key: %v", err)
	}
	if req.DeviceKey == req.DeviceSensitiveKey {
		return ErrBadRequest.Wrap("device_key and device_sensitive_key must differ")
	}
	if err := protocol.ValidateWebAuthnOrigin(req.DeviceSensitiveOrigin); err != nil {
		return ErrBadRequest.Wrap("device_sensitive_origin: %v", err)
	}
	if req.SealedName == "" || len(req.SealedName) > protocol.MaxSealedName {
		return ErrBadRequest.Wrap("sealed_name is required (at most %d characters)", protocol.MaxSealedName)
	}
	if req.MAC == "" || len(req.MAC) > 64 {
		return ErrBadRequest.Wrap("mac is required")
	}
	p, err := s.pairings.get(r.PathValue("id"))
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.currentStatus(time.Now()) {
	case protocol.PairPending:
	case protocol.PairExpired:
		return errExpired
	default:
		return errPairingClaimed
	}
	// Claiming needs a signed-in browser: the new machine joins its account, and adding a browser to a paired machine
	// needs a user token of the machine's account, so a stolen machine token can't be turned into a user token.
	if err := RequireUserToken(v); err != nil {
		return err
	}
	if p.userID != "" && p.userID != v.user.ID {
		return errOtherAccount
	}
	owner := v.user.ID
	device := &store.Device{ID: protocol.KeyID("dev_", req.DeviceKey), Key: req.DeviceKey, SensitiveKey: req.DeviceSensitiveKey,
		EncKey: req.DeviceEncKey, SensitiveOrigin: req.DeviceSensitiveOrigin}
	if err := s.checkDevice(ctx, device, owner); err != nil {
		return err
	}
	secret := randomString(32)
	req.Device = device.ID
	p.status, p.claim, p.claimSecretHash, p.claimUserID = protocol.PairClaimed, &req, sha256Hex(secret), owner
	p.wake()
	WriteJSON(w, http.StatusOK, protocol.PairStarted{Secret: secret, Expires: p.expires.Unix()})
	return nil
}

// checkDevice refuses a device that belongs to another account, or that pairs again with other keys. owner is ""
// for a claim that will create an account.
func (s *Server) checkDevice(ctx context.Context, d *store.Device, owner string) error {
	existing, err := s.store.Device(ctx, d.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	case existing.UserID != owner:
		return errOtherAccount
	case !existing.SameKeys(d):
		return errDeviceKeyChanged
	}
	return nil
}

func (s *Server) handlePairPoll(w http.ResponseWriter, r *http.Request, _ *Caller) error {
	ctx := r.Context()
	p, err := s.pairings.get(r.PathValue("id"))
	if err != nil {
		return err
	}
	secret := sha256Hex(r.URL.Query().Get("secret"))
	p.mu.Lock()
	host := secret == p.secretHash
	if !host && (p.claimSecretHash == "" || secret != p.claimSecretHash) {
		p.mu.Unlock()
		return ErrNotFound
	}
	// The host waits for a claim, the device for the terminal's answer.
	waiting := func() bool {
		st := p.currentStatus(time.Now())
		return host && st == protocol.PairPending || !host && st == protocol.PairClaimed
	}
	if wait, _ := strconv.Atoi(r.URL.Query().Get("wait")); wait > 0 && waiting() {
		ch, until := p.changed, time.Until(p.expires)
		p.mu.Unlock()
		timer := time.NewTimer(min(time.Duration(min(wait, 60))*time.Second, until))
		select {
		case <-ch:
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil // the client went away
		}
		timer.Stop()
		p.mu.Lock()
	}
	defer p.mu.Unlock()
	out := protocol.PairStatus{Status: p.currentStatus(time.Now())}
	switch {
	case host && out.Status == protocol.PairClaimed:
		out.Claim = p.claim
	case !host && out.Status == protocol.PairConfirmed:
		out.Confirm, out.Host, out.Username = p.confirm, &protocol.PairHost{ID: p.hostID, Key: p.hostKey, EncKey: p.hostEncKey}, p.username
	}
	WriteJSON(w, http.StatusOK, out)
	return nil
}

// claimedPairing returns a claimed pairing, locked, for the host holding its poll secret.
func (s *Server) claimedPairing(id, secret string) (*pairing, error) {
	p, err := s.pairings.get(id)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if sha256Hex(secret) != p.secretHash {
		p.mu.Unlock()
		return nil, ErrNotFound
	}
	switch st := p.currentStatus(time.Now()); st {
	case protocol.PairClaimed:
		return p, nil
	case protocol.PairExpired:
		p.mu.Unlock()
		return nil, errExpired
	default:
		p.mu.Unlock()
		return nil, ErrBadRequest.Wrap("pairing is %s, not claimed", st)
	}
}

func (s *Server) handlePairConfirm(w http.ResponseWriter, r *http.Request, _ *Caller) error {
	ctx := r.Context()
	var req protocol.PairConfirm
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Confirm == "" || len(req.Confirm) > maxSealedConfirm {
		return ErrBadRequest.Wrap("confirm is required")
	}
	p, err := s.claimedPairing(r.PathValue("id"), req.Secret)
	if err != nil {
		return err
	}
	defer p.mu.Unlock()
	now := time.Now().Unix()
	c := p.claim
	rec := &store.PairingRecord{
		Host:   &store.Host{ID: p.hostID, UserID: p.userID, Key: p.hostKey, EncKey: p.hostEncKey, Created: now},
		Device: &store.Device{ID: c.Device, Key: c.DeviceKey, SensitiveKey: c.DeviceSensitiveKey, EncKey: c.DeviceEncKey, SensitiveOrigin: c.DeviceSensitiveOrigin, Created: now},
	}
	newHost := p.userID == ""
	if newHost {
		rec.Host.UserID = p.claimUserID
		rec.HostToken = NewToken(rec.Host.UserID, store.TokenHost, "Machine", 0)
		rec.HostToken.HostID = p.hostID
	}
	switch err := s.store.CompletePairing(ctx, rec); {
	case errors.Is(err, store.ErrConflict):
		return errHostPaired
	case errors.Is(err, store.ErrDeviceElsewhere):
		return errOtherAccount
	case errors.Is(err, store.ErrDeviceKeys):
		return errDeviceKeyChanged
	case err != nil:
		return err
	}
	u, err := s.store.UserByID(ctx, rec.Host.UserID)
	if err != nil {
		return err
	}
	p.status, p.confirm, p.username = protocol.PairConfirmed, req.Confirm, u.Username
	p.wake()
	out := protocol.PairConfirmResult{HostID: p.hostID, Username: u.Username}
	if rec.HostToken != nil {
		out.Token = rec.HostToken.Token
	}
	WriteJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePairReject(w http.ResponseWriter, r *http.Request, _ *Caller) error {
	var req struct {
		Secret string `json:"secret"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	p, err := s.claimedPairing(r.PathValue("id"), req.Secret)
	if err != nil {
		return err
	}
	defer p.mu.Unlock()
	p.status = protocol.PairRejected
	p.wake()
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}
