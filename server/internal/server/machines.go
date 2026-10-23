package server

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"agentio.sh/protocol"
	"agentio.sh/server/internal/store"
)

// Machines (hosts) and devices as the server knows them: public keys and links, never names (docs/api.md §9.1).
// A host token sees and changes only its own machine.

func (s *Server) handleHostsList(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := requireUser(v); err != nil {
		return err
	}
	hosts, err := s.store.Hosts(r.Context(), v.user.ID)
	if err != nil {
		return err
	}
	out := []protocol.HostInfo{}
	for _, h := range hosts {
		if v.isHost() && h.ID != v.token.HostID {
			continue
		}
		out = append(out, protocol.HostInfo{ID: h.ID, Key: h.Key, EncKey: h.EncKey, Online: s.relay.hostOnline(h.ID), Created: h.Created})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"hosts": out})
	return nil
}

func (s *Server) handleHostDelete(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := requireUser(v); err != nil {
		return err
	}
	id := r.PathValue("id")
	if v.isHost() && v.token.HostID != id {
		return ErrNotFound // a machine can only unpair itself
	}
	devices, err := s.store.DeleteHost(r.Context(), v.user.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	s.relay.closeHost(id)
	s.relay.closeDevices("machine removed", devices...)
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

func (s *Server) handleDevicesList(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := requireUser(v); err != nil {
		return err
	}
	devices, err := s.store.Devices(r.Context(), v.user.ID)
	if err != nil {
		return err
	}
	out := []protocol.DeviceInfo{}
	for _, d := range devices {
		if v.isHost() && !contains(d.Hosts, v.token.HostID) {
			continue
		}
		out = append(out, protocol.DeviceInfo{ID: d.ID, Key: d.Key, SensitiveKey: d.SensitiveKey, EncKey: d.EncKey,
			SensitiveOrigin: d.SensitiveOrigin, Hosts: d.Hosts, Created: d.Created})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"devices": out})
	return nil
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := RequireUserToken(v); err != nil {
		return err
	}
	id := r.PathValue("id")
	if err := s.store.DeleteDevice(r.Context(), v.user.ID, id); errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	s.relay.closeDevices("device unpaired", id)
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

// handleHostDeviceDelete unlinks a device from a machine: the machine itself (`agentio devices remove`) or the user.
func (s *Server) handleHostDeviceDelete(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := requireUser(v); err != nil {
		return err
	}
	hostID, deviceID := r.PathValue("id"), r.PathValue("device")
	if v.isHost() && v.token.HostID != hostID {
		return ErrNotFound
	}
	if err := s.store.DeleteLink(r.Context(), v.user.ID, hostID, deviceID); errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	s.relay.closeDevices("unpaired from a machine", deviceID)
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

// userDevice returns one of the caller's devices.
func (s *Server) userDevice(r *http.Request, v *Caller) (*store.Device, error) {
	d, err := s.store.Device(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && d.UserID != v.user.ID {
		return nil, ErrNotFound
	}
	return d, err
}

func (s *Server) handleWebPushSet(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := RequireUserToken(v); err != nil {
		return err
	}
	if s.webpush == nil {
		return errPushUnavailable
	}
	d, err := s.userDevice(r, v)
	if err != nil {
		return err
	}
	var req protocol.WebPushSubscription
	if err := DecodeJSON(r, &req); err != nil {
		return err
	}
	if !s.validPushEndpoint(req.Endpoint) {
		return ErrBadRequest.Wrap("endpoint must be an https URL of a browser push service")
	}
	if req.Auth == "" || len(req.Auth) > 64 || req.P256dh == "" || len(req.P256dh) > 128 {
		return ErrBadRequest.Wrap("auth and p256dh are the subscription's keys")
	}
	if err := s.store.SetWebPush(r.Context(), &store.WebPush{DeviceID: d.ID, Endpoint: req.Endpoint, Auth: req.Auth, P256dh: req.P256dh}); err != nil {
		return err
	}
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

func (s *Server) handleWebPushDelete(w http.ResponseWriter, r *http.Request, v *Caller) error {
	if err := RequireUserToken(v); err != nil {
		return err
	}
	d, err := s.userDevice(r, v)
	if err != nil {
		return err
	}
	if err := s.store.DeleteWebPush(r.Context(), d.ID, ""); err != nil {
		return err
	}
	WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

// pushServiceHosts are the browser push services subscriptions may point at, so the server can't be made to post to
// arbitrary hosts. A leading dot matches subdomains.
var pushServiceHosts = []string{"fcm.googleapis.com", ".push.services.mozilla.com", ".notify.windows.com", "web.push.apple.com", ".push.apple.com"}

// validPushEndpoint accepts https URLs of a known push service, and http URLs on a loopback host when the server
// itself runs on one (development).
func (s *Server) validPushEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 1024 || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		if u.Port() != "" {
			return false
		}
		host := strings.ToLower(u.Hostname())
		for _, h := range pushServiceHosts {
			if host == h || strings.HasPrefix(h, ".") && strings.HasSuffix(host, h) {
				return true
			}
		}
		return false
	case "http":
		public, err := url.Parse(s.cfg.PublicURL)
		return err == nil && loopbackHost(public.Hostname()) && loopbackHost(u.Hostname())
	}
	return false
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
