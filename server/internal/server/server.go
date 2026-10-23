// Package server implements the agentio HTTP server: accounts, pairing, and the sealed relay between machines and
// browsers (docs/api.md). It stores no content and holds no key that can decrypt or sign any.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"agentio.sh/server/internal/config"
	"agentio.sh/server/internal/push"
	"agentio.sh/server/internal/store"
)

// Version and Revision (the private source revision it was built from) are set at build time.
var (
	Version  = "dev"
	Revision = "unknown"
)

// Server is the agentio server.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	log      *slog.Logger
	relay    *relayHub
	pairings *pairings
	limiters *rateLimiters
	webpush  *push.WebPush
	ext      Extension
	extended bool
	// pingInterval and idleTimeout are relayPingInterval and relayIdleTimeout; tests shorten them.
	pingInterval, idleTimeout time.Duration

	wg      sync.WaitGroup
	stop    chan struct{}
	baseCtx context.Context // canceled on shutdown, so open sockets and long polls end right away
	cancel  context.CancelFunc
}

// New creates a server from a configuration and an open store.
func New(cfg *config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:      cfg,
		store:    st,
		log:      log,
		relay:    newRelayHub(),
		pairings: newPairings(),
		limiters: newRateLimiters(),
		stop:     make(chan struct{}),

		pingInterval: relayPingInterval,
		idleTimeout:  relayIdleTimeout,
	}
	s.baseCtx, s.cancel = context.WithCancel(context.Background())
	if cfg.WebPushPublicKey != "" {
		s.webpush = push.NewWebPush(cfg.WebPushPublicKey, cfg.WebPushPrivateKey, cfg.WebPushContact)
	}
	return s, nil
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, fn HandlerFunc) {
		mux.Handle(pattern, s.wrap(fn))
	}

	// Server metadata
	h("GET /api/v1/health", s.handleHealth)
	h("GET /api/v1/config", s.handleClientConfig)

	// Accounts
	h("POST /api/v1/account", s.handleSignup)
	h("GET /api/v1/account", s.handleAccountShow)
	h("DELETE /api/v1/account", s.handleAccountRemove)
	h("POST /api/v1/account/password", s.handleAccountPassword)
	h("POST /api/v1/auth/password", s.handlePasswordLogin)
	h("DELETE /api/v1/account/tokens/{id}", s.handleTokenDelete)

	// Pairing
	h("POST /api/v1/pair", s.handlePairStart)
	h("POST /api/v1/pair/{id}/claim", s.handlePairClaim)
	h("GET /api/v1/pair/{id}", s.handlePairPoll)
	h("POST /api/v1/pair/{id}/confirm", s.handlePairConfirm)
	h("POST /api/v1/pair/{id}/reject", s.handlePairReject)

	// Machines and devices
	h("GET /api/v1/hosts", s.handleHostsList)
	h("DELETE /api/v1/hosts/{id}", s.handleHostDelete)
	h("DELETE /api/v1/hosts/{id}/devices/{device}", s.handleHostDeviceDelete)
	h("GET /api/v1/devices", s.handleDevicesList)
	h("DELETE /api/v1/devices/{id}", s.handleDeviceDelete)
	h("PUT /api/v1/devices/{id}/webpush", s.handleWebPushSet)
	h("DELETE /api/v1/devices/{id}/webpush", s.handleWebPushDelete)

	// Relay
	h("GET /api/v1/relay/host", s.handleRelayHost)
	h("GET /api/v1/relay/device", s.handleRelayDevice)

	if s.ext.Routes != nil {
		s.ext.Routes(h)
	}

	// The server serves no web pages: the web app is hosted separately.
	h("/", func(http.ResponseWriter, *http.Request, *Caller) error {
		return ErrNotFound
	})
	h("GET /{$}", func(http.ResponseWriter, *http.Request, *Caller) error {
		return errNoWebApp
	})
	return s.recoverer(mux)
}

// statusWriter records the response status for request logs. Unwrap lets WebSockets hijack the connection.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// wrap applies authentication, rate limiting, CORS, error rendering and request logging. Logs name the route
// template only: never the path, query string, body or credentials.
func (s *Server) wrap(fn HandlerFunc) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w := &statusWriter{ResponseWriter: rw}
		defer func() {
			d := time.Since(start)
			s.log.Debug("request", "method", r.Method, "route", r.Pattern, "status", w.status, "duration", d.Round(time.Millisecond).String())
		}()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.WriteHeader(http.StatusOK)
			return
		}
		// Failed credentials are limited per IP before any token lookup runs, so guessing is slow and cheap to refuse.
		ip := s.clientIP(r)
		if hasCredentials(r) && !s.limiters.authAttemptAllowed(ip) {
			s.renderError(w, r, ErrTooManyRequests)
			return
		}
		v, err := s.authenticate(r)
		if err != nil {
			var e *APIError
			if errors.As(err, &e) && e.Status == http.StatusUnauthorized {
				s.limiters.recordAuthFailure(ip)
			}
			s.renderError(w, r, err)
			return
		}
		if !s.exempt(v) && !s.limiters.allowRequest(v.rateKey()) {
			s.renderError(w, r, ErrTooManyRequests)
			return
		}
		if err := fn(w, r, v); err != nil {
			s.renderError(w, r, err)
		}
	})
}

func (s *Server) exempt(v *Caller) bool {
	if v.isAdmin() {
		return true
	}
	for _, h := range s.cfg.RateLimitExemptIPs {
		if h == v.ip {
			return true
		}
	}
	return false
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, err error) {
	var e *APIError
	if !errors.As(err, &e) {
		s.log.Error("request failed", "method", r.Method, "route", r.Pattern, "error", err)
	} else if e.Status >= 500 {
		s.log.Error("request failed", "method", r.Method, "route", r.Pattern, "error", e.Message)
	}
	writeError(w, err)
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "route", r.Pattern, "panic", fmt.Sprint(v))
				writeError(w, ErrInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Run serves HTTP until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.HTTPAddr, Handler: s.Handler(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute,
		BaseContext: func(net.Listener) context.Context { return s.baseCtx }}
	ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		return err
	}
	s.log.Info("listening", "http", ln.Addr().String(), "base_url", s.cfg.PublicURL)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.wg.Add(1)
	go s.manager()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.shutdown(srv)
			return err
		}
	}
	s.shutdown(srv)
	return nil
}

func (s *Server) shutdown(srv *http.Server) {
	close(s.stop)
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if srv != nil {
		_ = srv.Shutdown(ctx)
	}
	s.wg.Wait()
	if s.ext.Maintain != nil {
		if err := s.ext.Maintain(ctx); err != nil {
			s.log.Error("maintenance", "error", err)
		}
	}
}

// maintenanceInterval is how often the server forgets what has expired and runs the extension's maintenance.
const maintenanceInterval = time.Minute

// manager runs maintenance until shutdown.
func (s *Server) manager() {
	defer s.wg.Done()
	maintenance := time.NewTicker(maintenanceInterval)
	defer maintenance.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-maintenance.C:
			s.maintain()
		}
	}
}

// maintain forgets what has expired and runs the extension's maintenance.
func (s *Server) maintain() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	now := time.Now()
	if err := s.store.DeleteExpiredTokens(ctx, now.Unix()); err != nil {
		s.log.Error("maintenance", "error", err)
	}
	if s.ext.Maintain != nil {
		if err := s.ext.Maintain(ctx); err != nil {
			s.log.Error("maintenance", "error", err)
		}
	}
	s.pairings.prune(now)
	s.limiters.prune(time.Hour)
}
