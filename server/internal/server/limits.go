package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Every caller (each paired machine, each account, each anonymous IP) may make requestBurst requests, then one more
// per requestRefill. Each IP may fail failureBurst credentials, then one more per failureRefill.
const (
	requestBurst  = 60
	requestRefill = 5 * time.Second
	failureBurst  = 10
	failureRefill = 30 * time.Second
)

// rateLimiters holds per-caller token buckets.
type rateLimiters struct {
	mu       sync.Mutex
	requests map[string]*limiterEntry
	authFail map[string]*limiterEntry
	keyed    map[string]*limiterEntry // allowKey's buckets, each with its own rate

	// The request and failure budgets: the constants above; tests change them.
	requestBurst, failureBurst   int
	requestRefill, failureRefill time.Duration
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

func newRateLimiters() *rateLimiters {
	return &rateLimiters{requests: map[string]*limiterEntry{}, authFail: map[string]*limiterEntry{}, keyed: map[string]*limiterEntry{},
		requestBurst: requestBurst, requestRefill: requestRefill, failureBurst: failureBurst, failureRefill: failureRefill}
}

func (r *rateLimiters) get(m map[string]*limiterEntry, key string, every time.Duration, burst int) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := m[key]
	if e == nil {
		e = &limiterEntry{l: rate.NewLimiter(rate.Every(every), burst)}
		m[key] = e
	}
	e.seen = time.Now()
	return e.l
}

func (r *rateLimiters) allowRequest(key string) bool {
	return r.get(r.requests, key, r.requestRefill, r.requestBurst).Allow()
}

func (r *rateLimiters) authFailures(ip string) *rate.Limiter {
	return r.get(r.authFail, ip, r.failureRefill, r.failureBurst)
}

func (r *rateLimiters) authAttemptAllowed(ip string) bool { return r.authFailures(ip).Tokens() >= 1 }

func (r *rateLimiters) recordAuthFailure(ip string) { r.authFailures(ip).Allow() }

// allowKey takes one token from key's bucket: burst at first, then one per every. Keys share one namespace, so
// callers prefix them with what they limit.
func (r *rateLimiters) allowKey(key string, every time.Duration, burst int) bool {
	return r.get(r.keyed, key, every, burst).Allow()
}

func (r *rateLimiters) prune(olderThan time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-olderThan)
	for _, m := range []map[string]*limiterEntry{r.requests, r.authFail, r.keyed} {
		for k, e := range m {
			if e.seen.Before(cutoff) {
				delete(m, k)
			}
		}
	}
}
