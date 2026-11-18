package server

import (
	"sync"
	"time"
)

// Login-failure rate limiter: sliding-window counters per IP and per account; a
// bucket over threshold enters a lockout cooldown. In-process memory only
// (single-instance deployment; reset on restart is acceptable) — deliberately no
// DB writes so each failure doesn't become a write-amplification surface.
// Lock/unlock events are audit-logged by the caller and viewable on the logs
// page.
//
// Why both dimensions: account-only locking → an attacker can spam wrong
// passwords to lock out a legitimate user (DoS); adding per-IP locking → a single
// source spraying many usernames is also stopped. Either bucket tripped → deny.

type loginBucket struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginBucket
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{buckets: map[string]*loginBucket{}}
}

// loginPolicy holds the limiter's tunables, read from settings (secure defaults when unset).
type loginPolicy struct {
	enabled       bool
	userThreshold int
	ipThreshold   int
	window        time.Duration
	cooldown      time.Duration
}

// loginPolicy assembles the current policy: each field can be overridden via settings, invalid values fall back to defaults.
func (s *Server) loginPolicy() loginPolicy {
	pol := loginPolicy{
		enabled:       true,
		userThreshold: 10,
		ipThreshold:   30,
		window:        15 * time.Minute,
		cooldown:      15 * time.Minute,
	}
	if s.m == nil || s.m.pg == nil {
		return pol
	}
	pg := s.m.pg
	pol.enabled = pg.GetBool("auth.lockout_enabled", true)
	if v := pg.GetInt("auth.lockout_user_threshold", 0); v > 0 {
		pol.userThreshold = v
	}
	if v := pg.GetInt("auth.lockout_ip_threshold", 0); v > 0 {
		pol.ipThreshold = v
	}
	if v := pg.GetInt("auth.lockout_window_minutes", 0); v > 0 {
		pol.window = time.Duration(v) * time.Minute
	}
	if v := pg.GetInt("auth.lockout_cooldown_minutes", 0); v > 0 {
		pol.cooldown = time.Duration(v) * time.Minute
	}
	return pol
}

func ipKey(ip string) string     { return "ip:" + ip }
func userKey(user string) string { return "u:" + user }

// locked reports whether the IP or account is in a lockout cooldown, returning the remaining cooldown (the larger of the two buckets).
func (l *loginLimiter) locked(ip, user string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var remain time.Duration
	for _, k := range []string{ipKey(ip), userKey(user)} {
		if b := l.buckets[k]; b != nil && now.Before(b.lockedUntil) {
			if r := time.Until(b.lockedUntil); r > remain {
				remain = r
			}
		}
	}
	return remain > 0, remain
}

// fail records one failure into the IP bucket and the account bucket. Returns
// true when this failure pushed a bucket into a NEW lockout (so the caller can
// write one lockout audit entry). When the policy is off, nothing is recorded
// and locked is always false.
func (l *loginLimiter) fail(ip, user string, pol loginPolicy) bool {
	if !pol.enabled {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now, pol)
	newlyLocked := false
	if l.recordLocked(ipKey(ip), now, pol.window, pol.cooldown, pol.ipThreshold) {
		newlyLocked = true
	}
	if user != "" && l.recordLocked(userKey(user), now, pol.window, pol.cooldown, pol.userThreshold) {
		newlyLocked = true
	}
	return newlyLocked
}

// recordLocked records a failure on one bucket, sliding the window as needed,
// and sets the cooldown deadline when the threshold is hit. Returns true when
// this failure triggered the lock. Caller holds l.mu.
func (l *loginLimiter) recordLocked(key string, now time.Time, window, cooldown time.Duration, threshold int) bool {
	b := l.buckets[key]
	if b == nil {
		b = &loginBucket{windowStart: now}
		l.buckets[key] = b
	}
	if now.Sub(b.windowStart) > window {
		b.windowStart = now
		b.count = 0
	}
	b.count++
	if b.count >= threshold {
		b.lockedUntil = now.Add(cooldown)
		b.count = 0
		b.windowStart = now
		return true
	}
	return false
}

// reset clears the failure counters for the IP and account (called on login success).
func (l *loginLimiter) reset(ip, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, ipKey(ip))
	delete(l.buckets, userKey(user))
}

// sweepLocked drops stale buckets — not locked and window expired — once the
// bucket count grows large, so floods of distinct usernames/sources can't grow
// the map into memory pressure. Caller holds l.mu.
func (l *loginLimiter) sweepLocked(now time.Time, pol loginPolicy) {
	if len(l.buckets) < 4096 {
		return
	}
	for k, b := range l.buckets {
		if now.After(b.lockedUntil) && now.Sub(b.windowStart) > pol.window {
			delete(l.buckets, k)
		}
	}
}
