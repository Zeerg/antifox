package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"antifox/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash" // old single-user password (only for first-boot migration into rbac_users)
	// defaultSessionTTL is the default session (JWT) duration — doubling as the idle-timeout window:
	// active use slides it forward (see requireAuth); idle past the duration expires the token → re-login.
	// overridable via the auth.session_ttl_minutes setting (minutes).
	defaultSessionTTL = 60 * time.Minute
	sessionTTLKey     = "auth.session_ttl_minutes"
	keyChars          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type ctxKey int

const accessCtxKey ctxKey = 1

// adminRunCtxKey marks an agent run initiated by an admin session (so agent tools can tell they're in
// an admin context and apply the same admin-only gating as the HTTP layer to high-risk tools like update_mcp).
const adminRunCtxKey ctxKey = 2

func ctxIsAdmin(ctx context.Context) bool {
	v, _ := ctx.Value(adminRunCtxKey).(bool)
	return v
}

// authClaims carries the user id (Subject) + username + the password version at issue time (token_version).
// Ver makes "password change/disable kicks the user offline" work: at verify time it's compared to the current token_version — mismatch = reject.
type authClaims struct {
	Username string `json:"usr"`
	Ver      int    `json:"ver"`
	jwt.RegisteredClaims
}

// CurrentAccess fetches the logged-in user's RBAC authorization profile from the request context (injected by requireAuth).
func CurrentAccess(r *http.Request) *db.RBACAccess {
	acc, _ := r.Context().Value(accessCtxKey).(*db.RBACAccess)
	return acc
}

// loadOrCreateJWTKey reads / generates the 32-byte HS256 signing key.
func loadOrCreateJWTKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, jwtKeyFilename)
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

// sessionTTL reads the session-duration (minutes) setting; unset/invalid falls back to the default.
func (s *Server) sessionTTL() time.Duration {
	if s.m != nil && s.m.pg != nil {
		if m := s.m.pg.GetInt(sessionTTLKey, 0); m > 0 {
			return time.Duration(m) * time.Minute
		}
	}
	return defaultSessionTTL
}

// signJWT issues an HS256 token with the default session TTL (tests use this).
func signJWT(key []byte, userID, username string) (string, error) {
	return signJWTTTL(key, userID, username, 0, defaultSessionTTL)
}

// signJWTTTL issues an HS256 token that expires after ttl, stamped with the user's
// current token_version (ver) so a later password change / disable invalidates it.
func signJWTTTL(key []byte, userID, username string, ver int, ttl time.Duration) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{
		Username: username,
		Ver:      ver,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}).SignedString(key)
}

// parseJWT validates and returns the claims.
func parseJWT(tokenStr string, key []byte) (*authClaims, bool) {
	var c authClaims
	t, err := jwt.ParseWithClaims(tokenStr, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, false
	}
	return &c, true
}

// extractToken reads the JWT from Authorization: Bearer, antifox_token cookie, or ?token=.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("antifox_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth validates the JWT + resolves user/permissions into the context. /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		claims, ok := parseJWT(extractToken(r), s.jwtKey)
		if !ok {
			writeErr(w, 401, "unauthorized or token expired")
			return
		}
		// Authorization resolution is deny-by-default: any anomaly (empty subject /
		// DB unavailable / query failure / empty profile) is rejected outright —
		// prevents "deleted account's token still works" or "DB hiccup silently lets
		// requests through".
		if strings.TrimSpace(claims.Subject) == "" {
			writeErr(w, 401, "login session is no longer valid — please log in again")
			return
		}
		if s.m == nil || s.m.pg == nil {
			writeErr(w, 503, "authorization service temporarily unavailable")
			return
		}
		acc, err := s.m.pg.ResolveRBACAccess(claims.Subject)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeErr(w, 401, "login session is no longer valid — please log in again")
			} else {
				log.Printf("[auth] authorization query failed: %v", err)
				writeErr(w, 503, "authorization service temporarily unavailable")
			}
			return
		}
		if acc == nil {
			log.Printf("[auth] authorization query returned an empty profile")
			writeErr(w, 503, "authorization service temporarily unavailable")
			return
		}
		if !acc.User.Enabled {
			writeErr(w, 403, "account disabled")
			return
		}
		// token-version check: after a password change/disable, token_version
		// increments — a token carrying an older Ver is invalid → forced re-login.
		if claims.Ver != acc.User.TokenVersion {
			writeErr(w, 401, "login session is no longer valid — please log in again")
			return
		}
		// First-login forced password change: the first-boot seed uses a weak
		// default; must_change_password users are rejected everywhere except
		// /api/auth/* (exempted at the top of this function — includes the
		// change-password endpoint) until the password is changed.
		if acc.User.MustChangePassword {
			writeErr(w, 403, "first login requires a password change")
			return
		}
		// Sliding renewal (= idle timeout): once a token passes half its TTL and is
		// still in active use, a fresh token is issued via the X-Refresh-Token
		// response header — the frontend swaps it in; idle beyond the session
		// duration expires it naturally → re-login.
		if claims.ExpiresAt != nil {
			ttl := s.sessionTTL()
			if rem := time.Until(claims.ExpiresAt.Time); rem > 0 && rem < ttl/2 {
				if fresh, err := signJWTTTL(s.jwtKey, claims.Subject, claims.Username, acc.User.TokenVersion, ttl); err == nil {
					w.Header().Set("Access-Control-Expose-Headers", "X-Refresh-Token")
					w.Header().Set("X-Refresh-Token", fresh)
				}
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), accessCtxKey, acc))
		// permission enforcement. Safety valves: unmapped routes pass; admin (full access) is never blocked; the rbac.enforce toggle defaults to true.
		if s.m.pg.GetBool("rbac.enforce", true) {
			if perm := permissionForRequest(r.Method, r.URL.Path); perm != "" && !acc.Permissions[perm] {
				writeErr(w, 403, "insufficient permission: "+perm)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// bootstrapRBAC migrates the old single-user password into the built-in admin at first boot and seeds roles/permissions (idempotent).
func (s *Server) bootstrapRBAC() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	legacyHash, _, _ := s.m.pg.GetSetting(authPassKey)
	// migration path: the old single-user password may be a weak default — after migrating to admin, force a change on first login.
	if err := s.m.pg.BootstrapRBAC(legacyHash, true); err != nil {
		log.Printf("[rbac] bootstrap failed: %v", err)
		return
	}
	if strings.TrimSpace(legacyHash) != "" {
		log.Printf("[rbac] multi-user permissions ready (old password migrated to built-in admin)")
	} else {
		log.Printf("[rbac] multi-user permissions ready")
	}
}

// GET /api/auth/status — whether initialized (any platform users exist).
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	needs, err := pg.RBACNeedsBootstrap()
	if err != nil {
		writeErr(w, 500, "query failed")
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": !needs})
}

// POST /api/auth/init — first-boot admin password setup (creates the built-in admin).
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	// fail-closed: any error in the initialization-guard query is rejected outright —
	// a query failure must never be mistaken for "not initialized" and let a password
	// reset through (otherwise a failing query becomes an admin-password reset).
	needs, err := pg.RBACNeedsBootstrap()
	if err != nil {
		pg.RecordAudit("", "auth", "init", "fail", ip, "initialization guard query failed (rejected)", nil)
		writeErr(w, 503, "service temporarily unavailable")
		return
	}
	if !needs {
		pg.RecordAudit("", "auth", "init", "fail", ip, "platform already initialized — refused a repeated password setup", nil)
		writeErr(w, 403, "already initialized")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "malformed request")
		return
	}
	if msg := validatePasswordStrength(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "password hashing failed")
		return
	}
	// setup wizard: the user just chose a password that passed the strength check — don't force another change (would wedge the whole site at 403 after init).
	if err := pg.BootstrapRBAC(string(hash), false); err != nil {
		writeErr(w, 500, "initialization failed: "+err.Error())
		return
	}
	_ = pg.SetSetting(authPassKey, string(hash)) // kept for compatibility
	ver := 0
	if u, e := pg.GetRBACUserByID("admin"); e == nil && u != nil {
		ver = u.TokenVersion
	}
	tok, err := signJWTTTL(s.jwtKey, "admin", "admin", ver, s.sessionTTL())
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	pg.RecordAudit("admin", "auth", "init", "success", ip, "first-boot admin password initialized", nil)
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — change the logged-in user's password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	claims, ok := parseJWT(extractToken(r), s.jwtKey)
	if !ok {
		writeErr(w, 401, "unauthorized")
		return
	}
	u, err := pg.GetRBACUserByID(claims.Subject)
	if err != nil {
		writeErr(w, 401, "user does not exist")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "malformed request")
		return
	}
	if msg := validatePasswordStrength(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	ip := clientIP(r)
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
		pg.RecordAudit(u.Username, "auth", "change_password", "fail", ip, "wrong current password", nil)
		writeErr(w, 401, "wrong current password")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "password hashing failed")
		return
	}
	// UpdateRBACUserPassword increments token_version, invalidating every old token including the one that carried this request.
	if err := pg.UpdateRBACUserPassword(u.ID, string(newHash)); err != nil {
		writeErr(w, 500, "save failed: "+err.Error())
		return
	}
	pg.RecordAudit(u.Username, "auth", "change_password", "success", ip, "password changed", nil)
	// issue the caller a fresh token on the new version so they aren't kicked right after changing their password; old tokens on other devices still die.
	fresh := ""
	if nu, e := pg.GetRBACUserByID(u.ID); e == nil && nu != nil {
		fresh, _ = signJWTTTL(s.jwtKey, nu.ID, nu.Username, nu.TokenVersion, s.sessionTTL())
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": fresh})
}

// POST /api/auth/login — validates username/password, returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "malformed request")
		return
	}
	ip := clientIP(r)
	// Lockout counting folds by normalized (lowercase) username: account matching is
	// case-insensitive, so the lockout bucket must use the same key — otherwise an
	// attacker rotating Admin/aDmin/ADMIN case variants gets independent counters
	// and bypasses the account-level lockout.
	uname := strings.ToLower(strings.TrimSpace(req.Username))
	// Brute-force protection: check lockout on both IP and account dimensions. A
	// locked hit returns 429 immediately — no password compare at all (bcrypt is
	// CPU-heavy; blocking early also mitigates CPU/connection exhaustion from
	// mass attempts).
	if locked, retry := s.loginLimiter.locked(ip, uname); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		pg.RecordAudit(uname, "auth", "login_locked", "fail", ip,
			fmt.Sprintf("brute-force lockout triggered, %ds cooldown remaining", int(retry.Seconds())), nil)
		writeErr(w, 429, fmt.Sprintf("too many attempts — account/source temporarily locked, retry in %d seconds", int(retry.Seconds())))
		return
	}
	u, err := pg.GetRBACUserByUsername(req.Username)
	if err != nil || u == nil || !u.Enabled {
		reason := "wrong username or password"
		if u != nil && !u.Enabled {
			reason = "account disabled"
		}
		s.registerLoginFailure(pg, ip, uname)
		pg.RecordAudit(uname, "auth", "login_failed", "fail", ip, reason, nil)
		log.Printf("[auth] login failed user=%q ip=%s reason=%s", uname, ip, reason)
		writeErr(w, 401, reason)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		s.registerLoginFailure(pg, ip, u.Username)
		pg.RecordAudit(u.Username, "auth", "login_failed", "fail", ip, "wrong password", nil)
		log.Printf("[auth] login failed user=%q ip=%s reason=wrong password", u.Username, ip)
		writeErr(w, 401, "wrong username or password")
		return
	}
	tok, err := signJWTTTL(s.jwtKey, u.ID, u.Username, u.TokenVersion, s.sessionTTL())
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	s.loginLimiter.reset(ip, u.Username) // successful login clears the failure counter for this IP+account
	pg.RecordAudit(u.Username, "auth", "login", "success", ip, "login succeeded", nil)
	log.Printf("[auth] login succeeded user=%q ip=%s", u.Username, ip)
	// must_change_password sends the frontend straight to the change-password page after login; the backend requireAuth blocks them too.
	writeJSON(w, 200, map[string]any{"token": tok, "must_change_password": u.MustChangePassword})
}

// registerLoginFailure records one failure to the limiter; when it trips a lockout it also writes an audit entry (visible on the logs page).
func (s *Server) registerLoginFailure(pg *db.DB, ip, username string) {
	if s.loginLimiter.fail(ip, username, s.loginPolicy()) {
		pg.RecordAudit(username, "auth", "login_locked", "fail", ip, "failure count over threshold — temporarily locked", nil)
		log.Printf("[auth] brute-force lockout user=%q ip=%s", username, ip)
	}
}

// validatePasswordStrength returns an empty string on pass, else a user-facing reason.
// Rules: length 8–128, at least two character classes (letters / digits / symbols), not a single repeated character.
func validatePasswordStrength(pw string) string {
	if len(pw) < 8 {
		return "password must be at least 8 characters"
	}
	if len(pw) > 128 {
		return "password too long (max 128 characters)"
	}
	var hasLetter, hasDigit, hasOther bool
	allSame := true
	for i, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
		if i > 0 && rune(pw[i]) != rune(pw[0]) {
			allSame = false
		}
	}
	if allSame {
		return "password cannot be a single repeated character"
	}
	classes := 0
	for _, b := range []bool{hasLetter, hasDigit, hasOther} {
		if b {
			classes++
		}
	}
	if classes < 2 {
		return "password must contain at least two character classes (letters / digits / symbols)"
	}
	return ""
}

// clientIP extracts the client IP. Forwarded headers X-Real-IP / X-Forwarded-For
// are trusted only when the request comes from a trusted proxy (loopback /
// internal, e.g. an nginx reverse proxy); otherwise the direct source RemoteAddr
// is used, preventing clients from spoofing forwarded headers to bypass source-
// level rate-limiting / lockouts. Under a trusted proxy: X-Real-IP (overwrite
// style) wins first, then the LAST entry of X-Forwarded-For (each hop appends —
// the one closest to us is the real source; client-controlled prefixes are
// ignored).
func clientIP(r *http.Request) string {
	remote := remoteAddrIP(r.RemoteAddr)
	if isTrustedProxyIP(remote) {
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return remote
}

// remoteAddrIP extracts the IP part of net/http's RemoteAddr. net.SplitHostPort
// handles IPv6 correctly ("[::1]:port" → "::1", strips brackets — LastIndexByte
// can't); without a port, strip brackets as a fallback.
func remoteAddrIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr)); err == nil {
		return host
	}
	return strings.Trim(strings.TrimSpace(remoteAddr), "[]")
}

// trustedProxyNets is the trusted reverse-proxy networks, defaulting to loopback
// only (127.0.0.0/8 + ::1).
// WARNING: the whole private range is NOT trusted by default — in an
// intranet/VPN deployment any private client could spoof forwarded headers to
// bypass source-level lockouts. When the proxy isn't on loopback, declare its
// network explicitly via the auth.trusted_proxies setting (see SetTrustedProxies).
var trustedProxyNets = loopbackProxyNets()

func loopbackProxyNets() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"127.0.0.0/8", "::1/128"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// SetTrustedProxies rebuilds the trusted-proxy set from loopback + extra
// CIDRs/IPs (comma- or whitespace-separated); invalid entries are ignored, empty
// input = loopback only. Loaded from settings once at startup by the server
// (read-only thereafter, no concurrent writes).
func SetTrustedProxies(list string) {
	nets := loopbackProxyNets()
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") { // bare IP → single-host mask
			if ip := net.ParseIP(f); ip != nil {
				if ip.To4() != nil {
					f += "/32"
				} else {
					f += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			nets = append(nets, n)
		}
	}
	trustedProxyNets = nets
}

// isTrustedProxyIP checks whether the direct peer is a trusted proxy (inside
// trustedProxyNets). Only forwarded headers set by a trusted proxy are honored —
// direct peers (public/undeclared private) are never trusted for forwarded
// headers, closing the spoof-to-bypass-limit hole.
func isTrustedProxyIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
