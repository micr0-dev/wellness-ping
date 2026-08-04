package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/argon2"
)

const VERSION = "2.0.4"

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// isDev reports whether we are explicitly running in a development
// environment. Security features never degrade implicitly: anything that used
// to "fail open" when an env var was missing now requires APP_ENV=development
// to be set on purpose.
func isDev() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "development")
}

// baseURL is the public origin used to build check-in links.
func baseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("BASE_URL")), "/"); v != "" {
		return v
	}
	return "https://wellness-p.ing"
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// rateLimiter is a small fixed-window-per-key limiter. It is deliberately
// in-memory: this is a single-process service, and a restart erring on the
// side of "allow" is preferable to locking a user out of a check-in.
type rateLimiter struct {
	mu  sync.Mutex
	hit map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{hit: make(map[string][]time.Time)}
}

// allow records an attempt against key and reports whether it is within limit.
func (rl *rateLimiter) allow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	kept := rl.hit[key][:0]
	for _, t := range rl.hit[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		rl.hit[key] = kept
		return false
	}
	rl.hit[key] = append(kept, now)
	return true
}

// reset clears the history for a key, called after a successful auth so a user
// who fumbled their PIN twice is not penalised later.
func (rl *rateLimiter) reset(key string) {
	rl.mu.Lock()
	delete(rl.hit, key)
	rl.mu.Unlock()
}

// sweep drops entries older than window so the map cannot grow without bound.
func (rl *rateLimiter) sweep(window time.Duration) {
	cutoff := time.Now().Add(-window)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, times := range rl.hit {
		kept := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(rl.hit, k)
		} else {
			rl.hit[k] = kept
		}
	}
}

var (
	// Outbound verification codes: expensive (sends mail/Signal), so limited
	// per identifier and per source address.
	codeSendLimiter = newRateLimiter()
	// Verification code guesses.
	codeVerifyLimiter = newRateLimiter()
	// PIN and TOTP guesses, keyed by user so that discarding a flow and
	// starting a new one does not reset the counter.
	pinLimiter  = newRateLimiter()
	totpLimiter = newRateLimiter()
	// Check-in page hits, keyed by source address.
	pongLimiter = newRateLimiter()
	// Inbound reply-PONG processing, keyed by claimed sender.
	inboundLimiter = newRateLimiter()
	// Signal signup "I've sent the DM" clicks, keyed by source address.
	dmLimiter = newRateLimiter()
)

const (
	codeSendLimit    = 5
	codeSendWindow   = time.Hour
	codeVerifyLimit  = 5
	codeVerifyWindow = 15 * time.Minute
	moduleAttemptLim = 5
	moduleAttemptWin = 15 * time.Minute
	pongLimit        = 60
	pongWindow       = time.Hour
	inboundLimit     = 20
	inboundWindow    = time.Hour
	dmContinueLimit  = 20
	dmContinueWindow = 15 * time.Minute
	signupTTL        = 30 * time.Minute
	sendRetryDelay   = 60 * time.Second
	dmSeenTTL        = time.Hour
	flowTTL          = 15 * time.Minute
	sessionTTL       = 30 * time.Minute
	pendingCodeTTL   = 10 * time.Minute
)

// clientIP extracts the caller's address. Proxy headers are only honoured when
// TRUST_PROXY is set, since otherwise any client could spoof them and evade
// every per-address limit above.
func clientIP(r *http.Request) string {
	if envBool("TRUST_PROXY") {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first, _, ok := strings.Cut(xff, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(xff)
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------------------
// Password/PIN hashing
// ---------------------------------------------------------------------------

// argon2id parameters. Memory is kept modest because a PIN check happens on a
// user-facing path and the attempt limiter already bounds how often it runs.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 32 * 1024 // 32 MiB
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// hashSecret returns an argon2id PHC-style string for a secret.
// A PIN is a tiny keyspace, so the hash must be slow: a single SHA-256 round
// over 4-6 digits is recoverable instantly if the data file ever leaks.
func hashSecret(secret string) string {
	if secret == "" {
		return ""
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		// Failing closed here is right: we must never store a secret under a
		// predictable salt.
		log.Printf("FATAL: could not read random salt: %v", err)
		panic("no entropy available for hashing")
	}
	key := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// decoyHash is a throwaway argon2id hash used to keep the PIN check doing the
// same amount of work whether or not a duress PIN is configured. Computed once
// at startup from a random secret; it can never match anything.
var decoyHash = hashSecret(generateToken())

// verifySecret checks a candidate against a stored value in constant time.
func verifySecret(stored, candidate string) bool {
	ok, _ := verifySecretUpgrade(stored, candidate)
	return ok
}

// verifySecretUpgrade verifies a candidate and, when the stored value uses a
// superseded format (the v2.0 salted SHA-256, or pre-v2.0 plaintext), returns a
// freshly hashed replacement so the caller can migrate it in place. Legacy
// values are accepted once and then rewritten; they never linger.
func verifySecretUpgrade(stored, candidate string) (ok bool, upgraded string) {
	if stored == "" {
		return false, ""
	}
	parts := strings.Split(stored, "$")

	switch {
	case len(parts) == 5 && parts[0] == "argon2id":
		var version int
		var m, t int
		var p int
		if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
			return false, ""
		}
		if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
			return false, ""
		}
		salt, err := base64.RawStdEncoding.DecodeString(parts[3])
		if err != nil {
			return false, ""
		}
		want, err := base64.RawStdEncoding.DecodeString(parts[4])
		if err != nil {
			return false, ""
		}
		got := argon2.IDKey([]byte(candidate), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
		return subtle.ConstantTimeCompare(got, want) == 1, ""

	case len(parts) == 3 && parts[0] == "sha256":
		// v2.0 format: salted single-round SHA-256. Accepted, then upgraded.
		salt, err := base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return false, ""
		}
		h := sha256.Sum256(append(salt, []byte(candidate)...))
		sum := hex.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(sum), []byte(parts[2])) == 1 {
			return true, hashSecret(candidate)
		}
		return false, ""

	default:
		// Pre-v2.0 plaintext. Accepted once, then upgraded.
		if subtle.ConstantTimeCompare([]byte(stored), []byte(candidate)) == 1 {
			return true, hashSecret(candidate)
		}
		return false, ""
	}
}

// ---------------------------------------------------------------------------
// Transport hardening
// ---------------------------------------------------------------------------

// contentSecurityPolicy is strict: no inline script or style is used anywhere
// in the templates (all JS lives under /static). Turnstile is allowed only
// when it is actually configured.
func contentSecurityPolicy() string {
	script := "'self'"
	frame := "'none'"
	connect := "'self'"
	if os.Getenv("TURNSTILE_SITE_KEY") != "" {
		script += " https://challenges.cloudflare.com"
		frame = "https://challenges.cloudflare.com"
		connect += " https://challenges.cloudflare.com"
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + script,
		"style-src 'self'",
		"img-src 'self' data:",
		"connect-src " + connect,
		"frame-src " + frame,
		"form-action 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; ")
}

func securityHeaders(next http.Handler) http.Handler {
	csp := contentSecurityPolicy()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// The check-in token travels in the URL, so the browser must not leak
		// it to any third party via Referer.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy", csp)
		if !isDev() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

// setSessionCookie issues the settings session cookie. Secure is on unless
// explicitly disabled for local development over plain HTTP.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		HttpOnly: true,
		Secure:   !envBool("INSECURE_COOKIES"),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !envBool("INSECURE_COOKIES"),
		SameSite: http.SameSiteStrictMode,
	})
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

// renderTemplate parses and renders a template, reporting failures instead of
// panicking. template.Must on a live request path turns a missing or malformed
// template file into a panic.
func renderTemplate(w http.ResponseWriter, file string, data interface{}) {
	tmpl, err := template.ParseFiles(file)
	if err != nil {
		log.Printf("ERROR: could not parse %s: %v", file, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("ERROR: could not render %s: %v", file, err)
	}
}

// renderPage renders a simple message page. Everything user-influenced goes
// through html/template rather than fmt.Fprintf, so an address containing
// markup cannot be reflected into the response.
func renderPage(w http.ResponseWriter, status int, title, body string, links map[string]string) {
	tmpl, err := template.ParseFiles("templates/message.html")
	if err != nil {
		http.Error(w, title, status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	ordered := make([]map[string]string, 0, len(links))
	keys := make([]string, 0, len(links))
	for k := range links {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ordered = append(ordered, map[string]string{"Label": k, "Href": links[k]})
	}
	tmpl.Execute(w, map[string]interface{}{
		"Title":   title,
		"Body":    body,
		"Links":   ordered,
		"Version": VERSION,
	})
}

// SecurityModule represents an enabled security requirement.
type SecurityModule struct {
	Enabled    bool      `json:"enabled"`
	ModuleType string    `json:"module_type"` // "pin", "totp", "passkey"
	Config     string    `json:"config,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Module config payloads (stored as JSON in SecurityModule.Config)
type PINConfig struct {
	Pin    string `json:"pin"`
	Duress string `json:"duress"`
}

type TOTPConfig struct {
	Secret string `json:"secret"`
}

type User struct {
	Email             string            `json:"email"`
	AlertEmails       []string          `json:"alert_emails"`
	PingFrequency     string            `json:"ping_frequency"`
	CheckInHour       int               `json:"checkin_hour"`
	LastPing          time.Time         `json:"last_ping"`
	CurrentCycleStart time.Time         `json:"current_cycle_start"`
	LastReminderNum   int               `json:"last_reminder_num"`
	Active            bool              `json:"active"`
	Token             string            `json:"token"`
	AlertSent         bool              `json:"alert_sent"`
	PausedUntil       *time.Time        `json:"paused_until,omitempty"`
	AlertMessage      string            `json:"alert_message,omitempty"`
	AllClearMessage   string            `json:"all_clear_message,omitempty"`
	SecurityModules   []SecurityModule  `json:"security_modules"`
	SignalUUIDs       map[string]string `json:"signal_uuids,omitempty"` // canonical contact -> resolved ACI UUID

	// ReplyCode is a short per-cycle secret printed in the check-in message. A
	// reply-PONG must quote it, so knowing the address alone is not enough to
	// disarm the switch.
	ReplyCode string `json:"reply_code,omitempty"`

	// DuressActive records that the last check-in was made under duress. While
	// set, the service behaves outwardly as if everything is normal (no
	// reminders, no all-clear) so that whoever is watching learns nothing.
	DuressActive bool       `json:"duress_active,omitempty"`
	DuressAt     *time.Time `json:"duress_at,omitempty"`

	// ContactStatus records the outcome of the last delivery attempt per
	// contact so a silently undeliverable emergency contact is visible in
	// settings instead of only in the server log.
	ContactStatus map[string]string `json:"contact_status,omitempty"`
}

type PendingVerification struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PendingSignup tracks a new Signal-identifier signup that has not yet had
// its first contact with our bot acknowledged. This only applies to signup
// (a brand-new account), not to login.
type PendingSignup struct {
	Canonical string
	Kind      string // "signal" or "phone"
	Code      string
	// UUID is resolved once, when the signup is staged, so that confirming the
	// DM later needs no signal-cli call at all.
	UUID      string
	Sent      bool
	SentAt    time.Time
	CreatedAt time.Time
}

// pendingSignups holds in-progress Signal signups awaiting the user's first
// DM to our bot. In-memory only (short-lived, non-persistent).
var pendingSignups = struct {
	sync.RWMutex
	m map[string]*PendingSignup
}{m: map[string]*PendingSignup{}}

type Session struct {
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	CSRF      string    `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Store struct {
	Users                map[string]*User                `json:"users"`
	PendingVerifications map[string]*PendingVerification `json:"pending_verifications"`
	Sessions             map[string]*Session             `json:"sessions"`
	mu                   sync.RWMutex
}

var store = &Store{
	Users:                make(map[string]*User),
	PendingVerifications: make(map[string]*PendingVerification),
	Sessions:             make(map[string]*Session),
}

// CheckInFlow tracks which security modules have been authenticated for an
// in-progress auth challenge, keyed by the flow token. It is used both for
// check-ins ("/pong") and for signing into settings ("/login").
type CheckInFlow struct {
	Token     string
	Email     string
	Kind      string          // "checkin" or "login"
	Completed map[string]bool // "pin", "totp", "passkey"
	// Duress records that the duress PIN was used. The flow then continues
	// exactly as a normal check-in would - same pages, same clicks, same
	// timing - and the silent alert fires at the end instead of a check-in.
	Duress    bool
	StartedAt time.Time
}

var checkInFlows = struct {
	sync.RWMutex
	m map[string]*CheckInFlow
}{m: map[string]*CheckInFlow{}}

// moduleOrder is the order steps are shown in. TOTP is last because its
// codes are time-sensitive.
var moduleOrder = []string{"pin", "passkey", "totp"}

// WebAuthn globals ----------------------------------------------------------

var webAuthn *webauthn.WebAuthn

// waSessions stores WebAuthn ceremony session data: registration & login.
// Keyed by user email for registration, and by token for login flow.
var waSessions = struct {
	sync.RWMutex
	m map[string]*webauthn.SessionData
}{m: map[string]*webauthn.SessionData{}}

// WAUser adapts our User to the webauthn.User interface.
type WAUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WAUser) WebAuthnID() []byte                         { return u.ID }
func (u *WAUser) WebAuthnName() string                       { return u.Name }
func (u *WAUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *WAUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func initWebAuthn() {
	rpID := os.Getenv("WEBAUTHN_RPID")
	if rpID == "" {
		rpID = "wellness-p.ing"
	}
	origin := os.Getenv("WEBAUTHN_ORIGIN")
	if origin == "" {
		origin = "https://wellness-p.ing"
	}

	// Development origins are never shipped to production. Browsers already
	// refuse to sign for a mismatched rpId, but an allow-list containing
	// http://localhost is still an assertion-replay surface we do not need.
	origins := []string{origin}
	if isDev() {
		extra := strings.Split(os.Getenv("WEBAUTHN_DEV_ORIGINS"), ",")
		if strings.TrimSpace(os.Getenv("WEBAUTHN_DEV_ORIGINS")) == "" {
			extra = []string{"http://localhost:8080", "http://localhost:8087"}
		}
		for _, o := range extra {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
		log.Printf("WebAuthn: development origins enabled: %v", origins)
	}

	cfg := &webauthn.Config{
		RPDisplayName: "Wellness Ping",
		RPID:          rpID,
		RPOrigins:     origins,
	}
	var err error
	webAuthn, err = webauthn.New(cfg)
	if err != nil {
		log.Printf("Failed to init webauthn: %v", err)
	}
}

// PasskeyConfig is the JSON stored in the passkey SecurityModule config.
type PasskeyConfig struct {
	Credential string `json:"credential"` // URL-safe base64 of marshalled webauthn.Credential
}

func marshalCredential(c *webauthn.Credential) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func unmarshalCredential(encoded string) (*webauthn.Credential, error) {
	b, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var c webauthn.Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// wauserFor builds a WAUser for a given user
func wauserFor(u *User) *WAUser {
	if u == nil {
		return &WAUser{}
	}
	wu := &WAUser{
		ID:          []byte(u.Email),
		Name:        u.Email,
		DisplayName: u.Email,
	}
	for _, mod := range u.SecurityModules {
		if mod.ModuleType == "passkey" && mod.Enabled && mod.Config != "" {
			var pc PasskeyConfig
			if json.Unmarshal([]byte(mod.Config), &pc) == nil && pc.Credential != "" {
				if c, err := unmarshalCredential(pc.Credential); err == nil {
					wu.Credentials = append(wu.Credentials, *c)
				}
			}
		}
	}
	return wu
}

// checkConfig validates the environment at boot. In production a missing
// security-relevant setting is fatal rather than a warning that quietly
// disables a control; APP_ENV=development downgrades these to warnings.
func checkConfig() {
	var problems []string

	require := func(name, why string) {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			problems = append(problems, fmt.Sprintf("%s is not set (%s)", name, why))
		}
	}

	require("POSTMARK_TOKEN", "outbound mail, including emergency alerts, will not be delivered")
	require("INBOUND_SECRET", "the inbound reply-PONG webhook cannot be authenticated")
	require("TURNSTILE_SECRET_KEY", "signup would be unprotected against automated abuse")
	require("BASE_URL", "check-in links would fall back to the hardcoded default origin")
	require("WEBAUTHN_RPID", "passkeys would fall back to the hardcoded default relying party")

	if len(problems) == 0 {
		return
	}
	if isDev() {
		for _, p := range problems {
			log.Printf("WARNING (development mode): %s", p)
		}
		log.Printf("WARNING: APP_ENV=development - Turnstile, secure cookies and HSTS may be relaxed. Never use this in production.")
		return
	}
	for _, p := range problems {
		log.Printf("FATAL: %s", p)
	}
	log.Fatal("refusing to start with an incomplete security configuration; " +
		"set the variables above, or set APP_ENV=development to run locally")
}

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

	checkConfig()

	loadStore()
	initWebAuthn()
	detectSignal()

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/send-code", sendCodeHandler)
	mux.HandleFunc("/dm-continue", dmContinueHandler)
	mux.HandleFunc("/verify-code", verifyCodeHandler)
	mux.HandleFunc("/settings", settingsHandler)
	mux.HandleFunc("/update", updateHandler)
	mux.HandleFunc("/pong", pongHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/test-ping", testPingHandler)
	mux.HandleFunc("/inbound", inboundEmailHandler)

	// Security module setup
	mux.HandleFunc("/totp-setup", totpSetupHandler)
	mux.HandleFunc("/totp-verify", totpVerifyHandler)
	mux.HandleFunc("/passkey-register-begin", passkeyRegisterBegin)
	mux.HandleFunc("/passkey-register-finish", passkeyRegisterFinish)

	// Passkey check-in ceremony
	mux.HandleFunc("/passkey-login-begin", passkeyLoginBegin)
	mux.HandleFunc("/passkey-login-finish", passkeyLoginFinish)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	go pingScheduler()
	go signalReceiveLoop()

	addr := fmt.Sprintf(":%d", *port)
	srv := &http.Server{
		Addr:    addr,
		Handler: securityHeaders(mux),
		// Without these a single idle connection can hold a handler open
		// indefinitely (slowloris).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	log.Printf("Server starting on %s (env=%s)", addr, map[bool]string{true: "development", false: "production"}[isDev()])
	log.Fatal(srv.ListenAndServe())
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// The "/" pattern matches everything, so an unknown path used to render
	// the index page with a 200.
	if r.URL.Path != "/" {
		renderPage(w, http.StatusNotFound, "Not Found", "That page does not exist.",
			map[string]string{"Go to the home page": "/"})
		return
	}

	data := map[string]string{
		"Version":          VERSION,
		"TurnstileSiteKey": os.Getenv("TURNSTILE_SITE_KEY"),
	}
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func sendCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !verifyTurnstile(r) {
		http.Error(w, "CAPTCHA verification failed. Please try again.", http.StatusBadRequest)
		return
	}

	// The identifier may be an email, a phone number (default +1), or a Signal
	// username. Normalize it; the same canonical form is used as the account key.
	raw := strings.TrimSpace(r.FormValue("identifier"))
	if raw == "" {
		raw = strings.TrimSpace(r.FormValue("email")) // backwards-compatible
	}
	kind, canonical := classifyContact(raw)
	if kind == "" || canonical == "" {
		http.Error(w, "Enter a valid email, phone number, or Signal username", http.StatusBadRequest)
		return
	}

	// Two limits: one stops an attacker mailbombing a single victim, the other
	// stops one source enumerating or spamming many addresses. Both also bound
	// growth of the pending-verification map.
	if !codeSendLimiter.allow("send:ip:"+clientIP(r), codeSendLimit*4, codeSendWindow) ||
		!codeSendLimiter.allow("send:id:"+canonical, codeSendLimit, codeSendWindow) {
		http.Error(w, "Too many verification requests. Please wait and try again.", http.StatusTooManyRequests)
		return
	}

	code := generateCode()

	if kind == "email" {
		// Email signup/login: send the code by email as before.
		store.mu.Lock()
		store.PendingVerifications[canonical] = &PendingVerification{
			Email:     canonical,
			Code:      code,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		store.mu.Unlock()

		subject := "Wellness Ping Verification Code"
		body := fmt.Sprintf("Your Verification Code is: %s\n\nThis code expires in 10 minutes.", code)
		sendEmail(canonical, subject, body)

		renderTemplate(w, "templates/verify.html", map[string]interface{}{"Email": canonical, "ViaSignal": false})
		return
	}

	// Signal identifier (phone number or username).
	store.mu.RLock()
	_, existing := store.Users[canonical]
	store.mu.RUnlock()

	if existing {
		// LOGIN: we've messaged this account before, so send the code directly
		// (the conversation already exists - no new-contact throttle).
		store.mu.Lock()
		store.PendingVerifications[canonical] = &PendingVerification{
			Email:     canonical,
			Code:      code,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		store.mu.Unlock()

		// Off the request path: signal-cli invocations are serialised now, so a
		// queued send must not hold an HTTP handler open.
		go sendVerificationCodeSignal(canonical, code)

		renderTemplate(w, "templates/verify.html", map[string]interface{}{"Email": canonical, "ViaSignal": true})
		return
	}

	// SIGNUP via Signal: require the user to DM our bot first so that when we
	// send the code we're replying to an established conversation, not burning
	// a new-contact message (which Signal throttles hardest). We stage the code
	// now and only ship it once we've seen their incoming DM.
	// Check the identifier is actually on Signal before telling anyone to DM
	// us. A number with no Signal account can never complete this flow, and
	// sending it to a page that says "message our bot" is a dead end with no
	// explanation. The resolved UUID is cached on the pending signup, so
	// confirming the DM afterwards costs no signal-cli call at all.
	uuid, registered, err := signalLookup(canonical)
	if err != nil {
		log.Printf("WARNING: Signal lookup failed for %s: %v", canonical, err)
		renderDM(w, canonical, "We couldn't reach Signal just now. Give it a moment and try again.")
		return
	}
	if !registered {
		renderPage(w, http.StatusBadRequest, "Not on Signal",
			canonical+" isn't registered with Signal, so we can't send your check-ins there. "+
				"Sign up with an email address instead, or use a number that has Signal installed.",
			map[string]string{"Go back": "/"})
		return
	}

	pendingSignups.Lock()
	pendingSignups.m[canonical] = &PendingSignup{
		Canonical: canonical,
		Kind:      kind,
		Code:      code,
		UUID:      uuid,
		CreatedAt: time.Now(),
	}
	pendingSignups.Unlock()

	renderDM(w, canonical, "")
}

func verifyCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	raw := strings.TrimSpace(r.FormValue("identifier"))
	if raw == "" {
		raw = strings.TrimSpace(r.FormValue("email")) // backwards-compatible
	}
	kind, canonical := classifyContact(raw)
	if kind == "" || canonical == "" {
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	// Previously a wrong code left the pending verification in place, giving
	// an attacker unlimited guesses for the full ten-minute window.
	if !codeVerifyLimiter.allow("verify:"+canonical, codeVerifyLimit, codeVerifyWindow) ||
		!codeVerifyLimiter.allow("verify:ip:"+clientIP(r), codeVerifyLimit*4, codeVerifyWindow) {
		http.Error(w, "Too many attempts. Please request a new code.", http.StatusTooManyRequests)
		return
	}

	store.mu.Lock()
	pending, exists := store.PendingVerifications[canonical]
	expired := exists && time.Now().After(pending.ExpiresAt)
	if expired {
		delete(store.PendingVerifications, canonical)
	}
	var stored string
	if exists && !expired {
		stored = pending.Code
	}
	store.mu.Unlock()

	// One message for "no pending code", "expired" and "wrong code" alike, so
	// this endpoint cannot be used to enumerate which identifiers are
	// registered or have a code outstanding.
	if stored == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(code)) != 1 {
		http.Error(w, "That code is not valid. Please request a new one.", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	delete(store.PendingVerifications, canonical)
	store.mu.Unlock()
	codeVerifyLimiter.reset("verify:" + canonical)

	// If the user has any security modules enabled, this code is only the
	// first factor - they must complete each enabled module before a settings
	// session is granted.
	if len(enabledModulesFor(canonical)) > 0 {
		loginToken := generateToken()
		getFlow(loginToken, canonical, "login")
		http.Redirect(w, r, "/login?token="+url.QueryEscape(loginToken), http.StatusSeeOther)
		return
	}

	createSession(w, r, canonical, "")
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := requireSession(w, r)
	if !ok {
		return
	}
	email := session.Email

	store.mu.RLock()
	user := store.Users[email]
	data := map[string]interface{}{
		"User":              user,
		"Email":             email,
		"Version":           VERSION,
		"CSRF":              session.CSRF,
		"PinEnabled":        moduleEnabled(user, "pin"),
		"TOTPEnabled":       moduleEnabled(user, "totp"),
		"PasskeyEnabled":    moduleEnabled(user, "passkey"),
		"TOTPConfigured":    moduleConfigured(user, "totp"),
		"PasskeyConfigured": moduleConfigured(user, "passkey"),
		"PinConfigured":     moduleConfigured(user, "pin"),
	}
	if user != nil {
		// Surface per-contact delivery outcomes so an emergency contact that
		// silently bounces is visible here, not only in the server log.
		statuses := make([]map[string]string, 0, len(user.AlertEmails))
		for _, c := range user.AlertEmails {
			st := user.ContactStatus[c]
			if st == "" {
				st = "not yet contacted"
			}
			statuses = append(statuses, map[string]string{"Contact": c, "Status": st})
		}
		data["ContactStatuses"] = statuses
		data["DuressActive"] = user.DuressActive
	}
	store.mu.RUnlock()

	tmpl, err := template.ParseFiles("templates/settings.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

// maxPause bounds vacation mode. An unbounded pause is an attacker's simplest
// way to permanently disable the switch without leaving an obvious trace.
const maxPause = 90 * 24 * time.Hour

func updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	session, ok := requireSessionPost(w, r)
	if !ok {
		return
	}
	email := session.Email
	action := r.FormValue("action")

	// Snapshot the prior state so security-relevant changes can be reported.
	before, hadUser := snapshotUser(email)

	if action == "stop" {
		store.mu.Lock()
		delete(store.Users, email)
		delete(store.Sessions, session.Token)
		store.mu.Unlock()
		saveStore()
		clearSessionCookie(w)

		if hadUser {
			go notifyAccountChange(before, "Wellness Ping service stopped",
				"The Wellness Ping service for "+before.Email+" has been stopped and its data deleted. "+
					"Check-ins are no longer being monitored.\n\n"+
					"If you did not do this, someone else may have access to your account.")
		}

		renderPage(w, http.StatusOK, "Service Stopped",
			"Your wellness ping service has been stopped and all data deleted.",
			map[string]string{"Go back": "/"})
		return
	}

	if action == "test_ping" {
		snap, exists := snapshotUser(email)
		if !exists {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		go sendPing(snap, 0)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	// Module-level actions that affect only one module (no full save).
	switch action {
	case "clear_totp", "clear_passkey", "clear_pin":
		module := strings.TrimPrefix(action, "clear_")
		if !mutateUser(email, func(u *User) { setModuleEnabled(u, module, "", false) }) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		saveStore()
		after, _ := snapshotUser(email)
		go notifySecurityChange(before, after)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	case "clear_duress":
		mutateUser(email, func(u *User) { u.DuressActive = false; u.DuressAt = nil })
		saveStore()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	alertContactsStr := r.FormValue("alert_emails")
	if strings.TrimSpace(alertContactsStr) == "" {
		http.Error(w, "At least one alert contact is required", http.StatusBadRequest)
		return
	}

	alertContacts := []string{}
	seen := map[string]bool{}
	for _, e := range strings.Split(alertContactsStr, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// Accept an email, a Signal username (name.##), or a phone number.
		// classifyContact is now strict: anything it cannot positively
		// identify is rejected rather than silently coerced into "+1<junk>",
		// which used to produce an emergency contact that never received
		// anything and gave no sign of it.
		kind, canon := classifyContact(e)
		if kind == "" || canon == "" {
			http.Error(w, fmt.Sprintf("Not a valid email address, phone number or Signal username: %q", e), http.StatusBadRequest)
			return
		}
		if !seen[canon] {
			seen[canon] = true
			alertContacts = append(alertContacts, canon)
		}
	}

	if len(alertContacts) == 0 {
		http.Error(w, "At least one alert contact is required", http.StatusBadRequest)
		return
	}

	const maxContacts = 10
	if len(alertContacts) > maxContacts {
		http.Error(w, fmt.Sprintf("Maximum %d emergency contacts allowed (you provided %d)", maxContacts, len(alertContacts)), http.StatusBadRequest)
		return
	}

	pingFreq := r.FormValue("ping_frequency")
	if pingFreq != "daily" && pingFreq != "weekly" {
		http.Error(w, "Ping frequency must be 'daily' or 'weekly'", http.StatusBadRequest)
		return
	}

	localHour := 9
	if v := strings.TrimSpace(r.FormValue("checkin_hour")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			http.Error(w, "Invalid check-in hour format", http.StatusBadRequest)
			return
		}
		localHour = n
	}
	if localHour < 0 || localHour > 23 {
		http.Error(w, "Check-in hour must be between 0 and 23", http.StatusBadRequest)
		return
	}

	timezone := r.FormValue("timezone")
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		http.Error(w, "Invalid timezone", http.StatusBadRequest)
		return
	}

	now := time.Now()
	localTime := time.Date(now.Year(), now.Month(), now.Day(), localHour, 0, 0, 0, loc)
	checkInHourUTC := localTime.UTC().Hour()

	const maxMessageLen = 2000
	alertMessage := strings.TrimSpace(r.FormValue("alert_message"))
	allClearMessage := strings.TrimSpace(r.FormValue("all_clear_message"))
	if len(alertMessage) > maxMessageLen || len(allClearMessage) > maxMessageLen {
		http.Error(w, fmt.Sprintf("Custom messages are limited to %d characters", maxMessageLen), http.StatusBadRequest)
		return
	}

	var pausedUntil *time.Time
	if s := r.FormValue("paused_until"); s != "" {
		parsed, err := time.ParseInLocation("2006-01-02T15:04", s, loc)
		if err != nil {
			http.Error(w, "Invalid pause date", http.StatusBadRequest)
			return
		}
		if parsed.After(time.Now()) {
			if parsed.After(time.Now().Add(maxPause)) {
				http.Error(w, "A pause can be at most 90 days. Set a shorter date, or stop the service if you no longer want it.", http.StatusBadRequest)
				return
			}
			pt := parsed
			pausedUntil = &pt
		}
	}

	// PIN module. Enabling requires a PIN; unchecking keeps the stored value
	// so it can be re-enabled without retyping.
	pinEnabled := r.FormValue("pin_enable") == "1"
	pinVal := strings.TrimSpace(r.FormValue("pin_pin"))
	duressVal := strings.TrimSpace(r.FormValue("pin_duress"))

	if pinEnabled {
		alreadyConfigured := false
		store.mu.RLock()
		if u := store.Users[email]; u != nil {
			alreadyConfigured = moduleConfigured(u, "pin")
		}
		store.mu.RUnlock()

		if pinVal == "" && !alreadyConfigured {
			http.Error(w, "Set a check-in PIN before enabling the PIN module", http.StatusBadRequest)
			return
		}
		if pinVal != "" {
			if len(pinVal) < 4 {
				http.Error(w, "Your PIN must be at least 4 characters", http.StatusBadRequest)
				return
			}
			if duressVal != "" {
				if len(duressVal) < 4 {
					http.Error(w, "Your duress PIN must be at least 4 characters", http.StatusBadRequest)
					return
				}
				if duressVal == pinVal {
					http.Error(w, "Your duress PIN must be different from your check-in PIN", http.StatusBadRequest)
					return
				}
			}
		}
	}

	totpEnabled := r.FormValue("totp_enable") == "1"
	passkeyEnabled := r.FormValue("passkey_enable") == "1"

	// Apply everything under one write lock, mutating the existing record
	// rather than replacing the pointer. The scheduler holds no pointers now,
	// but replacing the record also used to reset the live cycle and mint a
	// new check-in token, silently invalidating the link already sitting in
	// the user's inbox.
	store.mu.Lock()
	u, exists := store.Users[email]
	if !exists {
		u = &User{
			Email:             email,
			Active:            true,
			Token:             generateToken(),
			ReplyCode:         generateReplyCode(),
			LastPing:          time.Now(),
			CurrentCycleStart: time.Time{},
		}
		store.Users[email] = u
	}

	u.AlertEmails = alertContacts
	u.PingFrequency = pingFreq
	u.CheckInHour = checkInHourUTC
	u.Active = true
	u.AlertMessage = alertMessage
	u.AllClearMessage = allClearMessage
	u.PausedUntil = pausedUntil
	if u.Token == "" {
		u.Token = generateToken()
	}
	if u.ReplyCode == "" {
		u.ReplyCode = generateReplyCode()
	}

	// Drop cached routing and delivery state for contacts that are gone.
	for k := range u.SignalUUIDs {
		if !seen[k] {
			delete(u.SignalUUIDs, k)
		}
	}
	for k := range u.ContactStatus {
		if !seen[k] {
			delete(u.ContactStatus, k)
		}
	}

	if pinEnabled {
		if pinVal != "" {
			cfg, _ := json.Marshal(PINConfig{Pin: hashSecret(pinVal), Duress: hashSecret(duressVal)})
			setModuleEnabled(u, "pin", string(cfg), true)
		} else {
			setModuleEnabled(u, "pin", getModuleConfig(u, "pin"), true)
		}
	} else {
		setModuleEnabled(u, "pin", getModuleConfig(u, "pin"), false)
	}

	if totpEnabled {
		if sec := getModuleConfig(u, "totp"); sec != "" {
			setModuleEnabled(u, "totp", sec, true)
		}
	} else {
		setModuleEnabled(u, "totp", getModuleConfig(u, "totp"), false)
	}

	if passkeyEnabled {
		if cred := getModuleConfig(u, "passkey"); cred != "" {
			setModuleEnabled(u, "passkey", cred, true)
		}
	} else {
		setModuleEnabled(u, "passkey", getModuleConfig(u, "passkey"), false)
	}

	after := snapshot(u)
	store.mu.Unlock()

	saveStore()
	go notifySecurityChange(before, after)

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// notifySecurityChange tells the account holder, and the contacts who were
// configured beforehand, when something safety-relevant changes. Without this,
// anyone who reaches the settings page can quietly remove every emergency
// contact, disable the security modules or pause the service, and nobody finds
// out until the day the alert fails to arrive.
func notifySecurityChange(before, after userSnapshot) {
	if before.Email == "" {
		return
	}

	var changes []string
	if !equalStrings(before.AlertContacts, after.AlertContacts) {
		changes = append(changes, "the emergency contact list was changed")
	}
	removed := difference(before.EnabledModules, after.EnabledModules)
	if len(removed) > 0 {
		changes = append(changes, "these security modules were turned off: "+strings.Join(removed, ", "))
	}
	if before.PausedUntil == nil && after.PausedUntil != nil {
		changes = append(changes, "check-ins were paused until "+after.PausedUntil.Format("2 Jan 2006 15:04 MST"))
	}
	if before.PingFrequency != after.PingFrequency && after.PingFrequency != "" {
		changes = append(changes, "the check-in frequency was changed to "+after.PingFrequency)
	}
	if len(changes) == 0 {
		return
	}

	body := "The following changes were just made to the Wellness Ping settings for " + after.Email + ":\n\n"
	for _, c := range changes {
		body += "  - " + c + "\n"
	}
	body += "\nIf you did not make these changes, someone else may have access to your account."

	notifyAccountChange(before, "Wellness Ping settings changed", body)
}

// notifyAccountChange sends to the account holder and to the previous contact
// list, so removing a contact still notifies the contact who was removed.
func notifyAccountChange(before userSnapshot, subject, body string) {
	recipients := map[string]bool{before.Email: true}
	for _, c := range before.AlertContacts {
		recipients[c] = true
	}
	for contact := range recipients {
		if contact == "" {
			continue
		}
		sendToContact(before, contact, subject, body)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// difference returns items in a that are absent from b.
func difference(a, b []string) []string {
	inB := map[string]bool{}
	for _, x := range b {
		inB[x] = true
	}
	var out []string
	for _, x := range a {
		if !inB[x] {
			out = append(out, x)
		}
	}
	return out
}

func testPingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, ok := requireSessionPost(w, r)
	if !ok {
		return
	}

	snap, exists := snapshotUser(session.Email)
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	go sendPing(snap, 0)

	renderPage(w, http.StatusOK, "Test Ping Sent",
		"A test message is on its way to your registered contact method.",
		map[string]string{"Back to settings": "/settings"})
}

// ---------------------------------------------------------------------------
// Check-in flow (progressive security authentication)
// ---------------------------------------------------------------------------

// enabledModulesLocked lists the security modules a user must satisfy.
// store.mu must be held by the caller.
func enabledModulesLocked(u *User) []string {
	if u == nil {
		return nil
	}
	var out []string
	for _, m := range moduleOrder {
		if moduleEnabled(u, m) {
			out = append(out, m)
		}
	}
	return out
}

// enabledModulesFor takes the lock itself.
func enabledModulesFor(email string) []string {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return enabledModulesLocked(store.Users[email])
}

// findEmailByToken resolves a check-in token to an account, in constant time
// with respect to the token value.
func findEmailByToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	match := ""
	found := false
	for _, u := range store.Users {
		if subtle.ConstantTimeCompare([]byte(u.Token), []byte(token)) == 1 {
			match = u.Email
			found = true
		}
	}
	return match, found
}

func userExists(email string) bool {
	store.mu.RLock()
	defer store.mu.RUnlock()
	_, ok := store.Users[email]
	return ok
}

// getFlowByToken returns a live flow, treating anything past its TTL as absent.
func getFlowByToken(token string) *CheckInFlow {
	checkInFlows.Lock()
	defer checkInFlows.Unlock()
	f, ok := checkInFlows.m[token]
	if !ok {
		return nil
	}
	if time.Since(f.StartedAt) > flowTTL {
		delete(checkInFlows.m, token)
		return nil
	}
	return f
}

// getFlow returns the existing live flow for a token or starts a new one.
// An expired flow is replaced rather than resumed, so a half-finished
// challenge cannot leave a module marked satisfied indefinitely.
func getFlow(token, email, kind string) *CheckInFlow {
	checkInFlows.Lock()
	defer checkInFlows.Unlock()

	if f, ok := checkInFlows.m[token]; ok {
		if time.Since(f.StartedAt) <= flowTTL && f.Kind == kind && f.Email == email {
			return f
		}
		delete(checkInFlows.m, token)
	}

	f := &CheckInFlow{
		Token:     token,
		Email:     email,
		Kind:      kind,
		Completed: map[string]bool{},
		StartedAt: time.Now(),
	}
	checkInFlows.m[token] = f
	return f
}

// flowCompleted / markFlowCompleted guard the Completed map, which is read and
// written from both the form handlers and the passkey JSON endpoints.
func flowCompleted(f *CheckInFlow, module string) bool {
	checkInFlows.RLock()
	defer checkInFlows.RUnlock()
	return f.Completed[module]
}

func markFlowCompleted(f *CheckInFlow, module string) {
	checkInFlows.Lock()
	f.Completed[module] = true
	checkInFlows.Unlock()
}

func discardFlow(token string) {
	checkInFlows.Lock()
	delete(checkInFlows.m, token)
	checkInFlows.Unlock()

	waSessions.Lock()
	delete(waSessions.m, "login:"+token)
	waSessions.Unlock()
}

// sweepFlows drops flows past their TTL. Without this the map grew for the
// lifetime of the process.
func sweepFlows() {
	checkInFlows.Lock()
	for token, f := range checkInFlows.m {
		if time.Since(f.StartedAt) > flowTTL {
			delete(checkInFlows.m, token)
		}
	}
	checkInFlows.Unlock()
}

// remainingSteps lists modules still outstanding for a flow.
func remainingSteps(email string, f *CheckInFlow) []string {
	var out []string
	for _, m := range enabledModulesFor(email) {
		if !flowCompleted(f, m) {
			out = append(out, m)
		}
	}
	return out
}

// completeCheckIn records a successful check-in.
func completeCheckIn(email, token string) {
	var wasAlerted, duress bool
	var snap userSnapshot

	store.mu.Lock()
	if u, ok := store.Users[email]; ok {
		u.LastPing = time.Now()
		u.LastReminderNum = 0
		wasAlerted = u.AlertSent
		duress = u.DuressActive
		u.AlertSent = false
		snap = snapshot(u)
	}
	store.mu.Unlock()

	saveStore()
	discardFlow(token)

	// An all-clear after a duress check-in would tell whoever is standing
	// there that the earlier alert was real. Stay silent until the user
	// clears the duress state from settings.
	if wasAlerted && !duress {
		go sendAllClear(snap)
	}
}

func confirmedPage(w http.ResponseWriter) {
	renderPage(w, http.StatusOK, "Confirmed", "Thanks for checking in.", nil)
}

// pongHandler runs the check-in. Note that a bare GET never completes a
// check-in: mail security products (Safe Links, spam filters, prefetchers)
// routinely fetch every URL in a message, and that would silently disarm the
// switch for the majority of users, who have no security modules enabled.
// Confirming always requires an explicit POST.
func pongHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")

	if !pongLimiter.allow("pong:"+clientIP(r), pongLimit, pongWindow) {
		http.Error(w, "Too many requests. Please wait and try again.", http.StatusTooManyRequests)
		return
	}

	token := r.URL.Query().Get("token")
	email, ok := findEmailByToken(token)
	if !ok {
		http.Error(w, "Invalid or expired check-in link", http.StatusBadRequest)
		return
	}

	flow := getFlow(token, email, "checkin")
	actionURL := "/pong?token=" + url.QueryEscape(token)

	if r.Method == http.MethodPost {
		if len(remainingSteps(email, flow)) > 0 {
			handleChallengeStep(w, r, email, flow, actionURL)
			return
		}
		if r.FormValue("step") != "confirm" {
			http.Error(w, "Unknown step", http.StatusBadRequest)
			return
		}
		checkInFlows.RLock()
		underDuress := flow.Duress
		checkInFlows.RUnlock()

		if underDuress {
			log.Printf("DURESS: silent alert dispatched for %s", email)
			triggerDuress(email)
			discardFlow(token)
		} else {
			completeCheckIn(email, token)
		}
		// Identical response either way.
		confirmedPage(w)
		return
	}

	if renderChallengeStep(w, email, flow, actionURL) {
		return
	}
	renderConfirmStep(w, flow, actionURL)
}

// renderConfirmStep shows the final "yes, I'm okay" button.
func renderConfirmStep(w http.ResponseWriter, flow *CheckInFlow, actionURL string) {
	tmpl, err := template.ParseFiles("templates/pong_confirm.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]interface{}{
		"Token":   flow.Token,
		"Action":  actionURL,
		"Version": VERSION,
	})
}

// loginHandler gates access to /settings behind any enabled security modules.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	flow := getFlowByToken(token)
	if flow == nil || flow.Kind != "login" {
		http.Error(w, "Invalid or expired login session", http.StatusBadRequest)
		return
	}
	email := flow.Email
	if !userExists(email) {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	actionURL := "/login?token=" + url.QueryEscape(token)

	if r.Method == http.MethodPost {
		if len(remainingSteps(email, flow)) > 0 {
			handleChallengeStep(w, r, email, flow, actionURL)
			return
		}
		createSession(w, r, email, token)
		return
	}

	if renderChallengeStep(w, email, flow, actionURL) {
		return
	}
	createSession(w, r, email, token)
}

// renderChallengeStep shows the next required step. Returns false when every
// enabled module has been satisfied.
func renderChallengeStep(w http.ResponseWriter, email string, flow *CheckInFlow, actionURL string) bool {
	remaining := remainingSteps(email, flow)
	if len(remaining) == 0 {
		return false
	}
	step := remaining[0]

	data := map[string]interface{}{
		"Token":   flow.Token,
		"Step":    step,
		"Action":  actionURL,
		"Version": VERSION,
	}

	var file string
	switch step {
	case "pin":
		file = "templates/pong_pin.html"
	case "totp":
		file = "templates/pong_totp.html"
	case "passkey":
		file = "templates/pong_passkey.html"
	default:
		http.Error(w, "Unknown step", http.StatusInternalServerError)
		return true
	}

	tmpl, err := template.ParseFiles(file)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return true
	}
	tmpl.Execute(w, data)
	return true
}

// handleChallengeStep processes one module's answer. Every branch is attempt
// limited per account, so discarding a flow and starting a fresh one does not
// hand an attacker an unlimited PIN oracle.
func handleChallengeStep(w http.ResponseWriter, r *http.Request, email string, flow *CheckInFlow, actionURL string) {
	step := r.FormValue("step")

	// Only accept an answer for the step we are actually asking for.
	remaining := remainingSteps(email, flow)
	if len(remaining) == 0 || step != remaining[0] {
		http.Error(w, "Unexpected step", http.StatusBadRequest)
		return
	}

	switch step {
	case "pin":
		handlePINStep(w, r, email, flow, actionURL)
	case "totp":
		handleTOTPStep(w, r, email, flow, actionURL)
	case "passkey":
		// The passkey ceremony completes over its own JSON endpoints; there is
		// nothing to post here.
		http.Error(w, "Use the passkey button to continue", http.StatusBadRequest)
	default:
		http.Error(w, "Unknown step", http.StatusBadRequest)
	}
}

func handlePINStep(w http.ResponseWriter, r *http.Request, email string, flow *CheckInFlow, actionURL string) {
	if !pinLimiter.allow("pin:"+email, moduleAttemptLim, moduleAttemptWin) {
		// Deliberately vague, and identical to the wording an attacker would
		// see for a wrong PIN plus a wait.
		http.Error(w, "Too many attempts. Please wait 15 minutes and try again.", http.StatusTooManyRequests)
		return
	}

	pin := r.FormValue("pin")

	store.mu.RLock()
	u := store.Users[email]
	rawCfg := ""
	if u != nil {
		rawCfg = moduleConfig(u, "pin")
	}
	store.mu.RUnlock()

	var cfg PINConfig
	if json.Unmarshal([]byte(rawCfg), &cfg) != nil {
		http.Error(w, "Invalid PIN", http.StatusUnauthorized)
		return
	}

	// Both comparisons are ALWAYS evaluated, in the same order, before
	// anything branches.
	//
	// Short-circuiting here is a real information leak: the duress PIN matches
	// on the first comparison and returns, while a correct normal PIN has to
	// fail the duress comparison first and then pass its own. That is two
	// argon2 invocations against one, roughly a 2x difference in response
	// time, which is enough to tell the two apart from outside. When the
	// safety property is "nobody can tell you entered the duress PIN", the
	// timing has to match as well as the pages do.
	duressStored := cfg.Duress
	if duressStored == "" {
		duressStored = decoyHash // pay the same cost when no duress PIN is set
	}
	duressOK, duressUpgraded := verifySecretUpgrade(duressStored, pin)
	duressOK = duressOK && cfg.Duress != ""

	pinOK, pinUpgraded := verifySecretUpgrade(cfg.Pin, pin)
	pinOK = pinOK && cfg.Pin != ""

	if duressOK {
		log.Printf("DURESS: duress PIN accepted for %s", email)
		checkInFlows.Lock()
		flow.Duress = true
		checkInFlows.Unlock()
		if duressUpgraded != "" {
			go upgradePINHash(email, "", duressUpgraded)
		}
		// Exactly the same success path from here on.
		pinLimiter.reset("pin:" + email)
		markFlowCompleted(flow, "pin")
		http.Redirect(w, r, actionURL, http.StatusSeeOther)
		return
	}

	if !pinOK {
		http.Error(w, "Invalid PIN", http.StatusUnauthorized)
		return
	}
	if pinUpgraded != "" {
		// Asynchronous to match the duress branch above.
		go upgradePINHash(email, pinUpgraded, "")
	}

	pinLimiter.reset("pin:" + email)
	markFlowCompleted(flow, "pin")
	http.Redirect(w, r, actionURL, http.StatusSeeOther)
}

func handleTOTPStep(w http.ResponseWriter, r *http.Request, email string, flow *CheckInFlow, actionURL string) {
	if !totpLimiter.allow("totp:"+email, moduleAttemptLim, moduleAttemptWin) {
		http.Error(w, "Too many attempts. Please wait 15 minutes and try again.", http.StatusTooManyRequests)
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))

	store.mu.RLock()
	u := store.Users[email]
	rawCfg := ""
	if u != nil {
		rawCfg = moduleConfig(u, "totp")
	}
	store.mu.RUnlock()

	var cfg TOTPConfig
	if json.Unmarshal([]byte(rawCfg), &cfg) != nil || cfg.Secret == "" || !totp.Validate(code, cfg.Secret) {
		http.Error(w, "Invalid code. Please try again.", http.StatusUnauthorized)
		return
	}
	if !consumeTOTPCode(email, code) {
		// Same wording as a wrong code: a replayed code must not be
		// distinguishable from an incorrect one.
		http.Error(w, "Invalid code. Please try again.", http.StatusUnauthorized)
		return
	}

	totpLimiter.reset("totp:" + email)
	markFlowCompleted(flow, "totp")
	http.Redirect(w, r, actionURL, http.StatusSeeOther)
}

// usedTOTPCodes gives TOTP single-use semantics within its validity window, so
// a code observed over the user's shoulder (or in a proxy log) cannot be
// replayed during the remainder of its 30-second step.
var usedTOTPCodes = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

func consumeTOTPCode(email, code string) bool {
	key := email + ":" + code
	usedTOTPCodes.Lock()
	defer usedTOTPCodes.Unlock()
	if seen, ok := usedTOTPCodes.m[key]; ok && time.Since(seen) < 90*time.Second {
		return false
	}
	usedTOTPCodes.m[key] = time.Now()
	return true
}

func sweepTOTPCodes() {
	usedTOTPCodes.Lock()
	for k, t := range usedTOTPCodes.m {
		if time.Since(t) > 90*time.Second {
			delete(usedTOTPCodes.m, k)
		}
	}
	usedTOTPCodes.Unlock()
}

// upgradePINHash rewrites a legacy PIN and/or duress hash in place.
func upgradePINHash(email, newPin, newDuress string) {
	mutateUser(email, func(u *User) {
		var cfg PINConfig
		if json.Unmarshal([]byte(getModuleConfig(u, "pin")), &cfg) != nil {
			return
		}
		if newPin != "" {
			cfg.Pin = newPin
		}
		if newDuress != "" {
			cfg.Duress = newDuress
		}
		if b, err := json.Marshal(cfg); err == nil {
			for i := range u.SecurityModules {
				if u.SecurityModules[i].ModuleType == "pin" {
					u.SecurityModules[i].Config = string(b)
				}
			}
		}
	})
	saveStore()
}

// triggerDuress records the duress check-in and dispatches the alert in the
// background. Outwardly the account now looks exactly like a normal check-in:
// the cycle is satisfied, so no further reminders go out and nothing on screen
// or in the mailbox hints that contacts were notified.
func triggerDuress(email string) {
	now := time.Now()
	var snap userSnapshot

	store.mu.Lock()
	if u, ok := store.Users[email]; ok {
		u.LastPing = now
		u.LastReminderNum = 0
		u.AlertSent = true
		u.DuressActive = true
		u.DuressAt = &now
		snap = snapshot(u)
	}
	store.mu.Unlock()

	// Persist synchronously, exactly as completeCheckIn does, so the two
	// confirmations take the same time. Only the alert itself is dispatched in
	// the background, since that can take a minute over signal-cli.
	saveStore()
	go sendAlert(snap)
}

// createSession grants a settings session cookie. All enabled security
// modules must already have been satisfied before calling this.
func createSession(w http.ResponseWriter, r *http.Request, email, flowToken string) {
	discardFlow(flowToken)

	sessionToken := generateToken()
	csrf := generateToken()
	store.mu.Lock()
	store.Sessions[sessionToken] = &Session{
		Email:     email,
		Token:     sessionToken,
		CSRF:      csrf,
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	store.mu.Unlock()
	saveStore()

	setSessionCookie(w, sessionToken)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	flow := getFlowByToken(token)
	if flow == nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	email := flow.Email

	// The passkey step must be the step we are actually asking for, otherwise
	// this endpoint could be used to satisfy it out of order.
	remaining := remainingSteps(email, flow)
	if len(remaining) == 0 || remaining[0] != "passkey" {
		http.Error(w, "Unexpected step", http.StatusBadRequest)
		return
	}

	store.mu.RLock()
	wu := wauserFor(store.Users[email])
	store.mu.RUnlock()

	if len(wu.Credentials) == 0 {
		http.Error(w, "No passkey registered", http.StatusBadRequest)
		return
	}

	options, sessionData, err := webAuthn.BeginLogin(wu)
	if err != nil {
		http.Error(w, "Failed to begin passkey login", http.StatusInternalServerError)
		return
	}
	waSessions.Lock()
	waSessions.m["login:"+token] = sessionData
	waSessions.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	flow := getFlowByToken(token)
	if flow == nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	email := flow.Email

	remaining := remainingSteps(email, flow)
	if len(remaining) == 0 || remaining[0] != "passkey" {
		http.Error(w, "Unexpected step", http.StatusBadRequest)
		return
	}

	// Consume the ceremony session immediately: a WebAuthn challenge is
	// single-use, and leaving it in place on failure allows unlimited retries
	// against the same challenge.
	waSessions.Lock()
	sessionData, ok := waSessions.m["login:"+token]
	delete(waSessions.m, "login:"+token)
	waSessions.Unlock()
	if !ok {
		http.Error(w, "No passkey session", http.StatusBadRequest)
		return
	}

	store.mu.RLock()
	wu := wauserFor(store.Users[email])
	store.mu.RUnlock()

	if _, err := webAuthn.FinishLogin(wu, *sessionData, r); err != nil {
		http.Error(w, "Passkey verification failed", http.StatusUnauthorized)
		return
	}

	markFlowCompleted(flow, "passkey")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Security module handlers
// ---------------------------------------------------------------------------

func moduleEnabled(u *User, moduleType string) bool {
	if u == nil {
		return false
	}
	for _, mod := range u.SecurityModules {
		if mod.ModuleType == moduleType && mod.Enabled {
			return true
		}
	}
	return false
}

func moduleConfig(u *User, moduleType string) string {
	if u == nil {
		return ""
	}
	for _, mod := range u.SecurityModules {
		if mod.ModuleType == moduleType && mod.Enabled {
			return mod.Config
		}
	}
	return ""
}

// getModuleConfig returns a module's config regardless of enabled state,
// so disabling a module can keep its config for later re-enabling.
func getModuleConfig(u *User, moduleType string) string {
	if u == nil {
		return ""
	}
	for _, mod := range u.SecurityModules {
		if mod.ModuleType == moduleType {
			return mod.Config
		}
	}
	return ""
}

// moduleConfigured reports whether a module has a real configuration stored,
// independent of whether it is currently enabled.
func moduleConfigured(u *User, moduleType string) bool {
	if u == nil {
		return false
	}
	switch moduleType {
	case "totp":
		var cfg TOTPConfig
		if json.Unmarshal([]byte(getModuleConfig(u, moduleType)), &cfg) == nil {
			return cfg.Secret != ""
		}
	case "passkey":
		var cfg PasskeyConfig
		if json.Unmarshal([]byte(getModuleConfig(u, moduleType)), &cfg) == nil {
			return cfg.Credential != ""
		}
	case "pin":
		var cfg PINConfig
		if json.Unmarshal([]byte(getModuleConfig(u, moduleType)), &cfg) == nil {
			return cfg.Pin != ""
		}
	}
	return false
}

func setModuleEnabled(u *User, moduleType string, config string, enabled bool) {
	now := time.Now()
	for i := range u.SecurityModules {
		if u.SecurityModules[i].ModuleType == moduleType {
			u.SecurityModules[i].Config = config
			u.SecurityModules[i].Enabled = enabled
			u.SecurityModules[i].CreatedAt = now
			return
		}
	}
	// Don't create an empty disabled placeholder module.
	if config == "" && !enabled {
		return
	}
	u.SecurityModules = append(u.SecurityModules, SecurityModule{
		Enabled:    enabled,
		ModuleType: moduleType,
		Config:     config,
		CreatedAt:  now,
	})
}

// requireSession validates the session cookie and returns a copy of the
// session (never the live pointer).
func requireSession(w http.ResponseWriter, r *http.Request) (Session, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized - please sign in first", http.StatusUnauthorized)
		return Session{}, false
	}
	store.mu.RLock()
	s, exists := store.Sessions[cookie.Value]
	var copied Session
	if exists {
		copied = *s
	}
	store.mu.RUnlock()

	if !exists || time.Now().After(copied.ExpiresAt) {
		http.Error(w, "Session expired - please sign in again", http.StatusUnauthorized)
		return Session{}, false
	}
	return copied, true
}

// requireSessionPost additionally enforces a CSRF token. SameSite=Strict
// blocks the common cross-site POST, but it is a single browser-side control:
// it does not cover a same-site subdomain that an attacker controls, and it is
// not honoured by every client. State-changing requests carry a token bound to
// the session as well.
func requireSessionPost(w http.ResponseWriter, r *http.Request) (Session, bool) {
	session, ok := requireSession(w, r)
	if !ok {
		return Session{}, false
	}
	token := r.FormValue("csrf")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if session.CSRF == "" || subtle.ConstantTimeCompare([]byte(token), []byte(session.CSRF)) != 1 {
		http.Error(w, "Request could not be verified. Reload the settings page and try again.", http.StatusForbidden)
		return Session{}, false
	}
	return session, true
}

func requireUser(email string, w http.ResponseWriter) bool {
	if !userExists(email) {
		http.Error(w, "User not found", http.StatusNotFound)
		return false
	}
	return true
}

func totpSetupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, ok := requireSession(w, r)
	if !ok {
		return
	}
	email := session.Email
	if !requireUser(email, w) {
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Wellness Ping",
		AccountName: email,
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP key", http.StatusInternalServerError)
		return
	}

	// Render the QR code locally so the TOTP secret never leaves this server.
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}
	qrDataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)

	data := map[string]interface{}{
		"Secret":  key.Secret(),
		"QR":      template.URL(qrDataURI),
		"Email":   email,
		"CSRF":    session.CSRF,
		"Version": VERSION,
	}
	tmpl, err := template.ParseFiles("templates/totp_setup.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func totpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	session, ok := requireSessionPost(w, r)
	if !ok {
		return
	}
	email := session.Email
	if !requireUser(email, w) {
		return
	}

	if !totpLimiter.allow("totp-setup:"+email, moduleAttemptLim, moduleAttemptWin) {
		http.Error(w, "Too many attempts. Please wait 15 minutes and try again.", http.StatusTooManyRequests)
		return
	}

	secret := strings.TrimSpace(r.FormValue("secret"))
	code := strings.TrimSpace(r.FormValue("code"))
	if secret == "" || !totp.Validate(code, secret) {
		http.Error(w, "Invalid code. Please try again.", http.StatusBadRequest)
		return
	}
	totpLimiter.reset("totp-setup:" + email)

	cfg, _ := json.Marshal(TOTPConfig{Secret: secret})
	before, _ := snapshotUser(email)
	mutateUser(email, func(u *User) { setModuleEnabled(u, "totp", string(cfg), true) })
	saveStore()
	after, _ := snapshotUser(email)
	go notifySecurityChange(before, after)

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	session, ok := requireSessionPost(w, r)
	if !ok {
		return
	}
	email := session.Email
	if !requireUser(email, w) {
		return
	}

	store.mu.RLock()
	wu := wauserFor(store.Users[email])
	store.mu.RUnlock()

	options, sessionData, err := webAuthn.BeginRegistration(wu)
	if err != nil {
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	waSessions.Lock()
	waSessions.m["register:"+email] = sessionData
	waSessions.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, ok := requireSessionPost(w, r)
	if !ok {
		return
	}
	email := session.Email
	if !requireUser(email, w) {
		return
	}

	// Single-use ceremony session.
	waSessions.Lock()
	sessionData, exists := waSessions.m["register:"+email]
	delete(waSessions.m, "register:"+email)
	waSessions.Unlock()
	if !exists {
		http.Error(w, "No registration session", http.StatusBadRequest)
		return
	}

	store.mu.RLock()
	wu := wauserFor(store.Users[email])
	store.mu.RUnlock()

	credential, err := webAuthn.FinishRegistration(wu, *sessionData, r)
	if err != nil {
		http.Error(w, "Registration failed", http.StatusBadRequest)
		return
	}

	encoded, err := marshalCredential(credential)
	if err != nil {
		http.Error(w, "Failed to store credential", http.StatusInternalServerError)
		return
	}
	cfg, _ := json.Marshal(PasskeyConfig{Credential: encoded})
	before, _ := snapshotUser(email)
	mutateUser(email, func(u *User) { setModuleEnabled(u, "passkey", string(cfg), true) })
	saveStore()
	after, _ := snapshotUser(email)
	go notifySecurityChange(before, after)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Inbound email (reply PONG)
//
// This is the highest-risk path in the service. An email's From header is set
// by whoever sends the message, so treating it as identity meant that anyone
// who knew a user's address could disarm their switch at will, indefinitely.
// Three independent checks now apply:
//
//  1. The webhook itself is authenticated (shared secret, constant-time).
//  2. The message must be DKIM/SPF authenticated and aligned with the From
//     domain, per the Authentication-Results header the inbound provider adds.
//  3. The body must quote the current cycle's reply code, which only appears
//     in the check-in message actually delivered to the user.
//
// Automated mail (vacation autoresponders, bounces) is discarded before any of
// this, and quoted text is stripped so the word in our own outgoing message
// cannot be reflected back as a check-in.
// ---------------------------------------------------------------------------

type inboundMessage struct {
	From        string `json:"From"`
	To          string `json:"To"`
	Subject     string `json:"Subject"`
	TextBody    string `json:"TextBody"`
	HtmlBody    string `json:"HtmlBody"`
	MessageID   string `json:"MessageID"`
	MailboxHash string `json:"MailboxHash"`
	Headers     []struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	} `json:"Headers"`
}

func (m *inboundMessage) header(name string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// isAutomated reports whether the message was machine-generated. An
// out-of-office responder that quotes our check-in message would otherwise
// check the user in every single cycle, which is precisely the situation the
// service exists to detect.
func (m *inboundMessage) isAutomated() (bool, string) {
	if v := m.header("Auto-Submitted"); v != "" && !strings.EqualFold(strings.TrimSpace(v), "no") {
		return true, "Auto-Submitted: " + v
	}
	switch strings.ToLower(strings.TrimSpace(m.header("Precedence"))) {
	case "bulk", "auto_reply", "junk", "list":
		return true, "Precedence: " + m.header("Precedence")
	}
	for _, h := range []string{"X-Autoreply", "X-Autorespond", "X-Auto-Response-Suppress", "List-Id", "List-Unsubscribe"} {
		if m.header(h) != "" {
			return true, h + " present"
		}
	}
	if rp := strings.TrimSpace(m.header("Return-Path")); rp == "<>" {
		return true, "null return path (bounce)"
	}
	if strings.Contains(strings.ToLower(m.Subject), "out of office") ||
		strings.Contains(strings.ToLower(m.Subject), "automatic reply") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(m.Subject)), "undeliverable") {
		return true, "autoresponder subject"
	}
	return false, ""
}

var (
	// Common reply separators. Everything from the first match onwards is the
	// quoted original, not something the sender typed.
	replySeparators = []*regexp.Regexp{
		regexp.MustCompile(`(?im)^-{2,}\s*original message\s*-{2,}`),
		regexp.MustCompile(`(?im)^_{5,}\s*$`),
		regexp.MustCompile(`(?im)^-{5,}\s*$`),
		regexp.MustCompile(`(?im)^on .{0,200}\bwrote:\s*$`),
		regexp.MustCompile(`(?im)^от:.*$`),
		regexp.MustCompile(`(?im)^\s*from:\s.*\bsent:\s`),
		regexp.MustCompile(`(?im)^sent from my \w+`),
	}
	authResultRe = regexp.MustCompile(`(?i)\b(dkim|spf|dmarc)=(\w+)`)
	dkimDomainRe = regexp.MustCompile(`(?i)header\.(?:d|i)=@?([A-Za-z0-9.\-_]+)`)
)

// newContent strips quoted material and signatures from a reply body.
func newContent(body string) string {
	cut := len(body)
	for _, re := range replySeparators {
		if loc := re.FindStringIndex(body); loc != nil && loc[0] < cut {
			cut = loc[0]
		}
	}
	body = body[:cut]

	var kept []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ">") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// verifyInboundAuth checks the provider's Authentication-Results header. We
// require a DKIM pass whose signing domain aligns with the From domain, or an
// SPF pass. Without an Authentication-Results header at all we refuse, since
// we then have no evidence the sender is who they claim.
func verifyInboundAuth(m *inboundMessage, fromEmail string) (bool, string) {
	if envBool("INBOUND_ALLOW_UNAUTHENTICATED") && isDev() {
		return true, "authentication bypassed (development)"
	}

	results := m.header("Authentication-Results")
	if results == "" {
		results = m.header("ARC-Authentication-Results")
	}
	if strings.TrimSpace(results) == "" {
		return false, "no Authentication-Results header"
	}

	verdicts := map[string]string{}
	for _, match := range authResultRe.FindAllStringSubmatch(results, -1) {
		method := strings.ToLower(match[1])
		if _, seen := verdicts[method]; !seen {
			verdicts[method] = strings.ToLower(match[2])
		}
	}

	if verdicts["dmarc"] == "pass" {
		return true, "dmarc=pass"
	}

	fromDomain := ""
	if at := strings.LastIndex(fromEmail, "@"); at >= 0 {
		fromDomain = strings.ToLower(fromEmail[at+1:])
	}

	if verdicts["dkim"] == "pass" {
		// Alignment matters: a DKIM pass for some unrelated domain says
		// nothing about whether this message really came from the user.
		signing := ""
		if md := dkimDomainRe.FindStringSubmatch(results); md != nil {
			signing = strings.ToLower(md[1])
		}
		if signing != "" && (signing == fromDomain || strings.HasSuffix(fromDomain, "."+signing)) {
			return true, "dkim=pass aligned with " + signing
		}
		return false, fmt.Sprintf("dkim=pass but signing domain %q is not aligned with %q", signing, fromDomain)
	}

	if verdicts["spf"] == "pass" {
		return true, "spf=pass"
	}

	return false, fmt.Sprintf("no passing authentication (%v)", verdicts)
}

func inboundEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	expectedSecret := os.Getenv("INBOUND_SECRET")
	if expectedSecret == "" {
		log.Printf("INBOUND_SECRET not set; rejecting inbound webhook")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	providedSecret := r.URL.Query().Get("secret")
	if subtle.ConstantTimeCompare([]byte(providedSecret), []byte(expectedSecret)) != 1 {
		log.Printf("Invalid inbound webhook secret from %s", clientIP(r))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var msg inboundMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		log.Printf("Error decoding inbound email: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Always answer 200 past this point: the provider should not retry, and a
	// distinguishable status would tell a prober whether an address is
	// registered.
	ack := func(reason string) {
		if reason != "" {
			log.Printf("Inbound reply not accepted: %s", reason)
		}
		w.WriteHeader(http.StatusOK)
	}

	if automated, why := msg.isAutomated(); automated {
		ack("automated message discarded (" + why + ")")
		return
	}

	fromEmail := extractEmail(msg.From)
	if fromEmail == "" {
		ack("could not parse sender")
		return
	}

	if !inboundLimiter.allow("inbound:"+fromEmail, inboundLimit, inboundWindow) {
		ack("rate limit exceeded for " + fromEmail)
		return
	}

	if ok, why := verifyInboundAuth(&msg, fromEmail); !ok {
		log.Printf("SECURITY: rejected inbound reply claiming to be from %s: %s", fromEmail, why)
		ack("")
		return
	}

	// Only the new text the sender wrote counts. Our own outgoing message
	// contains the reply instructions, so quoted text must never be matched.
	content := newContent(msg.TextBody)
	lower := strings.ToLower(content)
	if !strings.Contains(lower, "pong") {
		ack("no PONG in the new content of the reply")
		return
	}

	store.mu.Lock()
	user, exists := store.Users[fromEmail]
	var (
		wasAlerted bool
		duress     bool
		accepted   bool
		snap       userSnapshot
		reason     string
	)
	if exists {
		switch {
		case len(enabledModulesLocked(user)) > 0:
			// A reply cannot satisfy PIN/TOTP/passkey, so it must not stand in
			// for a check-in for these users.
			reason = "security modules enabled for " + fromEmail
		case user.ReplyCode == "":
			reason = "no reply code issued for the current cycle"
		case !strings.Contains(lower, strings.ToLower(user.ReplyCode)):
			// The code only ever appears in the message actually delivered to
			// the user, so a spoofed sender cannot produce it.
			reason = "reply code missing or incorrect for " + fromEmail
		default:
			accepted = true
			wasAlerted = user.AlertSent
			duress = user.DuressActive
			user.LastPing = time.Now()
			user.LastReminderNum = 0
			user.AlertSent = false
			snap = snapshot(user)
		}
	} else {
		reason = "no account for sender"
	}
	store.mu.Unlock()

	if !accepted {
		ack(reason)
		return
	}

	saveStore()
	log.Printf("Check-in accepted by email reply for %s", fromEmail)

	if wasAlerted && !duress {
		go sendAllClear(snap)
	}
	go sendReplyEmail(fromEmail, msg.MessageID, msg.Subject, content)

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

// redactForLog trims anything secret out of a log line. With POSTMARK_TOKEN
// unset the old code logged whole message bodies, which meant verification
// codes and live check-in links ended up in the server log.
var (
	logSecretURL  = regexp.MustCompile(`(?i)(token=)[A-Za-z0-9_\-=]+`)
	logSecretCode = regexp.MustCompile(`(?i)(code is:\s*)\S+`)
	logReplyCode  = regexp.MustCompile(`(?i)(PONG-)[A-Z0-9]+`)
)

func redactForLog(s string) string {
	s = logSecretURL.ReplaceAllString(s, "${1}[redacted]")
	s = logSecretCode.ReplaceAllString(s, "${1}[redacted]")
	s = logReplyCode.ReplaceAllString(s, "${1}[redacted]")
	return s
}

func sendPing(user userSnapshot, reminderNum int) {
	link := fmt.Sprintf("%s/pong?token=%s", baseURL(), url.QueryEscape(user.Token))
	subject := "Wellness Ping"

	// Reply-PONG only applies to email, when no security modules are enabled
	// (a reply cannot satisfy PIN/TOTP/passkey). The reply must quote this
	// cycle's code, so simply knowing the address is not enough to disarm the
	// switch on someone's behalf.
	kind, _ := classifyContact(user.Email)
	replyHint := ""
	if len(user.EnabledModules) == 0 && kind == "email" && user.ReplyCode != "" {
		replyHint = fmt.Sprintf("\n\nOr reply to this email with: PONG-%s", user.ReplyCode)
	}

	var body string
	if reminderNum == 0 {
		body = fmt.Sprintf("Hi! Just checking in.\n\nOpen this link and press the confirm button: %s%s", link, replyHint)
	} else {
		var timeRemaining string
		if user.PingFrequency == "daily" {
			timeRemaining = fmt.Sprintf("%d hours", 24-(reminderNum*6))
		} else {
			timeRemaining = fmt.Sprintf("%d days", 7-reminderNum)
		}
		body = fmt.Sprintf("Reminder: You haven't checked in yet.\n\nYou have %s remaining before your contacts are notified.\n\nOpen this link and press the confirm button: %s%s", timeRemaining, link, replyHint)
		subject = "Wellness Ping - Reminder"
	}

	sendToContact(user, user.Email, subject, body)
}

func sendAlert(user userSnapshot) {
	if user.Email == "" {
		return
	}
	subject := fmt.Sprintf("Wellness Alert - %s Not Responding", user.Email)
	body := user.AlertMessage
	if body == "" {
		body = fmt.Sprintf("WARNING: %s hasn't responded to their wellness ping.\n\nPlease check in on them to ensure they're okay.", user.Email)
	}
	fanOut(user, user.AlertContacts, subject, body)
}

func sendAllClear(user userSnapshot) {
	if user.Email == "" {
		return
	}
	subject := fmt.Sprintf("All Clear - %s Checked In", user.Email)
	body := user.AllClearMessage
	if body == "" {
		body = fmt.Sprintf("Good news! %s has now checked in and confirmed they're okay.", user.Email)
	}
	fanOut(user, user.AlertContacts, subject, body)
}

// fanOut delivers to every contact concurrently. Sequential delivery meant a
// single slow signal-cli invocation (up to 60s, plus 45s to resolve a UUID)
// held up every remaining contact - and, when called from the scheduler,
// every other user's pings and alerts too.
func fanOut(user userSnapshot, contacts []string, subject, body string) {
	var wg sync.WaitGroup
	for _, contact := range contacts {
		if contact == "" {
			continue
		}
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("ERROR: panic while notifying a contact of %s: %v", user.Email, rec)
				}
			}()
			sendToContact(user, c, subject, body)
		}(contact)
	}
	wg.Wait()
}

// urlPattern matches http(s) URLs in the message body so they can be linked.
var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

// plainToHTML converts a plaintext body into an HTML body: it HTML-escapes
// the text, turns any URL into a clickable link, and converts newlines to
// <br>. Everything that reaches an HtmlBody must go through here.
func plainToHTML(text string) string {
	var sb strings.Builder
	last := 0
	for _, m := range urlPattern.FindAllStringIndex(text, -1) {
		sb.WriteString(template.HTMLEscapeString(text[last:m[0]]))
		raw := text[m[0]:m[1]]
		// Only http(s) reaches here, but escape both the attribute and the
		// visible text regardless.
		esc := template.HTMLEscapeString(raw)
		sb.WriteString(fmt.Sprintf(`<a href="%s">%s</a>`, esc, esc))
		last = m[1]
	}
	sb.WriteString(template.HTMLEscapeString(text[last:]))
	return strings.ReplaceAll(sb.String(), "\n", "<br>")
}

// postmarkSend posts a single message. Returns an error so callers can record
// a delivery status instead of only logging one.
func postmarkSend(payload map[string]interface{}, to string) error {
	token := os.Getenv("POSTMARK_TOKEN")
	if token == "" {
		log.Printf("POSTMARK_TOKEN not set; would send to %s subject %q", to, payload["Subject"])
		return fmt.Errorf("mail is not configured")
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not encode message: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.postmarkapp.com/email", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("could not build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("delivery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("provider rejected the message (%d): %s", resp.StatusCode, redactForLog(strings.TrimSpace(string(bodyBytes))))
	}
	return nil
}

func sendEmail(to, subject, body string) error {
	return postmarkSend(map[string]interface{}{
		"From":          senderAddress(),
		"To":            to,
		"Subject":       subject,
		"TextBody":      body,
		"HtmlBody":      plainToHTML(body),
		"MessageStream": "outbound",
	}, to)
}

func senderAddress() string {
	if v := strings.TrimSpace(os.Getenv("POSTMARK_FROM")); v != "" {
		return v
	}
	return "ping@wellness-p.ing"
}

// sendReplyEmail acknowledges an accepted reply-PONG.
//
// The quoted body is attacker-influenced text. It previously went into the
// HtmlBody with no escaping at all, which let anyone who could get a message
// accepted have this service emit arbitrary HTML - working links included -
// from its own trusted domain. It is escaped here, and truncated so the
// acknowledgement cannot be used to relay bulk content.
func sendReplyEmail(to, inReplyTo, originalSubject, originalBody string) {
	const maxQuote = 500
	quoted := originalBody
	if len(quoted) > maxQuote {
		quoted = quoted[:maxQuote] + "\n[...]"
	}

	subject := strings.TrimSpace(originalSubject)
	if subject == "" {
		subject = "Wellness Ping"
	}
	if !strings.HasPrefix(strings.ToLower(subject), "re:") {
		subject = "Re: " + subject
	}
	if len(subject) > 200 {
		subject = subject[:200]
	}

	intro := "Thanks for checking in! We received your PONG.\n\n"
	textBody := intro + "> " + strings.ReplaceAll(quoted, "\n", "\n> ")

	// The quote is escaped but deliberately NOT linkified. plainToHTML turns
	// bare URLs into anchors, and quoted text is attacker-influenced, so
	// running it through there would let a sender place a working clickable
	// link into a message sent from our own domain.
	htmlBody := template.HTMLEscapeString(intro) +
		"<blockquote>" + strings.ReplaceAll(template.HTMLEscapeString(quoted), "\n", "<br>") + "</blockquote>"
	htmlBody = strings.ReplaceAll(htmlBody, "\n", "<br>")

	payload := map[string]interface{}{
		"From":          senderAddress(),
		"To":            to,
		"Subject":       subject,
		"TextBody":      textBody,
		"HtmlBody":      htmlBody,
		"MessageStream": "outbound",
		// Mark our own acknowledgement as automated so that the recipient's
		// mail system does not answer it, and neither do we.
		"Headers": []map[string]string{
			{"Name": "Auto-Submitted", "Value": "auto-replied"},
			{"Name": "X-Auto-Response-Suppress", "Value": "All"},
			{"Name": "Precedence", "Value": "auto_reply"},
		},
	}
	if inReplyTo != "" {
		hdrs := payload["Headers"].([]map[string]string)
		hdrs = append(hdrs,
			map[string]string{"Name": "In-Reply-To", "Value": inReplyTo},
			map[string]string{"Name": "References", "Value": inReplyTo})
		payload["Headers"] = hdrs
	}

	if err := postmarkSend(payload, to); err != nil {
		log.Printf("WARNING: could not send reply acknowledgement to %s: %v", to, err)
	}
}

// extractEmail pulls the address out of a From header value.
func extractEmail(from string) string {
	from = strings.TrimSpace(from)
	if from == "" {
		return ""
	}
	// Prefer a real RFC 5322 parse; fall back to the angle brackets.
	if addr, err := mail.ParseAddress(from); err == nil {
		return strings.ToLower(strings.TrimSpace(addr.Address))
	}
	if start := strings.Index(from, "<"); start != -1 {
		if end := strings.Index(from[start:], ">"); end > 0 {
			return strings.ToLower(strings.TrimSpace(from[start+1 : start+end]))
		}
	}
	if _, canon := classifyContact(from); canon != "" && strings.Contains(canon, "@") {
		return canon
	}
	return ""
}

// ---------------------------------------------------------------------------
// Signal (via signal-cli)
// ---------------------------------------------------------------------------

// OfficialSignalUsername is the account Wellness Ping sends from on Signal.
const OfficialSignalUsername = "wellness_ping.01"

// signalState tracks whether signal-cli is available and usable on this host.
type signalState struct {
	Binary  string
	Account string
	Ready   bool
	Message string
}

var signal = signalState{}

// signalUsernameRe matches a valid Signal username per libsignal's rules:
//
//	nickname: 3-32 chars, not starting with a digit, chars [a-zA-Z0-9_]
//	separator: '.'
//	discriminator: 2-9 digits; 2-digit may not be 00; 3+ digits may not have
//	              a leading zero (libsignal allows up to 9 digits).
var signalUsernameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{2,31}\.(?:[1-9][0-9]{2,8}|[0-9][1-9]|[1-9][0-9])$`)

// detectSignal locates signal-cli and confirms a registered account is present.
// If it isn't found/set up we do NOT fail the process - we fall back to email
// for dev, but log loudly so it's obvious Signal is not working.
func detectSignal() {
	bin := os.Getenv("SIGNAL_CLI_PATH")
	if bin == "" {
		b, err := exec.LookPath("signal-cli")
		if err != nil {
			signal.Message = "signal-cli not found on PATH (set SIGNAL_CLI_PATH to enable); Signal NOT working - falling back to email"
			log.Printf("WARNING: %s", signal.Message)
			return
		}
		bin = b
	}
	signal.Binary = bin

	signal.Account = os.Getenv("SIGNAL_ACCOUNT")
	if signal.Account == "" {
		signal.Message = "signal-cli found but SIGNAL_ACCOUNT is not set; cannot send - falling back to email"
		log.Printf("WARNING: %s", signal.Message)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// --output is a global flag and must precede the command.
	out, err := exec.CommandContext(ctx, bin, "--output=json", "listAccounts").CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			log.Printf("signal-cli listAccounts output: %s", detail)
		}
		if ctx.Err() == context.DeadlineExceeded {
			signal.Message = fmt.Sprintf("signal-cli found (%s) but listAccounts timed out after 60s and was killed. Output: %s - is signal-cli responsive / is another instance holding its config? Signal NOT working; falling back to email", bin, detail)
		} else {
			signal.Message = fmt.Sprintf("signal-cli found (%s) but listAccounts failed: %v. Output: %s - Signal NOT working; falling back to email", bin, err, detail)
		}
		log.Printf("WARNING: %s", signal.Message)
		return
	}

	if strings.TrimSpace(string(out)) == "" || !strings.Contains(string(out), signal.Account) {
		// No accounts, or the configured account isn't among them. Show what IS
		// registered so a mismatch (e.g. typo in SIGNAL_ACCOUNT) is obvious.
		registered := strings.TrimSpace(string(out))
		if registered == "" {
			registered = "(none)"
		}
		signal.Message = fmt.Sprintf("signal-cli found (%s) but SIGNAL_ACCOUNT=%s is not among registered accounts: %s. Signal NOT working; falling back to email", bin, signal.Account, registered)
		log.Printf("WARNING: %s", signal.Message)
		return
	}

	signal.Ready = true
	signal.Message = fmt.Sprintf("Signal enabled using %s (account %s); sending as %s", bin, signal.Account, OfficialSignalUsername)
	log.Printf("%s", signal.Message)
}

// classifyContact decides what a free-form contact identifier is and returns its
// kind ("email"/"signal"/"phone") plus a canonical form. A bare number defaults
// to country code +1 and handles +, 00, spaces, parens and dashes.
// phoneShapeRe describes what may legitimately appear in a typed phone number.
// Anything else is a typo, not a phone number.
var phoneShapeRe = regexp.MustCompile(`^\+?[0-9 ()\-\.\/]+$`)

// classifyContact decides what a free-form contact identifier is and returns
// its kind ("email"/"signal"/"phone") plus a canonical form. It is strict:
// previously any unrecognised string fell through to the phone branch, so a
// typo like "jane doe" became the contact "+1" and every emergency alert to it
// failed silently, with nothing shown to the user.
func classifyContact(raw string) (kind, canonical string) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 254 {
		return "", ""
	}

	if strings.Contains(s, "@") {
		addr, err := mail.ParseAddress(s)
		if err != nil {
			return "", ""
		}
		e := strings.ToLower(strings.TrimSpace(addr.Address))
		at := strings.LastIndex(e, "@")
		local, domain := e[:at], e[at+1:]
		// A domain with no dot, or an empty local part, is never deliverable.
		if local == "" || !strings.Contains(domain, ".") ||
			strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
			strings.Contains(e, " ") {
			return "", ""
		}
		return "email", e
	}

	if signalUsernameRe.MatchString(s) {
		return "signal", strings.ToLower(s)
	}

	if !phoneShapeRe.MatchString(s) {
		return "", ""
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)

	var e164 string
	switch {
	case strings.HasPrefix(s, "+"):
		e164 = "+" + digits
	case strings.HasPrefix(digits, "00"):
		e164 = "+" + digits[2:]
	default:
		// Bare national number, assumed to be the default country.
		cc := strings.TrimPrefix(strings.TrimSpace(os.Getenv("DEFAULT_COUNTRY_CODE")), "+")
		if cc == "" {
			cc = "1"
		}
		e164 = "+" + cc + digits
	}

	// E.164 allows 1-3 digits of country code plus a subscriber number, to a
	// maximum of 15 digits overall. Fewer than 8 is not a real number.
	if n := len(e164) - 1; n < 8 || n > 15 {
		return "", ""
	}
	return "phone", e164
}

// signalSendRaw delivers a message to a direct recipient argument: a Signal
// username (u:...), an E.164 phone number, or a resolved ACI UUID.
func signalSendRaw(recArg, body string) error {
	if !signal.Ready {
		return fmt.Errorf("Signal is not ready")
	}
	out, err := runSignalCLI(60*time.Second, body, "send", "--message-from-stdin", recArg)
	if err != nil {
		return fmt.Errorf("signal-cli send failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sendVerificationCodeSignal sends the verification code to a phone/Signal
// username as a plain Signal message.
func sendVerificationCodeSignal(contact, code string) bool {
	if !signal.Ready {
		log.Printf("WARNING: cannot send verification code to %s: Signal not ready", contact)
		return false
	}

	uuid := ""
	if u, ok := resolveSignalUUID(contact); ok {
		uuid = u
	}
	recArg := signalSendTarget(contact, uuid)

	err := signalSendRaw(recArg, fmt.Sprintf("Your Wellness Ping Verification Code is: %s\n\nThis code expires in 10 minutes.", code))
	if err != nil {
		log.Printf("WARNING: could not send verification code to %s via Signal: %v", contact, err)
	}
	return err == nil
}

// signalSendTarget turns a contact into the recipient argument signal-cli
// expects: u:<username>, the E.164, or a bare ACI UUID.
func signalSendTarget(contact, uuid string) string {
	kind, canon := classifyContact(contact)
	if uuid != "" {
		return uuid
	}
	if kind == "signal" {
		return "u:" + canon
	}
	return canon
}

// resolveSignalUUID asks signal-cli for the ACI UUID backing a username or
// phone number, so future sends keep working even if the username changes.
// signalMu serialises every signal-cli invocation.
//
// signal-cli takes an exclusive lock on its account config, so concurrent
// invocations queue up regardless, each holding a live process while it waits.
// On a small box that is the difference between one resident process and ten:
// a fan-out alert to ten Signal contacts used to start ten of them at once.
var signalMu sync.Mutex

// runSignalCLI runs one signal-cli command, one at a time.
func runSignalCLI(timeout time.Duration, stdin string, args ...string) ([]byte, error) {
	if signal.Binary == "" || signal.Account == "" {
		return nil, fmt.Errorf("Signal is not configured")
	}

	signalMu.Lock()
	defer signalMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, signal.Binary, append([]string{"-a", signal.Account}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// signalLookup reports whether a contact is registered on Signal and returns
// its ACI UUID. It distinguishes "not on Signal" from "the lookup failed":
// the first is a dead end worth telling the user about, the second is worth
// retrying.
func signalLookup(contact string) (uuid string, registered bool, err error) {
	if !signal.Ready {
		return "", false, fmt.Errorf("Signal is not configured")
	}
	kind, canon := classifyContact(contact)

	var args []string
	switch kind {
	case "signal":
		// getUserStatus --username takes the bare username, NOT the u: prefix
		// (u: is only valid as a positional recipient to send).
		args = []string{"--output=json", "getUserStatus", "--username", canon}
	case "phone":
		args = []string{"--output=json", "getUserStatus", canon}
	default:
		return "", false, fmt.Errorf("not a Signal contact")
	}

	out, err := runSignalCLI(45*time.Second, "", args...)
	if err != nil {
		return "", false, fmt.Errorf("%v: %s", err, firstLine(string(out)))
	}

	var list []struct {
		UUID       string `json:"uuid"`
		Registered bool   `json:"isRegistered"`
	}
	if json.Unmarshal(out, &list) != nil {
		return "", false, fmt.Errorf("could not parse getUserStatus output")
	}
	for _, u := range list {
		if u.Registered {
			return u.UUID, true, nil
		}
	}
	return "", false, nil
}

func resolveSignalUUID(contact string) (string, bool) {
	uuid, registered, err := signalLookup(contact)
	if err != nil {
		log.Printf("signal-cli getUserStatus failed for %s: %v", contact, err)
		return "", false
	}
	return uuid, registered && uuid != ""
}

// signalReceiveLine is one line of `signal-cli --output=json receive`.
//
// The sender fields live under "envelope"; reading them from the top level
// yields empty strings for every message, so no incoming DM would ever match.
// A couple of legacy top-level fields are accepted too, so a format change
// degrades rather than breaks.
type signalReceiveLine struct {
	Envelope struct {
		Source       string `json:"source"`
		SourceNumber string `json:"sourceNumber"`
		SourceUuid   string `json:"sourceUuid"`
		SourceName   string `json:"sourceName"`
		DataMessage  *struct {
			Message string `json:"message"`
		} `json:"dataMessage"`
	} `json:"envelope"`
	SourceNumber string `json:"sourceNumber"`
	SourceUuid   string `json:"sourceUuid"`
	Account      string `json:"account"`
}

// dmSeen records who has recently sent us a Signal message, keyed by
// "num:<E.164>" or "uuid:<aci>".
var dmSeen = struct {
	sync.RWMutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

func noteDM(key string) {
	if key == "" {
		return
	}
	dmSeen.Lock()
	dmSeen.m[key] = time.Now()
	dmSeen.Unlock()
}

func sawDM(key string) bool {
	if key == "" {
		return false
	}
	dmSeen.RLock()
	t, ok := dmSeen.m[key]
	dmSeen.RUnlock()
	return ok && time.Since(t) < dmSeenTTL
}

func sweepDMSeen() {
	dmSeen.Lock()
	for k, t := range dmSeen.m {
		if time.Since(t) > dmSeenTTL {
			delete(dmSeen.m, k)
		}
	}
	dmSeen.Unlock()
}

func sweepPendingSignups() {
	pendingSignups.Lock()
	for k, ps := range pendingSignups.m {
		if time.Since(ps.CreatedAt) > signupTTL {
			delete(pendingSignups.m, k)
		}
	}
	pendingSignups.Unlock()
}

// signalReceiveLoop is the ONLY place that runs `signal-cli receive`.
//
// receive is destructive: it pulls messages off the server queue and
// acknowledges them, after which they are gone. Running it from a request
// handler meant two people signing up at the same moment drained each other's
// messages, and whoever lost the race was told "we haven't seen your message"
// forever, with nothing left on the server to find. One reader, recording
// every sender it sees, removes the race: a DM that arrives before the user
// clicks is still remembered when they do.
//
// It is also needed for its own sake. The Signal protocol expects a client to
// receive regularly, both to drain the queue and to keep prekeys rotating.
// Nothing was doing that at all.
func signalReceiveLoop() {
	for {
		if !signal.Ready {
			time.Sleep(30 * time.Second)
			continue
		}

		out, err := runSignalCLI(45*time.Second, "", "--output=json", "receive", "--timeout", "5")
		if err != nil {
			log.Printf("WARNING: signal-cli receive failed: %v: %s", err, firstLine(string(out)))
			time.Sleep(30 * time.Second)
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var rl signalReceiveLine
			if json.Unmarshal([]byte(line), &rl) != nil {
				continue
			}
			for _, num := range []string{rl.Envelope.SourceNumber, rl.Envelope.Source, rl.SourceNumber} {
				if strings.HasPrefix(num, "+") {
					noteDM("num:" + num)
				}
			}
			for _, id := range []string{rl.Envelope.SourceUuid, rl.SourceUuid} {
				if id != "" {
					noteDM("uuid:" + id)
				}
			}
		}

		// Yield the signal-cli lock so queued sends get a turn.
		time.Sleep(3 * time.Second)
	}
}

// claimSignupCode atomically claims the staged verification code for a signup
// whose DM we have seen. Exactly one caller can claim within sendRetryDelay,
// so hammering the button cannot fan out a pile of Signal sends. Returning a
// status rather than un-claiming on failure keeps the decision in one place
// and testable.
func claimSignupCode(canonical string) (code string, status string) {
	pendingSignups.Lock()
	defer pendingSignups.Unlock()

	ps := pendingSignups.m[canonical]
	if ps == nil || time.Since(ps.CreatedAt) > signupTTL {
		return "", "expired"
	}
	if ps.Sent && time.Since(ps.SentAt) < sendRetryDelay {
		return "", "already-sent"
	}
	if !sawDM("num:"+canonical) && !(ps.UUID != "" && sawDM("uuid:"+ps.UUID)) {
		return "", "no-dm"
	}
	ps.Sent = true
	ps.SentAt = time.Now()
	return ps.Code, "ok"
}

// dmContinueHandler is where a new Signal signup reports that they have
// messaged our bot. It only reads the map the receive loop maintains, so it
// starts no subprocess: previously every click spawned one (two, for a
// username), unauthenticated, which was a straightforward way to exhaust the
// memory on a small host.
func dmContinueHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !dmLimiter.allow("dm:"+clientIP(r), dmContinueLimit, dmContinueWindow) {
		http.Error(w, "Too many attempts. Please wait a moment and try again.", http.StatusTooManyRequests)
		return
	}

	raw := strings.TrimSpace(r.FormValue("identifier"))
	if raw == "" {
		raw = strings.TrimSpace(r.FormValue("email")) // backwards-compatible
	}
	kind, canonical := classifyContact(raw)
	if kind == "" || canonical == "" {
		http.Error(w, "Invalid identifier", http.StatusBadRequest)
		return
	}

	code, status := claimSignupCode(canonical)
	switch status {
	case "expired":
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	case "no-dm":
		renderDM(w, canonical, "We haven't seen your message yet. Make sure you sent it from "+
			canonical+" to "+OfficialSignalUsername+", give it a few seconds, then try again.")
		return
	case "already-sent":
		// A code went out moments ago. Show the entry page rather than
		// sending another one.
		renderTemplate(w, "templates/verify.html", map[string]interface{}{"Email": canonical, "ViaSignal": true})
		return
	}

	store.mu.Lock()
	store.PendingVerifications[canonical] = &PendingVerification{
		Email:     canonical,
		Code:      code,
		ExpiresAt: time.Now().Add(pendingCodeTTL),
	}
	store.mu.Unlock()

	// Sent in the background: signal-cli is serialised now, so a queued send
	// must not hold this handler open.
	go sendVerificationCodeSignal(canonical, code)

	renderTemplate(w, "templates/verify.html", map[string]interface{}{"Email": canonical, "ViaSignal": true})
}

func renderDM(w http.ResponseWriter, canonical, notice string) {
	renderTemplate(w, "templates/dm.html", map[string]interface{}{
		"Email":   canonical,
		"From":    OfficialSignalUsername,
		"Version": VERSION,
		"Notice":  notice,
	})
}

// sendToContact dispatches a notification to a single contact by its best
// channel: email for email addresses, Signal for usernames/phone numbers.
// The contact's ACI UUID is resolved and cached on first use so a later
// username change doesn't break delivery.
// sendToContact dispatches a notification to a single contact by its best
// channel and records the outcome, so an undeliverable emergency contact shows
// up in settings rather than only in the log.
func sendToContact(user userSnapshot, contact, subject, body string) {
	kind, _ := classifyContact(contact)

	var err error
	switch kind {
	case "email":
		err = sendEmail(contact, subject, body)
	case "signal", "phone":
		err = sendViaSignal(user, contact, subject+"\n\n"+body)
	default:
		err = fmt.Errorf("not a deliverable address")
	}

	status := "delivered " + time.Now().UTC().Format("2006-01-02 15:04 MST")
	if err != nil {
		status = "FAILED " + time.Now().UTC().Format("2006-01-02 15:04 MST") + ": " + err.Error()
		log.Printf("WARNING: could not reach %s for %s: %v", contact, user.Email, err)
	}
	if user.Email != "" {
		recordContactStatus(user.Email, contact, status)
	}
}

func sendViaSignal(user userSnapshot, contact, msg string) error {
	if !signal.Ready {
		return fmt.Errorf("Signal is not configured on this server")
	}

	// Prefer a cached UUID if we already resolved one.
	uuid := user.SignalUUIDs[contact]
	if uuid == "" {
		if u, ok := resolveSignalUUID(contact); ok {
			uuid = u
			if user.Email != "" {
				cacheSignalUUID(user.Email, contact, u)
			}
		}
	}
	return signalSendRaw(signalSendTarget(contact, uuid), msg)
}

func generateCode() string {
	code := ""
	for i := 0; i < 8; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		code += fmt.Sprintf("%d", n)
	}
	return code
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A predictable check-in token would let anyone disarm the switch, so
		// there is no safe way to continue.
		log.Fatalf("FATAL: could not read random bytes: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// replyCodeAlphabet avoids characters that are easily confused when a person
// retypes the code out of a message.
const replyCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// generateReplyCode produces the short per-cycle secret quoted in a reply-PONG.
// 8 characters of a 32-symbol alphabet is 40 bits, which is far beyond guessing
// for a value that only lives for one check-in cycle.
func generateReplyCode() string {
	b := make([]byte, 8)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(replyCodeAlphabet))))
		if err != nil {
			log.Fatalf("FATAL: could not read random bytes: %v", err)
		}
		b[i] = replyCodeAlphabet[n.Int64()]
	}
	return string(b)
}

const (
	dataDir  = "data"
	dataFile = "data/users.json"
)

func loadStore() {
	// 0700: the file below holds PIN hashes, TOTP secrets and live session
	// tokens. It must not be world-readable.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("FATAL: cannot create %s: %v", dataDir, err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		log.Printf("WARNING: could not tighten permissions on %s: %v", dataDir, err)
	}

	data, err := os.ReadFile(dataFile)
	if err != nil {
		return
	}
	// Repair permissions on a store written by an earlier version.
	if info, statErr := os.Stat(dataFile); statErr == nil && info.Mode().Perm() != 0o600 {
		log.Printf("Tightening permissions on %s from %o to 600", dataFile, info.Mode().Perm())
		if err := os.Chmod(dataFile, 0o600); err != nil {
			log.Printf("WARNING: could not chmod %s: %v", dataFile, err)
		}
	}

	if err := json.Unmarshal(data, &store); err != nil {
		// Starting with an empty store would silently disarm every switch, so
		// refuse to run instead.
		log.Fatalf("FATAL: %s is present but could not be parsed (%v); "+
			"refusing to start with an empty store", dataFile, err)
	}

	if store.Sessions == nil {
		store.Sessions = make(map[string]*Session)
	}
	if store.Users == nil {
		store.Users = make(map[string]*User)
	}
	if store.PendingVerifications == nil {
		store.PendingVerifications = make(map[string]*PendingVerification)
	}

	// Backfill state introduced after a store was first written. Without a
	// reply code an existing user's reply-PONG would be rejected until their
	// next cycle started, which for a weekly user is up to seven days of a
	// working feature silently not working.
	backfilled := 0
	for _, u := range store.Users {
		if u.ReplyCode == "" {
			u.ReplyCode = generateReplyCode()
			backfilled++
		}
		if u.Token == "" {
			u.Token = generateToken()
		}
	}
	if backfilled > 0 {
		log.Printf("Issued reply codes to %d existing user(s)", backfilled)
	}
}

// saveStore serialises the store under a read lock and replaces the file
// atomically, so a crash mid-write cannot truncate it.
// Callers must not hold store.mu.
func saveStore() {
	store.mu.RLock()
	data, err := json.MarshalIndent(store, "", "  ")
	userCount := len(store.Users)
	store.mu.RUnlock()

	if err != nil {
		log.Printf("ERROR: could not serialise store: %v", err)
		return
	}

	tmp := dataFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("ERROR: could not write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, dataFile); err != nil {
		log.Printf("ERROR: could not replace %s: %v", dataFile, err)
		os.Remove(tmp)
		return
	}
	log.Printf("Store saved (%d users)", userCount)
}

// ---------------------------------------------------------------------------
// Safe store access
//
// Every read or write of a *User field goes through one of these helpers while
// holding store.mu. Previously the scheduler walked live *User pointers with no
// lock while handlers mutated (and in updateHandler, wholesale replaced) them.
// ---------------------------------------------------------------------------

// mutateUser applies fn to the stored user under the write lock. It reports
// whether the user existed. Callers must not call saveStore from within fn.
func mutateUser(email string, fn func(*User)) bool {
	store.mu.Lock()
	u, ok := store.Users[email]
	if ok {
		fn(u)
	}
	store.mu.Unlock()
	return ok
}

// userSnapshot is an immutable copy of everything the delivery and scheduling
// code needs. Passing snapshots instead of live pointers means a slow
// signal-cli call can never race a concurrent settings save.
type userSnapshot struct {
	Email             string
	AlertContacts     []string
	PingFrequency     string
	CheckInHour       int
	LastPing          time.Time
	CurrentCycleStart time.Time
	LastReminderNum   int
	Active            bool
	Token             string
	ReplyCode         string
	AlertSent         bool
	DuressActive      bool
	PausedUntil       *time.Time
	AlertMessage      string
	AllClearMessage   string
	EnabledModules    []string
	SignalUUIDs       map[string]string
}

// snapshot copies a user. store.mu must be held (read or write) by the caller.
func snapshot(u *User) userSnapshot {
	s := userSnapshot{
		Email:             u.Email,
		AlertContacts:     append([]string(nil), u.AlertEmails...),
		PingFrequency:     u.PingFrequency,
		CheckInHour:       u.CheckInHour,
		LastPing:          u.LastPing,
		CurrentCycleStart: u.CurrentCycleStart,
		LastReminderNum:   u.LastReminderNum,
		Active:            u.Active,
		Token:             u.Token,
		ReplyCode:         u.ReplyCode,
		AlertSent:         u.AlertSent,
		DuressActive:      u.DuressActive,
		AlertMessage:      u.AlertMessage,
		AllClearMessage:   u.AllClearMessage,
		EnabledModules:    enabledModulesLocked(u),
		SignalUUIDs:       make(map[string]string, len(u.SignalUUIDs)),
	}
	if u.PausedUntil != nil {
		p := *u.PausedUntil
		s.PausedUntil = &p
	}
	for k, v := range u.SignalUUIDs {
		s.SignalUUIDs[k] = v
	}
	return s
}

func snapshotUser(email string) (userSnapshot, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	u, ok := store.Users[email]
	if !ok {
		return userSnapshot{}, false
	}
	return snapshot(u), true
}

func snapshotAllUsers() []userSnapshot {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := make([]userSnapshot, 0, len(store.Users))
	for _, u := range store.Users {
		out = append(out, snapshot(u))
	}
	return out
}

// cacheSignalUUID and recordContactStatus are the only writers of their
// respective maps, and both take the lock.
func cacheSignalUUID(email, contact, uuid string) {
	mutateUser(email, func(u *User) {
		if u.SignalUUIDs == nil {
			u.SignalUUIDs = map[string]string{}
		}
		u.SignalUUIDs[contact] = uuid
	})
}

func recordContactStatus(email, contact, status string) {
	mutateUser(email, func(u *User) {
		if u.ContactStatus == nil {
			u.ContactStatus = map[string]string{}
		}
		u.ContactStatus[contact] = status
	})
}

// verifyTurnstile validates the CAPTCHA response. When the secret is missing
// it now fails closed unless APP_ENV=development is set explicitly: a single
// absent environment variable in production used to silently disable the
// control entirely.
func verifyTurnstile(r *http.Request) bool {
	secret := os.Getenv("TURNSTILE_SECRET_KEY")
	if secret == "" {
		if isDev() {
			log.Println("TURNSTILE_SECRET_KEY not set; accepting (development mode only)")
			return true
		}
		log.Println("ERROR: TURNSTILE_SECRET_KEY not set; rejecting request")
		return false
	}

	token := r.FormValue("cf-turnstile-response")
	if token == "" {
		return false
	}

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	// Binding the response to the client address makes a stolen token far less
	// useful to replay from elsewhere.
	if ip := clientIP(r); ip != "" {
		form.Set("remoteip", ip)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		log.Printf("Turnstile verify error: %v", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Turnstile decode error: %v", err)
		return false
	}
	if !result.Success {
		log.Printf("Turnstile verification failed: %v", result.ErrorCodes)
	}
	return result.Success
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

// startCycle mints a fresh check-in token and reply code for a new cycle and
// returns a snapshot to send from. Rotating both means a link or reply code
// from a previous cycle cannot be replayed to satisfy this one.
func startCycle(email string) (userSnapshot, bool) {
	var snap userSnapshot
	ok := mutateUser(email, func(u *User) {
		u.CurrentCycleStart = time.Now()
		u.LastReminderNum = 0
		u.AlertSent = false
		u.DuressActive = false
		u.DuressAt = nil
		u.Token = generateToken()
		u.ReplyCode = generateReplyCode()
		snap = snapshot(u)
	})
	return snap, ok
}

// dispatch runs a delivery off the scheduler goroutine. Sending inline meant a
// single unresponsive signal-cli invocation could stall the tick - and with it
// every other user's reminders and alerts - for many minutes.
func dispatch(fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("ERROR: panic in background delivery: %v", rec)
			}
		}()
		fn()
	}()
}

func pingScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		runSchedulerTick()
	}
}

func runSchedulerTick() {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("ERROR: panic in scheduler tick: %v", rec)
		}
	}()

	now := time.Now()
	needsSave := housekeeping(now)

	// Work from snapshots: the scheduler no longer holds live *User pointers
	// while handlers mutate them.
	for _, user := range snapshotAllUsers() {
		if !user.Active {
			continue
		}

		if user.PausedUntil != nil {
			if now.Before(*user.PausedUntil) {
				continue
			}
			mutateUser(user.Email, func(u *User) { u.PausedUntil = nil })
			log.Printf("Auto-resuming %s after pause", user.Email)
			needsSave = true
			user.PausedUntil = nil
		}

		var pingInterval, reminderInterval time.Duration
		maxReminders := 3
		if user.PingFrequency == "weekly" {
			pingInterval, reminderInterval, maxReminders = 7*24*time.Hour, 24*time.Hour, 6
		} else {
			pingInterval, reminderInterval = 24*time.Hour, 6*time.Hour
		}

		cycleComplete := user.CurrentCycleStart.IsZero() || user.LastPing.After(user.CurrentCycleStart)

		if cycleComplete && now.Hour() == user.CheckInHour && now.Minute() < 5 {
			shouldStart := false
			if user.PingFrequency == "daily" {
				shouldStart = now.Truncate(24 * time.Hour).After(user.LastPing.Truncate(24 * time.Hour))
			} else {
				shouldStart = user.CurrentCycleStart.IsZero() || time.Since(user.LastPing) >= pingInterval
			}
			if shouldStart {
				if snap, ok := startCycle(user.Email); ok {
					log.Printf("Starting new %s cycle for %s", user.PingFrequency, user.Email)
					dispatch(func() { sendPing(snap, 0) })
					needsSave = true
				}
				continue
			}
		}

		if user.CurrentCycleStart.IsZero() || !user.LastPing.Before(user.CurrentCycleStart) {
			continue
		}

		elapsed := now.Sub(user.CurrentCycleStart)

		if elapsed < pingInterval {
			expected := int(elapsed / reminderInterval)
			if expected > 0 && expected > user.LastReminderNum && expected <= maxReminders {
				var snap userSnapshot
				sent := false
				mutateUser(user.Email, func(u *User) {
					// Re-check under the lock: the user may have checked in
					// between the snapshot and here.
					if u.LastReminderNum >= expected || u.LastPing.After(u.CurrentCycleStart) {
						return
					}
					u.LastReminderNum = expected
					snap = snapshot(u)
					sent = true
				})
				if sent {
					log.Printf("Sending reminder #%d to %s", expected, user.Email)
					n := expected
					dispatch(func() { sendPing(snap, n) })
					needsSave = true
				}
			}
		}

		if elapsed >= pingInterval && !user.AlertSent {
			var snap userSnapshot
			fire := false
			mutateUser(user.Email, func(u *User) {
				// Guard against a double alert if two ticks overlap.
				if u.AlertSent || u.LastPing.After(u.CurrentCycleStart) {
					return
				}
				u.AlertSent = true
				snap = snapshot(u)
				fire = true
			})
			if fire {
				log.Printf("ALERT: emergency alert for %s", user.Email)
				dispatch(func() { sendAlert(snap) })
				needsSave = true
			}
		}
	}

	if needsSave {
		saveStore()
	}
}

// housekeeping expires the in-memory and persisted state that previously grew
// without bound: sessions, pending verification codes, challenge flows, used
// TOTP codes and rate-limiter history.
func housekeeping(now time.Time) bool {
	changed := false

	store.mu.Lock()
	for token, session := range store.Sessions {
		if now.After(session.ExpiresAt) {
			delete(store.Sessions, token)
			changed = true
		}
	}
	// Expired codes used to sit here until someone attempted a verification,
	// so an attacker could grow this map (and the data file) indefinitely.
	for key, pending := range store.PendingVerifications {
		if now.After(pending.ExpiresAt) {
			delete(store.PendingVerifications, key)
			changed = true
		}
	}
	store.mu.Unlock()

	sweepFlows()
	sweepTOTPCodes()
	sweepDMSeen()
	sweepPendingSignups()
	for _, rl := range []*rateLimiter{codeSendLimiter, codeVerifyLimiter, pinLimiter, totpLimiter, pongLimiter, inboundLimiter, dmLimiter} {
		rl.sweep(codeSendWindow)
	}

	return changed
}
