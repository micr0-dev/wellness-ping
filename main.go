package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

const VERSION = "2.0.0"

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
	Email             string           `json:"email"`
	AlertEmails       []string         `json:"alert_emails"`
	PingFrequency     string           `json:"ping_frequency"`
	CheckInHour       int              `json:"checkin_hour"`
	LastPing          time.Time        `json:"last_ping"`
	CurrentCycleStart time.Time        `json:"current_cycle_start"`
	LastReminderNum   int              `json:"last_reminder_num"`
	Active            bool             `json:"active"`
	Token             string           `json:"token"`
	AlertSent         bool             `json:"alert_sent"`
	PausedUntil       *time.Time       `json:"paused_until,omitempty"`
	AlertMessage      string           `json:"alert_message,omitempty"`
	AllClearMessage   string           `json:"all_clear_message,omitempty"`
	SecurityModules   []SecurityModule `json:"security_modules"`
	SignalUUIDs       map[string]string `json:"signal_uuids,omitempty"` // canonical contact -> resolved ACI UUID
}

type PendingVerification struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Session struct {
	Email     string    `json:"email"`
	Token     string    `json:"token"`
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
	Kind      string // "checkin" or "login"
	Completed map[string]bool // "pin", "totp", "passkey"
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

func (u *WAUser) WebAuthnID() []byte                        { return u.ID }
func (u *WAUser) WebAuthnName() string                      { return u.Name }
func (u *WAUser) WebAuthnDisplayName() string               { return u.DisplayName }
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

	cfg := &webauthn.Config{
		RPDisplayName: "Wellness Ping",
		RPID:          rpID,
		RPOrigins:     []string{origin, "http://localhost:8080", "http://localhost:8087"},
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

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

	if os.Getenv("POSTMARK_TOKEN") == "" {
		log.Println("Warning: POSTMARK_TOKEN not set. Emails will not be sent.")
	}

	if os.Getenv("INBOUND_SECRET") == "" {
		log.Println("Warning: INBOUND_SECRET not set. Inbound email verification will not work.")
	}

	loadStore()
	initWebAuthn()
	detectSignal()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/send-code", sendCodeHandler)
	http.HandleFunc("/verify-code", verifyCodeHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/update", updateHandler)
	http.HandleFunc("/pong", pongHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/test-ping", testPingHandler)
	http.HandleFunc("/inbound", inboundEmailHandler)

	// Security module setup
	http.HandleFunc("/totp-setup", totpSetupHandler)
	http.HandleFunc("/totp-verify", totpVerifyHandler)
	http.HandleFunc("/passkey-register-begin", passkeyRegisterBegin)
	http.HandleFunc("/passkey-register-finish", passkeyRegisterFinish)

	// Passkey check-in ceremony
	http.HandleFunc("/passkey-login-begin", passkeyLoginBegin)
	http.HandleFunc("/passkey-login-finish", passkeyLoginFinish)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	go pingScheduler()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Server starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"Version":          VERSION,
		"TurnstileSiteKey": os.Getenv("TURNSTILE_SITE_KEY"),
	}
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	tmpl.Execute(w, data)
}

func sendCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !verifyTurnstile(r.FormValue("cf-turnstile-response")) {
		http.Error(w, "CAPTCHA verification failed. Please try again.", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))

	code := generateCode()

	store.mu.Lock()
	store.PendingVerifications[email] = &PendingVerification{
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	store.mu.Unlock()

	subject := "Wellness Ping Verification Code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 10 minutes.", code)
	sendEmail(email, subject, body)

	data := map[string]string{"Email": email}
	tmpl := template.Must(template.ParseFiles("templates/verify.html"))
	tmpl.Execute(w, data)
}

func verifyCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	code := strings.TrimSpace(r.FormValue("code"))

	store.mu.Lock()
	pending, exists := store.PendingVerifications[email]
	store.mu.Unlock()

	if !exists {
		http.Error(w, "No verification pending for this email", http.StatusBadRequest)
		return
	}

	if time.Now().After(pending.ExpiresAt) {
		store.mu.Lock()
		delete(store.PendingVerifications, email)
		store.mu.Unlock()
		http.Error(w, "Code expired", http.StatusBadRequest)
		return
	}

	if pending.Code != code {
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	delete(store.PendingVerifications, email)
	store.mu.Unlock()

	// If the user has any security modules enabled, the email code is only the
	// first factor - they must complete each enabled module before a settings
	// session is granted.
	store.mu.RLock()
	user := store.Users[email]
	store.mu.RUnlock()
	if user != nil && len(enabledModules(user)) > 0 {
		loginToken := generateToken()
		getFlow(loginToken, email, "login")
		http.Redirect(w, r, "/login?token="+url.QueryEscape(loginToken), http.StatusSeeOther)
		return
	}

	sessionToken := generateToken()
	store.mu.Lock()
	store.Sessions[sessionToken] = &Session{
		Email:     email,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	delete(store.PendingVerifications, email)
	store.mu.Unlock()
	saveStore()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   1800,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized - please verify your email first", http.StatusUnauthorized)
		return
	}

	store.mu.RLock()
	session, exists := store.Sessions[cookie.Value]
	store.mu.RUnlock()

	if !exists || time.Now().After(session.ExpiresAt) {
		http.Error(w, "Session expired - please verify your email again", http.StatusUnauthorized)
		return
	}

	email := session.Email

	store.mu.RLock()
	user := store.Users[email]
	store.mu.RUnlock()

	data := map[string]interface{}{
		"User":           user,
		"Email":          email,
		"Version":        VERSION,
		"PinEnabled":        moduleEnabled(user, "pin"),
		"TOTPEnabled":       moduleEnabled(user, "totp"),
		"PasskeyEnabled":    moduleEnabled(user, "passkey"),
		"TOTPConfigured":    moduleConfigured(user, "totp"),
		"PasskeyConfigured": moduleConfigured(user, "passkey"),
	}

	tmpl := template.Must(template.ParseFiles("templates/settings.html"))
	tmpl.Execute(w, data)
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	store.mu.RLock()
	session, exists := store.Sessions[cookie.Value]
	store.mu.RUnlock()

	if !exists || time.Now().After(session.ExpiresAt) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	email := session.Email
	action := r.FormValue("action")

	if action == "stop" {
		store.mu.Lock()
		delete(store.Users, email)
		delete(store.Sessions, cookie.Value)
		store.mu.Unlock()
		saveStore()

		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Service Stopped</h1><p>Your wellness ping service has been stopped and all data deleted.</p><p><a href='/'>Go back</a></p></body></html>")
		return
	}

	alertEmailsStr := r.FormValue("alert_emails")
	if strings.TrimSpace(alertEmailsStr) == "" {
		http.Error(w, "Alert emails are required", http.StatusBadRequest)
		return
	}

	alertEmails := []string{}
	for _, e := range strings.Split(alertEmailsStr, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			// Accept an email, a Signal username (name.##), or a phone number
			// (default country code +1).
			kind, canon := classifyContact(e)
			if kind == "" || canon == "" {
				http.Error(w, fmt.Sprintf("Invalid alert contact: %s", e), http.StatusBadRequest)
				return
			}
			alertEmails = append(alertEmails, canon)
		}
	}

	if len(alertEmails) == 0 {
		http.Error(w, "At least one alert email is required", http.StatusBadRequest)
		return
	}

	const maxContacts = 10
	if len(alertEmails) > maxContacts {
		http.Error(w, fmt.Sprintf("Maximum %d emergency contacts allowed (you provided %d)", maxContacts, len(alertEmails)), http.StatusBadRequest)
		return
	}

	pingFreq := r.FormValue("ping_frequency")
	if pingFreq != "daily" && pingFreq != "weekly" {
		http.Error(w, "Ping frequency must be 'daily' or 'weekly'", http.StatusBadRequest)
		return
	}

	localHour := 9
	if r.FormValue("checkin_hour") != "" {
		n, err := fmt.Sscanf(r.FormValue("checkin_hour"), "%d", &localHour)
		if err != nil || n != 1 {
			http.Error(w, "Invalid check-in hour format", http.StatusBadRequest)
			return
		}
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
		http.Error(w, fmt.Sprintf("Invalid timezone: %s", timezone), http.StatusBadRequest)
		return
	}

	now := time.Now()
	localTime := time.Date(now.Year(), now.Month(), now.Day(), localHour, 0, 0, 0, loc)
	utcTime := localTime.UTC()
	checkInHourUTC := utcTime.Hour()

	// Parse custom messages
	alertMessage := strings.TrimSpace(r.FormValue("alert_message"))
	allClearMessage := strings.TrimSpace(r.FormValue("all_clear_message"))

	// Parse paused_until
	var pausedUntil *time.Time
	pausedUntilStr := r.FormValue("paused_until")
	if pausedUntilStr != "" {
		parsedTime, err := time.Parse("2006-01-02T15:04", pausedUntilStr)
		if err == nil && parsedTime.After(time.Now()) {
			pt := parsedTime
			pausedUntil = &pt
		}
	}

	store.mu.RLock()
	existingUser := store.Users[email]
	store.mu.RUnlock()

	// Module-level actions that affect only one module (no full save).
	switch action {
	case "clear_totp":
		store.mu.Lock()
		setModuleEnabled(existingUser, "totp", "", false)
		store.mu.Unlock()
		saveStore()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	case "clear_passkey":
		store.mu.Lock()
		setModuleEnabled(existingUser, "passkey", "", false)
		store.mu.Unlock()
		saveStore()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	case "clear_pin":
		store.mu.Lock()
		setModuleEnabled(existingUser, "pin", "", false)
		store.mu.Unlock()
		saveStore()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	user := &User{
		Email:             email,
		AlertEmails:       alertEmails,
		PingFrequency:     pingFreq,
		CheckInHour:       checkInHourUTC,
		LastPing:          time.Now(),
		CurrentCycleStart: time.Time{},
		LastReminderNum:   0,
		Active:            true,
		Token:             generateToken(),
		AlertSent:         false,
		AlertMessage:      alertMessage,
		AllClearMessage:   allClearMessage,
		PausedUntil:       pausedUntil,
	}
	if existingUser != nil {
		user.SecurityModules = existingUser.SecurityModules
	}

	// PIN module: enable => require a non-empty PIN; disable => keep config,
	// simply flip it off.
	pinEnabled := r.FormValue("pin_enable") == "1"
	pinVal := strings.TrimSpace(r.FormValue("pin_pin"))
	duressVal := strings.TrimSpace(r.FormValue("pin_duress"))
	if pinEnabled {
		if pinVal == "" {
			http.Error(w, "Check-in PIN cannot be empty when enabled", http.StatusBadRequest)
			return
		}
		cfg, _ := json.Marshal(PINConfig{Pin: hashSecret(pinVal), Duress: hashSecret(duressVal)})
		setModuleEnabled(user, "pin", string(cfg), true)
	} else {
		old := getModuleConfig(user, "pin")
		setModuleEnabled(user, "pin", old, false)
	}

	// TOTP: enabling only sticks if a secret is already configured; otherwise
	// the user must go through the setup ceremony. Unchecking disables it.
	totpEnabled := r.FormValue("totp_enable") == "1"
	if totpEnabled {
		if sec := getModuleConfig(user, "totp"); sec != "" {
			setModuleEnabled(user, "totp", sec, true)
		}
	} else {
		setModuleEnabled(user, "totp", getModuleConfig(user, "totp"), false)
	}

	// Passkey: same pattern as TOTP.
	passkeyEnabled := r.FormValue("passkey_enable") == "1"
	if passkeyEnabled {
		if cred := getModuleConfig(user, "passkey"); cred != "" {
			setModuleEnabled(user, "passkey", cred, true)
		}
	} else {
		setModuleEnabled(user, "passkey", getModuleConfig(user, "passkey"), false)
	}

	store.mu.Lock()
	store.Users[email] = user
	store.mu.Unlock()
	saveStore()

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func testPingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	store.mu.RLock()
	session, exists := store.Sessions[cookie.Value]
	store.mu.RUnlock()

	if !exists || time.Now().After(session.ExpiresAt) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	email := session.Email

	store.mu.RLock()
	user := store.Users[email]
	store.mu.RUnlock()

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sendPing(user, 0)

	fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Test Ping Sent!</h1><p>Check your email at %s</p><p><a href='/settings'>Back to settings</a></p></body></html>", user.Email)
}

// ---------------------------------------------------------------------------
// Check-in flow (progressive security authentication)
// ---------------------------------------------------------------------------

func enabledModules(u *User) []string {
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

func findUserByToken(token string) *User {
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, u := range store.Users {
		if u.Token == token {
			return u
		}
	}
	return nil
}

func findUserByEmail(email string) *User {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.Users[email]
}

func getFlowByToken(token string) *CheckInFlow {
	checkInFlows.RLock()
	defer checkInFlows.RUnlock()
	return checkInFlows.m[token]
}

func getFlow(token, email, kind string) *CheckInFlow {
	checkInFlows.RLock()
	f, ok := checkInFlows.m[token]
	checkInFlows.RUnlock()
	if ok {
		return f
	}
	f = &CheckInFlow{
		Token:     token,
		Email:     email,
		Kind:      kind,
		Completed: map[string]bool{},
		StartedAt: time.Now(),
	}
	checkInFlows.Lock()
	checkInFlows.m[token] = f
	checkInFlows.Unlock()
	return f
}

func completeCheckIn(u *User, token string) {
	store.mu.Lock()
	u.LastPing = time.Now()
	u.LastReminderNum = 0
	wasAlerted := u.AlertSent
	u.AlertSent = false
	store.mu.Unlock()

	saveStore()

	checkInFlows.Lock()
	delete(checkInFlows.m, token)
	checkInFlows.Unlock()

	if wasAlerted {
		sendAllClearEmail(u)
	}
}

func confirmedPage() string {
	return "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Confirmed</h1><p>Thanks for checking in!</p></body></html>"
}

func pongHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	token := r.URL.Query().Get("token")
	u := findUserByToken(token)
	if u == nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	flow := getFlow(token, u.Email, "checkin")
	actionURL := "/pong?token=" + url.QueryEscape(token)

	if r.Method == "POST" {
		handleChallengeStep(w, r, u, flow, actionURL, func() {
			completeCheckIn(u, token)
			fmt.Fprint(w, confirmedPage())
		})
		return
	}

	if !renderChallengeStep(w, u, flow, actionURL) {
		completeCheckIn(u, token)
		fmt.Fprint(w, confirmedPage())
	}
}

// loginHandler gates access to /settings behind any enabled security modules.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	flow := getFlowByToken(token)
	if flow == nil || flow.Kind != "login" {
		http.Error(w, "Invalid or expired login session", http.StatusBadRequest)
		return
	}

	u := findUserByEmail(flow.Email)
	if u == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	actionURL := "/login?token=" + url.QueryEscape(token)

	if r.Method == "POST" {
		handleChallengeStep(w, r, u, flow, actionURL, func() {
			createSession(w, r, u.Email, token)
		})
		return
	}

	if !renderChallengeStep(w, u, flow, actionURL) {
		createSession(w, r, u.Email, token)
	}
}

// renderChallengeStep shows the next required step. Returns false if all
// enabled modules are satisfied.
func renderChallengeStep(w http.ResponseWriter, u *User, flow *CheckInFlow, actionURL string) bool {
	step := ""
	for _, m := range enabledModules(u) {
		if !flow.Completed[m] {
			step = m
			break
		}
	}
	if step == "" {
		return false
	}

	data := map[string]interface{}{
		"Token":   flow.Token,
		"Step":    step,
		"Action":  actionURL,
		"Version": VERSION,
		"Email":   u.Email,
	}

	switch step {
	case "pin":
		tmpl := template.Must(template.ParseFiles("templates/pong_pin.html"))
		tmpl.Execute(w, data)
	case "totp":
		tmpl := template.Must(template.ParseFiles("templates/pong_totp.html"))
		tmpl.Execute(w, data)
	case "passkey":
		tmpl := template.Must(template.ParseFiles("templates/pong_passkey.html"))
		tmpl.Execute(w, data)
	}
	return true
}

func handleChallengeStep(w http.ResponseWriter, r *http.Request, u *User, flow *CheckInFlow, actionURL string, onComplete func()) {
	step := r.FormValue("step")

	if step == "pin" {
		pin := r.FormValue("pin")
		var cfg PINConfig
		json.Unmarshal([]byte(moduleConfig(u, "pin")), &cfg)

		// Duress PIN: never a real success - silently alert.
		if cfg.Duress != "" && verifySecret(cfg.Duress, pin) {
			log.Printf("DURESS: User %s triggered duress PIN", u.Email)
			store.mu.Lock()
			u.AlertSent = true
			store.mu.Unlock()
			sendAlert(u)
			discardFlow(flow.Token)
			fmt.Fprint(w, confirmedPage())
			return
		}

		// PIN is a hard requirement when the module is enabled.
		if cfg.Pin == "" || !verifySecret(cfg.Pin, pin) {
			http.Error(w, "Invalid PIN", http.StatusUnauthorized)
			return
		}
		flow.Completed["pin"] = true
		http.Redirect(w, r, actionURL, http.StatusSeeOther)
		return
	}

	if step == "totp" {
		code := r.FormValue("code")
		var cfg TOTPConfig
		if json.Unmarshal([]byte(moduleConfig(u, "totp")), &cfg) != nil || cfg.Secret == "" || !totp.Validate(code, cfg.Secret) {
			http.Error(w, "Invalid code. Please try again.", http.StatusUnauthorized)
			return
		}
		flow.Completed["totp"] = true
		http.Redirect(w, r, actionURL, http.StatusSeeOther)
		return
	}

	http.Error(w, "Unknown step", http.StatusBadRequest)
}

func discardFlow(token string) {
	checkInFlows.Lock()
	delete(checkInFlows.m, token)
	checkInFlows.Unlock()
}

// createSession grants a settings session cookie. All enabled security
// modules must already have been satisfied before calling this.
func createSession(w http.ResponseWriter, r *http.Request, email, flowToken string) {
	discardFlow(flowToken)

	sessionToken := generateToken()
	store.mu.Lock()
	store.Sessions[sessionToken] = &Session{
		Email:     email,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	store.mu.Unlock()
	saveStore()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   1800,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// flowUser resolves the user for a passkey ceremony from its flow token.
func flowUser(token string) *User {
	flow := getFlowByToken(token)
	if flow == nil {
		return nil
	}
	return findUserByEmail(flow.Email)
}

func passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	u := flowUser(token)
	if u == nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}
	wu := wauserFor(u)
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
	token := r.URL.Query().Get("token")
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u := flowUser(token)
	if u == nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	waSessions.RLock()
	sessionData, ok := waSessions.m["login:"+token]
	waSessions.RUnlock()
	if !ok {
		http.Error(w, "No passkey session", http.StatusBadRequest)
		return
	}

	wu := wauserFor(u)
	_, err := webAuthn.FinishLogin(wu, *sessionData, r)
	if err != nil {
		http.Error(w, "Passkey verification failed", http.StatusUnauthorized)
		return
	}

	waSessions.Lock()
	delete(waSessions.m, "login:"+token)
	waSessions.Unlock()

	flow := getFlowByToken(token)
	flow.Completed["passkey"] = true
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "token": flow.Token})
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



// hashSecret returns "sha256$<salt>$<hash>" for a secret. Salt is per-user
// random, so identical PINs produce different stored values.
func hashSecret(secret string) string {
	if secret == "" {
		return ""
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	h := sha256.Sum256(append(salt, []byte(secret)...))
	return fmt.Sprintf("sha256$%s$%s", base64.RawStdEncoding.EncodeToString(salt), hex.EncodeToString(h[:]))
}

// verifySecret checks a candidate against a stored value. It supports the
// salted-hash format and, for backward compatibility, legacy plaintext.
func verifySecret(stored, candidate string) bool {
	if stored == "" {
		return false
	}
	parts := strings.Split(stored, "$")
	if len(parts) == 3 && parts[0] == "sha256" {
		salt, err := base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return false
		}
		h := sha256.Sum256(append(salt, []byte(candidate)...))
		return hex.EncodeToString(h[:]) == parts[2]
	}
	// legacy plaintext value
	return stored == candidate
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

func requireSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}
	store.mu.RLock()
	session, exists := store.Sessions[cookie.Value]
	store.mu.RUnlock()
	if !exists || time.Now().After(session.ExpiresAt) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return "", false
	}
	return session.Email, true
}

func requireUser(email string, w http.ResponseWriter) *User {
	store.mu.RLock()
	user := store.Users[email]
	store.mu.RUnlock()
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return nil
	}
	return user
}

func totpSetupHandler(w http.ResponseWriter, r *http.Request) {
	email, ok := requireSession(w, r)
	if !ok {
		return
	}
	if requireUser(email, w) == nil {
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
		"Version": VERSION,
	}
	tmpl := template.Must(template.ParseFiles("templates/totp_setup.html"))
	tmpl.Execute(w, data)
}

func totpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	email, ok := requireSession(w, r)
	if !ok {
		return
	}
	user := requireUser(email, w)
	if user == nil {
		return
	}

	secret := r.FormValue("secret")
	code := r.FormValue("code")
	if !totp.Validate(code, secret) {
		http.Error(w, "Invalid code. Please try again.", http.StatusBadRequest)
		return
	}

	cfg, _ := json.Marshal(TOTPConfig{Secret: secret})
	store.mu.Lock()
	setModuleEnabled(user, "totp", string(cfg), true)
	store.mu.Unlock()
	saveStore()

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	email, ok := requireSession(w, r)
	if !ok {
		return
	}
	user := requireUser(email, w)
	if user == nil {
		return
	}

	wu := wauserFor(user)
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
	email, ok := requireSession(w, r)
	if !ok {
		return
	}
	user := requireUser(email, w)
	if user == nil {
		return
	}

	waSessions.RLock()
	sessionData, exists := waSessions.m["register:"+email]
	waSessions.RUnlock()
	if !exists {
		http.Error(w, "No registration session", http.StatusBadRequest)
		return
	}

	wu := wauserFor(user)
	credential, err := webAuthn.FinishRegistration(wu, *sessionData, r)
	if err != nil {
		http.Error(w, "Registration failed", http.StatusBadRequest)
		return
	}

	waSessions.Lock()
	delete(waSessions.m, "register:"+email)
	waSessions.Unlock()

	encoded, err := marshalCredential(credential)
	if err != nil {
		http.Error(w, "Failed to store credential", http.StatusInternalServerError)
		return
	}
	cfg, _ := json.Marshal(PasskeyConfig{Credential: encoded})
	store.mu.Lock()
	setModuleEnabled(user, "passkey", string(cfg), true)
	store.mu.Unlock()
	saveStore()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Inbound email (reply PONG)
// ---------------------------------------------------------------------------

func inboundEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	expectedSecret := os.Getenv("INBOUND_SECRET")
	if expectedSecret == "" {
		log.Printf("INBOUND_SECRET not set!")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	providedSecret := r.URL.Query().Get("secret")
	if providedSecret != expectedSecret {
		log.Printf("Invalid inbound secret from IP: %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var inboundEmail struct {
		From      string `json:"From"`
		To        string `json:"To"`
		Subject   string `json:"Subject"`
		TextBody  string `json:"TextBody"`
		HtmlBody  string `json:"HtmlBody"`
		MessageID string `json:"MessageID"`
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&inboundEmail); err != nil {
		log.Printf("Error decoding inbound email: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	bodyText := strings.ToLower(inboundEmail.TextBody)
	if !strings.Contains(bodyText, "pong") {
		log.Printf("Email from %s doesn't contain PONG, ignoring", inboundEmail.From)
		w.WriteHeader(http.StatusOK)
		return
	}

	fromEmail := extractEmail(inboundEmail.From)
	if fromEmail == "" {
		log.Printf("Could not extract email from: %s", inboundEmail.From)
		w.WriteHeader(http.StatusOK)
		return
	}

	store.mu.Lock()
	user, exists := store.Users[fromEmail]
	var wasAlerted bool
	if exists {
		// With any security module enabled, a reply-PONG alone is not a valid
		// check-in - it would bypass PIN/TOTP/passkey. Ignore it.
		if len(enabledModules(user)) > 0 {
			store.mu.Unlock()
			log.Printf("PONG email reply ignored for %s: security modules enabled", user.Email)
			w.WriteHeader(http.StatusOK)
			return
		}
		wasAlerted = user.AlertSent
		user.LastPing = time.Now()
		user.LastReminderNum = 0
		user.AlertSent = false
	}
	store.mu.Unlock()

	if !exists {
		log.Printf("No user found for email: %s", fromEmail)
		w.WriteHeader(http.StatusOK)
		return
	}

	saveStore()

	if wasAlerted {
		sendAllClearEmail(user)
	}

	sendReplyEmail(fromEmail, inboundEmail.MessageID, inboundEmail.Subject, inboundEmail.TextBody)

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Emails
// ---------------------------------------------------------------------------

func sendPing(user *User, reminderNum int) {
	link := fmt.Sprintf("https://wellness-p.ing/pong?token=%s", user.Token)
	subject := "Wellness Ping"
	body := ""

	// Reply-PONG only works when no security modules are enabled; otherwise it
	// would bypass PIN/TOTP/passkey.
	replyHint := "\n\nOr reply PONG to this email."
	if len(enabledModules(user)) > 0 {
		replyHint = ""
	}

	if reminderNum == 0 {
		body = fmt.Sprintf("Hi! Just checking in.\n\nClick here to confirm you're okay: %s%s", link, replyHint)
	} else {
		var timeRemaining string
		if user.PingFrequency == "daily" {
			hoursLeft := 24 - (reminderNum * 6)
			timeRemaining = fmt.Sprintf("%d hours", hoursLeft)
		} else {
			daysLeft := 7 - reminderNum
			timeRemaining = fmt.Sprintf("%d days", daysLeft)
		}

		body = fmt.Sprintf("Reminder: You haven't checked in yet.\n\nYou have %s remaining before your contacts are notified.\n\nClick here to confirm you're okay: %s%s", timeRemaining, link, replyHint)
		subject = "Wellness Ping - Reminder"
	}

	sendEmail(user.Email, subject, body)
}

func sendAlert(user *User) {
	subject := fmt.Sprintf("Wellness Alert - %s Not Responding", user.Email)
	body := user.AlertMessage
	if body == "" {
		body = fmt.Sprintf("WARNING: %s hasn't responded to their wellness ping.\n\nPlease check in on them to ensure they're okay.", user.Email)
	}

	for _, alertContact := range user.AlertEmails {
		sendToContact(user, alertContact, subject, body)
	}
}

func sendAllClearEmail(user *User) {
	subject := fmt.Sprintf("All Clear - %s Checked In", user.Email)
	body := user.AllClearMessage
	if body == "" {
		body = fmt.Sprintf("Good news! %s has now checked in and confirmed they're okay.", user.Email)
	}

	for _, alertContact := range user.AlertEmails {
		sendToContact(user, alertContact, subject, body)
	}
}

// urlPattern matches http(s) URLs in the email body so they can be linked.
var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

// plainToHTML converts a plaintext body into an HTML body: it HTML-escapes
// the text (except URLs), turns any URL into a clickable link, and converts
// newlines to <br> so the link works in mail clients.
func plainToHTML(text string) string {
	var sb strings.Builder
	last := 0
	for _, m := range urlPattern.FindAllStringIndex(text, -1) {
		sb.WriteString(template.HTMLEscapeString(text[last:m[0]]))
		u := template.HTMLEscapeString(text[m[0]:m[1]])
		sb.WriteString(fmt.Sprintf(`<a href="%s">%s</a>`, u, u))
		last = m[1]
	}
	sb.WriteString(template.HTMLEscapeString(text[last:]))
	return strings.ReplaceAll(sb.String(), "\n", "<br>")
}

func sendEmail(to, subject, body string) {
	token := os.Getenv("POSTMARK_TOKEN")
	if token == "" {
		log.Printf("POSTMARK_TOKEN not set, would send email to %s with subject: %s and body: %s", to, subject, body)
		return
	}

	htmlBody := plainToHTML(body)

	payload := map[string]interface{}{
		"From":          "ping@wellness-p.ing",
		"To":            to,
		"Subject":       subject,
		"TextBody":      body,
		"HtmlBody":      htmlBody,
		"MessageStream": "outbound",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling email data: %v", err)
		return
	}

	req, err := http.NewRequest("POST", "https://api.postmarkapp.com/email", strings.NewReader(string(jsonData)))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending email to %s: %v", to, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Error sending email to %s: %d - %s", to, resp.StatusCode, string(bodyBytes))
		return
	}
}

func sendReplyEmail(to, inReplyTo, originalSubject, originalBody string) {
	token := os.Getenv("POSTMARK_TOKEN")
	if token == "" {
		log.Printf("POSTMARK_TOKEN not set, would send reply email to %s", to)
		return
	}

	subject := originalSubject
	if !strings.HasPrefix(strings.ToLower(subject), "re:") {
		subject = "Re: " + subject
	}

	quotedBody := strings.ReplaceAll(originalBody, "\n", "\n> ")
	body := fmt.Sprintf("Thanks for checking in! We received your PONG.\n\n> %s", quotedBody)
	htmlBody := fmt.Sprintf("Thanks for checking in! We received your PONG.<br><br><blockquote style='border-left: 2px solid #ccc; padding-left: 10px; color: #666;'>%s</blockquote>", strings.ReplaceAll(originalBody, "\n", "<br>"))

	payload := map[string]interface{}{
		"From":          "ping@wellness-p.ing",
		"To":            to,
		"Subject":       subject,
		"TextBody":      body,
		"HtmlBody":      htmlBody,
		"MessageStream": "outbound",
	}

	if inReplyTo != "" {
		payload["Headers"] = []map[string]string{
			{
				"Name":  "In-Reply-To",
				"Value": inReplyTo,
			},
			{
				"Name":  "References",
				"Value": inReplyTo,
			},
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling email data: %v", err)
		return
	}

	req, err := http.NewRequest("POST", "https://api.postmarkapp.com/email", strings.NewReader(string(jsonData)))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending reply email to %s: %v", to, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Error sending reply email to %s: %d - %s", to, resp.StatusCode, string(bodyBytes))
		return
	}
}

func extractEmail(from string) string {
	from = strings.TrimSpace(strings.ToLower(from))

	if strings.Contains(from, "<") && strings.Contains(from, ">") {
		start := strings.Index(from, "<")
		end := strings.Index(from, ">")
		if start != -1 && end != -1 && end > start {
			return from[start+1 : end]
		}
	}

	return from
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

// signalUsernameRe matches a Signal username (base chars + .## discriminator).
var signalUsernameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}\.[0-9]{2}$`)

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
	out, err := exec.CommandContext(ctx, bin, "--output=json", "listAccounts").Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			signal.Message = fmt.Sprintf("signal-cli found (%s) but listAccounts timed out after 60s and was killed - is signal-cli responsive? Signal NOT working; falling back to email", bin)
		} else {
			signal.Message = fmt.Sprintf("signal-cli found (%s) but listAccounts failed: %v - Signal NOT working; falling back to email", bin, err)
		}
		log.Printf("WARNING: %s", signal.Message)
		return
	}

	if strings.TrimSpace(string(out)) == "" || !strings.Contains(string(out), signal.Account) {
		// No accounts, or the configured account isn't among them.
		signal.Message = fmt.Sprintf("signal-cli found (%s) but account %s is not registered (listAccounts). Signal NOT working; falling back to email", bin, signal.Account)
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
func classifyContact(raw string) (kind, canonical string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if strings.Contains(s, "@") {
		return "email", strings.ToLower(s)
	}
	if signalUsernameRe.MatchString(s) {
		return "signal", strings.ToLower(s)
	}
	// Otherwise treat as a phone number, stripping non-digits.
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	if strings.HasPrefix(s, "+") {
		return "phone", "+" + digits
	}
	if strings.HasPrefix(s, "00") {
		return "phone", "+" + digits[2:]
	}
	return "phone", "+1" + digits
}

// signalSendRaw delivers a message to a direct recipient argument: a Signal
// username (u:...), an E.164 phone number, or a resolved ACI UUID.
func signalSendRaw(recArg, body string) error {
	if !signal.Ready {
		return fmt.Errorf("Signal is not ready")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, signal.Binary, "-a", signal.Account, "send", "--message-from-stdin", recArg)
	cmd.Stdin = strings.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("signal-cli send failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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
func resolveSignalUUID(contact string) (string, bool) {
	if !signal.Ready {
		return "", false
	}
	kind, canon := classifyContact(contact)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var args []string
	args = append(args, "-a", signal.Account, "--output=json", "getUserStatus")
	if kind == "signal" {
		args = append(args, "--username", "u:"+canon)
	} else if kind == "phone" {
		args = append(args, canon)
	} else {
		return "", false
	}

	out, err := exec.CommandContext(ctx, signal.Binary, args...).Output()
	if err != nil {
		return "", false
	}

	var list []struct {
		UUID       string `json:"uuid"`
		Registered bool   `json:"isRegistered"`
	}
	if json.Unmarshal(out, &list) != nil {
		return "", false
	}
	for _, u := range list {
		if u.UUID != "" && u.Registered {
			return u.UUID, true
		}
	}
	return "", false
}

// firstContact tracks which Signal recipients we have already messaged, so the
// "confirm it matches" notice is only sent once per contact.
var firstContact = struct {
	sync.Mutex
	m map[string]bool
}{m: map[string]bool{}}

// signalFirstContactNotice returns a verification notice the first time we
// message a given Signal recipient, or "" for established contacts.
func signalFirstContactNotice(to string) string {
	firstContact.Lock()
	defer firstContact.Unlock()
	if firstContact.m[to] {
		return ""
	}
	firstContact.m[to] = true
	return fmt.Sprintf("This message is from the official Wellness Ping Signal account (username: %s).\n\nIf this account does not match the one you expected, do NOT share any personal or location details, and let us know. Please confirm this matches before sharing anything sensitive.\n\n---\n\n", OfficialSignalUsername)
}

// sendToContact dispatches a notification to a single contact by its best
// channel: email for email addresses, Signal for usernames/phone numbers.
// The contact's ACI UUID is resolved and cached on first use so a later
// username change doesn't break delivery.
func sendToContact(user *User, contact, subject, body string) {
	kind, _ := classifyContact(contact)
	if kind != "signal" && kind != "phone" {
		sendEmail(contact, subject, body)
		return
	}

	msg := subject + "\n\n" + body
	msg = signalFirstContactNotice(contact) + msg

	// Prefer a cached UUID if we already resolved one.
	uuid := ""
	if user != nil && user.SignalUUIDs != nil {
		uuid = user.SignalUUIDs[contact]
	}
	if uuid == "" {
		if u, ok := resolveSignalUUID(contact); ok {
			uuid = u
			if user != nil {
				if user.SignalUUIDs == nil {
					user.SignalUUIDs = map[string]string{}
				}
				user.SignalUUIDs[contact] = u
				saveStore()
			}
		}
	}

	if err := signalSendRaw(signalSendTarget(contact, uuid), msg); err != nil {
		log.Printf("WARNING: could not alert %s via Signal: %v", contact, err)
	}
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
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func loadStore() {
	data, err := os.ReadFile("data/users.json")
	if err != nil {
		os.MkdirAll("data", 0755)
		return
	}
	json.Unmarshal(data, &store)

	if store.Sessions == nil {
		store.Sessions = make(map[string]*Session)
	}
	if store.Users == nil {
		store.Users = make(map[string]*User)
	}
	if store.PendingVerifications == nil {
		store.PendingVerifications = make(map[string]*PendingVerification)
	}
}

func saveStore() {
	store.mu.Lock()
	defer store.mu.Unlock()

	log.Printf("Saving store with %d users (DATE: %s)", len(store.Users), time.Now().Format(time.RFC3339))

	data, _ := json.MarshalIndent(store, "", "  ")
	os.WriteFile("data/users.json", data, 0644)
}

func verifyTurnstile(token string) bool {
	secret := os.Getenv("TURNSTILE_SECRET_KEY")
	if secret == "" {
		log.Println("TURNSTILE_SECRET_KEY not set, accepting signup (WARNING: production should use Turnstile)")
		return true
	}
	if token == "" {
		return false
	}

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)

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

func pingScheduler() {
	ticker := time.NewTicker(1 * time.Minute)

	for range ticker.C {
		now := time.Now()

		// Clean up expired sessions
		store.mu.Lock()
		for token, session := range store.Sessions {
			if time.Now().After(session.ExpiresAt) {
				delete(store.Sessions, token)
			}
		}
		store.mu.Unlock()

		store.mu.RLock()
		users := make([]*User, 0, len(store.Users))
		for _, u := range store.Users {
			users = append(users, u)
		}
		store.mu.RUnlock()

		needsSave := false

		for _, user := range users {
			if !user.Active {
				continue
			}

			// Skip if user is paused (vacation/travel mode)
			if user.PausedUntil != nil && time.Now().Before(*user.PausedUntil) {
				continue
			}
			if user.PausedUntil != nil && time.Now().After(*user.PausedUntil) {
				user.PausedUntil = nil
				log.Printf("Auto-resuming user %s after vacation pause", user.Email)
				needsSave = true
			}

			var pingInterval time.Duration
			var reminderInterval time.Duration

			if user.PingFrequency == "daily" {
				pingInterval = 24 * time.Hour
				reminderInterval = 6 * time.Hour
			} else {
				pingInterval = 7 * 24 * time.Hour
				reminderInterval = 24 * time.Hour
			}

			cycleComplete := user.CurrentCycleStart.IsZero() || user.LastPing.After(user.CurrentCycleStart)

			if cycleComplete && now.Hour() == user.CheckInHour && now.Minute() < 5 {
				if user.PingFrequency == "daily" {
					lastResponseDate := user.LastPing.Truncate(24 * time.Hour)
					todayDate := now.Truncate(24 * time.Hour)

					if todayDate.After(lastResponseDate) {
						store.mu.Lock()
						user.CurrentCycleStart = time.Now()
						user.LastReminderNum = 0
						user.AlertSent = false
						user.Token = generateToken()
						store.mu.Unlock()
						log.Printf("Starting new DAILY cycle for %s", user.Email)
						sendPing(user, 0)
						needsSave = true
						continue
					}
				} else {
					if user.CurrentCycleStart.IsZero() {
						store.mu.Lock()
						user.CurrentCycleStart = time.Now()
						user.LastReminderNum = 0
						user.AlertSent = false
						user.Token = generateToken()
						store.mu.Unlock()
						log.Printf("Starting FIRST weekly cycle for %s", user.Email)
						sendPing(user, 0)
						needsSave = true
						continue
					}
					if time.Since(user.LastPing) >= pingInterval {
						store.mu.Lock()
						user.CurrentCycleStart = time.Now()
						user.LastReminderNum = 0
						user.AlertSent = false
						user.Token = generateToken()
						store.mu.Unlock()
						log.Printf("Starting new WEEKLY cycle for %s", user.Email)
						sendPing(user, 0)
						needsSave = true
						continue
					}
				}
			}

			if !user.CurrentCycleStart.IsZero() && user.LastPing.Before(user.CurrentCycleStart) {
				timeSinceCycleStart := time.Since(user.CurrentCycleStart)

				if timeSinceCycleStart < pingInterval {
					expectedReminderNum := int(timeSinceCycleStart / reminderInterval)

					maxReminders := 3
					if user.PingFrequency == "weekly" {
						maxReminders = 6
					}

					if expectedReminderNum > 0 && expectedReminderNum > user.LastReminderNum && expectedReminderNum <= maxReminders {
						store.mu.Lock()
						user.LastReminderNum = expectedReminderNum
						store.mu.Unlock()
						log.Printf("Sending reminder #%d to %s", expectedReminderNum, user.Email)
						sendPing(user, expectedReminderNum)
						needsSave = true
					}
				}

				if timeSinceCycleStart >= pingInterval && !user.AlertSent {
					store.mu.Lock()
					user.AlertSent = true
					store.mu.Unlock()
					log.Printf("ALERT: Sending emergency alert for %s", user.Email)
					sendAlert(user)
					needsSave = true
				}
			}
		}

		if needsSave {
			saveStore()
		}
	}
}
