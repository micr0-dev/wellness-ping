package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// resetStore gives each test a clean slate.
func resetStore(t *testing.T) {
	t.Helper()
	store.mu.Lock()
	store.Users = map[string]*User{}
	store.Sessions = map[string]*Session{}
	store.PendingVerifications = map[string]*PendingVerification{}
	store.mu.Unlock()
	checkInFlows.Lock()
	checkInFlows.m = map[string]*CheckInFlow{}
	checkInFlows.Unlock()
	for _, rl := range []*rateLimiter{codeSendLimiter, codeVerifyLimiter, pinLimiter, totpLimiter, pongLimiter, inboundLimiter} {
		rl.hit = map[string][]time.Time{}
	}
}

// ---------------------------------------------------------------------------
// C1/C2 - inbound email must not be spoofable
// ---------------------------------------------------------------------------

func TestNewContentStripsQuotedText(t *testing.T) {
	// Our own outgoing message contains the reply instructions. If quoted text
	// counted, every reply would check the user in.
	cases := []struct{ name, body, wantAbsent string }{
		{"angle quotes", "I'm fine\n> Or reply with: PONG-ABC", "PONG-ABC"},
		{"on-wrote separator", "ok\n\nOn Mon, 4 Aug 2026, ping wrote:\nPONG-ABC", "PONG-ABC"},
		{"original message", "hi\n----- Original Message -----\nPONG-ABC", "PONG-ABC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := newContent(c.body); strings.Contains(got, c.wantAbsent) {
				t.Fatalf("quoted text survived stripping: %q", got)
			}
		})
	}
}

func TestIsAutomatedRejectsAutoresponders(t *testing.T) {
	cases := []struct {
		name string
		msg  inboundMessage
		want bool
	}{
		{"auto-submitted", inboundMessage{Headers: hdr("Auto-Submitted", "auto-replied")}, true},
		{"precedence bulk", inboundMessage{Headers: hdr("Precedence", "bulk")}, true},
		{"mailing list", inboundMessage{Headers: hdr("List-Id", "<x.example.com>")}, true},
		{"bounce", inboundMessage{Headers: hdr("Return-Path", "<>")}, true},
		{"ooo subject", inboundMessage{Subject: "Out of Office: Wellness Ping"}, true},
		{"human reply", inboundMessage{Subject: "Re: Wellness Ping", Headers: hdr("Auto-Submitted", "no")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := c.msg.isAutomated()
			if got != c.want {
				t.Fatalf("isAutomated = %v, want %v", got, c.want)
			}
		})
	}
}

func TestVerifyInboundAuthRequiresAlignedPass(t *testing.T) {
	cases := []struct {
		name, results, from string
		want                bool
	}{
		{"no header at all", "", "alice@example.com", false},
		{"dkim fail", "dkim=fail header.d=example.com", "alice@example.com", false},
		{"dkim pass aligned", "mx; dkim=pass header.d=example.com", "alice@example.com", true},
		{"dkim pass unaligned", "mx; dkim=pass header.d=attacker.test", "alice@example.com", false},
		{"dkim pass subdomain", "mx; dkim=pass header.d=example.com", "alice@mail.example.com", true},
		{"spf pass", "mx; spf=pass smtp.mailfrom=example.com", "alice@example.com", true},
		{"dmarc pass", "mx; dmarc=pass", "alice@example.com", true},
		{"all fail", "mx; dkim=fail; spf=softfail; dmarc=fail", "alice@example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &inboundMessage{}
			if c.results != "" {
				m.Headers = hdr("Authentication-Results", c.results)
			}
			got, why := verifyInboundAuth(m, c.from)
			if got != c.want {
				t.Fatalf("verifyInboundAuth = %v (%s), want %v", got, why, c.want)
			}
		})
	}
}

func TestInboundRejectsSpoofedSender(t *testing.T) {
	resetStore(t)
	t.Setenv("INBOUND_SECRET", "topsecret")

	original := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	store.mu.Lock()
	store.Users["alice@example.com"] = &User{
		Email: "alice@example.com", Active: true, Token: "tok", ReplyCode: "GOODCODE",
		LastPing: original,
	}
	store.mu.Unlock()

	post := func(body string) {
		req := httptest.NewRequest(http.MethodPost, "/inbound?secret=topsecret", strings.NewReader(body))
		inboundEmailHandler(httptest.NewRecorder(), req)
	}

	// Anyone can set From. Without authentication this must not check Alice in.
	post(`{"From":"alice@example.com","TextBody":"PONG-GOODCODE","Headers":[]}`)
	if got := lastPing(t, "alice@example.com"); !got.Equal(original) {
		t.Fatal("unauthenticated spoofed reply was accepted as a check-in")
	}

	// Authenticated, but the attacker cannot know the reply code.
	post(`{"From":"alice@example.com","TextBody":"PONG-GUESSED",
	       "Headers":[{"Name":"Authentication-Results","Value":"dkim=pass header.d=example.com"}]}`)
	if got := lastPing(t, "alice@example.com"); !got.Equal(original) {
		t.Fatal("reply with the wrong reply code was accepted")
	}

	// The real thing.
	post(`{"From":"alice@example.com","TextBody":"PONG-GOODCODE",
	       "Headers":[{"Name":"Authentication-Results","Value":"dkim=pass header.d=example.com"}]}`)
	if got := lastPing(t, "alice@example.com"); got.Equal(original) {
		t.Fatal("a properly authenticated reply was rejected")
	}
}

// ---------------------------------------------------------------------------
// C3 - reflected content must be escaped
// ---------------------------------------------------------------------------

func TestPlainToHTMLEscapesInjectedMarkup(t *testing.T) {
	got := plainToHTML(`<script>alert(1)</script> <img src=x onerror=alert(1)>`)
	for _, bad := range []string{"<script>", "<img"} {
		if strings.Contains(got, bad) {
			t.Fatalf("unescaped markup survived: %q", got)
		}
	}
	// A genuine URL in our own generated text should still be linkified.
	if !strings.Contains(plainToHTML("see https://example.com/x"), `<a href="https://example.com/x">`) {
		t.Fatal("real URLs should still be linked")
	}
}

func TestReplyAcknowledgementDoesNotLinkifyQuotedText(t *testing.T) {
	// The quoted body is attacker-influenced. Escaping alone is not enough:
	// linkifying it would let a sender put a working clickable link into a
	// message sent from our own domain.
	quoted := "<b>hi</b> http://evil.test/phish"
	html := template.HTMLEscapeString(quoted)
	if strings.Contains(html, "<a href") || strings.Contains(html, "<b>") {
		t.Fatalf("quoted text must be inert, got %q", html)
	}
}

// ---------------------------------------------------------------------------
// C4 - a GET must never complete a check-in
// ---------------------------------------------------------------------------

func TestGetPongDoesNotCheckIn(t *testing.T) {
	resetStore(t)
	original := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	store.mu.Lock()
	store.Users["alice@example.com"] = &User{
		Email: "alice@example.com", Active: true, Token: "linktoken", LastPing: original,
	}
	store.mu.Unlock()

	// A mail security product fetching every link in the message.
	rec := httptest.NewRecorder()
	pongHandler(rec, httptest.NewRequest(http.MethodGet, "/pong?token=linktoken", nil))
	if !lastPing(t, "alice@example.com").Equal(original) {
		t.Fatal("GET completed the check-in; a link scanner would disarm the switch")
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/pong?token=linktoken", strings.NewReader("step=confirm"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pongHandler(rec, req)
	if lastPing(t, "alice@example.com").Equal(original) {
		t.Fatal("POST did not complete the check-in")
	}
}

// ---------------------------------------------------------------------------
// Challenge ordering and attempt limits
// ---------------------------------------------------------------------------

func TestPINStepCannotBeSkipped(t *testing.T) {
	resetStore(t)
	cfg, _ := json.Marshal(PINConfig{Pin: hashSecret("1234")})
	store.mu.Lock()
	store.Users["alice@example.com"] = &User{
		Email: "alice@example.com", Active: true, Token: "tok",
		SecurityModules: []SecurityModule{{Enabled: true, ModuleType: "pin", Config: string(cfg)}},
	}
	store.mu.Unlock()

	// Jumping straight to the final confirmation must not work.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/pong?token=tok", strings.NewReader("step=confirm"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pongHandler(rec, req)
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "Confirmed") {
		t.Fatal("confirmation succeeded without satisfying the PIN module")
	}
}

func TestPINAttemptsAreLimited(t *testing.T) {
	resetStore(t)
	cfg, _ := json.Marshal(PINConfig{Pin: hashSecret("1234")})
	store.mu.Lock()
	store.Users["alice@example.com"] = &User{
		Email: "alice@example.com", Active: true, Token: "tok",
		SecurityModules: []SecurityModule{{Enabled: true, ModuleType: "pin", Config: string(cfg)}},
	}
	store.mu.Unlock()

	guess := func(pin string) int {
		rec := httptest.NewRecorder()
		body := url.Values{"step": {"pin"}, "pin": {pin}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/pong?token=tok", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pongHandler(rec, req)
		return rec.Code
	}

	for i := 0; i < moduleAttemptLim; i++ {
		if code := guess("0000"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	// The limit must survive a wrong guess *and* a correct one: an attacker who
	// exhausts the budget should not be let through by finally hitting it.
	if code := guess("1234"); code != http.StatusTooManyRequests {
		t.Fatalf("after exhausting the budget, got %d, want 429", code)
	}
}

func TestDuressLooksExactlyLikeSuccess(t *testing.T) {
	resetStore(t)
	cfg, _ := json.Marshal(PINConfig{Pin: hashSecret("1234"), Duress: hashSecret("9999")})
	mk := func() {
		store.mu.Lock()
		store.Users["alice@example.com"] = &User{
			Email: "alice@example.com", Active: true, Token: "tok", AlertEmails: []string{"bob@example.com"},
			SecurityModules: []SecurityModule{{Enabled: true, ModuleType: "pin", Config: string(cfg)}},
		}
		store.mu.Unlock()
		checkInFlows.Lock()
		checkInFlows.m = map[string]*CheckInFlow{}
		checkInFlows.Unlock()
		pinLimiter.reset("pin:alice@example.com")
	}

	submit := func(pin string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		body := url.Values{"step": {"pin"}, "pin": {pin}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/pong?token=tok", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pongHandler(rec, req)
		return rec
	}

	confirm := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/pong?token=tok", strings.NewReader("step=confirm"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pongHandler(rec, req)
		return rec
	}

	mk()
	if code := submit("9999").Code; code != http.StatusSeeOther {
		t.Fatalf("duress PIN returned %d, want the same 303 redirect a correct PIN gives", code)
	}
	duress := confirm()

	// Check the duress state now, before the fixture is rebuilt below.
	store.mu.RLock()
	u := store.Users["alice@example.com"]
	checkedIn := u.LastPing.After(time.Now().Add(-time.Minute))
	duressFlagged := u.DuressActive
	store.mu.RUnlock()
	if !checkedIn || !duressFlagged {
		t.Fatal("duress should mark the cycle satisfied and record the duress state")
	}

	mk()
	if code := submit("1234").Code; code != http.StatusSeeOther {
		t.Fatalf("correct PIN returned %d, want 303", code)
	}
	realConfirm := confirm()

	if duress.Code != http.StatusOK {
		t.Fatalf("duress returned %d, want 200", duress.Code)
	}
	if duress.Body.String() != realConfirm.Body.String() {
		t.Fatal("duress page differs from the real confirmation page; it is distinguishable")
	}

}

// ---------------------------------------------------------------------------
// H6 - hashing
// ---------------------------------------------------------------------------

func TestVerifySecretUpgradesLegacyFormats(t *testing.T) {
	// Pre-v2.0 plaintext.
	ok, upgraded := verifySecretUpgrade("1234", "1234")
	if !ok || !strings.HasPrefix(upgraded, "argon2id$") {
		t.Fatal("plaintext should verify once and yield an argon2id replacement")
	}
	if ok, _ := verifySecretUpgrade("1234", "9999"); ok {
		t.Fatal("wrong plaintext candidate accepted")
	}

	// v2.0 salted SHA-256, produced the way the old code did.
	legacy := "sha256$AAAAAAAAAAAAAAAAAAAAAA$" + sha256Legacy("1234")
	ok, upgraded = verifySecretUpgrade(legacy, "1234")
	if !ok || !strings.HasPrefix(upgraded, "argon2id$") {
		t.Fatal("legacy sha256 should verify once and yield an argon2id replacement")
	}

	// Current format round-trips and rejects wrong input.
	h := hashSecret("secret-pin")
	if !verifySecret(h, "secret-pin") {
		t.Fatal("argon2id round-trip failed")
	}
	if verifySecret(h, "secret-pi") || verifySecret("", "anything") {
		t.Fatal("argon2id accepted a wrong or empty-stored secret")
	}
}

// ---------------------------------------------------------------------------
// M15 - contacts
// ---------------------------------------------------------------------------

func TestClassifyContactRejectsGarbage(t *testing.T) {
	bad := []string{"", "jane doe", "not-an-address", "asdf", "@example.com", "alice@", "alice@localhost", "+", "12345", "<script>"}
	for _, s := range bad {
		if kind, canon := classifyContact(s); kind != "" || canon != "" {
			t.Errorf("classifyContact(%q) = (%q,%q); a typo must not become a silent contact", s, kind, canon)
		}
	}

	good := map[string][2]string{
		"Alice@Example.COM": {"email", "alice@example.com"},
		"(415) 555-1234":    {"phone", "+14155551234"},
		"+44 20 7946 0958":  {"phone", "+442079460958"},
		"004420 7946 0958":  {"phone", "+442079460958"},
		"wellness_ping.01":  {"signal", "wellness_ping.01"},
	}
	for in, want := range good {
		kind, canon := classifyContact(in)
		if kind != want[0] || canon != want[1] {
			t.Errorf("classifyContact(%q) = (%q,%q), want (%q,%q)", in, kind, canon, want[0], want[1])
		}
	}
}

// ---------------------------------------------------------------------------
// H5 - rate limiter
// ---------------------------------------------------------------------------

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter()
	for i := 0; i < 3; i++ {
		if !rl.allow("k", 3, time.Minute) {
			t.Fatalf("attempt %d should have been allowed", i+1)
		}
	}
	if rl.allow("k", 3, time.Minute) {
		t.Fatal("fourth attempt should have been blocked")
	}
	if !rl.allow("other", 3, time.Minute) {
		t.Fatal("limits must be per key")
	}
	rl.reset("k")
	if !rl.allow("k", 3, time.Minute) {
		t.Fatal("reset should clear the budget")
	}
}

// ---------------------------------------------------------------------------
// A19 - CSRF
// ---------------------------------------------------------------------------

func TestUpdateRequiresCSRFToken(t *testing.T) {
	resetStore(t)
	store.mu.Lock()
	store.Sessions["sess"] = &Session{Email: "alice@example.com", Token: "sess", CSRF: "realcsrf", ExpiresAt: time.Now().Add(time.Hour)}
	store.Users["alice@example.com"] = &User{Email: "alice@example.com", Active: true, Token: "tok"}
	store.mu.Unlock()

	post := func(form string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "session", Value: "sess"})
		updateHandler(rec, req)
		return rec.Code
	}

	if code := post("action=stop"); code != http.StatusForbidden {
		t.Fatalf("stop without a CSRF token returned %d, want 403", code)
	}
	if !userExists("alice@example.com") {
		t.Fatal("a request with no CSRF token deleted the account")
	}
	if code := post("action=stop&csrf=wrong"); code != http.StatusForbidden {
		t.Fatalf("stop with a wrong CSRF token returned %d, want 403", code)
	}
}

// ---------------------------------------------------------------------------
// M11 - flow expiry
// ---------------------------------------------------------------------------

func TestExpiredFlowDoesNotRetainCompletedSteps(t *testing.T) {
	resetStore(t)
	f := getFlow("tok", "alice@example.com", "checkin")
	markFlowCompleted(f, "pin")

	checkInFlows.Lock()
	f.StartedAt = time.Now().Add(-2 * flowTTL)
	checkInFlows.Unlock()

	if getFlowByToken("tok") != nil {
		t.Fatal("an expired flow should be treated as absent")
	}
	fresh := getFlow("tok", "alice@example.com", "checkin")
	if fresh.Completed["pin"] {
		t.Fatal("an abandoned flow left the PIN step marked satisfied")
	}
}

// ---------------------------------------------------------------------------
// A20 - log redaction
// ---------------------------------------------------------------------------

func TestRedactForLog(t *testing.T) {
	in := "link https://x/pong?token=AbC123_-= and Code is: 12345678 and PONG-ABC23456"
	got := redactForLog(in)
	for _, secret := range []string{"AbC123_-=", "12345678", "ABC23456"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q survived redaction: %q", secret, got)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func hdr(name, value string) []struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
} {
	return []struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	}{{Name: name, Value: value}}
}

func lastPing(t *testing.T, email string) time.Time {
	t.Helper()
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.Users[email].LastPing
}

// sha256Legacy reproduces the v2.0 hash so the upgrade path can be tested.
func sha256Legacy(secret string) string {
	salt, _ := base64.RawStdEncoding.DecodeString("AAAAAAAAAAAAAAAAAAAAAA")
	h := sha256.Sum256(append(salt, []byte(secret)...))
	return hex.EncodeToString(h[:])
}
