package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetSignup(t *testing.T) {
	t.Helper()
	pendingSignups.Lock()
	pendingSignups.m = map[string]*PendingSignup{}
	pendingSignups.Unlock()
	dmSeen.Lock()
	dmSeen.m = map[string]time.Time{}
	dmSeen.Unlock()
	store.mu.Lock()
	store.PendingVerifications = map[string]*PendingVerification{}
	store.mu.Unlock()
	dmLimiter.hit = map[string][]time.Time{}
}

// The sender fields are nested under "envelope". Parsing them from the top
// level yields empty strings, so no DM would ever be recognised.
func TestReceiveLineParsesEnvelope(t *testing.T) {
	line := `{"envelope":{"source":"+14155551234","sourceNumber":"+14155551234",` +
		`"sourceUuid":"2e74f392-7e87-42fa-ab3f-795dd906c8ce","sourceName":"A",` +
		`"dataMessage":{"message":"hi"}},"account":"+61478786427"}`
	var rl signalReceiveLine
	if err := json.Unmarshal([]byte(line), &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Envelope.SourceNumber != "+14155551234" {
		t.Fatalf("sourceNumber not parsed, got %q", rl.Envelope.SourceNumber)
	}
	if rl.Envelope.SourceUuid == "" {
		t.Fatal("sourceUuid not parsed")
	}
}

// Two people signing up at once must both be recognised. Under the old design
// whichever one polled first drained and discarded the other's message.
func TestConcurrentSignupsBothRecognised(t *testing.T) {
	resetSignup(t)

	for _, u := range []string{"+14155551111", "+14155552222"} {
		pendingSignups.Lock()
		pendingSignups.m[u] = &PendingSignup{Canonical: u, Kind: "phone", Code: "12345678", CreatedAt: time.Now()}
		pendingSignups.Unlock()
		noteDM("num:" + u) // both DMs observed by the single reader
	}

	press := func(id string) int {
		rec := httptest.NewRecorder()
		body := url.Values{"identifier": {id}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/dm-continue", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		dmContinueHandler(rec, req)
		return rec.Code
	}

	for _, u := range []string{"+14155551111", "+14155552222"} {
		if code := press(u); code != http.StatusOK {
			t.Fatalf("%s got %d, want 200", u, code)
		}
		store.mu.RLock()
		_, staged := store.PendingVerifications[u]
		store.mu.RUnlock()
		if !staged {
			t.Fatalf("%s: no verification code was staged", u)
		}
	}
}

// A user who has not DM'd must not be let through.
func TestDMContinueRequiresAnActualMessage(t *testing.T) {
	resetSignup(t)
	pendingSignups.Lock()
	pendingSignups.m["+14155553333"] = &PendingSignup{Canonical: "+14155553333", Kind: "phone", Code: "1", CreatedAt: time.Now()}
	pendingSignups.Unlock()

	rec := httptest.NewRecorder()
	body := url.Values{"identifier": {"+14155553333"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/dm-continue", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dmContinueHandler(rec, req)

	store.mu.RLock()
	_, staged := store.PendingVerifications["+14155553333"]
	store.mu.RUnlock()
	if staged {
		t.Fatal("a code was staged without any DM having been received")
	}
	if !strings.Contains(rec.Body.String(), "seen your message yet") {
		t.Fatal("expected the try-again page")
	}
}

// Hammering the button must not send a pile of codes.
func TestDMContinueDoubleClickSendsOneCode(t *testing.T) {
	resetSignup(t)
	pendingSignups.Lock()
	pendingSignups.m["+14155554444"] = &PendingSignup{Canonical: "+14155554444", Kind: "phone", Code: "1", CreatedAt: time.Now()}
	pendingSignups.Unlock()
	noteDM("num:+14155554444")

	var wg sync.WaitGroup
	claimed := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			body := url.Values{"identifier": {"+14155554444"}}.Encode()
			req := httptest.NewRequest(http.MethodPost, "/dm-continue", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			_ = rec
			_ = req
			if _, status := claimSignupCode("+14155554444"); status == "ok" {
				mu.Lock()
				claimed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claimed > 1 {
		t.Fatalf("%d concurrent clicks each sent a code; want at most 1", claimed)
	}
}

func TestDMContinueIsRateLimited(t *testing.T) {
	resetSignup(t)
	blocked := false
	for i := 0; i < dmContinueLimit+5; i++ {
		rec := httptest.NewRecorder()
		body := url.Values{"identifier": {"+14155555555"}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/dm-continue", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		dmContinueHandler(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("/dm-continue never rate limited; each request used to spawn a signal-cli process")
	}
}

func TestExpiredSignupIsSweptAndRejected(t *testing.T) {
	resetSignup(t)
	pendingSignups.Lock()
	pendingSignups.m["+14155556666"] = &PendingSignup{
		Canonical: "+14155556666", Kind: "phone", Code: "1",
		CreatedAt: time.Now().Add(-2 * signupTTL),
	}
	pendingSignups.Unlock()
	noteDM("num:+14155556666")

	rec := httptest.NewRecorder()
	body := url.Values{"identifier": {"+14155556666"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/dm-continue", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dmContinueHandler(rec, req)

	store.mu.RLock()
	_, staged := store.PendingVerifications["+14155556666"]
	store.mu.RUnlock()
	if staged {
		t.Fatal("an expired signup was honoured")
	}

	sweepPendingSignups()
	pendingSignups.RLock()
	n := len(pendingSignups.m)
	pendingSignups.RUnlock()
	if n != 0 {
		t.Fatalf("sweep left %d expired signups behind", n)
	}
}

func TestDMSeenExpires(t *testing.T) {
	resetSignup(t)
	dmSeen.Lock()
	dmSeen.m["num:+1"] = time.Now().Add(-2 * dmSeenTTL)
	dmSeen.Unlock()
	if sawDM("num:+1") {
		t.Fatal("a stale DM still counted")
	}
	sweepDMSeen()
	dmSeen.RLock()
	n := len(dmSeen.m)
	dmSeen.RUnlock()
	if n != 0 {
		t.Fatalf("sweep left %d stale entries", n)
	}
}
