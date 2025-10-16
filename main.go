package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const VERSION = "1.0.2"

type User struct {
	Email             string    `json:"email"`
	AlertEmails       []string  `json:"alert_emails"`
	PingFrequency     string    `json:"ping_frequency"`
	CheckInHour       int       `json:"checkin_hour"`
	LastPing          time.Time `json:"last_ping"`
	CurrentCycleStart time.Time `json:"current_cycle_start"`
	LastReminderNum   int       `json:"last_reminder_num"`
	Active            bool      `json:"active"`
	Token             string    `json:"token"`
	AlertSent         bool      `json:"alert_sent"`
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

func main() {
	if os.Getenv("POSTMARK_TOKEN") == "" {
		log.Println("Warning: POSTMARK_TOKEN not set. Emails will not be sent.")
	}

	if os.Getenv("INBOUND_SECRET") == "" {
		log.Println("Warning: INBOUND_SECRET not set. Inbound email verification will not work.")
	}

	loadStore()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/send-code", sendCodeHandler)
	http.HandleFunc("/verify-code", verifyCodeHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/update", updateHandler)
	http.HandleFunc("/pong", pongHandler)
	http.HandleFunc("/inbound", inboundEmailHandler)
	http.HandleFunc("/test-ping", testPingHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	go pingScheduler()

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"Version": VERSION,
	}
	tmpl := template.Must(template.ParseFiles("templates/index.html"))

	tmpl.Execute(w, data)
}

func sendCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
		"User":    user,
		"Email":   email,
		"Version": VERSION,
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
	alertEmails := []string{}
	for _, e := range strings.Split(alertEmailsStr, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			alertEmails = append(alertEmails, e)
		}
	}

	pingFreq := r.FormValue("ping_frequency")

	localHour := 9
	if r.FormValue("checkin_hour") != "" {
		fmt.Sscanf(r.FormValue("checkin_hour"), "%d", &localHour)
	}

	timezone := r.FormValue("timezone")
	if timezone == "" {
		timezone = "UTC"
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		log.Printf("Invalid timezone %s, defaulting to UTC", timezone)
		loc = time.UTC
	}

	now := time.Now()
	localTime := time.Date(now.Year(), now.Month(), now.Day(), localHour, 0, 0, 0, loc)

	utcTime := localTime.UTC()
	checkInHourUTC := utcTime.Hour()

	token := generateToken()

	user := &User{
		Email:             email,
		AlertEmails:       alertEmails,
		PingFrequency:     pingFreq,
		CheckInHour:       checkInHourUTC,
		LastPing:          time.Now(),
		CurrentCycleStart: time.Time{},
		LastReminderNum:   0,
		Active:            true,
		Token:             token,
		AlertSent:         false,
	}

	store.mu.Lock()
	store.Users[email] = user
	store.mu.Unlock()
	saveStore()

	fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Settings Saved</h1><p>Your wellness ping is now active!</p><p>You'll receive check-ins at %d:00 %s (stored as %d:00 UTC)</p><p><a href='/settings'>Back to settings</a></p></body></html>", localHour, timezone, checkInHourUTC)
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

func pongHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	store.mu.Lock()
	var foundUser *User
	var wasAlerted bool

	for _, user := range store.Users {
		if user.Token == token {
			foundUser = user
			wasAlerted = user.AlertSent
			user.LastPing = time.Now()
			user.LastReminderNum = 0
			user.AlertSent = false
			break
		}
	}
	store.mu.Unlock()

	if foundUser == nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	saveStore()

	if wasAlerted {
		sendAllClearEmail(foundUser)
	}

	fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Confirmed</h1><p>Thanks for checking in!</p></body></html>")
}

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

func pingScheduler() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
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

		now := time.Now()
		needsSave := false

		for _, user := range users {
			if !user.Active {
				continue
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

			timeSinceLastPing := time.Since(user.LastPing)
			timeSinceCycleStart := time.Since(user.CurrentCycleStart)

			if user.PingFrequency == "daily" {
				lastPingDate := user.LastPing.Truncate(24 * time.Hour)
				todayDate := now.Truncate(24 * time.Hour)

				if todayDate.After(lastPingDate) {
					if now.Hour() >= user.CheckInHour {
						store.mu.Lock()
						user.LastReminderNum = 0
						user.CurrentCycleStart = time.Now() // Mark cycle start
						store.mu.Unlock()
						sendPing(user, 0)
						needsSave = true
						continue
					}
				}
			} else { // weekly
				if timeSinceLastPing >= pingInterval && now.Hour() >= user.CheckInHour {
					store.mu.Lock()
					user.LastReminderNum = 0
					user.CurrentCycleStart = time.Now() // Mark cycle start
					store.mu.Unlock()
					sendPing(user, 0)
					needsSave = true
					continue
				}
			}

			if !user.CurrentCycleStart.IsZero() &&
				user.LastPing.Before(user.CurrentCycleStart) &&
				timeSinceCycleStart < pingInterval {

				expectedReminderNum := int(timeSinceCycleStart / reminderInterval)

				maxReminders := 3
				if user.PingFrequency == "weekly" {
					maxReminders = 6
				}

				if expectedReminderNum > user.LastReminderNum && expectedReminderNum <= maxReminders {
					store.mu.Lock()
					user.LastReminderNum = expectedReminderNum
					store.mu.Unlock()
					sendPing(user, expectedReminderNum)
					needsSave = true
				}
			}

			if !user.CurrentCycleStart.IsZero() &&
				user.LastPing.Before(user.CurrentCycleStart) &&
				timeSinceCycleStart >= pingInterval &&
				!user.AlertSent {

				store.mu.Lock()
				user.AlertSent = true
				store.mu.Unlock()
				sendAlert(user)
				needsSave = true
			}
		}

		if needsSave {
			saveStore()
		}
	}
}

func sendPing(user *User, reminderNum int) {
	link := fmt.Sprintf("https://wellness-p.ing/pong?token=%s", user.Token)
	subject := "Wellness Ping"
	body := ""

	if reminderNum == 0 {
		body = fmt.Sprintf("Hi! Just checking in.\n\nClick here to confirm you're okay: %s\n\nOr reply PONG to this email.", link)
	} else {
		var timeRemaining string
		if user.PingFrequency == "daily" {
			hoursLeft := 24 - (reminderNum * 6)
			timeRemaining = fmt.Sprintf("%d hours", hoursLeft)
		} else {
			daysLeft := 7 - reminderNum
			timeRemaining = fmt.Sprintf("%d days", daysLeft)
		}

		body = fmt.Sprintf("Reminder: You haven't checked in yet.\n\nYou have %s remaining before your contacts are notified.\n\nClick here to confirm you're okay: %s\n\nOr reply PONG to this email.", timeRemaining, link)
		subject = "Wellness Ping - Reminder"
	}

	sendEmail(user.Email, subject, body)
}

func sendAlert(user *User) {
	subject := fmt.Sprintf("Wellness Alert - %s Not Responding", user.Email)
	body := fmt.Sprintf("WARNING: %s hasn't responded to their wellness ping.\n\nPlease check in on them to ensure they're okay.", user.Email)

	for _, alertEmail := range user.AlertEmails {
		sendEmail(alertEmail, subject, body)
	}
}

func sendAllClearEmail(user *User) {
	subject := fmt.Sprintf("All Clear - %s Checked In", user.Email)
	body := fmt.Sprintf("Good news! %s has now checked in and confirmed they're okay.", user.Email)

	for _, alertEmail := range user.AlertEmails {
		sendEmail(alertEmail, subject, body)
	}
}

func sendEmail(to, subject, body string) {
	token := os.Getenv("POSTMARK_TOKEN")
	if token == "" {
		log.Printf("POSTMARK_TOKEN not set, would send email to %s with subject: %s and body: %s", to, subject, body)
		return
	}

	htmlBody := strings.ReplaceAll(body, "\n", "<br>")

	payload := map[string]string{
		"From":          "ping@wellness-p.ing",
		"To":            to,
		"Subject":       subject,
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
}

func saveStore() {
	store.mu.RLock()
	defer store.mu.RUnlock()

	// User count to track growth
	log.Printf("Saving store with %d users (DATE: %s)", len(store.Users), time.Now().Format(time.RFC3339))

	data, _ := json.MarshalIndent(store, "", "  ")
	os.WriteFile("data/users.json", data, 0644)
}
