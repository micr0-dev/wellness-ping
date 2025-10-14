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

type User struct {
	Email           string    `json:"email"`
	AlertEmails     []string  `json:"alert_emails"`
	PingFrequency   string    `json:"ping_frequency"`
	InactivityHours int       `json:"inactivity_hours"`
	LastPing        time.Time `json:"last_ping"`
	Active          bool      `json:"active"`
	Token           string    `json:"token"`
	AlertSent       bool      `json:"alert_sent"`
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
	loadStore()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/send-code", sendCodeHandler)
	http.HandleFunc("/verify-code", verifyCodeHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/update", updateHandler)
	http.HandleFunc("/pong", pongHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	go pingScheduler()

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	tmpl.Execute(w, nil)
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
		MaxAge:   1800, // 30 minutes
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	// Get session from cookie
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
		"User":  user,
		"Email": email,
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

		fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Service Stopped</h1><p>Your wellness ping service has been stopped.</p><p><a href='/'>Go back</a></p></body></html>")
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
	inactivityHours := 24
	if r.FormValue("inactivity_hours") != "" {
		fmt.Sscanf(r.FormValue("inactivity_hours"), "%d", &inactivityHours)
	}

	token := generateToken()

	user := &User{
		Email:           email,
		AlertEmails:     alertEmails,
		PingFrequency:   pingFreq,
		InactivityHours: inactivityHours,
		LastPing:        time.Now(),
		Active:          true,
		Token:           token,
		AlertSent:       false,
	}

	store.mu.Lock()
	store.Users[email] = user
	store.mu.Unlock()
	saveStore()

	fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Settings Saved</h1><p>Your wellness ping is now active!</p><p><a href='/'>Go back</a></p></body></html>")
}

func pongHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	store.mu.Lock()
	defer store.mu.Unlock()

	for _, user := range store.Users {
		if user.Token == token {
			wasAlerted := user.AlertSent
			user.LastPing = time.Now()
			user.AlertSent = false
			saveStore()

			if wasAlerted {
				sendAllClearEmail(user)
			}

			fmt.Fprintf(w, "<html><head><link rel='stylesheet' href='/static/style.css'></head><body><h1>Confirmed</h1><p>Thanks for checking in!</p></body></html>")
			return
		}
	}

	http.Error(w, "Invalid token", http.StatusBadRequest)
}

func pingScheduler() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
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

		for _, user := range users {
			if !user.Active {
				continue
			}

			var pingInterval time.Duration
			if user.PingFrequency == "daily" {
				pingInterval = 24 * time.Hour
			} else {
				pingInterval = 7 * 24 * time.Hour
			}

			timeSinceLastPing := time.Since(user.LastPing)
			inactivityDuration := time.Duration(user.InactivityHours) * time.Hour

			if timeSinceLastPing >= pingInterval && timeSinceLastPing < pingInterval+inactivityDuration {
				sendPing(user)
			}

			if timeSinceLastPing >= pingInterval+inactivityDuration && !user.AlertSent {
				store.mu.Lock()
				user.AlertSent = true
				store.mu.Unlock()
				saveStore()
				sendAlert(user)
			}
		}
	}
}

func sendPing(user *User) {
	link := fmt.Sprintf("https://wellness-p.ing/pong?token=%s", user.Token)
	subject := "Wellness Ping"
	body := fmt.Sprintf("Hi! Just checking in.\n\nClick here to confirm you're okay: %s\n\nOr reply PONG to this email.", link)

	sendEmail(user.Email, subject, body)
}

func sendAlert(user *User) {
	link := fmt.Sprintf("https://wellness-p.ing/pong?token=%s", user.Token)
	subject := fmt.Sprintf("Wellness Alert - %s Not Responding", user.Email)
	body := fmt.Sprintf("WARNING: %s hasn't responded to their wellness ping.\n\nIf you hear from them, they can confirm they're okay here:\n%s", user.Email, link)

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

	// Convert plain text to basic HTML
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

	log.Printf("Email sent successfully to %s", to)
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
}

func saveStore() {
	store.mu.RLock()
	defer store.mu.RUnlock()

	data, _ := json.MarshalIndent(store, "", "  ")
	os.WriteFile("data/users.json", data, 0644)
}
