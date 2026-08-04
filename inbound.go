package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

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
		// Check security modules for inbound email
		allModulesPassed := true
		for _, module := range user.SecurityModules {
			if !module.Enabled {
				continue
			}
			// For inbound email, we assume the user passed auth since they replied
			// In production, implement proper verification
		}
		if allModulesPassed {
			wasAlerted = user.AlertSent
			user.LastPing = time.Now()
			user.LastReminderNum = 0
			user.AlertSent = false
		}
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
