// Package main runs the Go backend for the browser example.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	hcaptcha "github.com/hCaptcha/hcaptcha-go/hcaptcha"
)

const maxRequestBodyBytes = 16 << 10

type application struct {
	verifier *hcaptcha.Client
	siteKey  string
}

func main() {
	secret := strings.TrimSpace(os.Getenv("HCAPTCHA_SECRET"))
	siteKey := strings.TrimSpace(os.Getenv("VITE_HCAPTCHA_SITEKEY"))
	if secret == "" || siteKey == "" {
		log.Fatal("HCAPTCHA_SECRET and VITE_HCAPTCHA_SITEKEY are required")
	}

	verifier, err := hcaptcha.New(secret)
	if err != nil {
		log.Fatal(err)
	}
	app := application{verifier: verifier, siteKey: siteKey}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("POST /protected", app.protected)
	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Go backend listening on %s", server.Addr)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (app application) protected(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	// This example reads the token from a form POST. JSON APIs can decode the body instead.
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid form"})
		return
	}
	token := strings.TrimSpace(r.FormValue("h-captcha-response"))
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid token is required"})
		return
	}

	result, err := app.verifier.VerifyRequest(r.Context(), hcaptcha.Request{
		Token:    token,
		RemoteIP: clientIP(r),
		SiteKey:  app.siteKey,
	})
	if err != nil {
		log.Printf("siteverify call failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "siteverify unavailable"})
		return
	}

	if result["success"] != true {
		writeJSON(w, http.StatusForbidden, map[string]any{"siteverify": result})
		return
	}

	// Perform the protected action.
	writeJSON(w, http.StatusOK, map[string]any{"siteverify": result})
}

func clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !peerIP.IsLoopback() {
		return peer
	}

	forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
	if net.ParseIP(forwarded) != nil {
		return forwarded
	}
	return peer
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}
