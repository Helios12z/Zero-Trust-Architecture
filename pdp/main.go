package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var publicKey *rsa.PublicKey

func initKeys() {
	pubKeyPath := os.Getenv("PUBLIC_KEY_PATH")
	if pubKeyPath == "" {
		pubKeyPath = "/keys/public.pem"
	}

	log.Printf("[PDP-INIT] Loading RSA Public Key from path: %s", pubKeyPath)
	
	// Wait a moment for keys to be generated if the container starts quickly
	var pubKeyBytes []byte
	var err error
	for i := 0; i < 5; i++ {
		pubKeyBytes, err = os.ReadFile(pubKeyPath)
		if err == nil {
			break
		}
		log.Printf("[PDP-INIT] Key not found, retrying in 2 seconds... (%d/5)", i+1)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("[PDP-INIT ERROR] Failed to read public key after retries: %v", err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyBytes)
	if err != nil {
		log.Fatalf("[PDP-INIT ERROR] Failed to parse RSA public key: %v", err)
	}
	publicKey = pubKey
	log.Println("[PDP-INIT] ✓ Successfully loaded and parsed RSA Public Key for RS256 token verification.")
}

type ValidateRequest struct {
	Token       string `json:"token"`
	DeviceHash  string `json:"device_hash"`
}

type ValidateResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	Subject string `json:"subject,omitempty"`
	Role    string `json:"role,omitempty"`
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[PDP ERROR] Error reading validation request body: %v", err)
		writeJSON(w, http.StatusBadRequest, ValidateResponse{Allowed: false, Reason: "Invalid request body"})
		return
	}
	defer r.Body.Close()

	var req ValidateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("[PDP ERROR] Error parsing JSON validation payload: %v", err)
		writeJSON(w, http.StatusBadRequest, ValidateResponse{Allowed: false, Reason: "Invalid JSON format"})
		return
	}

	log.Println("==========================================================================")
	log.Println("🧠 [PDP EVALUATION ENGINE] Triggering access evaluation request...")
	log.Printf("🧠 [PDP] Received Device Posture Hash: '%s'", req.DeviceHash)
	log.Printf("🧠 [PDP] Token Present: %t", req.Token != "")

	// 1. JWT validation
	if req.Token == "" {
		log.Println("🔒 [PDP DENY] Rejection Reason: Identity verification failed. Authorization Token is missing.")
		writeJSON(w, http.StatusOK, ValidateResponse{Allowed: false, Reason: "Missing Identity Token (JWT)"})
		return
	}

	// Parse and verify token signature and claims
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		// Verify signature method is RSA (RS256)
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		// Log detailed error for the professor's demo!
		log.Printf("🔒 [PDP DENY] JWT Verification Failed! Cryptographic Signature Error or Expired: %v", err)
		writeJSON(w, http.StatusOK, ValidateResponse{
			Allowed: false, 
			Reason:  fmt.Sprintf("Cryptographic validation failed: %v", err),
		})
		return
	}

	if !token.Valid {
		log.Println("🔒 [PDP DENY] JWT is mathematically parsed but marked as invalid (e.g. claims constraints fail).")
		writeJSON(w, http.StatusOK, ValidateResponse{Allowed: false, Reason: "Token parsed successfully but is invalid"})
		return
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("🔒 [PDP DENY] Failed to extract map claims from JWT.")
		writeJSON(w, http.StatusOK, ValidateResponse{Allowed: false, Reason: "Failed to parse JWT claims"})
		return
	}

	subject, _ := claims["sub"].(string)
	role, _ := claims["role"].(string)
	log.Printf("🛡️ [PDP IDENTITY VERIFIED] User Subject: '%s', Role: '%s'", subject, role)

	// 2. Posture verification
	expectedHash := "a7b8f9d3e4"
	if req.DeviceHash == "" {
		log.Println("🔒 [PDP DENY] Rejection Reason: Device Posture check failed. Missing compliance posture headers.")
		writeJSON(w, http.StatusOK, ValidateResponse{
			Allowed: false, 
			Reason:  "Missing X-Device-Posture-Hash compliance header",
			Subject: subject,
			Role:    role,
		})
		return
	}

	if req.DeviceHash != expectedHash {
		log.Printf("🔒 [PDP DENY] Rejection Reason: Device compliance mismatch. Expected Compliant MDM Hash '%s', but received '%s' (Untrusted Device)", expectedHash, req.DeviceHash)
		writeJSON(w, http.StatusOK, ValidateResponse{
			Allowed: false, 
			Reason:  "Device Posture Untrusted (Device is not compliant with company security standards)",
			Subject: subject,
			Role:    role,
		})
		return
	}

	// Allowed!
	log.Printf("🎉 [PDP ALLOW] SUCCESS: Cryptographic identity verified AND Device posture matches compliance hash (%s). Access GRANTED for '%s'.", expectedHash, subject)
	log.Println("==========================================================================")
	
	writeJSON(w, http.StatusOK, ValidateResponse{
		Allowed: true,
		Subject: subject,
		Role:    role,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func main() {
	initKeys()
	http.HandleFunc("/validate", handleValidate)
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("🚀 [PDP] Policy Decision Point Engine successfully running internally on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("PDP failed to start: %v", err)
	}
}
