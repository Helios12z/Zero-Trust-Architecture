package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

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

var (
	pdpURL     string
	backendURL *url.URL
	proxy      *httputil.ReverseProxy
)

func init() {
	pdpURL = os.Getenv("PDP_URL")
	if pdpURL == "" {
		pdpURL = "http://pdp:8080/validate"
	}

	bURLStr := os.Getenv("BACKEND_URL")
	if bURLStr == "" {
		bURLStr = "http://backend:3000"
	}

	var err error
	backendURL, err = url.Parse(bURLStr)
	if err != nil {
		log.Fatalf("[PEP-INIT ERROR] Invalid Backend URL: %v", err)
	}

	// Create reverse proxy targeting backend
	proxy = httputil.NewSingleHostReverseProxy(backendURL)
	
	// Add custom headers to let the backend know it was authorized by the PEP
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-PEP-Authorized", "true")
		req.Header.Set("X-PEP-Authorized-At", time.Now().Format(time.RFC3339))
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Format(time.RFC3339)
	log.Println("--------------------------------------------------------------------------")
	log.Printf("🛡️ [PEP INTERCEPT] [%s] Intercepted incoming %s request for '%s' from client IP %s", now, r.Method, r.URL.Path, r.RemoteAddr)

	// Extract Bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	var token string
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			token = parts[1]
			log.Printf("🛡️ [PEP] Extracted JWT Bearer token from client request header (Length: %d)", len(token))
		} else {
			log.Printf("🛡️ [PEP WARNING] Authorization header present but malformed: '%s'", authHeader)
		}
	} else {
		log.Println("🛡️ [PEP WARNING] Authorization header is missing entirely from client request.")
	}

	// Extract Posture Hash compliance header
	postureHash := r.Header.Get("X-Device-Posture-Hash")
	if postureHash != "" {
		log.Printf("🛡️ [PEP] Extracted X-Device-Posture-Hash from client: '%s'", postureHash)
	} else {
		log.Println("🛡️ [PEP WARNING] X-Device-Posture-Hash compliance header is missing from client.")
	}

	// Send extraction context to PDP for a decision
	log.Printf("🛡️ [PEP] Contacting Policy Decision Point (PDP) at %s...", pdpURL)
	allowed, reason, statusCode, subject, role := callPDP(token, postureHash)

	if !allowed {
		log.Printf("🔒 [PEP BLOCKED] Access Denied! Status: %d, Reason: '%s'", statusCode, reason)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "access_denied",
			"code":        statusCode,
			"reason":      reason,
			"timestamp":   time.Now().Format(time.RFC3339),
			"enforced_by": "zta-pep-proxy",
		})
		log.Println("--------------------------------------------------------------------------")
		return
	}

	// Access granted! Forward request to internal backend API
	log.Printf("🔓 [PEP PASS] Access Approved! Subject: '%s', Role: '%s'. Forwarding traffic to target backend...", subject, role)
	
	// Inject authenticated subject info for downstream consumption (Backend Audit)
	r.Header.Set("X-Authenticated-User", subject)
	r.Header.Set("X-Authenticated-Role", role)
	
	proxy.ServeHTTP(w, r)
	log.Println("--------------------------------------------------------------------------")
}

func callPDP(token, postureHash string) (bool, string, int, string, string) {
	reqBody, err := json.Marshal(ValidateRequest{
		Token:      token,
		DeviceHash: postureHash,
	})
	if err != nil {
		return false, "Error serializing request context", http.StatusInternalServerError, "", ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(pdpURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("[PEP ERROR] PDP unreachable: %v", err)
		return false, "Policy Decision Point validation service is unreachable", http.StatusBadGateway, "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[PEP ERROR] PDP returned unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
		return false, "Policy Decision Point error", http.StatusInternalServerError, "", ""
	}

	var valResp ValidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&valResp); err != nil {
		return false, "Failed to decode decision context from PDP", http.StatusInternalServerError, "", ""
	}

	// Handle status codes according to ZTA rules:
	// Missing token -> 401 Unauthorized
	// Invalid token or device hash check failed -> 403 Forbidden
	if !valResp.Allowed {
		if token == "" {
			return false, valResp.Reason, http.StatusUnauthorized, "", ""
		}
		return false, valResp.Reason, http.StatusForbidden, "", ""
	}

	return true, "", http.StatusOK, valResp.Subject, valResp.Role
}

func main() {
	http.HandleFunc("/", handleProxy)

	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")

	if certPath == "" {
		certPath = "/keys/cert.pem"
	}
	if keyPath == "" {
		keyPath = "/keys/key.pem"
	}

	log.Println("🚀 [PEP] Policy Enforcement Point Front-Gate Proxy listening on port 443 with TLS (HTTPS)...")
	
	// Wait a moment for certs to be generated by generate_keys.sh on start
	var err error
	for i := 0; i < 5; i++ {
		err = http.ListenAndServeTLS(":443", certPath, keyPath, nil)
		if err != nil && (strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "open")) {
			log.Printf("[PEP-INIT] TLS Certificates not found, retrying in 2 seconds... (%d/5)", i+1)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	if err != nil {
		log.Fatalf("[PEP-INIT ERROR] Failed to start PEP TLS proxy: %v", err)
	}
}
