// mocksubsig is a small test server that mimics the SubSignature API v1
// as described in the server documentation - with TLS (self-signed
// certificate) or without. For developing and testing the agent only, not for production.
//
// Mimicked: bearer token (ssg_...), GET /api/v1/, GET /api/v1/signatures
// (email, username, updated_since, limit, offset), GET /api/v1/signatures/{id},
// POST /api/v1/status (device_id, agent_version, items[] with
// signature_id/status/message/html_sha256 - the status:write permission), error format
// {"error":{"code","message"}}, https_required, brute-force lockout
// (20 invalid tokens per address in 5 minutes) and a rate limit per token, each
// with Retry-After. Not mimicked: how html_sha256 is really computed
// (here SHA-256 over the HTML; the agent treats the value as opaque).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tsLayout = "2006-01-02 15:04:05"

// item is an entry as in the API; Active is not part of the response.
type item struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	Template   string `json:"template"`
	Source     string `json:"source"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	HTML       string `json:"html"`
	HTMLSHA256 string `json:"html_sha256"`
	Text       string `json:"text"`

	Active *bool `json:"active,omitempty"` // only in the data file; missing = active
}

func (it item) active() bool { return it.Active == nil || *it.Active }

func (it item) public() item {
	it.Active = nil
	sum := sha256.Sum256([]byte(it.HTML))
	it.HTMLSHA256 = hex.EncodeToString(sum[:])
	return it
}

func demoHTML(who, extra string) string {
	return `<table style="font-family:Arial,sans-serif;font-size:12px"><tr><td><b>` + who + `</b><br>Example Ltd` + extra + `</td></tr></table>`
}

func demoData() []item {
	std := demoHTML("Max Mustermann", "<br>Tel. +49 123 456")
	off := false
	return []item{
		// Same address, same template, several rows (duplicate cases):
		{ID: 1, Username: "max", Name: "Max Mustermann", Role: "Sales", Email: "max.mustermann@example.com", Phone: "+49 123 456",
			Template: "signature_pro.html", Source: "manual", CreatedAt: "2026-11-01 08:00:00", UpdatedAt: "2026-11-01 08:00:00", HTML: std},
		{ID: 2, Username: "max", Name: "Max Mustermann", Role: "Sales", Email: "max.mustermann@example.com", Phone: "+49 123 456",
			Template: "signature_pro.html", Source: "csv", CreatedAt: "2026-11-09 08:00:00", UpdatedAt: "2026-11-09 08:00:00",
			HTML: demoHTML("Max Mustermann", "<br>Tel. +49 123 456<br><i>New from the CSV import</i>")},
		{ID: 3, Username: "max", Name: "Max Mustermann", Role: "Sales", Email: "max.mustermann@example.com", Phone: "+49 123 456",
			Template: "signature_pro.html", Source: "manual", CreatedAt: "2026-11-01 08:00:00", UpdatedAt: "2026-11-01 08:00:00", HTML: std}, // exact duplicate of 1
		// Another template of the same person:
		{ID: 4, Username: "max", Name: "Max Mustermann", Role: "Sales", Email: "max.mustermann@example.com", Phone: "+49 123 456",
			Template: "signature_short.html", Source: "manual", CreatedAt: "2026-10-01 08:00:00", UpdatedAt: "2026-10-01 08:00:00",
			HTML: demoHTML("M. Mustermann", "")},

		{ID: 10, Username: "erika", Name: "Erika Muster", Role: "Management", Email: "erika.muster@example.com", Phone: "+49 777 888",
			Template: "signature_pro.html", Source: "ldap", CreatedAt: "2026-10-15 08:00:00", UpdatedAt: "2026-10-15 08:00:00", HTML: demoHTML("Erika Muster", "")},

		// Shared mailbox: two accounts, same address (the agent must not guess):
		{ID: 20, Username: "anna", Name: "Anna Example", Email: "info@example.com", Template: "signature_pro.html", Source: "manual",
			CreatedAt: "2026-10-20 08:00:00", UpdatedAt: "2026-10-20 08:00:00", HTML: demoHTML("Anna Example", "")},
		{ID: 21, Username: "bob", Name: "Bob Example", Email: "info@example.com", Template: "signature_pro.html", Source: "manual",
			CreatedAt: "2026-10-21 08:00:00", UpdatedAt: "2026-10-21 08:00:00", HTML: demoHTML("Bob Example", "")},

		// Inactive account: not returned by the API.
		{ID: 30, Username: "former", Name: "Former Employee", Email: "former@example.com", Template: "signature_pro.html", Source: "ldap",
			CreatedAt: "2026-01-01 08:00:00", UpdatedAt: "2026-01-01 08:00:00", HTML: demoHTML("Ehemalige", ""), Active: &off},
	}
}

type server struct {
	token         string
	items         []item
	httpsRequired bool // like a real server without API_ALLOW_HTTP
	rateLimit     int  // requests per minute and token
	statusScope   bool // whether the token carries status:write (for POST /status)

	mu       sync.Mutex
	badTries map[string][]time.Time // address -> times of invalid tokens
	calls    []time.Time
}

// statusItem mirrors one entry of a POST /api/v1/status request.
type statusItem struct {
	SignatureID int64  `json:"signature_id"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	HTMLSHA256  string `json:"html_sha256,omitempty"`
}

var sha256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func apiError(w http.ResponseWriter, status int, code, msg string, hdr ...string) {
	log.Printf("abgelehnt: %d %s", status, code)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	for i := 0; i+1 < len(hdr); i += 2 {
		w.Header().Set(hdr[i], hdr[i+1])
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

// guard checks method, HTTPS, brute-force lockout, token and rate limit.
func (s *server) guard(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed.", "Allow", "GET")
		return false
	}
	if s.httpsRequired && r.TLS == nil {
		apiError(w, http.StatusForbidden, "https_required", "The API is only available over HTTPS.")
		return false
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	recent := s.badTries[ip][:0]
	for _, t := range s.badTries[ip] {
		if now.Sub(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	s.badTries[ip] = recent
	if len(recent) >= 20 {
		apiError(w, http.StatusTooManyRequests, "too_many_attempts", "Too many invalid tokens.", "Retry-After", "300")
		return false
	}

	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		s.badTries[ip] = append(s.badTries[ip], now)
		apiError(w, http.StatusUnauthorized, "unauthorized", "Token is missing, invalid, expired or revoked.")
		return false
	}

	win := s.calls[:0]
	for _, t := range s.calls {
		if now.Sub(t) < time.Minute {
			win = append(win, t)
		}
	}
	s.calls = win
	if len(s.calls) >= s.rateLimit {
		apiError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.", "Retry-After", "30")
		return false
	}
	s.calls = append(s.calls, now)
	return true
}

func (s *server) root(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	log.Printf("GET /api/v1/")
	writeJSON(w, map[string]string{
		"service": "SubSignature", "version": "1.4.0", "api": "v1", "token": "mock",
		"server_time": time.Now().Format("2006-01-02T15:04:05-07:00"),
	})
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	q := r.URL.Query()
	limit, offset := 100, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			apiError(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 500.")
			return
		}
		limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			apiError(w, http.StatusBadRequest, "bad_request", "offset must be >= 0.")
			return
		}
		offset = n
	}
	var since time.Time
	if v := q.Get("updated_since"); v != "" {
		t, err := parseTime(v)
		if err != nil {
			apiError(w, http.StatusBadRequest, "bad_request", "updated_since is not a valid date.")
			return
		}
		since = t
	}

	var hit []item
	for _, it := range s.items {
		if !it.active() {
			continue
		}
		if v := q.Get("email"); v != "" && !strings.EqualFold(it.Email, v) {
			continue
		}
		if v := q.Get("username"); v != "" && !strings.EqualFold(it.Username, v) {
			continue
		}
		if !since.IsZero() {
			if t, err := time.ParseInLocation(tsLayout, it.UpdatedAt, time.UTC); err != nil || t.Before(since) {
				continue
			}
		}
		hit = append(hit, it.public())
	}
	// The real API does not define an order; the mock deliberately shuffles (by ID descending)
	// so that the agent does not accidentally depend on the order.
	sort.Slice(hit, func(i, j int) bool { return hit[i].ID > hit[j].ID })

	page := []item{}
	if offset < len(hit) {
		page = hit[offset:min(offset+limit, len(hit))]
	}
	log.Printf("GET signatures email=%q username=%q limit=%d offset=%d -> %d", q.Get("email"), q.Get("username"), limit, offset, len(page))
	writeJSON(w, map[string]any{"count": len(page), "limit": limit, "offset": offset, "items": page})
}

func (s *server) one(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		for _, it := range s.items {
			if it.ID == id && it.active() {
				writeJSON(w, it.public())
				return
			}
		}
	}
	apiError(w, http.StatusNotFound, "not_found", "Signature not found.")
}

// status mimics POST /api/v1/status. It shares the auth/lockout/rate-limit
// logic of guard() but checks for POST (not GET) and, additionally, the
// status:write permission - set via -no-status-scope to test how the agent
// handles a token that only has signatures:read.
func (s *server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed.", "Allow", "POST")
		return
	}
	if s.httpsRequired && r.TLS == nil {
		apiError(w, http.StatusForbidden, "https_required", "The API is only available over HTTPS.")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	now := time.Now()
	recent := s.badTries[ip][:0]
	for _, t := range s.badTries[ip] {
		if now.Sub(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	s.badTries[ip] = recent
	if len(recent) >= 20 {
		s.mu.Unlock()
		apiError(w, http.StatusTooManyRequests, "too_many_attempts", "Too many invalid tokens.", "Retry-After", "300")
		return
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		s.badTries[ip] = append(s.badTries[ip], now)
		s.mu.Unlock()
		apiError(w, http.StatusUnauthorized, "unauthorized", "Token is missing, invalid, expired or revoked.")
		return
	}
	if !s.statusScope {
		s.mu.Unlock()
		apiError(w, http.StatusForbidden, "forbidden", "The token lacks the status:write permission.")
		return
	}
	win := s.calls[:0]
	for _, t := range s.calls {
		if now.Sub(t) < time.Minute {
			win = append(win, t)
		}
	}
	s.calls = win
	if len(s.calls) >= s.rateLimit {
		s.mu.Unlock()
		apiError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.", "Retry-After", "30")
		return
	}
	s.calls = append(s.calls, now)
	s.mu.Unlock()

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536+1))
	if err != nil || len(body) > 65536 {
		apiError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body must be at most 64 KiB.")
		return
	}
	var req struct {
		DeviceID     string       `json:"device_id"`
		AgentVersion string       `json:"agent_version"`
		Items        []statusItem `json:"items"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "Request body must be a JSON object.")
		return
	}
	if req.DeviceID == "" {
		apiError(w, http.StatusBadRequest, "bad_request", "device_id is required.")
		return
	}
	if len(req.Items) == 0 {
		apiError(w, http.StatusBadRequest, "bad_request", "items must be a non-empty array.")
		return
	}
	if len(req.Items) > 200 {
		apiError(w, http.StatusBadRequest, "bad_request", "items must not contain more than 200 entries per request.")
		return
	}
	allowedStatus := map[string]bool{"ok": true, "warn": true, "error": true}
	for _, it := range req.Items {
		if !allowedStatus[it.Status] {
			apiError(w, http.StatusBadRequest, "bad_request", "status must be one of: ok, warn, error.")
			return
		}
		if it.HTMLSHA256 != "" && !sha256HexPattern.MatchString(it.HTMLSHA256) {
			apiError(w, http.StatusBadRequest, "bad_request", "html_sha256 must be 64 hexadecimal characters.")
			return
		}
	}

	s.mu.Lock()
	known := 0
	for _, it := range req.Items {
		for _, sig := range s.items {
			if sig.ID == it.SignatureID {
				known++
				break
			}
		}
	}
	s.mu.Unlock()

	for _, it := range req.Items {
		// Like the server: compare the applied version with the current one.
		current := "unknown signature"
		s.mu.Lock()
		for _, sig := range s.items {
			if sig.ID == it.SignatureID {
				current = "out of date"
				if it.HTMLSHA256 == "" {
					current = "no hash sent"
				} else if strings.EqualFold(sig.HTMLSHA256, it.HTMLSHA256) {
					current = "up to date"
				}
				break
			}
		}
		s.mu.Unlock()
		log.Printf("POST /api/v1/status device=%q version=%q signature=%d status=%s version-check=%s message=%q",
			req.DeviceID, req.AgentVersion, it.SignatureID, it.Status, current, it.Message)
	}
	writeJSON(w, map[string]any{"received": len(req.Items), "updated": known})
}

func parseTime(v string) (time.Time, error) {
	for _, l := range []string{time.RFC3339, tsLayout, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, v, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid")
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address:port")
	useTLS := flag.Bool("tls", false, "with TLS (self-signed certificate) instead of plain HTTP (plain HTTP corresponds to API_ALLOW_HTTP=true)")
	httpsRequired := flag.Bool("https-required", false, "reject plain HTTP with 403 https_required (like a server without API_ALLOW_HTTP)")
	caOut := flag.String("ca-out", "mock-ca.pem", "with -tls: the certificate (PEM) for <ca-file> is written here")
	token := flag.String("token", "ssg_"+strings.Repeat("0123456789abcdef", 4), "expected token")
	rateLimit := flag.Int("rate-limit", 600, "requests per minute and token, then 429 rate_limited")
	dataFile := flag.String("data", "", "JSON file with a list of entries (fields as in the API, optionally \"active\":false) instead of the demo data")
	noStatusScope := flag.Bool("no-status-scope", false, "reject POST /api/v1/status with 403 (simulates a token without the status:write permission)")
	flag.Parse()

	items := demoData()
	if *dataFile != "" {
		b, err := os.ReadFile(*dataFile)
		if err == nil {
			items = nil
			err = json.Unmarshal(b, &items)
		}
		if err != nil {
			log.Fatal(err)
		}
	}

	s := &server{token: *token, items: items, httpsRequired: *httpsRequired, rateLimit: *rateLimit,
		statusScope: !*noStatusScope, badTries: map[string][]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/{$}", s.root)
	mux.HandleFunc("/api/v1/signatures", s.list)
	mux.HandleFunc("/api/v1/signatures/{id}", s.one)
	mux.HandleFunc("/api/v1/status", s.status)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "Unknown endpoint.")
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Printf("Token: %s\n", *token)
	if *useTLS {
		cert, certPEM := selfSigned()
		if err := os.WriteFile(*caOut, certPEM, 0o644); err != nil {
			log.Fatal(err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		fmt.Printf("HTTPS on https://%s - certificate: %s (enter it as <ca-file>)\n", *listen, *caOut)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	fmt.Printf("HTTP (unencrypted!) on http://%s\n", *listen)
	log.Fatal(srv.ListenAndServe())
}

func selfSigned() (tls.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "mocksubsig"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certPEM
}
