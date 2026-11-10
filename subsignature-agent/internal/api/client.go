// Package api talks to the SubSignature server (API v1, read-only).
// It is based on the server documentation docs/API.md in the SubSignature
// repository; the agent's decisions about it are in docs/API.md of this project.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Error classes (testable with errors.Is). On any error the local
// configuration stays unchanged; the class controls log text, abort and wait time.
var (
	ErrAuth          = errors.New("server rejects the token (401/403) - check the token")
	ErrHTTPSRequired = errors.New("server requires HTTPS")
	ErrRateLimited   = errors.New("server is rate limiting requests (429)")
	ErrTLS           = errors.New("TLS verification failed")
	ErrUnreachable   = errors.New("server not reachable")
	ErrServer        = errors.New("Serverfehler (5xx)")
	ErrProtocol      = errors.New("unexpected server response")
)

const (
	maxBody      = 8 << 20 // 8 MiB per page
	maxErrBody   = 64 << 10
	pageSize     = 50 // entries per request (the server allows 1-500)
	maxPages     = 20 // safeguard against endless loops: at most 1000 entries per address
	maxRetryWait = time.Hour
)

// APIError describes an error response of the server.
type APIError struct {
	Status     int
	Code       string // machine-readable code from {"error":{"code":...}}, sanitized
	Message    string // the server's text, sanitized (for the log)
	RetryAfter time.Duration
	Hint       string
	kind       error
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("%v: HTTP %d", e.kind, e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Message != "" {
		s += " (" + e.Message + ")"
	}
	if e.Hint != "" {
		s += " - " + e.Hint
	}
	return s
}

func (e *APIError) Unwrap() error { return e.kind }

// RetryAfter returns the wait time requested by the server (only for ErrRateLimited).
func RetryAfter(err error) (time.Duration, bool) {
	var ae *APIError
	if errors.As(err, &ae) && errors.Is(ae.kind, ErrRateLimited) {
		return ae.RetryAfter, true
	}
	return 0, false
}

// Systemic: the error affects every further request of the same run
// (token, TLS, network, rate limit). The agent then aborts the sync instead
// of repeating the same request for every further address.
func Systemic(err error) bool {
	return errors.Is(err, ErrAuth) || errors.Is(err, ErrHTTPSRequired) || errors.Is(err, ErrRateLimited) ||
		errors.Is(err, ErrTLS) || errors.Is(err, ErrUnreachable)
}

// Time reads the server's timestamps: "YYYY-MM-DD HH:MM:SS" (UTC, without
// time zone) and, to be safe, ISO 8601 / RFC 3339 as well.
type Time struct{ time.Time }

func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if tm, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			t.Time = tm.UTC()
			return nil
		}
	}
	return fmt.Errorf("invalid timestamp %q", s)
}

// Signature is one entry from GET /api/v1/signatures.
type Signature struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"` // name of the person (not of the signature!)
	Role       string `json:"role"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	Template   string `json:"template"` // template file, e.g. signature_pro.html
	Source     string `json:"source"`   // manual | csv | ldap
	CreatedAt  Time   `json:"created_at"`
	UpdatedAt  Time   `json:"updated_at"`
	HTML       string `json:"html"`
	HTMLSHA256 string `json:"html_sha256"` // change marker only; how it is computed is not documented
	Text       string `json:"text"`
}

type listResponse struct {
	Count  int             `json:"count"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	Items  json.RawMessage `json:"items"`
}

// Info is the response of GET /api/v1/ (service info, credential check).
type Info struct {
	Service    string `json:"service"`
	Version    string `json:"version"`
	API        string `json:"api"`
	Token      string `json:"token"` // label of the token in use
	ServerTime string `json:"server_time"`
}

type Options struct {
	BaseURL            *url.URL
	APIPath            string // root of the API, default /api/v1
	Timeout            time.Duration
	CAFile             string
	InsecureSkipVerify bool
	UseProxy           bool
	Token              string
	UserAgent          string
}

type Client struct {
	o  Options
	hc *http.Client
}

func New(o Options) (*Client, error) {
	if o.BaseURL == nil {
		return nil, errors.New("api: BaseURL is missing")
	}
	if o.Token == "" {
		return nil, errors.New("api: token is missing")
	}
	if strings.ContainsFunc(o.Token, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return nil, errors.New("api: token contains whitespace or control characters")
	}
	if o.APIPath == "" {
		o.APIPath = "/api/v1"
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureSkipVerify}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("api: ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("api: ca-file %s contains no valid PEM certificate", o.CAFile)
		}
		tlsCfg.RootCAs = pool // only these CAs, deliberately without the system CAs
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
		DisableKeepAlives:     true, // infrequent requests; do not keep connections open
	}
	if o.UseProxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	if o.UserAgent == "" {
		o.UserAgent = "subsignature-agent"
	}
	return &Client{
		o: o,
		hc: &http.Client{
			Transport: tr,
			Timeout:   o.Timeout,
			// Never follow redirects: the token must never go to another host/scheme.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) endpoint(p string, q url.Values) string {
	u := *c.o.BaseURL
	u.Path = path.Join("/", c.o.BaseURL.Path, c.o.APIPath, p)
	if p == "" {
		u.Path += "/" // GET /api/v1/ - with trailing slash, as documented
	}
	u.RawPath = ""
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String()
}

// Ping calls GET /api/v1/: checks reachability, TLS and token.
func (c *Client) Ping(ctx context.Context) (*Info, error) {
	body, err := c.get(ctx, c.endpoint("", nil))
	if err != nil {
		return nil, err
	}
	var in Info
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrProtocol, err)
	}
	if in.API == "" && in.Service == "" {
		return nil, fmt.Errorf("%w: the response is not a SubSignature service info (check server/url and api-path)", ErrProtocol)
	}
	return &in, nil
}

// Signatures returns all signatures for an e-mail address (all pages).
// The server does not define the order; duplicate IDs (page boundaries
// shifting during a change) are merged. An empty list is not an error:
// the server then knows no signature for this address.
func (c *Client) Signatures(ctx context.Context, email string) ([]Signature, error) {
	if !strings.Contains(email, "@") || strings.ContainsAny(email, "\r\n\x00") {
		return nil, fmt.Errorf("api: invalid e-mail address %q", email)
	}
	var all []Signature
	seen := map[int64]bool{}
	offset := 0
	for page := 0; page < maxPages; page++ {
		q := url.Values{
			"email":  {email},
			"limit":  {strconv.Itoa(pageSize)},
			"offset": {strconv.Itoa(offset)},
		}
		body, err := c.get(ctx, c.endpoint("signatures", q))
		if err != nil {
			return nil, err
		}
		var lr listResponse
		if err := json.Unmarshal(body, &lr); err != nil {
			return nil, fmt.Errorf("%w: not valid JSON: %v", ErrProtocol, err)
		}
		if len(lr.Items) == 0 || string(lr.Items) == "null" {
			return nil, fmt.Errorf("%w: field \"items\" is missing (check server/url and api-path)", ErrProtocol)
		}
		var items []Signature
		if err := json.Unmarshal(lr.Items, &items); err != nil {
			return nil, fmt.Errorf("%w: Feld \"items\" unlesbar: %v", ErrProtocol, err)
		}
		for _, s := range items {
			if seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			all = append(all, s)
		}
		// The server may apply a smaller limit; then its value counts, and the
		// next offset follows what actually arrived.
		eff := lr.Limit
		if eff <= 0 || eff > pageSize {
			eff = pageSize
		}
		if len(items) < eff {
			return all, nil
		}
		offset += len(items)
	}
	return nil, fmt.Errorf("%w: more than %d entries for %s", ErrProtocol, maxPages*pageSize, email)
}

// get performs a GET request and returns the body only for HTTP 200.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.o.UserAgent)
	req.Header.Set("Authorization", "Bearer "+c.o.Token)

	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var cve *tls.CertificateVerificationError
		if errors.As(err, &cve) {
			return nil, fmt.Errorf("%w: %v (check ca-file or renew the server certificate)", ErrTLS, cve.Err)
		}
		// Do not pass on the transport's error text unfiltered: it contains the URL including the address.
		return nil, fmt.Errorf("%w: %s", ErrUnreachable, redactURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		if err != nil {
			return nil, fmt.Errorf("%w: response aborted: %s", ErrUnreachable, redactURLError(err))
		}
		if len(body) > maxBody {
			return nil, fmt.Errorf("%w: response larger than %d MiB", ErrProtocol, maxBody>>20)
		}
		return body, nil
	}
	return nil, c.statusError(resp)
}

func redactURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return clean(err.Error(), 200)
}

// statusError translates an error response into an *APIError.
func (c *Client) statusError(resp *http.Response) error {
	ae := &APIError{Status: resp.StatusCode}
	if b, err := io.ReadAll(io.LimitReader(resp.Body, maxErrBody)); err == nil {
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(b, &env) == nil {
			ae.Code, ae.Message = clean(env.Error.Code, 40), clean(env.Error.Message, 200)
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		ae.kind = ErrAuth
	case resp.StatusCode == http.StatusForbidden && ae.Code == "https_required":
		ae.kind = ErrHTTPSRequired
		ae.Hint = "use server/url with https:// (the server allows HTTP only with API_ALLOW_HTTP)"
	case resp.StatusCode == http.StatusForbidden:
		ae.kind = ErrAuth
		ae.Hint = "the token lacks the permission signatures:read"
	case resp.StatusCode == http.StatusTooManyRequests:
		ae.kind = ErrRateLimited
		ae.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	case resp.StatusCode >= 500:
		ae.kind = ErrServer
	case resp.StatusCode == http.StatusNotFound:
		ae.kind = ErrProtocol
		ae.Hint = "endpoint not found - check server/url and api-path"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		ae.kind = ErrProtocol
		ae.Hint = "redirects are deliberately not followed (the token would otherwise leave the server); point server/url directly at the target"
		if loc, err := url.Parse(resp.Header.Get("Location")); err == nil && loc.Host != "" {
			ae.Hint += " (target: " + clean(loc.Scheme+"://"+loc.Host, 100) + ")"
		}
	default:
		ae.kind = ErrProtocol
	}
	return ae
}

// parseRetryAfter understands seconds and HTTP dates; invalid or missing: 60 s;
// capped, so that a server cannot lock the agent out for an arbitrary time.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	d := time.Minute
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	switch {
	case d < time.Second:
		d = time.Second
	case d > maxRetryWait:
		d = maxRetryWait
	}
	return d
}

// clean makes server text fit for the log: no control characters (line breaks!), limited length.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			r = ' '
		}
		if n++; n > max {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
