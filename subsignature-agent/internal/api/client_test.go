package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "ssg_test0123456789"

func newTestClient(t *testing.T, rawURL string, mod func(*Options)) *Client {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{BaseURL: u, Timeout: 5 * time.Second, Token: testToken}
	if mod != nil {
		mod(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func item(id int64, email string) map[string]any {
	return map[string]any{
		"id": id, "username": "anna", "name": "Anna Example", "role": "CTO", "email": email,
		"phone": "+49 111 222", "template": "signature_pro.html", "source": "manual",
		"created_at": "2026-11-07 20:42:11", "updated_at": "2026-11-07 20:42:11",
		"html": "<table><tr><td>Anna</td></tr></table>", "html_sha256": "9f2c", "text": "Anna Example\nCTO",
	}
}

func page(items []map[string]any, limit, offset int) string {
	if items == nil {
		items = []map[string]any{} // like PHP: an empty list as [], not null
	}
	b, _ := json.Marshal(map[string]any{"count": len(items), "limit": limit, "offset": offset, "items": items})
	return string(b)
}

func apiErr(w http.ResponseWriter, status int, code, msg string, hdr ...string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	for i := 0; i+1 < len(hdr); i += 2 {
		w.Header().Set(hdr[i], hdr[i+1])
	}
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": msg}}) // %q would not produce valid JSON
	w.Write(b)
}

func TestSignaturesRequestAndFields(t *testing.T) {
	var gotReq *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		fmt.Fprint(w, page([]map[string]any{item(2, "max+test@example.com")}, 50, 0))
	}))
	defer srv.Close()

	got, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "max+test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if gotReq.URL.Path != "/api/v1/signatures" {
		t.Errorf("Pfad = %q", gotReq.URL.Path)
	}
	q := gotReq.URL.Query()
	if q.Get("email") != "max+test@example.com" || q.Get("limit") != "50" || q.Get("offset") != "0" {
		t.Errorf("query = %v (the + in the address must arrive as %%2B)", q)
	}
	if h := gotReq.Header.Get("Authorization"); h != "Bearer "+testToken {
		t.Errorf("Authorization = %q", h)
	}
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	s := got[0]
	if s.ID != 2 || s.Username != "anna" || s.Template != "signature_pro.html" || s.Source != "manual" ||
		s.HTMLSHA256 != "9f2c" || s.Role != "CTO" || s.Phone != "+49 111 222" || !strings.Contains(s.HTML, "<table>") {
		t.Errorf("fields read incorrectly: %+v", s)
	}
	if want := time.Date(2026, 11, 7, 20, 42, 11, 0, time.UTC); !s.UpdatedAt.Equal(want) {
		t.Errorf("updated_at = %v, expected %v (UTC)", s.UpdatedAt, want)
	}
}

func TestSignaturesEmptyListIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, page(nil, 50, 0)) // "items":[]
	}))
	defer srv.Close()
	got, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestSignaturesPagination(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var items []map[string]any
		for i := off; i < 120 && len(items) < 50; i++ { // 120 entries in total
			items = append(items, item(int64(i+1), "a@b.de"))
		}
		fmt.Fprint(w, page(items, 50, off))
	}))
	defer srv.Close()
	got, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 120 || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("%d entries in %d requests, expected 120 in 3", len(got), calls)
	}
}

func TestSignaturesServerClampsLimit(t *testing.T) {
	// The server returns at most 10 per page and reports limit=10: the next offset
	// must follow what arrived, otherwise entries are missing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var items []map[string]any
		for i := off; i < 25 && len(items) < 10; i++ {
			items = append(items, item(int64(i+1), "a@b.de"))
		}
		fmt.Fprint(w, page(items, 10, off))
	}))
	defer srv.Close()
	got, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
	if err != nil || len(got) != 25 {
		t.Fatalf("%d entries, err=%v (expected 25)", len(got), err)
	}
}

func TestSignaturesDuplicateIDsAcrossPagesAreMerged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var items []map[string]any
		if off == 0 {
			for i := 1; i <= 50; i++ {
				items = append(items, item(int64(i), "a@b.de"))
			}
		} else {
			items = append(items, item(50, "a@b.de")) // page boundary: ID 50 comes once more
		}
		fmt.Fprint(w, page(items, 50, off))
	}))
	defer srv.Close()
	got, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
	if err != nil || len(got) != 50 {
		t.Fatalf("%d entries, err=%v (expected 50)", len(got), err)
	}
}

func TestSignaturesEndlessPagingIsStopped(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		var items []map[string]any
		for i := 0; i < 50; i++ {
			items = append(items, item(int64(n)*100+int64(i), "a@b.de")) // every page full and new
		}
		fmt.Fprint(w, page(items, 50, 0))
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, expected ErrProtocol", err)
	}
	if calls > maxPages {
		t.Errorf("%d requests, the limit is %d", calls, maxPages)
	}
}

func TestSignaturesRejectsBadEmailBeforeRequest(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1", nil)
	for _, e := range []string{"", "no-at-sign", "a@b.de\r\nX: y", "a@b\x00.de"} {
		if _, err := c.Signatures(context.Background(), e); err == nil || errors.Is(err, ErrUnreachable) {
			t.Errorf("%q: err = %v (must fail before touching the network)", e, err)
		}
	}
}

func TestSignaturesMalformedResponses(t *testing.T) {
	cases := map[string]string{
		"not JSON":               `<html>Login</html>`,
		"without items":          `{"count":0,"limit":50,"offset":0}`,
		"items null":             `{"items":null}`,
		"items not an array":     `{"items":"x"}`,
		"id is text":             `{"items":[{"id":"two","email":"a@b.de"}]}`,
		"time unreadable":        `{"items":[{"id":1,"updated_at":"yesterday"}]}`,
		"root is an array":       `[]`,
		"service info, not list": `{"service":"SubSignature","version":"1.4.0","api":"v1"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer srv.Close()
			if _, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de"); !errors.Is(err, ErrProtocol) {
				t.Fatalf("err = %v, expected ErrProtocol", err)
			}
		})
	}
}

func TestSignaturesBodyTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"items":[{"id":1,"html":"%s"}]}`, strings.Repeat("x", maxBody))
	}))
	defer srv.Close()
	if _, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, expected ErrProtocol", err)
	}
}

func TestErrorMapping(t *testing.T) {
	type tc struct {
		name   string
		status int
		code   string
		hdr    []string
		want   error
	}
	cases := []tc{
		{"401", 401, "unauthorized", nil, ErrAuth},
		{"403 forbidden", 403, "forbidden", nil, ErrAuth},
		{"403 https_required", 403, "https_required", nil, ErrHTTPSRequired},
		{"429 too_many_attempts", 429, "too_many_attempts", []string{"Retry-After", "300"}, ErrRateLimited},
		{"429 rate_limited", 429, "rate_limited", []string{"Retry-After", "30"}, ErrRateLimited},
		{"500", 500, "", nil, ErrServer},
		{"503", 503, "", nil, ErrServer},
		{"400", 400, "bad_request", nil, ErrProtocol},
		{"404 does NOT mean 'no signature'", 404, "not_found", nil, ErrProtocol},
		{"405", 405, "method_not_allowed", nil, ErrProtocol},
		{"302 is not followed", 302, "", []string{"Location", "https://other.example/api/v1/signatures"}, ErrProtocol},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var other int32
			evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&other, 1) }))
			defer evil.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hdr := c.hdr
				if c.status == 302 {
					hdr = []string{"Location", evil.URL + "/x"}
				}
				apiErr(w, c.status, c.code, "Text", hdr...)
			}))
			defer srv.Close()
			_, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, expected %v", err, c.want)
			}
			if atomic.LoadInt32(&other) != 0 {
				t.Fatal("the redirect was followed - the token would have gone to another host")
			}
		})
	}
}

func TestRetryAfterAndSystemic(t *testing.T) {
	cases := []struct {
		hdr  string
		want time.Duration
	}{
		{"30", 30 * time.Second},
		{"0", time.Second},    // never retry immediately
		{"", time.Minute},     // missing: be careful
		{"abc", time.Minute},  // unreadable: be careful
		{"-5", time.Minute},   // negative: unreadable
		{"999999", time.Hour}, // capped
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var h []string
			if c.hdr != "" {
				h = []string{"Retry-After", c.hdr}
			}
			apiErr(w, 429, "rate_limited", "x", h...)
		}))
		_, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
		srv.Close()
		d, ok := RetryAfter(err)
		if !ok || d != c.want {
			t.Errorf("Retry-After %q: %v/%v, expected %v", c.hdr, d, ok, c.want)
		}
		if !Systemic(err) {
			t.Errorf("429 must abort the sync")
		}
	}
	if d := parseRetryAfter(time.Now().Add(90*time.Second).UTC().Format(http.TimeFormat), time.Now()); d < 85*time.Second || d > 95*time.Second {
		t.Errorf("HTTP date as Retry-After: %v", d)
	}
	if _, ok := RetryAfter(ErrAuth); ok {
		t.Error("RetryAfter for a different error")
	}
	if Systemic(ErrServer) || Systemic(ErrProtocol) {
		t.Error("5xx and protocol errors of one address must not block other addresses")
	}
}

func TestServerTextIsSanitizedAndTokenNeverLogged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiErr(w, 401, "unauthorized", "line1\nFORGED LOG LINE level=ERROR\x1b[31m"+strings.Repeat("A", 500))
	}))
	defer srv.Close()
	_, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de")
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "FORGED LOG LINE") {
		t.Fatalf("the server's text did not arrive at all (the test would be ineffective): %q", msg)
	}
	if strings.ContainsAny(msg, "\n\r\x1b") {
		t.Errorf("control characters in the error text: %q", msg)
	}
	if len(msg) > 400 {
		t.Errorf("error text too long (%d characters)", len(msg))
	}
	if strings.Contains(msg, testToken) {
		t.Error("token in the error text")
	}
}

func TestUnreachableDoesNotLeakTokenOrURL(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := "http://" + l.Addr().String()
	l.Close() // port closed
	_, err := newTestClient(t, addr, nil).Signatures(context.Background(), "secret@example.com")
	if !errors.Is(err, ErrUnreachable) || !Systemic(err) {
		t.Fatalf("err = %v, expected ErrUnreachable (systemic)", err)
	}
	if strings.Contains(err.Error(), "secret@example.com") || strings.Contains(err.Error(), testToken) {
		t.Errorf("the error text reveals address or token: %v", err)
	}
}

func TestTimeoutIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(600 * time.Millisecond) }))
	defer srv.Close()
	c := newTestClient(t, srv.URL, func(o *Options) { o.Timeout = 150 * time.Millisecond })
	if _, err := c.Signatures(context.Background(), "a@b.de"); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, expected ErrUnreachable", err)
	}
}

func TestCanceledContextIsReturnedAsIs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newTestClient(t, srv.URL, nil).Signatures(ctx, "a@b.de"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, expected context.Canceled", err)
	}
}

func TestPing(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		fmt.Fprint(w, `{"service":"SubSignature","version":"1.4.0","api":"v1","token":"Büro-Agent","server_time":"2026-11-07T20:51:07+00:00"}`)
	}))
	defer srv.Close()
	in, err := newTestClient(t, srv.URL, nil).Ping(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/v1/" {
		t.Errorf("path = %q, the docs say GET /api/v1/ (with trailing slash)", path)
	}
	if in.Service != "SubSignature" || in.API != "v1" || in.Token != "Büro-Agent" || in.ServerTime == "" {
		t.Errorf("Info = %+v", in)
	}
}

func TestPingRejectsForeignAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"hello":"world"}`) }))
	defer srv.Close()
	if _, err := newTestClient(t, srv.URL, nil).Ping(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err = %v, expected ErrProtocol", err)
	}
}

func TestPingBadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiErr(w, 401, "unauthorized", "token invalid")
	}))
	defer srv.Close()
	if _, err := newTestClient(t, srv.URL, nil).Ping(context.Background()); !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, expected ErrAuth", err)
	}
}

func TestEndpointJoinsBasePath(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/") {
			fmt.Fprint(w, `{"service":"SubSignature","api":"v1"}`)
			return
		}
		fmt.Fprint(w, page(nil, 50, 0))
	}))
	defer srv.Close()
	for _, base := range []string{"/", "/sig", "/sig/"} {
		paths = nil
		c := newTestClient(t, srv.URL+base, func(o *Options) { o.APIPath = "/api/v1" })
		if _, err := c.Ping(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Signatures(context.Background(), "a@b.de"); err != nil {
			t.Fatal(err)
		}
		prefix := strings.TrimRight(base, "/")
		want := []string{prefix + "/api/v1/", prefix + "/api/v1/signatures"}
		if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
			t.Errorf("base %q: paths %v, expected %v", base, paths, want)
		}
	}
}

func TestNewValidatesOptions(t *testing.T) {
	u, _ := url.Parse("https://x.example")
	bad := []Options{
		{Token: testToken}, // BaseURL missing
		{BaseURL: u},       // token missing (the API always requires one)
		{BaseURL: u, Token: "ssg_a\r\nX-Evil: 1"}, // header injection
		{BaseURL: u, Token: "ssg_a b"},            // whitespace
		{BaseURL: u, Token: testToken, CAFile: "/does/not/exist.pem"},
	}
	for i, o := range bad {
		if _, err := New(o); err == nil {
			t.Errorf("case %d: New should have failed", i)
		}
	}
	notPEM := filepath.Join(t.TempDir(), "x.pem")
	os.WriteFile(notPEM, []byte("not pem"), 0o600)
	if _, err := New(Options{BaseURL: u, Token: testToken, CAFile: notPEM}); err == nil {
		t.Error("ca-file without a certificate was accepted")
	}
}

func TestTimeParsing(t *testing.T) {
	ok := map[string]time.Time{
		`"2026-11-07 20:42:11"`:       time.Date(2026, 11, 7, 20, 42, 11, 0, time.UTC),
		`"2026-11-07T20:42:11Z"`:      time.Date(2026, 11, 7, 20, 42, 11, 0, time.UTC),
		`"2026-11-07T21:42:11+01:00"`: time.Date(2026, 11, 7, 20, 42, 11, 0, time.UTC),
	}
	for in, want := range ok {
		var tm Time
		if err := tm.UnmarshalJSON([]byte(in)); err != nil || !tm.Equal(want) {
			t.Errorf("%s -> %v, %v", in, tm.Time, err)
		}
	}
	var z Time
	if err := z.UnmarshalJSON([]byte(`null`)); err != nil || !z.IsZero() {
		t.Error("null must yield the zero time")
	}
	if err := z.UnmarshalJSON([]byte(`"morgen"`)); err == nil {
		t.Error("nonsense was accepted")
	}
}

// --- TLS ---------------------------------------------------------------

func TestTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, page([]map[string]any{item(1, "a@b.de")}, 50, 0))
	}))
	defer srv.Close()

	// 1. Unknown CA: must fail as a TLS error, without sending the token.
	if _, err := newTestClient(t, srv.URL, nil).Signatures(context.Background(), "a@b.de"); !errors.Is(err, ErrTLS) {
		t.Fatalf("without CA: err = %v, expected ErrTLS", err)
	}

	// 2. With the server's CA: works.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	got, err := newTestClient(t, srv.URL, func(o *Options) { o.CAFile = caFile }).Signatures(context.Background(), "a@b.de")
	if err != nil || len(got) != 1 {
		t.Fatalf("with CA: %v, %v", got, err)
	}

	// 3. For testing only: verification switched off.
	got, err = newTestClient(t, srv.URL, func(o *Options) { o.InsecureSkipVerify = true }).Signatures(context.Background(), "a@b.de")
	if err != nil || len(got) != 1 {
		t.Fatalf("insecure-skip-verify: %v, %v", got, err)
	}
}

func TestTLS12IsMinimum(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	_, err := newTestClient(t, srv.URL, func(o *Options) { o.InsecureSkipVerify = true }).Signatures(context.Background(), "a@b.de")
	if err == nil {
		t.Fatal("TLS 1.1 was accepted")
	}
}

// ---------- ReportStatus (POST /api/v1/status) ----------

type capturedStatusRequest struct {
	method string
	path   string
	auth   string
	body   statusReportRequest
}

func TestReportStatusRequestAndResponse(t *testing.T) {
	var got capturedStatusRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got.body); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"received":%d,"updated":%d}`, len(got.body.Items), len(got.body.Items))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	err := c.ReportStatus(context.Background(), "WIN-TEST-1", "1.6.0", []StatusItem{
		{SignatureID: 1, Status: "ok"},
		{SignatureID: 2, Status: "error", Message: "could not write registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/api/v1/status" {
		t.Errorf("method/path = %s %s", got.method, got.path)
	}
	if got.auth != "Bearer "+testToken {
		t.Errorf("Authorization = %q", got.auth)
	}
	if got.body.DeviceID != "WIN-TEST-1" || got.body.AgentVersion != "1.6.0" {
		t.Errorf("device_id/agent_version = %q/%q", got.body.DeviceID, got.body.AgentVersion)
	}
	if len(got.body.Items) != 2 || got.body.Items[0].Status != "ok" || got.body.Items[1].Message != "could not write registry" {
		t.Errorf("items = %+v", got.body.Items)
	}
}

func TestReportStatusSendsAppliedHash(t *testing.T) {
	var got capturedStatusRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got.body); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"received":3,"updated":3}`)
	}))
	defer srv.Close()

	valid := strings.Repeat("ab", 32)
	c := newTestClient(t, srv.URL, nil)
	err := c.ReportStatus(context.Background(), "dev-1", "", []StatusItem{
		{SignatureID: 1, Status: "ok", HTMLSHA256: valid},
		{SignatureID: 2, Status: "ok", HTMLSHA256: strings.ToUpper(valid)}, // normalised to lower case
		{SignatureID: 3, Status: "ok", HTMLSHA256: "not-a-hash"},           // dropped, report still sent
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.body.Items) != 3 {
		t.Fatalf("items = %+v", got.body.Items)
	}
	if got.body.Items[0].HTMLSHA256 != valid || got.body.Items[1].HTMLSHA256 != valid {
		t.Errorf("valid hashes not sent as lower-case hex: %+v", got.body.Items)
	}
	if got.body.Items[2].HTMLSHA256 != "" {
		t.Errorf("invalid hash must be left out, got %q", got.body.Items[2].HTMLSHA256)
	}
}

func TestReportStatusNoItemsSendsNoRequest(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)
	if err := c.ReportStatus(context.Background(), "dev-1", "", nil); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("an empty report must not cause a request")
	}
}

func TestReportStatusValidatesLocallyBeforeSending(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)

	cases := []struct {
		name     string
		deviceID string
		agentVer string
		items    []StatusItem
	}{
		{"empty device id", "", "", []StatusItem{{SignatureID: 1, Status: "ok"}}},
		{"device id starts with a separator", "-bad", "", []StatusItem{{SignatureID: 1, Status: "ok"}}},
		{"device id too long", strings.Repeat("a", 81), "", []StatusItem{{SignatureID: 1, Status: "ok"}}},
		{"invalid agent version", "dev-1", "1.0;rm -rf", []StatusItem{{SignatureID: 1, Status: "ok"}}},
		{"invalid status", "dev-1", "", []StatusItem{{SignatureID: 1, Status: "deleted"}}},
		{"non-positive signature id", "dev-1", "", []StatusItem{{SignatureID: 0, Status: "ok"}}},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			called = false
			if err := c.ReportStatus(context.Background(), c2.deviceID, c2.agentVer, c2.items); err == nil {
				t.Error("expected a validation error")
			}
			if called {
				t.Error("an invalid report must be rejected before any request is sent")
			}
		})
	}
}

func TestReportStatusForbiddenHintsAtScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiErr(w, http.StatusForbidden, "forbidden", "missing scope")
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)
	err := c.ReportStatus(context.Background(), "dev-1", "", []StatusItem{{SignatureID: 1, Status: "ok"}})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, expected ErrAuth", err)
	}
	if !strings.Contains(err.Error(), "status:write") {
		t.Errorf("err = %v, expected a hint mentioning status:write", err)
	}
}

func TestReportStatusBatchesLargeRequests(t *testing.T) {
	var batches [][]int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body statusReportRequest
		json.NewDecoder(r.Body).Decode(&body)
		var ids []int
		for _, it := range body.Items {
			ids = append(ids, int(it.SignatureID))
		}
		batches = append(batches, ids)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"received":%d,"updated":%d}`, len(body.Items), len(body.Items))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)

	const n = 450 // > 2x maxStatusItemsPerRequest (200): exercises 3 batches
	items := make([]StatusItem, n)
	for i := range items {
		items[i] = StatusItem{SignatureID: int64(i + 1), Status: "ok"}
	}
	if err := c.ReportStatus(context.Background(), "dev-1", "", items); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 {
		t.Fatalf("got %d requests, expected 3 (200+200+50)", len(batches))
	}
	if len(batches[0]) != 200 || len(batches[1]) != 200 || len(batches[2]) != 50 {
		t.Errorf("batch sizes = %d, %d, %d", len(batches[0]), len(batches[1]), len(batches[2]))
	}
}

func TestReportStatusStopsAtFirstFailingBatch(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			apiErr(w, http.StatusInternalServerError, "internal_error", "boom")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"received":1,"updated":1}`)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)

	items := make([]StatusItem, 201) // 2 batches
	for i := range items {
		items[i] = StatusItem{SignatureID: int64(i + 1), Status: "ok"}
	}
	err := c.ReportStatus(context.Background(), "dev-1", "", items)
	if !errors.Is(err, ErrServer) {
		t.Fatalf("err = %v, expected ErrServer", err)
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Errorf("sent %d requests, expected to stop after the first failure", requests)
	}
}
