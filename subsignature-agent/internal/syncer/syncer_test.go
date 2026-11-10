package syncer

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"subsignature-agent/internal/api"
	"subsignature-agent/internal/config"
	"subsignature-agent/internal/sigselect"
	"subsignature-agent/internal/thunderbird"
)

const (
	maxMail   = "max.mustermann@example.com"
	erikaMail = "erika.muster@example.com"
	nobody    = "nobody@example.com"
)

// ---------- test server ----------

const testToken = "ssg_tok"

// fakeServer mimics the SubSignature API v1 (list with email filter, error format).
type fakeServer struct {
	mu          sync.Mutex
	items       []map[string]any
	down        bool   // 503 for everything
	rateLimited string // if set: 429 rate_limited with this Retry-After
	ignoreEmail bool   // the server "forgets" the email filter and returns everything
	hits        map[string]int
	total       int
	pings       int
}

func row(id int64, user, email, tpl, source, updated, html string) map[string]any {
	return map[string]any{
		"id": id, "username": user, "name": "Person " + user, "role": "", "email": email, "phone": "",
		"template": tpl, "source": source, "created_at": updated, "updated_at": updated,
		"html": html, "html_sha256": fmt.Sprintf("marker-%d-%d", id, len(html)), "text": "",
	}
}

func newFake() *fakeServer {
	return &fakeServer{
		hits: map[string]int{},
		items: []map[string]any{
			// same address and template: duplicate cases (#3 has the same content as #1), plus a second template
			row(1, "max", maxMail, "signature_pro.html", "manual", "2026-11-01 08:00:00", "<p>Max Standard</p>"),
			row(2, "max", maxMail, "signature_pro.html", "csv", "2026-11-09 08:00:00", "<p>Max New</p>"),
			row(3, "max", maxMail, "signature_pro.html", "manual", "2026-11-01 08:00:00", "<p>Max Standard</p>"),
			row(4, "max", maxMail, "signature_short.html", "manual", "2026-10-01 08:00:00", "<p>Max Short</p>"),
			row(10, "erika", erikaMail, "signature_pro.html", "ldap", "2026-10-15 08:00:00", "<p>Erika v1</p>"),
		},
	}
}

func (f *fakeServer) setItems(items []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = items
}

func (f *fakeServer) edit(id int64, key string, val any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, it := range f.items {
		if it["id"] == id {
			it[key] = val
		}
	}
}

func (f *fakeServer) setDown(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = v
}

func (f *fakeServer) hitsFor(email string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[email]
}

func (f *fakeServer) totalHits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.total
}

func fakeErr(w http.ResponseWriter, status int, code string, hdr ...string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	for i := 0; i+1 < len(hdr); i += 2 {
		w.Header().Set(hdr[i], hdr[i+1])
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":"Test"}}`, code)
}

func (f *fakeServer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.total++
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			fakeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if f.rateLimited != "" {
			fakeErr(w, http.StatusTooManyRequests, "rate_limited", "Retry-After", f.rateLimited)
			return
		}
		if f.down {
			fakeErr(w, http.StatusServiceUnavailable, "")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.URL.Path == "/api/v1/" {
			f.pings++
			fmt.Fprintf(w, `{"service":"SubSignature","version":"1.4.0","api":"v1","token":"Test-Token","server_time":%q}`,
				time.Now().Add(90*time.Second).UTC().Format("2006-01-02T15:04:05+00:00"))
			return
		}
		if r.URL.Path != "/api/v1/signatures" {
			fakeErr(w, http.StatusNotFound, "not_found")
			return
		}
		email := r.URL.Query().Get("email")
		f.hits[email]++
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var hit []map[string]any
		for _, it := range f.items {
			if f.ignoreEmail || strings.EqualFold(it["email"].(string), email) {
				hit = append(hit, it)
			}
		}
		page := []map[string]any{}
		for i := offset; i < len(hit) && len(page) < limit; i++ {
			page = append(page, hit[i])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"count": len(page), "limit": limit, "offset": offset, "items": page})
	})
}

// ---------- test environment ----------

type env struct {
	t       *testing.T
	home    string
	profDir string
	cfg     *config.Config
	opt     Options
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newEnv(t *testing.T, serverURL string) *env {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	root := filepath.Join(home, ".thunderbird")
	profDir := filepath.Join(root, "abc123.default-release")
	must(t, os.MkdirAll(profDir, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "profiles.ini"), []byte(`[Profile0]
Name=default-release
IsRelative=1
Path=abc123.default-release
Default=1

[General]
StartWithLastProfile=1
Version=2
`), 0o644))
	// id1 and id3 have the same address (differing in case); id4 is a leftover without an account;
	// id5 has no signature on the server.
	must(t, os.WriteFile(filepath.Join(profDir, "prefs.js"), []byte(`# Mozilla User Preferences
user_pref("mail.account.account1.identities", "id1,id3");
user_pref("mail.account.account2.identities", "id2,id5");
user_pref("mail.identity.id1.useremail", "Max.Mustermann@Example.com");
user_pref("mail.identity.id2.useremail", "erika.muster@example.com");
user_pref("mail.identity.id3.useremail", "max.mustermann@example.com");
user_pref("mail.identity.id4.useremail", "orphaned@example.com");
user_pref("mail.identity.id5.useremail", "nobody@example.com");
`), 0o644))
	must(t, os.WriteFile(filepath.Join(profDir, "user.js"), []byte("user_pref(\"browser.own.setting\", 42);\n"), 0o644))

	cfg := config.Default()
	cfg.Server.URL = serverURL
	cfg.Server.AllowInsecureHTTP = strings.HasPrefix(serverURL, "http://")
	cfg.Server.Auth.TokenEnv = ""
	cfg.Server.Auth.Token = testToken
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, home: home, profDir: profDir, cfg: cfg,
		opt: Options{Home: home, StateDir: filepath.Join(home, "state"), Logger: discardLogger()}}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) run() (*Report, error) {
	e.t.Helper()
	return Run(context.Background(), e.cfg, e.opt)
}

func (e *env) sigFile(email string) string {
	return filepath.Join(e.profDir, SigDir, FileName(email))
}

func (e *env) read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func (e *env) userJS() string { return e.read(filepath.Join(e.profDir, "user.js")) }

// ---------- tests ----------

func TestFullFlowHTTP(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)

	// 1. First run
	rep, err := e.run()
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %v (%v)", rep.Errors, err)
	}
	if rep.Emails != 3 {
		t.Errorf("expected 3 distinct addresses (duplicate id1/id3 and leftover id4 do not count), got %d", rep.Emails)
	}
	if rep.FilesWritten != 2 || rep.PrefsChanged != 1 {
		t.Errorf("files=%d prefs=%d", rep.FilesWritten, rep.PrefsChanged)
	}
	if len(rep.Missing) != 1 || rep.Missing[0] != nobody {
		t.Errorf("Missing=%v", rep.Missing)
	}

	maxHTML := e.read(e.sigFile(maxMail))
	if !strings.Contains(maxHTML, "Max New") || strings.Contains(maxHTML, "Max Standard") || strings.Contains(maxHTML, "Short") {
		t.Errorf("expected the most recently changed signature (#2), got %q", maxHTML)
	}
	if !strings.Contains(maxHTML, `<meta charset="utf-8">`) {
		t.Errorf("HTML was not normalized: %q", maxHTML)
	}
	if !strings.Contains(e.read(e.sigFile(erikaMail)), "Erika v1") {
		t.Error("Erika's signature is missing")
	}
	if _, err := os.Stat(e.sigFile(nobody)); err == nil {
		t.Error("no file may be created for addresses without a server signature")
	}
	if fi, _ := os.Stat(e.sigFile(maxMail)); fi.Mode().Perm() != 0o600 {
		t.Errorf("permissions of the signature file: %v", fi.Mode().Perm())
	}

	js := e.userJS()
	if !strings.HasPrefix(js, "user_pref(\"browser.own.setting\", 42);\n") {
		t.Error("the user's line in user.js was modified")
	}
	prefs := thunderbird.ParsePrefs(js)
	maxPath := e.sigFile(maxMail)
	for _, id := range []string{"id1", "id3"} { // both identities with the same address
		p := "mail.identity." + id + "."
		if prefs[p+"attach_signature"] != true || prefs.String(p+"sig_file") != maxPath ||
			prefs.String(p+"sig_file-rel") != "[ProfD]"+SigDir+"/"+FileName(maxMail) {
			t.Errorf("%s set incorrectly", id)
		}
	}
	if prefs.String("mail.identity.id2.sig_file") != e.sigFile(erikaMail) {
		t.Error("id2 set incorrectly")
	}
	for _, id := range []string{"id4", "id5"} {
		if _, ok := prefs["mail.identity."+id+".sig_file"]; ok {
			t.Errorf("%s must not get an entry", id)
		}
	}
	if _, err := os.Stat(filepath.Join(e.profDir, "user.js.pre-subsignature")); err != nil {
		t.Error("backup of user.js is missing")
	}
	if _, err := os.Stat(filepath.Join(e.opt.StateDir, "state.json")); err != nil {
		t.Error("state.json is missing")
	}
	jsAfterFirst := js

	// 2. Second run: nothing to do (the server is asked anyway - there is no ETag).
	hitsBefore := fake.hitsFor(maxMail)
	rep, err = e.run()
	if err != nil || rep.Changed() {
		t.Fatalf("the second run must be quiet: changed=%v err=%v actions=%v", rep.Changed(), err, rep.Actions)
	}
	if fake.hitsFor(maxMail) != hitsBefore+1 {
		t.Error("every run must query the server in full")
	}
	if e.userJS() != jsAfterFirst {
		t.Error("user.js changed in the second run")
	}

	// 3. Server-side change: only the file changes, user.js does not (no Thunderbird restart needed).
	fake.edit(10, "html", "<p>Erika v2</p>")
	fake.edit(10, "html_sha256", "marker-new")
	rep, err = e.run()
	if err != nil || rep.FilesWritten != 1 || rep.PrefsChanged != 0 {
		t.Fatalf("change: files=%d prefs=%d err=%v", rep.FilesWritten, rep.PrefsChanged, err)
	}
	if !strings.Contains(e.read(e.sigFile(erikaMail)), "Erika v2") {
		t.Error("new content is missing")
	}
	if e.userJS() != jsAfterFirst {
		t.Error("user.js must not change when only the content changes")
	}

	// 4. Self-healing: file deleted -> it is written again ...
	must(t, os.Remove(e.sigFile(maxMail)))
	rep, err = e.run()
	if err != nil || rep.FilesWritten != 1 {
		t.Fatalf("healing: files=%d err=%v", rep.FilesWritten, err)
	}
	// ... and so is a file modified by hand.
	must(t, os.WriteFile(e.sigFile(maxMail), []byte("modified by hand"), 0o600))
	if _, err = e.run(); err != nil || !strings.Contains(e.read(e.sigFile(maxMail)), "Max New") {
		t.Fatalf("the modified file was not reset: %v", err)
	}
}

func TestServerDownKeepsEverything(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	if _, err := e.run(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before, js := e.read(e.sigFile(maxMail)), e.userJS()

	fake.setDown(true)
	rep, err := e.run()
	if err == nil || !errors.Is(err, api.ErrServer) {
		t.Fatalf("expected ErrServer, got %v", err)
	}
	if rep.Skipped != 0 {
		t.Errorf("a 5xx affects the single request, not the whole run: skipped=%d", rep.Skipped)
	}
	if rep.Changed() {
		t.Error("nothing may be changed during a server outage")
	}
	if e.read(e.sigFile(maxMail)) != before || e.userJS() != js {
		t.Error("files were modified during a server outage")
	}
	st := e.read(filepath.Join(e.opt.StateDir, "state.json"))
	if !strings.Contains(st, "last_error") {
		t.Error("the error should be recorded in the state")
	}

	// Server back: the error disappears.
	fake.setDown(false)
	if _, err := e.run(); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestWrongTokenIsAuthError(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.cfg.Server.Auth.Token = "ssg_falsch"
	rep, err := e.run()
	if !errors.Is(err, api.ErrAuth) || rep.Changed() {
		t.Fatalf("err=%v changed=%v", err, rep.Changed())
	}
	if _, statErr := os.Stat(e.sigFile(maxMail)); statErr == nil {
		t.Error("no file may be created without authentication")
	}
	// The server's brute-force protection: a wrong token may cost only ONE request, not one per address.
	if n := fake.totalHits(); n != 1 {
		t.Errorf("%d requests with a wrong token, expected 1", n)
	}
	if rep.Skipped != rep.Emails-1 {
		t.Errorf("skipped=%d of %d", rep.Skipped, rep.Emails)
	}
}

func TestMaliciousHTMLIsRejectedAndOldSignatureStays(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	_, _ = e.run()
	old := e.read(e.sigFile(erikaMail))

	fake.edit(10, "html", `<p>x</p><script>steal()</script>`)
	rep, err := e.run()
	if err == nil || len(rep.Errors) == 0 {
		t.Fatal("expected an error")
	}
	if e.read(e.sigFile(erikaMail)) != old {
		t.Error("the old signature must remain when the HTML is rejected")
	}
	// The fetch for Max continues anyway (an error for one address does not block the others).
	if rep.Emails != 3 {
		t.Errorf("emails=%d", rep.Emails)
	}
}

func TestTemplateSelectionAndMismatch(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)

	e.cfg.Signature.Template = "signature_short" // without .html, case does not matter
	if _, err := e.run(); !errors.Is(err, sigselect.ErrNoMatch) {
		t.Fatalf("expected ErrNoMatch (Erika has no template signature_short), got %v", err)
	}
	if !strings.Contains(e.read(e.sigFile(maxMail)), "Max Short") {
		t.Errorf("expected template signature_short, got %q", e.read(e.sigFile(maxMail)))
	}
	// Erika does not have this template: her file must not be created, the error is reported.
	if _, err := os.Stat(e.sigFile(erikaMail)); err == nil {
		t.Error("no file may be created without a match")
	}

	// Override per address
	e.cfg.Signature.Overrides = []config.Override{{Email: erikaMail, Template: "SIGNATURE_PRO.html"}}
	rep, err := e.run()
	if err != nil {
		t.Fatalf("err=%v rep=%+v", err, rep.Errors)
	}
	if !strings.Contains(e.read(e.sigFile(erikaMail)), "Erika v1") {
		t.Error("the override for Erika has no effect")
	}
}

func TestPreferSourceEndToEnd(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.cfg.Signature.PreferSources = []string{"manual"}
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	if got := e.read(e.sigFile(maxMail)); !strings.Contains(got, "Max Standard") {
		t.Errorf("manual should rank before csv, got %q", got)
	}
}

func TestSkipPolicyDoesNotTouchAmbiguousAddress(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.cfg.Signature.DuplicatePolicy = "skip"
	rep, err := e.run()
	if !errors.Is(err, sigselect.ErrAmbiguous) {
		t.Fatalf("err=%v", err)
	}
	if rep.Skipped != 0 {
		t.Error("an ambiguous address must not abort the run for the others")
	}
	if _, statErr := os.Stat(e.sigFile(maxMail)); statErr == nil {
		t.Error("an ambiguous address must not be applied")
	}
	if _, statErr := os.Stat(e.sigFile(erikaMail)); statErr != nil {
		t.Error("an unambiguous address must still be applied")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.opt.DryRun = true
	userBefore := e.userJS()

	rep, err := e.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Actions) == 0 || !strings.Contains(rep.Actions[0], "dry run") {
		t.Errorf("actions: %v", rep.Actions)
	}
	if e.userJS() != userBefore {
		t.Error("the dry run modified user.js")
	}
	if _, err := os.Stat(filepath.Join(e.profDir, SigDir)); err == nil {
		t.Error("the dry run created the signature folder")
	}
	if _, err := os.Stat(e.opt.StateDir); err == nil {
		t.Error("the dry run created state/lock")
	}
}

func TestExcludedAddressIsLeftAlone(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.cfg.Thunderbird.ExcludeEmails = []string{erikaMail}
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.sigFile(erikaMail)); err == nil {
		t.Error("an excluded address got a file")
	}
	if _, ok := thunderbird.ParsePrefs(e.userJS())["mail.identity.id2.sig_file"]; ok {
		t.Error("an excluded identity got an entry")
	}
}

func TestSigOptionsAreWritten(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	yes, no := true, false
	e.cfg.Thunderbird.SigOnReply, e.cfg.Thunderbird.SigOnForward, e.cfg.Thunderbird.SigBottom = &yes, &no, &yes
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	p := thunderbird.ParsePrefs(e.userJS())
	if p["mail.identity.id2.sig_on_reply"] != true || p["mail.identity.id2.sig_on_fwd"] != false || p["mail.identity.id2.sig_bottom"] != true {
		t.Errorf("options missing: %v", e.userJS())
	}
}

func TestCorruptUserJSBlockIsNotTouched(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	broken := "important\n" + thunderbird.BeginMarker + "\nno end\n"
	must(t, os.WriteFile(filepath.Join(e.profDir, "user.js"), []byte(broken), 0o644))
	_, err := e.run()
	if !errors.Is(err, thunderbird.ErrCorruptBlock) {
		t.Fatalf("err=%v", err)
	}
	if e.userJS() != broken {
		t.Error("the damaged user.js was modified")
	}
}

func TestNoProfile(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	must(t, os.RemoveAll(filepath.Join(e.home, ".thunderbird")))
	if _, err := e.run(); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("err=%v", err)
	}
}

func TestExplicitProfilePath(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	must(t, os.RemoveAll(filepath.Join(e.home, ".thunderbird", "profiles.ini")))
	e.cfg.Thunderbird.ProfilePath = e.profDir
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.read(e.sigFile(maxMail)), "Max New") {
		t.Error("the explicitly given profile was not used")
	}
}

func TestSecondInstanceIsRefused(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	lk, err := acquireLock(e.opt.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Close()
	if _, err := e.run(); !errors.Is(err, ErrBusy) {
		t.Fatalf("err=%v", err)
	}
	// A dry run needs no lock and runs anyway.
	e.opt.DryRun = true
	if _, err := e.run(); errors.Is(err, ErrBusy) {
		t.Fatal("a dry run must not fail on the lock")
	}
}

func TestTLSWithCAAndWithout(t *testing.T) {
	fake := newFake()
	srv := httptest.NewTLSServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)

	// Without CA: abort with a TLS error, nothing is written.
	rep, err := e.run()
	if !errors.Is(err, api.ErrTLS) {
		t.Fatalf("expected ErrTLS, got %v", err)
	}
	if rep.Changed() {
		t.Error("nothing may be written on a TLS error")
	}
	if fake.totalHits() != 0 {
		t.Error("the request (with the token) should never have reached the server")
	}

	// With ca-file: works.
	ca := filepath.Join(e.home, "ca.pem")
	must(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	e.cfg.Server.TLS.CAFile = ca
	if _, err := e.run(); err != nil {
		t.Fatalf("with CA: %v", err)
	}
	if !strings.Contains(e.read(e.sigFile(maxMail)), "Max New") {
		t.Error("no signature was written with the CA")
	}
}

func TestStatus(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	_, _ = e.run()
	lines, err := Status(e.cfg, e.opt)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"default-release", "id1", "id3", maxMail, "file: yes", "file: no", "signature #2 (signature_pro.html, source csv)"} {
		if !strings.Contains(all, want) {
			t.Errorf("%q missing:\n%s", want, all)
		}
	}
	if strings.Contains(all, "id4") {
		t.Error("the orphaned identity must not appear")
	}
}

func TestFileNameIsSafeAndCollisionFree(t *testing.T) {
	a, b := FileName("a+b@x.de"), FileName("a_b@x.de")
	if a == b {
		t.Fatal("addresses that would be sanitized to the same text must get different file names")
	}
	for _, in := range []string{"../../etc/passwd@x.de", "a/b@x.de", `a\b@x.de`, "ä@ü.de", strings.Repeat("x", 300) + "@x.de"} {
		n := FileName(in)
		if strings.ContainsAny(n, `/\`) || len(n) > 90 || !strings.HasSuffix(n, ".html") {
			t.Errorf("unsafe file name %q for %q", n, in)
		}
		if filepath.Base(n) != n {
			t.Errorf("the file name contains path components: %q", n)
		}
	}
	if FileName("x@y.de") != FileName("x@y.de") {
		t.Fatal("not stable")
	}
}

func TestNextDelay(t *testing.T) {
	cfg := config.Default() // interval 2h, jitter 5m, retry 10m
	inFull := func(err error) {
		t.Helper()
		for i := 0; i < 200; i++ {
			if d := NextDelay(cfg, err); d < 2*time.Hour || d > 2*time.Hour+5*time.Minute {
				t.Fatalf("%v: outside [2h, 2h5m]: %v", err, d)
			}
		}
	}
	inFull(nil)
	// Wrong token or HTTPS required: do not knock every ten minutes (the server's brute-force lockout).
	inFull(fmt.Errorf("Abruf: %w", api.ErrAuth))
	inFull(errors.Join(errors.New("x"), fmt.Errorf("y: %w", api.ErrHTTPSRequired)))

	// Transient (network, server, TLS, no profile yet): try again soon.
	for _, err := range []error{api.ErrServer, api.ErrUnreachable, api.ErrTLS, api.ErrProtocol, ErrNoProfile} {
		if d := NextDelay(cfg, fmt.Errorf("a: %w", err)); d != cfg.Sync.RetryInterval.Duration {
			t.Errorf("%v: %v, expected retry-interval", err, d)
		}
	}
	// Permanent (ambiguous, no matching template, rejected HTML): not the same error message every 10 minutes.
	inFull(fmt.Errorf("a: %w", sigselect.ErrNoMatch))
	inFull(fmt.Errorf("a: %w", sigselect.ErrAmbiguous))
	inFull(errors.New("HTML rejected"))
	// Mixed: a token error always wins (brute-force lockout).
	inFull(errors.Join(api.ErrServer, api.ErrAuth))
	// Mixed with something transient: try again soon.
	if d := NextDelay(cfg, errors.Join(sigselect.ErrAmbiguous, api.ErrServer)); d != cfg.Sync.RetryInterval.Duration {
		t.Errorf("gemischt: %v", d)
	}
	cfg.Sync.Jitter.Duration = 0
	if d := NextDelay(cfg, nil); d != 2*time.Hour {
		t.Errorf("without jitter: %v", d)
	}
}

func TestNextDelayHonoursRetryAfter(t *testing.T) {
	cfg := config.Default()
	rate := func(secs string) error {
		var err error
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fakeErr(w, 429, "rate_limited", "Retry-After", secs)
		}))
		defer srv.Close()
		e := newEnv(t, srv.URL)
		_, err = e.run()
		return err
	}
	for secs, want := range map[string]time.Duration{
		"30":    cfg.Sync.RetryInterval.Duration, // shorter than retry-interval: retry-interval applies
		"1800":  30 * time.Minute,                // longer: the server's wish
		"86400": time.Hour,                       // the client caps Retry-After at 1 h
	} {
		err := rate(secs)
		if !errors.Is(err, api.ErrRateLimited) {
			t.Fatalf("Retry-After %s: err=%v", secs, err)
		}
		if d := NextDelay(cfg, err); d != want {
			t.Errorf("Retry-After %s: %v, expected %v", secs, d, want)
		}
		if secs == "1800" { // never wait longer than the normal interval
			short := config.Default()
			short.Sync.Interval.Duration, short.Sync.RetryInterval.Duration = 20*time.Minute, 5*time.Minute
			if d := NextDelay(short, err); d != 20*time.Minute {
				t.Errorf("upper bound interval: %v", d)
			}
		}
	}
}

func TestDaemonRunsRepeatedlyAndReloads(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)

	cfg := e.cfg
	cfg.Sync.Interval.Duration = time.Hour // never fires in the test
	cfg.Sync.Jitter.Duration = 0
	reload := make(chan struct{}, 1)
	loads := 0
	load := func() (*config.Config, error) { loads++; return cfg, nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Daemon(ctx, load, e.opt, reload) }()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timeout: %s", what)
	}
	hits := func() int { return fake.hitsFor(maxMail) }

	waitFor("first run at start", func() bool { return hits() >= 1 })
	before := hits()
	reload <- struct{}{} // SIGHUP: reload the configuration and sync immediately
	waitFor("run after reload", func() bool { return hits() > before })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon did not stop")
	}
	if loads != 2 {
		t.Errorf("the configuration should be loaded at start and on reload, loads=%d", loads)
	}
	if !strings.Contains(e.read(e.sigFile(maxMail)), "Max New") {
		t.Error("the daemon wrote no signature")
	}
}

func TestDaemonRunOnStartFalse(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.cfg.Sync.RunOnStart = false
	e.cfg.Sync.Interval.Duration = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Daemon(ctx, func() (*config.Config, error) { return e.cfg, nil }, e.opt, nil)
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	if h := fake.hitsFor(maxMail); h != 0 {
		t.Errorf("with run-on-start=false nothing may be queried at start, hits=%d", h)
	}
}

// ---------- further cases of the real API ----------

func (e *env) addIdentity(id, account, email string) {
	e.t.Helper()
	f, err := os.OpenFile(filepath.Join(e.profDir, "prefs.js"), os.O_APPEND|os.O_WRONLY, 0o644)
	must(e.t, err)
	defer f.Close()
	_, err = fmt.Fprintf(f, "user_pref(\"mail.account.%s.identities\", %q);\nuser_pref(\"mail.identity.%s.useremail\", %q);\n", account, id, id, email)
	must(e.t, err)
}

func TestEmptyListMeansNoSignatureNotAnError(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	before := e.read(e.sigFile(erikaMail))

	// Erika's account is deactivated on the server: the API then simply returns nothing any more.
	fake.setItems(fake.items[:4])
	rep, err := e.run()
	if err != nil {
		t.Fatalf("no signature is not an error: %v", err)
	}
	if len(rep.Missing) != 2 { // nobody@ and erika@
		t.Errorf("Missing=%v", rep.Missing)
	}
	if e.read(e.sigFile(erikaMail)) != before || before == "" {
		t.Error("the local signature stays unchanged (nothing is deleted automatically)")
	}
}

func TestServerThatIgnoresEmailFilterCannotInstallForeignSignatures(t *testing.T) {
	fake := newFake()
	fake.ignoreEmail = true // returns all entries for EVERY request
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	rep, err := e.run()
	if err != nil {
		t.Fatalf("%v (%v)", err, rep.Errors)
	}
	if got := e.read(e.sigFile(erikaMail)); !strings.Contains(got, "Erika v1") || strings.Contains(got, "Max") {
		t.Errorf("Erika got %q", got)
	}
	if got := e.read(e.sigFile(maxMail)); strings.Contains(got, "Erika") {
		t.Errorf("Max got %q", got)
	}
	if _, statErr := os.Stat(e.sigFile(nobody)); statErr == nil {
		t.Error("the signature of someone else must never be installed for an address without entries of its own")
	}
	if len(rep.Missing) != 1 || rep.Missing[0] != nobody {
		t.Errorf("Missing=%v", rep.Missing)
	}
}

func TestSharedMailboxIsNotGuessed(t *testing.T) {
	fake := newFake()
	info := "info@example.com"
	fake.setItems(append(fake.items,
		row(20, "anna", info, "signature_pro.html", "manual", "2026-10-20 08:00:00", "<p>Anna</p>"),
		row(21, "bob", info, "signature_pro.html", "manual", "2026-10-21 08:00:00", "<p>Bob</p>"),
	))
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.addIdentity("id6", "account3", info)

	rep, err := e.run()
	if !errors.Is(err, sigselect.ErrAmbiguous) || !strings.Contains(err.Error(), "<username>") {
		t.Fatalf("err = %v, expected a hint at <username>", err)
	}
	if _, statErr := os.Stat(e.sigFile(info)); statErr == nil {
		t.Error("nothing may be guessed for a shared mailbox with two accounts")
	}
	if _, statErr := os.Stat(e.sigFile(maxMail)); statErr != nil {
		t.Error("the other addresses must still work")
	}
	if len(rep.Errors) != 1 {
		t.Errorf("errors=%v", rep.Errors)
	}

	e.cfg.Signature.Overrides = []config.Override{{Email: info, Username: "bob"}}
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	if got := e.read(e.sigFile(info)); !strings.Contains(got, "Bob") || strings.Contains(got, "Anna") {
		t.Errorf("with username=bob: %q", got)
	}
}

func TestRateLimitAbortsRun(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	before, js := e.read(e.sigFile(maxMail)), e.userJS()
	fake.mu.Lock()
	fake.rateLimited = "120"
	fake.mu.Unlock()
	hits := fake.totalHits()

	rep, err := e.run()
	if !errors.Is(err, api.ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if ra, ok := api.RetryAfter(err); !ok || ra != 2*time.Minute {
		t.Errorf("Retry-After = %v/%v", ra, ok)
	}
	if n := fake.totalHits() - hits; n != 1 {
		t.Errorf("%d requests despite 429, expected 1", n)
	}
	if rep.Skipped != rep.Emails-1 || rep.Changed() {
		t.Errorf("skipped=%d changed=%v", rep.Skipped, rep.Changed())
	}
	if e.read(e.sigFile(maxMail)) != before || e.userJS() != js {
		t.Error("nothing may be changed on a 429")
	}
}

func TestUnreachableServerAbortsRunAfterOneRequest(t *testing.T) {
	srv := httptest.NewServer(newFake().Handler())
	e := newEnv(t, srv.URL)
	srv.Close() // port closed
	rep, err := e.run()
	if !errors.Is(err, api.ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
	if len(rep.Errors) != 1 || rep.Skipped != rep.Emails-1 {
		t.Errorf("errors=%d skipped=%d of %d - with an unreachable server do not try every address individually",
			len(rep.Errors), rep.Skipped, rep.Emails)
	}
}

func TestHTTPSRequiredIsReportedClearly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fakeErr(w, 403, "https_required")
	}))
	defer srv.Close()
	e := newEnv(t, srv.URL)
	_, err := e.run()
	if !errors.Is(err, api.ErrHTTPSRequired) || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingTokenStopsBeforeAnyRequest(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	e.cfg.Server.Auth.Token = ""
	e.cfg.Server.Auth.TokenEnv = "SUBSIG_TEST_UNSET_TOKEN"
	if _, err := e.run(); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("err = %v", err)
	}
	if fake.totalHits() != 0 {
		t.Error("without a token no request may go out")
	}
}

func TestPing(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	res, err := Ping(context.Background(), e.cfg, e.opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Info.Service != "SubSignature" || res.Info.Token != "Test-Token" {
		t.Errorf("Info=%+v", res.Info)
	}
	if !res.HasSkew || res.Skew < 60*time.Second || res.Skew > 120*time.Second {
		t.Errorf("clock skew = %v/%v, expected about 90s", res.Skew, res.HasSkew)
	}
	e.cfg.Server.Auth.Token = "ssg_falsch"
	if _, err := Ping(context.Background(), e.cfg, e.opt); !errors.Is(err, api.ErrAuth) {
		t.Fatalf("err = %v", err)
	}
}
