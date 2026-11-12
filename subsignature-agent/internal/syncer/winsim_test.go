package syncer

// These tests play through the Windows side on Linux: an environment with
// GOOS=windows, an in-memory registry, files in a temp folder. They check the
// logic; they do not check the real access to Windows (registry_windows.go).

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"subsignature-agent/internal/config"
	"subsignature-agent/internal/outlook"
	"subsignature-agent/internal/platform"
	"subsignature-agent/internal/state"
)

const acctBase = `Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`

type winEnv struct {
	t       *testing.T
	home    string
	appData string
	local   string
	reg     *outlook.MemRegistry
	cfg     *config.Config
	opt     Options
	fake    *fakeServer
}

func sz(s string) outlook.Value { return outlook.StringValue(outlook.RegSZ, s) }

func newWinEnv(t *testing.T) *winEnv {
	t.Helper()
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)

	home := t.TempDir()
	w := &winEnv{t: t, home: home, fake: fake,
		appData: filepath.Join(home, "AppData", "Roaming"),
		local:   filepath.Join(home, "AppData", "Local"),
		reg:     outlook.NewMemRegistry()}
	vars := map[string]string{"APPDATA": w.appData, "LOCALAPPDATA": w.local, "ProgramData": filepath.Join(home, "ProgramData")}
	penv := platform.Env{GOOS: "windows", Home: home, Getenv: func(k string) string { return vars[k] }}
	must(t, os.MkdirAll(w.appData, 0o755))
	must(t, os.MkdirAll(w.local, 0o755))

	cfg := config.Default()
	cfg.Env = penv
	cfg.Server.URL = srv.URL
	cfg.Server.AllowInsecureHTTP = true
	cfg.Server.Auth.TokenEnv = ""
	cfg.Server.Auth.Token = testToken
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	w.cfg = cfg
	w.opt = Options{Env: penv, StateDir: filepath.Join(w.local, "subsignature-agent"), Registry: w.reg, Logger: discardLogger()}

	// This is what an Outlook 2016/365 looks like: default profile "Outlook", Setup key present.
	w.reg.Put(`Software\Microsoft\Office\16.0\Outlook`, "DefaultProfile", sz("Outlook"))
	w.reg.AddKey(`Software\Microsoft\Office\16.0\Outlook\Setup`)
	w.reg.Put(acctBase+`\00000001`, "Account Name", sz("Outlook Address Book")) // not a mail account
	return w
}

// imap creates a POP/IMAP account (address in the value "Email").
func (w *winEnv) imap(id, email string) string {
	key := acctBase + `\` + id
	w.reg.Put(key, "Account Name", sz("My account"))
	w.reg.Put(key, "Email", sz(email))
	return key
}

// exchange creates an Exchange account (Outlook names it after the address; no value "Email").
func (w *winEnv) exchange(id, email string) string {
	key := acctBase + `\` + id
	w.reg.Put(key, "Account Name", sz(email))
	return key
}

func (w *winEnv) run() (*Report, error) { w.t.Helper(); return Run(context.Background(), w.cfg, w.opt) }
func (w *winEnv) sigDir() string        { return filepath.Join(w.appData, "Microsoft", "Signatures") }
func (w *winEnv) sigFile(email, ext string) string {
	return filepath.Join(w.sigDir(), outlook.SignatureName("SubSignature", email)+ext)
}

func (w *winEnv) str(key, name string) (string, bool) {
	v, err := w.reg.Get(key, name)
	if err != nil {
		return "", false
	}
	s, _ := v.String()
	return s, true
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestWindowsOutlookOnly(t *testing.T) {
	w := newWinEnv(t)
	kMax := w.imap("00000002", "Max.Mustermann@Example.com")
	kErika := w.exchange("00000003", erikaMail)
	kNobody := w.imap("00000004", nobody)

	rep, err := w.run()
	if err != nil {
		t.Fatalf("%v (%v)", err, rep.Errors)
	}
	// 2 accounts + the roaming switch (disabled by default since 0.6.1)
	if rep.Emails != 3 || rep.FilesWritten != 2 || rep.PrefsChanged != 3 {
		t.Errorf("addresses=%d files=%d entries=%d, expected 3/2/3", rep.Emails, rep.FilesWritten, rep.PrefsChanged)
	}
	name := outlook.SignatureName("SubSignature", maxMail)
	if name != "SubSignature max.mustermann@example.com" {
		t.Fatalf("signature name = %q", name)
	}
	if htm := readFile(t, w.sigFile(maxMail, ".htm")); !strings.Contains(htm, "Max New") || strings.Contains(htm, "Erika") {
		t.Errorf(".htm = %q", htm)
	}
	for _, ext := range outlook.Extensions {
		if _, err := os.Stat(w.sigFile(erikaMail, ext)); err != nil {
			t.Errorf("file %s for Erika is missing", ext)
		}
	}
	for _, k := range []string{kMax, kErika} {
		for _, v := range []string{outlook.ValueNew, outlook.ValueReply} {
			if got, ok := w.str(k, v); !ok || !strings.HasPrefix(got, "SubSignature ") {
				t.Errorf("%s|%s = %q/%v", k, v, got, ok)
			}
		}
	}
	// Without a signature on the server: no file AND no registry entry (otherwise Outlook would point at nothing).
	if _, ok := w.str(kNobody, outlook.ValueNew); ok {
		t.Error("no default may be set for an address without a signature")
	}
	// Every write access hits only account keys and only the two values - plus
	// the two roaming switches in Outlook\Setup.
	if len(w.reg.Writes) != 6 {
		t.Errorf("%d write accesses, expected 6: %v", len(w.reg.Writes), w.reg.Writes)
	}
	setup := "set " + `Software\Microsoft\Office\16.0\Outlook\Setup|`
	for _, wr := range w.reg.Writes {
		account := strings.HasPrefix(wr, "set "+acctBase+`\0000000`) && (strings.HasSuffix(wr, "|"+outlook.ValueNew) || strings.HasSuffix(wr, "|"+outlook.ValueReply))
		roaming := wr == setup+outlook.ValueNoRoaming || wr == setup+outlook.ValueNoRoamingOld
		if !account && !roaming {
			t.Errorf("unexpected registry write access: %s", wr)
		}
	}

	// Second run: nothing to do.
	w.reg.Writes = nil
	rep, err = w.run()
	if err != nil || rep.Changed() || len(w.reg.Writes) != 0 {
		t.Fatalf("second run: err=%v changed=%v writes=%v", err, rep.Changed(), w.reg.Writes)
	}
}

func TestWindowsDryRunWritesNothing(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	w.cfg.Outlook.RoamingSignatures = "disable"
	w.opt.DryRun = true
	rep, err := w.run()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Actions) < 2 {
		t.Errorf("the dry run should show what would happen: %v", rep.Actions)
	}
	if len(w.reg.Writes) != 0 {
		t.Errorf("registry written in a dry run: %v", w.reg.Writes)
	}
	if _, err := os.Stat(filepath.Join(w.appData, "Microsoft")); err == nil {
		t.Error("no folder may be created in a dry run")
	}
	if _, err := os.Stat(w.opt.StateDir); err == nil {
		t.Error("no state may be created in a dry run")
	}
}

func TestWindowsRemoveRestoresPreviousValues(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	w.reg.Put(k, outlook.ValueNew, sz("My old signature")) // there was no "Reply-Forward Signature"
	must(t, os.MkdirAll(w.sigDir(), 0o755))
	own := filepath.Join(w.sigDir(), "My old signature.htm")
	must(t, os.WriteFile(own, []byte("<p>old</p>"), 0o644))

	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.str(k, outlook.ValueNew); !strings.HasPrefix(got, "SubSignature ") {
		t.Fatalf("New = %q", got)
	}
	// The previous value stays remembered even if the agent runs several times.
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}

	rep, err := Remove(w.cfg, w.opt)
	if err != nil {
		t.Fatalf("%v (%v)", err, rep.Errors)
	}
	if got, ok := w.str(k, outlook.ValueNew); !ok || got != "My old signature" {
		t.Errorf("New after remove = %q/%v, expected the earlier value", got, ok)
	}
	if _, ok := w.str(k, outlook.ValueReply); ok {
		t.Error("Reply did not exist before and must be absent again")
	}
	for _, ext := range outlook.Extensions {
		if _, err := os.Stat(w.sigFile(maxMail, ext)); err == nil {
			t.Errorf("file %s was not deleted", ext)
		}
	}
	if _, err := os.Stat(own); err != nil {
		t.Error("the user's own signature was deleted")
	}
	if _, err := os.Stat(filepath.Join(w.opt.StateDir, "state.json")); err == nil {
		t.Error("the state should be gone after remove")
	}
	// Once more: nothing left to do.
	rep, err = Remove(w.cfg, w.opt)
	if err != nil || len(rep.Actions) != 0 {
		t.Errorf("second remove: %v %v", err, rep.Actions)
	}
}

func TestWindowsRemoveLeavesUsersOwnChoiceAlone(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	w.reg.Put(k, outlook.ValueNew, sz("Chosen myself")) // the user switches in Outlook
	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.str(k, outlook.ValueNew); got != "Chosen myself" {
		t.Errorf("New = %q - remove may only undo what still points to the agent's signature", got)
	}
	if _, ok := w.str(k, outlook.ValueReply); ok {
		t.Error("Reply still pointed to the agent's signature and must be removed")
	}
}

func TestWindowsRemoveWithoutStateStillCleansUp(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	must(t, os.Remove(filepath.Join(w.opt.StateDir, "state.json")))
	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.str(k, outlook.ValueNew); ok {
		t.Error("without state the agent's entry must at least be removed")
	}
	if _, err := os.Stat(w.sigFile(maxMail, ".htm")); err == nil {
		t.Error("file not deleted")
	}
}

func TestWindowsRemoveDoesNotTrustStateFile(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	// Someone writes a foreign folder and name into the state file.
	victimDir := filepath.Join(w.home, "Documents")
	must(t, os.MkdirAll(victimDir, 0o755))
	victim := filepath.Join(victimDir, "Important.htm")
	must(t, os.WriteFile(victim, []byte("x"), 0o644))
	st, err := state.Load(filepath.Join(w.opt.StateDir, "state.json"))
	must(t, err)
	st.OutlookEntry(`Software\Fremd\1`).Dir, st.OutlookEntry(`Software\Fremd\1`).SigName = victimDir, "Important"
	st.OutlookEntry(`Software\Fremd\2`).Dir, st.OutlookEntry(`Software\Fremd\2`).SigName = w.sigDir(), `..\..\..\Documents\Important`
	// On Linux only "/" separates folders; so that the test really bites here, this spelling as well:
	st.OutlookEntry(`Software\Fremd\3`).Dir, st.OutlookEntry(`Software\Fremd\3`).SigName = w.sigDir(), "../../../../Documents/Important"
	must(t, st.Save())
	if _, err := os.Stat(filepath.Join(w.sigDir(), "../../../../Documents/Important.htm")); err != nil {
		t.Fatal("test setup is wrong: the path should point at the file")
	}

	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("remove deleted a file outside the signature folder")
	}
}

func TestWindowsEnforcesAndKeepsOriginalPreviousValue(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	w.reg.Put(k, outlook.ValueNew, sz("Original"))
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	w.reg.Put(k, outlook.ValueNew, sz("In between")) // the user switches, the agent sets it again
	rep, err := w.run()
	if err != nil || rep.PrefsChanged != 1 {
		t.Fatalf("err=%v entries=%d", err, rep.PrefsChanged)
	}
	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.str(k, outlook.ValueNew); got != "Original" {
		t.Errorf("New = %q, expected the value from before the FIRST change", got)
	}
}

func TestWindowsSetNewOnly(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	w.reg.Put(k, outlook.ValueReply, sz("Kurz"))
	no := false
	w.cfg.Outlook.SetReply = &no
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.str(k, outlook.ValueReply); got != "Kurz" {
		t.Errorf("Reply = %q, should stay untouched", got)
	}
	if got, _ := w.str(k, outlook.ValueNew); !strings.HasPrefix(got, "SubSignature ") {
		t.Errorf("New = %q", got)
	}
	// Both off: files yes, registry no (the user chooses).
	w2 := newWinEnv(t)
	k2 := w2.imap("00000002", maxMail)
	w2.cfg.Outlook.SetReply, w2.cfg.Outlook.SetNew = &no, &no
	w2.cfg.Outlook.RoamingSignatures = "keep"
	if _, err := w2.run(); err != nil {
		t.Fatal(err)
	}
	if _, ok := w2.str(k2, outlook.ValueNew); ok || len(w2.reg.Writes) != 0 {
		t.Errorf("registry written: %v", w2.reg.Writes)
	}
	if _, err := os.Stat(w2.sigFile(maxMail, ".htm")); err != nil {
		t.Error("file missing")
	}
}

func TestWindowsOldOutlookStoresBinary(t *testing.T) {
	w := newWinEnv(t)
	key := `Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\00000002`
	w.reg.Put(key, "Email", outlook.StringValue(outlook.RegBinary, maxMail))
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	v, err := w.reg.Get(key, outlook.ValueNew)
	if err != nil || v.Type != outlook.RegBinary {
		t.Fatalf("type = %d, err=%v - Outlook 2013 expects REG_BINARY", v.Type, err)
	}
	if s, _ := v.String(); !strings.HasPrefix(s, "SubSignature ") {
		t.Errorf("value = %q", s)
	}
}

func TestWindowsRedirectedSignatureFolderIsRefused(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	w.reg.Put(`Software\Microsoft\Office\16.0\Common\General`, "Signatures", sz(`..\..\..\Evil`))
	rep, err := w.run()
	if !errors.Is(err, outlook.ErrUnusualDir) {
		t.Fatalf("err = %v", err)
	}
	if rep.Changed() || len(w.reg.Writes) != 0 {
		t.Errorf("changed anyway: %v %v", rep.Actions, w.reg.Writes)
	}
	if _, ok := w.str(k, outlook.ValueNew); ok {
		t.Error("registry set")
	}
	if _, err := os.Stat(filepath.Join(w.home, "Evil")); err == nil {
		t.Error("written outside %APPDATA%\\Microsoft")
	}
}

func TestWindowsLocalizedSignatureFolder(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	w.reg.Put(`Software\Microsoft\Office\16.0\Common\General`, "Signatures", sz("Signaturen"))
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(w.appData, "Microsoft", "Signaturen", outlook.SignatureName("SubSignature", maxMail)+".htm")
	if _, err := os.Stat(p); err != nil {
		t.Errorf("file not in the folder from the registry: %v", err)
	}
}

func TestWindowsRoamingSignatures(t *testing.T) {
	setup := `Software\Microsoft\Office\16.0\Outlook\Setup`
	hasNote := func(rep *Report, part string) bool {
		for _, n := range rep.Notes {
			if strings.Contains(n, part) {
				return true
			}
		}
		return false
	}

	// keep: only a note, no change.
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	w.cfg.Outlook.RoamingSignatures = "keep"
	rep, err := w.run()
	if err != nil || !hasNote(rep, "roaming signatures are on") {
		t.Fatalf("err=%v notes=%v", err, rep.Notes)
	}
	if _, err := w.reg.Get(setup, outlook.ValueNoRoaming); err == nil {
		t.Fatal("without being told to, the switch must not be set")
	}

	// disable (the default since 0.6.1): both switches, and remove reverts them.
	w = newWinEnv(t)
	w.imap("00000002", maxMail)
	rep, err = w.run()
	if err != nil || hasNote(rep, "roaming signatures are on") {
		t.Fatalf("err=%v notes=%v", err, rep.Notes)
	}
	for _, n := range []string{outlook.ValueNoRoaming, outlook.ValueNoRoamingOld} {
		v, err := w.reg.Get(setup, n)
		if d, ok := v.DWORD(); err != nil || !ok || d != 1 {
			t.Errorf("%s = %v/%v", n, v, err)
		}
	}
	if rep2, _ := w.run(); rep2.Changed() {
		t.Errorf("the second run changes again: %v", rep2.Actions)
	}
	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if _, err := w.reg.Get(setup, outlook.ValueNoRoaming); err == nil {
		t.Error("remove did not revert the switch")
	}

	// Already disabled by group policy: do nothing, report nothing.
	w = newWinEnv(t)
	w.imap("00000002", maxMail)
	w.cfg.Outlook.RoamingSignatures = "disable"
	w.reg.Put(`Software\Policies\Microsoft\Office\16.0\Outlook\Setup`, outlook.ValueNoRoaming, outlook.DWORDValue(1))
	rep, _ = w.run()
	if hasNote(rep, "Roaming") || strings.Contains(strings.Join(w.reg.Writes, " "), "Setup") {
		t.Errorf("notes=%v writes=%v", rep.Notes, w.reg.Writes)
	}
}

func TestWindowsNewOutlookIsReportedNotFaked(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	w.reg.Put(`Software\Microsoft\Office\16.0\Outlook\Preferences`, "UseNewOutlook", outlook.DWORDValue(1))
	rep, err := w.run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Notes, "|"), "new Outlook is switched on") {
		t.Errorf("no note about the new Outlook: %v", rep.Notes)
	}

	// Only the new Outlook, nothing else: a clear error with an explanation.
	w = newWinEnv(t)
	must(t, os.MkdirAll(filepath.Join(w.local, "Packages", "Microsoft.OutlookForWindows_8wekyb3d8bbwe"), 0o755))
	rep, err = w.run()
	if !errors.Is(err, ErrNoProfile) || !strings.Contains(strings.Join(rep.Notes, "|"), "Only the new Outlook") {
		t.Errorf("err=%v notes=%v", err, rep.Notes)
	}
	if w.fake.totalHits() != 0 {
		t.Error("without a target the server must not be asked")
	}
}

func (w *winEnv) addThunderbird(emails ...string) string {
	root := filepath.Join(w.appData, "Thunderbird")
	prof := filepath.Join(root, "Profiles", "x1y2z3.default-release")
	must(w.t, os.MkdirAll(prof, 0o755))
	// This is how Thunderbird writes profiles.ini on Windows: relative path with "/".
	must(w.t, os.WriteFile(filepath.Join(root, "profiles.ini"), []byte("[Profile0]\r\nName=default-release\r\nIsRelative=1\r\nPath=Profiles/x1y2z3.default-release\r\nDefault=1\r\n"), 0o644))
	prefs := ""
	for i, e := range emails {
		id := "id" + string(rune('1'+i))
		prefs += `user_pref("mail.account.account` + string(rune('1'+i)) + `.identities", "` + id + `");` + "\r\n" +
			`user_pref("mail.identity.` + id + `.useremail", "` + e + `");` + "\r\n"
	}
	must(w.t, os.WriteFile(filepath.Join(prof, "prefs.js"), []byte(prefs), 0o644))
	return prof
}

func TestWindowsThunderbirdAndOutlookTogether(t *testing.T) {
	w := newWinEnv(t)
	prof := w.addThunderbird(maxMail, erikaMail)
	k := w.imap("00000002", maxMail)

	rep, err := w.run()
	if err != nil {
		t.Fatalf("%v (%v)", err, rep.Errors)
	}
	if rep.Emails != 2 {
		t.Errorf("addresses = %d", rep.Emails)
	}
	if n := w.fake.hitsFor(maxMail); n != 1 {
		t.Errorf("%d requests for the same address in two mail clients, expected 1", n)
	}
	js := readFile(t, filepath.Join(prof, "user.js"))
	if !strings.Contains(js, "[ProfD]subsignature/") || !strings.Contains(js, "mail.identity.id1.sig_file") {
		t.Errorf("user.js = %q", js)
	}
	if !strings.Contains(readFile(t, filepath.Join(prof, SigDir, FileName(maxMail))), "Max New") {
		t.Error("Thunderbird file missing")
	}
	if got, _ := w.str(k, outlook.ValueNew); got == "" {
		t.Error("Outlook not set")
	}

	// remove cleans up both mail clients.
	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if js := readFile(t, filepath.Join(prof, "user.js")); strings.Contains(js, "subsignature") {
		t.Errorf("user.js after remove: %q", js)
	}
	if _, err := os.Stat(filepath.Join(prof, SigDir)); err == nil {
		t.Error("the folder subsignature should be empty and removed")
	}
	if _, ok := w.str(k, outlook.ValueNew); ok {
		t.Error("the Outlook entry remained")
	}
}

func TestWindowsStoreThunderbirdIsFound(t *testing.T) {
	w := newWinEnv(t)
	root := filepath.Join(w.local, "Packages", "MozillaThunderbird.MZLA_h5892qc0xkpca", "LocalCache", "Roaming", "Thunderbird")
	prof := filepath.Join(root, "Profiles", "abc.default-release")
	must(t, os.MkdirAll(prof, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "profiles.ini"), []byte("[Profile0]\nName=store\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(prof, "prefs.js"), []byte(`user_pref("mail.account.account1.identities", "id1");`+"\n"+`user_pref("mail.identity.id1.useremail", "`+maxMail+`");`+"\n"), 0o644))
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(prof, SigDir, FileName(maxMail))); err != nil {
		t.Errorf("profile of the Store version not handled: %v", err)
	}
}

func TestWindowsExcludeAndDisable(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	w.imap("00000003", erikaMail)
	w.cfg.Thunderbird.ExcludeEmails = []string{maxMail} // the list applies to all mail clients
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.str(k, outlook.ValueNew); ok || w.fake.hitsFor(maxMail) != 0 {
		t.Error("an excluded address was touched or queried")
	}

	w = newWinEnv(t)
	w.imap("00000002", maxMail)
	off := false
	w.cfg.Outlook.Enabled = &off
	if _, err := w.run(); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("err = %v (Outlook off, no Thunderbird)", err)
	}
	if len(w.reg.Writes) != 0 {
		t.Error("Outlook is switched off")
	}
}

func TestWindowsRegistryErrorHitsOnlyThatAccount(t *testing.T) {
	w := newWinEnv(t)
	bad := w.imap("00000002", maxMail)
	good := w.imap("00000003", erikaMail)
	w.reg.FailOn = `\00000002`
	rep, err := w.run()
	if err == nil || len(rep.Errors) != 2 { // New and Reply of the one account
		t.Fatalf("err=%v errors=%d", err, len(rep.Errors))
	}
	if _, ok := w.str(bad, outlook.ValueNew); ok {
		t.Error("the failed entry is there anyway")
	}
	if got, _ := w.str(good, outlook.ValueNew); got == "" {
		t.Error("the other account must still work")
	}
}

func TestWindowsStatus(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	w.reg.Put(`Software\Microsoft\Office\16.0\Outlook\Preferences`, "UseNewOutlook", outlook.DWORDValue(1))
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	lines, err := Status(w.cfg, w.opt)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{`Outlook profile "Outlook" [Office 16.0]`, maxMail, "file: yes", "new: SubSignature", "New Outlook: switched on"} {
		if !strings.Contains(all, want) {
			t.Errorf("status without %q:\n%s", want, all)
		}
	}
}

// On Linux there is no Outlook: even with a (planted) registry nothing is touched.
func TestLinuxNeverTouchesOutlook(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	reg := outlook.NewMemRegistry()
	reg.Put(acctBase+`\00000002`, "Email", sz(maxMail))
	e.opt.Registry = reg
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	if len(reg.Writes) != 0 {
		t.Errorf("registry written on Linux: %v", reg.Writes)
	}
	lines, _ := Status(e.cfg, e.opt)
	for _, l := range lines { // (the temp path contains the test name, hence the targeted check)
		if strings.HasPrefix(l, "Outlook") || strings.HasPrefix(l, "New Outlook") {
			t.Errorf("status mentions Outlook on Linux: %s", l)
		}
	}
}

func TestRemoveThunderbirdOnLinux(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	e := newEnv(t, srv.URL)
	if _, err := e.run(); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(e.profDir, SigDir, "own-note.html") // does not match the agent's naming pattern
	must(t, os.WriteFile(foreign, []byte("x"), 0o600))

	e.opt.DryRun = true
	rep, err := Remove(e.cfg, e.opt)
	if err != nil || len(rep.Actions) == 0 || !strings.Contains(e.userJS(), "subsignature-agent managed block") {
		t.Fatalf("remove check: err=%v actions=%v - the dry run must not change anything", err, rep.Actions)
	}
	e.opt.DryRun = false
	rep, err = Remove(e.cfg, e.opt)
	if err != nil {
		t.Fatalf("%v (%v)", err, rep.Errors)
	}
	js := e.userJS()
	if strings.Contains(js, "subsignature") || !strings.Contains(js, `user_pref("browser.own.setting", 42);`) {
		t.Errorf("user.js after remove = %q", js)
	}
	if _, err := os.Stat(e.sigFile(maxMail)); err == nil {
		t.Error("the signature file remained")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("a foreign file in the folder was deleted")
	}
	if len(rep.Notes) == 0 {
		t.Error("the note about the remaining setting in Thunderbird is missing")
	}
}

// Field report (agent 0.5.0, Microsoft 365, IMAP): the account's texts are
// REG_BINARY, the agent wrote "New Signature" as REG_BINARY too, and Outlook
// listed the signature but did not use it. Outlook 2016+ only reads REG_SZ.
func TestWindowsOutlook2016BinaryAccountGetsStringDefault(t *testing.T) {
	w := newWinEnv(t)
	key := acctBase + `\00000002`
	w.reg.Put(key, "Account Name", outlook.StringValue(outlook.RegBinary, maxMail))
	w.reg.Put(key, "Email", outlook.StringValue(outlook.RegBinary, maxMail))
	name := outlook.SignatureName("SubSignature", maxMail)
	// What 0.5.0 left behind: the right name, the wrong type.
	w.reg.Put(key, outlook.ValueNew, outlook.StringValue(outlook.RegBinary, name))
	w.reg.Put(key, outlook.ValueReply, outlook.StringValue(outlook.RegBinary, name))

	rep, err := w.run()
	if err != nil {
		t.Fatal(err)
	}
	for _, vn := range []string{outlook.ValueNew, outlook.ValueReply} {
		v, err := w.reg.Get(key, vn)
		if err != nil || v.Type != outlook.RegSZ {
			t.Fatalf("%s: type %d, err %v - Outlook 2016+ only reads REG_SZ", vn, v.Type, err)
		}
		if s, _ := v.String(); s != name {
			t.Errorf("%s = %q", vn, s)
		}
	}
	if rep.PrefsChanged == 0 {
		t.Error("rewriting the type must count as a change")
	}
	// Second run: nothing left to do.
	w.reg.Writes = nil
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if len(w.reg.Writes) != 0 {
		t.Errorf("second run wrote again: %v", w.reg.Writes)
	}
}

// Thunderbird and Outlook on one PC with the same address: each mail client is
// reported as its own device, an edit on the server reaches both, and an error
// in one client marks only that client as failed.
func TestWindowsStatusReportPerMailClient(t *testing.T) {
	w := newWinEnv(t)
	w.addThunderbird(erikaMail)
	w.imap("00000002", erikaMail)

	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(filepath.Join(w.opt.StateDir, "state.json"))
	if err != nil || st.DeviceID == "" {
		t.Fatalf("device id not persisted: %v", err)
	}
	base := st.DeviceID
	byDevice := func() map[string]fakeStatusReport {
		m := map[string]fakeStatusReport{}
		for _, r := range w.fake.statusReportsCopy() {
			m[r.DeviceID] = r // later reports of the same device replace earlier ones
		}
		return m
	}
	got := byDevice()
	tb, ol := got[base+" Thunderbird"], got[base+" Outlook"]
	if len(got) != 2 || len(tb.Items) != 1 || len(ol.Items) != 1 {
		t.Fatalf("reports = %+v, expected one per mail client", got)
	}
	if tb.Items[0].Status != "ok" || ol.Items[0].Status != "ok" || ol.Items[0].HTMLSHA256 != w.fake.itemField(10, "html_sha256") {
		t.Errorf("first run: thunderbird=%+v outlook=%+v", tb.Items[0], ol.Items[0])
	}

	// The signature is edited on the server: the next run rewrites the Outlook files too.
	w.fake.edit(10, "html", "<p>Erika v2</p>")
	w.fake.edit(10, "html_sha256", htmlHash("<p>Erika v2</p>"))
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, w.sigFile(erikaMail, ".htm")), "Erika v2") {
		t.Error("Outlook .htm was not updated after the edit on the server")
	}
	if ol := byDevice()[base+" Outlook"]; ol.Items[0].HTMLSHA256 != htmlHash("<p>Erika v2</p>") {
		t.Errorf("Outlook reported %q, expected the new version", ol.Items[0].HTMLSHA256)
	}

	// Outlook cannot write its file (here: a folder in its place); Thunderbird can.
	w.fake.edit(10, "html", "<p>Erika v3</p>")
	w.fake.edit(10, "html_sha256", htmlHash("<p>Erika v3</p>"))
	must(t, os.Remove(w.sigFile(erikaMail, ".htm")))
	must(t, os.MkdirAll(filepath.Join(w.sigFile(erikaMail, ".htm"), "blocker"), 0o755))
	if _, err := w.run(); err == nil {
		t.Fatal("expected an error for the Outlook file")
	}
	got = byDevice()
	if s := got[base+" Thunderbird"].Items[0].Status; s != "ok" {
		t.Errorf("Thunderbird = %q, an Outlook error must not mark Thunderbird as failed", s)
	}
	if it := got[base+" Outlook"].Items[0]; it.Status != "error" || it.Message == "" {
		t.Errorf("Outlook = %+v, expected error with a message", it)
	}
}

func hasNotePart(rep *Report, part string) bool {
	for _, n := range rep.Notes {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

// While Outlook runs, remove leaves Outlook alone (Outlook would write its old
// values back when it closes and keeps showing the signature until a restart).
func TestWindowsRemoveWaitsForOutlookToClose(t *testing.T) {
	w := newWinEnv(t)
	prof := w.addThunderbird(maxMail)
	k := w.imap("00000002", maxMail)
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}

	running := true
	w.opt.OutlookRunning = func() bool { return running }
	w.reg.Writes = nil
	if _, err := Remove(w.cfg, w.opt); !errors.Is(err, ErrOutlookRunning) {
		t.Fatalf("err = %v, expected ErrOutlookRunning", err)
	}
	if len(w.reg.Writes) != 0 {
		t.Errorf("registry changed while Outlook runs: %v", w.reg.Writes)
	}
	if _, err := os.Stat(w.sigFile(maxMail, ".htm")); err != nil {
		t.Error("Outlook file deleted while Outlook runs")
	}
	if js := readFile(t, filepath.Join(prof, "user.js")); strings.Contains(js, "subsignature") {
		t.Error("Thunderbird must be cleaned up anyway")
	}

	// Outlook closed: the second remove finishes the job (the state was kept).
	running = false
	if _, err := Remove(w.cfg, w.opt); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.str(k, outlook.ValueNew); ok {
		t.Error("default signature still set")
	}
	if _, err := os.Stat(w.sigFile(maxMail, ".htm")); err == nil {
		t.Error("Outlook file still there")
	}
	if _, err := w.reg.Get(`Software\Microsoft\Office\16.0\Outlook\Setup`, outlook.ValueNoRoaming); err == nil {
		t.Error("roaming switch not reverted")
	}
}

func TestWindowsSyncWhileOutlookRuns(t *testing.T) {
	w := newWinEnv(t)
	k := w.imap("00000002", maxMail)
	w.opt.OutlookRunning = func() bool { return true }
	rep, err := w.run()
	if err != nil {
		t.Fatal(err)
	}
	// Written anyway (Outlook applies it after a restart), but the user is told.
	if got, _ := w.str(k, outlook.ValueNew); !strings.HasPrefix(got, "SubSignature ") {
		t.Errorf("New = %q", got)
	}
	if !hasNotePart(rep, "Outlook is running") {
		t.Errorf("notes = %v", rep.Notes)
	}
	lines, err := Status(w.cfg, w.opt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "Outlook (classic): running") {
		t.Errorf("status does not say that Outlook runs:\n%s", strings.Join(lines, "\n"))
	}
}

// Outlook's roaming signatures overwrite the agent's file: detected, reported
// in status, and rewritten by the next sync.
func TestWindowsOutlookFileChangedOutsideTheAgent(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(w.sigFile(maxMail, ".htm"), []byte("<p>old cloud copy</p>"), 0o600))

	lines, _ := Status(w.cfg, w.opt)
	if !strings.Contains(strings.Join(lines, "\n"), "CHANGED OUTSIDE THE AGENT") {
		t.Errorf("status:\n%s", strings.Join(lines, "\n"))
	}
	rep, err := w.run()
	if err != nil {
		t.Fatal(err)
	}
	if !hasNotePart(rep, "changed outside the agent") {
		t.Errorf("notes = %v", rep.Notes)
	}
	if !strings.Contains(readFile(t, w.sigFile(maxMail, ".htm")), "Max New") {
		t.Error("file not rewritten")
	}
	lines, _ = Status(w.cfg, w.opt)
	if strings.Contains(strings.Join(lines, "\n"), "CHANGED OUTSIDE") {
		t.Error("still reported as changed after the rewrite")
	}
}

// A NewSignature/ReplySignature in Common\MailSettings (group policy or a
// leftover) can override the per-account default: reported, never written.
func TestWindowsForcedDefaultSignatureIsReported(t *testing.T) {
	w := newWinEnv(t)
	w.imap("00000002", maxMail)
	w.reg.Put(`Software\Policies\Microsoft\Office\16.0\Common\MailSettings`, "NewSignature", outlook.StringValue(outlook.RegExpandSZ, "Corporate"))
	rep, err := w.run()
	if err != nil {
		t.Fatal(err)
	}
	if !hasNotePart(rep, `NewSignature is fixed to "Corporate" by a group policy`) {
		t.Errorf("notes = %v", rep.Notes)
	}
	for _, wr := range w.reg.Writes {
		if strings.Contains(wr, "MailSettings") {
			t.Errorf("MailSettings must never be written: %s", wr)
		}
	}
	lines, _ := Status(w.cfg, w.opt)
	if !strings.Contains(strings.Join(lines, "\n"), "WARNING: NewSignature fixed to \"Corporate\" by group policy") {
		t.Errorf("status:\n%s", strings.Join(lines, "\n"))
	}
}
