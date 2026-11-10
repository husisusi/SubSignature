package thunderbird

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"subsignature-agent/internal/platform"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParsePrefs(t *testing.T) {
	p := ParsePrefs(`# Mozilla User Preferences
user_pref("mail.identity.id1.fullName", "Müller \"Max\" \\ x");
user_pref("mail.identity.id1.attach_signature", true);
user_pref("mail.identity.id1.reply_on_top", 1);
user_pref("mail.identity.id1.useremail", "max@example.com");
// user_pref("commented.out", "yes");
  user_pref( "with.whitespace" , "ok" ) ;
user_pref("kaputt", ;
`)
	if got := p.String("mail.identity.id1.fullName"); got != `Müller "Max" \ x` {
		t.Errorf("fullName: %q", got)
	}
	if p["mail.identity.id1.attach_signature"] != true {
		t.Error("bool")
	}
	if p["mail.identity.id1.reply_on_top"] != float64(1) {
		t.Error("int")
	}
	if _, ok := p["commented.out"]; ok {
		t.Error("a comment was read")
	}
	if p.String("with.whitespace") != "ok" {
		t.Error("Leerraum")
	}
	if _, ok := p["kaputt"]; ok {
		t.Error("broken line was read")
	}
}

func TestIdentities(t *testing.T) {
	p := ParsePrefs(`
user_pref("mail.account.account1.identities", "id1,id10");
user_pref("mail.account.account2.identities", "id2");
user_pref("mail.identity.id1.useremail", "  Max@Example.COM ");
user_pref("mail.identity.id2.useremail", "erika@example.com");
user_pref("mail.identity.id3.useremail", "orphaned@example.com");
user_pref("mail.identity.id10.useremail", "max@example.com");
user_pref("mail.identity.id1.fullName", "Max");
user_pref("mail.identity.default.useremail", "template@example.com");
`)
	ids := Identities(p)
	if len(ids) != 3 {
		t.Fatalf("expected 3 (orphaned one and template omitted), got %+v", ids)
	}
	// natural sort order: id1, id2, id10
	if ids[0].ID != "id1" || ids[1].ID != "id2" || ids[2].ID != "id10" {
		t.Errorf("Reihenfolge: %+v", ids)
	}
	if ids[0].Email != "max@example.com" || ids[0].FullName != "Max" {
		t.Errorf("normalization: %+v", ids[0])
	}
	if ids[0].Email != ids[2].Email {
		t.Error("the same address in two identities must be kept")
	}
}

func TestIdentitiesWithoutAccountLinksFallBackToAll(t *testing.T) {
	ids := Identities(ParsePrefs(`user_pref("mail.identity.id1.useremail", "a@b.de");`))
	if len(ids) != 1 {
		t.Fatalf("%+v", ids)
	}
}

func TestLoadEffectiveUserJSWinsAndIgnoresOwnBlock(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "prefs.js"), `user_pref("a", "prefs");
user_pref("mail.identity.id1.useremail", "old@example.com");
`)
	write(t, filepath.Join(dir, "user.js"), `user_pref("a", "user");
`+BeginMarker+`
user_pref("mail.identity.id1.useremail", "from-block@example.com");
`+EndMarker+`
`)
	p, err := LoadEffective(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.String("a") != "user" {
		t.Error("user.js must override prefs.js")
	}
	if p.String("mail.identity.id1.useremail") != "old@example.com" {
		t.Error("our block must not be read as a user setting")
	}
	if _, err := LoadEffective(t.TempDir()); err != nil {
		t.Fatalf("empty profile: %v", err)
	}
}

func TestReadRootInstallSectionWins(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "profiles.ini"), `[Install4F96D1932A9F858E]
Default=zwei.default-release
Locked=1

[Profile1]
Name=old
IsRelative=1
Path=eins.default
Default=1

[Profile0]
Name=default-release
IsRelative=1
Path=zwei.default-release

[Profile2]
Name=absolute
IsRelative=0
Path=/opt/tb/three

[General]
StartWithLastProfile=1
Version=2
`)
	profs, err := ReadRoot(Root{root, "native"})
	if err != nil || len(profs) != 3 {
		t.Fatalf("%+v %v", profs, err)
	}
	var def []string
	for _, p := range profs {
		if p.IsDefault {
			def = append(def, p.Name)
		}
		if p.Name == "absolute" && p.Dir != "/opt/tb/three" {
			t.Errorf("absolute path: %q", p.Dir)
		}
	}
	if len(def) != 1 || def[0] != "default-release" {
		t.Fatalf("[Install...] must override Default=1, got %v", def)
	}
}

func TestReadRootSingleProfileIsDefaultAndMissingIniIsFine(t *testing.T) {
	root := t.TempDir()
	if profs, err := ReadRoot(Root{root, "native"}); err != nil || profs != nil {
		t.Fatalf("without profiles.ini: %v %v", profs, err)
	}
	write(t, filepath.Join(root, "profiles.ini"), "[Profile0]\nName=x\nIsRelative=1\nPath=x.default\n")
	profs, _ := ReadRoot(Root{root, "native"})
	if len(profs) != 1 || !profs[0].IsDefault {
		t.Fatalf("%+v", profs)
	}
}

func TestDiscoverDedupesSymlinkedRoots(t *testing.T) {
	home := t.TempDir()
	native := filepath.Join(home, ".thunderbird")
	write(t, filepath.Join(native, "profiles.ini"), "[Profile0]\nName=p\nIsRelative=1\nPath=abc.default\nDefault=1\n")
	if err := os.MkdirAll(filepath.Join(native, "abc.default"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The Snap path is a link to ~/.thunderbird (happens according to the Mozilla forum).
	snapRoot := filepath.Join(home, "snap", "thunderbird", "common")
	if err := os.MkdirAll(snapRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(native, filepath.Join(snapRoot, ".thunderbird")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	profs, err := Discover(CandidateRoots(platform.Env{GOOS: "linux", Home: home}), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(profs) != 1 {
		t.Fatalf("the same profile via two paths must appear only once: %+v", profs)
	}
}

func TestDiscoverSkipsMissingDirsAndHonorsAll(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".thunderbird")
	write(t, filepath.Join(root, "profiles.ini"), `[Profile0]
Name=a
IsRelative=1
Path=a.default
Default=1
[Profile1]
Name=b
IsRelative=1
Path=b.default
[Profile2]
Name=weg
IsRelative=1
Path=not-there
`)
	for _, d := range []string{"a.default", "b.default"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if p, _ := Discover(CandidateRoots(platform.Env{GOOS: "linux", Home: home}), false); len(p) != 1 || p[0].Name != "a" {
		t.Fatalf("default only: %+v", p)
	}
	if p, _ := Discover(CandidateRoots(platform.Env{GOOS: "linux", Home: home}), true); len(p) != 2 {
		t.Fatalf("all existing ones: %+v", p)
	}
}

func TestRenderBlock(t *testing.T) {
	yes, no := true, false
	b := RenderBlock([]SigPref{{
		IdentityID: "id1", FilePath: `/home/u/.thunderbird/x/subsignature/a "b".html`, RelPath: "subsignature/a-1.html",
		OnReply: &yes, OnForward: &no,
	}})
	for _, want := range []string{
		BeginMarker, EndMarker,
		`user_pref("mail.identity.id1.attach_signature", true);`,
		`user_pref("mail.identity.id1.htmlSigFormat", true);`,
		`user_pref("mail.identity.id1.sig_file", "/home/u/.thunderbird/x/subsignature/a \"b\".html");`,
		`user_pref("mail.identity.id1.sig_file-rel", "[ProfD]subsignature/a-1.html");`,
		`user_pref("mail.identity.id1.sig_on_reply", true);`,
		`user_pref("mail.identity.id1.sig_on_fwd", false);`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("missing: %s\n---\n%s", want, b)
		}
	}
	if strings.Contains(b, "sig_bottom") {
		t.Error("options that are not set must not appear")
	}
	if RenderBlock(nil) != "" {
		t.Error("without entries the block must be empty")
	}
	// The generated block must be readable as prefs again (round trip).
	p := ParsePrefs(b)
	if p.String("mail.identity.id1.sig_file") != `/home/u/.thunderbird/x/subsignature/a "b".html` {
		t.Errorf("round trip: %q", p.String("mail.identity.id1.sig_file"))
	}
}

func TestMergeBlock(t *testing.T) {
	block := RenderBlock([]SigPref{{IdentityID: "id1", FilePath: "/x/a.html", RelPath: "subsignature/a.html"}})
	user := "user_pref(\"browser.own\", 1);\n// a comment by the user\n"

	// append, the user's content stays
	m1, err := MergeBlock(user, block)
	if err != nil || !strings.HasPrefix(m1, user) || !strings.HasSuffix(m1, block) {
		t.Fatalf("append: %v\n%s", err, m1)
	}
	// idempotent
	m2, _ := MergeBlock(m1, block)
	if m2 != m1 {
		t.Fatalf("not idempotent:\n%s\n---\n%s", m1, m2)
	}
	// replace
	block2 := RenderBlock([]SigPref{{IdentityID: "id2", FilePath: "/x/b.html", RelPath: "subsignature/b.html"}})
	m3, _ := MergeBlock(m1, block2)
	if strings.Contains(m3, "id1") || !strings.Contains(m3, "id2") || !strings.HasPrefix(m3, user) {
		t.Fatalf("ersetzen:\n%s", m3)
	}
	// remove -> exactly the original user content
	m4, _ := MergeBlock(m3, "")
	if m4 != user {
		t.Fatalf("entfernen:\n%q\n%q", m4, user)
	}
	// block in the middle of the file: the lines before and after stay
	mid := "A\n\n" + block + "B\n"
	m5, err := MergeBlock(mid, block2)
	if err != nil || !strings.HasPrefix(m5, "A\n") || !strings.Contains(m5, "B\n") || strings.Contains(m5, "id1") {
		t.Fatalf("mitten:\n%s %v", m5, err)
	}
	// empty file
	if m, _ := MergeBlock("", block); m != block {
		t.Fatalf("leer: %q", m)
	}
	if m, _ := MergeBlock("", ""); m != "" {
		t.Fatalf("leer/leer: %q", m)
	}
}

func TestMergeBlockRefusesCorruptMarkers(t *testing.T) {
	block := RenderBlock([]SigPref{{IdentityID: "id1", FilePath: "/x", RelPath: "y"}})
	for name, in := range map[string]string{
		"begin only":  "A\n" + BeginMarker + "\nB\n",
		"end only":    "A\n" + EndMarker + "\n",
		"wrong order": EndMarker + "\n" + BeginMarker + "\n",
		"doppelt":     block + block,
	} {
		if _, err := MergeBlock(in, block); err != ErrCorruptBlock {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestUpdateUserJS(t *testing.T) {
	dir := t.TempDir()
	block := RenderBlock([]SigPref{{IdentityID: "id1", FilePath: "/x/a.html", RelPath: "subsignature/a.html"}})
	userJS := filepath.Join(dir, "user.js")

	// Without a block and without a file: create nothing.
	if changed, err := UpdateUserJS(dir, "", false); changed || err != nil {
		t.Fatalf("leer: %v %v", changed, err)
	}
	if _, err := os.Stat(userJS); !os.IsNotExist(err) {
		t.Fatal("user.js must not be created without reason")
	}

	// A dry run writes nothing.
	write(t, userJS, "user_pref(\"own\", true);\n")
	if changed, _ := UpdateUserJS(dir, block, true); !changed {
		t.Fatal("the dry run must report the change")
	}
	if b, _ := os.ReadFile(userJS); string(b) != "user_pref(\"own\", true);\n" {
		t.Fatal("the dry run wrote something")
	}

	// First real change: backup + block.
	if changed, err := UpdateUserJS(dir, block, false); !changed || err != nil {
		t.Fatalf("schreiben: %v %v", changed, err)
	}
	bak, err := os.ReadFile(userJS + ".pre-subsignature")
	if err != nil || string(bak) != "user_pref(\"own\", true);\n" {
		t.Fatalf("backup: %q %v", bak, err)
	}
	// Second run: unchanged.
	if changed, _ := UpdateUserJS(dir, block, false); changed {
		t.Fatal("the second run must not change anything")
	}
	// The backup is not overwritten when the block changes later.
	block2 := RenderBlock([]SigPref{{IdentityID: "id2", FilePath: "/x/b.html", RelPath: "subsignature/b.html"}})
	if changed, _ := UpdateUserJS(dir, block2, false); !changed {
		t.Fatal("change not detected")
	}
	if b, _ := os.ReadFile(userJS + ".pre-subsignature"); string(b) != "user_pref(\"own\", true);\n" {
		t.Fatal("the backup was overwritten")
	}
	if fi, _ := os.Stat(userJS); fi.Mode().Perm() != 0o644 {
		t.Errorf("the permissions of the existing file must be kept: %v", fi.Mode().Perm())
	}
}

func TestUpdateUserJSFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(t.TempDir(), "dotfiles-user.js")
	write(t, real, "// from the dotfile repo\n")
	if err := os.Symlink(real, filepath.Join(dir, "user.js")); err != nil {
		t.Fatal(err)
	}
	block := RenderBlock([]SigPref{{IdentityID: "id1", FilePath: "/x", RelPath: "y"}})
	if _, err := UpdateUserJS(dir, block, false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, "user.js")); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced by a regular file")
	}
	if b, _ := os.ReadFile(real); !strings.Contains(string(b), BeginMarker) {
		t.Fatal("the symlink's target was not updated")
	}
}

func TestUpdateUserJSCorruptLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	broken := "important\n" + BeginMarker + "\nno end\n"
	write(t, filepath.Join(dir, "user.js"), broken)
	_, err := UpdateUserJS(dir, RenderBlock([]SigPref{{IdentityID: "id1", FilePath: "/x", RelPath: "y"}}), false)
	if err != ErrCorruptBlock {
		t.Fatalf("err=%v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "user.js")); string(b) != broken {
		t.Fatal("the damaged file was modified")
	}
}

func TestRunning(t *testing.T) {
	dir := t.TempDir()
	if Running(dir) {
		t.Fatal("without a lock link nothing is running")
	}
	if err := os.Symlink("127.0.0.1:+"+strconv.Itoa(os.Getpid()), filepath.Join(dir, "lock")); err != nil {
		t.Fatal(err)
	}
	if !Running(dir) {
		t.Fatal("a lock with our own PID must count as running")
	}
	dir2 := t.TempDir()
	_ = os.Symlink("127.0.0.1:+999999999", filepath.Join(dir2, "lock"))
	if Running(dir2) {
		t.Fatal("an orphaned lock link must not count as running")
	}
	dir3 := t.TempDir()
	_ = os.Symlink("quatsch", filepath.Join(dir3, "lock"))
	if Running(dir3) {
		t.Fatal("unreadable lock link")
	}
}

// ---------- Windows ----------

func TestCandidateRootsWindows(t *testing.T) {
	home := t.TempDir()
	vars := map[string]string{"APPDATA": filepath.Join(home, "Roaming"), "LOCALAPPDATA": filepath.Join(home, "Local")}
	env := platform.Env{GOOS: "windows", Home: home, Getenv: func(k string) string { return vars[k] }}
	roots := CandidateRoots(env)
	if len(roots) != 1 || roots[0].Dir != filepath.Join(home, "Roaming", "Thunderbird") || roots[0].Flavor != "native" {
		t.Fatalf("roots = %+v", roots)
	}
	// Microsoft Store version: the profile is under %LOCALAPPDATA%\Packages\MozillaThunderbird.<...>
	store := filepath.Join(home, "Local", "Packages", "MozillaThunderbird.MZLA_h5892qc0xkpca", "LocalCache", "Roaming", "Thunderbird")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	// Other packages must not be picked up.
	os.MkdirAll(filepath.Join(home, "Local", "Packages", "Mozilla.Firefox_x", "LocalCache", "Roaming", "Thunderbird"), 0o755)
	roots = CandidateRoots(env)
	if len(roots) != 2 || roots[1].Dir != store || roots[1].Flavor != "store" {
		t.Fatalf("roots = %+v", roots)
	}
	for _, r := range roots {
		if strings.Contains(r.Dir, ".thunderbird") || strings.Contains(r.Dir, "snap") {
			t.Errorf("Linux location on Windows: %s", r.Dir)
		}
	}
}

func TestWindowsProfilesIniUsesForwardSlashes(t *testing.T) {
	root := t.TempDir()
	prof := filepath.Join(root, "Profiles", "abc.default-release")
	if err := os.MkdirAll(prof, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "profiles.ini"), []byte("[Install308046B0AF4A39CB]\r\nDefault=Profiles/abc.default-release\r\nLocked=1\r\n\r\n[Profile0]\r\nName=default-release\r\nIsRelative=1\r\nPath=Profiles/abc.default-release\r\n"), 0o644)
	profs, err := Discover([]Root{{root, "native"}}, false)
	if err != nil || len(profs) != 1 || profs[0].Dir != prof || !profs[0].IsDefault {
		t.Fatalf("profs=%+v err=%v", profs, err)
	}
}

func TestBlockWithWindowsPathSurvivesAsJavaScript(t *testing.T) {
	path := `C:\Users\Jörg Müller\AppData\Roaming\Thunderbird\Profiles\abc.default\subsignature\a_b.de-12345678.html`
	block := RenderBlock([]SigPref{{IdentityID: "id1", FilePath: path, RelPath: "subsignature/a_b.de-12345678.html"}})
	// In the file every backslash must be doubled, otherwise Thunderbird reads "\U", "\A" ... as escapes.
	if !strings.Contains(block, `"C:\\Users\\Jörg Müller\\AppData\\Roaming`) {
		t.Fatalf("backslashes not escaped:\n%s", block)
	}
	p := ParsePrefs(block)
	if got := p.String("mail.identity.id1.sig_file"); got != path {
		t.Errorf("read back: %q", got)
	}
	if got := p.String("mail.identity.id1.sig_file-rel"); got != "[ProfD]subsignature/a_b.de-12345678.html" {
		t.Errorf("sig_file-rel = %q (relative to the profile, always with /)", got)
	}
}

func TestUserJSWithWindowsLineEndings(t *testing.T) {
	dir := t.TempDir()
	orig := "user_pref(\"a.b\", 1);\r\nuser_pref(\"c.d\", \"x\");\r\n"
	os.WriteFile(filepath.Join(dir, "user.js"), []byte(orig), 0o644)
	block := RenderBlock([]SigPref{{IdentityID: "id1", FilePath: `C:\x\s.html`, RelPath: "subsignature/s.html"}})
	if _, err := UpdateUserJS(dir, block, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "user.js"))
	if !strings.HasPrefix(string(b), orig) {
		t.Errorf("the user's own lines were modified:\n%q", b)
	}
	if p := ParsePrefs(string(b)); p.String("c.d") != "x" || p.String("mail.identity.id1.sig_file") != `C:\x\s.html` {
		t.Errorf("no longer readable: %v", p)
	}
	// remove again: the file is as before
	if _, err := UpdateUserJS(dir, "", false); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "user.js"))
	if strings.TrimRight(string(b), "\r\n") != strings.TrimRight(orig, "\r\n") {
		t.Errorf("after removing: %q", b)
	}
}
