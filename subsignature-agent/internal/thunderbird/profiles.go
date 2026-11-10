// Package thunderbird finds Thunderbird profiles on Linux and Windows, reads
// their settings (read-only) and writes nothing but a marked block in user.js.
// prefs.js is never touched: Thunderbird overwrites that file on exit anyway.
package thunderbird

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"subsignature-agent/internal/platform"
)

// Root is a directory that contains a profiles.ini.
type Root struct {
	Dir    string
	Flavor string // native, snap, flatpak, xdg, custom
}

// Profile is a Thunderbird profile folder.
type Profile struct {
	Name      string
	Dir       string
	IsDefault bool
	Flavor    string
}

// CandidateRoots lists the usual locations. Locations that do not exist are
// simply skipped later.
//
// Linux: according to the Mozilla forum, Snap puts the profile sometimes under
// ~/snap/thunderbird/common/.thunderbird and sometimes as a link to ~/.thunderbird.
//
// Windows: %APPDATA%\Thunderbird; the Microsoft Store version keeps the profile
// under %LOCALAPPDATA%\Packages\MozillaThunderbird.<...>\LocalCache\Roaming\Thunderbird
// (Thunderbird itself shows a wrong path there, Bugzilla 1878276).
func CandidateRoots(env platform.Env) []Root {
	if env.Windows() {
		roots := []Root{{filepath.Join(env.AppData(), "Thunderbird"), "native"}}
		store, _ := filepath.Glob(filepath.Join(env.LocalAppData(), "Packages", "MozillaThunderbird.*", "LocalCache", "Roaming", "Thunderbird"))
		sort.Strings(store)
		for _, d := range store {
			roots = append(roots, Root{d, "store"})
		}
		return roots
	}
	home := env.Home
	roots := []Root{
		{filepath.Join(home, ".thunderbird"), "native"},
		{filepath.Join(home, "snap", "thunderbird", "common", ".thunderbird"), "snap"},
		{filepath.Join(home, ".var", "app", "org.mozilla.Thunderbird", ".thunderbird"), "flatpak"},
		{filepath.Join(home, ".var", "app", "eu.betterbird.Betterbird", ".thunderbird"), "flatpak"},
	}
	// Speculative: Mozilla is discussing XDG paths for Thunderbird (Bugzilla 735285).
	xdg := ""
	if env.Getenv != nil {
		xdg = env.Getenv("XDG_CONFIG_HOME")
	}
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	return append(roots, Root{filepath.Join(xdg, "thunderbird"), "xdg"})
}

type iniSection struct {
	Name string
	KV   map[string]string
}

func parseINI(r io.Reader) []iniSection {
	var secs []iniSection
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			secs = append(secs, iniSection{Name: line[1 : len(line)-1], KV: map[string]string{}})
			continue
		}
		if len(secs) == 0 {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			secs[len(secs)-1].KV[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return secs
}

func resolve(root, p string, relative bool) string {
	if relative && !filepath.IsAbs(p) {
		// profiles.ini writes relative paths with "/" on Windows too.
		return filepath.Join(root, filepath.FromSlash(p))
	}
	return filepath.Clean(p)
}

// ReadRoot reads the profiles.ini of a root. A missing file is not an error.
func ReadRoot(root Root) ([]Profile, error) {
	f, err := os.Open(filepath.Join(root.Dir, "profiles.ini"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var profs []Profile
	installDefaults := map[string]bool{}
	for _, sec := range parseINI(f) {
		switch {
		case strings.HasPrefix(sec.Name, "Profile"):
			p := sec.KV["Path"]
			if p == "" {
				continue
			}
			dir := resolve(root.Dir, p, sec.KV["IsRelative"] != "0")
			profs = append(profs, Profile{
				Name:      sec.KV["Name"],
				Dir:       dir,
				IsDefault: sec.KV["Default"] == "1",
				Flavor:    root.Flavor,
			})
		case strings.HasPrefix(sec.Name, "Install"):
			if d := sec.KV["Default"]; d != "" {
				installDefaults[resolve(root.Dir, d, true)] = true
			}
		}
	}
	// [Install...] determines the installation's default profile; Default=1 is only the fallback.
	if len(installDefaults) > 0 {
		for i := range profs {
			profs[i].IsDefault = installDefaults[profs[i].Dir]
		}
	}
	any := false
	for _, p := range profs {
		any = any || p.IsDefault
	}
	if !any && len(profs) == 1 {
		profs[0].IsDefault = true
	}
	return profs, nil
}

// Discover collects profiles from all roots. all=false returns only the
// default profiles. A profile that is reachable through several paths
// (e.g. a Snap link to ~/.thunderbird) is returned only once.
func Discover(roots []Root, all bool) ([]Profile, error) {
	var out []Profile
	seen := map[string]bool{}
	for _, r := range roots {
		profs, err := ReadRoot(r)
		if err != nil {
			return nil, err
		}
		for _, p := range profs {
			if fi, err := os.Stat(p.Dir); err != nil || !fi.IsDir() {
				continue
			}
			if !all && !p.IsDefault {
				continue
			}
			key := p.Dir
			if real, err := filepath.EvalSymlinks(p.Dir); err == nil {
				key = real
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// ExplicitProfile builds a profile from an explicitly configured folder.
func ExplicitProfile(dir string) (Profile, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return Profile{}, err
	}
	if !fi.IsDir() {
		return Profile{}, &os.PathError{Op: "profile-path", Path: dir, Err: os.ErrInvalid}
	}
	return Profile{Name: filepath.Base(dir), Dir: dir, IsDefault: true, Flavor: "custom"}, nil
}
