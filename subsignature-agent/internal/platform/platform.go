// Package platform knows the locations that differ between Linux and Windows
// (configuration, state, AppData). All functions depend only on Env and not on
// the running operating system - so the Windows logic can be tested on Linux
// as well.
package platform

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const appName = "subsignature-agent"

// Env describes a user's environment.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string
}

// Current returns the environment of the running process.
func Current() Env {
	home, _ := os.UserHomeDir()
	return Env{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv}
}

func (e Env) Windows() bool { return e.GOOS == "windows" }

func (e Env) env(key string) string {
	if e.Getenv == nil {
		return ""
	}
	return strings.TrimSpace(e.Getenv(key))
}

// AppData is %APPDATA% (Roaming). Only meaningful on Windows.
func (e Env) AppData() string {
	if v := e.env("APPDATA"); v != "" {
		return v
	}
	return filepath.Join(e.Home, "AppData", "Roaming")
}

// LocalAppData is %LOCALAPPDATA%. Only meaningful on Windows.
func (e Env) LocalAppData() string {
	if v := e.env("LOCALAPPDATA"); v != "" {
		return v
	}
	return filepath.Join(e.Home, "AppData", "Local")
}

// ConfigDir is the folder of the per-user configuration.
func (e Env) ConfigDir() string {
	if e.Windows() {
		return filepath.Join(e.AppData(), appName)
	}
	if xdg := e.env("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, appName)
	}
	return filepath.Join(e.Home, ".config", appName)
}

// SystemConfigDir is the folder of a machine-wide configuration (deployed by
// the admin). Empty if this system has none.
func (e Env) SystemConfigDir() string {
	if e.Windows() {
		if pd := e.env("ProgramData"); pd != "" {
			return filepath.Join(pd, appName)
		}
		return ""
	}
	return "/etc/" + appName
}

// StateDir is the folder for state, lock and (on Windows) the log.
func (e Env) StateDir() string {
	if e.Windows() {
		return filepath.Join(e.LocalAppData(), appName)
	}
	if xdg := e.env("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, appName)
	}
	return filepath.Join(e.Home, ".local", "state", appName)
}

var percentVar = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_()]*)%`)

// ExpandPath resolves ~ (home), $VAR and - on Windows - %VAR%. A relative
// path is relative to baseDir (the folder of the configuration file), so that
// the same config.xml works on Linux and Windows and the result does not
// depend on the folder the agent was started from.
func (e Env) ExpandPath(p, baseDir string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = filepath.Join(e.Home, p[1:])
	}
	if e.Windows() {
		p = percentVar.ReplaceAllStringFunc(p, func(m string) string {
			if v := e.env(m[1 : len(m)-1]); v != "" {
				return v
			}
			return m
		})
	} else {
		p = os.Expand(p, e.env)
	}
	if baseDir != "" && !filepath.IsAbs(p) && !e.isAbsForeign(p) {
		p = filepath.Join(baseDir, p)
	}
	return filepath.Clean(p)
}

// isAbsForeign recognizes absolute Windows paths (C:\..., \\server\...) even
// when the code is not running on Windows (tests).
func (e Env) isAbsForeign(p string) bool {
	if !e.Windows() {
		return false
	}
	return strings.HasPrefix(p, `\\`) || (len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

// Within reports whether path lies inside dir (after cleaning; case does not
// matter on Windows). Symlinks are not resolved.
func (e Env) Within(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	if e.Windows() {
		path, dir = strings.ToLower(path), strings.ToLower(dir)
		path, dir = strings.ReplaceAll(path, "/", `\`), strings.ReplaceAll(dir, "/", `\`)
	}
	if path == dir {
		return true
	}
	for _, sep := range []string{"/", `\`} {
		if strings.HasPrefix(path, strings.TrimRight(dir, `/\`)+sep) {
			return true
		}
	}
	return false
}
