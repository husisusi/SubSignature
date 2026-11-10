package platform

import (
	"path/filepath"
	"testing"
)

func env(goos string, vars map[string]string) Env {
	return Env{GOOS: goos, Home: filepath.FromSlash("/home/u"), Getenv: func(k string) string { return vars[k] }}
}

func TestDirsLinux(t *testing.T) {
	e := env("linux", nil)
	if got := e.ConfigDir(); got != "/home/u/.config/subsignature-agent" {
		t.Errorf("ConfigDir = %q", got)
	}
	if got := e.StateDir(); got != "/home/u/.local/state/subsignature-agent" {
		t.Errorf("StateDir = %q", got)
	}
	if got := e.SystemConfigDir(); got != "/etc/subsignature-agent" {
		t.Errorf("SystemConfigDir = %q", got)
	}
	e = env("linux", map[string]string{"XDG_CONFIG_HOME": "/x/cfg", "XDG_STATE_HOME": "/x/state"})
	if e.ConfigDir() != "/x/cfg/subsignature-agent" || e.StateDir() != "/x/state/subsignature-agent" {
		t.Errorf("XDG: %q %q", e.ConfigDir(), e.StateDir())
	}
}

func TestDirsWindows(t *testing.T) {
	e := env("windows", map[string]string{"APPDATA": "/u/Roaming", "LOCALAPPDATA": "/u/Local", "ProgramData": "/pd"})
	for got, want := range map[string]string{
		e.ConfigDir():       "/u/Roaming/subsignature-agent",
		e.StateDir():        "/u/Local/subsignature-agent",
		e.SystemConfigDir(): "/pd/subsignature-agent",
	} {
		if got != filepath.FromSlash(want) {
			t.Errorf("got %q, expected %q", got, want)
		}
	}
	// Without environment variables: fall back to the usual folders in the profile; no machine-wide configuration.
	e = env("windows", nil)
	if e.AppData() != filepath.FromSlash("/home/u/AppData/Roaming") || e.LocalAppData() != filepath.FromSlash("/home/u/AppData/Local") {
		t.Errorf("fallback: %q %q", e.AppData(), e.LocalAppData())
	}
	if e.SystemConfigDir() != "" {
		t.Errorf("SystemConfigDir = %q", e.SystemConfigDir())
	}
}

func TestExpandPath(t *testing.T) {
	lin := env("linux", map[string]string{"FOO": "/opt/foo"})
	win := env("windows", map[string]string{"APPDATA": `C:\Users\u\AppData\Roaming`, "ProgramFiles(x86)": `C:\PF86`})
	base := filepath.FromSlash("/etc/agent")
	cases := []struct {
		e    Env
		in   string
		want string
	}{
		{lin, "", ""},
		{lin, "  token  ", "/etc/agent/token"}, // relative: next to the configuration
		{lin, "./sub/token", "/etc/agent/sub/token"},
		{lin, "../token", "/etc/token"},
		{lin, "/abs/token", "/abs/token"},
		{lin, "~/t", "/home/u/t"},
		{lin, "~", "/home/u"},
		{lin, "$FOO/t", "/opt/foo/t"},
		{lin, "${FOO}/t", "/opt/foo/t"},
		{lin, "%APPDATA%/t", "/etc/agent/%APPDATA%/t"}, // %VAR% is Windows syntax
		{win, `%APPDATA%\agent\token`, `C:\Users\u\AppData\Roaming\agent\token`},
		{win, `%ProgramFiles(x86)%\x`, `C:\PF86\x`},
		{win, `%DOESNOTEXIST%\x`, base + string(filepath.Separator) + `%DOESNOTEXIST%\x`}, // unknown stays as it is
		{win, `C:\Tokens\t`, `C:\Tokens\t`},                                               // absolute: do not append to the configuration folder
		{win, `\\server\share\t`, `\\server\share\t`},
		{win, "token", base + string(filepath.Separator) + "token"},
		{win, "$FOO/t", base + string(filepath.Separator) + filepath.FromSlash("$FOO/t")}, // $VAR is not replaced on Windows
	}
	for _, c := range cases {
		got := c.e.ExpandPath(c.in, base)
		want := c.want
		if c.e.GOOS == "linux" {
			want = filepath.FromSlash(want)
		}
		if got != want {
			t.Errorf("[%s] %q -> %q, expected %q", c.e.GOOS, c.in, got, want)
		}
	}
	if got := lin.ExpandPath("token", ""); got != "token" {
		t.Errorf("without base folder: %q", got)
	}
}

func TestWithin(t *testing.T) {
	lin, win := env("linux", nil), env("windows", nil)
	yes := [][3]any{
		{lin, "/home/u/a/b", "/home/u"}, {lin, "/home/u", "/home/u"}, {lin, "/home/u/x/../a", "/home/u/"},
		{win, `C:\Users\U\AppData\x`, `c:\users\u`}, {win, `C:/Users/u/x`, `C:\Users\u`},
	}
	no := [][3]any{
		{lin, "/home/user2/a", "/home/u"}, {lin, "/home/u/../v/a", "/home/u"}, {lin, "/etc", "/home/u"}, {lin, "", "/home/u"}, {lin, "/x", ""},
		{win, `C:\Users\u2\x`, `C:\Users\u`}, {win, `C:\ProgramData\x`, `C:\Users\u`},
	}
	for _, c := range yes {
		if !c[0].(Env).Within(c[1].(string), c[2].(string)) {
			t.Errorf("%q should lie inside %q", c[1], c[2])
		}
	}
	for _, c := range no {
		if c[0].(Env).Within(c[1].(string), c[2].(string)) {
			t.Errorf("%q does NOT lie inside %q", c[1], c[2])
		}
	}
}
