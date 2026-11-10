// Command line of the SubSignature agent (alpha): Linux with Thunderbird,
// Windows with Thunderbird and classic Outlook.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"subsignature-agent/internal/config"
	"subsignature-agent/internal/platform"
	"subsignature-agent/internal/syncer"
	"subsignature-agent/internal/version"
)

const usageText = `subsignature-agent %s - fetches HTML signatures from the SubSignature server and applies them
(Linux: Thunderbird; Windows: Thunderbird and classic Outlook)

Usage:   subsignature-agent [-c config.xml] [-v] <command>
         (options go BEFORE the command)

Commands:
  run       daemon: syncs immediately and then at the configured interval (default 2 h)
  sync      sync once and exit (for cron, a systemd timer or the Windows Task Scheduler)
  check     dry run: shows what sync would change, writes nothing
  ping      checks server, TLS and token (GET /api/v1/), changes nothing
  status    shows the profiles and accounts found and the last state
  remove    undoes everything the agent has set up ("remove check" only shows it)
  init      writes an example configuration (default: %s)
  version   shows the version

The configuration is looked up in: -c, environment variable SUBSIGNATURE_CONFIG, %s%s
`

func usage(w io.Writer) {
	env := platform.Current()
	user := filepath.Join(env.ConfigDir(), "config.xml")
	system := ""
	if d := env.SystemConfigDir(); d != "" {
		system = ", " + filepath.Join(d, "config.xml")
	}
	fmt.Fprintf(w, usageText, version.Version, user, user, system)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	verbose := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-c":
			if len(args) < 2 {
				fmt.Fprintln(stderr, "-c needs a file name")
				return 2
			}
			cfgPath, args = args[1], args[2:]
		case "-v":
			verbose, args = true, args[1:]
		case "-h", "--help":
			usage(stdout)
			return 0
		default:
			fmt.Fprintf(stderr, "unknown option %s\n\n", args[0])
			usage(stderr)
			return 2
		}
	}
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "subsignature-agent", version.Version)
		return 0
	case "help":
		usage(stdout)
		return 0
	case "init":
		return cmdInit(rest, stdout, stderr)
	case "run", "sync", "check", "status", "ping", "remove":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return 2
	}

	path, err := config.Find(cfgPath)
	if err != nil {
		startupError(stderr, cmd, "Error: "+err.Error())
		return 1
	}
	cfg, warns, err := config.Load(path)
	if err != nil {
		startupError(stderr, cmd, "Error in the configuration: "+err.Error())
		return 1
	}
	logFile := cfg.Logging.File
	if logFile == "" && cmd == "run" && runtime.GOOS == "windows" {
		// As a daemon the agent runs without a console on Windows; without a file there would be no log.
		logFile = filepath.Join(platform.Current().StateDir(), "agent.log")
	}
	log := newLogger(stderr, cfg.Logging.Level, verbose, logFile)
	for _, w := range warns {
		log.Warn(w)
	}
	opt := syncer.Options{Logger: log}

	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	defer stop()

	switch cmd {
	case "status":
		lines, err := syncer.Status(cfg, opt)
		if err != nil {
			fmt.Fprintln(stderr, "Error:", err)
			return 1
		}
		scheme := "TLS (https)"
		if cfg.Server.BaseURL.Scheme == "http" {
			scheme = "WITHOUT TLS (http, test only)"
		}
		fmt.Fprintf(stdout, "Konfiguration: %s\nServer:        %s [%s]\nIntervall:     %s\n\n", cfg.Path, cfg.Server.BaseURL, scheme, cfg.Sync.Interval.Duration)
		for _, l := range lines {
			fmt.Fprintln(stdout, l)
		}
		return 0

	case "remove":
		opt.DryRun = len(rest) > 0 && rest[0] == "check"
		rep, err := syncer.Remove(cfg, opt)
		if errors.Is(err, syncer.ErrBusy) {
			fmt.Fprintln(stderr, "A sync is running right now - please stop the daemon first.")
			return 75
		}
		for _, a := range rep.Actions {
			fmt.Fprintln(stdout, "-", a)
		}
		if len(rep.Actions) == 0 && err == nil {
			fmt.Fprintln(stdout, "Nothing to remove.")
		}
		for _, n := range rep.Notes {
			fmt.Fprintln(stdout, "Note:", n)
		}
		if err != nil {
			fmt.Fprintf(stderr, "Removal finished with %d error(s) (details above).\n", len(rep.Errors))
			return 1
		}
		if !opt.DryRun {
			fmt.Fprintln(stdout, "If the agent runs as a daemon or on a schedule, please stop it there as well - otherwise it sets the signature up again on the next sync.")
		}
		return 0

	case "ping":
		res, err := syncer.Ping(ctx, cfg, opt)
		if err != nil {
			fmt.Fprintln(stderr, "Error:", err)
			return 1
		}
		in := res.Info
		fmt.Fprintf(stdout, "Server reachable: %s %s (API %s)\nToken:            %q - valid\n", in.Service, in.Version, in.API, in.Token)
		if res.HasSkew {
			skew := res.Skew.Round(time.Second)
			fmt.Fprintf(stdout, "Server time:      %s (difference to the local clock: %s)\n", in.ServerTime, skew)
			if skew > 5*time.Minute || skew < -5*time.Minute {
				fmt.Fprintln(stdout, "Note: the clock differs considerably - with TLS errors, check the time first.")
			}
		}
		if in.API != "v1" {
			fmt.Fprintf(stdout, "Warning: this agent only knows API v1, the server reports %q.\n", in.API)
			return 1
		}
		return 0

	case "sync", "check":
		opt.DryRun = cmd == "check"
		rep, err := syncer.Run(ctx, cfg, opt)
		if errors.Is(err, syncer.ErrBusy) {
			fmt.Fprintln(stderr, "Another sync is already running.")
			return 75
		}
		for _, a := range rep.Actions {
			fmt.Fprintln(stdout, "-", a)
		}
		if len(rep.Actions) == 0 && err == nil {
			fmt.Fprintln(stdout, "Everything is up to date, no changes needed.")
		}
		for _, m := range rep.Missing {
			fmt.Fprintf(stdout, "! No signature on the server for %s\n", m)
		}
		if rep.Skipped > 0 {
			fmt.Fprintf(stdout, "! %d address(es) were not checked because the run was aborted\n", rep.Skipped)
		}
		for _, n := range rep.Notes {
			fmt.Fprintln(stdout, "Note:", n)
		}
		if len(rep.RestartNeeded) > 0 {
			fmt.Fprintf(stdout, "Note: Thunderbird is running (%s). New settings apply after its next start; changed signature texts immediately.\n", strings.Join(rep.RestartNeeded, ", "))
		}
		switch {
		case err == nil:
			return 0
		case errors.Is(err, syncer.ErrNoProfile):
			if runtime.GOOS == "windows" {
				fmt.Fprintln(stderr, "Error: neither a Thunderbird profile nor an account in classic Outlook was found (start the program once and set up an account).")
			} else {
				fmt.Fprintln(stderr, "Error: no Thunderbird profile found (start Thunderbird once or set <profile-path>).")
			}
		case len(rep.Errors) > 0:
			// The individual errors are already in the log; only the summary here.
			fmt.Fprintf(stderr, "Sync finished with %d error(s) (details above). Affected addresses were left unchanged.\n", len(rep.Errors))
		default:
			fmt.Fprintln(stderr, "Error:", err)
		}
		return 1

	case "run":
		reload := reloadChannel()
		load := func() (*config.Config, error) {
			c, w, err := config.Load(path)
			for _, x := range w {
				log.Warn(x)
			}
			return c, err
		}
		log.Info("subsignature-agent started", "version", version.Version, "server", cfg.Server.BaseURL.String(), "interval", cfg.Sync.Interval.Duration.String())
		if err := syncer.Daemon(ctx, load, opt, reload); err != nil {
			fmt.Fprintln(stderr, "Error:", err)
			return 1
		}
		log.Info("stopped")
		return 0
	}
	return 0
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	var path string
	if len(args) > 0 {
		path = args[0]
	} else {
		path = filepath.Join(platform.Current().ConfigDir(), "config.xml")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintln(stderr, "Error:", err)
		return 1
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(stderr, "%s already exists - not overwritten.\n", path)
		} else {
			fmt.Fprintln(stderr, "Error:", err)
		}
		return 1
	}
	defer f.Close()
	if _, err := io.WriteString(f, config.Example()); err != nil {
		fmt.Fprintln(stderr, "Error:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Example configuration written: %s\nPlease adjust server/url, the token and, if needed, ca-file, then run: subsignature-agent check\n", path)
	return 0
}

// startupError reports an error that occurs before the log is set up.
// On Windows the daemon runs without a console; so that a typo in config.xml
// does not go unnoticed there, the message also ends up in the log.
func startupError(stderr io.Writer, cmd, msg string) {
	fmt.Fprintln(stderr, msg)
	if cmd != "run" || runtime.GOOS != "windows" {
		return
	}
	dir := platform.Current().StateDir()
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	if f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		fmt.Fprintf(f, "time=%s level=ERROR msg=%q\n", time.Now().Format(time.RFC3339), msg)
		f.Close()
	}
}

// tolerantWriter writes to both targets and only reports an error if both
// fail (io.MultiWriter would stop after the first error).
type tolerantWriter struct{ a, b io.Writer }

func (t tolerantWriter) Write(p []byte) (int, error) {
	_, errA := t.a.Write(p)
	_, errB := t.b.Write(p)
	if errA != nil && errB != nil {
		return 0, errB
	}
	return len(p), nil
}

func newLogger(stderr io.Writer, level string, verbose bool, file string) *slog.Logger {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	if verbose {
		lvl = slog.LevelDebug
	}
	var w io.Writer = stderr
	if file != "" {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err == nil {
			// Simple size limit: from 1 MiB on the file becomes <name>.1 (one generation).
			if fi, err := os.Stat(file); err == nil && fi.Size() > 1<<20 {
				_ = os.Remove(file + ".1")
				_ = os.Rename(file, file+".1")
			}
			if f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
				// Without a console (Windows autostart) writing to stderr fails;
				// that must not prevent writing to the file.
				w = tolerantWriter{stderr, f}
			}
		}
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
}
