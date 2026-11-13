// Package version holds the agent's version number.
package version

// Version is overridden at build time with -ldflags "-X subsignature-agent/internal/version.Version=...".
var Version = "1.0.0-rc2"
