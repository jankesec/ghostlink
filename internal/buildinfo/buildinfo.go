// Package buildinfo exposes release metadata injected at build time.
package buildinfo

import "fmt"

var (
	// Version, Commit, and Date are overridden with -ldflags for release builds.
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a compact, human-readable build identifier.
func String() string {
	if Commit == "unknown" {
		return fmt.Sprintf("ghostlink %s", Version)
	}
	return fmt.Sprintf("ghostlink %s (%s, %s)", Version, Commit, Date)
}
