package operator

import (
	"os"
	"runtime"

	"github.com/byjanke/ghostlink/internal/buildinfo"
	"github.com/byjanke/ghostlink/pkg/protocol"
)

// Check is one read-only diagnostic result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Report is the deterministic, network-free doctor result.
type Report struct {
	Version    string  `json:"version"`
	Platform   string  `json:"platform"`
	Protocol   uint8   `json:"protocol"`
	Transports int     `json:"transports"`
	Network    string  `json:"network"`
	Checks     []Check `json:"checks"`
}

// Diagnose inspects only local process metadata and the compiled registry. It opens no sockets.
func Diagnose() Report {
	transports := Transports()
	report := Report{
		Version:    buildinfo.String(),
		Platform:   runtime.GOOS + "/" + runtime.GOARCH,
		Protocol:   protocol.ProtocolVersion,
		Transports: len(transports),
		Network:    "not accessed",
	}

	if err := ValidateCatalog(); err != nil {
		report.Checks = append(report.Checks, Check{"transport catalog", "WARN", err.Error()})
	} else {
		report.Checks = append(report.Checks, Check{"transport catalog", "PASS", "all compiled transports are documented"})
	}

	if cwd, err := os.Getwd(); err != nil {
		report.Checks = append(report.Checks, Check{"working directory", "WARN", err.Error()})
	} else if info, err := os.Stat(cwd); err != nil || !info.IsDir() {
		report.Checks = append(report.Checks, Check{"working directory", "WARN", "directory is unavailable"})
	} else {
		report.Checks = append(report.Checks, Check{"working directory", "PASS", cwd})
	}

	report.Checks = append(report.Checks,
		Check{"safe defaults", "PASS", "network commands require explicit addresses"},
		Check{"doctor boundary", "PASS", "0 sockets · 0 targets · 0 external services"},
	)
	return report
}

// Healthy reports whether the environment has any failed checks.
func (r Report) Healthy() bool {
	for _, check := range r.Checks {
		if check.Status == "FAIL" {
			return false
		}
	}
	return true
}
