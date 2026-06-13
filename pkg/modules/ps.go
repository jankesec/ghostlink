package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type ProcessList struct{}

func (m *ProcessList) Name() string        { return "ps" }
func (m *ProcessList) Description() string { return "List running processes" }

func (m *ProcessList) Run(args []string) ([]byte, error) {
	if runtime.GOOS == "linux" {
		return m.linuxPS()
	}
	return m.fallbackPS()
}

func (m *ProcessList) linuxPS() ([]byte, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m.fallbackPS()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-7s %-7s %-16s %s\n", "PID", "PPID", "USER", "CMD"))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		statusData, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}

		var name, ppid, uid string
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Name:") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			} else if strings.HasPrefix(line, "PPid:") {
				ppid = strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			} else if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					uid = fields[1]
				}
			}
		}

		cmdline, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		cmd := name
		if len(cmdline) > 0 {
			cmd = strings.ReplaceAll(string(cmdline), "\x00", " ")
			cmd = strings.TrimSpace(cmd)
			if len(cmd) > 80 {
				cmd = cmd[:80] + "..."
			}
		}

		sb.WriteString(fmt.Sprintf("%-7d %-7s %-16s %s\n", pid, ppid, uid, cmd))
	}

	return []byte(sb.String()), nil
}

func (m *ProcessList) fallbackPS() ([]byte, error) {
	return execCommandOutput("ps", "aux")
}
