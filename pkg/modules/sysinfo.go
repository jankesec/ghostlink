package modules

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
)

type SysInfo struct{}

func (m *SysInfo) Name() string        { return "sysinfo" }
func (m *SysInfo) Description() string { return "OS, user, hostname, IPs, architecture" }

func (m *SysInfo) Run(args []string) ([]byte, error) {
	var sb strings.Builder

	hostname, _ := os.Hostname()
	u, _ := user.Current()
	wd, _ := os.Getwd()

	sb.WriteString(fmt.Sprintf("hostname:  %s\n", hostname))
	sb.WriteString(fmt.Sprintf("os:        %s/%s\n", runtime.GOOS, runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("cpus:      %d\n", runtime.NumCPU()))
	sb.WriteString(fmt.Sprintf("go:        %s\n", runtime.Version()))
	sb.WriteString(fmt.Sprintf("pid:       %d\n", os.Getpid()))
	sb.WriteString(fmt.Sprintf("ppid:      %d\n", os.Getppid()))
	sb.WriteString(fmt.Sprintf("cwd:       %s\n", wd))

	if u != nil {
		sb.WriteString(fmt.Sprintf("user:      %s (uid=%s gid=%s)\n", u.Username, u.Uid, u.Gid))
		sb.WriteString(fmt.Sprintf("home:      %s\n", u.HomeDir))
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		sb.WriteString("interfaces:\n")
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
			var ips []string
			for _, a := range addrs {
				ips = append(ips, a.String())
			}
			sb.WriteString(fmt.Sprintf("  %-12s %s  %s\n", iface.Name, iface.HardwareAddr, strings.Join(ips, ", ")))
		}
	}

	sb.WriteString(fmt.Sprintf("time:      %s\n", time.Now().Format(time.RFC3339)))

	for _, env := range []string{"PATH", "SHELL", "TERM", "LANG", "SSH_CONNECTION"} {
		if v := os.Getenv(env); v != "" {
			sb.WriteString(fmt.Sprintf("$%-9s %s\n", env, v))
		}
	}

	return []byte(sb.String()), nil
}
