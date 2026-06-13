package modules

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type NetStat struct{}

func (m *NetStat) Name() string        { return "netstat" }
func (m *NetStat) Description() string { return "Active network connections and listeners" }

func (m *NetStat) Run(args []string) ([]byte, error) {
	if runtime.GOOS == "linux" {
		return m.linuxNetstat()
	}
	return m.fallbackNetstat()
}

func (m *NetStat) linuxNetstat() ([]byte, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-6s %-24s %-24s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, proto := range []struct {
		name string
		path string
	}{
		{"tcp", "/proc/net/tcp"},
		{"tcp6", "/proc/net/tcp6"},
		{"udp", "/proc/net/udp"},
	} {
		data, err := os.ReadFile(proto.path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}

			local := parseHexAddr(fields[1])
			remote := parseHexAddr(fields[2])
			state := tcpState(fields[3])

			if proto.name == "udp" {
				state = ""
			}

			sb.WriteString(fmt.Sprintf("%-6s %-24s %-24s %s\n", proto.name, local, remote, state))
		}
	}

	return []byte(sb.String()), nil
}

func parseHexAddr(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	ipHex := parts[0]
	portHex := parts[1]

	port, _ := strconv.ParseUint(portHex, 16, 16)

	if len(ipHex) == 8 {
		b, _ := hex.DecodeString(ipHex)
		if len(b) == 4 {
			ip := net.IPv4(b[3], b[2], b[1], b[0])
			return fmt.Sprintf("%s:%d", ip, port)
		}
	}

	return fmt.Sprintf("%s:%d", ipHex, port)
}

func tcpState(s string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if v, ok := states[strings.ToUpper(s)]; ok {
		return v
	}
	return s
}

func (m *NetStat) fallbackNetstat() ([]byte, error) {
	return execCommandOutput("netstat", "-an")
}
