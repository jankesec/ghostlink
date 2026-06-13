package modules

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortScan struct{}

func (m *PortScan) Name() string        { return "portscan" }
func (m *PortScan) Description() string { return "TCP connect scan with port ranges" }

func (m *PortScan) Run(args []string) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: portscan <host> [ports]\n  ports: 80 | 1-1024 | 22,80,443 | common (default: common)")
	}

	host := args[0]
	portSpec := "common"
	if len(args) > 1 {
		portSpec = args[1]
	}

	timeout := 2 * time.Second
	if len(args) > 2 {
		if d, err := time.ParseDuration(args[2]); err == nil {
			timeout = d
		}
	}

	ports, err := parsePorts(portSpec)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(open)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("scan %s | %d ports | timeout %v\n", host, len(ports), timeout))
	if len(open) == 0 {
		sb.WriteString("no open ports found\n")
	} else {
		sb.WriteString(fmt.Sprintf("%d open:\n", len(open)))
		for _, p := range open {
			svc := knownService(p)
			if svc != "" {
				sb.WriteString(fmt.Sprintf("  %5d/tcp  %s\n", p, svc))
			} else {
				sb.WriteString(fmt.Sprintf("  %5d/tcp\n", p))
			}
		}
	}

	return []byte(sb.String()), nil
}

func parsePorts(spec string) ([]int, error) {
	if spec == "common" {
		return []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
			1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9090, 27017,
		}, nil
	}

	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid start port: %s", parts[0])
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid end port: %s", parts[1])
		}
		if start > end || start < 1 || end > 65535 {
			return nil, fmt.Errorf("invalid range: %d-%d", start, end)
		}
		var ports []int
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	var ports []int
	for _, s := range strings.Split(spec, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port: %s", s)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

func knownService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
		143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
		3389: "rdp", 5432: "postgres", 5900: "vnc", 5985: "winrm",
		6379: "redis", 8080: "http-alt", 8443: "https-alt", 9090: "proxy",
		27017: "mongodb",
	}
	return services[port]
}
