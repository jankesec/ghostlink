package modules

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type Screenshot struct{}

func (m *Screenshot) Name() string        { return "screenshot" }
func (m *Screenshot) Description() string { return "Capture screen (macOS/Linux)" }

func (m *Screenshot) Run(args []string) ([]byte, error) {
	tmpFile := filepath.Join(os.TempDir(), "gl_ss.png")
	defer os.Remove(tmpFile)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("screencapture", "-x", tmpFile)
	case "linux":
		if _, err := exec.LookPath("import"); err == nil {
			cmd = exec.Command("import", "-window", "root", tmpFile)
		} else if _, err := exec.LookPath("scrot"); err == nil {
			cmd = exec.Command("scrot", tmpFile)
		} else if _, err := exec.LookPath("gnome-screenshot"); err == nil {
			cmd = exec.Command("gnome-screenshot", "-f", tmpFile)
		} else {
			return nil, fmt.Errorf("no screenshot tool found (install scrot or imagemagick)")
		}
	default:
		return nil, fmt.Errorf("screenshot not supported on %s", runtime.GOOS)
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("screenshot: %w", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("read screenshot: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	result := fmt.Sprintf("screenshot captured (%d bytes)\nbase64:%s", len(data), encoded)
	return []byte(result), nil
}
