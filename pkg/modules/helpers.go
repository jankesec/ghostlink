package modules

import (
	"fmt"
	"os/exec"
)

func execCommandOutput(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w\n%s", name, err, string(out))
	}
	return out, nil
}
