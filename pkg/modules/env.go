package modules

import (
	"os"
	"sort"
	"strings"
)

type EnvDump struct{}

func (m *EnvDump) Name() string        { return "env" }
func (m *EnvDump) Description() string { return "Environment variables" }

func (m *EnvDump) Run(args []string) ([]byte, error) {
	envs := os.Environ()
	sort.Strings(envs)

	filter := ""
	if len(args) > 0 {
		filter = strings.ToUpper(args[0])
	}

	var sb strings.Builder
	for _, e := range envs {
		if filter != "" && !strings.Contains(strings.ToUpper(e), filter) {
			continue
		}
		sb.WriteString(e)
		sb.WriteByte('\n')
	}

	return []byte(sb.String()), nil
}
