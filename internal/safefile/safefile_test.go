package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicallyUsesOwnerOnlyPermissions(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nested", "evidence.bin")
	if err := WriteFile(target, []byte("first")); err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	if err := WriteFile(target, []byte("synthetic evidence")); err != nil {
		t.Fatalf("second WriteFile: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("file mode = %04o, want %04o", got, fileMode)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if got := string(content); got != "synthetic evidence" {
		t.Fatalf("file content = %q", got)
	}
}

func TestBaseName(t *testing.T) {
	for input, want := range map[string]string{
		"../../secrets.txt": "secrets.txt",
		"/":                 "unnamed",
		".":                 "unnamed",
		"report.bin":        "report.bin",
	} {
		if got := BaseName(input); got != want {
			t.Errorf("BaseName(%q) = %q, want %q", input, got, want)
		}
	}
}
