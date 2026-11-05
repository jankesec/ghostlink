package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateFileUsesOwnerOnlyPermissions(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nested", "evidence.bin")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(target, []byte("stale"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := writePrivateFile(target, []byte("synthetic evidence")); err != nil {
		t.Fatalf("writePrivateFile: %v", err)
	}

	fileInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("file mode = %04o, want 0600", got)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if got := string(content); got != "synthetic evidence" {
		t.Fatalf("file content = %q", got)
	}

	dirInfo, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("directory mode = %04o, want 0700", got)
	}
}

func TestSanitizeFileNameRemovesPathTraversal(t *testing.T) {
	for input, want := range map[string]string{
		"../../secrets.txt": "secrets.txt",
		"/":                 "unnamed",
		".":                 "unnamed",
		"report.bin":        "report.bin",
	} {
		if got := sanitizeFileName(input); got != want {
			t.Errorf("sanitizeFileName(%q) = %q, want %q", input, got, want)
		}
	}
}
