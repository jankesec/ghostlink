// Package safefile provides owner-only, atomic local file writes.
package safefile

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	directoryMode = 0700
	fileMode      = 0600
)

// BaseName removes directory components from an untrusted filename.
func BaseName(name string) string {
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "unnamed"
	}
	return name
}

// WriteFile atomically replaces path with owner-readable and owner-writable data.
func WriteFile(path string, data []byte) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".ghostlink-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryName)
		}
	}()

	if err = temporary.Chmod(fileMode); err != nil {
		return fmt.Errorf("set private permissions: %w", err)
	}
	if _, err = temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err = os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}
	return nil
}
