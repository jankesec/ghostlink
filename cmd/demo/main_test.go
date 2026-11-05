package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDemoValidatesTheOfflinePipeline(t *testing.T) {
	var output bytes.Buffer
	if err := runDemo(&output, false); err != nil {
		t.Fatalf("runDemo: %v", err)
	}

	text := output.String()
	for _, expected := range []string{
		"LOCAL PIPELINE VALIDATION",
		"Key agreement",
		"Compression",
		"Parity layout",
		"Framing",
		"Encryption",
		"Integrity",
		"6/6 checks passed",
		"no sockets",
		"transports are not contacted",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("output missing %q", expected)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatal("non-color output contains ANSI escapes")
	}
}
