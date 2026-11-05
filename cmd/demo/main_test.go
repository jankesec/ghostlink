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
		"SAFE OFFLINE ROUND TRIP",
		"Can Ghostlink protect and reconstruct one synthetic lab record?",
		"0 sockets · 0 targets · 0 external services",
		"INPUT → COMPRESS → SHARD → FRAME → ENCRYPT → DECRYPT → REBUILD → VERIFY",
		"Key agreement",
		"Compression",
		"Parity layout",
		"Framing",
		"Encryption",
		"Integrity",
		"VERIFIED OUTPUT",
		"EXACT MATCH",
		"6/6 checks passed",
		"DOES NOT PROVE",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("output missing %q", expected)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatal("non-color output contains ANSI escapes")
	}
}
