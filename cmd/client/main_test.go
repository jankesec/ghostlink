package main

import "testing"

func TestResolveTransferFile(t *testing.T) {
	if got, err := resolveTransferFile("", "lab.txt"); err != nil || got != "lab.txt" {
		t.Fatalf("current flag: got %q, err %v", got, err)
	}
	if got, err := resolveTransferFile("legacy.txt", ""); err != nil || got != "legacy.txt" {
		t.Fatalf("legacy flag: got %q, err %v", got, err)
	}
	if _, err := resolveTransferFile("legacy.txt", "lab.txt"); err == nil {
		t.Fatal("conflicting transfer flags unexpectedly accepted")
	}
}
