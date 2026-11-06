package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnifiedOperatorCommands(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{nil, "ghostlink <command>"},
		{[]string{"doctor"}, "0 sockets · 0 targets · 0 external services"},
		{[]string{"doctor", "--json"}, `"network": "not accessed"`},
		{[]string{"transports"}, "COMPILED TRANSPORTS"},
		{[]string{"transports", "--json"}, `"id": "dns"`},
		{[]string{"demo", "--no-color"}, "6/6 checks passed"},
		{[]string{"version"}, "ghostlink"},
	} {
		var out, errOut bytes.Buffer
		if err := run(test.args, &out, &errOut); err != nil {
			t.Fatalf("run(%v): %v (%s)", test.args, err, errOut.String())
		}
		if !strings.Contains(out.String(), test.want) {
			t.Errorf("run(%v) missing %q", test.args, test.want)
		}
	}
}

func TestUnknownCommandFailsClosed(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"connect"}, &out, &out); err == nil {
		t.Fatal("unknown command unexpectedly succeeded")
	}
}
