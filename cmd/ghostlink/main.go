package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/byjanke/ghostlink/internal/buildinfo"
	"github.com/byjanke/ghostlink/internal/demo"
	"github.com/byjanke/ghostlink/internal/operator"
)

const usage = `Ghostlink — authorized-lab transport research toolkit

Usage:
  ghostlink <command> [options]

Start here:
  doctor       verify the local build and safe defaults (offline)
  transports   list compiled transports and their requirements
  demo         run the real protected pipeline round trip (offline)
  version      print release metadata
  help         show this help

Network-facing server and client binaries remain explicit, separate tools.
Run ghostlink-server -h or ghostlink-client -h only inside an authorized lab.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "ghostlink: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	case "version", "-version", "--version":
		fmt.Fprintln(out, buildinfo.String())
		return nil
	case "doctor":
		return runDoctor(args[1:], out, errOut)
	case "transports":
		return runTransports(args[1:], out, errOut)
	case "demo":
		return runDemo(args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown command %q; run 'ghostlink help'", args[0])
	}
}

func runDoctor(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(errOut)
	asJSON := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("doctor accepts no positional arguments")
	}

	report := operator.Diagnose()
	if *asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}

	fmt.Fprintln(out, "GHOSTLINK DOCTOR / READ-ONLY")
	fmt.Fprintf(out, "Build       %s\n", report.Version)
	fmt.Fprintf(out, "Platform    %s\n", report.Platform)
	fmt.Fprintf(out, "Protocol    v%d\n", report.Protocol)
	fmt.Fprintf(out, "Transports  %d compiled\n", report.Transports)
	fmt.Fprintf(out, "Network     %s\n\n", report.Network)
	for _, check := range report.Checks {
		fmt.Fprintf(out, "%-5s %-20s %s\n", check.Status, check.Name, check.Detail)
	}
	return nil
}

func runTransports(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("transports", flag.ContinueOnError)
	flags.SetOutput(errOut)
	asJSON := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("transports accepts no positional arguments")
	}

	items := operator.Transports()
	if *asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	}

	fmt.Fprintln(out, "COMPILED TRANSPORTS / NO CONNECTIONS OPENED")
	fmt.Fprintf(out, "%-14s %-12s %-14s %s\n", "ID", "CLASS", "STATUS", "REQUIREMENT")
	fmt.Fprintln(out, strings.Repeat("─", 76))
	for _, item := range items {
		fmt.Fprintf(out, "%-14s %-12s %-14s %s\n", item.ID, item.Class, item.Stability, item.Requirement)
	}
	return nil
}

func runDemo(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(errOut)
	noColor := flags.Bool("no-color", false, "disable ANSI color output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("demo accepts no positional arguments")
	}
	color := false
	if file, ok := out.(*os.File); ok {
		if info, err := file.Stat(); err == nil {
			color = info.Mode()&os.ModeCharDevice != 0 && !*noColor && os.Getenv("NO_COLOR") == ""
		}
	}
	return demo.Run(out, color)
}
