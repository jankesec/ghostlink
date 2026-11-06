package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/byjanke/ghostlink/internal/buildinfo"
	"github.com/byjanke/ghostlink/internal/demo"
)

func main() {
	noColor := flag.Bool("no-color", false, "disable ANSI color output")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	info, err := os.Stdout.Stat()
	color := err == nil && info.Mode()&os.ModeCharDevice != 0 && !*noColor && os.Getenv("NO_COLOR") == ""
	if err := demo.Run(os.Stdout, color); err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}
}
