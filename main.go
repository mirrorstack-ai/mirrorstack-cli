package main

import (
	"fmt"
	"os"

	"github.com/mirrorstack-ai/mirrorstack-cli/cmd"
)

func main() {
	if err := cmd.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
