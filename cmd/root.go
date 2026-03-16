package cmd

import "fmt"

const version = "0.1.0"

func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "version", "--version", "-v":
		fmt.Println("mirrorstack", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s\nRun 'mirrorstack help' for usage", args[0])
	}
}

func printUsage() {
	fmt.Println(`MirrorStack CLI — scaffold, develop, and deploy modules

Usage:
  mirrorstack <command> [arguments]

Commands:
  init <name>     Scaffold a new module
  version         Show CLI version
  help            Show this help`)
}
