package cmd

import "fmt"

const version = "0.1.0"

func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "app":
		return runApp(args[1:])
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

func runApp(args []string) error {
	if len(args) == 0 {
		printAppUsage()
		return nil
	}

	switch args[0] {
	case "module":
		return runAppModule(args[1:])
	case "help", "--help", "-h":
		printAppUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: mirrorstack app %s\nRun 'mirrorstack app help' for usage", args[0])
	}
}

func runAppModule(args []string) error {
	if len(args) == 0 {
		printAppModuleUsage()
		return nil
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "help", "--help", "-h":
		printAppModuleUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: mirrorstack app module %s\nRun 'mirrorstack app module help' for usage", args[0])
	}
}

func printUsage() {
	fmt.Println(`MirrorStack CLI

Usage:
  mirrorstack <command>

Commands:
  app         App and module management
  version     Show CLI version
  help        Show this help`)
}

func printAppUsage() {
	fmt.Println(`Usage:
  mirrorstack app <command>

Commands:
  module      Module management`)
}

func printAppModuleUsage() {
	fmt.Println(`Usage:
  mirrorstack app module <command>

Commands:
  init <name>     Scaffold a new module`)
}
