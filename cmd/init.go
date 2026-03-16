package cmd

import (
	"fmt"

	"github.com/mirrorstack-ai/mirrorstack-cli/scaffold"
)

func runInit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mirrorstack init <module-name>")
	}

	name := args[0]
	if err := scaffold.Validate(name); err != nil {
		return err
	}

	fmt.Printf("Creating module: %s\n\n", name)

	if err := scaffold.Create(name); err != nil {
		return err
	}

	fmt.Printf("\nDone! Next steps:\n")
	fmt.Printf("  cd %s\n", name)
	fmt.Printf("  mirrorstack dev\n")
	return nil
}
