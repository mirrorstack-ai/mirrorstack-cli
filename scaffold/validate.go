package scaffold

import (
	"fmt"
	"os"
	"regexp"
)

var validID = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func Validate(name string) error {
	if len(name) < 2 || len(name) > 40 {
		return fmt.Errorf("module name must be 2-40 characters, got %d", len(name))
	}
	if !validID.MatchString(name) {
		return fmt.Errorf("module name must be lowercase alphanumeric with hyphens (e.g., my-analytics)")
	}
	if _, err := os.Stat(name); err == nil {
		return fmt.Errorf("directory %q already exists", name)
	}
	return nil
}
