package main

import (
	"fmt"
	"io"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
)

// loadConfig is the one way a command reads its config: it loads path and
// writes one line to warn for each key the config carries that no setting
// declares. An unknown key never stops the load.
func loadConfig(path string, warn io.Writer) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	for _, line := range cfg.UnknownKeyWarnings() {
		fmt.Fprintln(warn, line)
	}
	return cfg, nil
}
