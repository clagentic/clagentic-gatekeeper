package broker

import (
	"context"
	"fmt"
	"os"
)

// envbroker satisfies Broker by reading values from environment variables.
// The path argument is the env var name. Suitable for local dev and CI.
type envbroker struct{}

func (b *envbroker) Get(_ context.Context, path string) (string, error) {
	v := os.Getenv(path)
	if v == "" {
		// Report the variable name (not a secret value) so callers can diagnose
		// missing config without leaking anything sensitive.
		return "", fmt.Errorf("env broker: variable %q is unset or empty", path)
	}
	return v, nil
}
