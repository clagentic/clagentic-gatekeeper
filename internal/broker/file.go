package broker

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// filebroker satisfies Broker by reading values from the filesystem.
// The path argument is an absolute or relative filesystem path.
// Suitable for local dev workflows where secrets are stored as plain files.
type filebroker struct{}

func (b *filebroker) Get(_ context.Context, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// os.ErrNotExist and permission errors are surfaced without value leakage;
		// the path is config, not a secret.
		return "", fmt.Errorf("file broker: read %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
