package config

import (
	"fmt"
	"path/filepath"
)

// MaxSocketPathBytes is the longest unix socket path a client can connect to:
// sun_path holds 108 bytes and the terminating NUL takes one.
const MaxSocketPathBytes = 107

// CheckAbsPath refuses a non-empty relative path. name is what the operator
// typed, a flag or a config key, so the refusal names the input that is wrong.
// Every path input, flag or config, goes through this one check: a relative path
// would resolve against whatever directory the process was started in.
func CheckAbsPath(name, value string) error {
	if value != "" && !filepath.IsAbs(value) {
		return fmt.Errorf("%s %q must be an absolute path", name, value)
	}
	return nil
}

// CheckSocketPath is CheckAbsPath plus the unix socket length limit. A longer
// path can be created on disk but no client can connect to it, so it is refused
// where it is named instead of at the first connect.
func CheckSocketPath(name, value string) error {
	if err := CheckAbsPath(name, value); err != nil {
		return err
	}
	if len(value) > MaxSocketPathBytes {
		return fmt.Errorf("%s %q is %d bytes, over the %d-byte limit of a unix socket path", name, value, len(value), MaxSocketPathBytes)
	}
	return nil
}
