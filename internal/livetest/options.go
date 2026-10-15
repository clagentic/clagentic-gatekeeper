package livetest

import "time"

// Options parameterizes a run. The zero value builds the module in the current
// directory and runs every shape the host supports.
type Options struct {
	// Source is the module root to build the binary from. Default ".".
	Source string
	// Binary is a prebuilt gatekeeper binary; when set nothing is built.
	Binary string
	// TempParent is the directory the private working directory is created in.
	// Default: the system temporary directory.
	TempParent string

	// RuntimeCLI names or points at the agent runtime CLI the runtime shapes
	// drive. Empty means the runtime's usual command name, looked up on PATH.
	RuntimeCLI string
	// RuntimeEnv is extra KEY=VALUE environment for the runtime process, for
	// example a state directory or a credential the runtime needs.
	RuntimeEnv []string
	// NoRuntime skips every runtime shape without looking for the CLI.
	NoRuntime bool
	// RequireRuntime turns a runtime shape that would skip into a failure, for a
	// gate that must have the runtime evidence.
	RequireRuntime bool
	// RuntimeAttempts bounds how often a runtime shape is retried when the model
	// did not do what the prompt asked. Default 2.
	RuntimeAttempts int
	// RuntimeTimeout bounds one runtime invocation. Default 4 minutes.
	RuntimeTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.Source == "" {
		o.Source = "."
	}
	if o.RuntimeAttempts <= 0 {
		o.RuntimeAttempts = 2
	}
	if o.RuntimeTimeout <= 0 {
		o.RuntimeTimeout = 4 * time.Minute
	}
	return o
}
