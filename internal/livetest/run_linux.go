//go:build linux

package livetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Exit codes of Run.
const (
	ExitOK          = 0
	ExitFailed      = 1
	ExitInterrupted = 130
)

// runtimePrefix names the shapes that need an agent runtime.
const runtimePrefix = "runtime-"

// Run builds the tree, starts an isolated issuer and runs every shape against
// it, writing one JSON line per shape to out. Everything it created is removed
// before it returns, whether the shapes passed, failed or ctx was cancelled.
func Run(ctx context.Context, opts Options, out io.Writer) int {
	opts = opts.withDefaults()
	rep := NewReporter(out)
	env, err := NewEnv(ctx, opts)
	if err != nil {
		rep.Add(Result{Shape: "setup", Status: Fail, Reason: err.Error()})
		return finish(ctx, rep)
	}
	// The deferred call covers a panic in a shape; the explicit one below puts a
	// teardown failure on the record before the summary.
	defer env.Close()

	var all []shape
	all = append(all, env.issuerShapes()...)
	all = append(all, env.hookShapes()...)
	all = append(all, env.mintShapes()...)
	all = append(all, env.callerShapes()...)
	all = append(all, env.runtimeShapes()...)
	all = append(all, env.runtimeMintShapes()...)
	for _, s := range all {
		if ctx.Err() != nil {
			rep.Add(Result{Shape: s.name, Status: Fail, Reason: "interrupted before it ran"})
			continue
		}
		rep.Add(execute(ctx, s, opts))
	}
	if err := env.Close(); err != nil {
		rep.Add(Result{Shape: "teardown", Status: Fail, Reason: err.Error()})
	} else {
		rep.Add(Result{Shape: "teardown", Status: Pass})
	}
	return finish(ctx, rep)
}

func finish(ctx context.Context, rep *Reporter) int {
	rep.Summary()
	switch {
	case ctx.Err() != nil:
		return ExitInterrupted
	case rep.Failed(), rep.Err() != nil:
		return ExitFailed
	}
	return ExitOK
}

// execute runs one shape and classifies its outcome.
func execute(ctx context.Context, s shape, opts Options) Result {
	err := s.run(ctx)
	var skip skipError
	switch {
	case err == nil:
		return Result{Shape: s.name, Status: Pass}
	case ctx.Err() != nil:
		return Result{Shape: s.name, Status: Fail, Reason: "interrupted"}
	case errors.As(err, &skip):
		if opts.RequireRuntime && strings.HasPrefix(s.name, runtimePrefix) {
			return Result{Shape: s.name, Status: Fail, Reason: "runtime evidence is required but the shape cannot run: " + skip.reason}
		}
		return Result{Shape: s.name, Status: Skip, Reason: skip.reason}
	}
	return Result{Shape: s.name, Status: Fail, Reason: fmt.Sprintf("%v", err)}
}
