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
	all = append(all, env.selfCheckShapes()...)
	all = append(all, env.hookShapes()...)
	all = append(all, env.mintShapes()...)
	all = append(all, env.callerShapes()...)
	all = append(all, env.runtimeShapes()...)
	all = append(all, env.runtimeMintShapes()...)
	all = append(all, env.sandboxShapes()...)
	all, unmatched := selectShapes(all, opts.Shapes)
	for _, p := range unmatched {
		rep.Add(Result{Shape: "shape-filter", Status: Fail, Reason: fmt.Sprintf("--shape %q matches no shape", p)})
	}
	if len(unmatched) > 0 {
		all = nil
	}
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

// selectShapes keeps the shapes whose name starts with one of prefixes, in their
// original order, and returns the prefixes that matched none. With no prefixes
// every shape is kept.
func selectShapes(all []shape, prefixes []string) (kept []shape, unmatched []string) {
	if len(prefixes) == 0 {
		return all, nil
	}
	for _, p := range prefixes {
		hit := false
		for _, s := range all {
			if strings.HasPrefix(s.name, p) {
				hit = true
				break
			}
		}
		if !hit {
			unmatched = append(unmatched, p)
		}
	}
	for _, s := range all {
		for _, p := range prefixes {
			if strings.HasPrefix(s.name, p) {
				kept = append(kept, s)
				break
			}
		}
	}
	return kept, unmatched
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
	var note passNote
	switch {
	case err == nil:
		return Result{Shape: s.name, Status: Pass}
	case errors.As(err, &note):
		return Result{Shape: s.name, Status: Pass, Reason: note.note}
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
