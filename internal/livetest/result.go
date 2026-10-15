// Package livetest drives the real gatekeeper binary through the caller shapes
// of the issuer and its runtime adapters, in a private temporary directory, and
// reports one machine-readable result per shape. It assumes nothing about the
// host: every agent runtime is optional and a missing one skips its shapes.
package livetest

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Status is the outcome of one shape.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Result is one line of the harness output.
type Result struct {
	Shape  string `json:"shape"`
	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Reporter writes each result as one JSON line as it happens and tallies them,
// so a harness that is interrupted still leaves every finished shape on record.
type Reporter struct {
	mu     sync.Mutex
	w      io.Writer
	counts map[Status]int
	err    error
}

// NewReporter writes to w.
func NewReporter(w io.Writer) *Reporter {
	return &Reporter{w: w, counts: map[Status]int{}}
}

// Add records and writes one result. A failed write is kept and surfaces from
// Err: a gate must not read a truncated report as a clean one.
func (r *Reporter) Add(res Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[res.Status]++
	r.write(res)
}

// Summary writes the closing line with the tallies.
func (r *Reporter) Summary() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.write(map[string]any{"summary": map[Status]int{
		Pass: r.counts[Pass], Fail: r.counts[Fail], Skip: r.counts[Skip],
	}})
}

func (r *Reporter) write(v any) {
	b, err := json.Marshal(v)
	if err == nil {
		_, err = fmt.Fprintf(r.w, "%s\n", b)
	}
	if err != nil && r.err == nil {
		r.err = err
	}
}

// Failed reports whether any shape failed.
func (r *Reporter) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[Fail] > 0
}

// Count is the number of results with status s.
func (r *Reporter) Count(s Status) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[s]
}

// Err is the first write error, if any.
func (r *Reporter) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
