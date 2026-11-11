package main

import (
	"fmt"
	"io"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/mintrecord"
)

// recordWriter returns the function that appends a mint record to the sink at
// path, or nil when path is empty (sink off). A write failure is reported on
// errOut and goes no further: the mint's result and exit code are the mint's
// own, whatever happens to the record.
func recordWriter(path string, errOut io.Writer) func(mintrecord.Record) {
	sink := mintrecord.Sink{Path: path}
	if !sink.Enabled() {
		return nil
	}
	return func(r mintrecord.Record) {
		if err := sink.Write(r); err != nil {
			fmt.Fprintf(errOut, "mint record not written: %v\n", err)
		}
	}
}

// recordRefusal writes a record for a mint refused before the mint service
// ran: a configuration or request error. It is a no-op when write is nil.
func recordRefusal(write func(mintrecord.Record), role string, repos []string) {
	if write == nil {
		return
	}
	write(mintrecord.Record{
		Time:            time.Now().UTC().Format(time.RFC3339),
		Role:            role,
		RequestedRepos:  repos,
		Outcome:         mintrecord.OutcomeError,
		FailureCategory: mintrecord.CategoryConfig,
	})
}
