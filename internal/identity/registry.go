//go:build linux

package identity

import (
	"sync"
	"time"
)

// issuedTo records which runtime process an assertion was issued to: the
// process that owns the session, which for a request made by a hook or the CLI
// is the runtime above it (bindRuntime), not the transient requester.
type issuedTo struct {
	// uid is the SO_PEERCRED uid, the only credential a grant may rest on; pid
	// and startTime narrow a grant further but never widen it.
	uid       uint32
	pid       int32
	startTime uint64
	// exeDev and exeIno pin the executable file, so an exec that keeps pid and
	// start time still ends the binding.
	exeDev, exeIno uint64
	exp            int64
}

// Registry remembers, in memory, the process each live assertion went to, so
// issue-child can tie a parent token to the pid that asks for a child. It is
// deliberately not persisted: after a restart a holder asks for a new
// session, which keeps the runtime binding from outliving the process it was
// made for.
type Registry struct {
	mu      sync.Mutex
	entries map[string]issuedTo
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{entries: map[string]issuedTo{}} }

func (r *Registry) put(jti string, e issuedTo, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.entries {
		if v.exp <= now.Unix() {
			delete(r.entries, k)
		}
	}
	r.entries[jti] = e
}

func (r *Registry) get(jti string) (issuedTo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[jti]
	return e, ok
}
