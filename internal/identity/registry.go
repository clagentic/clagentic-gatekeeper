package identity

import (
	"sync"
	"time"
)

// issuedTo records which process an assertion was issued to.
type issuedTo struct {
	// uid is the SO_PEERCRED uid, the only credential a grant may rest on; pid
	// and startTime narrow a grant further but never widen it.
	uid       uint32
	pid       int32
	startTime uint64
	exp       int64
}

// Registry remembers, in memory, the process each live assertion went to, so
// issue-child can tie a parent token to the pid that asks for a child. It is
// deliberately not persisted: after a restart a holder asks for a new
// session, which keeps the pid binding from outliving the process it was made
// for.
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
