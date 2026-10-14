//go:build linux

package identity

import (
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// oneShot hands out the queued connections, then fails like a closed listener.
type oneShot struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (o *oneShot) Accept() (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := o.conns[0]
	o.conns = o.conns[1:]
	return c, nil
}
func (o *oneShot) Close() error   { return nil }
func (o *oneShot) Addr() net.Addr { return &net.UnixAddr{Name: "test", Net: "unix"} }

// Every dropped connection leaves a server-side line with its cause, because
// the client sees only a closed socket.
func TestDroppedConnectionsAreLogged(t *testing.T) {
	sock := filepath.Join(shortSocketDir(t), "s")
	real, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := real.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// Reading SO_PEERCRED from a closed connection fails.
	accepted.Close()
	pipeA, pipeB := net.Pipe()
	defer pipeB.Close()

	var mu sync.Mutex
	var lines []string
	l := peerListener{
		Listener: &oneShot{conns: []net.Conn{pipeA, accepted}},
		logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, format)
		},
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("Accept returned a connection that could not be attested")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 {
		t.Fatalf("logged %d lines for 2 dropped connections: %q", len(lines), lines)
	}
	if !strings.Contains(lines[1], "peer attestation failed") {
		t.Errorf("attestation failure line: %q", lines[1])
	}
}
