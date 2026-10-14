package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Wire paths. JWKS discovery uses the contract's fixed path.
const (
	PathJWKS         = "/.well-known/jwks.json"
	PathIssueSession = "/v1/issue-session"
	PathIssueChild   = "/v1/issue-child"
)

const maxRequestBytes = 64 << 10

// DefaultSocketPath is used when neither --socket nor identity.socket_path is set.
const DefaultSocketPath = "/run/clagentic-gatekeeper/identity.sock"

type peerKey struct{}

// peerConn carries the credentials read at accept time with the connection,
// so a handler can never see a peer other than the one that connected.
type peerConn struct {
	net.Conn
	peer Peer
}

type peerListener struct{ net.Listener }

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		p, err := peerCred(uc)
		if err != nil {
			// A connection whose peer cannot be attested is dropped, not served.
			c.Close()
			continue
		}
		return &peerConn{Conn: c, peer: p}, nil
	}
}

// Server serves the issuer over a unix socket.
type Server struct {
	Issuer *Issuer
	// Logf receives the internal cause of a refusal; nil logs to stderr.
	Logf func(format string, args ...any)
}

// Handler returns the HTTP surface; the peer is taken from the request
// context set by ConnContext.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathJWKS, s.jwks)
	mux.HandleFunc("POST "+PathIssueSession, s.issueSession)
	mux.HandleFunc("POST "+PathIssueChild, s.issueChild)
	return mux
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	body, err := s.Issuer.Keys.MarshalJWKS()
	if err != nil {
		s.writeRefusal(w, refuseInternal(http.StatusInternalServerError, "internal", publicInternalMessage, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=60")
	_, _ = w.Write(body)
}

func peerOf(r *http.Request) (Peer, bool) {
	p, ok := r.Context().Value(peerKey{}).(Peer)
	return p, ok
}

func (s *Server) issueSession(w http.ResponseWriter, r *http.Request) {
	var req SessionRequest
	peer, ok := s.decode(w, r, &req)
	if !ok {
		return
	}
	s.respond(w)(s.Issuer.IssueSession(peer, req))
}

func (s *Server) issueChild(w http.ResponseWriter, r *http.Request) {
	var req ChildRequest
	peer, ok := s.decode(w, r, &req)
	if !ok {
		return
	}
	s.respond(w)(s.Issuer.IssueChild(peer, req))
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, into any) (Peer, bool) {
	peer, ok := peerOf(r)
	if !ok {
		s.writeRefusal(w, refuse(http.StatusForbidden, "peer_unattested", "no peer credentials for this connection"))
		return Peer{}, false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil && !errors.Is(err, io.EOF) {
		s.writeRefusal(w, refuse(http.StatusBadRequest, "bad_request", "request body: %v", err))
		return Peer{}, false
	}
	return peer, true
}

func (s *Server) respond(w http.ResponseWriter) func(*Issued, error) {
	return func(out *Issued, err error) {
		if err != nil {
			if ie, ok := IsIssueError(err); ok {
				s.writeRefusal(w, ie)
				return
			}
			s.writeRefusal(w, refuseInternal(http.StatusInternalServerError, "internal", publicInternalMessage, err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// writeRefusal sends only the public code and message; the internal cause, if
// any, goes to the server log.
func (s *Server) writeRefusal(w http.ResponseWriter, e *IssueError) {
	if e.Detail != nil {
		logf := s.Logf
		if logf == nil {
			logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
		}
		logf("identity: refused %s (%d): %v", e.Code, e.Status, e.Detail)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

// probeSocket tries to connect to path. It is a variable so a test can produce
// outcomes (a timeout from a backlogged server) a filesystem cannot on demand.
var probeSocket = func(path string) error {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		c.Close()
	}
	return err
}

// Listen binds the socket. A leftover socket file is replaced only when it is
// provably stale: a socket owned by the serving uid whose probe is refused
// outright (ECONNREFUSED, nothing is listening). A probe that merely failed,
// such as a timeout from a live but paused or backlogged server, proves
// nothing, and unlinking then would let a second issuer bind the path, so
// Listen refuses and names the path.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	default:
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if uid, ok := ownerUID(fi); !ok || int(uid) != os.Geteuid() {
			return nil, fmt.Errorf("%s exists and is not owned by the serving uid; remove it by hand if it is stale", path)
		}
		perr := probeSocket(path)
		if perr == nil {
			return nil, fmt.Errorf("another server is already listening on %s", path)
		}
		if !errors.Is(perr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot tell whether a server is listening on %s (%v); remove the file by hand if it is stale", path, perr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve answers on l until ctx is done. It reaps stale delivery directories
// on start and hourly.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(*peerConn); ok {
				return context.WithValue(ctx, peerKey{}, pc.peer)
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	go s.reapLoop(ctx)
	err := srv.Serve(peerListener{l})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) reapLoop(ctx context.Context) {
	maxAge := 2 * MaxLifetimeSeconds * time.Second
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		n, err := s.Issuer.Dirs.Reap(s.Issuer.Now(), maxAge)
		if n > 0 {
			fmt.Fprintf(os.Stderr, "identity: removed %d stale spawn directories\n", n)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "identity: stale spawn directories remain: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ParseSocketMode parses an octal permission string such as "0666".
func ParseSocketMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0o666, nil
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("identity.socket_mode %q is not an octal permission", s)
	}
	return os.FileMode(n), nil
}
