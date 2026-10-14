package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
		writeRefusal(w, refuse(http.StatusInternalServerError, "internal", "%v", err))
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
	peer, ok := decode(w, r, &req)
	if !ok {
		return
	}
	respond(w)(s.Issuer.IssueSession(peer, req))
}

func (s *Server) issueChild(w http.ResponseWriter, r *http.Request) {
	var req ChildRequest
	peer, ok := decode(w, r, &req)
	if !ok {
		return
	}
	respond(w)(s.Issuer.IssueChild(peer, req))
}

func decode(w http.ResponseWriter, r *http.Request, into any) (Peer, bool) {
	peer, ok := peerOf(r)
	if !ok {
		writeRefusal(w, refuse(http.StatusForbidden, "peer_unattested", "no peer credentials for this connection"))
		return Peer{}, false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil && !errors.Is(err, io.EOF) {
		writeRefusal(w, refuse(http.StatusBadRequest, "bad_request", "request body: %v", err))
		return Peer{}, false
	}
	return peer, true
}

func respond(w http.ResponseWriter) func(*Issued, error) {
	return func(out *Issued, err error) {
		if err != nil {
			if ie, ok := IsIssueError(err); ok {
				writeRefusal(w, ie)
				return
			}
			writeRefusal(w, refuse(http.StatusInternalServerError, "internal", "%v", err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func writeRefusal(w http.ResponseWriter, e *IssueError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

// Listen binds the socket. A leftover socket file from a dead server is
// replaced; a live one is an error.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another server is already listening on %s", path)
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
