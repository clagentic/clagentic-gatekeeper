package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	if err := decodeOneObject(http.MaxBytesReader(w, r.Body, maxRequestBytes), into); err != nil {
		s.writeRefusal(w, refuseInternal(http.StatusBadRequest, "bad_request", publicBadBody, err))
		return Peer{}, false
	}
	return peer, true
}

const publicBadBody = "the request body must be exactly one JSON object with known members"

// decodeOneObject decodes a body that is a single JSON object and nothing
// else: empty, non-object, malformed, unknown-member and trailing content are
// all errors, so an operation never runs on a request only partly understood.
func decodeOneObject(body io.Reader, into any) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("body is not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after the JSON object")
	}
	return nil
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
	if e.detail != nil {
		logf := s.Logf
		if logf == nil {
			logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
		}
		logf("identity: refused %s (%d): %v", e.Code, e.Status, e.detail)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

// Listen binds the socket and refuses to start when anything already exists at
// path, whatever it is. Two invariants hold for every caller:
//
//   - path is never connectable with a mode other than mode. The socket is bound
//     at a private temporary name in the same directory, given mode there, and
//     only then linked to path, so path does not exist until it carries mode.
//   - nothing at path is ever unlinked. The link step fails if path exists
//     (link(2) never replaces), so two issuers can never both own the path, and
//     the listener is not asked to unlink on Close. The only name this function
//     removes is the temporary one it created itself.
//
// Cleanup of a leftover socket belongs to the operator or the service manager.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	tmp := filepath.Join(dir, ".gk-"+hex.EncodeToString(suffix[:]))
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	// discard releases the listener and removes only the temporary name.
	discard := func(cause error) (net.Listener, error) {
		l.Close()
		os.Remove(tmp)
		return nil, cause
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return discard(err)
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return discard(fmt.Errorf("%s already exists; refusing to start (it was left untouched; remove it yourself once no server uses it)", path))
		}
		return discard(fmt.Errorf("publish socket at %s: %w", path, err))
	}
	if err := os.Remove(tmp); err != nil {
		// The socket is already published with its mode; a leftover temporary
		// name is the same inode and is harmless to leave, but report it.
		fmt.Fprintf(os.Stderr, "identity: could not remove temporary socket name %s: %v\n", tmp, err)
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
	// A context that is already done must not leave Serve running: Shutdown can
	// win the race against Serve registering the listener, so the listener is
	// also closed here, which unblocks Accept whichever side ran first.
	if ctx.Err() != nil {
		l.Close()
		return nil
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		_ = l.Close()
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
