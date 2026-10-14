//go:build linux

package identity

import (
	"bytes"
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

const maxRequestBytes = 64 << 10

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
		s.writeRefusal(w, refuse(http.StatusInternalServerError, CodeInternal, err))
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
		s.writeRefusal(w, refuse(http.StatusForbidden, CodePeerUnattested, errors.New("no peer credentials for this connection")))
		return Peer{}, false
	}
	if err := decodeOneObject(http.MaxBytesReader(w, r.Body, maxRequestBytes), into); err != nil {
		s.writeRefusal(w, refuse(http.StatusBadRequest, CodeBadRequest, err))
		return Peer{}, false
	}
	return peer, true
}

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
			s.writeRefusal(w, refuse(http.StatusInternalServerError, CodeInternal, err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// writeRefusal sends only the public code and message; the internal cause, if
// any, goes to the server log with the code.
func (s *Server) writeRefusal(w http.ResponseWriter, e *IssueError) {
	logf := s.Logf
	if logf == nil {
		logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	}
	logf("identity: refused %s (%d): %v", e.Code, e.Status, e.detail)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

// listenAfterBind, when set by a test, runs once the temporary socket exists and
// before it is chmodded or linked, which is the only window in which a name
// bound to the listener is not yet at its final mode.
var listenAfterBind func(privateDir, tempSocket string)

// Listen binds the socket and refuses to start when anything already exists at
// path, whatever it is. The directory that holds path is a trust root: it and
// every ancestor must be owned by root or the serving uid and not writable by
// group or other, and its final component is created when missing. Invariants,
// for every caller and under any process umask:
//
//   - no name bound to the listener is ever connectable by a uid that mode
//     excludes. The socket is first bound inside a fresh directory created by
//     this call and chmodded to 0700 explicitly (so umask cannot widen it); only
//     the serving uid can reach anything inside it. The socket is given mode
//     there, then linked to path, so path does not exist until it carries mode.
//   - nothing at path is ever unlinked. The link step fails if path exists
//     (link(2) never replaces), so two issuers can never both own the path, and
//     the listener is not asked to unlink on Close. The only names this function
//     removes are the temporary socket and the private directory it created.
//
// Cleanup of a leftover socket, including after a graceful stop, belongs to the
// operator or the service manager.
//
// bind(2), chmod and link(2) take a path and AF_UNIX has no *at form. The
// paths used for them are built from the verified directory plus a name this
// call generated, and no uid but the serving uid and root can alter any
// component of them; everything else here goes through the directory handle.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	path = filepath.Clean(path)
	dirPath := filepath.Dir(path)
	dir, err := openTrustedDir(dirPath, 0o755)
	if err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}
	defer dir.Close()
	dfd := int(dir.Fd())

	id, err := randomID()
	if err != nil {
		return nil, err
	}
	privName := ".gk-" + id[:16]
	if err := syscall.Mkdirat(dfd, privName, 0o700); err != nil {
		return nil, err
	}
	// cleanup removes only the directory this call created and its contents.
	cleanup := func() { _ = removeAt(dfd, privName) }
	pfd, err := syscall.Openat(dfd, privName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		cleanup()
		return nil, err
	}
	// Mkdirat is filtered by the umask; fchmod is not.
	err = syscall.Fchmod(pfd, 0o700)
	syscall.Close(pfd)
	if err != nil {
		cleanup()
		return nil, err
	}
	private := filepath.Join(dirPath, privName)
	tmp := filepath.Join(private, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		cleanup()
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	discard := func(cause error) (net.Listener, error) {
		l.Close()
		cleanup()
		return nil, cause
	}
	if listenAfterBind != nil {
		listenAfterBind(private, tmp)
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
	// The socket is already published with its mode; a leftover private
	// directory is unreachable to other uids, but report it.
	if err := removeAt(dfd, privName); err != nil {
		fmt.Fprintf(os.Stderr, "identity: could not remove temporary socket directory %s: %v\n", private, err)
	}
	return publishedListener{UnixListener: l, addr: &net.UnixAddr{Name: path, Net: "unix"}}, nil
}

// publishedListener reports the path the socket was published at. The
// embedded listener is bound to a temporary name that no longer exists.
type publishedListener struct {
	*net.UnixListener
	addr net.Addr
}

func (p publishedListener) Addr() net.Addr { return p.addr }

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

// DefaultSocketMode is the socket mode when identity.socket_mode is unset: the
// serving uid only. Who may ask is decided in-process from SO_PEERCRED, which
// admits the serving uid alone; the mode is a second layer, and widening it
// never admits another uid.
const DefaultSocketMode os.FileMode = 0o600

// ParseSocketMode parses an octal permission string such as "0660".
func ParseSocketMode(s string) (os.FileMode, error) {
	if s == "" {
		return DefaultSocketMode, nil
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("identity.socket_mode %q is not an octal permission", s)
	}
	return os.FileMode(n), nil
}
