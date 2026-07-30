package hysteria

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

// fakeClient is a stand-in for apernet's client.Client used to drive the
// liveness-invalidation logic without a real QUIC server.
type fakeClient struct {
	tcpErr error
	udpErr error
	closed bool
}

func (f *fakeClient) TCP(addr string) (net.Conn, error) {
	return nil, f.tcpErr
}

func (f *fakeClient) UDP() (client.HyUDPConn, error) {
	return nil, f.udpErr
}

func (f *fakeClient) Close() error {
	f.closed = true
	return nil
}

// errConn is a net.Conn whose Read always returns the configured error.
type errConn struct {
	err error
}

func (c *errConn) Read(b []byte) (int, error)         { return 0, c.err }
func (c *errConn) Write(b []byte) (int, error)        { return 0, nil }
func (c *errConn) Close() error                       { return nil }
func (c *errConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *errConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *errConn) SetDeadline(t time.Time) error       { return nil }
func (c *errConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *errConn) SetWriteDeadline(t time.Time) error  { return nil }

func TestIsDeadSession(t *testing.T) {
	if isDeadSession(nil) {
		t.Fatal("nil error must not be a dead session")
	}
	// quic-go IdleTimeoutError ("timeout: no recent network activity") is
	// wrapped by apernet as ClosedError whose Unwrap chain reaches net.ErrClosed.
	if !isDeadSession(coreErrs.ClosedError{Err: net.ErrClosed}) {
		t.Fatal("ClosedError wrapping net.ErrClosed must be a dead session")
	}
	// A clean stream close must NOT count.
	if isDeadSession(io.EOF) {
		t.Fatal("io.EOF must not be a dead session")
	}
	// A server-side DialError (target unreachable, session still alive) must NOT count.
	if isDeadSession(coreErrs.DialError{Message: "refused"}) {
		t.Fatal("DialError must not be a dead session")
	}
}

// TestHySession_TCP_DeadSession_Invalidates verifies that a stream-open
// failure on a dead session removes it from the cache and closes the client,
// so the next Dial rebuilds a fresh session instead of reusing the corpse.
func TestHySession_TCP_DeadSession_Invalidates(t *testing.T) {
	d := &hysteriaDialer{sessions: make(map[string]*hySession)}
	fc := &fakeClient{tcpErr: coreErrs.ClosedError{Err: net.ErrClosed}}
	s := &hySession{Client: fc, d: d, addr: "1.2.3.4:443"}
	d.sessions[s.addr] = s

	if _, err := s.TCP("8.8.8.8:443"); err == nil {
		t.Fatal("expected error from dead session")
	}
	if _, ok := d.sessions[s.addr]; ok {
		t.Fatal("dead session must be removed from cache")
	}
	if !fc.closed {
		t.Fatal("dead session client must be Closed")
	}
}

// TestHySession_TCP_NonDeadError_KeepsSession verifies that a non-fatal error
// (e.g. server rejects the target) does NOT evict an otherwise-healthy session.
func TestHySession_TCP_NonDeadError_KeepsSession(t *testing.T) {
	d := &hysteriaDialer{sessions: make(map[string]*hySession)}
	fc := &fakeClient{tcpErr: coreErrs.DialError{Message: "refused"}}
	s := &hySession{Client: fc, d: d, addr: "1.2.3.4:443"}
	d.sessions[s.addr] = s

	if _, err := s.TCP("8.8.8.8:443"); err == nil {
		t.Fatal("expected error from rejected dial")
	}
	if _, ok := d.sessions[s.addr]; !ok {
		t.Fatal("healthy session must be KEPT on non-dead error")
	}
	if fc.closed {
		t.Fatal("healthy session client must NOT be Closed")
	}
}

// TestInvalidatingConn_ReadDeadSession_Invalidates covers the half-dead case:
// a stream that opened successfully but later times out on read (the exact
// "timeout: no recent network activity" symptom) must invalidate the session.
func TestInvalidatingConn_ReadDeadSession_Invalidates(t *testing.T) {
	d := &hysteriaDialer{sessions: make(map[string]*hySession)}
	fc := &fakeClient{}
	s := &hySession{Client: fc, d: d, addr: "1.2.3.4:443"}
	d.sessions[s.addr] = s

	wrapped := &invalidatingConn{Conn: &errConn{err: coreErrs.ClosedError{Err: net.ErrClosed}}, s: s}
	if _, err := wrapped.Read(make([]byte, 8)); err == nil {
		t.Fatal("expected read error")
	}
	if _, ok := d.sessions[s.addr]; ok {
		t.Fatal("session must be invalidated after dead I/O error")
	}
}

// TestDirectMode_DialThenConnect_InvalidatesDeadSession exercises the exact
// path used in direct mode (the GostX VPN / SOCKS5 configuration): Dial returns
// hyClientConn{Client: *hySession}, and the connector opens the real stream via
// the embedded *hySession.TCP. The dispatch must go through hySession.TCP (not
// the bare apernet client) so a dead session is detected and evicted.
func TestDirectMode_DialThenConnect_InvalidatesDeadSession(t *testing.T) {
	d := &hysteriaDialer{sessions: make(map[string]*hySession)}
	fc := &fakeClient{tcpErr: coreErrs.ClosedError{Err: net.ErrClosed}}
	s := &hySession{Client: fc, d: d, addr: "1.2.3.4:443"}
	d.sessions[s.addr] = s

	// Direct-mode Dial returns a hyClientConn carrying the *hySession.
	hc := &hyClientConn{Client: s}

	// The connector type-asserts and opens the real stream — this must resolve
	// to *hySession.TCP (via the embedded client.Client interface), not apernet's.
	opener, ok := interface{}(hc).(interface{ TCP(string) (net.Conn, error) })
	if !ok {
		t.Fatal("hyClientConn must expose TCP(string) via embedded *hySession")
	}
	if _, err := opener.TCP("8.8.8.8:443"); err == nil {
		t.Fatal("expected error from dead session")
	}
	if _, ok := d.sessions[s.addr]; ok {
		t.Fatal("dead session must be invalidated through direct-mode connector path")
	}
}

// TestInvalidatingConn_ReadCleanEOF_KeepsSession verifies a clean EOF does not
// evict the session.
func TestInvalidatingConn_ReadCleanEOF_KeepsSession(t *testing.T) {
	d := &hysteriaDialer{sessions: make(map[string]*hySession)}
	fc := &fakeClient{}
	s := &hySession{Client: fc, d: d, addr: "1.2.3.4:443"}
	d.sessions[s.addr] = s

	wrapped := &invalidatingConn{Conn: &errConn{err: io.EOF}, s: s}
	if _, err := wrapped.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if _, ok := d.sessions[s.addr]; !ok {
		t.Fatal("session must be KEPT on clean EOF")
	}
}
