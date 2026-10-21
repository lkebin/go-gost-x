package wg

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tcpStub is a minimal net.Conn.
type tcpStub struct{}

func (c *tcpStub) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *tcpStub) Write(b []byte) (int, error)        { return len(b), nil }
func (c *tcpStub) Close() error                       { return nil }
func (c *tcpStub) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *tcpStub) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *tcpStub) SetDeadline(t time.Time) error      { return nil }
func (c *tcpStub) SetReadDeadline(t time.Time) error  { return nil }
func (c *tcpStub) SetWriteDeadline(t time.Time) error { return nil }

// udpStub is a minimal net.PacketConn that is also a net.Conn, mirroring
// netstack's gonet.UDPConn.
type udpStub struct{}

func (c *udpStub) Read(b []byte) (int, error)                { return 0, io.EOF }
func (c *udpStub) Write(b []byte) (int, error)               { return len(b), nil }
func (c *udpStub) ReadFrom(b []byte) (int, net.Addr, error)  { return 0, nil, io.EOF }
func (c *udpStub) WriteTo(b []byte, a net.Addr) (int, error) { return len(b), nil }
func (c *udpStub) Close() error                              { return nil }
func (c *udpStub) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *udpStub) RemoteAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *udpStub) SetDeadline(t time.Time) error             { return nil }
func (c *udpStub) SetReadDeadline(t time.Time) error         { return nil }
func (c *udpStub) SetWriteDeadline(t time.Time) error        { return nil }

// fakeTunnels plays the role of dialer/wg's tunnel handle.
type fakeTunnels struct {
	tcpAddr, udpAddr string
	tcpErr, udpErr   error
	closed           bool
	tcpConn          net.Conn
	udpConn          net.PacketConn
}

func (f *fakeTunnels) TCP(ctx context.Context, addr string) (net.Conn, error) {
	f.tcpAddr = addr
	return f.tcpConn, f.tcpErr
}
func (f *fakeTunnels) UDP(ctx context.Context, addr string) (net.PacketConn, error) {
	f.udpAddr = addr
	return f.udpConn, f.udpErr
}
func (f *fakeTunnels) Read(b []byte) (int, error)         { return 0, io.EOF }
func (f *fakeTunnels) Write(b []byte) (int, error)        { return len(b), nil }
func (f *fakeTunnels) Close() error                       { f.closed = true; return nil }
func (f *fakeTunnels) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (f *fakeTunnels) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (f *fakeTunnels) SetDeadline(t time.Time) error      { return nil }
func (f *fakeTunnels) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeTunnels) SetWriteDeadline(t time.Time) error { return nil }

func TestConnect_TCP(t *testing.T) {
	f := &fakeTunnels{tcpConn: &tcpStub{}}
	got, err := NewConnector().Connect(context.Background(), f, "tcp", "10.7.0.1:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || f.tcpAddr != "10.7.0.1:443" || !f.closed {
		t.Fatalf("got=%v tcpAddr=%q closed=%v", got, f.tcpAddr, f.closed)
	}
}

func TestConnect_TCP6Network(t *testing.T) {
	f := &fakeTunnels{tcpConn: &tcpStub{}}
	if _, err := NewConnector().Connect(context.Background(), f, "tcp6", "10.7.0.1:443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.tcpAddr != "10.7.0.1:443" {
		t.Fatalf("tcpAddr = %q", f.tcpAddr)
	}
}

func TestConnect_UDP(t *testing.T) {
	f := &fakeTunnels{udpConn: &udpStub{}}
	got, err := NewConnector().Connect(context.Background(), f, "udp4", "10.7.0.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || f.udpAddr != "10.7.0.1:53" || !f.closed {
		t.Fatalf("got=%v udpAddr=%q closed=%v", got, f.udpAddr, f.closed)
	}
	if _, ok := got.(net.PacketConn); !ok {
		t.Fatal("udp connections must be net.PacketConn")
	}
}

func TestConnect_Errors(t *testing.T) {
	c := NewConnector()

	wantErr := errors.New("boom")
	if _, err := c.Connect(context.Background(), &fakeTunnels{tcpErr: wantErr}, "tcp", "x:1"); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if _, err := c.Connect(context.Background(), &fakeTunnels{udpErr: wantErr}, "udp", "x:1"); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestConnect_WrongConnType(t *testing.T) {
	if _, err := NewConnector().Connect(context.Background(), &tcpStub{}, "tcp", "10.7.0.1:443"); err == nil {
		t.Fatal("expected an error for a connection that is not a tunnel handle")
	}
}

func TestInit(t *testing.T) {
	if err := NewConnector().Init(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
