package hysteria

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

// mockHyClientConn implements net.Conn and exposes UDP() for connector type-assertion.
type mockHyClientConn struct {
	hyUDP client.HyUDPConn
}

func (m *mockHyClientConn) Read(b []byte) (int, error)     { return 0, nil }
func (m *mockHyClientConn) Write(b []byte) (int, error)    { return 0, nil }
func (m *mockHyClientConn) Close() error                   { return nil }
func (m *mockHyClientConn) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (m *mockHyClientConn) RemoteAddr() net.Addr           { return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443} }
func (m *mockHyClientConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockHyClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockHyClientConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockHyClientConn) TCP(addr string) (net.Conn, error) { return nil, nil }
func (m *mockHyClientConn) UDP() (client.HyUDPConn, error) {
	return m.hyUDP, nil
}

// plainMockConn implements only net.Conn without UDP().
type plainMockConn struct{}

func (p *plainMockConn) Read(b []byte) (int, error)     { return 0, nil }
func (p *plainMockConn) Write(b []byte) (int, error)    { return 0, nil }
func (p *plainMockConn) Close() error                   { return nil }
func (p *plainMockConn) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (p *plainMockConn) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (p *plainMockConn) SetDeadline(t time.Time) error      { return nil }
func (p *plainMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *plainMockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHyConnector_Connect_UDP(t *testing.T) {
	c := &hyConnector{}
	mockConn := &mockHyClientConn{hyUDP: newMockHyUDPConn()}

	result, err := c.Connect(context.Background(), mockConn, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pc, ok := result.(*hyPacketConn)
	if !ok {
		t.Fatalf("expected *hyPacketConn, got %T", result)
	}
	if _, ok := result.(net.PacketConn); !ok {
		t.Fatal("result does not implement net.PacketConn")
	}
	// Verify raddr is the TARGET address (8.8.8.8:53), not the hysteria server address
	udpAddr, ok := pc.raddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("raddr should be *net.UDPAddr, got %T", pc.raddr)
	}
	if udpAddr.String() != "8.8.8.8:53" {
		t.Fatalf("expected raddr 8.8.8.8:53, got %s", udpAddr.String())
	}
}

func TestHyConnector_Connect_UDP_NoInterface(t *testing.T) {
	c := &hyConnector{}
	conn := &plainMockConn{}

	result, err := c.Connect(context.Background(), conn, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != conn {
		t.Fatal("expected conn to be returned unchanged")
	}
}

func TestHyConnector_Connect_TCP(t *testing.T) {
	c := &hyConnector{}
	mockConn := &mockHyClientConn{}

	result, err := c.Connect(context.Background(), mockConn, "tcp", "1.1.1.1:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil from mock TCP, got %T", result)
	}
}

// orderedMockConn tracks call order to verify Close happens after UDP/TCP.
type orderedMockConn struct {
	calls []string
	hyUDP client.HyUDPConn
}

func (m *orderedMockConn) Read(b []byte) (int, error)     { m.calls = append(m.calls, "Read"); return 0, nil }
func (m *orderedMockConn) Write(b []byte) (int, error)    { m.calls = append(m.calls, "Write"); return 0, nil }
func (m *orderedMockConn) Close() error                   { m.calls = append(m.calls, "Close"); return nil }
func (m *orderedMockConn) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (m *orderedMockConn) RemoteAddr() net.Addr           { return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443} }
func (m *orderedMockConn) SetDeadline(t time.Time) error  { return nil }
func (m *orderedMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *orderedMockConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *orderedMockConn) TCP(addr string) (net.Conn, error)  {
	m.calls = append(m.calls, "TCP")
	return nil, nil
}
func (m *orderedMockConn) UDP() (client.HyUDPConn, error) {
	m.calls = append(m.calls, "UDP")
	return m.hyUDP, nil
}

func (m *orderedMockConn) lastCall() string {
	if len(m.calls) == 0 {
		return ""
	}
	return m.calls[len(m.calls)-1]
}

func (m *orderedMockConn) closeIndex() int {
	for i, c := range m.calls {
		if c == "Close" {
			return i
		}
	}
	return -1
}

func TestHyConnector_Connect_UDP_ClosesAfterUDP(t *testing.T) {
	c := &hyConnector{}
	mock := &orderedMockConn{hyUDP: newMockHyUDPConn()}

	_, err := c.Connect(context.Background(), mock, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	closeIdx := mock.closeIndex()
	if closeIdx < 0 {
		t.Fatal("Close was never called")
	}
	if closeIdx == 0 || mock.calls[closeIdx-1] != "UDP" {
		t.Fatalf("UDP must be called before Close, got calls: %v", mock.calls)
	}
}

func TestHyConnector_Connect_TCP_ClosesAfterTCP(t *testing.T) {
	c := &hyConnector{}
	mock := &orderedMockConn{}

	_, err := c.Connect(context.Background(), mock, "tcp", "1.1.1.1:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	closeIdx := mock.closeIndex()
	if closeIdx < 0 {
		t.Fatal("Close was never called")
	}
	if closeIdx == 0 || mock.calls[closeIdx-1] != "TCP" {
		t.Fatalf("TCP must be called before Close, got calls: %v", mock.calls)
	}
}
