package hysteria

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/apernet/hysteria/core/v2/client"
)

// mockHyUDPConn implements client.HyUDPConn for testing.
type mockHyUDPConn struct {
	mu       sync.Mutex
	closed   bool
	recvCh   chan recvPacket
	sendErrs map[string]error
}

type recvPacket struct {
	data []byte
	addr string
	err  error
}

var _ client.HyUDPConn = (*mockHyUDPConn)(nil)

func newMockHyUDPConn() *mockHyUDPConn {
	return &mockHyUDPConn{
		recvCh:   make(chan recvPacket, 10),
		sendErrs: make(map[string]error),
	}
}

func (m *mockHyUDPConn) Receive() ([]byte, string, error) {
	pkt, ok := <-m.recvCh
	if !ok {
		return nil, "", net.ErrClosed
	}
	return pkt.data, pkt.addr, pkt.err
}

func (m *mockHyUDPConn) Send(data []byte, addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	if err, ok := m.sendErrs[addr]; ok {
		return err
	}
	return nil
}

func (m *mockHyUDPConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	m.closed = true
	close(m.recvCh)
	return nil
}

func (m *mockHyUDPConn) queueReceive(data []byte, addr string) {
	m.recvCh <- recvPacket{data: data, addr: addr}
}

func (m *mockHyUDPConn) setSendError(addr string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendErrs[addr] = err
}

// compile-time check — will fail until hyPacketConn exists (Task 3)
var _ net.PacketConn = (*hyPacketConn)(nil)

func TestHyPacketConn_ReadFrom(t *testing.T) {
	mock := newMockHyUDPConn()
	pc := &hyPacketConn{hyUDP: mock}

	mock.queueReceive([]byte("hello"), "192.0.2.1:53")

	buf := make([]byte, 1500)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", buf[:n])
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}
	if udpAddr.IP.String() != "192.0.2.1" || udpAddr.Port != 53 {
		t.Fatalf("expected 192.0.2.1:53, got %s", addr)
	}
}

func TestHyPacketConn_WriteTo(t *testing.T) {
	mock := newMockHyUDPConn()
	pc := &hyPacketConn{hyUDP: mock}

	target := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	n, err := pc.WriteTo([]byte("query"), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}
}

func TestHyPacketConn_Close(t *testing.T) {
	mock := newMockHyUDPConn()
	pc := &hyPacketConn{hyUDP: mock}

	if err := pc.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	if _, _, err := pc.ReadFrom(make([]byte, 1500)); err == nil {
		t.Fatal("expected error after close")
	}

	if _, err := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}); err == nil {
		t.Fatal("expected error after close")
	}
}

func TestHyPacketConn_SendError(t *testing.T) {
	mock := newMockHyUDPConn()
	pc := &hyPacketConn{hyUDP: mock}

	sendErr := errors.New("send failed")
	mock.setSendError("1.1.1.1:53", sendErr)

	_, err := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53})
	if err == nil {
		t.Fatal("expected send error")
	}
}

func TestHyPacketConn_Read_DelegatesToReceive(t *testing.T) {
	mock := newMockHyUDPConn()
	pc := &hyPacketConn{hyUDP: mock}

	mock.queueReceive([]byte("hello"), "8.8.8.8:53")

	buf := make([]byte, 1500)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", buf[:n])
	}
}

func TestHyPacketConn_Write_DelegatesToSend(t *testing.T) {
	mock := newMockHyUDPConn()
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	pc := &hyPacketConn{hyUDP: mock, raddr: target}

	n, err := pc.Write([]byte("query"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}
}

func TestHyPacketConn_Write_NoRemoteAddr(t *testing.T) {
	pc := &hyPacketConn{hyUDP: newMockHyUDPConn()}
	_, err := pc.Write([]byte("query"))
	if err == nil {
		t.Fatal("expected error when raddr is nil")
	}
}
