# Hysteria UDP Datagram Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add UDP datagram relay through hysteria's native QUIC datagram channel by adapting `client.HyUDPConn` to `net.PacketConn` in the connector layer.

**Architecture:** The connector's `Connect` method receives `network` — when it's `"udp"`, type-assert for `UDP()` on the connection (already embedded in `hyClientConn` via `client.Client`), get a `HyUDPConn`, and wrap it in a new `hyPacketConn` adapter. The adapter implements both `net.PacketConn` and `net.Conn`.

**Tech Stack:** Go 1.26.3, `github.com/apernet/hysteria/core/v2` v2.9.3, `github.com/go-gost/core` v0.4.1

---

### Task 1: Create mock HyUDPConn for testing

**Files:**
- Create: `connector/hysteria/packet_conn_test.go`

- [ ] **Step 1: Write the test file with mock and compile-time interface check**

```go
package hysteria

import (
	"errors"
	"net"
	"sync"

	"github.com/apernet/hysteria/core/v2/client"
)

// mockHyUDPConn implements client.HyUDPConn for testing.
type mockHyUDPConn struct {
	mu       sync.Mutex
	closed   bool
	recvCh   chan recvPacket
	sendErrs map[string]error // keyed by target address
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

// compile-time check
var _ net.PacketConn = (*hyPacketConn)(nil)
```

- [ ] **Step 2: Run go build to verify it fails — hyPacketConn doesn't exist yet**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./connector/hysteria/...
```

Expected: FAIL — `undefined: hyPacketConn`

- [ ] **Step 3: Commit**

```bash
git add connector/hysteria/packet_conn_test.go
git commit -m "test: add mock HyUDPConn and compile-time check for hyPacketConn"
```

---

### Task 2: Write hyPacketConn unit tests (RED)

**Files:**
- Modify: `connector/hysteria/packet_conn_test.go`

- [ ] **Step 1: Add TestHyPacketConn_ReadFrom**

Append to `packet_conn_test.go`:

```go
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
```

- [ ] **Step 2: Add TestHyPacketConn_WriteTo**

```go
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
```

- [ ] **Step 3: Add TestHyPacketConn_Close**

```go
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
```

- [ ] **Step 4: Add TestHyPacketConn_SendError**

```go
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
```

- [ ] **Step 5: Add TestHyPacketConn_ReadReturnsError and TestHyPacketConn_WriteReturnsError**

```go
func TestHyPacketConn_ReadReturnsError(t *testing.T) {
	pc := &hyPacketConn{}
	_, err := pc.Read(make([]byte, 100))
	if err == nil {
		t.Fatal("expected error from Read (stream)")
	}
}

func TestHyPacketConn_WriteReturnsError(t *testing.T) {
	pc := &hyPacketConn{}
	_, err := pc.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected error from Write (stream)")
	}
}
```

- [ ] **Step 6: Run tests to verify they fail — hyPacketConn doesn't exist**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go test ./connector/hysteria/...
```

Expected: FAIL — `undefined: hyPacketConn`

- [ ] **Step 7: Commit**

```bash
git add connector/hysteria/packet_conn_test.go
git commit -m "test: add hyPacketConn unit tests (RED)"
```

---

### Task 3: Implement hyPacketConn (GREEN)

**Files:**
- Create: `connector/hysteria/packet_conn.go`

- [ ] **Step 1: Write the implementation**

```go
package hysteria

import (
	"errors"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

// hyPacketConn adapts hysteria's HyUDPConn to net.PacketConn.
// Also implements net.Conn with stub stream methods to satisfy
// the connector.Connect return type.
type hyPacketConn struct {
	hyUDP client.HyUDPConn
	raddr net.Addr
}

// net.PacketConn interface

func (c *hyPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.hyUDP == nil {
		return 0, nil, errors.New("hysteria: nil HyUDPConn")
	}
	data, addrStr, err := c.hyUDP.Receive()
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, data)
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		addr = &net.UDPAddr{}
	}
	return n, addr, nil
}

func (c *hyPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.hyUDP == nil {
		return 0, errors.New("hysteria: nil HyUDPConn")
	}
	if err := c.hyUDP.Send(b, addr.String()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *hyPacketConn) Close() error {
	if c.hyUDP == nil {
		return nil
	}
	return c.hyUDP.Close()
}

func (c *hyPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *hyPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *hyPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *hyPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// net.Conn stub methods — datagrams must use ReadFrom/WriteTo

func (c *hyPacketConn) Read(b []byte) (int, error) {
	return 0, errors.New("hysteria: use ReadFrom for datagrams")
}

func (c *hyPacketConn) Write(b []byte) (int, error) {
	return 0, errors.New("hysteria: use WriteTo for datagrams")
}

func (c *hyPacketConn) RemoteAddr() net.Addr {
	if c.raddr != nil {
		return c.raddr
	}
	return &net.UDPAddr{}
}
```

- [ ] **Step 2: Run unit tests to verify they pass**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go test ./connector/hysteria/ -v -run "TestHyPacketConn"
```

Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add connector/hysteria/packet_conn.go
git commit -m "feat: add hyPacketConn adapter for hysteria UDP"
```

---

### Task 4: Write connector UDP integration tests (RED)

**Files:**
- Create: `connector/hysteria/connector_test.go`

- [ ] **Step 1: Write the connector tests**

```go
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

	result, err := c.Connect(context.Background(), mockConn, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result.(*hyPacketConn); !ok {
		t.Fatalf("expected *hyPacketConn, got %T", result)
	}
	if _, ok := result.(net.PacketConn); !ok {
		t.Fatal("result does not implement net.PacketConn")
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
```

- [ ] **Step 2: Run connector tests to verify they fail**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go test ./connector/hysteria/ -v -run "TestHyConnector"
```

Expected: `TestHyConnector_Connect_UDP` FAIL — connector doesn't check `network == "udp"` yet.

- [ ] **Step 3: Commit**

```bash
git add connector/hysteria/connector_test.go
git commit -m "test: add connector UDP integration tests (RED)"
```

---

### Task 5: Add UDP branch to connector (GREEN)

**Files:**
- Modify: `connector/hysteria/connector.go`

- [ ] **Step 1: Add the UDP branch to Connect**

Replace the `Connect` method (lines 34-42) with:

```go
func (c *hyConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	if network == "udp" {
		if cc, ok := conn.(interface {
			UDP() (client.HyUDPConn, error)
		}); ok {
			conn.Close()
			hyUDP, err := cc.UDP()
			if err != nil {
				return nil, err
			}
			raddr := &net.UDPAddr{}
			if ra := conn.RemoteAddr(); ra != nil {
				raddr = ra
			}
			return &hyPacketConn{hyUDP: hyUDP, raddr: raddr}, nil
		}
		return conn, nil
	}

	if opener, ok := conn.(interface {
		TCP(string) (net.Conn, error)
	}); ok {
		conn.Close()
		return opener.TCP(address)
	}
	return conn, nil
}
```

- [ ] **Step 2: Add missing import**

Add `"github.com/apernet/hysteria/core/v2/client"` to the import block.

- [ ] **Step 3: Run all tests**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go test ./connector/hysteria/ -v
```

Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add connector/hysteria/connector.go
git commit -m "feat: add UDP datagram relay support to hysteria connector"
```

---

### Task 6: Build + vet verification

- [ ] **Step 1: Build the entire module**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./...
```

Expected: no errors

- [ ] **Step 2: Run go vet**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go vet ./connector/hysteria/...
```

Expected: no warnings

- [ ] **Step 3: Run all tests one final time**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go test ./connector/hysteria/ -v -count=1
```

Expected: all PASS

---

### Task 7: Final commit

- [ ] **Step 1: Commit any remaining changes**

```bash
git status
# If nothing left to commit, done.
```
