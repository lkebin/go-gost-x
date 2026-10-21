package wg

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	xwg "github.com/go-gost/x/dialer/wg"
	xmetadata "github.com/go-gost/x/metadata"
)

const e2eMTU = 1420

var (
	e2eServerAddr = netip.MustParseAddr("10.7.0.1")
	e2eClientAddr = netip.MustParseAddr("10.7.0.2")
)

// newTunnelDialer builds a dialer/wg client pointing at the in-process server.
func newTunnelDialer(t *testing.T, server keyPair, client keyPair, serverPort uint16, allowed ...string) dialer.Dialer {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{e2eServerAddr.String() + "/32"}
	}
	d := xwg.NewDialer()
	if err := d.Init(xmetadata.NewMetadata(map[string]any{
		"privateKey":    b64(client.priv),
		"peerPublicKey": b64(server.pub),
		"endpoint":      net.JoinHostPort("127.0.0.1", strconv.Itoa(int(serverPort))),
		"localIPs":      e2eClientAddr.String() + "/32",
		"allowedIPs":    allowed,
		"mtu":           e2eMTU,
	})); err != nil {
		t.Fatalf("init dialer: %v", err)
	}
	return d
}

func TestE2E_TCPThroughTunnel(t *testing.T) {
	serverKP, clientKP := newKeyPair(t), newKeyPair(t)
	port, ns, cleanup := startWGServer(t, serverKP, clientKP.pub, e2eServerAddr, e2eClientAddr, e2eMTU)
	defer cleanup()
	echoPort := startTCPEcho(t, ns, e2eServerAddr)

	d := newTunnelDialer(t, serverKP, clientKP, port)
	defer d.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := d.Dial(ctx, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cc, err := NewConnector().Connect(ctx, handle, "tcp",
		netip.AddrPortFrom(e2eServerAddr, uint16(echoPort)).String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cc.Close()

	payload := []byte("hello wireguard")
	if _, err := cc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
}

func TestE2E_UDPThroughTunnel(t *testing.T) {
	serverKP, clientKP := newKeyPair(t), newKeyPair(t)
	port, ns, cleanup := startWGServer(t, serverKP, clientKP.pub, e2eServerAddr, e2eClientAddr, e2eMTU)
	defer cleanup()
	echoPort := startUDPEcho(t, ns, e2eServerAddr)

	d := newTunnelDialer(t, serverKP, clientKP, port)
	defer d.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := d.Dial(ctx, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cc, err := NewConnector().Connect(ctx, handle, "udp",
		netip.AddrPortFrom(e2eServerAddr, uint16(echoPort)).String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cc.Close()

	pc, ok := cc.(net.PacketConn)
	if !ok {
		t.Fatalf("udp connection is %T, want net.PacketConn", cc)
	}

	payload := []byte("ping")
	if _, err := pc.WriteTo(payload, &net.UDPAddr{IP: e2eServerAddr.AsSlice(), Port: echoPort}); err != nil {
		t.Fatalf("write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}
}

// WireGuard silently drops packets whose destination is outside the peer's
// allowed IPs, so the failure surfaces as a timeout, not as an error from
// Connect. This test pins that behaviour.
func TestE2E_OutsideAllowedIPsTimesOut(t *testing.T) {
	serverKP, clientKP := newKeyPair(t), newKeyPair(t)
	port, _, cleanup := startWGServer(t, serverKP, clientKP.pub, e2eServerAddr, e2eClientAddr, e2eMTU)
	defer cleanup()

	d := newTunnelDialer(t, serverKP, clientKP, port, "10.7.0.0/24")
	defer d.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	handle, err := d.Dial(ctx, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := NewConnector().Connect(ctx, handle, "tcp", "10.9.9.9:80"); err == nil {
		t.Fatal("expected a timeout error for a destination outside allowedIPs")
	}
}
