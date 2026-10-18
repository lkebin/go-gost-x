package wg

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"golang.org/x/crypto/curve25519"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type keyPair struct {
	priv [32]byte
	pub  [32]byte
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	var kp keyPair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(kp.pub[:], pub)
	return kp
}

func b64(k [32]byte) string    { return base64.StdEncoding.EncodeToString(k[:]) }
func hexKey(k [32]byte) string { return hex.EncodeToString(k[:]) }

// testBind records the UDP port the device actually bound to.
type testBind struct {
	wgconn.Bind
	port uint16
}

func (b *testBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	b.port = actual
	return fns, actual, err
}

// startWGServer starts an in-process WireGuard endpoint with a gVisor
// netstack and returns its UDP port plus the netstack.
func startWGServer(t *testing.T, server keyPair, clientPub [32]byte, serverAddr, clientAddr netip.Addr, mtu int) (uint16, *netstack.Net, func()) {
	t.Helper()

	tunDev, ns, err := netstack.CreateNetTUN([]netip.Addr{serverAddr}, nil, mtu)
	if err != nil {
		t.Fatalf("create netstack: %v", err)
	}

	b := &testBind{Bind: wgconn.NewDefaultBind()}
	dev := device.NewDevice(tunDev, b, device.NewLogger(device.LogLevelError, "wg-test:"))
	cfg := "private_key=" + hexKey(server.priv) + "\n" +
		"public_key=" + hexKey(clientPub) + "\n" +
		"allowed_ip=" + clientAddr.String() + "/32\n"
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		t.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("up: %v", err)
	}
	// Up() opens the bind synchronously (device.BindUpdate), so the port is
	// known here.
	if b.port == 0 {
		dev.Close()
		t.Fatal("server bind did not open a udp port")
	}
	return b.port, ns, func() { dev.Close() }
}

func startTCPEcho(t *testing.T, ns *netstack.Net, ip netip.Addr) int {
	t.Helper()
	ln, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(ip, 0))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener addr %q: %v", ln.Addr(), err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startUDPEcho(t *testing.T, ns *netstack.Net, ip netip.Addr) int {
	t.Helper()
	pc, err := ns.ListenUDPAddrPort(netip.AddrPortFrom(ip, 0))
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("udp addr %q: %v", pc.LocalAddr(), err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
