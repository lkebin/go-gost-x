package wg

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// conn is the tunnel handle returned by wgDialer.Dial. It carries no payload
// of its own: connector/wg uses it to open per-destination connections inside
// the tunnel (mirrors dialer/hysteria's hyClientConn).
type conn struct {
	net    *netstack.Net
	hasDNS bool
}

// TCP dials addr inside the tunnel.
func (c *conn) TCP(ctx context.Context, addr string) (net.Conn, error) {
	ap, err := c.addrPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	return c.net.DialContextTCPAddrPort(ctx, ap)
}

// UDP dials addr inside the tunnel, returning a connected datagram socket.
func (c *conn) UDP(ctx context.Context, addr string) (net.PacketConn, error) {
	ap, err := c.addrPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	return c.net.DialUDPAddrPort(netip.AddrPort{}, ap)
}

// addrPort resolves addr to an ip:port usable inside the tunnel. Domains are
// only resolved when a dns server is configured: wireguard-go's netstack
// degrades to an empty lookup when it has no dns servers, so we refuse early
// with an explicit error instead.
func (c *conn) addrPort(ctx context.Context, addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wg: invalid address %q: %w", addr, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wg: invalid port %q: %w", port, err)
	}

	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, uint16(p)), nil
	}
	if !c.hasDNS {
		return netip.AddrPort{}, fmt.Errorf("wg: %q is not an IP address and no dns is configured", addr)
	}

	ips, err := c.net.LookupContextHost(ctx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wg: resolve %q: %w", host, err)
	}
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			return netip.AddrPortFrom(a, uint16(p)), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("wg: resolve %q: no usable address", host)
}

// net.Conn: the handle is a placeholder, all payload flows through TCP/UDP.

func (c *conn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *conn) Write(b []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *conn) Close() error                       { return nil }
func (c *conn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *conn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *conn) SetDeadline(t time.Time) error      { return nil }
func (c *conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*conn)(nil)
