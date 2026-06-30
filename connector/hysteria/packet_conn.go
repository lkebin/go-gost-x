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

// net.Conn methods — delegate to ReadFrom/WriteTo for connected-UDP pattern (e.g. DNS)

// Read implements net.Conn.Read by delegating to ReadFrom and discarding
// the source address. This enables connected-UDP usage (e.g. DNS).
func (c *hyPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// Write implements net.Conn.Write by delegating to WriteTo with the
// stored remote address. This enables connected-UDP usage (e.g. DNS).
func (c *hyPacketConn) Write(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, errors.New("hysteria: no remote address for Write, use WriteTo")
	}
	return c.WriteTo(b, c.raddr)
}

func (c *hyPacketConn) RemoteAddr() net.Addr {
	if c.raddr != nil {
		return c.raddr
	}
	return &net.UDPAddr{}
}
