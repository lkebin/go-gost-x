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
