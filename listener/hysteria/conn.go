package hysteria

import "net"

type hyConn struct {
	net.Conn
	laddr net.Addr
	raddr net.Addr
}

func (c *hyConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *hyConn) RemoteAddr() net.Addr {
	return c.raddr
}
