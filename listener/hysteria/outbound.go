package hysteria

import (
	"net"

	"github.com/apernet/hysteria/core/v2/server"
)

type hyOutbound struct {
	queue chan<- net.Conn
	laddr net.Addr
}

func (ob *hyOutbound) TCP(reqAddr string) (net.Conn, error) {
	local, remote := net.Pipe()
	conn := &hyConn{
		Conn:  remote,
		laddr: ob.laddr,
		raddr: &hyAddr{network: "tcp", addr: reqAddr},
	}

	select {
	case ob.queue <- conn:
	default:
		remote.Close()
		local.Close()
	}
	return local, nil
}

func (ob *hyOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	return nil, net.ErrClosed
}

func (ob *hyOutbound) CheckUDP(reqAddr string) error {
	return net.ErrClosed
}

type hyAddr struct {
	network string
	addr    string
}

func (a *hyAddr) Network() string { return a.network }
func (a *hyAddr) String() string  { return a.addr }
