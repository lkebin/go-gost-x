package hysteria

import (
	"context"
	"net"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("hysteria", NewConnector)
}

type hyConnector struct {
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &hyConnector{
		options: options,
	}
}

func (c *hyConnector) Init(md md.Metadata) error {
	return nil
}

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
			raddr := conn.RemoteAddr()
			if raddr == nil {
				raddr = &net.UDPAddr{}
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
