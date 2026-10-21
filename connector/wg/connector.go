package wg

import (
	"context"
	"fmt"
	"net"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("wg", NewConnector)
}

type wgConnector struct {
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &wgConnector{options: options}
}

func (c *wgConnector) Init(md md.Metadata) error {
	return nil
}

// tunnels is implemented by the connection handle returned by dialer/wg.
type tunnels interface {
	TCP(ctx context.Context, addr string) (net.Conn, error)
	UDP(ctx context.Context, addr string) (net.PacketConn, error)
}

// Connect dials the target inside the WireGuard tunnel. The incoming conn is
// the tunnel handle, not a data connection: it is closed once the real
// per-destination connection exists.
func (c *wgConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	t, ok := conn.(tunnels)
	if !ok {
		return nil, fmt.Errorf("wg: unsupported connection type %T", conn)
	}

	switch network {
	case "udp", "udp4", "udp6":
		pc, err := t.UDP(ctx, address)
		if err != nil {
			return nil, err
		}
		// gost's UDP paths expect a conn that is both a net.Conn and a
		// net.PacketConn (netstack's gonet.UDPConn is both; a plain
		// net.PacketConn does not satisfy net.Conn).
		cc, ok := pc.(net.Conn)
		if !ok {
			return nil, fmt.Errorf("wg: udp connection %T is not a net.Conn", pc)
		}
		conn.Close()
		return cc, nil
	default:
		cc, err := t.TCP(ctx, address)
		if err != nil {
			return nil, err
		}
		conn.Close()
		return cc, nil
	}
}
