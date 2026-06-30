package hysteria

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	netdialer "github.com/go-gost/x/internal/net/dialer"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("hysteria", NewDialer)
}

type hysteriaDialer struct {
	sessions     map[string]*hySession
	sessionMutex sync.Mutex
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

type hySession struct {
	client.Client
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &hysteriaDialer{
		sessions: make(map[string]*hySession),
		logger:   options.Logger,
		options:  options,
	}
}

func (d *hysteriaDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *hysteriaDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
	if !ok {
		tlsCfg := d.options.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}

		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(strings.Trim(addr, "[]"), "443")
		}
		serverAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}

		hyClient, _, err := client.NewClient(&client.Config{
			ServerAddr:  serverAddr,
			Auth:        d.md.auth,
			ConnFactory: &hyConnFactory{logger: d.logger},
			TLSConfig: client.TLSConfig{
				ServerName:         tlsCfg.ServerName,
				InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
				RootCAs:            tlsCfg.RootCAs,
			},
			QUICConfig: client.QUICConfig{
				KeepAlivePeriod: d.md.keepAlivePeriod,
				MaxIdleTimeout:  d.md.maxIdleTimeout,
			},
			CongestionConfig: client.CongestionConfig{
				Type: d.md.congestionType,
			},
			BandwidthConfig: client.BandwidthConfig{
				MaxTx: d.md.bandwidthTx,
				MaxRx: d.md.bandwidthRx,
			},
			FastOpen: d.md.fastOpen,
		})
		if err != nil {
			return nil, err
		}

		session = &hySession{Client: hyClient}
		d.sessions[addr] = session
	}

	if d.md.direct {
		return &hyClientConn{Client: session.Client}, nil
	}

	conn, err = session.TCP("0.0.0.0:0")
	if err != nil {
		session.Close()
		delete(d.sessions, addr)
		return nil, err
	}

	return
}

type hyClientConn struct {
	client.Client
}

func (c *hyClientConn) Read(b []byte) (int, error)     { return 0, io.EOF }
func (c *hyClientConn) Write(b []byte) (int, error)    { return 0, io.EOF }
func (c *hyClientConn) Close() error                   { return nil }
func (c *hyClientConn) LocalAddr() net.Addr            { return nil }
func (c *hyClientConn) RemoteAddr() net.Addr           { return nil }
func (c *hyClientConn) SetDeadline(t time.Time) error  { return nil }
func (c *hyClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *hyClientConn) SetWriteDeadline(t time.Time) error { return nil }

func (d *hysteriaDialer) Multiplex() bool {
	return true
}

// hyConnFactory is a hysteria ConnFactory that applies gost's global
// socket control hook to the UDP socket, so that on Android the QUIC
// traffic can bypass VPN routing via VpnService.protect().
type hyConnFactory struct {
	logger logger.Logger
}

func (f *hyConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	network := "udp"
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr.IP != nil {
		if udpAddr.IP.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if fn := netdialer.GlobalSocketControl; fn != nil {
					fn(fd)
				}
			})
		},
	}
	return lc.ListenPacket(context.Background(), network, "")
}
