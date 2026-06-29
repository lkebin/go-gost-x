package hysteria

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
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

		serverAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}

		hyClient, _, err := client.NewClient(&client.Config{
			ServerAddr: serverAddr,
			Auth:       d.md.auth,
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

	target := ""
	if d.md.direct {
		target = addr
	}
	conn, err = session.TCP(target)
	if err != nil {
		session.Close()
		delete(d.sessions, addr)
		return nil, err
	}

	return
}

func (d *hysteriaDialer) Multiplex() bool {
	return true
}
