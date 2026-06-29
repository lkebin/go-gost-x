package hysteria

import (
	"crypto/tls"
	"net"
	"strings"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("hysteria", NewListener)
}

type hysteriaListener struct {
	server  server.Server
	ln      net.PacketConn
	queue   chan net.Conn
	errChan chan error
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &hysteriaListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *hysteriaListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	addr := l.options.Addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "443")
	}

	network := "udp"
	if xnet.IsIPv4(addr) {
		network = "udp4"
	}
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return
	}
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return
	}
	l.ln = conn

	l.queue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	tlsCfg := l.options.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}

	sv, err := server.NewServer(&server.Config{
		TLSConfig: server.TLSConfig{
			Certificates:   tlsCfg.Certificates,
			GetCertificate: tlsCfg.GetCertificate,
		},
		Conn: conn,
		QUICConfig: server.QUICConfig{
			MaxIdleTimeout: l.md.maxIdleTimeout,
		},
		CongestionConfig: server.CongestionConfig{
			Type: l.md.congestionType,
		},
		BandwidthConfig: server.BandwidthConfig{
			MaxTx: l.md.bandwidthTx,
			MaxRx: l.md.bandwidthRx,
		},
		IgnoreClientBandwidth: l.md.bandwidthTx <= 0 && l.md.bandwidthRx <= 0,
		DisableUDP:            l.md.disableUDP,
		Authenticator: &passwordAuthenticator{
			password: l.md.auth,
		},
		Outbound: &hyOutbound{
			queue: l.queue,
			laddr: conn.LocalAddr(),
		},
	})
	if err != nil {
		conn.Close()
		return err
	}

	l.server = sv

	go func() {
		if err := sv.Serve(); err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()

	return
}

func (l *hysteriaListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.queue:
	case err, ok = <-l.errChan:
		if !ok {
			err = listener.ErrClosed
		}
	}
	return
}

func (l *hysteriaListener) Close() error {
	return l.server.Close()
}

func (l *hysteriaListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

type passwordAuthenticator struct {
	password string
}

func (a *passwordAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	return auth == a.password, ""
}
