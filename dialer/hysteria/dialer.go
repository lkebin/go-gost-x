package hysteria

import (
	"context"
	"crypto/tls"
	"errors"
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

// apernet's client.Client interface (TCP/UDP/Close) does not expose the
// underlying QUIC connection's lifetime, so we cannot do a pre-use active()
// probe. Instead we invalidate reactively: any operation that surfaces a
// dead or half-dead session (a stream-open failure, or a read/write error
// on an already-opened stream) removes this session from the cache so the
// next Dial builds a fresh one. Without this, a silently-dead QUIC session
// (NAT rebind, network switch, server drop — the quic-go IdleTimeoutError
// "timeout: no recent network activity") is reused forever and every
// chained request fails until the process restarts.
type hySession struct {
	client.Client
	d    *hysteriaDialer
	addr string
}

// TCP opens a stream on the underlying session and wraps the returned
// net.Conn so a later read/write error (half-dead session) also invalidates
// the cache. A stream-open failure on a dead session invalidates immediately.
func (s *hySession) TCP(addr string) (net.Conn, error) {
	c, err := s.Client.TCP(addr)
	if err != nil {
		if isDeadSession(err) {
			s.invalidate()
		}
		return nil, err
	}
	return &invalidatingConn{Conn: c, s: s}, nil
}

// UDP opens a UDP session on the underlying session and wraps it so a later
// receive/send error (half-dead session) also invalidates the cache.
func (s *hySession) UDP() (client.HyUDPConn, error) {
	u, err := s.Client.UDP()
	if err != nil {
		if isDeadSession(err) {
			s.invalidate()
		}
		return nil, err
	}
	return &invalidatingUDPConn{HyUDPConn: u, s: s}, nil
}

// invalidate removes this session from the dialer cache and closes it, but
// only if it is still the current session for its address (a newer session
// may already have replaced it under the same address).
func (s *hySession) invalidate() {
	s.d.invalidate(s.addr, s)
}

// isDeadSession reports whether err indicates the QUIC session itself is
// dead/half-dead and must be discarded. apernet wraps non-recoverable QUIC
// errors (including quic-go's IdleTimeoutError "timeout: no recent network
// activity") as coreErrs.ClosedError, whose Unwrap chain reaches
// net.ErrClosed. A clean stream close (io.EOF) or a server-side DialError
// (target unreachable while the session is still alive) must NOT count.
func isDeadSession(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed)
}

// invalidatingConn wraps a data-carrying net.Conn (a single hysteria TCP
// stream) and invalidates the owning session when I/O fails because the
// underlying QUIC session died after the stream was opened.
type invalidatingConn struct {
	net.Conn
	s *hySession
}

func (c *invalidatingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && isDeadSession(err) {
		c.s.invalidate()
	}
	return n, err
}

func (c *invalidatingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil && isDeadSession(err) {
		c.s.invalidate()
	}
	return n, err
}

// invalidatingUDPConn wraps a data-carrying HyUDPConn and invalidates the
// owning session when I/O fails because the underlying QUIC session died.
type invalidatingUDPConn struct {
	client.HyUDPConn
	s *hySession
}

func (c *invalidatingUDPConn) Receive() ([]byte, string, error) {
	data, addr, err := c.HyUDPConn.Receive()
	if err != nil && isDeadSession(err) {
		c.s.invalidate()
	}
	return data, addr, err
}

func (c *invalidatingUDPConn) Send(b []byte, addr string) error {
	err := c.HyUDPConn.Send(b, addr)
	if err != nil && isDeadSession(err) {
		c.s.invalidate()
	}
	return err
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
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "443")
	}

	d.sessionMutex.Lock()
	session, ok := d.sessions[addr]
	d.sessionMutex.Unlock()

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

		d.sessionMutex.Lock()
		if existing, ok := d.sessions[addr]; ok {
			d.sessionMutex.Unlock()
			hyClient.Close()
			session = existing
		} else {
			session = &hySession{Client: hyClient, d: d, addr: addr}
			d.sessions[addr] = session
			d.sessionMutex.Unlock()
		}
	}

	if d.md.direct {
		// In direct mode the connector opens the real streams via
		// session.TCP(address); returning the *hySession (which satisfies
		// client.Client) lets those opens go through hySession.TCP, which
		// performs the liveness-based invalidation above.
		return &hyClientConn{Client: session}, nil
	}

	conn, err = session.TCP("0.0.0.0:0")
	if err != nil {
		// session.TCP already invalidated the cache on a dead-session error.
		// On any other error, drop the cached session so the next Dial
		// rebuilds it (identity-checked to avoid closing a newer session).
		d.invalidate(addr, session)
		return nil, err
	}

	return
}

// invalidate removes and closes the session for addr, but only if it is
// still the current session (cur == s). This guards against a stale session
// (one that already triggered invalidation) closing a freshly-built
// replacement that now occupies the same address slot.
func (d *hysteriaDialer) invalidate(addr string, s *hySession) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()
	if cur, ok := d.sessions[addr]; ok && cur == s {
		cur.Client.Close()
		delete(d.sessions, addr)
	}
}

type hyClientConn struct {
	client.Client
}

func (c *hyClientConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *hyClientConn) Write(b []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *hyClientConn) Close() error                       { return nil }
func (c *hyClientConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *hyClientConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *hyClientConn) SetDeadline(t time.Time) error      { return nil }
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
