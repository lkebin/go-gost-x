package wg

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	netdialer "github.com/go-gost/x/internal/net/dialer"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("wg", NewDialer)
}

// newDeviceFunc builds the WireGuard device; a variable so tests can
// substitute a fake without touching wireguard-go.
var newDeviceFunc = newDevice

type wgDialer struct {
	md     metadata
	logger logger.Logger

	mu  sync.Mutex
	dev *wgDevice
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}
	log := options.Logger
	if log == nil {
		log = logger.Default()
	}
	return &wgDialer{
		logger: log.WithFields(map[string]any{"kind": "dialer", "dialer": "wg"}),
	}
}

func (d *wgDialer) Init(md md.Metadata) error {
	return d.parseMetadata(md)
}

// Dial returns a tunnel handle. The WireGuard device is created on first use
// and reused afterwards; addr is ignored (the peer comes from the metadata).
func (d *wgDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	dev, err := d.device(ctx, options)
	if err != nil {
		return nil, err
	}
	return &conn{net: dev.net, hasDNS: len(d.md.dns) > 0}, nil
}

func (d *wgDialer) device(ctx context.Context, options dialer.DialOptions) (*wgDevice, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dev != nil {
		return d.dev, nil
	}

	var ifce string
	var mark int
	if nd, ok := options.Dialer.(*netdialer.Dialer); ok && nd != nil {
		ifce, mark = nd.Interface, nd.Mark
	}
	if ifce != "" {
		// wireguard-go's StdNetBind only supports interface binding on
		// Windows; on unix the socket follows the routing table.
		d.logger.Warnf("wg: metadata.interface %q is not supported, ignoring", ifce)
	}

	dev, err := newDeviceFunc(ctx, d.md, d.logger, mark)
	if err != nil {
		return nil, err
	}
	d.dev = dev
	return dev, nil
}

// Close implements io.Closer. gost closes a node's transport when the config
// is reloaded (chain.Transport.Close -> hop's chainHop.Close), which releases
// the WireGuard device. Safe to call repeatedly.
func (d *wgDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dev == nil {
		return nil
	}
	dev := d.dev
	d.dev = nil
	return dev.Close()
}

var _ io.Closer = (*wgDialer)(nil)
