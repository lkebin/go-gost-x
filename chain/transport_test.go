package chain

import (
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/metadata"
)

// closingDialer is a dialer.Dialer that also implements io.Closer, like
// dialer/wg (which holds a WireGuard device).
type closingDialer struct {
	closed int
}

func (d *closingDialer) Init(md metadata.Metadata) error { return nil }
func (d *closingDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return &testConn{}, nil
}
func (d *closingDialer) Close() error {
	d.closed++
	return nil
}

func TestTransportClose(t *testing.T) {
	d := &closingDialer{}
	tr := NewTransport(d, &plainConnector{})
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if d.closed != 1 {
		t.Fatalf("dialer closed %d times, want 1", d.closed)
	}
}

func TestTransportCloseWithoutCloser(t *testing.T) {
	tr := NewTransport(&plainDialer{}, &plainConnector{})
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
