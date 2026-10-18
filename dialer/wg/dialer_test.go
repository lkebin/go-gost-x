package wg

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
	xmetadata "github.com/go-gost/x/metadata"
)

func newTestDialer(t *testing.T) *wgDialer {
	t.Helper()
	d := NewDialer(dialer.LoggerOption(xlogger.Nop())).(*wgDialer)
	if err := d.Init(xmetadata.NewMetadata(validRaw())); err != nil {
		t.Fatalf("init: %v", err)
	}
	return d
}

// withDeviceFunc substitutes the device factory for the duration of a test.
func withDeviceFunc(t *testing.T, fn func(context.Context, metadata, logger.Logger, int) (*wgDevice, error)) {
	t.Helper()
	old := newDeviceFunc
	newDeviceFunc = fn
	t.Cleanup(func() { newDeviceFunc = old })
}

// Review Focus 2: concurrent Dial calls must create exactly one device.
func TestDialerCreatesDeviceOnce(t *testing.T) {
	d := newTestDialer(t)

	var calls int32
	withDeviceFunc(t, func(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
		atomic.AddInt32(&calls, 1)
		return &wgDevice{}, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.Dial(context.Background(), ""); err != nil {
				t.Errorf("dial: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("device created %d times, want 1", got)
	}
}

// Review Focus 3: Close is idempotent and Dial still works afterwards.
func TestDialerCloseIdempotentAndDialAfterClose(t *testing.T) {
	d := newTestDialer(t)

	var calls int32
	withDeviceFunc(t, func(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
		atomic.AddInt32(&calls, 1)
		return &wgDevice{}, nil
	})

	if _, err := d.Dial(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := d.Dial(context.Background(), ""); err != nil {
		t.Fatalf("dial after close: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("device created %d times, want 2 (one per tunnel lifetime)", got)
	}
}

func TestDialerDialErrorNotCached(t *testing.T) {
	d := newTestDialer(t)

	var calls int32
	withDeviceFunc(t, func(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return nil, errors.New("boom")
		}
		return &wgDevice{}, nil
	})

	if _, err := d.Dial(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := d.Dial(context.Background(), ""); err != nil {
		t.Fatalf("second dial must retry: %v", err)
	}
}

// Review Focus 4: a domain target without a dns server must fail fast and
// explicitly instead of relying on netstack's degraded lookup.
func TestConnDomainWithoutDNS(t *testing.T) {
	c := &conn{hasDNS: false}
	if _, err := c.TCP(context.Background(), "example.com:80"); err == nil {
		t.Fatal("expected an error for a domain without dns")
	}
	if _, err := c.UDP(context.Background(), "example.com:80"); err == nil {
		t.Fatal("expected an error for a domain without dns")
	}
}

func TestConnSatisfiesNetConn(t *testing.T) {
	var _ net.Conn = (*conn)(nil)
	c := &conn{}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("Read err = %v, want EOF", err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write must fail on the tunnel handle")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
