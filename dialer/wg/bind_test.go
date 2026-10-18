package wg

import (
	"errors"
	"testing"

	netdialer "github.com/go-gost/x/internal/net/dialer"
	wgconn "golang.zx2c4.com/wireguard/conn"
)

// fakeBind is a minimal wgconn.Bind without fd peeking (non-Android behaviour).
type fakeBind struct {
	fns      []wgconn.ReceiveFunc
	lastPort uint16
	openErr  error
}

func (b *fakeBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	if b.openErr != nil {
		return nil, 0, b.openErr
	}
	b.lastPort = port
	return b.fns, port, nil
}
func (b *fakeBind) Close() error                                    { return nil }
func (b *fakeBind) SetMark(mark uint32) error                       { return nil }
func (b *fakeBind) Send(bufs [][]byte, ep wgconn.Endpoint) error    { return nil }
func (b *fakeBind) ParseEndpoint(s string) (wgconn.Endpoint, error) { return nil, nil }
func (b *fakeBind) BatchSize() int                                  { return 1 }

// fakePeekBind additionally implements the fd-peek interfaces that
// wireguard-go provides on Android.
type fakePeekBind struct {
	*fakeBind
	fd4, fd6 int
}

func (b *fakePeekBind) PeekLookAtSocketFd4() (int, error) { return b.fd4, nil }
func (b *fakePeekBind) PeekLookAtSocketFd6() (int, error) { return b.fd6, nil }

func withSocketControl(t *testing.T, fn func(fd uintptr)) {
	t.Helper()
	old := netdialer.GlobalSocketControl
	netdialer.GlobalSocketControl = fn
	t.Cleanup(func() { netdialer.GlobalSocketControl = old })
}

func TestBindOpenAppliesSocketControl(t *testing.T) {
	var got []uintptr
	withSocketControl(t, func(fd uintptr) { got = append(got, fd) })

	b := &bind{Bind: &fakePeekBind{fakeBind: &fakeBind{}, fd4: 7, fd6: 9}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != 7 || got[1] != 9 {
		t.Fatalf("socket control called with %v, want [7 9]", got)
	}
}

func TestBindOpenWithoutPeekSupport(t *testing.T) {
	called := false
	withSocketControl(t, func(fd uintptr) { called = true })

	b := &bind{Bind: &fakeBind{}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("socket control must not be called when the bind exposes no fd")
	}
}

func TestBindOpenPropagatesError(t *testing.T) {
	withSocketControl(t, func(fd uintptr) { t.Fatal("must not be called on failure") })

	wantErr := errors.New("boom")
	b := &bind{Bind: &fakeBind{openErr: wantErr}}
	if _, _, err := b.Open(0); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestBindOpenReturnsUnderlyingValues(t *testing.T) {
	recv := func(packets [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) { return 0, nil }
	b := &bind{Bind: &fakeBind{fns: []wgconn.ReceiveFunc{recv}}}
	gotFns, port, err := b.Open(51820)
	if err != nil || len(gotFns) != 1 || port != 51820 {
		t.Fatalf("fns=%v port=%d err=%v", gotFns, port, err)
	}
}
