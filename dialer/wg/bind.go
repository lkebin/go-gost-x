package wg

import (
	netdialer "github.com/go-gost/x/internal/net/dialer"
	"golang.zx2c4.com/wireguard/conn"
)

// bind wraps a wireguard conn.Bind and applies gost's global socket control
// hook (Android VpnService.protect) to every UDP socket it opens, so the
// WireGuard transport does not loop back into the app's own TUN device.
type bind struct {
	conn.Bind
}

func newBind() *bind {
	return &bind{Bind: conn.NewDefaultBind()}
}

// fdPeeker4/fdPeeker6 are implemented by wireguard-go's StdNetBind on Android
// (conn/boundif_android.go). Elsewhere no fd is exposed and the socket
// control hook is simply not applied.
type fdPeeker4 interface{ PeekLookAtSocketFd4() (int, error) }
type fdPeeker6 interface{ PeekLookAtSocketFd6() (int, error) }

func (b *bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	if fn := netdialer.GlobalSocketControl; fn != nil {
		if p, ok := b.Bind.(fdPeeker4); ok {
			if fd, err := p.PeekLookAtSocketFd4(); err == nil {
				fn(uintptr(fd))
			}
		}
		if p, ok := b.Bind.(fdPeeker6); ok {
			if fd, err := p.PeekLookAtSocketFd6(); err == nil {
				fn(uintptr(fd))
			}
		}
	}

	return fns, actualPort, nil
}