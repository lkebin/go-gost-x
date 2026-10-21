package wg

import (
	netdialer "github.com/go-gost/x/internal/net/dialer"
	wgconn "golang.zx2c4.com/wireguard/conn"
)

// bind wraps a wireguard conn.Bind and applies gost's global socket control
// hook (Android VpnService.protect) to every UDP socket it opens, so the
// WireGuard transport does not loop back into the app's own TUN device.
type bind struct {
	wgconn.Bind
}

func newBind() *bind {
	return &bind{Bind: wgconn.NewDefaultBind()}
}

// fdPeeker4/fdPeeker6 are implemented by wireguard-go's StdNetBind on Android
// (conn/boundif_android.go). Elsewhere no fd is exposed and the socket
// control hook is simply not applied.
type fdPeeker4 interface{ PeekLookAtSocketFd4() (int, error) }
type fdPeeker6 interface{ PeekLookAtSocketFd6() (int, error) }

func (b *bind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	if fn := netdialer.GlobalSocketControl; fn != nil {
		if p, ok := b.Bind.(fdPeeker4); ok {
			protectFd(fn, p.PeekLookAtSocketFd4)
		}
		if p, ok := b.Bind.(fdPeeker6); ok {
			protectFd(fn, p.PeekLookAtSocketFd6)
		}
	}

	return fns, actualPort, nil
}

// protectFd applies the socket control hook to one address family's socket.
// The peek is wrapped in a recover: wireguard-go's StdNetBind tolerates
// EAFNOSUPPORT from one family (conn/bind_std.go) but its peek method then
// dereferences the nil socket of that family (conn/boundif_android.go), so a
// single-stack device would otherwise crash the tunnel.
func protectFd(control func(fd uintptr), peek func() (int, error)) {
	defer func() { _ = recover() }()
	if fd, err := peek(); err == nil {
		control(uintptr(fd))
	}
}
