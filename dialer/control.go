package dialer

import netdialer "github.com/go-gost/x/internal/net/dialer"

// SetGlobalSocketControl sets a function that is called for every TCP/UDP
// socket created by gost's internal dialer, immediately after creation and
// before connect(). Intended for use on Android where VpnService.protect(fd)
// must be called to bypass VPN routing on upstream proxy connections.
//
// The function receives the raw Linux file descriptor of the socket.
// Set to nil to clear. Concurrency-safe to call once at startup.
func SetGlobalSocketControl(fn func(fd uintptr)) {
	netdialer.GlobalSocketControl = fn
}
