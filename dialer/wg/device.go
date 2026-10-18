package wg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgDevice owns the userspace WireGuard device and its gVisor netstack.
type wgDevice struct {
	dev *device.Device
	net *netstack.Net
}

// Close tears down the device; wireguard-go's Device.Close also closes the
// netstack and is idempotent.
func (d *wgDevice) Close() error {
	if d == nil || d.dev == nil {
		return nil
	}
	d.dev.Close()
	return nil
}

// resolveEndpoint turns the configured endpoint into a literal ip:port.
// wireguard-go's conn.StdNetBind.ParseEndpoint only accepts a literal address
// (conn/bind_std.go), so a domain must be resolved here.
func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap, nil
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint port %q: %w", port, err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: %w", endpoint, err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: no address", endpoint)
	}
	return netip.AddrPortFrom(ips[0], uint16(p)), nil
}

// ipcConfig renders the uapi configuration for a single peer.
func ipcConfig(md metadata, endpoint netip.AddrPort) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", md.privateKey.hex())
	fmt.Fprintf(&sb, "public_key=%s\n", md.peerPublicKey.hex())
	for _, p := range md.allowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", p.String())
	}
	fmt.Fprintf(&sb, "endpoint=%s\n", endpoint.String())
	if md.keepalive >= time.Second {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", int(md.keepalive.Seconds()))
	}
	return sb.String()
}

// wgLogger bridges wireguard-go's logger into gost's logger.
func wgLogger(log logger.Logger) *device.Logger {
	return &device.Logger{
		Errorf:   func(format string, args ...any) { log.Errorf(format, args...) },
		Verbosef: func(format string, args ...any) { log.Debugf(format, args...) },
	}
}

// newDevice creates and brings up the userspace WireGuard device.
func newDevice(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
	endpoint, err := resolveEndpoint(ctx, md.endpoint)
	if err != nil {
		return nil, fmt.Errorf("wg: %w", err)
	}

	addrs := make([]netip.Addr, 0, len(md.localIPs))
	for _, p := range md.localIPs {
		addrs = append(addrs, p.Addr())
	}

	tunDev, netStack, err := netstack.CreateNetTUN(addrs, md.dns, md.mtu)
	if err != nil {
		return nil, fmt.Errorf("wg: create netstack: %w", err)
	}

	dev := device.NewDevice(tunDev, newBind(), wgLogger(log))
	if err := dev.IpcSet(ipcConfig(md, endpoint)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg: configure device: %w", err)
	}
	if mark > 0 {
		if err := dev.BindSetMark(uint32(mark)); err != nil {
			log.Warnf("wg: set socket mark %d: %v", mark, err)
		}
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg: bring device up: %w", err)
	}

	log.Infof("wg: tunnel up, endpoint=%s, local=%v, mtu=%d", endpoint, md.localIPs, md.mtu)
	return &wgDevice{dev: dev, net: netStack}, nil
}