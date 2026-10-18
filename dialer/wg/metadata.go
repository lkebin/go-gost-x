package wg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultMTU        = 1420
	minMTU            = 576
	maxMTU            = 65535
	defaultAllowedIPs = "0.0.0.0/0"
)

// key is a 32-byte WireGuard key (private or public).
type key [32]byte

// hex returns the uapi representation of the key.
func (k key) hex() string { return hex.EncodeToString(k[:]) }

// parseKey decodes a wg-quick style base64 WireGuard key.
func parseKey(s string) (k key, err error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("invalid key length %d, want %d", len(b), len(k))
	}
	copy(k[:], b)
	return k, nil
}

type metadata struct {
	privateKey    key
	peerPublicKey key
	endpoint      string
	localIPs      []netip.Prefix
	allowedIPs    []netip.Prefix
	dns           []netip.Addr
	mtu           int
	keepalive     time.Duration
}

// getStrings returns a list-valued metadata field. mdutil.GetStrings only
// accepts []string / []any (metadata/util/util.go), so a single
// comma-separated string is handled here as well.
func getStrings(md mdata.Metadata, keys ...string) (ss []string) {
	if ss = mdutil.GetStrings(md, keys...); len(ss) > 0 {
		return
	}
	for _, s := range strings.Split(mdutil.GetString(md, keys...), ",") {
		if s = strings.TrimSpace(s); s != "" {
			ss = append(ss, s)
		}
	}
	return
}

// parsePrefix parses "10.7.0.2/32"; a bare "10.7.0.2" becomes /32 (/128 for v6).
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// validateEndpointSyntax checks the host:port shape without any DNS lookup: a
// domain is resolved later (see resolveEndpoint), but a syntactically broken
// endpoint must fail at config load instead of at the first dial.
func validateEndpointSyntax(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid %q: %w", endpoint, err)
	}
	if host == "" {
		return fmt.Errorf("invalid %q: missing host", endpoint)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port %q: %w", port, err)
	}
	return nil
}

func (d *wgDialer) parseMetadata(md mdata.Metadata) error {
	const (
		keyPrivateKey    = "privateKey"
		keyPeerPublicKey = "peerPublicKey"
		keyEndpoint      = "endpoint"
		keyLocalIPs      = "localIPs"
		keyAllowedIPs    = "allowedIPs"
		keyDNS           = "dns"
		keyMTU           = "mtu"
		keyKeepalive     = "keepalive"
	)

	s := mdutil.GetString(md, keyPrivateKey, "wg.privateKey")
	if s == "" {
		return fmt.Errorf("wg: privateKey is required")
	}
	privateKey, err := parseKey(s)
	if err != nil {
		return fmt.Errorf("wg: privateKey: %w", err)
	}

	s = mdutil.GetString(md, keyPeerPublicKey, "wg.peerPublicKey")
	if s == "" {
		return fmt.Errorf("wg: peerPublicKey is required")
	}
	peerPublicKey, err := parseKey(s)
	if err != nil {
		return fmt.Errorf("wg: peerPublicKey: %w", err)
	}

	endpoint := strings.TrimSpace(mdutil.GetString(md, keyEndpoint, "wg.endpoint"))
	if endpoint == "" {
		return fmt.Errorf("wg: endpoint is required")
	}
	if err := validateEndpointSyntax(endpoint); err != nil {
		return fmt.Errorf("wg: endpoint: %w", err)
	}

	var localIPs []netip.Prefix
	for _, s := range getStrings(md, keyLocalIPs, "wg.localIPs") {
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("wg: localIPs: invalid %q: %w", s, err)
		}
		localIPs = append(localIPs, p)
	}
	if len(localIPs) == 0 {
		return fmt.Errorf("wg: localIPs is required")
	}

	allowedIPStrs := getStrings(md, keyAllowedIPs, "wg.allowedIPs")
	if len(allowedIPStrs) == 0 {
		allowedIPStrs = []string{defaultAllowedIPs}
	}
	var allowedIPs []netip.Prefix
	for _, s := range allowedIPStrs {
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("wg: allowedIPs: invalid %q: %w", s, err)
		}
		allowedIPs = append(allowedIPs, p)
	}

	var dns []netip.Addr
	for _, s := range getStrings(md, keyDNS, "wg.dns") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("wg: dns: invalid %q: %w", s, err)
		}
		dns = append(dns, addr)
	}

	mtu := mdutil.GetInt(md, keyMTU, "wg.mtu")
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < minMTU || mtu > maxMTU {
		return fmt.Errorf("wg: mtu %d out of range [%d, %d]", mtu, minMTU, maxMTU)
	}

	keepalive := mdutil.GetDuration(md, keyKeepalive, "wg.keepalive")
	if keepalive < 0 {
		return fmt.Errorf("wg: keepalive must not be negative")
	}
	if secs := keepalive.Seconds(); secs > 65535 {
		return fmt.Errorf("wg: keepalive %s exceeds the uapi limit of 65535s", keepalive)
	}

	d.md.privateKey = privateKey
	d.md.peerPublicKey = peerPublicKey
	d.md.endpoint = endpoint
	d.md.localIPs = localIPs
	d.md.allowedIPs = allowedIPs
	d.md.dns = dns
	d.md.mtu = mtu
	d.md.keepalive = keepalive
	return nil
}
