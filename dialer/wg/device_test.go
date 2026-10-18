package wg

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestResolveEndpoint_Literal(t *testing.T) {
	ap, err := resolveEndpoint(context.Background(), "127.0.0.1:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap.String() != "127.0.0.1:51820" {
		t.Fatalf("endpoint = %s", ap)
	}
}

// conn.StdNetBind.ParseEndpoint only accepts a literal ip:port, so a domain
// has to be resolved before it is handed to the uapi.
func TestResolveEndpoint_Domain(t *testing.T) {
	ap, err := resolveEndpoint(context.Background(), "localhost:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ap.Addr().IsLoopback() || ap.Port() != 51820 {
		t.Fatalf("endpoint = %s", ap)
	}
}

func TestResolveEndpoint_Errors(t *testing.T) {
	for _, endpoint := range []string{
		"localhost",              // no port
		"127.0.0.1:not-a-number", // bad port
		"invalid.invalid:51820",  // unresolvable
	} {
		if _, err := resolveEndpoint(context.Background(), endpoint); err == nil {
			t.Fatalf("expected error for endpoint %q", endpoint)
		}
	}
}

func TestIPCConfig(t *testing.T) {
	k1, err := parseKey(testPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := parseKey(testPublicKey())
	if err != nil {
		t.Fatal(err)
	}

	md := metadata{
		privateKey:    k1,
		peerPublicKey: k2,
		allowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.7.0.0/24"),
			netip.MustParsePrefix("10.8.0.0/24"),
		},
		keepalive: 25 * time.Second,
	}

	got := ipcConfig(md, netip.MustParseAddrPort("127.0.0.1:51820"))
	want := strings.Join([]string{
		"private_key=" + k1.hex(),
		"public_key=" + k2.hex(),
		"allowed_ip=10.7.0.0/24",
		"allowed_ip=10.8.0.0/24",
		"endpoint=127.0.0.1:51820",
		"persistent_keepalive_interval=25",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("ipcConfig mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestIPCConfig_NoKeepalive(t *testing.T) {
	md := metadata{allowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	got := ipcConfig(md, netip.MustParseAddrPort("127.0.0.1:51820"))
	if strings.Contains(got, "persistent_keepalive_interval") {
		t.Fatalf("keepalive must be omitted when unset:\n%s", got)
	}
}