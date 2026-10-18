package wg

import (
	"encoding/base64"
	"testing"
	"time"

	xmetadata "github.com/go-gost/x/metadata"
)

func testPrivateKey() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func testPublicKey() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(255 - i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// validRaw returns a minimal valid raw config map (callers mutate a copy).
func validRaw() map[string]any {
	return map[string]any{
		"privateKey":    testPrivateKey(),
		"peerPublicKey": testPublicKey(),
		"endpoint":      "wg.example.com:51820",
		"localIPs":      "10.7.0.2/32",
	}
}

func parseRaw(t *testing.T, raw map[string]any) (*wgDialer, error) {
	t.Helper()
	d := &wgDialer{}
	err := d.parseMetadata(xmetadata.NewMetadata(raw))
	return d, err
}

func TestParseMetadata_RequiredFields(t *testing.T) {
	for _, key := range []string{"privateKey", "peerPublicKey", "endpoint", "localIPs"} {
		t.Run("missing "+key, func(t *testing.T) {
			raw := validRaw()
			delete(raw, key)
			if _, err := parseRaw(t, raw); err == nil {
				t.Fatalf("expected error when %s is missing", key)
			}
		})
	}
}

func TestParseMetadata_InvalidKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
		val  string
	}{
		{"bad base64", "privateKey", "not-base64!!"},
		{"short key", "privateKey", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"bad peer base64", "peerPublicKey", "***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := validRaw()
			raw[tt.key] = tt.val
			if _, err := parseRaw(t, raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseMetadata_Defaults(t *testing.T) {
	d, err := parseRaw(t, validRaw())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.md.mtu != defaultMTU {
		t.Errorf("mtu = %d, want %d", d.md.mtu, defaultMTU)
	}
	if len(d.md.allowedIPs) != 1 || d.md.allowedIPs[0].String() != defaultAllowedIPs {
		t.Errorf("allowedIPs = %v, want [%s]", d.md.allowedIPs, defaultAllowedIPs)
	}
	if len(d.md.localIPs) != 1 || d.md.localIPs[0].String() != "10.7.0.2/32" {
		t.Errorf("localIPs = %v, want [10.7.0.2/32]", d.md.localIPs)
	}
	if d.md.keepalive != 0 {
		t.Errorf("keepalive = %v, want 0", d.md.keepalive)
	}
	if len(d.md.dns) != 0 {
		t.Errorf("dns = %v, want empty", d.md.dns)
	}
}

// Scalar strings must work: config authors write "10.7.0.2/32", not a list.
func TestParseMetadata_ScalarStringList(t *testing.T) {
	raw := validRaw()
	raw["localIPs"] = "10.7.0.2/32"
	raw["allowedIPs"] = "10.7.0.0/24, 10.8.0.0/24"
	raw["dns"] = "10.7.0.1"

	d, err := parseRaw(t, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.md.localIPs) != 1 {
		t.Fatalf("localIPs = %v, want 1 entry", d.md.localIPs)
	}
	if len(d.md.allowedIPs) != 2 || d.md.allowedIPs[1].String() != "10.8.0.0/24" {
		t.Fatalf("allowedIPs = %v, want 2 entries", d.md.allowedIPs)
	}
	if len(d.md.dns) != 1 || d.md.dns[0].String() != "10.7.0.1" {
		t.Fatalf("dns = %v, want [10.7.0.1]", d.md.dns)
	}
}

func TestParseMetadata_ListValues(t *testing.T) {
	raw := validRaw()
	raw["localIPs"] = []string{"10.7.0.2/32", "10.7.0.3/32"}
	raw["allowedIPs"] = []any{"10.7.0.0/24"}
	raw["dns"] = []string{"10.7.0.1", "10.7.0.2"}

	d, err := parseRaw(t, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.md.localIPs) != 2 || len(d.md.allowedIPs) != 1 || len(d.md.dns) != 2 {
		t.Fatalf("localIPs=%v allowedIPs=%v dns=%v", d.md.localIPs, d.md.allowedIPs, d.md.dns)
	}
}

// A bare IP without a prefix length is accepted and treated as /32.
func TestParseMetadata_BareIPAsPrefix(t *testing.T) {
	raw := validRaw()
	raw["localIPs"] = "10.7.0.2"
	d, err := parseRaw(t, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.md.localIPs[0].String() != "10.7.0.2/32" {
		t.Fatalf("localIPs[0] = %s, want 10.7.0.2/32", d.md.localIPs[0])
	}
}

func TestParseMetadata_WgPrefixedKeys(t *testing.T) {
	raw := map[string]any{
		"wg.privateKey":    testPrivateKey(),
		"wg.peerPublicKey": testPublicKey(),
		"wg.endpoint":      "127.0.0.1:51820",
		"wg.localIPs":      "10.7.0.2/32",
	}
	if _, err := parseRaw(t, raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseMetadata_MTURange(t *testing.T) {
	for _, mtu := range []int{575, 65536} {
		raw := validRaw()
		raw["mtu"] = mtu
		if _, err := parseRaw(t, raw); err == nil {
			t.Fatalf("expected error for mtu %d", mtu)
		}
	}
	raw := validRaw()
	raw["mtu"] = 1280
	d, err := parseRaw(t, raw)
	if err != nil || d.md.mtu != 1280 {
		t.Fatalf("mtu = %d, err = %v", d.md.mtu, err)
	}
}

func TestParseMetadata_Keepalive(t *testing.T) {
	raw := validRaw()
	raw["keepalive"] = "25s"
	d, err := parseRaw(t, raw)
	if err != nil || d.md.keepalive != 25*time.Second {
		t.Fatalf("keepalive = %v, err = %v", d.md.keepalive, err)
	}

	raw = validRaw()
	raw["keepalive"] = 30 // integer seconds
	d, err = parseRaw(t, raw)
	if err != nil || d.md.keepalive != 30*time.Second {
		t.Fatalf("keepalive = %v, err = %v", d.md.keepalive, err)
	}

	raw = validRaw()
	raw["keepalive"] = "48h"
	if _, err := parseRaw(t, raw); err == nil {
		t.Fatal("expected error for keepalive above the uapi limit")
	}
}

func TestParseMetadata_InvalidIPs(t *testing.T) {
	for _, tt := range []struct{ key, val string }{
		{"localIPs", "not-an-ip"},
		{"allowedIPs", "10.0.0.0/99"},
		{"dns", "not-an-ip"},
	} {
		raw := validRaw()
		raw[tt.key] = tt.val
		if _, err := parseRaw(t, raw); err == nil {
			t.Fatalf("expected error for %s=%q", tt.key, tt.val)
		}
	}
}

func TestParseKey_RoundTrip(t *testing.T) {
	k, err := parseKey(testPrivateKey()) // test key bytes are 0x00..0x1f
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if k.hex() != want {
		t.Fatalf("hex = %q, want %q", k.hex(), want)
	}
}