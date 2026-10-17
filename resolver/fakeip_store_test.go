package resolver

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
)

var (
	testFakeIP4 = netip.MustParsePrefix("198.18.0.0/15")
	testFakeIP6 = netip.MustParsePrefix("fc00::/18")
)

func TestFakeIPAllocatorRoundTrip(t *testing.T) {
	original := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	addr, err := original.Create("example.com", false)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := original.Store(&buf); err != nil {
		t.Fatal(err)
	}

	restored := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	if err := restored.Load(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if domain, ok := restored.Lookup(addr); !ok || domain != "example.com" {
		t.Fatalf("Lookup(%s) = (%q, %v)", addr, domain, ok)
	}
	next, err := restored.Create("next.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if next == addr {
		t.Fatalf("restored allocator reused %s", addr)
	}
}

func TestFakeIPAllocatorLoadValidation(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "version",
			data: `{"version":2,"inet4":"198.18.0.0/15","inet6":"fc00::/18","entries":[]}`,
			want: "unsupported state version",
		},
		{
			name: "range",
			data: `{"version":1,"inet4":"198.19.0.0/16","inet6":"fc00::/18","entries":[]}`,
			want: "does not match configured range",
		},
		{
			name: "duplicate address",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","entries":[{"domain":"a.example","addr":"198.18.0.1"},{"domain":"b.example","addr":"198.18.0.1"}]}`,
			want: "duplicate address",
		},
		{
			name: "duplicate domain after normalization",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","entries":[{"domain":"Example.com.","addr":"198.18.0.1"},{"domain":"example.com","addr":"198.18.0.2"}]}`,
			want: "duplicate inet4 domain",
		},
		{
			name: "address outside range",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","entries":[{"domain":"a.example","addr":"192.0.2.1"}]}`,
			want: "outside inet4 range",
		},
		{
			name: "ipv4 network address",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","entries":[{"domain":"a.example","addr":"198.18.0.0"}]}`,
			want: "network address",
		},
		{
			name: "ipv6 network address",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","entries":[{"domain":"a.example","addr":"fc00::"}]}`,
			want: "network address",
		},
		{
			name: "invalid cursor",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","current4":"198.18.0.0","entries":[]}`,
			want: "invalid current4",
		},
		{
			name: "ipv4 cursor missing from entries",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","current4":"198.18.0.255","entries":[{"domain":"a.example","addr":"198.18.0.1"}]}`,
			want: "current4 address",
		},
		{
			name: "ipv6 cursor missing from entries",
			data: `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::/18","current6":"fc00::ff","entries":[{"domain":"a.example","addr":"fc00::1"}]}`,
			want: "current6 address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
			if err := store.Load(strings.NewReader(tt.data)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestFakeIPAllocatorLoadRejectsMaskedNetworkAddress(t *testing.T) {
	tests := []struct {
		name  string
		inet4 netip.Prefix
		inet6 netip.Prefix
		data  string
	}{
		{
			name:  "ipv4",
			inet4: netip.MustParsePrefix("198.18.0.1/15"),
			inet6: testFakeIP6,
			data:  `{"version":1,"inet4":"198.18.0.1/15","inet6":"fc00::/18","entries":[{"domain":"a.example","addr":"198.18.0.0"}]}`,
		},
		{
			name:  "ipv6",
			inet4: testFakeIP4,
			inet6: netip.MustParsePrefix("fc00::1/18"),
			data:  `{"version":1,"inet4":"198.18.0.0/15","inet6":"fc00::1/18","entries":[{"domain":"a.example","addr":"fc00::"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewFakeIPAllocator(tt.inet4, tt.inet6)
			if err := store.Load(strings.NewReader(tt.data)); err == nil || !strings.Contains(err.Error(), "network address") {
				t.Fatalf("Load error = %v, want masked network address error", err)
			}
		})
	}
}

func TestFakeIPAllocatorLoadLeavesStateOnError(t *testing.T) {
	store := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	addr, err := store.Create("keep.example", false)
	if err != nil {
		t.Fatal(err)
	}
	bad := `{"version":1,"inet4":"198.19.0.0/16","inet6":"fc00::/18","entries":[]}`
	if err := store.Load(strings.NewReader(bad)); err == nil {
		t.Fatal("Load unexpectedly accepted mismatched range")
	}
	if domain, ok := store.Lookup(addr); !ok || domain != "keep.example" {
		t.Fatalf("state after failed Load = (%q, %v)", domain, ok)
	}
}

func TestFakeIPAllocatorRestoredCursorScansIPv4(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.0.0/30")
	store := NewFakeIPAllocator(prefix, netip.Prefix{})
	state := `{"version":1,"inet4":"198.18.0.0/30","inet6":"","current4":"198.18.0.1","entries":[{"domain":"one.example","addr":"198.18.0.1"},{"domain":"two.example","addr":"198.18.0.2"}]}`
	if err := store.Load(strings.NewReader(state)); err != nil {
		t.Fatal(err)
	}
	addr, err := store.Create("three.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("198.18.0.3"); addr != want {
		t.Fatalf("Create() = %s, want %s", addr, want)
	}
}

func TestFakeIPAllocatorRestoredCursorScansIPv6(t *testing.T) {
	prefix := netip.MustParsePrefix("fc00::/126")
	store := NewFakeIPAllocator(netip.Prefix{}, prefix)
	state := `{"version":1,"inet4":"","inet6":"fc00::/126","current6":"fc00::1","entries":[{"domain":"one.example","addr":"fc00::1"},{"domain":"two.example","addr":"fc00::2"}]}`
	if err := store.Load(strings.NewReader(state)); err != nil {
		t.Fatal(err)
	}
	addr, err := store.Create("three.example", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("fc00::3"); addr != want {
		t.Fatalf("Create() = %s, want %s", addr, want)
	}
}

func TestFakeIPAllocatorRejectsOutOfRangeIPv6Cursor(t *testing.T) {
	store := NewFakeIPAllocator(netip.Prefix{}, netip.MustParsePrefix("fc00::/126"))
	state := `{"version":1,"inet4":"","inet6":"fc00::/126","current6":"fd00::1","entries":[{"domain":"one.example","addr":"fc00::1"}]}`
	if err := store.Load(strings.NewReader(state)); err == nil || !strings.Contains(err.Error(), "invalid current6") {
		t.Fatalf("Load() error = %v, want out-of-range current6 error", err)
	}
}

func TestFakeIPAllocatorStoreAndLoadIPv6(t *testing.T) {
	store := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	v4, err := store.Create("Example.com.", false)
	if err != nil {
		t.Fatal(err)
	}
	v6, err := store.Create("Example.com.", true)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := store.Store(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"current4": "198.18.0.1"`)) ||
		!bytes.Contains(buf.Bytes(), []byte(`"current6": "fc00::1"`)) {
		t.Fatalf("state did not include cursors: %s", buf.Bytes())
	}

	restored := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	if err := restored.Load(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if domain, ok := restored.Lookup(v4); !ok || domain != "example.com" {
		t.Fatalf("v4 Lookup = (%q, %v)", domain, ok)
	}
	if domain, ok := restored.Lookup(v6); !ok || domain != "example.com" {
		t.Fatalf("v6 Lookup = (%q, %v)", domain, ok)
	}
}

func TestFakeIPAllocatorNoAutomaticFileIO(t *testing.T) {
	t.Chdir(t.TempDir())
	store := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	if _, err := store.Create("example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("fakeip-state.json"); err == nil {
		t.Fatal("allocator created fakeip-state.json")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestFakeIPAllocatorRanges(t *testing.T) {
	store := NewFakeIPAllocator(testFakeIP4, testFakeIP6)
	inet4, inet6 := store.Ranges()
	if inet4 != testFakeIP4 || inet6 != testFakeIP6 {
		t.Fatalf("Ranges = (%s, %s)", inet4, inet6)
	}
}

func TestParseFakeIPNode(t *testing.T) {
	inet4, inet6, ok := ParseFakeIPNode("fakeip://?inet4=198.18.0.0/15&inet6=fc00::/18&persistence=true")
	if !ok || inet4 != testFakeIP4 || inet6 != testFakeIP6 {
		t.Fatalf("ParseFakeIPNode = (%s, %s, %v)", inet4, inet6, ok)
	}
	inet4, inet6, ok = ParseFakeIPNode("fakeip://")
	if !ok || inet4 != testFakeIP4 || inet6 != testFakeIP6 {
		t.Fatalf("ParseFakeIPNode defaults = (%s, %s, %v)", inet4, inet6, ok)
	}
	if _, _, ok := ParseFakeIPNode("udp://127.0.0.1:53"); ok {
		t.Fatal("non-fakeip node was accepted")
	}
}

func TestFakeIPAllocatorErrorFormatting(t *testing.T) {
	store := NewFakeIPAllocator(netip.MustParsePrefix("198.18.0.0/31"), netip.Prefix{})
	if _, err := store.Create("a.example", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("b.example", false); err == nil || !strings.Contains(fmt.Sprint(err), "exhausted") {
		t.Fatalf("Create error = %v, want exhaustion", err)
	}
}
