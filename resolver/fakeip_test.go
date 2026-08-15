package resolver

import (
	"net/netip"
	"testing"

	resolver_util "github.com/go-gost/x/internal/util/resolver"
)

func TestFakeIPGlobalAccessorsUnset(t *testing.T) {
	SetFakeIPStore(nil)
	if FakeIPContains(netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("FakeIPContains should be false with no store")
	}
	if _, ok := FakeIPLookup(netip.MustParseAddr("198.18.0.1")); ok {
		t.Fatal("FakeIPLookup should miss with no store")
	}
}

func TestFakeIPGlobalAccessors(t *testing.T) {
	store := resolver_util.NewFakeIPStore(
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("fc00::/18"),
	)
	addr, err := store.Create("example.com", false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	SetFakeIPStore(store)
	defer SetFakeIPStore(nil)

	if !FakeIPContains(addr) {
		t.Fatalf("FakeIPContains(%s) = false, want true", addr)
	}
	if FakeIPContains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("FakeIPContains(8.8.8.8) = true, want false")
	}
	if domain, ok := FakeIPLookup(addr); !ok || domain != "example.com" {
		t.Fatalf("FakeIPLookup got (%q, %v), want (example.com, true)", domain, ok)
	}
	if _, ok := FakeIPLookup(netip.MustParseAddr("1.2.3.4")); ok {
		t.Fatal("FakeIPLookup(1.2.3.4) should miss")
	}
}
