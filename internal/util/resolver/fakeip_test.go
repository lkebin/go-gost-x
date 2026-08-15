package resolver

import (
	"net/netip"
	"testing"
)

func testFakeIPStore() *FakeIPStore {
	return NewFakeIPStore(
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("fc00::/18"),
	)
}

func TestFakeIPStoreCreateStable(t *testing.T) {
	store := testFakeIPStore()
	a1, err := store.Create("example.com", false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	a2, err := store.Create("example.com", false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a1 != a2 {
		t.Fatalf("same domain got different addresses: %s != %s", a1, a2)
	}
}

func TestFakeIPStoreCreateSequential(t *testing.T) {
	store := testFakeIPStore()
	a1, _ := store.Create("a.com", false)
	a2, _ := store.Create("b.com", false)
	a3, _ := store.Create("c.com", false)
	if !(a1.Less(a2) && a2.Less(a3)) {
		t.Fatalf("addresses not sequential: %s, %s, %s", a1, a2, a3)
	}
}

func TestFakeIPStoreCreateStartsInsideRange(t *testing.T) {
	store := testFakeIPStore()
	a, err := store.Create("a.com", false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	r := netip.MustParsePrefix("198.18.0.0/15")
	if !r.Contains(a) {
		t.Fatalf("allocated address %s outside range %s", a, r)
	}
}

func TestFakeIPStoreCreateIPv4IPv6Independent(t *testing.T) {
	store := testFakeIPStore()
	a4, _ := store.Create("example.com", false)
	a6, err := store.Create("example.com", true)
	if err != nil {
		t.Fatalf("Create v6: %v", err)
	}
	if !a4.Is4() || !a6.Is6() {
		t.Fatalf("family mismatch: %s (%v) %s (%v)", a4, a4.Is4(), a6, a6.Is6())
	}
	// same domain, different family → different address
	if a4 == a6 {
		t.Fatalf("v4 and v6 share address %s", a4)
	}
}

func TestFakeIPStoreLookup(t *testing.T) {
	store := testFakeIPStore()
	a, _ := store.Create("example.com", false)
	domain, ok := store.Lookup(a)
	if !ok {
		t.Fatalf("lookup of %s failed", a)
	}
	if domain != "example.com" {
		t.Fatalf("lookup got %q, want %q", domain, "example.com")
	}
	if _, ok := store.Lookup(netip.MustParseAddr("9.9.9.9")); ok {
		t.Fatal("lookup of unknown address should fail")
	}
}

func TestFakeIPStoreContains(t *testing.T) {
	store := testFakeIPStore()
	a, _ := store.Create("example.com", false)
	if !store.Contains(a) {
		t.Fatalf("Contains(%s) = false, want true", a)
	}
	if store.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("Contains(8.8.8.8) = true, want false")
	}
}

func TestFakeIPStoreWrapAround(t *testing.T) {
	// A /30 v4 range holds 4 addresses; the network address is skipped, so
	// 3 are allocatable. The 4th allocation wraps back to the first.
	store := NewFakeIPStore(netip.MustParsePrefix("198.18.0.0/30"), netip.Prefix{})
	a1, _ := store.Create("a.com", false)
	a2, _ := store.Create("b.com", false)
	a3, _ := store.Create("c.com", false)
	a4, _ := store.Create("d.com", false) // wraps back to a1's slot
	if a4 != a1 {
		t.Fatalf("d.com should wrap to %s, got %s", a1, a4)
	}
	// a.com's mapping must remain intact after the wrap collision.
	again, _ := store.Create("a.com", false)
	if again != a1 {
		t.Fatalf("a.com remapped to %s, want %s", again, a1)
	}
	if a2 == a1 || a3 == a1 {
		t.Fatalf("collision: %s %s %s", a1, a2, a3)
	}
}

func TestFakeIPStoreLookupUnmap(t *testing.T) {
	store := testFakeIPStore()
	a, _ := store.Create("example.com", false)
	// IPv4-mapped IPv6 form of the same address must still resolve.
	mapped := netip.AddrFrom16(a.As16())
	domain, ok := store.Lookup(mapped)
	if !ok || domain != "example.com" {
		t.Fatalf("mapped lookup got (%q, %v), want (%q, true)", domain, ok, "example.com")
	}
}
