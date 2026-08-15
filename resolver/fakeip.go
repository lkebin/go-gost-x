package resolver

import (
	"net/netip"
	"sync/atomic"
)

// FakeIPStore is the interface the data plane needs from the fakeip store:
// range containment checks and address-to-domain lookups. Defined here (rather
// than exposing the internal implementation type) so out-of-module consumers
// such as the libgost TUN handler can depend on it.
type FakeIPStore interface {
	Lookup(addr netip.Addr) (string, bool)
	Contains(addr netip.Addr) bool
}

// storeBox wraps the store interface so atomic.Pointer can hold a nil-able
// reference (atomic.Value rejects nil interface values).
type storeBox struct {
	store FakeIPStore
}

// fakeIPStoreGlobal is the process-wide fakeip store, installed by the DNS
// handler when its config enables fakeip. The TUN data plane queries it via
// FakeIPLookup/FakeIPContains to recover domains from fake addresses.
var fakeIPStoreGlobal atomic.Pointer[storeBox]

// SetFakeIPStore installs (or clears, with nil) the process-wide fakeip store.
func SetFakeIPStore(store FakeIPStore) {
	if store == nil {
		fakeIPStoreGlobal.Store(nil)
		return
	}
	fakeIPStoreGlobal.Store(&storeBox{store: store})
}

func loadFakeIPStore() FakeIPStore {
	box := fakeIPStoreGlobal.Load()
	if box == nil {
		return nil
	}
	return box.store
}

// FakeIPLookup returns the domain previously assigned to addr via the fakeip
// store, if a store is installed and the address is known.
func FakeIPLookup(addr netip.Addr) (string, bool) {
	store := loadFakeIPStore()
	if store == nil {
		return "", false
	}
	return store.Lookup(addr)
}

// FakeIPContains reports whether addr falls inside the configured fakeip
// ranges. Returns false when no fakeip store is installed.
func FakeIPContains(addr netip.Addr) bool {
	store := loadFakeIPStore()
	if store == nil {
		return false
	}
	return store.Contains(addr)
}
