package resolver

import (
	"net/netip"
	"sync"
)

// FakeIPStore assigns fake addresses from reserved ranges and maintains the
// bidirectional domain <-> address mapping. Mappings never expire, so a domain
// can always be recovered from a fake address, regardless of how long the
// client keeps using it.
//
// Allocation is sequential within each family range and wraps around at the
// end. The network address itself is never handed out.
type FakeIPStore struct {
	inet4Range netip.Prefix
	inet6Range netip.Prefix

	mu        sync.RWMutex
	byAddr    map[netip.Addr]string
	byDomain4 map[string]netip.Addr
	byDomain6 map[string]netip.Addr
	current   netip.Addr // last allocated v4 address
	current6  netip.Addr // last allocated v6 address
}

// NewFakeIPStore creates a store with the given IPv4/IPv6 reserved ranges.
// A zero-value prefix disables that family.
func NewFakeIPStore(inet4Range, inet6Range netip.Prefix) *FakeIPStore {
	return &FakeIPStore{
		inet4Range: inet4Range,
		inet6Range: inet6Range,
		byAddr:     make(map[netip.Addr]string),
		byDomain4:  make(map[string]netip.Addr),
		byDomain6:  make(map[string]netip.Addr),
	}
}

// Create returns the fake address for domain, allocating a new one if needed.
// isIPv6 selects the address family. The same domain always maps to the same
// address within a family.
func (s *FakeIPStore) Create(domain string, isIPv6 bool) (netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if isIPv6 {
		if addr, ok := s.byDomain6[domain]; ok {
			return addr, nil
		}
	} else {
		if addr, ok := s.byDomain4[domain]; ok {
			return addr, nil
		}
	}

	r := s.inet4Range
	if isIPv6 {
		r = s.inet6Range
	}
	if !r.IsValid() {
		return netip.Addr{}, &FakeIPError{"missing fakeip address range"}
	}

	cur := s.current
	if isIPv6 {
		cur = s.current6
	}

	next := cur.Next()
	if !r.Contains(next) {
		// wrap around: restart just after the network address
		next = r.Addr().Next()
	}
	// Guard against a degenerate range with no allocatable addresses
	// (e.g. a /31 with only the network address usable). If we cannot
	// advance to a usable address, refuse rather than returning garbage.
	if !r.Contains(next) || next == r.Addr() {
		return netip.Addr{}, &FakeIPError{"fakeip address range exhausted"}
	}

	if isIPv6 {
		s.current6 = next
	} else {
		s.current = next
	}
	s.byAddr[next] = domain
	if isIPv6 {
		s.byDomain6[domain] = next
	} else {
		s.byDomain4[domain] = next
	}
	return next, nil
}

// Lookup returns the domain previously stored for addr, if any.
func (s *FakeIPStore) Lookup(addr netip.Addr) (string, bool) {
	addr = addr.Unmap()
	s.mu.RLock()
	domain, ok := s.byAddr[addr]
	s.mu.RUnlock()
	return domain, ok
}

// Contains reports whether addr falls inside the store's reserved ranges.
func (s *FakeIPStore) Contains(addr netip.Addr) bool {
	return s.inet4Range.Contains(addr) || s.inet6Range.Contains(addr)
}

// FakeIPError reports a fakeip allocation failure.
type FakeIPError struct {
	msg string
}

func (e *FakeIPError) Error() string { return e.msg }
