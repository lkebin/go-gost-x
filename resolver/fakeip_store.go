package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// FakeIPAllocator extends FakeIPStore with fake address allocation and state
// import/export for callers that own persistence lifecycle.
type FakeIPAllocator interface {
	FakeIPStore
	Create(domain string, isIPv6 bool) (netip.Addr, error)
	Load(r io.Reader) error
	Store(w io.Writer) error
	Ranges() (inet4, inet6 netip.Prefix)
}

// fakeIPAllocator assigns fake addresses from reserved ranges and maintains a
// bidirectional domain/address mapping. It does not perform file I/O.
type fakeIPAllocator struct {
	inet4Range netip.Prefix
	inet6Range netip.Prefix

	mu        sync.RWMutex
	byAddr    map[netip.Addr]string
	byDomain4 map[string]netip.Addr
	byDomain6 map[string]netip.Addr
	current   netip.Addr
	current6  netip.Addr
}

// NewFakeIPAllocator creates an in-memory fake IP allocator. A zero-value
// prefix disables that address family.
func NewFakeIPAllocator(inet4Range, inet6Range netip.Prefix) FakeIPAllocator {
	return &fakeIPAllocator{
		inet4Range: inet4Range,
		inet6Range: inet6Range,
		byAddr:     make(map[netip.Addr]string),
		byDomain4:  make(map[string]netip.Addr),
		byDomain6:  make(map[string]netip.Addr),
	}
}

// ParseFakeIPNode reports whether addr is a fakeip node and returns its
// configured IPv4 and IPv6 allocation ranges. Missing ranges use the default
// fakeip ranges. Persistence-related query parameters are intentionally ignored.
func ParseFakeIPNode(addr string) (inet4, inet6 netip.Prefix, ok bool) {
	const fakeipScheme = "fakeip://"
	if !strings.HasPrefix(addr, fakeipScheme) {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	u, err := url.Parse(addr)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	q := u.Query()

	if s := q.Get("inet4"); s != "" {
		if p, err := netip.ParsePrefix(s); err == nil {
			inet4 = p
		}
	} else {
		inet4, _ = netip.ParsePrefix("198.18.0.0/15")
	}
	if s := q.Get("inet6"); s != "" {
		if p, err := netip.ParsePrefix(s); err == nil {
			inet6 = p
		}
	} else {
		inet6, _ = netip.ParsePrefix("fc00::/18")
	}
	return inet4, inet6, true
}

// Create returns the fake address for domain, allocating a new one if needed.
// Domain names are normalized by lowercasing and removing a trailing dot.
func (s *fakeIPAllocator) Create(domain string, isIPv6 bool) (netip.Addr, error) {
	domain = normalizeFakeIPDomain(domain)
	if domain == "" {
		return netip.Addr{}, &FakeIPError{"empty fakeip domain"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if isIPv6 {
		if addr, ok := s.byDomain6[domain]; ok {
			return addr, nil
		}
	} else if addr, ok := s.byDomain4[domain]; ok {
		return addr, nil
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
	first := r.Addr().Next()
	if !r.Contains(first) {
		return netip.Addr{}, &FakeIPError{"fakeip address range exhausted"}
	}
	next := cur.Next()
	if !r.Contains(next) {
		next = first
	}
	start := next
	for {
		if next != r.Addr() {
			if _, used := s.byAddr[next]; !used {
				break
			}
		}
		next = next.Next()
		if !r.Contains(next) {
			next = first
		}
		if next == start {
			return netip.Addr{}, &FakeIPError{"fakeip address range exhausted"}
		}
	}

	s.byAddr[next] = domain
	if isIPv6 {
		s.current6 = next
		s.byDomain6[domain] = next
	} else {
		s.current = next
		s.byDomain4[domain] = next
	}
	return next, nil
}

const fakeIPStateVersion = 1

type fakeIPState struct {
	Version  int                `json:"version"`
	Inet4    string             `json:"inet4"`
	Inet6    string             `json:"inet6"`
	Current4 string             `json:"current4"`
	Current6 string             `json:"current6"`
	Entries  []fakeIPStateEntry `json:"entries"`
}

type fakeIPStateEntry struct {
	Domain string `json:"domain"`
	Addr   string `json:"addr"`
}

// Load replaces the allocator state from r after validating the complete
// snapshot. It never opens files and leaves the existing state untouched on
// error.
func (s *fakeIPAllocator) Load(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("fakeip: read state: %w", err)
	}
	var state fakeIPState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("fakeip: parse state: %w", err)
	}
	if state.Version != fakeIPStateVersion {
		return fmt.Errorf("fakeip: unsupported state version %d", state.Version)
	}
	if err := validateStateRange(state.Inet4, s.inet4Range, "inet4"); err != nil {
		return err
	}
	if err := validateStateRange(state.Inet6, s.inet6Range, "inet6"); err != nil {
		return err
	}

	current4, err := validateCurrent(state.Current4, s.inet4Range, "current4")
	if err != nil {
		return err
	}
	current6, err := validateCurrent(state.Current6, s.inet6Range, "current6")
	if err != nil {
		return err
	}

	byAddr := make(map[netip.Addr]string, len(state.Entries))
	byDomain4 := make(map[string]netip.Addr)
	byDomain6 := make(map[string]netip.Addr)
	for _, entry := range state.Entries {
		domain := normalizeFakeIPDomain(entry.Domain)
		if domain == "" {
			return fmt.Errorf("fakeip: state entry has empty domain")
		}
		addr, err := netip.ParseAddr(entry.Addr)
		if err != nil {
			return fmt.Errorf("fakeip: invalid address %q: %w", entry.Addr, err)
		}
		addr = addr.Unmap()
		if _, exists := byAddr[addr]; exists {
			return fmt.Errorf("fakeip: duplicate address %q", entry.Addr)
		}
		if addr.Is4() {
			if !s.inet4Range.Contains(addr) {
				return fmt.Errorf("fakeip: address %q is outside inet4 range", entry.Addr)
			}
			if addr == s.inet4Range.Masked().Addr() {
				return fmt.Errorf("fakeip: address %q is network address for inet4 range", entry.Addr)
			}
			if _, exists := byDomain4[domain]; exists {
				return fmt.Errorf("fakeip: duplicate inet4 domain %q", domain)
			}
			byDomain4[domain] = addr
		} else if addr.Is6() {
			if !s.inet6Range.Contains(addr) {
				return fmt.Errorf("fakeip: address %q is outside inet6 range", entry.Addr)
			}
			if addr == s.inet6Range.Masked().Addr() {
				return fmt.Errorf("fakeip: address %q is network address for inet6 range", entry.Addr)
			}
			if _, exists := byDomain6[domain]; exists {
				return fmt.Errorf("fakeip: duplicate inet6 domain %q", domain)
			}
			byDomain6[domain] = addr
		} else {
			return fmt.Errorf("fakeip: invalid address %q", entry.Addr)
		}
		byAddr[addr] = domain
	}

	// A non-empty cursor must point at an entry in the same family. A cursor
	// that is outside the restored allocation history can make Create wrap to
	// an occupied address and report exhaustion even though free addresses
	// remain, so reject the inconsistent snapshot before installing it.
	if current4.IsValid() {
		if _, ok := byAddr[current4]; !ok {
			return fmt.Errorf("fakeip: current4 address %q is not present in entries", current4)
		}
	}
	if current6.IsValid() {
		if _, ok := byAddr[current6]; !ok {
			return fmt.Errorf("fakeip: current6 address %q is not present in entries", current6)
		}
	}

	// Older valid snapshots may omit cursors. Continue after the greatest
	// restored address so the next allocation cannot collide with an entry.
	if !current4.IsValid() {
		for addr := range byAddr {
			if addr.Is4() && (!current4.IsValid() || current4.Less(addr)) {
				current4 = addr
			}
		}
	}
	if !current6.IsValid() {
		for addr := range byAddr {
			if addr.Is6() && (!current6.IsValid() || current6.Less(addr)) {
				current6 = addr
			}
		}
	}

	s.mu.Lock()
	s.byAddr = byAddr
	s.byDomain4 = byDomain4
	s.byDomain6 = byDomain6
	s.current = current4
	s.current6 = current6
	s.mu.Unlock()
	return nil
}

func validateStateRange(value string, configured netip.Prefix, family string) error {
	if value == "" {
		if configured.IsValid() {
			return fmt.Errorf("fakeip: state %s range is missing", family)
		}
		return nil
	}
	stored, err := netip.ParsePrefix(value)
	if err != nil || stored != configured {
		return fmt.Errorf("fakeip: state %s range %q does not match configured range %s", family, value, configured)
	}
	return nil
}

func validateCurrent(value string, configured netip.Prefix, field string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("fakeip: invalid %s address %q", field, value)
	}
	addr = addr.Unmap()
	if (field == "current4" && !addr.Is4()) || (field == "current6" && !addr.Is6()) ||
		!configured.Contains(addr) || addr == configured.Masked().Addr() {
		return netip.Addr{}, fmt.Errorf("fakeip: invalid %s address %q", field, value)
	}
	return addr, nil
}

// Store writes a deterministic JSON snapshot to w. It does not create or
// replace files; the caller owns file lifecycle and atomic replacement.
func (s *fakeIPAllocator) Store(w io.Writer) error {
	s.mu.RLock()
	state := fakeIPState{
		Version:  fakeIPStateVersion,
		Inet4:    prefixString(s.inet4Range),
		Inet6:    prefixString(s.inet6Range),
		Current4: addrString(s.current),
		Current6: addrString(s.current6),
		Entries:  make([]fakeIPStateEntry, 0, len(s.byAddr)),
	}
	addrs := make([]netip.Addr, 0, len(s.byAddr))
	for addr := range s.byAddr {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	for _, addr := range addrs {
		state.Entries = append(state.Entries, fakeIPStateEntry{Domain: s.byAddr[addr], Addr: addr.String()})
	}
	data, err := json.MarshalIndent(state, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("fakeip: encode state: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("fakeip: write state: %w", err)
	}
	return nil
}

func normalizeFakeIPDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func prefixString(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

// Lookup returns the domain previously stored for addr, if any.
func (s *fakeIPAllocator) Lookup(addr netip.Addr) (string, bool) {
	addr = addr.Unmap()
	s.mu.RLock()
	domain, ok := s.byAddr[addr]
	s.mu.RUnlock()
	return domain, ok
}

// Contains reports whether addr falls inside either configured fakeip range.
func (s *fakeIPAllocator) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	s.mu.RLock()
	ok := s.inet4Range.Contains(addr) || s.inet6Range.Contains(addr)
	s.mu.RUnlock()
	return ok
}

func (s *fakeIPAllocator) Ranges() (inet4, inet6 netip.Prefix) {
	s.mu.RLock()
	inet4, inet6 = s.inet4Range, s.inet6Range
	s.mu.RUnlock()
	return inet4, inet6
}

// FakeIPError reports a fakeip allocation failure.
type FakeIPError struct {
	msg string
}

func (e *FakeIPError) Error() string { return e.msg }
