package registry

import (
	"net"
	"sync"

	reg "github.com/go-gost/core/registry"
)

// Ipset holds an in-memory set of IP addresses.
type Ipset struct {
	mu  sync.RWMutex
	ips map[string]struct{}
}

// NewIpset creates a new Ipset instance.
func NewIpset() *Ipset {
	return &Ipset{
		ips: make(map[string]struct{}),
	}
}

// Add inserts an IP into the set. Duplicate or nil IPs are silently ignored.
func (s *Ipset) Add(ip net.IP) {
	if ip == nil {
		return
	}
	s.mu.Lock()
	s.ips[ip.String()] = struct{}{}
	s.mu.Unlock()
}

// Contains reports whether the given host string matches any IP in the set.
// host should be an IP address string (e.g. "142.250.80.4").
func (s *Ipset) Contains(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ips == nil {
		return false
	}
	_, ok := s.ips[host]
	return ok
}

// Len returns the number of IPs in the set.
func (s *Ipset) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips)
}

var (
	ipsetReg = new(registry[*Ipset])
)

// IpsetRegistry returns the global registry of Ipset instances.
func IpsetRegistry() reg.Registry[*Ipset] {
	return ipsetReg
}
