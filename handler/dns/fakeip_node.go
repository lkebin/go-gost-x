package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	resolver_util "github.com/go-gost/x/internal/util/resolver"
	"github.com/miekg/dns"
)

// fakeipScheme identifies a synthetic fakeip forwarder node in the dns
// service's forwarder.nodes list, e.g.
//
//	forwarder:
//	  nodes:
//	    - name: fakeip
//	      addr: "fakeip://?inet4=198.18.0.0/15&inet6=fc00::/18"
//
// A node with this scheme answers DNS queries with a fake address allocated
// from the store instead of contacting any upstream. It has no bypass, so it
// acts as the fallback for queries the other nodes bypass (e.g. gfwlist
// domains when the domestic node bypasses them), giving those domains fake IPs
// while the domestic node keeps serving real addresses for direct domains.
const fakeipScheme = "fakeip://"

// parseFakeIPNode reports whether addr is a synthetic fakeip node and returns
// the IPv4/IPv6 ranges to allocate from. When a range is omitted from the node
// address it defaults to 198.18.0.0/15 / fc00::/18.
func parseFakeIPNode(addr string) (netip.Prefix, netip.Prefix, bool) {
	if !strings.HasPrefix(addr, fakeipScheme) {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	u, err := url.Parse(addr)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	q := u.Query()

	var inet4, inet6 netip.Prefix
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

// fakeipExchanger is a synthetic DNS exchanger used as a forwarder node. It does
// not talk to any upstream resolver; for each query it allocates a fake address
// from the store and answers with it directly. This lets the dns handler serve
// fake IPs for proxied domains without an external DNS server, keeping the
// real-domain→real-IP mapping out of the TUN data plane: the tun handler
// recovers the domain from the fake address and routes it through the proxy,
// where server-side resolution happens.
type fakeipExchanger struct {
	store *resolver_util.FakeIPStore
	ttl   time.Duration
}

func (e *fakeipExchanger) String() string { return fakeipScheme }

func (e *fakeipExchanger) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	mq := new(dns.Msg)
	if err := mq.Unpack(msg); err != nil {
		return nil, err
	}
	if len(mq.Question) == 0 {
		return nil, errors.New("dns: empty question")
	}
	q := mq.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")

	mr := new(dns.Msg).SetReply(mq)
	mr.RecursionAvailable = true
	ttl := uint32(e.ttl.Seconds())
	if ttl <= 0 {
		ttl = 600
	}

	switch q.Qtype {
	case dns.TypeA:
		fake, err := e.store.Create(domain, false)
		if err != nil {
			return nil, err
		}
		mr.Answer = append(mr.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.IP(fake.AsSlice()),
		})
	case dns.TypeAAAA:
		// Without an IPv6 range configured, answer with no record (NOERROR)
		// rather than failing the query.
		if fake, err := e.store.Create(domain, true); err == nil {
			mr.Answer = append(mr.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: net.IP(fake.AsSlice()),
			})
		}
	}

	return mr.Pack()
}
