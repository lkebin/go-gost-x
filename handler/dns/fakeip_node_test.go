package dns

import (
	"context"
	"net/netip"
	"testing"

	resolver_util "github.com/go-gost/x/internal/util/resolver"
	"github.com/miekg/dns"
)

// mustPrefix parses a CIDR prefix or panics; test-only helper.
func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestParseFakeIPNode(t *testing.T) {
	inet4, inet6, ok := parseFakeIPNode("fakeip://?inet4=198.18.0.0/15&inet6=fc00::/18")
	if !ok {
		t.Fatal("expected fakeip node")
	}
	if inet4 != mustPrefix("198.18.0.0/15") || inet6 != mustPrefix("fc00::/18") {
		t.Fatalf("ranges = %s / %s", inet4, inet6)
	}

	// Defaults when no ranges are given.
	inet4, inet6, ok = parseFakeIPNode("fakeip://")
	if !ok {
		t.Fatal("expected fakeip node (defaults)")
	}
	if inet4 != mustPrefix("198.18.0.0/15") || inet6 != mustPrefix("fc00::/18") {
		t.Fatalf("default ranges = %s / %s", inet4, inet6)
	}

	if _, _, ok = parseFakeIPNode("udp://223.5.5.5:53"); ok {
		t.Fatal("udp node must not be treated as fakeip node")
	}
}

func TestFakeIPNodeExchanger(t *testing.T) {
	store := resolver_util.NewFakeIPStore(mustPrefix("198.18.0.0/15"), netip.Prefix{})
	ex := &fakeipExchanger{store: store, ttl: 0}

	// Build an A query for google.com.
	mq := new(dns.Msg)
	mq.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	qb, err := mq.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	respB, err := ex.Exchange(context.Background(), qb)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	mr := new(dns.Msg)
	if err := mr.Unpack(respB); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(mr.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(mr.Answer))
	}
	a, ok := mr.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", mr.Answer[0])
	}
	fake := netip.MustParseAddr(a.A.String())
	if !mustPrefix("198.18.0.0/15").Contains(fake) {
		t.Fatalf("fake IP = %s, want inside 198.18.0.0/15", fake)
	}
	// The tun handler recovers the domain from this address via the store.
	if domain, ok := store.Lookup(fake); !ok || domain != "google.com" {
		t.Fatalf("store lookup = %q (%v), want google.com", domain, ok)
	}

	// Same domain yields the same fake IP (stable mapping).
	mq2 := new(dns.Msg)
	mq2.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	qb2, _ := mq2.Pack()
	respB2, err := ex.Exchange(context.Background(), qb2)
	if err != nil {
		t.Fatalf("exchange 2: %v", err)
	}
	mr2 := new(dns.Msg)
	mr2.Unpack(respB2)
	a2 := mr2.Answer[0].(*dns.A)
	if a2.A.String() != a.A.String() {
		t.Fatalf("unstable mapping: %s != %s", a2.A.String(), a.A.String())
	}
}

func TestFakeIPNodeExchangerNoV6(t *testing.T) {
	store := resolver_util.NewFakeIPStore(mustPrefix("198.18.0.0/15"), netip.Prefix{})
	ex := &fakeipExchanger{store: store, ttl: 0}

	mq := new(dns.Msg)
	mq.SetQuestion(dns.Fqdn("google.com"), dns.TypeAAAA)
	qb, _ := mq.Pack()
	respB, err := ex.Exchange(context.Background(), qb)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	mr := new(dns.Msg)
	mr.Unpack(respB)
	if len(mr.Answer) != 0 {
		t.Fatalf("AAAA without v6 range should have no answer, got %d", len(mr.Answer))
	}
}
