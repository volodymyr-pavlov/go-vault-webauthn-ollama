package geo

import (
	"math"
	"net"
	"net/netip"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestPlaceAndDistance(t *testing.T) {
	locator, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}

	berlin := locator.Place(netip.MustParseAddr("192.0.2.7"))
	sydney := locator.Place(netip.MustParseAddr("203.0.113.200"))

	tokyo := locator.Place(netip.MustParseAddr("203.0.113.5"))
	if berlin.Country != "DE" || sydney.Country != "AU" || tokyo.Country != "JP" {
		t.Fatalf("places: %+v %+v %+v", berlin, sydney, tokyo)
	}

	if locator.Place(netip.MustParseAddr("8.8.8.8")).Known() {
		t.Fatal("an address outside the table must be unknown")
	}

	if km := Distance(berlin, sydney); math.Abs(km-16100) > 200 {
		t.Fatalf("Berlin to Sydney: %.0f km", km)
	}

	if km := Distance(berlin, berlin); km != 0 {
		t.Fatalf("a place to itself: %f", km)
	}
}

func TestAddressBehindProxy(t *testing.T) {
	locator, err := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}

	var ctx fasthttp.RequestCtx
	ctx.Init(&fasthttp.Request{}, &net.TCPAddr{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 1234,
	}, nil)
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedFor, "203.0.113.9, 10.1.2.3")

	if got := locator.Address(&ctx); got != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("behind the proxy: %s", got)
	}

	ctx.Init(&fasthttp.Request{}, &net.TCPAddr{
		IP:   net.ParseIP("198.51.100.4"),
		Port: 1234,
	}, nil)
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedFor, "203.0.113.9")

	if got := locator.Address(&ctx); got != netip.MustParseAddr("198.51.100.4") {
		t.Fatalf("a forwarding header from an untrusted peer must be ignored: %s", got)
	}

	ctx.Init(&fasthttp.Request{}, &net.TCPAddr{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 1234,
	}, nil)
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedFor, "not an address")

	if got := locator.Address(&ctx); got != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("a bad forwarding header must give the peer: %s", got)
	}

	ctx.Init(&fasthttp.Request{}, &net.TCPAddr{
		IP:   net.ParseIP("10.1.2.3"),
		Port: 1234,
	}, nil)
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedFor, "192.0.2.77, 203.0.113.9, 10.9.9.9")

	if got := locator.Address(&ctx); got != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("an address that the client prepended must not win: %s", got)
	}
}

// TestPrefixMapFindsTheLongestPrefix proves that a lookup returns the value of the longest prefix whatever the order
// the prefixes were stored in, counts a prefix once, and keeps IPv4 and IPv6 apart.
func TestPrefixMapFindsTheLongestPrefix(t *testing.T) {
	var m prefixMap[string]
	m.set(netip.MustParsePrefix("203.0.113.128/25"), "narrow")
	m.set(netip.MustParsePrefix("203.0.113.0/24"), "wide")
	m.set(netip.MustParsePrefix("203.0.113.0/24"), "wide again")
	m.set(netip.MustParsePrefix("2001:db8::/32"), "six")

	if m.len() != 3 {
		t.Fatalf("a prefix counts once: %d", m.len())
	}

	if got, _ := m.lookup(netip.MustParseAddr("203.0.113.200")); got != "narrow" {
		t.Fatalf("the longest prefix wins: %q", got)
	}

	if got, _ := m.lookup(netip.MustParseAddr("203.0.113.5")); got != "wide again" {
		t.Fatalf("a later value replaces the earlier one: %q", got)
	}

	if got, _ := m.lookup(netip.MustParseAddr("::ffff:203.0.113.200")); got != "narrow" {
		t.Fatalf("a mapped address counts as IPv4: %q", got)
	}

	if _, found := m.lookup(netip.MustParseAddr("2001:db9::1")); found {
		t.Fatal("an address outside every prefix is not found")
	}

	if _, found := m.lookup(netip.Addr{}); found {
		t.Fatal("an invalid address is not found")
	}
}
