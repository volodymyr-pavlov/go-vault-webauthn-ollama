// Package geo finds the client address of a request that arrives through a reverse proxy. It also places an address
// with a mock geo-IP table, for the risk signals.
//
// The table is synthetic. It has a few address prefixes, each with a country and a point. This is enough to show a
// change of country and an impossible travel.
package geo

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

//go:embed table.csv
var table []byte

// EarthRadiusKm is the radius of the Earth in kilometres that [Distance] uses.
const EarthRadiusKm = 6371

// Place is the location that the table gives to an address. An address that is not in the table has the zero Place.
type Place struct {
	// Country is the ISO 3166-1 alpha-2 code of the country.
	Country string

	// Latitude and Longitude are the point of the address prefix, in degrees.
	Latitude  float64
	Longitude float64
}

// Known reports whether the table has a location for the address.
func (p Place) Known() bool {
	return p.Country != ""
}

// row is one line of the table: an address prefix and its [Place].
type row struct {
	prefix netip.Prefix
	place  Place
}

// Locator finds the client address of a request and places an address with the table. [New] builds it.
type Locator struct {
	// TrustedProxies are the address prefixes of the peers that may set the X-Forwarded-For header, such as the reverse
	// proxy that ends TLS. [Locator.Address] ignores the header of any other peer.
	TrustedProxies []netip.Prefix

	rows []row
}

// New returns a [Locator] that uses the embedded table and trusts the X-Forwarded-For header of the peers in proxies.
//
// It returns an error wrapping [ErrTable] if a line of the table does not have four fields. It returns another error if
// a prefix, a latitude or a longitude of the table cannot be parsed.
func New(proxies []netip.Prefix) (*Locator, error) {
	locator := &Locator{
		TrustedProxies: proxies,
	}
	scanner := bufio.NewScanner(bytes.NewReader(table))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		fields := strings.Split(text, ",")
		if len(fields) != 4 {
			return nil, fmt.Errorf("table line %d: %w", line, ErrTable)
		}

		prefix, err := netip.ParsePrefix(strings.TrimSpace(fields[0]))
		if err != nil {
			return nil, fmt.Errorf("table line %d: %w", line, err)
		}

		latitude, err := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		if err != nil {
			return nil, fmt.Errorf("table line %d: %w", line, err)
		}

		longitude, err := strconv.ParseFloat(strings.TrimSpace(fields[3]), 64)
		if err != nil {
			return nil, fmt.Errorf("table line %d: %w", line, err)
		}

		locator.rows = append(locator.rows, row{
			prefix: prefix,
			place: Place{
				Country:   strings.TrimSpace(fields[1]),
				Latitude:  latitude,
				Longitude: longitude,
			},
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read the table: %w", err)
	}

	return locator, nil
}

// Address returns the client address of the request. If the peer is a trusted proxy, it reads the X-Forwarded-For
// header from the right, skips the addresses of trusted proxies and returns the first other address, which the last
// trusted proxy saw. Addresses further left are not trusted, because the client can set them. It returns the address of
// the peer if the peer is not a trusted proxy or if the header holds no usable address. It returns the zero address if
// the address of the peer is not known.
func (l *Locator) Address(ctx *fasthttp.RequestCtx) netip.Addr {
	peer, ok := netip.AddrFromSlice(ctx.RemoteIP())
	if !ok {
		return netip.Addr{}
	}

	peer = peer.Unmap()
	if !l.trusts(peer) {
		return peer
	}

	var hops []string
	for _, value := range ctx.Request.Header.PeekAll(fasthttp.HeaderXForwardedFor) {
		hops = append(hops, strings.Split(string(value), ",")...)
	}

	for i := len(hops) - 1; i >= 0; i-- {
		address, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}

		address = address.Unmap()
		if !l.trusts(address) {
			return address
		}
	}

	return peer
}

// trusts reports whether address belongs to one of the [Locator.TrustedProxies].
func (l *Locator) trusts(address netip.Addr) bool {
	for _, proxy := range l.TrustedProxies {
		if proxy.Contains(address) {
			return true
		}
	}

	return false
}

// Place returns the [Place] of address. It uses the longest prefix of the table that contains the address. It returns
// the zero Place if no prefix contains it.
func (l *Locator) Place(address netip.Addr) Place {
	var best Place
	bits := -1
	for _, r := range l.rows {
		if r.prefix.Contains(address) && r.prefix.Bits() > bits {
			best = r.place
			bits = r.prefix.Bits()
		}
	}

	return best
}

// Distance returns the great-circle distance between the places a and b, in kilometres.
func Distance(a, b Place) float64 {
	lat1 := a.Latitude * math.Pi / 180
	lat2 := b.Latitude * math.Pi / 180
	dLat := lat2 - lat1
	dLon := (b.Longitude - a.Longitude) * math.Pi / 180
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * EarthRadiusKm * math.Asin(math.Sqrt(h))
}
