package geo

import (
	"net/netip"
	"slices"
)

// prefixMap maps address prefixes to values and finds the longest prefix that contains an address. The zero value is
// an empty map. It keeps the IPv4 and the IPv6 prefixes apart, and an IPv4 address in IPv6 form counts as IPv4.
type prefixMap[V any] struct {
	// v4 and v6 map the length of a prefix to the values of the masked prefix addresses of that length.
	v4 map[int]map[netip.Addr]V
	v6 map[int]map[netip.Addr]V

	// lengths4 and lengths6 are the prefix lengths in use, longest first, so a lookup tries each length once and the
	// first hit is the longest prefix.
	lengths4 []int
	lengths6 []int

	count int
}

// set stores value for prefix and replaces an earlier value of the same prefix. The prefix must be valid.
func (m *prefixMap[V]) set(prefix netip.Prefix, value V) {
	prefix = prefix.Masked()

	sets, lengths := &m.v6, &m.lengths6
	if prefix.Addr().Is4() {
		sets, lengths = &m.v4, &m.lengths4
	}

	if *sets == nil {
		*sets = map[int]map[netip.Addr]V{}
	}

	bits := prefix.Bits()
	if (*sets)[bits] == nil {
		(*sets)[bits] = map[netip.Addr]V{}

		at, _ := slices.BinarySearchFunc(*lengths, bits, func(a, b int) int { return b - a })
		*lengths = slices.Insert(*lengths, at, bits)
	}

	if _, seen := (*sets)[bits][prefix.Addr()]; !seen {
		m.count++
	}

	(*sets)[bits][prefix.Addr()] = value
}

// lookup returns the value of the longest prefix that contains address and reports whether there is one. An invalid
// address is in no prefix.
func (m *prefixMap[V]) lookup(address netip.Addr) (V, bool) {
	var zero V
	if m == nil || !address.IsValid() {
		return zero, false
	}

	address = address.Unmap()

	sets, lengths := m.v6, m.lengths6
	if address.Is4() {
		sets, lengths = m.v4, m.lengths4
	}

	for _, bits := range lengths {
		prefix, err := address.Prefix(bits)
		if err != nil {
			continue
		}

		if value, found := sets[bits][prefix.Addr()]; found {
			return value, true
		}
	}

	return zero, false
}

// len returns the number of prefixes in the map.
func (m *prefixMap[V]) len() int {
	if m == nil {
		return 0
	}

	return m.count
}
