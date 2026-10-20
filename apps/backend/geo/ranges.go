package geo

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// MaxRangesFileSize is the largest file of address ranges that [ReadRanges] reads, in bytes. A list of the ranges of
// VPN and hosting providers has some ten thousand lines, which is far below the limit.
const MaxRangesFileSize = 16 << 20

// Ranges is a set of address prefixes. The service uses one to tell the addresses of VPN, proxy and hosting providers
// from the addresses of people at home. The zero value and a nil pointer are empty sets.
type Ranges struct {
	// v4 and v6 map the length of a prefix to the set of masked prefix addresses of that length.
	v4 map[int]map[netip.Addr]struct{}
	v6 map[int]map[netip.Addr]struct{}

	// lengths4 and lengths6 are the prefix lengths in use, longest first, so a lookup tries each length once.
	lengths4 []int
	lengths6 []int

	count int
}

// ReadRanges reads a file of address prefixes, one on each line. An empty line is skipped, and so is everything after a
// "#". An address without a length counts as a prefix of one address.
//
// It returns an error wrapping [ErrRanges] if the file is larger than [MaxRangesFileSize] or a line is not a prefix. It
// returns another error if the file cannot be read.
func ReadRanges(path string) (*Ranges, error) {
	path = filepath.Clean(path)

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read the ranges file: %w", err)
	}

	if info.Size() > MaxRangesFileSize {
		return nil, fmt.Errorf("%w: the file has %d bytes, the limit is %d", ErrRanges, info.Size(), MaxRangesFileSize)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the ranges file: %w", err)
	}

	ranges := &Ranges{
		v4: map[int]map[netip.Addr]struct{}{},
		v6: map[int]map[netip.Addr]struct{}{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for line := 1; scanner.Scan(); line++ {
		text, _, _ := strings.Cut(scanner.Text(), "#")

		text = strings.TrimSpace(text)

		if text == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			address, addressErr := netip.ParseAddr(text)
			if addressErr != nil {
				return nil, fmt.Errorf("line %d: %w", line, ErrRanges)
			}

			prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
		}

		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
		sets := ranges.v6
		if prefix.Addr().Is4() {
			sets = ranges.v4
		}

		if sets[prefix.Bits()] == nil {
			sets[prefix.Bits()] = map[netip.Addr]struct{}{}
		}

		if _, seen := sets[prefix.Bits()][prefix.Addr()]; !seen {
			ranges.count++
		}

		sets[prefix.Bits()][prefix.Addr()] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read the ranges file: %w", err)
	}

	for bits := range ranges.v4 {
		ranges.lengths4 = append(ranges.lengths4, bits)
	}

	for bits := range ranges.v6 {
		ranges.lengths6 = append(ranges.lengths6, bits)
	}

	slices.SortFunc(ranges.lengths4, func(a, b int) int { return b - a })
	slices.SortFunc(ranges.lengths6, func(a, b int) int { return b - a })

	return ranges, nil
}

// Len returns the number of prefixes in the set.
func (r *Ranges) Len() int {
	if r == nil {
		return 0
	}

	return r.count
}

// Contains reports whether the address is inside one of the prefixes. An invalid address is in no prefix, and an IPv4
// address in IPv6 form counts as an IPv4 address.
func (r *Ranges) Contains(address netip.Addr) bool {
	if r == nil || !address.IsValid() {
		return false
	}

	address = address.Unmap()

	sets, lengths := r.v6, r.lengths6
	if address.Is4() {
		sets, lengths = r.v4, r.lengths4
	}

	for _, bits := range lengths {
		prefix, err := address.Prefix(bits)
		if err != nil {
			continue
		}

		if _, found := sets[bits][prefix.Addr()]; found {
			return true
		}
	}

	return false
}
