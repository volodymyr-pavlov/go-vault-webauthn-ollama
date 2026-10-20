package geo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

		// An IPv4 prefix in IPv6 form, such as ::ffff:198.51.100.0/120, counts as an IPv4 prefix: the first 96 bits only say
		// that the address is mapped. A shorter mapped prefix covers more than the mapped range and stays an IPv6 prefix.
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}

		prefix = prefix.Masked()
		if !prefix.IsValid() {
			return nil, fmt.Errorf("line %d: %w", line, ErrRanges)
		}

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

// RangesRefreshInterval is how often [RangesFile.Run] looks at the file for a change.
const RangesRefreshInterval = time.Minute

// RangesFile is a set of address prefixes that follows a file. The service reads the file at start-up, and [RangesFile.Run]
// reads it again when its size or its time of change differs, so an operator can update the list without a restart. A
// reload that fails keeps the list that works. The zero value and a nil pointer are empty sets, and every method is safe
// to call from several goroutines.
type RangesFile struct {
	path    string
	current atomic.Pointer[Ranges]

	// mu serializes the reloads, and modified and size say which version of the file current holds.
	mu       sync.Mutex
	modified time.Time
	size     int64
}

// WatchRanges reads the file at path and returns the set that follows it.
//
// It returns the errors of [ReadRanges].
func WatchRanges(path string) (*RangesFile, error) {
	file := &RangesFile{
		path: filepath.Clean(path),
	}

	if _, err := file.Reload(); err != nil {
		return nil, err
	}

	return file, nil
}

// Contains reports whether the address is inside one of the prefixes of the list that is loaded now.
func (f *RangesFile) Contains(address netip.Addr) bool {
	if f == nil {
		return false
	}

	return f.current.Load().Contains(address)
}

// Len returns the number of prefixes in the list that is loaded now.
func (f *RangesFile) Len() int {
	if f == nil {
		return 0
	}

	return f.current.Load().Len()
}

// Reload reads the file again if its size or its time of change differs from the version that is loaded, and then
// replaces the list as a whole, so a lookup sees the old list or the new one and never a mix. It reports whether it
// loaded a new list.
//
// It returns the errors of [ReadRanges], and then it keeps the list that is loaded. A later call tries again.
func (f *RangesFile) Reload() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	info, err := os.Stat(f.path)
	if err != nil {
		return false, fmt.Errorf("read the ranges file: %w", err)
	}

	if f.current.Load() != nil && info.ModTime().Equal(f.modified) && info.Size() == f.size {
		return false, nil
	}

	ranges, err := ReadRanges(f.path)
	if err != nil {
		return false, err
	}

	f.current.Store(ranges)
	f.modified = info.ModTime()
	f.size = info.Size()

	return true, nil
}

// Run looks at the file every interval and reloads it when it changed, until ctx ends. A failed reload goes to onFailure
// and the list that works stays. A successful reload goes to onReload with the number of prefixes.
func (f *RangesFile) Run(ctx context.Context, interval time.Duration, onReload func(prefixes int), onFailure func(error)) {
	if f == nil {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		changed, err := f.Reload()
		if err != nil {
			onFailure(err)

			continue
		}

		if changed {
			onReload(f.Len())
		}
	}
}
