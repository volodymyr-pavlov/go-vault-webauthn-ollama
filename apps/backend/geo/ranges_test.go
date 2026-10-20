package geo

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRanges(t *testing.T, text string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ranges.txt")

	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestRangesContainAddressesInsideTheirPrefixes(t *testing.T) {
	ranges, err := ReadRanges(writeRanges(t, `
# a VPN provider
198.51.100.0/24   # exit nodes
203.0.113.77
2001:db8:abcd::/48
`))
	if err != nil {
		t.Fatal(err)
	}

	if ranges.Len() != 3 {
		t.Fatalf("three prefixes expected, got %d", ranges.Len())
	}

	for address, want := range map[string]bool{
		"198.51.100.9":          true,
		"198.51.101.9":          false,
		"203.0.113.77":          true,
		"203.0.113.78":          false,
		"2001:db8:abcd:1::5":    true,
		"2001:db8:abce::5":      false,
		"::ffff:198.51.100.200": true,
		"8.8.8.8":               false,
	} {
		if got := ranges.Contains(netip.MustParseAddr(address)); got != want {
			t.Errorf("%s: want %v, got %v", address, want, got)
		}
	}
}

func TestRangesAreEmptyWhenNilOrUnset(t *testing.T) {
	var ranges *Ranges

	if ranges.Contains(netip.MustParseAddr("198.51.100.9")) || ranges.Len() != 0 {
		t.Fatal("a nil set is empty")
	}

	if (&Ranges{}).Contains(netip.Addr{}) {
		t.Fatal("an invalid address is in no range")
	}
}

func TestReadRangesRefusesABadLineAndALargeFile(t *testing.T) {
	_, err := ReadRanges(writeRanges(t, "198.51.100.0/24\nnot a prefix\n"))
	if !errors.Is(err, ErrRanges) || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("a bad line: %v", err)
	}

	large := writeRanges(t, strings.Repeat("198.51.100.0/24\n", MaxRangesFileSize/16+10))

	if _, err := ReadRanges(large); !errors.Is(err, ErrRanges) {
		t.Fatalf("a large file: %v", err)
	}

	if _, err := ReadRanges(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("a missing file must fail")
	}
}
