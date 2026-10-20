package geo

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestRangesReadAnIPv4PrefixWrittenInIPv6Form(t *testing.T) {
	ranges, err := ReadRanges(writeRanges(t, "::ffff:198.51.100.0/120\n::ffff:203.0.113.77\n"))
	if err != nil {
		t.Fatal(err)
	}

	for address, want := range map[string]bool{
		"198.51.100.200": true,
		"198.51.101.1":   false,
		"203.0.113.77":   true,
		"203.0.113.78":   false,
	} {
		if got := ranges.Contains(netip.MustParseAddr(address)); got != want {
			t.Errorf("%s: want %v, got %v", address, want, got)
		}
	}

	if ranges.Len() != 2 {
		t.Fatalf("two prefixes expected, got %d", ranges.Len())
	}
}

func TestRangesFileFollowsItsFileAndKeepsTheListThatWorks(t *testing.T) {
	path := writeRanges(t, "198.51.100.0/24\n")

	file, err := WatchRanges(path)
	if err != nil {
		t.Fatal(err)
	}

	inside := netip.MustParseAddr("203.0.113.9")
	if file.Contains(inside) || !file.Contains(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("the first list holds 198.51.100.0/24 only")
	}

	if changed, err := file.Reload(); err != nil || changed {
		t.Fatalf("an unchanged file must not reload: %v %v", changed, err)
	}

	if err := os.WriteFile(path, []byte("198.51.100.0/24\n203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if changed, err := file.Reload(); err != nil || !changed || !file.Contains(inside) || file.Len() != 2 {
		t.Fatalf("a changed file must reload: %v %v %d", changed, err, file.Len())
	}

	// A broken file fails the reload and the earlier list stays in use.
	if err := os.WriteFile(path, []byte("this is not a prefix at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := file.Reload(); !errors.Is(err, ErrRanges) {
		t.Fatalf("a broken file: %v", err)
	}

	if !file.Contains(inside) || file.Len() != 2 {
		t.Fatal("the earlier list must stay after a failed reload")
	}

	var nilFile *RangesFile
	if nilFile.Contains(inside) || nilFile.Len() != 0 {
		t.Fatal("a nil file is an empty set")
	}
}

func TestRangesFileRunPicksUpAChange(t *testing.T) {
	path := writeRanges(t, "198.51.100.0/24\n")

	file, err := WatchRanges(path)
	if err != nil {
		t.Fatal(err)
	}

	reloaded := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go file.Run(ctx, 10*time.Millisecond, func(prefixes int) { reloaded <- prefixes }, func(error) {})

	if err := os.WriteFile(path, []byte("198.51.100.0/24\n203.0.113.0/24\n2001:db8::/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case prefixes := <-reloaded:
		if prefixes != 3 {
			t.Fatalf("three prefixes expected, got %d", prefixes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the change was not picked up")
	}
}
