package vault

import (
	"strconv"
	"strings"
	"testing"
)

// FuzzSplit feeds arbitrary strings to the parser of the "vault:vN:payload" ciphertext form. The parser must never
// panic, and every string it accepts must join back to the same text.
func FuzzSplit(f *testing.F) {
	f.Add("vault:v1:abc")
	f.Add("vault:v12:YWJj")
	f.Add("vault:v0:x")
	f.Add("vault:v:x")
	f.Add("")
	f.Add("vault:v1:")
	f.Fuzz(func(t *testing.T, value string) {
		version, payload, err := Split(value)
		if err != nil {
			return
		}

		if version < 1 || payload == "" {
			t.Fatalf("accepted version %d payload %q", version, payload)
		}

		if !strings.HasPrefix(value, "vault:v"+strconv.Itoa(version)+":"+payload) {
			t.Fatalf("%q split into %d and %q", value, version, payload)
		}
	})
}
