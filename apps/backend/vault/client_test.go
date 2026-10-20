package vault

import (
	"errors"
	"testing"
)

func TestSplit(t *testing.T) {
	for _, bad := range []string{"", "vault:v1", "vault:v1:", "v1:x", "vault:v0:x", "vault:vx:y", "vault:1:x"} {
		if _, _, err := Split(bad); !errors.Is(err, ErrCiphertextForm) {
			t.Errorf("Split(%q): %v, want ErrCiphertextForm", bad, err)
		}
	}

	version, payload, err := Split("vault:v12:abc=")
	if err != nil || version != 12 || payload != "abc=" {
		t.Fatalf("Split: %d, %q, %v", version, payload, err)
	}
}
