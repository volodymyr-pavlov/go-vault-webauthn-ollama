package auth

import (
	"errors"
	"strings"
	"testing"
)

// fast is a [HasherOptions] value with small cost parameters. It keeps the hash format and the checks the same
// and makes each hash take a few milliseconds.
var fast = HasherOptions{
	Memory:  1 << 10,
	Time:    1,
	Threads: 1,
}

func TestHashAndVerify(t *testing.T) {
	h := &Hasher{
		HasherOptions: fast,
	}

	hash, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("hash format: %s", hash)
	}

	if err := h.Verify(hash, "correct horse"); err != nil {
		t.Fatalf("the right password: %v", err)
	}

	if err := h.Verify(hash, "correct horsE"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a wrong password: %v, want ErrMismatch", err)
	}

	again, err := h.Hash("correct horse")
	if err != nil || again == hash {
		t.Fatalf("a second hash must have a fresh salt: %v", err)
	}
}

func TestVerifyRefusesBadHashes(t *testing.T) {
	h := &Hasher{}
	for _, bad := range []string{
		"",
		"$argon2i$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=1024,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=0,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$!!$aGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$",
		"plain",
	} {
		if err := h.Verify(bad, "x"); !errors.Is(err, ErrHashFormat) {
			t.Errorf("Verify(%q): %v, want ErrHashFormat", bad, err)
		}
	}
}

func TestLengthBound(t *testing.T) {
	h := &Hasher{
		HasherOptions: fast,
	}
	long := strings.Repeat("a", MaxLength+1)

	if _, err := h.Hash(long); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Hash of a long password: %v, want ErrTooLong", err)
	}

	hash, _ := h.Hash("short")

	if err := h.Verify(hash, long); !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify of a long password: %v, want ErrMismatch", err)
	}
}
