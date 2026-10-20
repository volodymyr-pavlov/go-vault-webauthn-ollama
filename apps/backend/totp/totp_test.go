package totp

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// rfcSecret and rfcVectors hold the SHA-1 test vectors of RFC 6238, appendix B. The secret is the ASCII digits
// repeated to 20 bytes, and the codes have 8 digits.
var rfcSecret = []byte("12345678901234567890")

var rfcVectors = []struct {
	unix int64
	code string
}{
	{59, "94287082"},
	{1111111109, "07081804"},
	{1111111111, "14050471"},
	{1234567890, "89005924"},
	{2000000000, "69279037"},
	{20000000000, "65353130"},
}

func TestRFC6238Vectors(t *testing.T) {
	opts := Options{
		Digits: 8,
	}
	for _, v := range rfcVectors {
		at := time.Unix(v.unix, 0)

		if got := opts.Code(rfcSecret, opts.Step(at)); got != v.code {
			t.Errorf("at %d: %s, want %s", v.unix, got, v.code)
		}

		step, err := opts.Verify(rfcSecret, v.code, at, 0)
		if err != nil || step != opts.Step(at) {
			t.Errorf("Verify at %d: step %d, %v", v.unix, step, err)
		}
	}
}

func TestWindowAndReuse(t *testing.T) {
	var opts Options
	now := time.Unix(1_700_000_000, 0)
	current := opts.Step(now)
	for _, step := range []uint64{current - 1, current, current + 1} {
		got, err := opts.Verify(rfcSecret, opts.Code(rfcSecret, step), now, 0)
		if err != nil || got != step {
			t.Fatalf("a code of step %d (current %d): %d, %v", step, current, got, err)
		}
	}

	for _, step := range []uint64{current - 2, current + 2} {
		if _, err := opts.Verify(rfcSecret, opts.Code(rfcSecret, step), now, 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("a code of step %d (current %d): %v, want ErrInvalid", step, current, err)
		}
	}

	code := opts.Code(rfcSecret, current)

	if _, err := opts.Verify(rfcSecret, code, now, current); !errors.Is(err, ErrReused) {
		t.Fatalf("the same step again: %v, want ErrReused", err)
	}

	if _, err := opts.Verify(rfcSecret, opts.Code(rfcSecret, current-1), now, current); !errors.Is(err, ErrReused) {
		t.Fatalf("an earlier step after a later one: %v, want ErrReused", err)
	}

	if _, err := opts.Verify(rfcSecret, opts.Code(rfcSecret, current+1), now, current); err != nil {
		t.Fatalf("the next step after the current one: %v", err)
	}
}

func TestFormat(t *testing.T) {
	var opts Options
	now := time.Now()
	for _, bad := range []string{"", "12345", "1234567", "12345a", "12 456"} {
		if _, err := opts.Verify(rfcSecret, bad, now, 0); !errors.Is(err, ErrFormat) {
			t.Errorf("Verify(%q): %v, want ErrFormat", bad, err)
		}
	}

	if code := opts.Code(rfcSecret, 1); len(code) != 6 {
		t.Fatalf("a six-digit code: %q", code)
	}
}

func TestSecretAndURI(t *testing.T) {
	secret, err := NewSecret()
	if err != nil || len(secret) != SecretLength {
		t.Fatalf("NewSecret: %d bytes, %v", len(secret), err)
	}

	uri := URI("Vault Login", "a@example.com", secret, Options{})
	for _, want := range []string{"otpauth://totp/Vault%20Login:a@example.com?", "algorithm=SHA1", "digits=6", "period=30", "issuer=Vault+Login", "secret="} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %s lacks %s", uri, want)
		}
	}
}

func TestVerifyRefusesDigitsOutOfRange(t *testing.T) {
	for _, digits := range []int{-1, MaxDigits + 1} {
		_, err := Options{Digits: digits}.Verify([]byte("secret"), "123456", time.Unix(0, 0), 0)
		if !errors.Is(err, ErrOptions) {
			t.Fatalf("%d digits: %v, want ErrOptions", digits, err)
		}
	}
}
