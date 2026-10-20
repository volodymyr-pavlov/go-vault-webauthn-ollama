package validate

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		input      string
		empty, max bool
		min        bool
	}{
		{"", true, false, true},
		{"   ", true, false, false},
		{"abc", false, false, false},
		{"abcdef", false, true, false},
		{"a", false, false, true},
	}
	for _, c := range cases {
		v := Validate{
			Input: c.input,
			Max:   5,
			Min:   2,
		}
		if v.IsEmpty() != c.empty || v.TooLong() != c.max || v.TooShort() != c.min {
			t.Errorf("%q: empty %v max %v min %v", c.input, v.IsEmpty(), v.TooLong(), v.TooShort())
		}
	}
}

func TestIsEmail(t *testing.T) {
	for _, good := range []string{"a@b.co", "alice+tag@example.com"} {
		if !IsEmail(good) {
			t.Errorf("%q must be an address", good)
		}
	}

	for _, bad := range []string{"", "a", "a@b", "a b@c.de", "@b.co", "a@@b.co", strings.Repeat("a", MaxEmailLength) + "@b.co"} {
		if IsEmail(bad) {
			t.Errorf("%q must not be an address", bad)
		}
	}
}

func TestShapes(t *testing.T) {
	if !IsDigits("012345", 6) || IsDigits("12345", 6) || IsDigits("12345a", 6) || IsDigits("１２３４５６", 6) {
		t.Fatal("IsDigits")
	}

	if !IsRecoveryCode("ABCDEFGHIJKLMNOP") || IsRecoveryCode("ABCDEFGHIJKLMNO") || IsRecoveryCode("abcdefghijklmnop") || IsRecoveryCode("ABCDEFGHIJKLMN01") {
		t.Fatal("IsRecoveryCode")
	}

	if _, ok := HexToken(strings.Repeat("ab", TokenLength)); !ok {
		t.Fatal("a good token")
	}

	for _, bad := range []string{"", "zz", strings.Repeat("ab", TokenLength-1), strings.Repeat("ab", TokenLength+1), " " + strings.Repeat("ab", TokenLength)} {
		if _, ok := HexToken(bad); ok {
			t.Errorf("%q must not be a token", bad)
		}
	}

}
