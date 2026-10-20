package totp

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// field appends a protobuf field with a wire type 2 (length-prefixed) value.
func bytesField(number byte, value []byte) []byte {
	if len(value) > 127 {
		panic("a test field must be shorter than 128 bytes")
	}

	out := make([]byte, 0, 2+len(value))
	out = append(out, number<<3|2, byte(min(len(value), 127)))

	return append(out, value...)
}

// varintField appends a protobuf field with a wire type 0 (varint) value below 128.
func varintField(number byte, value byte) []byte {
	return []byte{number << 3, value}
}

// migrationLink builds an otpauth-migration link from the entries.
func migrationLink(entries ...[]byte) string {
	payload := make([]byte, 0, 64)
	for _, entry := range entries {
		payload = append(payload, bytesField(1, entry)...)
	}

	// The version and the batch size are fields that the parser skips.
	payload = append(payload, varintField(2, 1)...)
	payload = append(payload, varintField(3, 1)...)

	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
}

func migrationEntry(secret []byte, name, issuer string, algorithm, digits, kind byte) []byte {
	out := make([]byte, 0, 64)
	out = append(out, bytesField(1, secret)...)
	out = append(out, bytesField(2, []byte(name))...)
	out = append(out, bytesField(3, []byte(issuer))...)
	out = append(out, varintField(4, algorithm)...)
	out = append(out, varintField(5, digits)...)
	out = append(out, varintField(6, kind)...)

	return out
}

func TestParseURIReadsAnOTPAuthLink(t *testing.T) {
	accounts, skipped, err := ParseURI("otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60&algorithm=sha256")
	if err != nil || skipped != 0 || len(accounts) != 1 {
		t.Fatalf("one account expected: %v %d %v", accounts, skipped, err)
	}

	got := accounts[0]
	if got.Issuer != "GitHub" || got.Label != "alice@example.com" || got.Digits != 8 || got.Period != 60 || got.Algorithm != "SHA256" {
		t.Fatalf("unexpected account: %+v", got)
	}

	if string(got.Secret) != "Hello!\xde\xad\xbe\xef" {
		t.Fatalf("unexpected secret bytes: %x", got.Secret)
	}
}

func TestParseURIUsesTheDefaultsAndTheIssuerOfTheLabel(t *testing.T) {
	accounts, _, err := ParseURI("otpauth://totp/Example:bob?secret=jbsw y3dp ehpk 3pxp")
	if err != nil {
		t.Fatal(err)
	}

	got := accounts[0]
	if got.Issuer != "Example" || got.Label != "bob" || got.Digits != 6 || got.Period != 30 || got.Algorithm != "SHA1" {
		t.Fatalf("unexpected account: %+v", got)
	}
}

func TestParseURIRefusesWhatItCannotImport(t *testing.T) {
	valid := "JBSWY3DPEHPK3PXP"

	for _, refused := range []struct {
		name string
		link string
	}{
		{"hotp", "otpauth://hotp/x?counter=1&secret=" + valid},
		{"another scheme", "https://example.com"},
		{"no secret", "otpauth://totp/x"},
		{"not base32", "otpauth://totp/x?secret=!!!!"},
		{"short secret", "otpauth://totp/x?secret=MFRGG"},
		{"nine digits", "otpauth://totp/x?digits=9&secret=" + valid},
		{"huge period", "otpauth://totp/x?period=100000&secret=" + valid},
		{"md5", "otpauth://totp/x?algorithm=MD5&secret=" + valid},
		{"empty migration", "otpauth-migration://offline"},
		{"bad base64", "otpauth-migration://offline?data=@@@"},
		{"too long", "otpauth://totp/x?secret=" + strings.Repeat("A", MaxURILength)},
	} {
		name, link := refused.name, refused.link

		if _, _, err := ParseURI(link); !errors.Is(err, ErrImport) {
			t.Errorf("%s: want ErrImport, got %v", name, err)
		}
	}
}

func TestParseURIReadsAGoogleMigrationExport(t *testing.T) {
	secretA := []byte("0123456789abcdef0123")
	secretB := []byte("ABCDEFGHIJKLMNOP")

	link := migrationLink(
		migrationEntry(secretA, "alice@example.com", "GitHub", 1, 1, 2),
		migrationEntry(secretB, "Example:bob", "", 2, 2, 2),
		migrationEntry([]byte("counter-based-1234"), "hotp", "Bank", 1, 1, 1),
	)

	accounts, skipped, err := ParseURI(link)
	if err != nil {
		t.Fatal(err)
	}

	if len(accounts) != 2 || skipped != 1 {
		t.Fatalf("two accounts and one skipped HOTP expected, got %d and %d", len(accounts), skipped)
	}

	if accounts[0].Issuer != "GitHub" || accounts[0].Label != "alice@example.com" || accounts[0].Digits != 6 || accounts[0].Algorithm != "SHA1" || string(accounts[0].Secret) != string(secretA) {
		t.Fatalf("first account: %+v", accounts[0])
	}

	if accounts[1].Issuer != "Example" || accounts[1].Label != "bob" || accounts[1].Digits != 8 || accounts[1].Algorithm != "SHA256" {
		t.Fatalf("second account: %+v", accounts[1])
	}
}

func TestParseURIRefusesADamagedMigrationExport(t *testing.T) {
	full := migrationLink(migrationEntry([]byte("0123456789abcdef0123"), "a", "b", 1, 1, 2))
	prefix := "otpauth-migration://offline?data="

	raw, err := base64.StdEncoding.DecodeString(mustUnescape(t, strings.TrimPrefix(full, prefix)))
	if err != nil {
		t.Fatal(err)
	}

	for cut := 1; cut < len(raw)-4; cut += 3 {
		link := prefix + url.QueryEscape(base64.StdEncoding.EncodeToString(raw[:cut]))

		if _, _, err := ParseURI(link); err != nil && !errors.Is(err, ErrImport) {
			t.Errorf("a cut at %d must give ErrImport or succeed, got %v", cut, err)
		}
	}

	only := migrationLink(migrationEntry([]byte("counter-based-1234"), "hotp", "Bank", 1, 1, 1))

	if _, _, err := ParseURI(only); !errors.Is(err, ErrImport) {
		t.Errorf("an export with no time-based account must give ErrImport, got %v", err)
	}
}

func TestParseSecretAcceptsSpacesAndLowerCase(t *testing.T) {
	account, err := ParseSecret("jbsw-y3dp ehpk 3pxp", "  Example\n", "carol")
	if err != nil {
		t.Fatal(err)
	}

	if account.Issuer != "Example" || account.Label != "carol" || account.Digits != 6 || account.Period != 30 {
		t.Fatalf("unexpected account: %+v", account)
	}

	if _, err := ParseSecret("MFRGG", "x", "y"); !errors.Is(err, ErrImport) {
		t.Fatalf("a short secret: %v", err)
	}
}

func mustUnescape(t *testing.T, text string) string {
	t.Helper()

	out, err := url.QueryUnescape(text)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func FuzzParseURI(f *testing.F) {
	f.Add("otpauth://totp/Example:bob?secret=JBSWY3DPEHPK3PXP")
	f.Add(migrationLink(migrationEntry([]byte("0123456789abcdef0123"), "a", "b", 1, 1, 2)))
	f.Add("otpauth-migration://offline?data=CgA=")

	f.Fuzz(func(t *testing.T, link string) {
		accounts, _, err := ParseURI(link)
		if err != nil {
			if !errors.Is(err, ErrImport) {
				t.Fatalf("an error must wrap ErrImport, got %v", err)
			}

			return
		}

		if len(accounts) == 0 || len(accounts) > MaxImportAccounts {
			t.Fatalf("the number of accounts is out of range: %d", len(accounts))
		}

		for _, account := range accounts {
			if err := account.check(); err != nil {
				t.Fatalf("an accepted account must pass check: %v", err)
			}
		}
	})
}
