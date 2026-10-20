package web

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
)

// The constants hold the public key and the signed request from RFC 9421, appendix B.2.6.
const (
	rfcPublicKey = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
	rfcInput     = `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	rfcSignature = `sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`
	rfcBase      = `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
)

func rfcResolve(component string) (string, error) {
	values := map[string]string{
		"date":           "Tue, 20 Apr 2021 02:07:55 GMT",
		"@method":        "POST",
		"@path":          "/foo",
		"@authority":     "example.com",
		"content-type":   "application/json",
		"content-length": "18",
	}

	if value, ok := values[component]; ok {
		return value, nil
	}

	return "", ErrComponent
}

func TestRFC9421EdDSAVector(t *testing.T) {
	input, err := ParseInput(rfcInput, "sig-b26")
	if err != nil {
		t.Fatal(err)
	}

	if input.Created != 1618884473 || input.KeyID != "test-key-ed25519" || len(input.Components) != 6 {
		t.Fatalf("input: %+v", input)
	}

	base, err := Base(input, rfcResolve)
	if err != nil {
		t.Fatal(err)
	}

	if base != rfcBase {
		t.Fatalf("base:\n%s\nwant:\n%s", base, rfcBase)
	}

	signature, err := ParseSignature(rfcSignature, "sig-b26")
	if err != nil {
		t.Fatal(err)
	}

	key, err := base64.RawURLEncoding.DecodeString(rfcPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(key, []byte(base), signature) {
		t.Fatal("the signature of the RFC must verify with the public key of the RFC")
	}
}

func TestParseInputPicksTheLabelAndKeepsTheOrder(t *testing.T) {
	field := `other=("@method");created=1, sig=("@method" "@path" "content-digest");created=7;keyid="k";alg="ed25519";nonce="n"`

	input, err := ParseInput(field, "sig")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(input.Components, []string{"@method", "@path", "content-digest"}) ||
		!slices.Equal(input.Params, []string{"created", "keyid", "alg", "nonce"}) ||
		input.Created != 7 || input.KeyID != "k" || input.Alg != "ed25519" || input.Nonce != "n" {
		t.Fatalf("input: %+v", input)
	}

	if input.Raw != `("@method" "@path" "content-digest");created=7;keyid="k";alg="ed25519";nonce="n"` {
		t.Fatalf("raw: %s", input.Raw)
	}

	if _, err := ParseInput(field, "missing"); !errors.Is(err, ErrNoLabel) {
		t.Fatalf("a missing label: %v", err)
	}
}

func TestParseInputRefusesWhatIsNotASignature(t *testing.T) {
	for _, field := range []string{
		`sig=@method;created=1`,
		`sig=("@method";created=1`,
		`sig=("@method" "@path);created=1`,
		`sig=("@method"x);created=1`,
		`sig=("@method");created=abc`,
		`sig=("@method");created`,
		`sig=("@method")created=1`,
		`sig=("@method");nonce=:AAAA:`,
	} {
		if _, err := ParseInput(field, "sig"); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v, want ErrMalformed", field, err)
		}
	}
}

func TestParseSignatureRefusesWhatIsNotAByteSequence(t *testing.T) {
	for _, field := range []string{`sig=AAAA`, `sig=:AAAA`, `sig=:@@@@:`} {
		if _, err := ParseSignature(field, "sig"); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v, want ErrMalformed", field, err)
		}
	}
}

func TestBaseNamesTheUnknownComponent(t *testing.T) {
	input, err := ParseInput(`sig=("@nothing");created=1`, "sig")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Base(input, rfcResolve); !errors.Is(err, ErrComponent) {
		t.Fatalf("an unknown component: %v", err)
	}
}

func TestContentDigest(t *testing.T) {
	want := "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"

	if got := ContentDigest(nil); got != want {
		t.Fatalf("digest of nothing: %s, want %s", got, want)
	}
}
