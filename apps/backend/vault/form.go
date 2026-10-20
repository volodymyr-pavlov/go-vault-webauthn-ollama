package vault

import (
	"strconv"
	"strings"
)

// prefix starts every ciphertext, hash and signature of Transit.
const prefix = "vault:v"

// Split splits a value in the "vault:vN:payload" form into its version and payload. N is a decimal number from 1 up,
// without a sign or a leading zero, as Transit writes it.
//
// It returns [ErrCiphertextForm] if the value is not in that form.
func Split(value string) (version int, payload string, err error) {
	rest, found := strings.CutPrefix(value, prefix)
	if !found {
		return 0, "", ErrCiphertextForm
	}

	versionText, payload, found := strings.Cut(rest, ":")
	if !found || payload == "" || versionText == "" || versionText[0] == '0' {
		return 0, "", ErrCiphertextForm
	}

	for _, r := range versionText {
		if r < '0' || r > '9' {
			return 0, "", ErrCiphertextForm
		}
	}

	version, err = strconv.Atoi(versionText)
	if err != nil || version < 1 {
		return 0, "", ErrCiphertextForm
	}

	return version, payload, nil
}
