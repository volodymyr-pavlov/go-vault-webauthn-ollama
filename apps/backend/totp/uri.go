package totp

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MinImportSecretLength is the shortest secret that [ParseURI] and [ParseSecret] accept, in bytes. It is 80 bits,
	// which is what Google Authenticator accepts.
	MinImportSecretLength = 10

	// MaxImportSecretLength is the longest secret that they accept, in bytes.
	MaxImportSecretLength = 128

	// MinImportPeriod and MaxImportPeriod are the shortest and the longest step that they accept, in seconds.
	MinImportPeriod = 15
	MaxImportPeriod = 300

	// MaxURILength is the longest URI that [ParseURI] reads. A migration link with many accounts is long, so the limit
	// is generous.
	MaxURILength = 16 << 10

	// MaxImportAccounts is the most accounts that one URI may hold.
	MaxImportAccounts = 50

	// maxTextLength is the longest issuer or label that [ParseURI] keeps, in bytes.
	maxTextLength = 128
)

// Account is one TOTP account that a user imports into an authenticator: the secret and the parameters of its codes.
type Account struct {
	// Secret is the shared secret. It is the only sensitive field.
	Secret []byte

	// Issuer is the service that the account belongs to, such as "GitHub". Label is the name of the account at the
	// issuer, such as an email.
	Issuer string
	Label  string

	// Algorithm is "SHA1", "SHA256" or "SHA512". Digits is 6 or 8. Period is the length of a step in seconds.
	Algorithm string
	Digits    uint8
	Period    uint32
}

// ParseSecret returns the account of a secret that a person typed, in Base32, with the issuer and the label given
// separately. Spaces and hyphens in the secret are ignored and case does not matter, as in authenticator apps. The
// parameters are the defaults: SHA-1, six digits and 30 seconds.
//
// It returns [ErrImport] if the secret is not Base32 or has a length that is out of range.
func ParseSecret(secret, issuer, label string) (Account, error) {
	decoded, err := decodeBase32(secret)
	if err != nil {
		return Account{}, err
	}

	account := Account{
		Secret:    decoded,
		Issuer:    cutText(issuer),
		Label:     cutText(label),
		Algorithm: "SHA1",
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
	}

	return account, account.check()
}

// ParseURI reads the accounts in a link of an authenticator. It accepts two forms. An "otpauth://totp/..." link holds
// one account. An "otpauth-migration://offline?data=..." link is the export of Google Authenticator, and it holds
// several. The second return value is the number of entries it skipped because they are not time-based, which are
// counter-based (HOTP) accounts.
//
// It returns [ErrImport] if the link is malformed, has no account, has more than [MaxImportAccounts], or holds a value
// that is out of range.
func ParseURI(link string) ([]Account, int, error) {
	if len(link) > MaxURILength {
		return nil, 0, fmt.Errorf("%w: the link is too long", ErrImport)
	}

	link = strings.TrimSpace(link)

	parsed, err := url.Parse(link)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrImport, err)
	}

	switch parsed.Scheme {
	case "otpauth":
		account, err := parseOTPAuth(parsed)
		if err != nil {
			return nil, 0, err
		}

		return []Account{account}, 0, nil
	case "otpauth-migration":
		return parseMigration(parsed)
	}

	return nil, 0, fmt.Errorf("%w: the link must start with otpauth:// or otpauth-migration://", ErrImport)
}

// parseOTPAuth reads an otpauth://totp/Issuer:label?secret=... link.
func parseOTPAuth(link *url.URL) (Account, error) {
	if link.Host != "totp" {
		return Account{}, fmt.Errorf("%w: only time-based accounts (totp) can be imported", ErrImport)
	}

	query := link.Query()

	decoded, err := decodeBase32(query.Get("secret"))
	if err != nil {
		return Account{}, err
	}

	label := strings.TrimPrefix(link.Path, "/")
	issuer := query.Get("issuer")

	if before, after, found := strings.Cut(label, ":"); found {
		if issuer == "" {
			issuer = before
		}

		label = strings.TrimSpace(after)
	}

	account := Account{
		Secret:    decoded,
		Issuer:    cutText(issuer),
		Label:     cutText(label),
		Algorithm: strings.ToUpper(query.Get("algorithm")),
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
	}

	if account.Algorithm == "" {
		account.Algorithm = "SHA1"
	}

	if value := query.Get("digits"); value != "" {
		digits, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return Account{}, fmt.Errorf("%w: the digits are not a number", ErrImport)
		}

		account.Digits = uint8(digits)
	}

	if value := query.Get("period"); value != "" {
		period, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return Account{}, fmt.Errorf("%w: the period is not a number", ErrImport)
		}

		account.Period = uint32(period)
	}

	return account, account.check()
}

// parseMigration reads the export of Google Authenticator. The data is a protobuf message in Base64: the field 1
// repeats, one entry for each account, and an entry holds the secret (1), the name (2), the issuer (3), the algorithm
// (4), the number of digits (5) and the type (6).
func parseMigration(link *url.URL) ([]Account, int, error) {
	data := link.Query().Get("data")
	if data == "" {
		return nil, 0, fmt.Errorf("%w: the migration link has no data", ErrImport)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(data, " ", "+"))
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(data, "="))
		if err != nil {
			return nil, 0, fmt.Errorf("%w: the data is not Base64", ErrImport)
		}
	}

	var accounts []Account
	skipped := 0

	for len(raw) > 0 {
		field, wire, rest, err := readTag(raw)
		if err != nil {
			return nil, 0, err
		}

		raw = rest

		if field != 1 || wire != wireBytes {
			raw, err = skipValue(raw, wire)
			if err != nil {
				return nil, 0, err
			}

			continue
		}

		item, rest, err := readBytes(raw)
		if err != nil {
			return nil, 0, err
		}

		raw = rest

		account, isTOTP, err := parseEntry(item)
		if err != nil {
			return nil, 0, err
		}

		if !isTOTP {
			skipped++

			continue
		}

		if len(accounts) == MaxImportAccounts {
			return nil, 0, fmt.Errorf("%w: more than %d accounts", ErrImport, MaxImportAccounts)
		}

		accounts = append(accounts, account)
	}

	if len(accounts) == 0 {
		return nil, 0, fmt.Errorf("%w: the link holds no time-based account", ErrImport)
	}

	return accounts, skipped, nil
}

// parseEntry reads one account of the migration message. isTOTP is false for an entry of another type.
func parseEntry(item []byte) (account Account, isTOTP bool, err error) {
	account = Account{
		Algorithm: "SHA1",
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
	}

	// The type is 0 when the field is missing. Google writes it for every entry, and 2 is TOTP. An entry without a type
	// counts as time-based, because that is what the apps export.
	kind := uint64(2)

	for len(item) > 0 {
		field, wire, rest, err := readTag(item)
		if err != nil {
			return Account{}, false, err
		}

		item = rest

		switch {
		case field == 1 && wire == wireBytes:
			account.Secret, item, err = readBytes(item)
		case field == 2 && wire == wireBytes:
			var name []byte
			name, item, err = readBytes(item)
			account.Label = cutText(string(name))
		case field == 3 && wire == wireBytes:
			var issuer []byte
			issuer, item, err = readBytes(item)
			account.Issuer = cutText(string(issuer))
		case field == 4 && wire == wireVarint:
			var value uint64
			value, item, err = readVarint(item)
			switch value {
			case 0, 1:
				account.Algorithm = "SHA1"
			case 2:
				account.Algorithm = "SHA256"
			case 3:
				account.Algorithm = "SHA512"
			default:
				err = fmt.Errorf("%w: the algorithm %d is not supported", ErrImport, value)
			}
		case field == 5 && wire == wireVarint:
			var value uint64
			value, item, err = readVarint(item)
			switch value {
			case 0, 1:
				account.Digits = 6
			case 2:
				account.Digits = 8
			default:
				err = fmt.Errorf("%w: the digit count %d is not supported", ErrImport, value)
			}
		case field == 6 && wire == wireVarint:
			kind, item, err = readVarint(item)
		default:
			item, err = skipValue(item, wire)
		}

		if err != nil {
			return Account{}, false, err
		}
	}

	if kind != 2 {
		return Account{}, false, nil
	}

	// The name of an entry may be "Issuer:label".
	if before, after, found := strings.Cut(account.Label, ":"); found {
		if account.Issuer == "" {
			account.Issuer = before
		}

		account.Label = strings.TrimSpace(after)
	}

	return account, true, account.check()
}

// check validates the secret and the parameters of the account.
func (a Account) check() error {
	if len(a.Secret) < MinImportSecretLength || len(a.Secret) > MaxImportSecretLength {
		return fmt.Errorf("%w: the secret must have %d to %d bytes", ErrImport, MinImportSecretLength, MaxImportSecretLength)
	}

	switch a.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return fmt.Errorf("%w: the algorithm %q is not supported", ErrImport, a.Algorithm)
	}

	if a.Digits != 6 && a.Digits != 8 {
		return fmt.Errorf("%w: the digits must be 6 or 8", ErrImport)
	}

	if a.Period < MinImportPeriod || a.Period > MaxImportPeriod {
		return fmt.Errorf("%w: the period must be %d to %d seconds", ErrImport, MinImportPeriod, MaxImportPeriod)
	}

	return nil
}

// decodeBase32 decodes a secret that a person or a link gives. It ignores case, spaces, hyphens and padding.
func decodeBase32(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	if cleaned == "" {
		return nil, fmt.Errorf("%w: the secret is empty", ErrImport)
	}

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: the secret is not Base32", ErrImport)
	}

	return decoded, nil
}

// cutText returns text without control characters, cut to at most maxTextLength bytes without a broken character.
func cutText(text string) string {
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}

		return r
	}, text)

	text = strings.TrimSpace(text)
	if len(text) <= maxTextLength {
		return text
	}

	cut := text[:maxTextLength]
	for !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}

	return cut
}

// The wire types of protobuf that the migration message uses.
const (
	wireVarint  = 0
	wire64      = 1
	wireBytes   = 2
	wire32      = 5
	maxVarintLn = 10
)

// readVarint reads a varint from the start of data.
func readVarint(data []byte) (value uint64, rest []byte, err error) {
	for i := 0; i < len(data) && i < maxVarintLn; i++ {
		value |= uint64(data[i]&0x7f) << (7 * uint(i))

		if data[i] < 0x80 {
			return value, data[i+1:], nil
		}
	}

	return 0, nil, fmt.Errorf("%w: the migration data is damaged: %w", ErrImport, errTruncated)
}

// readTag reads the field number and the wire type of the next field.
func readTag(data []byte) (field uint64, wire uint64, rest []byte, err error) {
	tag, rest, err := readVarint(data)
	if err != nil {
		return 0, 0, nil, err
	}

	return tag >> 3, tag & 7, rest, nil
}

// readBytes reads a length-prefixed field.
func readBytes(data []byte) (value []byte, rest []byte, err error) {
	length, rest, err := readVarint(data)
	if err != nil {
		return nil, nil, err
	}

	if length > uint64(len(rest)) {
		return nil, nil, fmt.Errorf("%w: the migration data is damaged: %w", ErrImport, errTruncated)
	}

	return rest[:length], rest[length:], nil
}

// skipValue skips a field of an unknown number.
func skipValue(data []byte, wire uint64) ([]byte, error) {
	switch wire {
	case wireVarint:
		_, rest, err := readVarint(data)

		return rest, err
	case wireBytes:
		_, rest, err := readBytes(data)

		return rest, err
	case wire64:
		if len(data) < 8 {
			return nil, fmt.Errorf("%w: the migration data is damaged: %w", ErrImport, errTruncated)
		}

		return data[8:], nil
	case wire32:
		if len(data) < 4 {
			return nil, fmt.Errorf("%w: the migration data is damaged: %w", ErrImport, errTruncated)
		}

		return data[4:], nil
	}

	return nil, fmt.Errorf("%w: the migration data has an unknown field type", ErrImport)
}
