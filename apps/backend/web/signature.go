package web

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Input is one signature of a Signature-Input field: the covered components and the parameters.
type Input struct {
	// Components are the names of the covered components in order, such as "@method" or "content-digest".
	Components []string

	// Created, KeyID, Alg, Nonce and Tag are the values of the parameters created, keyid, alg, nonce and tag. A missing
	// parameter leaves Created at zero and the others empty.
	Created int64
	KeyID   string
	Alg     string
	Nonce   string
	Tag     string

	// Params lists the names of all the parameters of the signature in order. A caller that accepts only some
	// parameters can compare it with what it expects.
	Params []string

	// Raw is the serialization of the inner list and the parameters, as the field carries it. It is the value of the
	// "@signature-params" line of the signature base.
	Raw string
}

// ParseInput reads the signature with the given label from a Signature-Input field. It skips other labels in the field.
//
// It returns [ErrNoLabel] if the field has no such label. It returns [ErrMalformed] if the value of the label is not in
// the form of RFC 9421.
func ParseInput(field, label string) (Input, error) {
	for _, member := range split(field) {
		name, value, found := strings.Cut(strings.TrimSpace(member), "=")
		if !found || name != label {
			continue
		}

		return parseMember(value)
	}

	return Input{}, ErrNoLabel
}

// ParseSignature reads the bytes of the signature with the given label from a Signature field.
//
// It returns [ErrNoLabel] if the field has no such label. It returns [ErrMalformed] if the value is not a byte
// sequence.
func ParseSignature(field, label string) ([]byte, error) {
	for _, member := range split(field) {
		name, value, found := strings.Cut(strings.TrimSpace(member), "=")
		if !found || name != label {
			continue
		}

		if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
			return nil, ErrMalformed
		}

		raw, err := base64.StdEncoding.DecodeString(value[1 : len(value)-1])
		if err != nil {
			return nil, ErrMalformed
		}

		return raw, nil
	}

	return nil, ErrNoLabel
}

// Base returns the signature base of RFC 9421, section 2.5: a line for each covered component of input, then the line
// of the signature parameters. The function resolve returns the value of a component.
//
// If resolve fails, Base returns an error that wraps the error of resolve and names the component. By convention,
// resolve returns [ErrComponent] for a name it does not know.
func Base(input Input, resolve func(component string) (string, error)) (string, error) {
	var base strings.Builder
	for _, component := range input.Components {
		value, err := resolve(component)
		if err != nil {
			return "", fmt.Errorf("%s: %w", component, err)
		}

		fmt.Fprintf(&base, "%q: %s\n", component, value)
	}

	base.WriteString(`"@signature-params": `)
	base.WriteString(input.Raw)

	return base.String(), nil
}

// ContentDigest returns the value of a Content-Digest field (RFC 9530) that holds the SHA-256 digest of body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)

	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// split cuts a field into its members at the commas that are outside a string, a byte sequence and an inner list.
func split(field string) []string {
	var (
		members []string
		start   int
		depth   int
		quoted  bool
		bytes   bool
	)

	for i := 0; i < len(field); i++ {
		switch c := field[i]; {
		case quoted:
			switch c {
			case '\\':
				i++
			case '"':
				quoted = false
			}
		case bytes:
			if c == ':' {
				bytes = false
			}
		case c == '"':
			quoted = true
		case c == ':':
			bytes = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			members = append(members, field[start:i])
			start = i + 1
		}
	}

	return append(members, field[start:])
}

// parseMember reads an inner list of strings, followed by parameters, as the value of one signature.
func parseMember(value string) (Input, error) {
	input := Input{
		Raw: value,
	}

	if !strings.HasPrefix(value, "(") {
		return Input{}, ErrMalformed
	}

	end := strings.IndexByte(value, ')')
	if end < 0 {
		return Input{}, ErrMalformed
	}

	list := value[1:end]
	for list != "" {
		name, rest, ok := readString(list)
		if !ok {
			return Input{}, ErrMalformed
		}

		input.Components = append(input.Components, name)
		list = strings.TrimPrefix(rest, " ")
		if rest != "" && list == rest {
			return Input{}, ErrMalformed
		}
	}

	params := value[end+1:]
	for params != "" {
		if params[0] != ';' {
			return Input{}, ErrMalformed
		}

		key, rest, found := strings.Cut(params[1:], "=")
		if !found || key == "" {
			return Input{}, ErrMalformed
		}

		var text string
		switch {
		case strings.HasPrefix(rest, `"`):
			parsed, tail, ok := readString(rest)
			if !ok {
				return Input{}, ErrMalformed
			}

			text, params = parsed, tail
		default:
			next := strings.IndexByte(rest, ';')
			if next < 0 {
				next = len(rest)
			}

			text, params = rest[:next], rest[next:]
			if strings.HasPrefix(text, ":") {
				return Input{}, ErrMalformed
			}
		}

		input.Params = append(input.Params, key)

		switch key {
		case "created":
			created, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return Input{}, ErrMalformed
			}

			input.Created = created
		case "keyid":
			input.KeyID = text
		case "alg":
			input.Alg = text
		case "nonce":
			input.Nonce = text
		case "tag":
			input.Tag = text
		}
	}

	return input, nil
}

// readString reads a quoted string at the start of text. It returns the string, the text after it, and whether the
// string was valid.
func readString(text string) (string, string, bool) {
	if len(text) < 2 || text[0] != '"' {
		return "", "", false
	}

	var out strings.Builder
	for i := 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++

			if i >= len(text) || (text[i] != '"' && text[i] != '\\') {
				return "", "", false
			}

			out.WriteByte(text[i])
		case '"':
			return out.String(), text[i+1:], true
		default:
			out.WriteByte(text[i])
		}
	}

	return "", "", false
}
