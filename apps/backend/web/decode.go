package web

import (
	"bytes"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
)

// JSONDecoder fills itself from a parsed JSON value. A request type implements it with a switch over the names of its
// members. The switch returns [ErrUnknownBody] for a name it does not know, so a body with an extra field is refused.
type JSONDecoder interface {
	DecodeJSON(gjson.Result) error
}

// Unmarshal decodes the body of the request into args.
//
// It returns [ErrNoBody] if the body is empty and [ErrMalformedBody] if it is not valid JSON. It returns the errors of
// args.DecodeJSON as they are.
func Unmarshal(ctx *fasthttp.RequestCtx, args JSONDecoder) error {
	body := ctx.PostBody()
	if len(bytes.TrimSpace(body)) == 0 {
		return ErrNoBody
	}

	if !gjson.ValidBytes(body) {
		return ErrMalformedBody.Wrap(fmt.Errorf("decode the body: %w", ErrInvalidJSON))
	}

	return args.DecodeJSON(gjson.ParseBytes(body))
}

// VisitObject calls visit for each member of the JSON object value and stops at the first error. It skips a member
// whose value is null.
//
// It returns [ErrMalformedBody] if value is not an object. It returns the first error of visit as it is.
func VisitObject(value gjson.Result, visit func(key string, member gjson.Result) error) error {
	if !value.IsObject() {
		return malformed("an object", ErrWrongType)
	}

	var visitErr error
	value.ForEach(func(key, member gjson.Result) bool {
		if member.Type == gjson.Null {
			return true
		}

		visitErr = visit(key.String(), member)
		return visitErr == nil
	})
	return visitErr
}

// JSONString returns the string that value holds.
//
// It returns [ErrMalformedBody] if value is not a JSON string.
func JSONString(value gjson.Result) (string, error) {
	if value.Type != gjson.String {
		return "", malformed("a string", ErrWrongType)
	}

	return value.String(), nil
}

// JSONRaw returns the JSON text of value in a new slice. It is for a value that another parser reads, such as a
// WebAuthn response.
func JSONRaw(value gjson.Result) []byte {
	return []byte(value.Raw)
}

// malformed returns [ErrMalformedBody] with a cause that names the expected type.
func malformed(expected string, cause error) error {
	return ErrMalformedBody.Wrap(fmt.Errorf("the json value is not %s: %w", expected, cause))
}
