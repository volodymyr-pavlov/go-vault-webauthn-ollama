package web

import (
	"errors"
	"fmt"

	"github.com/valyala/fasthttp"
)

// Error is a refusal that the server sends. It is both a Go error and the JSON body of a response.
//
// Two errors are the same under [errors.Is] when their numbers are the same.
type Error struct {
	// Status is the HTTP status of the response.
	Status int `json:"status"`

	// Num identifies the error and never changes.
	Num uint16 `json:"num"`

	// Code is the same identity as Num, as a readable constant.
	Code string `json:"code"`

	// Message is the text for people.
	Message string `json:"message"`

	// Params holds the values that explain the refusal.
	Params Params `json:"params,omitempty"`

	// cause is the reason for the error. It stays in the log and is never sent.
	cause error
}

// Error returns the status, number, code, message, params and cause of e as one line for the log.
func (e *Error) Error() string {
	s := fmt.Sprintf("HTTP status [%d] num [%d] code [%s] - %s", e.Status, e.Num, e.Code, e.Message)
	if len(e.Params) != 0 {
		s += fmt.Sprintf(" params [%s]", e.Params)
	}

	if e.cause != nil {
		s += ": " + e.cause.Error()
	}

	return s
}

// Is reports whether target is an [Error] with the same number as e. A copy of an error that carries params or a cause
// still matches the original.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other.Num == e.Num
}

// Unwrap returns the cause of e, or nil if it has none.
func (e *Error) Unwrap() error {
	return e.cause
}

// With returns a copy of e that has params. It returns e itself if params is empty.
func (e *Error) With(params Params) *Error {
	if len(params) == 0 {
		return e
	}

	clone := *e
	clone.Params = params
	return &clone
}

// Wrap returns a copy of e that has cause. The [Mux] logs the cause.
func (e *Error) Wrap(cause error) *Error {
	clone := *e
	clone.cause = cause
	return &clone
}

// ErrInternalNum and the numbers after it identify the errors of this package. They start at 100.
const (
	ErrInternalNum uint16 = iota + 100
	ErrTooLargeBodyNum
	ErrNoBodyNum
	ErrMalformedBodyNum
	ErrUnknownBodyNum
)

// ErrInternal is the response to any failure that is not an [Error]. It hides the cause from the client.
var ErrInternal = &Error{
	Status:  fasthttp.StatusInternalServerError,
	Num:     ErrInternalNum,
	Code:    "INTERNAL",
	Message: "An unknown error occurred. Try again later.",
}

// ErrTooLargeBody is the response to a request whose body is larger than the server accepts.
var ErrTooLargeBody = &Error{
	Status:  fasthttp.StatusRequestEntityTooLarge,
	Num:     ErrTooLargeBodyNum,
	Code:    "TOO_LARGE_BODY",
	Message: "The request body is too large.",
}

// ErrNoBody is the response to a request whose body is empty.
var ErrNoBody = &Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyNum,
	Code:    "NO_BODY",
	Message: "The request body must not be empty.",
}

// ErrMalformedBody is the response to a body that is not valid JSON, or that has a value of the wrong type or range.
var ErrMalformedBody = &Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMalformedBodyNum,
	Code:    "MALFORMED_BODY",
	Message: "The request contains incorrect fields or values.",
}

// ErrUnknownBody is the response to a body that has a field the endpoint does not know.
var ErrUnknownBody = &Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrUnknownBodyNum,
	Code:    "UNKNOWN_BODY",
	Message: "The request contains unknown fields.",
}

// asError returns err as an [Error]. If err is not an [Error], it returns [ErrInternal] with err as the cause.
func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}

	return ErrInternal.Wrap(err)
}

// ErrInvalidJSON is the cause that [Unmarshal] gives [ErrMalformedBody] when the body is not valid JSON.
var ErrInvalidJSON = errors.New("web: the body is not valid JSON")

// ErrWrongType is the cause that the JSON readers give [ErrMalformedBody] when a value has another JSON type than the
// one expected.
var ErrWrongType = errors.New("web: the value has another type")

// ErrMalformed is returned by [ParseInput] and [ParseSignature] when a Signature-Input or Signature field is not in the
// form of RFC 9421.
var ErrMalformed = errors.New("web: the signature field is malformed")

// ErrNoLabel is returned by [ParseInput] and [ParseSignature] when the field has no signature with the label that was
// asked for.
var ErrNoLabel = errors.New("web: the field has no signature with this label")

// ErrComponent is the error that the function given to [Base] returns for a component it does not know.
var ErrComponent = errors.New("web: unknown component")
