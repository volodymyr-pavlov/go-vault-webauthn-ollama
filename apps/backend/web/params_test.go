package web

import (
	"errors"
	"testing"

	"github.com/valyala/fasthttp"
)

var errNotFoundThing = &Error{
	Status:  fasthttp.StatusNotFound,
	Num:     900,
	Code:    "NOT_FOUND_THING",
	Message: "The thing is not found.",
}

func TestWithKeepsTheIdentityAndLeavesTheOriginalAlone(t *testing.T) {
	err := errNotFoundThing.With(Params{"id": 42})

	if err.Params["id"] != 42 || !errors.Is(err, errNotFoundThing) {
		t.Fatalf("got %v", err.Params)
	}

	if errNotFoundThing.Params != nil {
		t.Fatal("With changed the original")
	}
}

func TestWithReturnsTheErrorItselfWithoutParams(t *testing.T) {
	if errNotFoundThing.With(nil) != errNotFoundThing {
		t.Fatal("With made a copy for no params")
	}
}

func TestParamsStringIsSortedByKey(t *testing.T) {
	if got := (Params{
		"b": 2,
		"a": "x",
	}).String(); got != "a=x b=2" {
		t.Fatalf("got %q", got)
	}
}

func TestParamsStringOfNoParamsIsEmpty(t *testing.T) {
	if got := Params(nil).String(); got != "" {
		t.Fatalf("got %q", got)
	}
}
