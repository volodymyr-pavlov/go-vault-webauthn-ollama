package api

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// TestEventAttrsAreCanonicalAndNeverAmbiguous proves that the text of the attributes of an event is sorted by key and
// that two different lists never give the same text, even with values that hold the separators.
func TestEventAttrsAreCanonicalAndNeverAmbiguous(t *testing.T) {
	cases := []struct {
		attrs []slog.Attr
		want  string
	}{
		{nil, ""},
		{[]slog.Attr{slog.String("b", "2"), slog.String("a", "1")}, "a=1 b=2"},
		{[]slog.Attr{slog.Uint64("score", 40), slog.Bool("raised", false)}, "raised=false score=40"},
		{[]slog.Attr{slog.String("a", "x y")}, `a="x y"`},
		{[]slog.Attr{slog.String("a", "")}, `a=""`},
		{[]slog.Attr{slog.String("a", "1 b=2")}, `a="1 b=2"`},
	}
	for _, c := range cases {
		if got := eventAttrs(c.attrs); got != c.want {
			t.Errorf("eventAttrs(%v) = %q, want %q", c.attrs, got, c.want)
		}
	}

	// A value that looks like two pairs must not give the text of two pairs.
	one := eventAttrs([]slog.Attr{slog.String("a", "1 b=2")})

	two := eventAttrs([]slog.Attr{slog.String("a", "1"), slog.String("b", "2")})
	if one == two {
		t.Fatalf("one pair and two pairs gave the same text %q", one)
	}
}

// TestSetEventKeepsTheLastEventOfTheRequest proves that a request reports at most one event, the last one it set, and
// that a request with none reports an empty name.
func TestSetEventKeepsTheLastEventOfTheRequest(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}

	if name, attrs := requestEvent(ctx); name != "" || attrs != "" {
		t.Fatalf("a request with no event: %q %q", name, attrs)
	}

	SetEvent(ctx, es.EventLogin)
	SetEvent(ctx, es.EventLogout, slog.String("factor", "passkey"))

	if name, attrs := requestEvent(ctx); name != es.EventLogout || attrs != "factor=passkey" {
		t.Fatalf("got %q %q", name, attrs)
	}
}

// TestLogAddressClearsTheHostPart proves that a log line names a network and not a device: an IPv4 address keeps its
// first 24 bits, an IPv6 address its first 48 bits, an IPv4 address in IPv6 form is treated as IPv4, and an invalid
// address gives an empty text.
func TestLogAddressClearsTheHostPart(t *testing.T) {
	cases := map[string]string{
		"192.0.2.77":            "192.0.2.0/24",
		"2001:db8:abcd:1234::7": "2001:db8:abcd::/48",
		"::ffff:192.0.2.77":     "192.0.2.0/24",
	}

	for in, want := range cases {
		if got := logAddress(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s: want %s, got %s", in, want, got)
		}
	}

	if got := logAddress(netip.Addr{}); got != "" {
		t.Errorf("an invalid address: got %q", got)
	}
}
