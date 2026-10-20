package es

import "testing"

func TestTransportsRoundTripThroughTheirNames(t *testing.T) {
	set := ParseTransports([]string{"usb", "internal", "made-up", "usb"})

	if got := set.Names(); len(got) != 2 || got[0] != "usb" || got[1] != "internal" {
		t.Fatalf("names %v, want [usb internal]", got)
	}

	if set != TransportUSB|TransportInternal {
		t.Fatalf("set %b", set)
	}

	if names := Transports(0).Names(); names == nil || len(names) != 0 {
		t.Fatalf("an empty set must give an empty list, got %#v", names)
	}
}

func TestFactorsShowTheirNames(t *testing.T) {
	if got := (FactorPassword | FactorTOTP).String(); got != "password+totp" {
		t.Fatalf("got %q", got)
	}

	if !FactorPasskey.Single() || (FactorPassword | FactorTOTP).Single() || Factors(0).Single() {
		t.Fatal("Single must be true for exactly one factor")
	}

	text, err := FactorPasskey.MarshalText()
	if err != nil || string(text) != "passkey" {
		t.Fatalf("text %q %v", text, err)
	}
}
