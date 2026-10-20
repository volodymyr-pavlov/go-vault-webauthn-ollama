package main

import (
	"math"
	"testing"
)

func TestWilson(t *testing.T) {
	cases := []struct {
		successes, total int
		low, high        float64
	}{
		{0, 10, 0, 0.2775},
		{5, 10, 0.2366, 0.7634},
		{10, 10, 0.7225, 1},
		{50, 100, 0.4038, 0.5962},
	}
	for _, c := range cases {
		low, high := wilson(c.successes, c.total)
		if math.Abs(low-c.low) > 0.001 || math.Abs(high-c.high) > 0.001 {
			t.Errorf("wilson(%d, %d) = %.4f, %.4f, want %.4f, %.4f", c.successes, c.total, low, high, c.low, c.high)
		}
	}
}

func TestWilsonNoTrials(t *testing.T) {
	if low, high := wilson(0, 0); low != 0 || high != 1 {
		t.Errorf("wilson(0, 0) = %v, %v, want 0, 1", low, high)
	}
}

func TestShare(t *testing.T) {
	if got, want := share(5, 10), "0.500 (0.237-0.763)"; got != want {
		t.Errorf("share(5, 10) = %q, want %q", got, want)
	}

	if got := share(0, 0); got != "n/a" {
		t.Errorf("share(0, 0) = %q, want n/a", got)
	}
}
