package main

import (
	"fmt"
	"math"
)

// z95 is the point of the standard normal distribution that leaves 2.5 percent in each tail. It gives a two-sided 95
// percent interval.
const z95 = 1.959964

// wilson returns the 95 percent Wilson score interval of a share, where successes of total trials succeeded. The
// interval stays inside 0 and 1 and is not zero-width at 0 or at total, unlike the normal approximation. It returns the
// whole range from 0 to 1 if total is not positive.
func wilson(successes, total int) (low, high float64) {
	if total <= 0 {
		return 0, 1
	}

	n := float64(total)
	p := float64(successes) / n
	z2 := z95 * z95
	denominator := 1 + z2/n
	center := (p + z2/(2*n)) / denominator
	half := z95 * math.Sqrt(p*(1-p)/n+z2/(4*n*n)) / denominator

	return max(0, center-half), min(1, center+half)
}

// share formats successes of total as a share with its 95 percent Wilson interval, such as "0.855 (0.802-0.896)". It
// returns "n/a" if total is not positive.
func share(successes, total int) string {
	if total <= 0 {
		return "n/a"
	}

	low, high := wilson(successes, total)

	return fmt.Sprintf("%.3f (%.3f-%.3f)", float64(successes)/float64(total), low, high)
}
