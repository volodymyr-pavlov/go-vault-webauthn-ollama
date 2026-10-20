// Package clock provides the current time through an interface, so that a test can control the time.
package clock

import "time"

// Clock reports the current time.
type Clock interface {
	Now() time.Time
}

var _ Clock = SystemClock{}
var _ Clock = &FixedClock{}

// SystemClock is a [Clock] that reports the system time.
type SystemClock struct{}

// Now returns [time.Now].
func (SystemClock) Now() time.Time {
	return time.Now()
}

// FixedClock is a [Clock] for tests. It reports the value of Time. Its zero value reports the zero time.
type FixedClock struct {
	Time time.Time
}

// Now returns the value of Time.
func (c *FixedClock) Now() time.Time {
	return c.Time
}

// Advance moves Time forward by d.
func (c *FixedClock) Advance(d time.Duration) {
	c.Time = c.Time.Add(d)
}
