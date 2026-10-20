package es

import "time"

// RateLimit is one request against the budget of a key. A [Writer] with [WriteCreate] takes one slot of the budget of
// Key and returns the item with Wait set.
type RateLimit struct {
	// Key names the budget, for example the keyed hash of a user.
	Key string

	// Wait is how long the caller must wait before it runs the request. It is zero if the request may run now. The
	// writer sets it.
	Wait time.Duration
}
