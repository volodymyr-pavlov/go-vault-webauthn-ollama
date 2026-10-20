package geo

import "errors"

// ErrTable means that a line of the geo table does not have four fields. [New] wraps it with the line number.
var ErrTable = errors.New("a line of the geo table must have a prefix, a country, a latitude and a longitude")
