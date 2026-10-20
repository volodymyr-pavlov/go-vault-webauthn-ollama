package geo

import "errors"

// ErrTable means that a line of the geo table does not have four fields. [New] wraps it with the line number.
var ErrTable = errors.New("a line of the geo table must have a prefix, a country, a latitude and a longitude")

// ErrRanges means that a line of a file of address ranges is not an address prefix, or that the file is too large.
// [ReadRanges] wraps it with the line number.
var ErrRanges = errors.New("a line of the ranges file must be an address prefix such as 192.0.2.0/24")
