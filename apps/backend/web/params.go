package web

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Params holds the values that explain an [Error], by name.
type Params map[string]any

// String returns the params as key=value pairs, sorted by key and separated by spaces.
func (p Params) String() string {
	var out strings.Builder
	for i, key := range slices.Sorted(maps.Keys(p)) {
		if i > 0 {
			out.WriteByte(' ')
		}

		fmt.Fprintf(&out, "%s=%v", key, p[key])
	}

	return out.String()
}
