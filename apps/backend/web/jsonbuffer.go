package web

import (
	"encoding/json"

	"github.com/valyala/bytebufferpool"
)

// EncodeJSON encodes v as JSON, without a trailing newline, into a buffer from the pool. The caller returns the buffer
// with [bytebufferpool.Put] after it has used the bytes.
//
// If EncodeJSON returns an error, the buffer is already returned.
func EncodeJSON(v any) (*bytebufferpool.ByteBuffer, error) {
	bp := bytebufferpool.Get()

	if err := json.NewEncoder(bp).Encode(v); err != nil {
		bytebufferpool.Put(bp)
		return nil, err
	}

	bp.B = bp.B[:len(bp.B)-1] // the encoder ends the value with a newline
	return bp, nil
}
