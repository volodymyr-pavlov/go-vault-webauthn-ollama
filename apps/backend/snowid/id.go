// Package snowid issues the external identifiers of the records. An identifier is a time-ordered 64-bit number in the
// snowflake layout. From the high bits to the low bits, it holds 41 bits of milliseconds since [Epoch], 6 bits of
// instance, 4 bits of kind and 12 bits of sequence.
//
// Each kind of record has a [Snowflake] with its own kind, so identifiers of two kinds never collide. Each running
// instance of the service has its own instance number, so identifiers of two instances never collide either.
//
// The identifiers are separate from the internal database keys of the rows.
package snowid

import (
	"sync/atomic"
	"time"
)

const (
	// Epoch is the zero point of the time bits, 2026-01-01T00:00:00Z, in Unix milliseconds.
	Epoch = 1767225600000

	kindBits       = 4
	instanceBits   = 6
	sequenceBits   = 12
	maxKind        = (1 << kindBits) - 1
	maxInstance    = (1 << instanceBits) - 1
	maxSequence    = (1 << sequenceBits) - 1
	kindShift      = sequenceBits
	instanceShift  = sequenceBits + kindBits
	timestampShift = sequenceBits + kindBits + instanceBits
)

// Snowflake issues the identifiers of one kind of record on one instance. It is safe for concurrent use and takes no
// lock.
type Snowflake struct {
	kind     uint16
	instance uint16

	// last holds the last slot that Next issued. The high bits are the millisecond. The low [sequenceBits] bits are the
	// sequence.
	last atomic.Uint64
}

// NewSnowflake returns the issuer for a kind, from 0 to 15, on an instance, from 0 to 63. It panics if a number is
// larger, because that is an error in the setup code.
func NewSnowflake(kind, instance uint) *Snowflake {
	if kind > maxKind {
		panic("snowid: the kind exceeds 4 bits (15)")
	}

	if instance > maxInstance {
		panic("snowid: the instance exceeds 6 bits (63)")
	}

	return &Snowflake{
		kind:     uint16(kind),
		instance: uint16(instance),
	}
}

// Next returns the next identifier. It never returns a value twice, and each value is larger than the one before. This
// holds if the clock moves back. It also holds if the caller asks for more than 4096 identifiers in one millisecond.
// The extra identifiers use the following milliseconds.
func (s *Snowflake) Next() uint64 {
	slot := millis() << sequenceBits
	for {
		last := s.last.Load()

		next := max(slot, last+1)
		if s.last.CompareAndSwap(last, next) {
			return next>>sequenceBits<<timestampShift | uint64(s.instance)<<instanceShift | uint64(s.kind)<<kindShift | next&maxSequence
		}
	}
}

// millis returns the milliseconds since [Epoch]. It returns zero if the clock is before [Epoch].
func millis() uint64 {
	ms := time.Now().UnixMilli() - Epoch
	if ms < 0 {
		return 0
	}

	return uint64(ms)
}

// Parse splits an identifier into its time in Unix milliseconds, its kind, its instance and its sequence number.
func Parse(id uint64) (timestampMs int64, kind, instance, seq uint64) {
	seq = id & maxSequence
	kind = (id >> kindShift) & maxKind
	instance = (id >> instanceShift) & maxInstance
	timestampMs = int64(id>>timestampShift) + Epoch
	return timestampMs, kind, instance, seq
}
