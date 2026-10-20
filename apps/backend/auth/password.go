package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// DefaultMemory, DefaultTime and DefaultThreads are the Argon2id parameters of a new hash: 64 MiB of memory,
	// 3 passes and 4 lanes. DefaultMemory is in KiB. They are the second recommended choice of RFC 9106. [Hasher] uses
	// each one when the matching field of [HasherOptions] is zero.
	DefaultMemory  = 64 << 10
	DefaultTime    = 3
	DefaultThreads = 4

	// saltLength and keyLength are the sizes of the salt and of the derived key, in bytes.
	saltLength = 16
	keyLength  = 32

	// MaxLength is the longest password that [Hasher] accepts, in bytes. Argon2 takes any length. The limit stops a
	// client from making the server hash a huge input.
	MaxLength = 1024
)

// HasherOptions holds the Argon2id parameters of a new hash. A zero field means its default.
type HasherOptions struct {
	// Memory is the memory cost, in KiB.
	Memory uint32

	// Time is the number of passes over the memory.
	Time uint32

	// Threads is the number of parallel lanes.
	Threads uint8
}

// Hasher makes and checks password hashes. The zero value is ready to use.
type Hasher struct {
	// HasherOptions are the parameters of the hashes that [Hasher.Hash] makes. [Hasher.Verify] ignores them and reads
	// the parameters from the hash.
	HasherOptions HasherOptions
}

// Hash returns the Argon2id hash of password as a PHC string. The hash uses the parameters of the hasher and a new
// random salt. The string carries both, so [Hasher.Verify] needs nothing else.
//
// It returns [ErrTooLong] if password is longer than [MaxLength].
func (h *Hasher) Hash(password string) (string, error) {
	if len(password) > MaxLength {
		return "", ErrTooLong
	}

	opts := h.HasherOptions
	if opts.Memory == 0 {
		opts.Memory = DefaultMemory
	}

	if opts.Time == 0 {
		opts.Time = DefaultTime
	}

	if opts.Threads == 0 {
		opts.Threads = DefaultThreads
	}

	salt := make([]byte, saltLength)

	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("make the salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, opts.Time, opts.Memory, opts.Threads, keyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, opts.Memory, opts.Time, opts.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks whether password is the one that hash was made from. It compares the hashes in constant time.
//
// It returns [ErrMismatch] for a wrong password, including one that is longer than [MaxLength]. It returns
// [ErrHashFormat] if hash is not an Argon2id hash in the PHC string format.
func (h *Hasher) Verify(hash, password string) error {
	if len(password) > MaxLength {
		return ErrMismatch
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return ErrHashFormat
	}

	var version int

	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return ErrHashFormat
	}

	var opts HasherOptions

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &opts.Memory, &opts.Time, &opts.Threads); err != nil {
		return ErrHashFormat
	}

	if opts.Memory == 0 || opts.Time == 0 || opts.Threads == 0 {
		return ErrHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrHashFormat
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != keyLength {
		return ErrHashFormat
	}

	got := argon2.IDKey([]byte(password), salt, opts.Time, opts.Memory, opts.Threads, keyLength)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}

	return nil
}
