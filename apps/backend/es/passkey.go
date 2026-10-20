package es

import "time"

// Passkey is one WebAuthn credential of a user.
//
// A [Reader] identifies a passkey by ID, PasskeyXID or CredentialID, in that order. A [BatchReader] lists the passkeys
// of a UserID in the order of registration. A [Writer] update identifies a passkey by ID and writes the fields that
// are set.
type Passkey struct {
	// ID is the internal key of the row.
	ID uint64

	// PasskeyXID is the external identifier of the passkey. The API carries it. It comes from the snowflake of
	// passkeys.
	PasskeyXID uint64

	// Flags holds the state of the credential. See [PasskeyFlag].
	Flags PasskeyFlag

	// UserID is the ID of the user that owns the passkey.
	UserID uint64

	// CredentialID is the credential ID that the authenticator chose. It has up to 1023 bytes. The browser sends it
	// at login.
	CredentialID []byte

	// PublicKey is the public key of the credential in COSE encoding.
	PublicKey []byte

	// AttestationType and AttestationFormat are the values that the authenticator reported at registration.
	AttestationType   string
	AttestationFormat string

	// Transports are the ways to reach the authenticator, as reported at registration.
	Transports Transports

	// AAGUID identifies the model of the authenticator. It is empty if the authenticator does not report it.
	AAGUID []byte

	// SignCount is the signature counter of the last accepted assertion.
	SignCount uint32

	// Name is the name that the user gave to the passkey.
	Name string

	// CreatedAt is the time when the passkey was stored.
	CreatedAt time.Time
}

// Present reports whether the passkey counts as a passkey of the user. It is true unless the passkey is removed. A
// disabled passkey is present but not usable.
func (p Passkey) Present() bool {
	return p.Flags&PasskeyFlagRemoved == 0
}

// Usable reports whether the passkey may authenticate the user. A removed or disabled passkey cannot.
func (p Passkey) Usable() bool {
	return p.Flags&(PasskeyFlagRemoved|PasskeyFlagDisabled) == 0
}

// Transports is a set of the ways to reach an authenticator, one bit for each. The names are the transports of the
// WebAuthn standard.
type Transports uint8

// The transports. A name that the standard adds later has no bit and is dropped by [ParseTransports].
const (
	TransportUSB Transports = 1 << iota
	TransportNFC
	TransportBLE
	TransportSmartCard
	TransportHybrid
	TransportInternal
)

// transportNames are the names of the transports in bit order.
var transportNames = [...]string{
	"usb",
	"nfc",
	"ble",
	"smart-card",
	"hybrid",
	"internal",
}

// ParseTransports returns the set of the named transports. It skips a name that is not one of the known transports.
func ParseTransports(names []string) Transports {
	var set Transports
	for _, name := range names {
		for bit, known := range transportNames {
			if known == name {
				set |= 1 << bit
			}
		}
	}

	return set
}

// Names returns the names of the transports in the set, in bit order. It returns an empty, non-nil slice for an empty
// set.
func (t Transports) Names() []string {
	names := []string{}
	for bit, name := range transportNames {
		if t&(1<<bit) != 0 {
			names = append(names, name)
		}
	}

	return names
}
