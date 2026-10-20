package es

import "time"

// MaxAccounts is the most accounts that one user may keep in the authenticator.
const MaxAccounts = 50

// Account is one TOTP account of another service, such as GitHub or a bank, that a user keeps in the authenticator of
// the service, as an app on a phone keeps it. The row holds only what is needed to show it. The secret lives in Vault, under the key named VaultKey, and it
// never reaches a store.
//
// A [Reader] identifies an account by AccountXID and UserID. A [BatchReader] lists the accounts of a UserID in
// the order they were added.
type Account struct {
	// ID is the internal key of the row.
	ID uint64

	// AccountXID is the external identifier of the account. The API carries it. It comes from the snowflake of
	// authenticator accounts.
	AccountXID uint64

	// Flags holds the state of the account. It has no bits yet.
	Flags AccountFlag

	// UserID is the ID of the user that owns the account.
	UserID uint64

	// VaultKey is the name of the key in the TOTP engine of Vault that holds the secret.
	VaultKey string

	// Issuer is the service that the account belongs to, and Label is the name of the account at that service.
	Issuer string
	Label  string

	// Algorithm is "SHA1", "SHA256" or "SHA512", Digits is 6 or 8, and Period is the length of a step in seconds.
	Algorithm string
	Digits    uint8
	Period    uint32

	// CreatedAt is the time when the user added the account.
	CreatedAt time.Time
}

// AuthenticatorKey is a key of the TOTP engine of Vault. A [Writer] with [WriteCreate] stores the secret under the Name.
// A [Writer] with [DeleteAuthenticatorKey] deletes the key. A [Reader] returns the Code of the key for the current time.
// Vault keeps the secret, and nothing reads it back.
type AuthenticatorKey struct {
	// Name is the name of the key in Vault.
	Name string

	// Secret is the secret in Base32. A store reads it only to create the key. It is empty in every item that a call
	// returns.
	Secret string

	// Issuer and Label name the account. Algorithm, Digits and Period are its parameters.
	Issuer    string
	Label     string
	Algorithm string
	Digits    uint8
	Period    uint32

	// Code is the current code, the output of a [Reader].
	Code string
}

// AccountGroup is the unit of work that is anchored at one user. A [Writer] changes the accounts of the user in
// one transaction.
//
// The [Op] of the write sets exactly one of the intents in [AccountIntents].
type AccountGroup struct {
	// User names the owner by ID.
	User User

	// Items are the accounts that [AddAccounts] stores. The writer returns the stored rows. For
	// [RemoveAccount], the first item names the account to remove, by AccountXID.
	Items []Account
}
