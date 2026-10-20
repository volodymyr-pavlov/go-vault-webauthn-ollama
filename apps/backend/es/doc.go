// Package es is the entity store of the service. It defines the record types, the flags that describe their state and
// the store interfaces that the mysql package implements.
//
// The package contains no database code and no business rules. Code that uses records depends on es and never on a
// concrete database.
//
// # Store interfaces
//
// A store reads or writes one kind of record. Small generic interfaces describe the stores, and a store implements
// only the ones it needs. In every interface, T is the record type and F is its flag type. The [Op] argument carries
// the options of a call.
//
//   - [Reader] finds one record.
//   - [Writer] creates or updates one record. The [WriteCreate] or [WriteUpdate] option selects which.
//   - [Replacer] swaps flag bits of one record, or of every record of one owner.
//   - [BatchReader] reads one page of records.
//   - [BatchWriter] creates many records at once.
//   - [Tx] finds, locks, creates and updates a record, and swaps its flag bits, inside a transaction that the caller
//     controls. Several [Tx] stores of different records share one transaction, so the records change together.
//   - [UpdateBuilder] builds the update statement that [Writer] and [Tx] run.
//
// A [Paginator] selects the page of a list.
//
// # The record is the query
//
// A call such as ReadOne(ctx, es.User{Email: "a@b"}, 0) means "find the user that looks like this". Each store
// documents which fields identify a record and in which order it tries them.
//
// A zero field means "not set". A search cannot ask for a zero value, and an update writes only the fields that are
// set, unless an option says otherwise.
//
// # Records
//
// A [User] is a user. A [RecoveryCode] is the keyed hash of one single-use code of a user. A [Passkey] is one
// WebAuthn credential of a user. A [Session] is the sign-in of one device, found by the ID of its key. It collects one
// flag for each step that passes and holds the state of the step in progress. The sessions of a user are also the
// login history that the risk engine reads.
//
// Some types are not rows. [Message], [Transit], [RateLimit], [HTTPRequest], [SignedRequest] and [RequestNonce] describe
// an action that a [Writer] or a [Reader] runs on another system, such as the mail server or Vault.
//
// # Flags
//
// A flag is one bit of the Flags field of a record. Together the bits give the state of the record. Each table has its
// own flag type, so a user flag cannot be mixed up with a session flag.
//
// A pending step works only once. The update that accepts the step also clears it. With [ConsumeChallenge], the update
// matches only a session that still holds a challenge, so a challenge is accepted once, however many callers present
// it.
//
// # Errors
//
// [ErrNoArguments], [ErrNoCreatedRows], [ErrNoUpdatedRows], [ErrNotFound], [ErrDuplicate] and [ErrNoMethod] report what happened to a
// request without exposing the database driver. Callers match them with [errors.Is].
package es
