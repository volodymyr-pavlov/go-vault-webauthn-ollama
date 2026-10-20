package es

import "errors"

// ErrNoArguments reports that the request has no identifier or filter that the store can search or write by. An
// example is a ReadOne call with neither an ID nor an email.
var ErrNoArguments = errors.New("es: missing arguments")

// ErrNoCreatedRows reports that an insert ran but the database added no row. The record is not saved.
var ErrNoCreatedRows = errors.New("es: no created new rows")

// ErrNoUpdatedRows reports that an update matched no row. The record is missing or not in the state that the update
// requires, for example when a single-use record is already used or another request changed it first.
var ErrNoUpdatedRows = errors.New("es: no updated rows")

// ErrNotFound reports that no record matches the request.
var ErrNotFound = errors.New("es: record not found")

// ErrDuplicate reports that the record already exists because a unique key is taken.
var ErrDuplicate = errors.New("es: duplicated record")

// ErrNoMethod reports that the store does not offer the method. An example is CreateOneTx on a store of records that
// the application never creates.
var ErrNoMethod = errors.New("es: the store does not offer this method")

// ErrLastFactor reports that a removal would leave the account without a way to log in: the factor is the last one.
var ErrLastFactor = errors.New("es: the factor is the last one of the account")

// ErrNoTOTPSecret reports that the account has no TOTP secret to remove.
var ErrNoTOTPSecret = errors.New("es: the account has no TOTP secret")
