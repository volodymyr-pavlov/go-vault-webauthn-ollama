package config

import "errors"

// ErrNoHTTPAddr means that the listen address of the HTTP server is empty. [Options.Validate] returns it, joined with
// the errors of the other broken rules.
var ErrNoHTTPAddr = errors.New("config: the address of the HTTP server is required")

// ErrNoMySQLDSN means that the data source name of the database is empty. [Options.Validate] returns it.
var ErrNoMySQLDSN = errors.New("config: the MySQL DSN is required")

// ErrNoRedisAddr means that the address of Redis is empty. [Options.Validate] returns it.
var ErrNoRedisAddr = errors.New("config: the Redis address is required")

// ErrNoRedisMaster means that Redis Sentinel addresses are set and the name of the master is empty. [Options.Validate]
// returns it.
var ErrNoRedisMaster = errors.New("config: the name of the Redis master is required with the sentinels")

// ErrNoVaultAddr means that the address of Vault is empty. [Options.Validate] returns it.
var ErrNoVaultAddr = errors.New("config: the Vault address is required")

// ErrNoVaultRoleID means that neither the AppRole role ID nor the file that holds it is set. [Options.Validate]
// returns it.
var ErrNoVaultRoleID = errors.New("config: the Vault role ID, or the file that holds it, is required")

// ErrNoVaultSecret means that neither the wrapped token file nor the secret ID is set. [Options.Validate] returns it.
var ErrNoVaultSecret = errors.New("config: the Vault wrapped token file or a secret ID is required")

// ErrNoSMTPAddr means that the address of the mail server is empty. [Options.Validate] returns it.
var ErrNoSMTPAddr = errors.New("config: the address of the mail server is required")

// ErrNoMailFrom means that the sender address of the messages is empty. [Options.Validate] returns it.
var ErrNoMailFrom = errors.New("config: the sender address of the messages is required")

// ErrInstance means that the instance number is above [MaxInstance]. [Options.Validate] wraps it with the number.
var ErrInstance = errors.New("config: the instance number must be 63 or less")

// ErrNoRPID means that the relying party ID is empty. [Options.Validate] returns it.
var ErrNoRPID = errors.New("config: the relying party ID is required")

// ErrNoOrigins means that no origin is allowed. [Options.Validate] returns it.
var ErrNoOrigins = errors.New("config: at least one origin is required")

// ErrTrustedProxy means that a trusted proxy is not an address prefix. [Options.Validate] wraps it with the value.
var ErrTrustedProxy = errors.New("config: a trusted proxy must be an address prefix")

// ErrNoOllamaURL means that the address of Ollama is empty and [FlagMockAdvisor] is not set. [Options.Validate]
// returns it.
var ErrNoOllamaURL = errors.New("config: the address of Ollama is required")

// ErrNoOllamaModel means that the model of Ollama or its digest is empty and [FlagMockAdvisor] is not set.
// [Options.Validate] returns it.
var ErrNoOllamaModel = errors.New("config: the Ollama model and its digest are required")

// ErrNegative means that a setting is below zero. [Options.Validate] wraps it after the name of the setting.
var ErrNegative = errors.New("config: must be 0 or more")

// ErrMissingFromEnv means that a mandatory field of [Env] is nil. [Env.Validate] wraps it after the name of the field.
var ErrMissingFromEnv = errors.New("config: missing from the environment")

// ErrSMTPTLSConflict means that both STARTTLS and implicit TLS are set for the mail server. [Options.Validate] returns
// it.
var ErrSMTPTLSConflict = errors.New("config: the SMTP STARTTLS and implicit TLS options exclude each other")

// ErrNoSMTPPassword means that the SMTP user is set without the file that holds the password. [Options.Validate]
// returns it.
var ErrNoSMTPPassword = errors.New("config: the SMTP user needs a password file")

// ErrNoSMTPUser means that the SMTP password file is set without a user. [Options.Validate] returns it.
var ErrNoSMTPUser = errors.New("config: the SMTP password file needs a user")

// ErrSMTPAuthWithoutTLS means that the SMTP user is set but neither STARTTLS nor implicit TLS is. [Options.Validate]
// returns it, because the service never sends a password over an unencrypted connection.
var ErrSMTPAuthWithoutTLS = errors.New("config: SMTP authentication needs STARTTLS or implicit TLS")
