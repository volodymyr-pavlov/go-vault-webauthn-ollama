// Package config builds the dependencies of the server from its settings.
//
// [Options] are the settings, and [Env] holds every concrete dependency, built once by [NewEnv]. Only this package
// chooses the concrete types. The handlers take what they need as fields of interface types.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// MaxInstance is the highest instance number. A snowflake identifier keeps 6 bits for the instance.
const MaxInstance = 63

// Flag is a bit of [Options.Flags]. A flag changes what the program does.
type Flag uint8

const (
	// FlagMockAdvisor makes the risk engine use [ai.MockAdvisor] instead of Ollama. It is for tests only. The server
	// command has no option for it, and the server does not start without Ollama.
	FlagMockAdvisor Flag = 1 << iota

	// FlagRewrap makes the server command rewrap every stored TOTP secret with the latest version of the key and exit,
	// instead of serving. It is meant to run after a rotation of the key.
	FlagRewrap
)

// Options are the settings of the server. [Options.Validate] checks them.
type Options struct {
	// HTTPAddr is the listen address of the HTTP server.
	HTTPAddr string

	// MetricsAddr is the listen address of the metrics server, such as ":9090". If it is empty, the service serves no
	// metrics. The metrics never use the address of the API.
	MetricsAddr string

	// MySQLDSN is the data source name of the MySQL database.
	MySQLDSN string

	// RedisAddr is the address of Redis. The service keeps the rate limits and the request nonces there.
	RedisAddr string

	// RedisSentinels are the addresses of the Redis Sentinel nodes. If the list is not empty, the service asks the
	// sentinels for the current master of RedisMaster and follows it after a failover, and RedisAddr is not used.
	// RedisMaster is the name of the master that the sentinels monitor.
	RedisSentinels []string
	RedisMaster    string

	// VaultAddr is the address of Vault.
	//
	// VaultRoleID is the AppRole role ID. VaultRoleIDFile is the file that holds it, and it replaces VaultRoleID if
	// set. VaultWrappedTokenFile is the file with the wrapping token that unwraps to the secret ID. The
	// initialization job writes both files.
	//
	// VaultSecretID is the secret ID itself, for tests and tools.
	VaultAddr             string
	VaultRoleID           string
	VaultRoleIDFile       string
	VaultWrappedTokenFile string
	VaultSecretID         string

	// SMTPAddr is the address of the mail server, and MailFrom is the sender address of the messages.
	SMTPAddr string
	MailFrom string

	// SMTPStartTLS makes the mail client upgrade the connection with STARTTLS and refuse to go on in plain text.
	// SMTPImplicitTLS makes it use TLS from the first byte. They exclude each other. If neither is set, the connection
	// is plain, which is for local stands only.
	SMTPStartTLS    bool
	SMTPImplicitTLS bool

	// SMTPUser is the user name for SMTP AUTH PLAIN, and SMTPPasswordFile is the file that holds the password. Both
	// are set or both are empty. Authentication needs SMTPStartTLS or SMTPImplicitTLS.
	SMTPUser         string
	SMTPPasswordFile string

	// SMTPTLSServerName is the name that the certificate of the mail server must match. If it is empty, the host of
	// SMTPAddr is used.
	SMTPTLSServerName string

	// RPID is the relying party ID of the passkeys, and RPName is its name. Origins are the allowed origins, separated
	// by commas.
	RPID    string
	RPName  string
	Origins string

	// TrustedProxies are the address prefixes of the proxies that may set the X-Forwarded-For header, separated by
	// commas.
	TrustedProxies string

	// OllamaURL, OllamaModel and OllamaDigest describe the local model. They are required unless [FlagMockAdvisor] is
	// set. OllamaTimeout is the time that one advice may take. If it is zero, [ai.DefaultTimeout] applies.
	OllamaURL     string
	OllamaModel   string
	OllamaDigest  string
	OllamaTimeout time.Duration

	// Instance is the number of this instance of the service, from 0 to [MaxInstance]. Every instance that runs at the
	// same time needs its own number, so that the identifiers they issue never collide.
	Instance uint

	// FreshWindow is the time after a factor passes in which an action that needs a fresh authentication may run. If it
	// is zero, the default of the API applies.
	FreshWindow time.Duration

	// SessionIdle is how long a session may stay without a request before it ends. If it is zero, the default of the API
	// applies. SessionRetention is how long the service keeps an expired session as login history before it deletes the
	// row. If it is zero, the default applies.
	SessionIdle      time.Duration
	SessionRetention time.Duration

	// RequestLogRetention is how long the service keeps the rows of the request log, which hold the address and the user
	// agent of each request, before it deletes them. If it is zero, the default of the API applies.
	RequestLogRetention time.Duration

	// RecoveryDelay is how long a recovery request waits before an operator can approve it. If it is zero, the default of
	// the API applies.
	RecoveryDelay time.Duration

	// BuildVersion is the version of the service. The server command sets it from the build. It goes into every row of
	// the request log.
	BuildVersion string

	// Flags are the [Flag] bits that are set.
	Flags Flag

	// LogLevel is the name of the log level, such as "info". The server command parses it.
	LogLevel string
}

// Validate checks the settings.
//
// It returns nil if they are valid. Otherwise it returns the errors of all broken rules, joined: [ErrNoHTTPAddr] and
// the other ErrNo errors for a missing setting, [ErrTrustedProxy], [ErrInstance], [ErrNegative], or one of the mail rules: [ErrSMTPTLSConflict],
// [ErrNoSMTPPassword], [ErrNoSMTPUser] and [ErrSMTPAuthWithoutTLS].
func (o Options) Validate() error {
	var errs []error
	if o.HTTPAddr == "" {
		errs = append(errs, ErrNoHTTPAddr)
	}

	if o.MySQLDSN == "" {
		errs = append(errs, ErrNoMySQLDSN)
	}

	if o.RedisAddr == "" {
		errs = append(errs, ErrNoRedisAddr)
	}

	if len(o.RedisSentinels) > 0 && o.RedisMaster == "" {
		errs = append(errs, ErrNoRedisMaster)
	}

	if o.VaultAddr == "" {
		errs = append(errs, ErrNoVaultAddr)
	}

	if o.VaultRoleID == "" && o.VaultRoleIDFile == "" {
		errs = append(errs, ErrNoVaultRoleID)
	}

	if o.VaultWrappedTokenFile == "" && o.VaultSecretID == "" {
		errs = append(errs, ErrNoVaultSecret)
	}

	if o.SMTPAddr == "" {
		errs = append(errs, ErrNoSMTPAddr)
	}

	if o.MailFrom == "" {
		errs = append(errs, ErrNoMailFrom)
	}

	if o.SMTPStartTLS && o.SMTPImplicitTLS {
		errs = append(errs, ErrSMTPTLSConflict)
	}

	if o.SMTPUser != "" && o.SMTPPasswordFile == "" {
		errs = append(errs, ErrNoSMTPPassword)
	}

	if o.SMTPUser == "" && o.SMTPPasswordFile != "" {
		errs = append(errs, ErrNoSMTPUser)
	}

	if o.SMTPUser != "" && !o.SMTPStartTLS && !o.SMTPImplicitTLS {
		errs = append(errs, ErrSMTPAuthWithoutTLS)
	}

	if o.RPID == "" {
		errs = append(errs, ErrNoRPID)
	}

	if o.Origins == "" {
		errs = append(errs, ErrNoOrigins)
	}

	for _, prefix := range o.trustedProxies() {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			errs = append(errs, fmt.Errorf("%w: %q", ErrTrustedProxy, prefix))
		}
	}

	if o.Flags&FlagMockAdvisor == 0 {
		if o.OllamaURL == "" {
			errs = append(errs, ErrNoOllamaURL)
		}

		if o.OllamaModel == "" || o.OllamaDigest == "" {
			errs = append(errs, ErrNoOllamaModel)
		}
	}

	if o.Instance > MaxInstance {
		errs = append(errs, fmt.Errorf("%w: %d", ErrInstance, o.Instance))
	}

	if o.FreshWindow < 0 {
		errs = append(errs, fmt.Errorf("fresh window %w", ErrNegative))
	}

	if o.SessionIdle < 0 || o.SessionRetention < 0 || o.RequestLogRetention < 0 {
		errs = append(errs, fmt.Errorf("session idle and retention, and request log retention %w", ErrNegative))
	}

	if o.RecoveryDelay < 0 {
		errs = append(errs, fmt.Errorf("recovery delay %w", ErrNegative))
	}

	return errors.Join(errs...)
}

// OriginList returns the allowed origins as a list. It trims white space and skips empty items.
func (o Options) OriginList() []string {
	return SplitList(o.Origins)
}

// trustedProxies returns the trusted proxy prefixes as a list. It trims white space and skips empty items.
func (o Options) trustedProxies() []string {
	return SplitList(o.TrustedProxies)
}

// SplitList splits a comma-separated setting into its items. It trims white space around each item and skips the empty
// ones.
func SplitList(text string) []string {
	var items []string
	for item := range strings.SplitSeq(text, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}

	return items
}
