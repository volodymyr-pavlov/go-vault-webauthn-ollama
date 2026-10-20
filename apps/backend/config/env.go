package config

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis_rate/v10"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/redis/go-redis/v9"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/auth"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/geo"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/smtp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vault"
)

// The kinds of snowflake identifiers, one for each kind of record. A snowflake identifier carries its kind.
const (
	KindUser            = 1
	KindPasskey         = 2
	KindSession         = 3
	KindRecoveryCode    = 4
	KindRecoveryRequest = 5
)

// Env holds every concrete dependency of the server, one field each. [NewEnv] builds it once from [Options]. The
// handlers are not part of it: the server builds them from the Env. [Env.Validate] reports a mandatory field that is
// missing. The Ollama field is empty only when [FlagMockAdvisor] is set.
type Env struct {
	Logger      *slog.Logger
	SystemClock clock.Clock

	Database *sql.DB
	Redis    *redis.Client

	// TransitWriter is the Transit client of Vault, and VaultLease keeps the Vault token alive.
	TransitWriter es.Writer[es.Transit]
	VaultLease    *vault.Lease

	UserReader      es.Reader[es.User]
	UserWriter      es.Writer[es.User]
	UserBatchReader es.BatchReader[es.User]
	UserTx          es.Tx[es.User, es.UserFlag]

	PasskeyReader      es.Reader[es.Passkey]
	PasskeyBatchReader es.BatchReader[es.Passkey]
	PasskeyTx          es.Tx[es.Passkey, es.PasskeyFlag]
	PasskeyBatchTx     es.BatchReaderTx[es.Passkey]

	RecoveryCodeTx es.Tx[es.RecoveryCode, es.RecoveryCodeFlag]

	RecoveryRequestReader es.Reader[es.RecoveryRequest]
	RecoveryRequestWriter es.Writer[es.RecoveryRequest]
	RecoveryRequestTx     es.Tx[es.RecoveryRequest, es.RecoveryRequestFlag]

	// HTTPRequestWriter saves the row of each request that the API received.
	HTTPRequestWriter es.Writer[es.HTTPRequest]

	// HTTPRequestBatchReader lists the request log rows of one user. The export of an account reads them.
	HTTPRequestBatchReader es.BatchReader[es.HTTPRequest]

	SessionReader      es.Reader[es.Session]
	SessionWriter      es.Writer[es.Session]
	SessionBatchReader es.BatchReader[es.Session]
	SessionTx          es.Tx[es.Session, es.SessionFlag]

	// SessionGroupWriter, AccountGroupWriter and RecoveryGroupWriter write the units of work of the API. Each write
	// runs in one transaction and ends with the audit event of the change.
	SessionGroupWriter  es.Writer[es.SessionGroup]
	AccountGroupWriter  es.Writer[es.AccountGroup]
	RecoveryGroupWriter es.Writer[es.RecoveryGroup]

	UserSnowflake            *snowid.Snowflake
	PasskeySnowflake         *snowid.Snowflake
	SessionSnowflake         *snowid.Snowflake
	RecoveryCodeSnowflake    *snowid.Snowflake
	RecoveryRequestSnowflake *snowid.Snowflake

	RelyingParty    *auth.RelyingParty
	RequestVerifier es.Reader[es.SignedRequest]

	PasswordHasher *auth.Hasher

	// StandInHash is the hash of a random password. The service checks a password against it when the email address is
	// unknown, so that the answer takes the same time as for a known address.
	StandInHash string

	Locator       *geo.Locator
	MessageWriter es.Writer[es.Message]
	RateLimiter   *redis_rate.Limiter
	Engine        *ai.Engine

	// Ollama is the client of the local model. It is nil only when [FlagMockAdvisor] is set, which only tests do.
	Ollama *ai.Client
}

// NewEnv builds the [Env] that opts describes. It connects to the database and Redis and logs in to Vault. It builds
// the stores, the relying party, the request verifier, the locator, the message sender and the risk engine. It also
// checks the model in Ollama.
//
// It returns an error if opts is not valid or if any of these steps fails, including an Ollama that is missing or has
// a model with another digest. If [FlagMockAdvisor] is set, it uses [ai.MockAdvisor] and does not contact Ollama. When a
// step fails, it closes the database and Redis connections that it opened.
func NewEnv(ctx context.Context, logger *slog.Logger, opts Options) (*Env, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("check settings: %w", err)
	}

	env := &Env{
		Logger:      logger,
		SystemClock: clock.SystemClock{},
	}

	if err := env.connect(ctx, opts); err != nil {
		return nil, errors.Join(err, env.Close())
	}

	return env, nil
}

// connect fills the fields of the Env from opts. It returns the first error and leaves the connections that it
// opened for the caller to close.
func (env *Env) connect(ctx context.Context, opts Options) error {
	logger := env.Logger

	db, err := mysql.Open(ctx, mysql.OpenOptions{
		DSN: opts.MySQLDSN,
	})
	if err != nil {
		return fmt.Errorf("open the database: %w", err)
	}

	env.Database = db

	if len(opts.RedisSentinels) > 0 {
		env.Redis = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    opts.RedisMaster,
			SentinelAddrs: opts.RedisSentinels,
		})
	} else {
		env.Redis = redis.NewClient(&redis.Options{
			Addr: opts.RedisAddr,
		})
	}

	if err := env.Redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}

	env.RateLimiter = redis_rate.NewLimiter(env.Redis)

	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = opts.VaultAddr

	client, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("make the vault client: %w", err)
	}

	roleID := opts.VaultRoleID
	if opts.VaultRoleIDFile != "" {
		raw, err := os.ReadFile(opts.VaultRoleIDFile)
		if err != nil {
			return fmt.Errorf("read the role ID: %w", err)
		}

		roleID = strings.TrimSpace(string(raw))
	}

	var wrappingToken string
	if opts.VaultWrappedTokenFile != "" {
		raw, err := os.ReadFile(opts.VaultWrappedTokenFile)
		if err != nil {
			return fmt.Errorf("read the wrapped token: %w", err)
		}

		wrappingToken = strings.TrimSpace(string(raw))
	}

	lease, err := vault.Login(ctx, client, vault.LoginOptions{
		RoleID:        roleID,
		WrappingToken: wrappingToken,
		SecretID:      opts.VaultSecretID,
		Logger:        logger,
	})
	if err != nil {
		return fmt.Errorf("log in to vault: %w", err)
	}

	transit := &vault.Client{
		API: client,
	}
	env.VaultLease = lease
	env.TransitWriter = transit

	queryBuilder := mysql.NewQueryBuilder(db)
	env.UserReader = &mysql.UserReader{
		Database: db,
	}
	env.UserWriter = &mysql.UserWriter{
		Database:    db,
		SystemClock: env.SystemClock,
		UpdateUserBuilder: &mysql.UpdateUserBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.UserBatchReader = &mysql.UserBatchReader{
		Database: db,
	}
	env.UserTx = &mysql.UserTx{
		SystemClock: env.SystemClock,
		UpdateUserBuilder: &mysql.UpdateUserBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.PasskeyReader = &mysql.PasskeyReader{
		Database: db,
	}
	env.PasskeyBatchReader = &mysql.PasskeyBatchReader{
		Database: db,
	}
	env.PasskeyTx = &mysql.PasskeyTx{
		SystemClock: env.SystemClock,
		UpdatePasskeyBuilder: &mysql.UpdatePasskeyBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.PasskeyBatchTx = &mysql.PasskeyBatchTx{}
	env.RecoveryCodeTx = &mysql.RecoveryCodeTx{
		SystemClock: env.SystemClock,
	}
	env.RecoveryRequestReader = &mysql.RecoveryRequestReader{
		Database: db,
	}
	env.RecoveryRequestWriter = &mysql.RecoveryRequestWriter{
		Database:    db,
		SystemClock: env.SystemClock,
	}
	env.RecoveryRequestTx = &mysql.RecoveryRequestTx{
		SystemClock: env.SystemClock,
	}
	env.HTTPRequestWriter = &mysql.HTTPRequestWriter{
		Database:    db,
		SystemClock: env.SystemClock,
	}
	env.HTTPRequestBatchReader = &mysql.HTTPRequestBatchReader{
		Database: db,
	}
	env.SessionReader = &mysql.SessionReader{
		Database: db,
	}
	env.SessionWriter = &mysql.SessionWriter{
		Database:    db,
		SystemClock: env.SystemClock,
		UpdateSessionBuilder: &mysql.UpdateSessionBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.SessionTx = &mysql.SessionTx{
		SystemClock: env.SystemClock,
		UpdateSessionBuilder: &mysql.UpdateSessionBuilder{
			QueryBuilder: queryBuilder,
		},
	}
	env.SessionGroupWriter = &mysql.SessionGroupWriter{
		Database:          db,
		SystemClock:       env.SystemClock,
		SessionTx:         env.SessionTx,
		UserTx:            env.UserTx,
		PasskeyTx:         env.PasskeyTx,
		RecoveryCodeTx:    env.RecoveryCodeTx,
		RecoveryRequestTx: env.RecoveryRequestTx,
	}
	env.AccountGroupWriter = &mysql.AccountGroupWriter{
		Database:       db,
		SystemClock:    env.SystemClock,
		UserTx:         env.UserTx,
		SessionTx:      env.SessionTx,
		PasskeyTx:      env.PasskeyTx,
		PasskeyBatchTx: env.PasskeyBatchTx,
		RecoveryCodeTx: env.RecoveryCodeTx,
	}
	env.RecoveryGroupWriter = &mysql.RecoveryGroupWriter{
		Database:          db,
		SystemClock:       env.SystemClock,
		SessionTx:         env.SessionTx,
		RecoveryRequestTx: env.RecoveryRequestTx,
	}
	env.SessionBatchReader = &mysql.SessionBatchReader{
		Database: db,
	}

	env.UserSnowflake = snowid.NewSnowflake(KindUser, opts.Instance)
	env.PasskeySnowflake = snowid.NewSnowflake(KindPasskey, opts.Instance)
	env.SessionSnowflake = snowid.NewSnowflake(KindSession, opts.Instance)
	env.RecoveryCodeSnowflake = snowid.NewSnowflake(KindRecoveryCode, opts.Instance)
	env.RecoveryRequestSnowflake = snowid.NewSnowflake(KindRecoveryRequest, opts.Instance)

	env.RelyingParty, err = auth.NewRelyingParty(auth.RelyingPartyOptions{
		RPID:    opts.RPID,
		RPName:  opts.RPName,
		Origins: opts.OriginList(),
	})
	if err != nil {
		return err
	}

	env.RequestVerifier = &auth.RequestVerifier{
		SystemClock: env.SystemClock,
		NonceWriter: &auth.NonceStore{
			Redis: env.Redis,
		},
	}

	env.PasswordHasher = &auth.Hasher{}
	standIn := make([]byte, 32)

	if _, err := rand.Read(standIn); err != nil {
		return fmt.Errorf("make the stand-in password: %w", err)
	}

	env.StandInHash, err = env.PasswordHasher.Hash(hex.EncodeToString(standIn))
	if err != nil {
		return fmt.Errorf("hash the stand-in password: %w", err)
	}

	var proxies []netip.Prefix
	for _, text := range opts.trustedProxies() {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return fmt.Errorf("parse a trusted proxy: %w", err)
		}

		proxies = append(proxies, prefix)
	}

	env.Locator, err = geo.New(proxies)
	if err != nil {
		return err
	}

	smtpPassword, err := readSMTPPassword(opts.SMTPPasswordFile)
	if err != nil {
		return err
	}

	mailClient, err := smtp.NewClient(smtp.Config{
		Addr:          opts.SMTPAddr,
		From:          opts.MailFrom,
		StartTLS:      opts.SMTPStartTLS,
		ImplicitTLS:   opts.SMTPImplicitTLS,
		User:          opts.SMTPUser,
		Password:      smtpPassword,
		TLSServerName: opts.SMTPTLSServerName,
	})
	if err != nil {
		return fmt.Errorf("make the mail client: %w", err)
	}

	env.MessageWriter, err = smtp.NewSender(mailClient)
	if err != nil {
		return fmt.Errorf("make the mail sender: %w", err)
	}

	env.Engine = &ai.Engine{
		Logger: logger,
	}

	if opts.Flags&FlagMockAdvisor != 0 {
		env.Engine.Advisor = &ai.MockAdvisor{}
		env.Engine.Timeout = time.Second

		return nil
	}

	timeout := opts.OllamaTimeout
	if timeout == 0 {
		timeout = ai.DefaultTimeout
	}

	env.Ollama, err = ai.New(ai.Options{
		URL:     opts.OllamaURL,
		Model:   opts.OllamaModel,
		Digest:  opts.OllamaDigest,
		Timeout: timeout,
	})
	if err != nil {
		return fmt.Errorf("build the model client: %w", err)
	}

	if err := env.Ollama.Check(ctx); err != nil {
		return fmt.Errorf("check the model: %w", err)
	}

	env.Engine.Advisor = env.Ollama
	env.Engine.Timeout = timeout

	return nil
}

// Validate checks that the mandatory fields of the Env are set.
//
// It returns an error wrapping [ErrMissingFromEnv] with the name of the first mandatory field that is nil.
func (e *Env) Validate() error {
	switch {
	case e.Logger == nil:
		return fmt.Errorf("the field Logger %w", ErrMissingFromEnv)
	case e.SystemClock == nil:
		return fmt.Errorf("the field SystemClock %w", ErrMissingFromEnv)
	case e.Database == nil:
		return fmt.Errorf("the field Database %w", ErrMissingFromEnv)
	case e.Redis == nil:
		return fmt.Errorf("the field Redis %w", ErrMissingFromEnv)
	case e.TransitWriter == nil || e.VaultLease == nil:
		return fmt.Errorf("the field Vault %w", ErrMissingFromEnv)
	case e.UserReader == nil || e.UserWriter == nil || e.UserBatchReader == nil || e.UserTx == nil:
		return fmt.Errorf("the user stores %w", ErrMissingFromEnv)
	case e.PasskeyReader == nil || e.PasskeyBatchReader == nil || e.PasskeyTx == nil || e.PasskeyBatchTx == nil:
		return fmt.Errorf("the passkey stores %w", ErrMissingFromEnv)
	case e.RecoveryCodeTx == nil:
		return fmt.Errorf("the recovery code stores %w", ErrMissingFromEnv)
	case e.RecoveryRequestReader == nil || e.RecoveryRequestWriter == nil || e.RecoveryRequestTx == nil:
		return fmt.Errorf("the recovery request stores %w", ErrMissingFromEnv)
	case e.HTTPRequestBatchReader == nil:
		return fmt.Errorf("the field HTTPRequestBatchReader %w", ErrMissingFromEnv)
	case e.HTTPRequestWriter == nil:
		return fmt.Errorf("the field HTTPRequestWriter %w", ErrMissingFromEnv)
	case e.SessionReader == nil || e.SessionWriter == nil || e.SessionBatchReader == nil || e.SessionTx == nil:
		return fmt.Errorf("the session stores %w", ErrMissingFromEnv)
	case e.SessionGroupWriter == nil || e.AccountGroupWriter == nil || e.RecoveryGroupWriter == nil:
		return fmt.Errorf("the group writers %w", ErrMissingFromEnv)
	case e.UserSnowflake == nil || e.PasskeySnowflake == nil || e.SessionSnowflake == nil || e.RecoveryCodeSnowflake == nil || e.RecoveryRequestSnowflake == nil:
		return fmt.Errorf("the snowflakes %w", ErrMissingFromEnv)
	case e.RelyingParty == nil:
		return fmt.Errorf("the field RelyingParty %w", ErrMissingFromEnv)
	case e.RequestVerifier == nil:
		return fmt.Errorf("the request verifier %w", ErrMissingFromEnv)
	case e.PasswordHasher == nil || e.StandInHash == "":
		return fmt.Errorf("the password hasher %w", ErrMissingFromEnv)
	case e.Locator == nil:
		return fmt.Errorf("the field Locator %w", ErrMissingFromEnv)
	case e.MessageWriter == nil:
		return fmt.Errorf("the field MessageWriter %w", ErrMissingFromEnv)
	case e.RateLimiter == nil:
		return fmt.Errorf("the field RateLimiter %w", ErrMissingFromEnv)
	case e.Engine == nil:
		return fmt.Errorf("the field Engine %w", ErrMissingFromEnv)
	}

	return nil
}

// Close closes the database and Redis connections. It returns the errors of both, joined.
func (e *Env) Close() error {
	var errs []error
	if e.Database != nil {
		errs = append(errs, e.Database.Close())
	}

	if e.Redis != nil {
		errs = append(errs, e.Redis.Close())
	}

	return errors.Join(errs...)
}

// readSMTPPassword returns the content of the password file without the surrounding white space. It returns an empty
// password if path is empty. The error never contains the password.
func readSMTPPassword(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read the SMTP password: %w", err)
	}

	return strings.TrimSpace(string(raw)), nil
}
