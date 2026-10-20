package vault

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/hashicorp/vault/api"
)

// DefaultAppRoleMount is the path of the AppRole method when [LoginOptions.Mount] is empty.
const DefaultAppRoleMount = "approle"

// LoginOptions holds the credentials that the service uses to log in to Vault.
type LoginOptions struct {
	// RoleID is the ID of the AppRole.
	RoleID string

	// WrappingToken is a single-use token that unwraps to the secret ID. The initialization job hands the secret ID
	// over this way, so it is never written down. One of WrappingToken and SecretID is required. If both are set,
	// WrappingToken is used.
	WrappingToken string

	// SecretID is the secret ID itself, for tests and tools.
	SecretID string

	// Mount is the path of the AppRole method. Empty means [DefaultAppRoleMount].
	Mount string

	// Logger receives the messages about logins and renewals. If it is nil, they are discarded.
	Logger *slog.Logger
}

// Lease holds the token of a logged-in service and keeps it valid. [Lease.Run] renews the token, and logs in again when
// the token cannot be renewed any more.
type Lease struct {
	client   *api.Client
	mount    string
	roleID   string
	secretID string
	logger   *slog.Logger
	auth     *api.Secret

	// retryMin and retryMax bound the wait between two failed logins. A zero value selects the defaults.
	retryMin time.Duration
	retryMax time.Duration
}

const (
	// defaultRetryMin and defaultRetryMax are the first and the longest wait between two failed logins.
	defaultRetryMin = time.Second
	defaultRetryMax = 30 * time.Second
)

// Login trades the AppRole credentials of opts for a token, sets the token on client, and returns the [Lease] that
// keeps it valid. It unwraps a wrapping token first, which uses the token up. A second start with the same token fails,
// which shows that someone else unwrapped it.
//
// It returns [ErrNoRoleID] or [ErrNoSecretID] if opts lacks a credential. It returns [ErrNoToken] if Vault responds
// without a token.
func Login(ctx context.Context, client *api.Client, opts LoginOptions) (*Lease, error) {
	if opts.RoleID == "" {
		return nil, ErrNoRoleID
	}

	if opts.WrappingToken == "" && opts.SecretID == "" {
		return nil, ErrNoSecretID
	}

	lease := &Lease{
		client:   client,
		mount:    opts.Mount,
		roleID:   opts.RoleID,
		secretID: opts.SecretID,
		logger:   opts.Logger,
	}
	if lease.mount == "" {
		lease.mount = DefaultAppRoleMount
	}

	if lease.logger == nil {
		lease.logger = slog.New(slog.DiscardHandler)
	}

	if opts.WrappingToken != "" {
		secretID, err := lease.unwrap(ctx, opts.WrappingToken)
		if err != nil {
			return nil, err
		}

		lease.secretID = secretID
	}

	if err := lease.login(ctx); err != nil {
		return nil, err
	}

	return lease, nil
}

// unwrap trades the wrapping token for the secret ID that it holds. This uses the token up.
func (l *Lease) unwrap(ctx context.Context, wrappingToken string) (string, error) {
	unwrapped, err := l.client.Logical().UnwrapWithContext(ctx, wrappingToken)
	if err != nil {
		return "", fmt.Errorf("unwrap the secret ID: %w", err)
	}

	if unwrapped == nil {
		return "", fmt.Errorf("secret_id: %w", ErrNoField)
	}

	return field(unwrapped, "secret_id")
}

// login trades the credentials for a token and sets the token on the client.
func (l *Lease) login(ctx context.Context) error {
	response, err := l.client.Logical().WriteWithContext(ctx, "auth/"+l.mount+"/login", map[string]any{
		"role_id":   l.roleID,
		"secret_id": l.secretID,
	})
	if err != nil {
		return fmt.Errorf("log in with AppRole: %w", err)
	}

	if response == nil || response.Auth == nil || response.Auth.ClientToken == "" {
		return ErrNoToken
	}

	l.client.SetToken(response.Auth.ClientToken)
	l.auth = response
	l.logger.Info("logged in to vault", "ttl", time.Duration(response.Auth.LeaseDuration)*time.Second, "renewable", response.Auth.Renewable)
	return nil
}

// Run renews the token until ctx ends. Each time the token cannot be renewed any more, it logs in again with the same
// credentials. A failed login does not end Run: it waits, with a growing delay, and tries again, so a short outage of
// Vault does not stop the service. While there is no valid token, the operations that need Vault fail and the service
// refuses what it cannot check.
//
// It returns nil when ctx ends. It returns an error only if the watcher cannot be made.
func (l *Lease) Run(ctx context.Context) error {
	for {
		loggedIn := time.Now()

		watcher, err := l.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
			Secret: l.auth,
		})
		if err != nil {
			return fmt.Errorf("watch the token: %w", err)
		}

		go watcher.Start()

		if err := l.watch(ctx, watcher); err != nil {
			return err
		}

		if ctx.Err() != nil {
			return nil
		}

		// The token reached the end of its life, or Vault refused to renew it. A token that ended at once, such as one
		// that cannot be renewed, must not turn this loop into a stream of logins, so wait out the rest of the shortest
		// allowed life. Then log in again with the same credentials.
		if err := pause(ctx, l.shortestLogin()-time.Since(loggedIn)); err != nil {
			return nil
		}

		if err := l.loginAgain(ctx); err != nil {
			return nil
		}
	}
}

// shortestLogin returns the shortest time between two logins that succeed one after the other. It is the first wait
// after a failed login.
func (l *Lease) shortestLogin() time.Duration {
	if l.retryMin == 0 {
		return defaultRetryMin
	}

	return l.retryMin
}

// pause waits for d and returns the error of ctx if ctx ends first. It returns at once for a d that is not positive.
func pause(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// loginAgain logs in until a login succeeds or ctx ends. It waits between two failures, first for [defaultRetryMin] and
// then twice as long each time, up to [defaultRetryMax]. It logs each failure. It returns the error of ctx if ctx ends
// first.
func (l *Lease) loginAgain(ctx context.Context) error {
	wait := l.shortestLogin()

	longest := l.retryMax
	if longest == 0 {
		longest = defaultRetryMax
	}

	for {
		err := l.login(ctx)
		if err == nil {
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		l.logger.Warn("the vault login failed, trying again", "error", err, "wait", wait)

		if err := pause(ctx, wait); err != nil {
			return err
		}

		wait = min(wait*2, longest)
	}
}

// watch reads the renewals of watcher until the token cannot be renewed any more or ctx ends. It logs a failed renewal.
func (l *Lease) watch(ctx context.Context, watcher *api.LifetimeWatcher) error {
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-watcher.DoneCh():
			if err != nil {
				l.logger.Warn("the vault token could not be renewed", "error", err)
			}

			return nil
		case renewal := <-watcher.RenewCh():
			if renewal != nil && renewal.Secret != nil && renewal.Secret.Auth != nil {
				l.logger.Debug("renewed the vault token", "ttl", time.Duration(renewal.Secret.Auth.LeaseDuration)*time.Second)
			}
		}
	}
}
