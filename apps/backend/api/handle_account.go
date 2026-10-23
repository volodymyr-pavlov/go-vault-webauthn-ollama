package api

import (
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"
	"golang.org/x/sync/errgroup"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/totp"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &AddAccountHandler{}
var _ web.Handler = &ListAccountsHandler{}
var _ web.Handler = &RemoveAccountHandler{}

var addAuthenticatorHandlerBodyArgsPool web.Pool[AddAccountHandlerBodyArgs]

// VaultConcurrency is the number of Vault calls that one request of the account handlers runs at a time. An import or
// a listing touches one key for each account, and the calls are independent, so they run side by side.
const VaultConcurrency = 8

// AccountView describes one account of the authenticator. It never holds a secret.
type AccountView struct {
	AccountXID uint64 `json:"account_xid,string"`
	Issuer     string `json:"issuer"`
	Label      string `json:"label"`
	Algorithm  string `json:"algorithm"`
	Digits     uint8  `json:"digits"`
	Period     uint32 `json:"period"`
}

// AddAccountHandlerBodyArgs are the arguments of POST /authenticator. A body holds either URI, which is an
// otpauth:// link or the otpauth-migration:// export of Google Authenticator, or Secret with an optional Issuer and
// Label.
type AddAccountHandlerBodyArgs struct {
	URI    string
	Secret string
	Issuer string
	Label  string
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *AddAccountHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "uri":
			a.URI, err = web.JSONString(member)
		case "secret":
			a.Secret, err = web.JSONString(member)
		case "issuer":
			a.Issuer, err = web.JSONString(member)
		case "label":
			a.Label, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks that the body holds a link or a secret, and not both.
//
// It returns [ErrNoBodyAccount] if it does not.
func (a *AddAccountHandlerBodyArgs) Validate() error {
	a.URI = strings.TrimSpace(a.URI)
	a.Secret = strings.TrimSpace(a.Secret)

	if (a.URI == "") == (a.Secret == "") {
		return ErrNoBodyAccount
	}

	return nil
}

// AddAccountHandlerResult is the response of POST /authenticator. Skipped is the number of entries of a Google
// export that the service did not import, because they are counter-based.
type AddAccountHandlerResult struct {
	Accounts []AccountView `json:"accounts"`
	Skipped  int           `json:"skipped"`
}

// AddAccountHandler handles POST /authenticator. It adds one account, or all the accounts of a Google
// Authenticator export, to the authenticator of the user. Vault keeps each secret in its TOTP engine and makes the
// codes, so the secret never comes back.
//
// The secrets and the rows are in two systems, so the handler creates the keys first, then stores the rows in one
// transaction, and deletes the keys again if the rows do not commit.
type AddAccountHandler struct {
	AccountBatchReader     es.BatchReader[es.Account]
	AccountGroupWriter     es.Writer[es.AccountGroup]
	AuthenticatorKeyWriter es.Writer[es.AuthenticatorKey]
	AccountSnowflake       *snowid.Snowflake
}

// ServeHTTP implements [web.Handler]. It responds with status 201.
//
// It returns [ErrSessionWithoutUser] if the session is bound to no account. It returns [ErrMalformedAccount] if the link or
// the secret cannot be imported, and [ErrAccountLimit] if the authenticator would hold more than
// [es.MaxAccounts] accounts.
func (h *AddAccountHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := addAuthenticatorHandlerBodyArgsPool.Get()
	defer addAuthenticatorHandlerBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	var accounts []totp.Account
	skipped := 0

	if bodyArgs.URI != "" {
		accounts, skipped, err = totp.ParseURI(bodyArgs.URI)
	} else {
		var account totp.Account
		account, err = totp.ParseSecret(bodyArgs.Secret, bodyArgs.Issuer, bodyArgs.Label)
		accounts = []totp.Account{account}
	}

	if errors.Is(err, totp.ErrImport) {
		return ErrMalformedAccount
	} else if err != nil {
		return fmt.Errorf("read the accounts: %w", err)
	}

	stored, err := h.AccountBatchReader.ReadAll(ctx, es.Account{
		UserID: user.ID,
	}, es.PageNumberPagination{
		PageSize: es.MaxAccounts + 1,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the authenticator accounts: %w", err)
	}

	if len(stored)+len(accounts) > es.MaxAccounts {
		return ErrAccountLimit
	}

	items := make([]es.Account, 0, len(accounts))
	secrets := make([]string, 0, len(accounts))

	for _, account := range accounts {
		xid := h.AccountSnowflake.Next()

		items = append(items, es.Account{
			AccountXID: xid,
			VaultKey:   fmt.Sprintf("u%d-a%d", user.UserXID, xid),
			Issuer:     account.Issuer,
			Label:      account.Label,
			Algorithm:  account.Algorithm,
			Digits:     account.Digits,
			Period:     account.Period,
		})
		secrets = append(secrets, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(account.Secret))
	}

	// The keys go to Vault side by side. A failed call stops the others, and the keys that made it are deleted again.
	created := make([]bool, len(items))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(VaultConcurrency)

	for i, item := range items {
		group.Go(func() error {
			_, err := h.AuthenticatorKeyWriter.WriteOne(groupCtx, es.AuthenticatorKey{
				Name:      item.VaultKey,
				Secret:    secrets[i],
				Issuer:    item.Issuer,
				Label:     item.Label,
				Algorithm: item.Algorithm,
				Digits:    item.Digits,
				Period:    item.Period,
			}, es.WriteCreate)
			if err != nil {
				return fmt.Errorf("store a secret in Vault: %w", err)
			}

			created[i] = true

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		made := make([]es.Account, 0, len(items))
		for i, item := range items {
			if created[i] {
				made = append(made, item)
			}
		}

		return errors.Join(err, h.forget(ctx, made))
	}

	written, err := h.AccountGroupWriter.WriteOne(ctx, es.AccountGroup{
		User: es.User{
			ID: user.ID,
		},
		Items: items,
	}, es.AddAccounts)
	if errors.Is(err, es.ErrTooManyAccounts) {
		return errors.Join(ErrAccountLimit, h.forget(ctx, items))
	} else if err != nil {
		return errors.Join(fmt.Errorf("store the authenticator accounts: %w", err), h.forget(ctx, items))
	}

	result := AddAccountHandlerResult{
		Accounts: make([]AccountView, 0, len(written.Items)),
		Skipped:  skipped,
	}

	for _, item := range written.Items {
		result.Accounts = append(result.Accounts, accountView(item))
	}

	SetEvent(ctx, es.EventAccountAdded, slog.Int("count", len(written.Items)), slog.Int("skipped", skipped))

	return web.Write(ctx, fasthttp.StatusCreated, result)
}

// forget deletes the keys of items from Vault, [VaultConcurrency] at a time. It runs after a failure, so it does not
// stop when the request ends or when one delete fails, and it returns the errors of all the deletes that failed.
func (h *AddAccountHandler) forget(ctx *fasthttp.RequestCtx, items []es.Account) error {
	failures := make([]error, len(items))

	var group errgroup.Group
	group.SetLimit(VaultConcurrency)

	for i, item := range items {
		group.Go(func() error {
			_, err := h.AuthenticatorKeyWriter.WriteOne(ctx, es.AuthenticatorKey{
				Name: item.VaultKey,
			}, es.DeleteAuthenticatorKey)
			if err != nil {
				failures[i] = fmt.Errorf("delete a secret from Vault: %w", err)
			}

			return nil
		})
	}

	_ = group.Wait()

	return errors.Join(failures...)
}

// accountView returns the view of an account.
func accountView(item es.Account) AccountView {
	return AccountView{
		AccountXID: item.AccountXID,
		Issuer:     item.Issuer,
		Label:      item.Label,
		Algorithm:  item.Algorithm,
		Digits:     item.Digits,
		Period:     item.Period,
	}
}

// AccountCode is one account of the authenticator with its current code.
type AccountCode struct {
	AccountView

	// Code is the current code. It is empty if Vault has no key for the account.
	Code string `json:"code"`

	// ValidFor is how many seconds the code lasts.
	ValidFor int64 `json:"valid_for"`

	// Unavailable is true if Vault has no key for the account, so the account shows no code.
	Unavailable bool `json:"unavailable,omitempty"`
}

// ListAccountsHandlerResult is the response of GET /authenticator.
type ListAccountsHandlerResult struct {
	Accounts []AccountCode `json:"accounts"`
}

// ListAccountsHandler handles GET /authenticator. It lists the accounts of the authenticator with their current
// codes, which Vault makes. The page asks again when a code runs out.
type ListAccountsHandler struct {
	AccountBatchReader     es.BatchReader[es.Account]
	AuthenticatorKeyReader es.Reader[es.AuthenticatorKey]
	SystemClock            clock.Clock
}

// ServeHTTP implements [web.Handler].
//
// It returns [ErrSessionWithoutUser] if the session is bound to no account.
func (h *ListAccountsHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	stored, err := h.AccountBatchReader.ReadAll(ctx, es.Account{
		UserID: user.ID,
	}, es.PageNumberPagination{
		PageSize: es.MaxAccounts,
	}, 0)
	if err != nil {
		return fmt.Errorf("read the authenticator accounts: %w", err)
	}

	now := h.SystemClock.Now()
	result := ListAccountsHandlerResult{
		Accounts: make([]AccountCode, len(stored)),
	}

	// The codes come from Vault side by side, each into its own slot, so the order of the rows stays.
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(VaultConcurrency)

	for i, item := range stored {
		group.Go(func() error {
			entry := AccountCode{
				AccountView: accountView(item),
				ValidFor:    int64(item.Period) - now.Unix()%int64(item.Period),
			}

			key, err := h.AuthenticatorKeyReader.ReadOne(groupCtx, es.AuthenticatorKey{
				Name: item.VaultKey,
			}, 0)
			if errors.Is(err, es.ErrNotFound) {
				entry.Unavailable = true
			} else if err != nil {
				return fmt.Errorf("read a code from Vault: %w", err)
			}

			entry.Code = key.Code
			result.Accounts[i] = entry

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return err
	}

	return web.Write(ctx, fasthttp.StatusOK, result)
}

// RemoveAccountHandler handles DELETE /authenticator/{account_xid}. It deletes the secret from Vault and
// then the row. If the second step fails, the request can be repeated: deleting a key that is gone is not an error.
type RemoveAccountHandler struct {
	AccountReader          es.Reader[es.Account]
	AccountGroupWriter     es.Writer[es.AccountGroup]
	AuthenticatorKeyWriter es.Writer[es.AuthenticatorKey]
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
//
// It returns [ErrNoParamAccountXID] if the path has no xid and [ErrSessionWithoutUser] if the session is bound to no
// account. It returns [ErrNotFoundAccount] if the user has no such account.
func (h *RemoveAccountHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	xid := web.ParamUint[uint64](ctx, "account_xid")
	if xid == 0 {
		return ErrNoParamAccountXID
	}

	user, err := User(ctx)
	if err != nil {
		return ErrSessionWithoutUser
	}

	item, err := h.AccountReader.ReadOne(ctx, es.Account{
		AccountXID: xid,
		UserID:     user.ID,
	}, 0)
	if errors.Is(err, es.ErrNotFound) {
		return ErrNotFoundAccount
	} else if err != nil {
		return fmt.Errorf("read the authenticator account: %w", err)
	}

	_, err = h.AuthenticatorKeyWriter.WriteOne(ctx, es.AuthenticatorKey{
		Name: item.VaultKey,
	}, es.DeleteAuthenticatorKey)
	if err != nil {
		return fmt.Errorf("delete the secret from Vault: %w", err)
	}

	_, err = h.AccountGroupWriter.WriteOne(ctx, es.AccountGroup{
		User: es.User{
			ID: user.ID,
		},
		Items: []es.Account{item},
	}, es.RemoveAccount)
	if errors.Is(err, es.ErrNotFound) {
		return ErrNotFoundAccount
	} else if err != nil {
		return fmt.Errorf("delete the authenticator account: %w", err)
	}

	SetEvent(ctx, es.EventAccountRemoved, slog.Uint64("account_xid", xid))

	ctx.SetStatusCode(fasthttp.StatusNoContent)
	return nil
}
