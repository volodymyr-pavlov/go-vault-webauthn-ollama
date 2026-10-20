package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// DefaultAuthenticatorMount is the path of the TOTP engine when [AuthenticatorClient.Mount] is empty.
const DefaultAuthenticatorMount = "authenticator"

var _ es.Writer[es.AuthenticatorKey] = &AuthenticatorClient{}
var _ es.Reader[es.AuthenticatorKey] = &AuthenticatorClient{}

// AuthenticatorClient uses the TOTP engine of one Vault with the token that its API client holds. The engine keeps the
// secrets, and it makes the codes inside Vault, so a secret never comes back out. It implements [es.Writer] and
// [es.Reader] for [es.AuthenticatorKey].
type AuthenticatorClient struct {
	// API is the Vault API client, with its address and token set. It is the client that [Login] keeps valid.
	API *api.Client

	// Mount is the path of the TOTP engine. Empty means [DefaultAuthenticatorMount].
	Mount string
}

// WriteOne implements [es.Writer]. With [es.WriteCreate] it stores the Secret of the item as the key Name, with the
// issuer, the label and the parameters of the item. With [es.DeleteAuthenticatorKey] it deletes the key Name. The item
// that comes back has no Secret.
//
// It returns [es.ErrNoArguments] if the Name is empty, or if op is neither a create nor a delete. A delete of a key
// that does not exist is not an error, so a caller can repeat it.
func (c *AuthenticatorClient) WriteOne(ctx context.Context, item es.AuthenticatorKey, op es.Op) (es.AuthenticatorKey, error) {
	if item.Name == "" {
		return item, es.ErrNoArguments
	}

	path := c.mount() + "/keys/" + item.Name

	switch {
	case op&es.DeleteAuthenticatorKey != 0:
		if _, err := c.API.Logical().DeleteWithContext(ctx, path); err != nil {
			return item, fmt.Errorf("delete the authenticator key: %w", err)
		}

		return item, nil
	case es.IsCreate(op):
		if item.Secret == "" {
			return item, es.ErrNoArguments
		}

		_, err := c.API.Logical().WriteWithContext(ctx, path, map[string]any{
			"generate":     false,
			"key":          item.Secret,
			"issuer":       item.Issuer,
			"account_name": item.Label,
			"algorithm":    item.Algorithm,
			"digits":       item.Digits,
			"period":       item.Period,
		})

		item.Secret = ""
		if err != nil {
			return item, fmt.Errorf("store the authenticator key: %w", err)
		}

		return item, nil
	}

	return item, es.ErrNoArguments
}

// ReadOne implements [es.Reader]. It returns the item with the Code that Vault makes for the key Name at this moment.
//
// It returns [es.ErrNoArguments] if the Name is empty and [es.ErrNotFound] if Vault has no such key.
func (c *AuthenticatorClient) ReadOne(ctx context.Context, item es.AuthenticatorKey, _ es.Op) (es.AuthenticatorKey, error) {
	if item.Name == "" {
		return item, es.ErrNoArguments
	}

	response, err := c.API.Logical().ReadWithContext(ctx, c.mount()+"/code/"+item.Name)
	if err != nil {
		var apiErr *api.ResponseError
		if errors.As(err, &apiErr) && isMissingKey(apiErr) {
			return item, es.ErrNotFound
		}

		return item, fmt.Errorf("read the authenticator code: %w", err)
	}

	if response == nil {
		return item, es.ErrNotFound
	}

	item.Code, err = field(response, "code")

	return item, err
}

// mount returns the path of the TOTP engine.
func (c *AuthenticatorClient) mount() string {
	if c.Mount == "" {
		return DefaultAuthenticatorMount
	}

	return c.Mount
}

// isMissingKey reports whether the response says that the key does not exist. The TOTP engine answers a code request
// for a missing key with status 400 and the message "unknown key", and other paths answer with 404.
func isMissingKey(response *api.ResponseError) bool {
	if response.StatusCode == http.StatusNotFound {
		return true
	}

	if response.StatusCode != http.StatusBadRequest {
		return false
	}

	for _, message := range response.Errors {
		if strings.Contains(message, "unknown key") {
			return true
		}
	}

	return false
}
