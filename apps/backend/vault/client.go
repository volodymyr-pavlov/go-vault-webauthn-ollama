package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// DefaultMount is the path of the Transit engine when [Client.Mount] is empty.
const DefaultMount = "transit"

var _ es.Writer[es.Transit] = &Client{}

// Client uses the Transit engine of one Vault with the token that its API client holds. [Login] keeps that token valid.
// It implements [es.Writer] for [es.Transit].
type Client struct {
	// API is the Vault API client, with its address and token set.
	API *api.Client

	// Mount is the path of the Transit engine. Empty means [DefaultMount].
	Mount string
}

// WriteOne implements [es.Writer]. With [es.WriteCreate] it runs the Transit operation that op names on the Key of the
// item, and returns the item with the output of the operation set. The operations are [es.EncryptTOTPSecret],
// [es.DecryptTOTPSecret], [es.RewrapTOTPSecret] and [es.HashTheValue].
//
// It returns [es.ErrNoArguments] if op is not [es.WriteCreate] or names no operation. For [es.DecryptTOTPSecret] it
// returns [ErrDecrypt] if the ciphertext does not decrypt with this key and context. If a response lacks a field, the
// error wraps [ErrNoField].
func (c *Client) WriteOne(ctx context.Context, item es.Transit, op es.Op) (es.Transit, error) {
	if !es.IsCreate(op) {
		return item, es.ErrNoArguments
	}

	switch {
	case op&es.EncryptTOTPSecret != 0:
		return c.encrypt(ctx, item)
	case op&es.DecryptTOTPSecret != 0:
		return c.decrypt(ctx, item)
	case op&es.RewrapTOTPSecret != 0:
		return c.rewrap(ctx, item)
	case op&es.HashTheValue != 0:
		return c.hash(ctx, item)
	}

	return item, es.ErrNoArguments
}

// write sends data to the Transit operation on key and returns the response.
func (c *Client) write(ctx context.Context, operation, key string, data map[string]any) (*api.Secret, error) {
	response, err := c.API.Logical().WriteWithContext(ctx, c.mount()+"/"+operation+"/"+key, data)
	if err != nil {
		return nil, fmt.Errorf("%s with %s: %w", operation, key, err)
	}

	if response == nil {
		return nil, fmt.Errorf("%s with %s: %w", operation, key, ErrNoField)
	}

	return response, nil
}

// mount returns the path of the Transit engine.
func (c *Client) mount() string {
	if c.Mount == "" {
		return DefaultMount
	}

	return c.Mount
}
