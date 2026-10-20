package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// encrypt encrypts the Plaintext of the item with its Key, derived with its Context, and sets the Ciphertext.
func (c *Client) encrypt(ctx context.Context, item es.Transit) (es.Transit, error) {
	response, err := c.write(ctx, "encrypt", item.Key, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(item.Plaintext),
		"context":   base64.StdEncoding.EncodeToString(item.Context),
	})
	if err != nil {
		return item, err
	}

	item.Ciphertext, err = field(response, "ciphertext")
	return item, err
}

// decrypt decrypts the Ciphertext of the item and sets the Plaintext.
//
// It returns [ErrDecrypt] if the ciphertext does not decrypt with this key and context.
func (c *Client) decrypt(ctx context.Context, item es.Transit) (es.Transit, error) {
	if _, _, err := Split(item.Ciphertext); err != nil {
		return item, ErrDecrypt
	}

	response, err := c.write(ctx, "decrypt", item.Key, map[string]any{
		"ciphertext": item.Ciphertext,
		"context":    base64.StdEncoding.EncodeToString(item.Context),
	})
	if err != nil {
		var apiErr *api.ResponseError
		// Transit responds with status 400 to a ciphertext that does not decrypt: a wrong context, a retired version or
		// invalid data.
		if errors.As(err, &apiErr) && apiErr.StatusCode == 400 {
			return item, ErrDecrypt
		}

		return item, err
	}

	encoded, err := field(response, "plaintext")
	if err != nil {
		return item, err
	}

	item.Plaintext, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return item, fmt.Errorf("decode the plaintext: %w", err)
	}

	return item, nil
}

// rewrap sets the Ciphertext of the item to its encryption under the latest version of the key. The plaintext never
// leaves Vault.
func (c *Client) rewrap(ctx context.Context, item es.Transit) (es.Transit, error) {
	response, err := c.write(ctx, "rewrap", item.Key, map[string]any{
		"ciphertext": item.Ciphertext,
		"context":    base64.StdEncoding.EncodeToString(item.Context),
	})
	if err != nil {
		return item, err
	}

	item.Ciphertext, err = field(response, "ciphertext")
	return item, err
}

// hash sets the MAC of the item to the HMAC-SHA256 of its Plaintext under its Key.
func (c *Client) hash(ctx context.Context, item es.Transit) (es.Transit, error) {
	response, err := c.write(ctx, "hmac", item.Key, map[string]any{
		"input":     base64.StdEncoding.EncodeToString(item.Plaintext),
		"algorithm": "sha2-256",
	})
	if err != nil {
		return item, err
	}

	item.MAC, err = field(response, "hmac")
	return item, err
}
