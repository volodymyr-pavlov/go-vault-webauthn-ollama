package api

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vault"
)

// macOf returns the Transit MAC of "purpose:value" under [MACKey], in the form that Vault returns it. The purpose
// keeps the hashes of different kinds of value apart.
func macOf(ctx context.Context, transit es.Writer[es.Transit], purpose, value string) (string, error) {
	result, err := transit.WriteOne(ctx, es.Transit{
		Key:       MACKey,
		Plaintext: []byte(purpose + ":" + value),
	}, es.WriteCreate|es.HashTheValue)
	if err != nil {
		return "", err
	}

	return result.MAC, nil
}

// macBytesOf returns the raw bytes of the Transit MAC of "purpose:value", without the version prefix of Vault.
func macBytesOf(ctx context.Context, transit es.Writer[es.Transit], purpose, value string) ([]byte, error) {
	mac, err := macOf(ctx, transit, purpose, value)
	if err != nil {
		return nil, err
	}

	_, payload, err := vault.Split(mac)
	if err != nil {
		return nil, fmt.Errorf("split the MAC: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode the MAC: %w", err)
	}

	return raw, nil
}
