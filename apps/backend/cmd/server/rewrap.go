package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/config"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// rewrap encrypts the TOTP secret of every user again with the latest version of the key, page by page. Vault Transit
// does the work, so the plaintext never leaves Vault. A secret that already has the latest version is rewrapped too,
// which does no harm.
//
// It returns an error if a page cannot be read or if a secret cannot be rewrapped or stored.
func rewrap(ctx context.Context, logger *slog.Logger, env *config.Env) error {
	done := 0
	for page := uint64(1); ; page++ {
		users, err := env.UserBatchReader.ReadAll(ctx, es.User{}, es.PageNumberPagination{
			Page:     page,
			PageSize: 100,
		}, es.HoldingTOTPSecret)
		if err != nil {
			return fmt.Errorf("read the users: %w", err)
		}

		if len(users) == 0 {
			break
		}

		for _, user := range users {
			rewrapped, err := env.TransitWriter.WriteOne(ctx, es.Transit{
				Key:        api.TOTPKey,
				Context:    api.TOTPContext(user.UserXID),
				Ciphertext: user.TOTPCiphertext,
			}, es.WriteCreate|es.RewrapTOTPSecret)
			if err != nil {
				return fmt.Errorf("rewrap the secret of user %d: %w", user.UserXID, err)
			}

			ciphertext := rewrapped.Ciphertext

			_, err = env.UserWriter.WriteOne(ctx, es.User{
				ID:             user.ID,
				TOTPCiphertext: ciphertext,
				TOTPLastStep:   user.TOTPLastStep,
				TOTPFailures:   user.TOTPFailures,
			}, es.WriteUpdate|es.ResetTOTP)
			if err != nil {
				return fmt.Errorf("store the secret of user %d: %w", user.UserXID, err)
			}

			done++
		}
	}

	logger.Info("rewrapped the TOTP secrets", "users", done)
	return nil
}
