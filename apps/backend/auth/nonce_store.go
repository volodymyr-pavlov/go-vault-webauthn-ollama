package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Writer[es.RequestNonce] = &NonceStore{}

// NonceStore remembers the nonces of signed requests in Redis, so every instance of the service sees them. It
// implements [es.Writer] for [es.RequestNonce].
type NonceStore struct {
	// Redis is the client of the Redis server that holds the nonces.
	Redis *redis.Client

	// TTL is how long a nonce is remembered. Zero means twice [DefaultRequestWindow], which covers a request made at
	// either end of the window.
	TTL time.Duration
}

// WriteOne implements [es.Writer]. With [es.WriteCreate] it remembers the nonce of the item for the key ID of the item
// and returns the item.
//
// It returns [es.ErrDuplicate] if the key ID used the nonce already. It returns [es.ErrNoArguments] if op is not
// [es.WriteCreate], or if the key ID or the nonce is empty.
func (s *NonceStore) WriteOne(ctx context.Context, item es.RequestNonce, op es.Op) (es.RequestNonce, error) {
	if !es.IsCreate(op) || item.KeyID == "" || item.Nonce == "" {
		return item, es.ErrNoArguments
	}

	ttl := s.TTL
	if ttl == 0 {
		ttl = 2 * DefaultRequestWindow
	}

	stored, err := s.Redis.SetNX(ctx, "nonce:"+item.KeyID+":"+item.Nonce, 1, ttl).Result()
	if err != nil {
		return item, fmt.Errorf("remember the nonce: %w", err)
	}

	if !stored {
		return item, es.ErrDuplicate
	}

	return item, nil
}
