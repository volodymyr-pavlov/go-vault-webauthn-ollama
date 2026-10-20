package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

// field returns the string field name of the response. It returns an error that wraps [ErrNoField] if the field is
// missing or empty.
func field(response *api.Secret, name string) (string, error) {
	value, ok := response.Data[name].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s: %w", name, ErrNoField)
	}

	return value, nil
}
