//go:build integration

package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// policy is the Vault policy of the backend. It must match scripts/vault-policy.hcl.
const policy = `
path "transit/encrypt/totp" { capabilities = ["update"] }
path "transit/decrypt/totp" { capabilities = ["update"] }
path "transit/rewrap/totp" { capabilities = ["update"] }
path "transit/hmac/mac" { capabilities = ["update"] }
`

// startVault runs Vault in dev mode. It returns a root client and a function that removes the container.
func startVault(t *testing.T) (*api.Client, func()) {
	t.Helper()
	endpoint := os.Getenv("DOCKER_HOST")
	if home, err := os.UserHomeDir(); endpoint == "" && err == nil {
		if _, err := os.Stat(home + "/.docker/run/docker.sock"); err == nil {
			endpoint = "unix://" + home + "/.docker/run/docker.sock"
		}
	}
	pool, err := dockertest.NewPool(endpoint)
	if err != nil {
		t.Fatalf("docker is needed for the integration tests: %v", err)
	}
	pool.MaxWait = 2 * time.Minute
	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hashicorp/vault",
		Tag:        "1.21",
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=root-for-tests",
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		},
		CapAdd: []string{"IPC_LOCK"},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{
			Name: "no",
		}
	})
	if err != nil {
		t.Fatalf("start vault: %v", err)
	}
	if err := container.Expire(600); err != nil {
		t.Fatal(err)
	}
	purge := func() {
		_ = pool.Purge(container)
	}
	config := api.DefaultConfig()
	config.Address = "http://127.0.0.1:" + container.GetPort("8200/tcp")
	client, err := api.NewClient(config)
	if err != nil {
		purge()
		t.Fatal(err)
	}
	client.SetToken("root-for-tests")
	err = pool.Retry(func() error {
		health, err := client.Sys().Health()
		if err != nil {
			return err
		}
		if health.Sealed || !health.Initialized {
			return errors.New("not ready")
		}
		return nil
	})
	if err != nil {
		purge()
		t.Fatalf("wait for vault: %v", err)
	}
	return client, purge
}

// setup uses the root client to enable Transit and create the keys, the policy and the AppRole, as the init job does.
// It returns the role ID and a wrapping token.
func setup(t *testing.T, root *api.Client) (roleID, wrappingToken string) {
	t.Helper()
	ctx := context.Background()
	if err := root.Sys().MountWithContext(ctx, "transit", &api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Fatal(err)
	}
	for name, options := range map[string]map[string]any{
		"totp": {"type": "aes256-gcm96", "derived": true, "exportable": false, "allow_plaintext_backup": false},
		"mac":  {"type": "hmac", "key_size": 32, "exportable": false, "allow_plaintext_backup": false},
	} {
		if _, err := root.Logical().WriteWithContext(ctx, "transit/keys/"+name, options); err != nil {
			t.Fatalf("make the key %s: %v", name, err)
		}
	}
	if err := root.Sys().PutPolicyWithContext(ctx, "backend", policy); err != nil {
		t.Fatal(err)
	}
	if err := root.Sys().EnableAuthWithOptionsWithContext(ctx, "approle", &api.EnableAuthOptions{
		Type: "approle",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Logical().WriteWithContext(ctx, "auth/approle/role/backend", map[string]any{
		"token_policies": "backend",
		"token_ttl":      "2m",
		"token_max_ttl":  "10m",
	}); err != nil {
		t.Fatal(err)
	}
	role, err := root.Logical().ReadWithContext(ctx, "auth/approle/role/backend/role-id")
	if err != nil {
		t.Fatal(err)
	}
	roleID, _ = role.Data["role_id"].(string)
	wrapper, err := root.Clone()
	if err != nil {
		t.Fatal(err)
	}
	wrapper.SetToken("root-for-tests")
	wrapper.SetWrappingLookupFunc(func(string, string) string {
		return "5m"
	})
	wrapped, err := wrapper.Logical().WriteWithContext(ctx, "auth/approle/role/backend/secret-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped == nil || wrapped.WrapInfo == nil {
		t.Fatal("the secret ID was not wrapped")
	}
	return roleID, wrapped.WrapInfo.Token
}

func TestTransitWithRealVault(t *testing.T) {
	root, purge := startVault(t)
	defer purge()
	roleID, wrappingToken := setup(t, root)
	ctx := context.Background()

	// The backend logs in with a wrapped secret ID. Unwrapping uses the token up, so it cannot be read twice.
	backend, err := api.NewClient(root.CloneConfig())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := Login(ctx, backend, LoginOptions{
		RoleID:        roleID,
		WrappingToken: wrappingToken,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if backend.Token() == "" || backend.Token() == "root-for-tests" {
		t.Fatal("the backend must hold its own token")
	}
	again, err := api.NewClient(root.CloneConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Login(ctx, again, LoginOptions{
		RoleID:        roleID,
		WrappingToken: wrappingToken,
	}); err == nil {
		t.Fatal("a second unwrap of the same token must fail")
	}
	_ = lease

	transit := &Client{
		API: backend,
	}

	// The user is the encryption context, so a ciphertext copied to another user does not decrypt.
	user1 := []byte("user-1")
	encrypted, err := transit.WriteOne(ctx, es.Transit{
		Key:       "totp",
		Context:   user1,
		Plaintext: []byte("secret"),
	}, es.WriteCreate|es.EncryptTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted.Ciphertext, "vault:v1:") {
		t.Fatalf("ciphertext: %s", encrypted.Ciphertext)
	}
	decrypted, err := transit.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    user1,
		Ciphertext: encrypted.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if err != nil || string(decrypted.Plaintext) != "secret" {
		t.Fatalf("decrypt: %q, %v", decrypted.Plaintext, err)
	}
	_, err = transit.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("user-2"),
		Ciphertext: encrypted.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("decrypt with another context: %v, want ErrDecrypt", err)
	}

	// After the operator rotates the key, the backend rewraps. Ciphertexts of older key versions keep decrypting until
	// the operator retires that version.
	if _, err := root.Logical().WriteWithContext(ctx, "transit/keys/totp/rotate", nil); err != nil {
		t.Fatal(err)
	}
	rewrapped, err := transit.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    user1,
		Ciphertext: encrypted.Ciphertext,
	}, es.WriteCreate|es.RewrapTOTPSecret)
	if err != nil || !strings.HasPrefix(rewrapped.Ciphertext, "vault:v2:") {
		t.Fatalf("rewrap: %s, %v", rewrapped.Ciphertext, err)
	}
	decrypted, err = transit.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    user1,
		Ciphertext: rewrapped.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if err != nil || string(decrypted.Plaintext) != "secret" {
		t.Fatalf("decrypt the rewrapped: %q, %v", decrypted.Plaintext, err)
	}
	if _, err := root.Logical().WriteWithContext(ctx, "transit/keys/totp/config", map[string]any{
		"min_decryption_version": 2,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = transit.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    user1,
		Ciphertext: encrypted.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("decrypt with a retired version: %v, want ErrDecrypt", err)
	}

	// A keyed hash of the same input is always the same.
	code := es.Transit{
		Key:       "mac",
		Plaintext: []byte("code"),
	}
	first, err := transit.WriteOne(ctx, code, es.WriteCreate|es.HashTheValue)
	if err != nil || !strings.HasPrefix(first.MAC, "vault:v1:") {
		t.Fatalf("mac: %s, %v", first.MAC, err)
	}
	second, err := transit.WriteOne(ctx, code, es.WriteCreate|es.HashTheValue)
	if err != nil || second.MAC != first.MAC {
		t.Fatalf("the same input must hash the same: %s %s %v", first.MAC, second.MAC, err)
	}

	// The policy grants no export, no rotation and no read of the keys, so the backend cannot leak them.
	for _, path := range []string{"transit/export/encryption-key/totp", "transit/backup/totp"} {
		if _, err := backend.Logical().ReadWithContext(ctx, path); err == nil {
			t.Fatalf("the backend must not read %s", path)
		}
	}
	if _, err := backend.Logical().WriteWithContext(ctx, "transit/keys/totp/rotate", nil); err == nil {
		t.Fatal("the backend must not rotate keys")
	}
	if _, err := backend.Logical().ReadWithContext(ctx, "transit/keys/totp"); err == nil {
		t.Fatal("the backend must not read the TOTP key")
	}
	fmt.Fprintln(os.Stderr, "the real Vault behaves like the stand-in of vaulttest")
}
