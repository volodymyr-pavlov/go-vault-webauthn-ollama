package vaulttest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/vault"
)

func TestContextBindsCiphertext(t *testing.T) {
	ctx := context.Background()
	client := New(t).Client(t)

	encrypted, err := client.WriteOne(ctx, es.Transit{
		Key:       "totp",
		Context:   []byte("user-a"),
		Plaintext: []byte("secret"),
	}, es.WriteCreate|es.EncryptTOTPSecret)
	if err != nil || !strings.HasPrefix(encrypted.Ciphertext, "vault:v1:") {
		t.Fatalf("encrypt: %q, %v", encrypted.Ciphertext, err)
	}

	decrypted, err := client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("user-a"),
		Ciphertext: encrypted.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if err != nil || string(decrypted.Plaintext) != "secret" {
		t.Fatalf("decrypt with the same context: %q, %v", decrypted.Plaintext, err)
	}

	_, err = client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("user-b"),
		Ciphertext: encrypted.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("decrypt with another context: %v, want ErrDecrypt", err)
	}

	_, err = client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("user-a"),
		Ciphertext: "garbage",
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("decrypt garbage: %v, want ErrDecrypt", err)
	}

	if _, err := client.WriteOne(ctx, es.Transit{Key: "totp"}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no operation: %v, want ErrNoArguments", err)
	}
}

func TestRotateRewrapRetire(t *testing.T) {
	ctx := context.Background()
	server := New(t)
	client := server.Client(t)

	old, err := client.WriteOne(ctx, es.Transit{
		Key:       "totp",
		Context:   []byte("u"),
		Plaintext: []byte("s"),
	}, es.WriteCreate|es.EncryptTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}

	server.Rotate("totp")

	_, err = client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("u"),
		Ciphertext: old.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if err != nil {
		t.Fatalf("an old ciphertext must decrypt after a rotation: %v", err)
	}

	fresh, err := client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("u"),
		Ciphertext: old.Ciphertext,
	}, es.WriteCreate|es.RewrapTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}

	if version, _, err := vault.Split(fresh.Ciphertext); err != nil || version != 2 {
		t.Fatalf("rewrapped version %d, %v, want 2", version, err)
	}

	server.Retire("totp", 2)
	_, err = client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("u"),
		Ciphertext: old.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("a retired version must not decrypt: %v", err)
	}

	decrypted, err := client.WriteOne(ctx, es.Transit{
		Key:        "totp",
		Context:    []byte("u"),
		Ciphertext: fresh.Ciphertext,
	}, es.WriteCreate|es.DecryptTOTPSecret)
	if err != nil || string(decrypted.Plaintext) != "s" {
		t.Fatalf("the rewrapped ciphertext must decrypt: %q, %v", decrypted.Plaintext, err)
	}
}

func TestMACIsKeyed(t *testing.T) {
	ctx := context.Background()
	client := New(t).Client(t)
	input := es.Transit{
		Key:       "mac",
		Plaintext: []byte("code"),
	}

	first, err := client.WriteOne(ctx, input, es.WriteCreate|es.HashTheValue)
	if err != nil {
		t.Fatal(err)
	}

	again, err := client.WriteOne(ctx, input, es.WriteCreate|es.HashTheValue)
	if err != nil || again.MAC != first.MAC {
		t.Fatalf("the same input must hash the same: %q %q %v", first.MAC, again.MAC, err)
	}

	other, err := New(t).Client(t).WriteOne(ctx, input, es.WriteCreate|es.HashTheValue)
	if err != nil || other.MAC == first.MAC {
		t.Fatalf("another key must hash differently: %q, %v", other.MAC, err)
	}
}
