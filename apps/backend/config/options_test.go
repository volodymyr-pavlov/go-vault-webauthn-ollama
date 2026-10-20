package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func validOptions() Options {
	return Options{
		HTTPAddr:      ":8080",
		MySQLDSN:      "dsn",
		RedisAddr:     "redis:6379",
		VaultAddr:     "http://vault:8200",
		VaultRoleID:   "role",
		VaultSecretID: "secret",
		SMTPAddr:      "mailpit:1025",
		MailFrom:      "login@example.com",
		RPID:          "localhost",
		Origins:       "http://localhost:8080",
		OllamaURL:     "http://ollama:11434",
		OllamaModel:   "llama3.2:3b",
		OllamaDigest:  "abcd",
	}
}

func TestValidateAcceptsCompleteOptions(t *testing.T) {
	if err := validOptions().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesOptionsWithoutOllama(t *testing.T) {
	options := validOptions()
	options.OllamaURL = ""

	if err := options.Validate(); !errors.Is(err, ErrNoOllamaURL) {
		t.Fatalf("no address: %v, want ErrNoOllamaURL", err)
	}

	options = validOptions()
	options.OllamaDigest = ""

	if err := options.Validate(); !errors.Is(err, ErrNoOllamaModel) {
		t.Fatalf("no digest: %v, want ErrNoOllamaModel", err)
	}
}

func TestValidateLetsTheMockAdvisorSkipOllama(t *testing.T) {
	options := validOptions()
	options.OllamaURL = ""
	options.OllamaModel = ""
	options.OllamaDigest = ""
	options.Flags = FlagMockAdvisor

	if err := options.Validate(); err != nil {
		t.Fatalf("the mock advisor needs no Ollama: %v", err)
	}
}

func TestValidateRefusesBrokenSMTPSecurity(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Options)
		want   error
	}{
		{"both TLS modes", func(o *Options) { o.SMTPStartTLS, o.SMTPImplicitTLS = true, true }, ErrSMTPTLSConflict},
		{"user without password file", func(o *Options) { o.SMTPUser, o.SMTPStartTLS = "login", true }, ErrNoSMTPPassword},
		{"password file without user", func(o *Options) { o.SMTPPasswordFile, o.SMTPStartTLS = "/run/smtp", true }, ErrNoSMTPUser},
		{"user without TLS", func(o *Options) { o.SMTPUser, o.SMTPPasswordFile = "login", "/run/smtp" }, ErrSMTPAuthWithoutTLS},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := validOptions()
			test.change(&options)

			if err := options.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("%v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateAcceptsSMTPAuthOverTLS(t *testing.T) {
	options := validOptions()
	options.SMTPImplicitTLS = true
	options.SMTPUser = "login"
	options.SMTPPasswordFile = "/run/smtp"

	if err := options.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestReadSMTPPasswordTrimsTheNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")

	if err := os.WriteFile(path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readSMTPPassword(path)
	if err != nil || got != "s3cret" {
		t.Fatalf("got %q, %v", got, err)
	}

	if got, err := readSMTPPassword(""); err != nil || got != "" {
		t.Fatalf("no file: %q, %v", got, err)
	}
}

func TestReadSMTPPasswordFailsOnMissingFile(t *testing.T) {
	if _, err := readSMTPPassword(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing file must fail")
	}
}

func TestValidateRefusesSentinelsWithoutAMasterName(t *testing.T) {
	options := validOptions()
	options.RedisSentinels = []string{"sentinel-1:26379"}

	if err := options.Validate(); !errors.Is(err, ErrNoRedisMaster) {
		t.Fatalf("sentinels without a master: %v, want ErrNoRedisMaster", err)
	}

	options.RedisMaster = "main"

	if err := options.Validate(); err != nil {
		t.Fatalf("sentinels with a master: %v", err)
	}
}
