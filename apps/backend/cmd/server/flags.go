package main

import (
	"errors"
	"flag"
	"io"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/config"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/server"
)

// parseFlags returns the [config.Options] that args set. The flags that are not in args keep their defaults.
//
// It returns [flag.ErrHelp] after it prints the usage for -help. It returns another error if args cannot be parsed.
func parseFlags(args []string) (config.Options, error) {
	var opts config.Options
	var rewrapOnly bool
	set := flag.NewFlagSet("server", flag.ContinueOnError)
	set.StringVar(&opts.HTTPAddr, "http", ":8080", "the address of the HTTP server")
	set.StringVar(&opts.MetricsAddr, "metrics", "", "the address of the metrics server, such as :9090; empty turns the metrics off")
	set.StringVar(&opts.MySQLDSN, "mysql", "", "the MySQL data source name, user:password@tcp(host:port)/database")
	set.StringVar(&opts.RedisAddr, "redis", "127.0.0.1:6379", "the address of Redis")
	redisSentinels := set.String("redis-sentinels", "", "the addresses of the Redis Sentinel nodes, separated by commas; if set, the service follows the master of -redis-master and ignores -redis")
	set.StringVar(&opts.RedisMaster, "redis-master", "", "the name of the master that the Redis Sentinel nodes monitor")
	set.StringVar(&opts.VaultAddr, "vault", "", "the address of Vault")
	set.StringVar(&opts.VaultRoleID, "vault-role-id", "", "the AppRole role ID")
	set.StringVar(&opts.VaultRoleIDFile, "vault-role-id-file", "", "the file that holds the AppRole role ID")
	set.StringVar(&opts.VaultWrappedTokenFile, "vault-wrapped-token-file", "", "the file with the wrapping token that unwraps to the secret ID")
	set.StringVar(&opts.VaultSecretID, "vault-secret-id", "", "the AppRole secret ID itself, for tests and tools")
	set.StringVar(&opts.SMTPAddr, "smtp", "", "the address of the mail server, such as mailpit:1025")
	set.BoolVar(&opts.SMTPStartTLS, "smtp-starttls", false, "upgrade the mail connection with STARTTLS and refuse to go on in plain text; without it and -smtp-implicit-tls the connection is plain SMTP, for local stands only")
	set.BoolVar(&opts.SMTPImplicitTLS, "smtp-implicit-tls", false, "use TLS from the first byte of the mail connection, as on port 465; excludes -smtp-starttls")
	set.StringVar(&opts.SMTPUser, "smtp-user", "", "the user name for SMTP AUTH PLAIN; needs -smtp-password-file and TLS")
	set.StringVar(&opts.SMTPPasswordFile, "smtp-password-file", "", "the file that holds the SMTP password")
	set.StringVar(&opts.SMTPTLSServerName, "smtp-tls-server-name", "", "the name the certificate of the mail server must match (default the host of -smtp)")
	set.StringVar(&opts.MailFrom, "mail-from", "", "the address the messages come from")
	set.StringVar(&opts.RPID, "rp-id", "localhost", "the relying party ID of the passkeys: the domain of the service")
	set.StringVar(&opts.RPName, "rp-name", "Vault Login", "the name of the relying party")
	set.StringVar(&opts.Origins, "origins", "http://localhost:8080", "the origins allowed, separated by commas")
	set.StringVar(&opts.TrustedProxies, "trusted-proxies", "", "the address prefixes that may set X-Forwarded-For, separated by commas")
	set.StringVar(&opts.OllamaURL, "ollama", "", "the address of Ollama, such as http://ollama:11434; the server does not start without it")
	set.StringVar(&opts.OllamaModel, "ollama-model", "", "the model name and tag, such as llama3.2:3b; required")
	set.StringVar(&opts.OllamaDigest, "ollama-digest", "", "the digest the model must have; required")
	set.DurationVar(&opts.OllamaTimeout, "ollama-timeout", 0, "how long one advice may take (default 8s)")
	set.UintVar(&opts.Instance, "instance", 0, "the number of this instance, from 0 to 63; every instance that runs at the same time needs its own")
	set.DurationVar(&opts.FreshWindow, "fresh-window", api.DefaultFreshWindow, "how long after a factor passes a sensitive action may run")
	set.DurationVar(&opts.SessionIdle, "session-idle", api.DefaultIdleTimeout, "how long a session may stay without a request before it ends")
	set.DurationVar(&opts.SessionRetention, "session-retention", server.DefaultSessionRetention, "how long an expired session stays as login history before the service deletes it")
	set.DurationVar(&opts.RequestLogRetention, "request-log-retention", server.DefaultRequestLogRetention, "how long the service keeps the rows of the request log, which hold the address and the user agent, before it deletes them")
	set.DurationVar(&opts.RecoveryDelay, "recovery-delay", api.DefaultRecoveryDelay, "how long a recovery request waits before an operator can approve it")
	set.StringVar(&opts.LogLevel, "log-level", "info", "the log level: debug, info, warn or error")
	set.BoolVar(&rewrapOnly, "rewrap", false, "rewrap every stored TOTP secret with the latest key version and exit")
	set.SetOutput(io.Discard)

	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			set.SetOutput(flag.CommandLine.Output())
			set.PrintDefaults()
		}

		return config.Options{}, err
	}

	if *redisSentinels != "" {
		opts.RedisSentinels = config.SplitList(*redisSentinels)
	}

	if rewrapOnly {
		opts.Flags |= config.FlagRewrap
	}

	return opts, nil
}
