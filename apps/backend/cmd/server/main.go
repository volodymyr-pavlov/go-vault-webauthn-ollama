// Command server runs the login service. It supports passkeys and a password with TOTP, uses Vault Transit for secrets,
// and checks the risk of each login with rules and a local model.
//
// Ollama is a required part of the risk checks, so the command does not start without it. Run the command with -help
// to see the flags.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/config"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/launch"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/server"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

// run builds the server from the command-line arguments and runs it until the process gets an interrupt or a SIGTERM
// signal. With the -rewrap flag, it rewraps the TOTP secrets and returns instead of serving.
//
// It returns the first error that stops the server.
func run(args []string) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}

	opts.BuildVersion = version

	var level slog.Level

	if err := level.UnmarshalText([]byte(opts.LogLevel)); err != nil {
		return fmt.Errorf("log level: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})).With("version", version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env, err := config.NewEnv(ctx, logger, opts)
	if err != nil {
		return fmt.Errorf("create the environment: %w", err)
	}

	if opts.Flags&config.FlagRewrap != 0 {
		return errors.Join(rewrap(ctx, logger, env), env.Close())
	}

	srv, err := server.NewServer(opts.HTTPAddr, logger, env, opts)
	if err != nil {
		return errors.Join(fmt.Errorf("create the server: %w", err), env.Close())
	}

	logger.Info("listening", "http", opts.HTTPAddr, "rp_id", opts.RPID)
	return launch.Serve(ctx, logger, srv, launch.DefaultShutdownTimeout)
}
