package launch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// DefaultShutdownTimeout is the time that callers of [Serve] give a [Server] to shut down by default.
const DefaultShutdownTimeout = 5 * time.Second

// Server is a service that [Serve] starts and stops.
//
// Startup runs the service. It blocks until its context ends or the service fails.
//
// Shutdown stops the service. Work in progress may finish until the context of Shutdown ends.
type Server interface {
	Startup(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// Serve starts server and blocks until ctx ends or the server stops on its own. After ctx ends, it shuts the server
// down and waits at most shutdownTimeout.
//
// It returns nil after a clean shutdown. It returns the error of [Server.Startup] if the server fails before ctx
// ends. It returns the errors of [Server.Shutdown] and [Server.Startup] joined if the shutdown is not clean.
//
// A shutdown that runs out of time is logged and is not an error. The server did stop, but work in progress was cut
// short.
func Serve(ctx context.Context, logger *slog.Logger, server Server, shutdownTimeout time.Duration) error {
	serverCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()

	startupCh := make(chan error, 1)
	go func() {
		logger.Info("server started")
		startupCh <- server.Startup(serverCtx)
	}()

	select {
	case err := <-startupCh:
		if err != nil {
			return fmt.Errorf("server failure: %w", err)
		}

		return nil
	case <-ctx.Done():
	}

	logger.Info("shutdown started")
	shutdownCtx, release := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer release()

	shutdownErr := server.Shutdown(shutdownCtx)
	if errors.Is(shutdownErr, context.DeadlineExceeded) {
		logger.Warn("shutdown ran out of time and cut open work short", "timeout", shutdownTimeout)
		shutdownErr = nil
	}

	cancel()
	startupErr := <-startupCh
	if errors.Is(startupErr, context.Canceled) {
		startupErr = nil
	}

	if err := errors.Join(shutdownErr, startupErr); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	logger.Info("shutdown complete")
	return nil
}
