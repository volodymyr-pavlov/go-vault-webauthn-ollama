package launch

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeServer is a [Server] that serves until its context ends or an error arrives on failCh. It records whether it
// shut down.
type fakeServer struct {
	failCh    chan error
	shutdown  error
	stoppedCh chan struct{}
}

func (s *fakeServer) Startup(ctx context.Context) error {
	select {
	case err := <-s.failCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *fakeServer) Shutdown(context.Context) error {
	close(s.stoppedCh)
	return s.shutdown
}

func TestServeShutsTheServerDownWhenTheContextEnds(t *testing.T) {
	server := &fakeServer{
		failCh:    make(chan error),
		stoppedCh: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() { doneCh <- Serve(ctx, quiet, server, time.Second) }()

	cancel()

	if err := <-doneCh; err != nil {
		t.Fatalf("got %v, want a clean shutdown", err)
	}

	select {
	case <-server.stoppedCh:
	default:
		t.Fatal("Shutdown was not called")
	}
}

func TestServeReturnsTheFailureOfTheServer(t *testing.T) {
	server := &fakeServer{
		failCh:    make(chan error, 1),
		stoppedCh: make(chan struct{}),
	}
	broken := errors.New("broken")
	server.failCh <- broken

	if err := Serve(context.Background(), quiet, server, time.Second); !errors.Is(err, broken) {
		t.Fatalf("got %v, want the failure", err)
	}
}

func TestServeReportsAShutdownThatIsNotClean(t *testing.T) {
	unclean := errors.New("unclean")
	server := &fakeServer{
		failCh:    make(chan error),
		shutdown:  unclean,
		stoppedCh: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Serve(ctx, quiet, server, time.Second); !errors.Is(err, unclean) {
		t.Fatalf("got %v, want the shutdown error", err)
	}
}

func TestServeTreatsAShutdownThatRanOutOfTimeAsClean(t *testing.T) {
	server := &fakeServer{
		failCh:    make(chan error),
		shutdown:  context.DeadlineExceeded,
		stoppedCh: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Serve(ctx, quiet, server, time.Second); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
}
