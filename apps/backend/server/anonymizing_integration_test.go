//go:build integration

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/api"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/config"
)

// TestAnonymizingNetworkSignal proves that a login from an address in the list of VPN, proxy and hosting ranges sets
// the signal and adds its points, and that the same login without the list does not.
func TestAnonymizingNetworkSignal(t *testing.T) {
	login := func(s *stand) ai.Signals {
		email := fmt.Sprintf("vpn-%d@example.com", time.Now().UnixNano())
		session := s.open()
		s.register(session.Handle, email)
		authenticator := s.authenticator()
		if _, a := s.enrollPasskey(session.Handle, authenticator, "key"); a.Error != nil {
			t.Fatalf("enroll: %+v", a.Error)
		}
		var result api.AuthorizeResult
		s.decode(s.loginPasskey(session.Handle, email, authenticator), &result)

		return s.advisor.Last().Signals
	}

	// A list that holds every address, because the test does not depend on the address of its own requests.
	path := filepath.Join(t.TempDir(), "ranges.txt")
	if err := os.WriteFile(path, []byte("# every address\n0.0.0.0/0\n::/0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	listed := newStand(t, func(opts *config.Options) { opts.AnonymizingRanges = path })
	signals := login(listed)
	if !signals.Has(ai.SignalAnonymizingNetwork) {
		t.Fatalf("an address in the list must set the signal: %s", signals.List())
	}

	// The passkey was enrolled a moment ago, so the recent enrollment adds its 15 points to the 15 of the network.
	if signals.Score() != 30 {
		t.Fatalf("the score is 15 for the network and 15 for the enrollment, got %d for %s", signals.Score(), signals.List())
	}

	if signals := login(newStand(t)); signals.Has(ai.SignalAnonymizingNetwork) {
		t.Fatalf("without a list the signal is never set: %s", signals.List())
	}
}
