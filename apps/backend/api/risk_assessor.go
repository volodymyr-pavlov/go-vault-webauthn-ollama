package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/geo"
)

var _ es.Reader[LoginAttempt] = &RiskAssessor{}

// LoginAttempt is a login that a factor has just proved. [RiskAssessor] reads the risk of it.
type LoginAttempt struct {
	// Session is the session that the login belongs to.
	Session es.Session

	// User is the user that logs in, with its failure counters.
	User es.User

	// Passkeys are the passkeys of the user.
	Passkeys []es.Passkey

	// Factor is the set of factors that the person just proved.
	Factor es.Factors

	// Now is the time of the login.
	Now time.Time

	// Outcome is the decision on the login. [RiskAssessor.ReadOne] sets it.
	Outcome ai.Outcome
}

// RiskAssessor implements [es.Reader] of [LoginAttempt]. It turns the history of the user and of the address into
// the risk signals of a login and asks the [ai.Engine] for the decision. The summary that the engine sees holds a
// pseudonym of the user, never the user itself. The passkey and TOTP handlers share one.
type RiskAssessor struct {
	// Sessions lists the earlier sessions, which are the login history.
	Sessions es.BatchReader[es.Session]

	// Transit makes the pseudonym of the user.
	Transit es.Writer[es.Transit]

	// Engine decides on the signals.
	Engine *ai.Engine

	// Anonymizing is the list of the address ranges of VPN, proxy and hosting providers. A nil list is empty, so the
	// signal is never set.
	Anonymizing *geo.Ranges
}

// ReadOne implements [es.Reader]. It returns the attempt with Outcome set. The [Op] is not used.
//
// It returns an error if the history cannot be read or the pseudonym cannot be made.
func (r *RiskAssessor) ReadOne(ctx context.Context, a LoginAttempt, _ es.Op) (LoginAttempt, error) {
	session, user, now, passkeys := a.Session, a.User, a.Now, a.Passkeys

	// The risk signals come from the earlier sessions of the user, which are the login history, and from the user
	// record.
	history, err := r.Sessions.ReadAll(ctx, es.Session{
		UserID:    user.ID,
		CreatedAt: now.Add(-HistoryWindow),
	}, es.PageNumberPagination{
		PageSize: 200,
	}, es.LoginsSince)
	if err != nil {
		return a, fmt.Errorf("read the history: %w", err)
	}

	fromAddress, err := r.Sessions.ReadAll(ctx, es.Session{
		IP:        session.IP,
		CreatedAt: now.Add(-ai.SharedAddressWindow),
	}, es.PageNumberPagination{
		PageSize: 200,
	}, es.LoginsSince)
	if err != nil {
		return a, fmt.Errorf("read the history of the address: %w", err)
	}

	var signals ai.Signals
	failed := session.Failures
	var last es.Session
	logins := 0
	nearHour := false
	knownDevice := false
	for _, s := range history {
		if s.ID == session.ID {
			continue
		}

		if s.CreatedAt.After(now.Add(-ai.FailureWindow)) && s.Failures < math.MaxUint16-failed {
			failed += s.Failures
		}

		if s.AuthTime.IsZero() {
			continue
		}

		logins++

		if bytes.Equal(s.DeviceIDHash, session.DeviceIDHash) {
			knownDevice = true
		}

		if s.AuthTime.After(last.AuthTime) {
			last = s
		}

		hour := s.AuthTime.UTC().Hour()

		if diff := (now.UTC().Hour() - hour + 24) % 24; diff <= 2 || diff >= 22 {
			nearHour = true
		}
	}

	// The history of the address covers the longer window of the shared-address signal. Only the failures inside the
	// shorter failure window count, and every other user that tried this address counts once.
	users := map[uint64]struct{}{
		user.ID: {},
	}
	for _, s := range fromAddress {
		if s.ID == session.ID {
			continue
		}

		if s.UserID != 0 {
			users[s.UserID] = struct{}{}
		}

		if s.UserID != user.ID && s.CreatedAt.After(now.Add(-ai.FailureWindow)) && s.Failures < math.MaxUint16-failed {
			failed += s.Failures
		}
	}

	if len(users) >= ai.SharedAddressUsers {
		signals = signals.With(ai.SignalSharedAddress)
	}

	signals = signals.WithFailedAttempts(int(min(failed, ai.MaxFailedAttempts)))
	signals = signals.WithTOTPFailures(int(min(user.TOTPFailures, ai.MaxTOTPFailures)))

	// The first login of a user has no device to compare with. A device is new only if the user has logged in
	// before from other devices.
	if logins > 0 && !knownDevice {
		signals = signals.With(ai.SignalNewDevice)
	}

	if logins >= 3 && !nearHour {
		signals = signals.With(ai.SignalUnusualHour)
	}

	if last.ID != 0 && last.Country != "" && session.Country != "" {
		hours := now.Sub(last.AuthTime).Hours()
		km := geo.Distance(geo.Place{
			Latitude:  last.Latitude,
			Longitude: last.Longitude,
		}, geo.Place{
			Latitude:  session.Latitude,
			Longitude: session.Longitude,
		})
		if hours > 0 && km/hours > ai.ImpossibleSpeedKmh {
			signals = signals.With(ai.SignalImpossibleTravel)
		}
	}

	if r.Anonymizing.Contains(session.IP) {
		signals = signals.With(ai.SignalAnonymizingNetwork)
	}

	for _, p := range passkeys {
		if now.Sub(p.CreatedAt) < ai.RecentCredential {
			signals = signals.With(ai.SignalRecentEnrollment)
		}
	}

	pseudonym, err := pseudonymOf(ctx, r.Transit, user.UserXID)
	if err != nil {
		return a, err
	}

	country := session.Country
	if country == "" {
		country = "unknown"
	}

	bucket := now.UTC().Hour() / 4 * 4

	a.Outcome = r.Engine.Decide(ctx, ai.Summary{
		Pseudonym:  pseudonym,
		Country:    country,
		HourBucket: fmt.Sprintf("%02d-%02d", bucket, bucket+4),
		Factor:     a.Factor,
		Signals:    signals,
	})

	return a, nil
}

// pseudonymOf returns the pseudonym of the user: the first eight bytes of its Transit MAC, in hex. The pseudonym is
// stable for the user and tells nothing about it.
func pseudonymOf(ctx context.Context, transit es.Writer[es.Transit], userXID uint64) (string, error) {
	raw, err := macBytesOf(ctx, transit, "pseudonym", strconv.FormatUint(userXID, 10))
	if err != nil {
		return "", fmt.Errorf("make the pseudonym: %w", err)
	}

	return hex.EncodeToString(raw[:8]), nil
}
