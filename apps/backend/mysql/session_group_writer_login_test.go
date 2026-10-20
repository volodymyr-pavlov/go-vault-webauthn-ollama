package mysql

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// loginFakes holds the fake stores of the login and recovery coordinators. They share one log, so a test sees the
// order of the calls across the stores.
type loginFakes struct {
	log      *callLog
	user     *groupStepTx[es.User, es.UserFlag]
	passkey  *groupStepTx[es.Passkey, es.PasskeyFlag]
	session  *groupStepTx[es.Session, es.SessionFlag]
	code     *groupStepTx[es.RecoveryCode, es.RecoveryCodeFlag]
	requests *groupStepTx[es.RecoveryRequest, es.RecoveryRequestFlag]
}

// newLoginFakes returns the fakes. The store whose name prefixes failOn, written as "<store>.<call>", fails on that
// call with err.
func newLoginFakes(failOn string, err error) loginFakes {
	log := newCallLog()
	fakes := loginFakes{
		log: log,
		user: &groupStepTx[es.User, es.UserFlag]{
			name: "user",
			log:  log,
		},
		passkey: &groupStepTx[es.Passkey, es.PasskeyFlag]{
			name: "passkey",
			log:  log,
		},
		session: &groupStepTx[es.Session, es.SessionFlag]{
			name: "session",
			log:  log,
		},
		code: &groupStepTx[es.RecoveryCode, es.RecoveryCodeFlag]{
			name: "code",
			log:  log,
		},
		requests: &groupStepTx[es.RecoveryRequest, es.RecoveryRequestFlag]{
			name:    "request",
			log:     log,
			created: es.RecoveryRequest{ID: 41},
		},
	}

	fakes.user.fail(failOn, err)
	fakes.passkey.fail(failOn, err)
	fakes.session.fail(failOn, err)
	fakes.code.fail(failOn, err)
	fakes.requests.fail(failOn, err)

	return fakes
}

func TestPasskeyLoginChallengeOpenerResetsTheSessionAndKeepsTheChallenge(t *testing.T) {
	fakes := newLoginFakes("", nil)
	opener := &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		SessionTx: fakes.session,
	}

	_, err := opener.WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{
			ID:        9,
			UserID:    3,
			Challenge: []byte{1},
		},
	}, es.OpenPasskeyLogin)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "session.replace", "session.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if got := fakes.session.received; got.UserID != 3 || got.ID != 9 || !slices.Equal(got.Challenge, []byte{1}) {
		t.Fatalf("the challenge update %+v", got)
	}
}

func TestPasskeyLoginChallengeOpenerStopsAtTheFailedStep(t *testing.T) {
	tests := []struct {
		name  string
		fail  string
		calls []string
	}{
		{
			name:  "reset",
			fail:  "session.replace",
			calls: []string{"begin", "session.replace", "rollback"},
		},
		{
			name:  "challenge",
			fail:  "session.update",
			calls: []string{"begin", "session.replace", "session.update", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes(test.fail, es.ErrNoUpdatedRows)
			opener := &SessionGroupWriter{
				Database:  newFakeDatabase(fakes.log),
				SessionTx: fakes.session,
			}

			_, err := opener.WriteOne(context.Background(), es.SessionGroup{}, es.OpenPasskeyLogin)
			if !errors.Is(err, es.ErrNoUpdatedRows) {
				t.Fatalf("got %v", err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}

func newTestLoginRefuser(fakes loginFakes) *SessionGroupWriter {
	return &SessionGroupWriter{
		Database:  newFakeDatabase(fakes.log),
		UserTx:    fakes.user,
		PasskeyTx: fakes.passkey,
		SessionTx: fakes.session,
	}
}

func TestLoginRefuserCountsTheFailuresInOneTransaction(t *testing.T) {
	tests := []struct {
		name  string
		group es.SessionGroup
		op    es.Op
		calls []string
	}{
		{
			name: "wrong code",
			group: es.SessionGroup{
				Session: es.Session{
					ID:       9,
					Failures: 2,
				},
				User: es.User{
					ID:           3,
					TOTPFailures: 1,
				},
			},
			op:    es.RefuseLogin,
			calls: []string{"begin", "user.update", "session.update", "commit"},
		},
		{
			name: "challenge and counter regression",
			group: es.SessionGroup{
				Session: es.Session{
					ID:       9,
					Failures: 2,
				},
				Passkey: es.Passkey{
					ID:    4,
					Flags: es.PasskeyFlagDisabled,
				},
			},
			op:    es.RefuseLogin | es.ConsumeChallenge,
			calls: []string{"begin", "session.update", "passkey.update", "commit"},
		},
		{
			name:  "audit only",
			group: es.SessionGroup{},
			op:    es.RefuseLogin,
			calls: []string{"begin", "commit"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes("", nil)

			_, err := newTestLoginRefuser(fakes).WriteOne(context.Background(), test.group, test.op)
			if err != nil {
				t.Fatal(err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}

		})
	}
}

func TestLoginRefuserUsesTheChallengeUpOnlyWithTheOption(t *testing.T) {
	fakes := newLoginFakes("", nil)

	_, err := newTestLoginRefuser(fakes).WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{
			ID:       9,
			Failures: 2,
		},
	}, es.RefuseLogin|es.ConsumeChallenge)
	if err != nil {
		t.Fatal(err)
	}

	if fakes.session.op&es.ConsumeChallenge == 0 || fakes.session.op&es.ClearFlag == 0 {
		t.Fatalf("the session update must consume the challenge, got %b", fakes.session.op)
	}

	if fakes.session.received.Flags != es.SessionFlagChallenge || fakes.session.received.Failures != 2 {
		t.Fatalf("the session update %+v", fakes.session.received)
	}
}

func TestLoginRefuserRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	group := es.SessionGroup{
		Session: es.Session{
			ID:       9,
			Failures: 2,
		},
		User:    es.User{ID: 3},
		Passkey: es.Passkey{ID: 4},
	}

	tests := []struct {
		name  string
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "user",
			fail:  "user.update",
			err:   errGroupStep,
			calls: []string{"begin", "user.update", "rollback"},
		},
		{
			name:  "challenge already used",
			fail:  "session.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "user.update", "session.update", "rollback"},
		},
		{
			name:  "passkey",
			fail:  "passkey.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "user.update", "session.update", "passkey.update", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes(test.fail, test.err)

			_, err := newTestLoginRefuser(fakes).WriteOne(context.Background(), group, es.RefuseLogin)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}

func TestLoginRefuserRefusesAnOpWithoutUpdate(t *testing.T) {
	fakes := newLoginFakes("", nil)

	for _, op := range []es.Op{0, es.WriteCreate} {
		if _, err := newTestLoginRefuser(fakes).WriteOne(context.Background(), es.SessionGroup{}, op); !errors.Is(err, es.ErrNoArguments) {
			t.Fatalf("op %b: got %v", op, err)
		}
	}

	if got := fakes.log.get(); len(got) != 0 {
		t.Fatalf("no call must reach the database, got %v", got)
	}
}

func newTestLoginAuthorizer(fakes loginFakes) *SessionGroupWriter {
	return &SessionGroupWriter{
		Database:          newFakeDatabase(fakes.log),
		UserTx:            fakes.user,
		PasskeyTx:         fakes.passkey,
		SessionTx:         fakes.session,
		RecoveryRequestTx: fakes.requests,
	}
}

func TestLoginAuthorizerApprovesInOneTransaction(t *testing.T) {
	fakes := newLoginFakes("", nil)

	group := es.SessionGroup{
		Session: es.Session{
			ID:        9,
			UserID:    3,
			Flags:     es.SessionFlagPasskeyApproved | es.SessionFlagAuthorized,
			RiskScore: 12,
		},
		User: es.User{
			ID:           3,
			TOTPLastStep: 8,
		},
		Passkey: es.Passkey{
			ID:        4,
			SignCount: 6,
		},
	}

	_, err := newTestLoginAuthorizer(fakes).WriteOne(context.Background(), group, es.AuthorizeLogin|es.ConsumeChallenge)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"begin",
		"user.update",
		"session.update",
		"passkey.update",
		"session.update",
		"request.replace",
		"commit",
	}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if len(fakes.session.ops) != 2 || fakes.session.ops[0]&es.ConsumeChallenge == 0 || fakes.session.ops[0]&es.ClearFlag == 0 {
		t.Fatalf("the first session update must use the challenge up, got %b", fakes.session.ops)
	}

	if fakes.session.op&es.AppendFlag == 0 || fakes.session.op&es.StoreRiskOutcome == 0 {
		t.Fatalf("the approval must append the flags and store the outcome, got %b", fakes.session.op)
	}

	if fakes.requests.received.UserID != 3 {
		t.Fatalf("the requests of the user must end, got %+v", fakes.requests.received)
	}
}

func TestLoginAuthorizerDeniesWithoutEndingTheRecoveryRequests(t *testing.T) {
	fakes := newLoginFakes("", nil)

	group := es.SessionGroup{
		Session: es.Session{
			ID:        9,
			RiskScore: 90,
		},
		User: es.User{ID: 3},
	}

	_, err := newTestLoginAuthorizer(fakes).WriteOne(context.Background(), group, es.DenyLogin)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "user.update", "session.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.session.op&es.ClearFlag == 0 || fakes.session.received.Flags != es.SessionFlagFactors {
		t.Fatalf("the denial must clear the factors, got %+v with %b", fakes.session.received, fakes.session.op)
	}
}

func TestLoginAuthorizerIgnoresAUserWithoutOpenRecoveryRequests(t *testing.T) {
	fakes := newLoginFakes("request.replace", es.ErrNoUpdatedRows)

	_, err := newTestLoginAuthorizer(fakes).WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{
			ID:     9,
			UserID: 3,
		},
	}, es.AuthorizeLogin)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "session.update", "request.replace", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func TestLoginAuthorizerRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	group := es.SessionGroup{
		Session: es.Session{
			ID:     9,
			UserID: 3,
		},
		User:    es.User{ID: 3},
		Passkey: es.Passkey{ID: 4},
	}

	tests := []struct {
		name  string
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "challenge already used",
			fail:  "session.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "user.update", "session.update", "rollback"},
		},
		{
			name:  "user",
			fail:  "user.update",
			err:   errGroupStep,
			calls: []string{"begin", "user.update", "rollback"},
		},
		{
			name:  "passkey",
			fail:  "passkey.update",
			err:   errGroupStep,
			calls: []string{"begin", "user.update", "session.update", "passkey.update", "rollback"},
		},
		{
			name:  "recovery requests",
			fail:  "request.replace",
			err:   errGroupStep,
			calls: []string{"begin", "user.update", "session.update", "passkey.update", "session.update", "request.replace", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes(test.fail, test.err)

			_, err := newTestLoginAuthorizer(fakes).WriteOne(context.Background(), group, es.AuthorizeLogin|es.ConsumeChallenge)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}

func TestLoginAuthorizerRefusesAnOpWithoutUpdate(t *testing.T) {
	fakes := newLoginFakes("", nil)

	if _, err := newTestLoginAuthorizer(fakes).WriteOne(context.Background(), es.SessionGroup{}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("got %v", err)
	}

	if got := fakes.log.get(); len(got) != 0 {
		t.Fatalf("no call must reach the database, got %v", got)
	}
}

func newTestSessionBinder(fakes loginFakes) *SessionGroupWriter {
	return &SessionGroupWriter{
		Database:          newFakeDatabase(fakes.log),
		SessionTx:         fakes.session,
		RecoveryCodeTx:    fakes.code,
		RecoveryRequestTx: fakes.requests,
	}
}

func TestSessionBinderUsesTheCodeUpBindsAndEndsTheRecoveryRequests(t *testing.T) {
	fakes := newLoginFakes("", nil)

	_, err := newTestSessionBinder(fakes).WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{
			ID:     9,
			UserID: 3,
			Flags:  es.SessionFlagRecoveryApproved,
		},
		RecoveryCode: es.RecoveryCode{MAC: "mac"},
	}, es.ApproveRecoveryCode)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"begin",
		"session.replace",
		"session.update",
		"code.update",
		"request.replace",
		"commit",
	}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	if fakes.code.received.UserID != 3 || fakes.code.received.MAC != "mac" || fakes.code.op&es.UseUpRecoveryCode == 0 {
		t.Fatalf("the code update %+v with %b", fakes.code.received, fakes.code.op)
	}
}

func TestSessionBinderForAPasswordUsesNoCodeAndEndsNoRequests(t *testing.T) {
	fakes := newLoginFakes("", nil)

	_, err := newTestSessionBinder(fakes).WriteOne(context.Background(), es.SessionGroup{
		Session: es.Session{
			ID:     9,
			UserID: 3,
			Flags:  es.SessionFlagPasswordApproved,
		},
	}, es.ApprovePassword)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"begin", "session.replace", "session.update", "commit"}

	if got := fakes.log.get(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

func TestSessionBinderRollsBackAndStopsAtTheFailedStep(t *testing.T) {
	group := es.SessionGroup{
		Session: es.Session{
			ID:     9,
			UserID: 3,
		},
		RecoveryCode: es.RecoveryCode{MAC: "mac"},
	}

	tests := []struct {
		name  string
		fail  string
		err   error
		calls []string
	}{
		{
			name:  "used code",
			fail:  "code.update",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "session.replace", "session.update", "code.update", "rollback"},
		},
		{
			name:  "reset",
			fail:  "session.replace",
			err:   es.ErrNoUpdatedRows,
			calls: []string{"begin", "session.replace", "rollback"},
		},
		{
			name:  "bind",
			fail:  "session.update",
			err:   errGroupStep,
			calls: []string{"begin", "session.replace", "session.update", "rollback"},
		},
		{
			name:  "recovery requests",
			fail:  "request.replace",
			err:   errGroupStep,
			calls: []string{"begin", "session.replace", "session.update", "code.update", "request.replace", "rollback"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakes := newLoginFakes(test.fail, test.err)

			_, err := newTestSessionBinder(fakes).WriteOne(context.Background(), group, es.ApproveRecoveryCode)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}

			if got := fakes.log.get(); !slices.Equal(got, test.calls) {
				t.Fatalf("calls %v, want %v", got, test.calls)
			}
		})
	}
}
