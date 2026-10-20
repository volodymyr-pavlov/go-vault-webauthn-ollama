package mysql

import (
	"errors"
	"testing"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

func newRecoveryCodeReissuer(f *enrollFakes) *UserGroupWriter {
	return &UserGroupWriter{
		Database:       newFakeDatabase(f.log),
		UserTx:         f.user,
		RecoveryCodeTx: f.code,
	}
}

func TestRecoveryCodeReissuer(t *testing.T) {
	f := newEnrollFakes()
	group := es.UserGroup{
		Codes: []es.RecoveryCode{
			{MAC: "a"},
			{MAC: "b"},
		},
	}

	if _, err := newRecoveryCodeReissuer(f).WriteOne(t.Context(), group, es.WriteUpdate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("update: %v", err)
	}

	f.failures["code.replace"] = es.ErrNoUpdatedRows

	got, err := newRecoveryCodeReissuer(f).WriteOne(t.Context(), group, es.ReissueRecoveryCodes)
	if err != nil {
		t.Fatalf("a user without codes: %v", err)
	}

	if len(got.Codes) != 2 {
		t.Fatalf("got %d codes", len(got.Codes))
	}

	f.checkCalls(t, "begin", "user.lock", "code.replace", "code.create", "code.create", "commit")
}

func TestRecoveryCodeReissuerRollsBack(t *testing.T) {
	f := newEnrollFakes()
	f.failures["code.create"] = es.ErrDuplicate

	group := es.UserGroup{
		Codes: []es.RecoveryCode{
			{MAC: "a"},
			{MAC: "b"},
		},
	}

	if _, err := newRecoveryCodeReissuer(f).WriteOne(t.Context(), group, es.ReissueRecoveryCodes); !errors.Is(err, es.ErrDuplicate) {
		t.Fatalf("got %v", err)
	}

	f.checkCalls(t, "begin", "user.lock", "code.replace", "code.create", "rollback")

	f = newEnrollFakes()
	f.failures["code.replace"] = errEnrollStep

	if _, err := newRecoveryCodeReissuer(f).WriteOne(t.Context(), group, es.ReissueRecoveryCodes); !errors.Is(err, errEnrollStep) {
		t.Fatalf("got %v", err)
	}

	f.checkCalls(t, "begin", "user.lock", "code.replace", "rollback")
}
