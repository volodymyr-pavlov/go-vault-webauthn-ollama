//go:build integration

package mysql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
)

var testClock = &clock.FixedClock{
	Time: time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC),
}

var userSnowflake = snowid.NewSnowflake(1, 0)

var sessionSnowflake = snowid.NewSnowflake(2, 0)

func newUser(t *testing.T, email string) es.User {
	t.Helper()
	writer := &UserWriter{
		Database:    testDB,
		SystemClock: testClock,
		UpdateUserBuilder: &UpdateUserBuilder{
			QueryBuilder: NewQueryBuilder(testDB),
		},
	}
	user, err := writer.WriteOne(context.Background(), es.User{
		UserXID:      userSnowflake.Next(),
		Email:        email,
		Handle:       []byte(email + "-handle"),
		PasswordHash: "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA",
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestUserCreateReadUpdate(t *testing.T) {
	ctx := context.Background()
	reader := &UserReader{
		Database: testDB,
	}
	writer := &UserWriter{
		Database:    testDB,
		SystemClock: testClock,
		UpdateUserBuilder: &UpdateUserBuilder{
			QueryBuilder: NewQueryBuilder(testDB),
		},
	}
	created := newUser(t, "alice@example.com")
	if created.ID == 0 || created.CreatedAt != testClock.Time {
		t.Fatalf("created: %+v", created)
	}

	for _, query := range []es.User{{ID: created.ID}, {UserXID: created.UserXID}, {Email: "alice@example.com"}, {Handle: created.Handle}} {
		user, err := reader.ReadOne(ctx, query, 0)
		if err != nil || user.ID != created.ID || user.Email != "alice@example.com" {
			t.Fatalf("read by %+v: %+v, %v", query, user, err)
		}
	}
	if _, err := reader.ReadOne(ctx, es.User{Email: "nobody@example.com"}, 0); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("unknown email: %v", err)
	}
	if _, err := reader.ReadOne(ctx, es.User{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no arguments: %v", err)
	}
	if _, err := writer.WriteOne(ctx, es.User{
		UserXID:      userSnowflake.Next(),
		Email:        "alice@example.com",
		Handle:       []byte("other"),
		PasswordHash: "x",
	}, es.WriteCreate); !errors.Is(err, es.ErrDuplicate) {
		t.Fatalf("a second alice: %v", err)
	}

	_, err := writer.WriteOne(ctx, es.User{
		ID:             created.ID,
		Flags:          es.UserFlagVerified,
		TOTPCiphertext: "vault:v1:abc",
		TOTPLastStep:   42,
	}, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		t.Fatal(err)
	}
	user, err := reader.ReadOne(ctx, es.User{ID: created.ID}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if user.Flags != es.UserFlagVerified || user.TOTPCiphertext != "vault:v1:abc" || user.TOTPLastStep != 42 {
		t.Fatalf("after the update: %+v", user)
	}

	// An update skips empty values, so clearing the TOTP secret needs the ResetTOTP option.
	if _, err := writer.WriteOne(ctx, es.User{ID: created.ID, PasswordHash: "$argon2id$other"}, es.WriteUpdate); err != nil {
		t.Fatal(err)
	}
	user, _ = reader.ReadOne(ctx, es.User{ID: created.ID}, 0)
	if user.TOTPCiphertext != "vault:v1:abc" {
		t.Fatalf("an update without the option must keep the secret: %+v", user)
	}
	if _, err := writer.WriteOne(ctx, es.User{ID: created.ID}, es.WriteUpdate|es.ResetTOTP); err != nil {
		t.Fatal(err)
	}
	user, _ = reader.ReadOne(ctx, es.User{ID: created.ID}, 0)
	if user.TOTPCiphertext != "" || user.TOTPLastStep != 0 {
		t.Fatalf("after the rewrite: %+v", user)
	}
	if _, err := writer.WriteOne(ctx, es.User{ID: created.ID, Flags: es.UserFlagVerified}, es.WriteUpdate|es.ClearFlag); err != nil {
		t.Fatal(err)
	}
	user, _ = reader.ReadOne(ctx, es.User{ID: created.ID}, 0)
	if user.Flags != 0 {
		t.Fatalf("after the clear: %+v", user.Flags)
	}
	if _, err := writer.WriteOne(ctx, es.User{ID: 999999, Email: "x@example.com"}, es.WriteUpdate); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("an update of a missing user: %v", err)
	}
}

func TestUserTxLock(t *testing.T) {
	ctx := context.Background()
	created := newUser(t, "lock@example.com")
	store := &UserTx{
		UpdateUserBuilder: &UpdateUserBuilder{
			QueryBuilder: NewQueryBuilder(testDB),
		},
	}
	tx, err := testDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.LockOneTx(tx, es.User{ID: created.ID})
	if err != nil || user.Email != "lock@example.com" {
		t.Fatalf("lock: %+v, %v", user, err)
	}
	if err := store.UpdateOneTx(tx, es.User{ID: created.ID, Flags: es.UserFlagTOTPConfirmed}, es.WriteUpdate|es.AppendFlag); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	user, err = (&UserReader{Database: testDB}).ReadOne(ctx, es.User{ID: created.ID}, 0)
	if err != nil || user.Flags != es.UserFlagTOTPConfirmed {
		t.Fatalf("after the commit: %+v, %v", user, err)
	}
}

func TestUsersWithTOTP(t *testing.T) {
	ctx := context.Background()
	with := newUser(t, "with-totp@example.com")
	newUser(t, "without-totp@example.com")
	writer := &UserWriter{
		Database:    testDB,
		SystemClock: testClock,
		UpdateUserBuilder: &UpdateUserBuilder{
			QueryBuilder: NewQueryBuilder(testDB),
		},
	}
	if _, err := writer.WriteOne(ctx, es.User{ID: with.ID, TOTPCiphertext: "vault:v1:x"}, es.WriteUpdate); err != nil {
		t.Fatal(err)
	}
	users, err := (&UserBatchReader{Database: testDB}).ReadAll(ctx, es.User{}, es.DefaultPaginator, es.HoldingTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, user := range users {
		if user.Email == "without-totp@example.com" {
			t.Fatal("a user without a secret was listed")
		}
		if user.ID == with.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("the user with a secret was not listed")
	}
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	user := newUser(t, "session@example.com")
	reader := &SessionReader{
		Database: testDB,
	}
	writer := &SessionWriter{
		Database:    testDB,
		SystemClock: testClock,
		UpdateSessionBuilder: &UpdateSessionBuilder{
			QueryBuilder: NewQueryBuilder(testDB),
		},
	}
	ip := netip.MustParseAddr("203.0.113.9")
	created, err := writer.WriteOne(ctx, es.Session{
		SessionXID:   sessionSnowflake.Next(),
		Flags:        es.SessionFlagStarted,
		DeviceIDHash: []byte("device"),
		IP:           ip,
		Country:      "DE",
		Latitude:     52.5,
		Longitude:    13.4,
		ExpiresAt:    testClock.Time.Add(24 * time.Hour),
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}
	session, err := reader.ReadOne(ctx, es.Session{SessionXID: created.SessionXID}, 0)
	if err != nil || session.ID != created.ID || session.IP != ip || session.UserID != 0 || !session.AuthTime.IsZero() {
		t.Fatalf("read: %+v, %v", session, err)
	}

	// A verification token is stored, then consumed by an update that clears it.
	hash := sha256.Sum256([]byte("token"))
	_, err = writer.WriteOne(ctx, es.Session{
		ID:              created.ID,
		Flags:           es.SessionFlagRegistryBegun,
		VerifyHash:      hash[:],
		VerifyExpiresAt: testClock.Time.Add(time.Hour),
	}, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		t.Fatal(err)
	}
	session, _ = reader.ReadOne(ctx, es.Session{ID: created.ID}, 0)
	if string(session.VerifyHash) != string(hash[:]) || session.VerifyExpiresAt.IsZero() || session.Flags != es.SessionFlagStarted|es.SessionFlagRegistryBegun {
		t.Fatalf("with the token: %+v", session)
	}
	_, err = writer.WriteOne(ctx, es.Session{
		ID:       created.ID,
		UserID:   user.ID,
		Flags:    es.SessionFlagRegistryVerified,
		AuthTime: testClock.Time,
	}, es.WriteUpdate|es.AppendFlag|es.ClearVerifyToken)
	if err != nil {
		t.Fatal(err)
	}
	session, _ = reader.ReadOne(ctx, es.Session{ID: created.ID}, 0)
	if len(session.VerifyHash) != 0 || !session.VerifyExpiresAt.IsZero() || session.UserID != user.ID || !session.AuthTime.Equal(testClock.Time) {
		t.Fatalf("after the verification: %+v", session)
	}

	// A challenge works once. The second update matches no row.
	_, err = writer.WriteOne(ctx, es.Session{
		ID:                 created.ID,
		Flags:              es.SessionFlagChallengeLogin,
		Challenge:          []byte("challenge"),
		ChallengeExpiresAt: testClock.Time.Add(2 * time.Minute),
	}, es.WriteUpdate|es.AppendFlag)
	if err != nil {
		t.Fatal(err)
	}
	consume := es.Session{
		ID:    created.ID,
		Flags: es.SessionFlagChallenge,
	}
	if _, err := writer.WriteOne(ctx, consume, es.WriteUpdate|es.ClearFlag|es.ConsumeChallenge); err != nil {
		t.Fatalf("the first consumption: %v", err)
	}
	if _, err := writer.WriteOne(ctx, consume, es.WriteUpdate|es.ClearFlag|es.ConsumeChallenge); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("the second consumption: %v, want ErrNoUpdatedRows", err)
	}
	session, _ = reader.ReadOne(ctx, es.Session{ID: created.ID}, 0)
	if len(session.Challenge) != 0 || session.Flags&es.SessionFlagChallenge != 0 {
		t.Fatalf("after the consumption: %+v", session)
	}

	// The sessions of a user and of an address form the login history.
	sessions, err := (&SessionBatchReader{Database: testDB}).ReadAll(ctx, es.Session{UserID: user.ID}, es.DefaultPaginator, 0)
	if err != nil || len(sessions) != 1 || sessions[0].ID != created.ID {
		t.Fatalf("by user: %d, %v", len(sessions), err)
	}
	sessions, err = (&SessionBatchReader{Database: testDB}).ReadAll(ctx, es.Session{
		IP:        ip,
		CreatedAt: testClock.Time.Add(time.Minute),
	}, es.DefaultPaginator, es.LoginsSince)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("by address since later: %d, %v", len(sessions), err)
	}
	sessions, err = (&SessionBatchReader{Database: testDB}).ReadAll(ctx, es.Session{
		IP:        ip,
		CreatedAt: testClock.Time,
	}, es.DefaultPaginator, es.LoginsSince)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("by address since now: %d, %v", len(sessions), err)
	}

	// Revocation by owner ends every session of the user.
	replacer := &SessionReplacer{
		Database: testDB,
	}
	if err := replacer.ReplaceOne(ctx, es.SessionFlagAuthorized, es.SessionFlagRevoked, es.Session{UserID: user.ID}, es.AllOfUser); err != nil {
		t.Fatal(err)
	}
	session, _ = reader.ReadOne(ctx, es.Session{ID: created.ID}, 0)
	if session.Flags&es.SessionFlagRevoked == 0 || session.Active(testClock.Time, 0) {
		t.Fatalf("after the revocation: %+v", session)
	}
}

func TestPasskeyCreateReadUpdate(t *testing.T) {
	ctx := context.Background()
	user := newUser(t, "passkey@example.com")
	reader := &PasskeyReader{
		Database: testDB,
	}
	writer := &PasskeyWriter{
		Database:    testDB,
		SystemClock: testClock,
		UpdatePasskeyBuilder: &UpdatePasskeyBuilder{
			QueryBuilder: NewQueryBuilder(testDB),
		},
	}
	created, err := writer.WriteOne(ctx, es.Passkey{
		PasskeyXID:   snowid.NewSnowflake(3, 0).Next(),
		Flags:        es.PasskeyFlagUserVerified | es.PasskeyFlagBackupEligible,
		UserID:       user.ID,
		CredentialID: []byte{1, 2, 3},
		PublicKey:    []byte{4, 5, 6},
		Transports:   es.TransportInternal,
		Name:         "phone",
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []es.Passkey{{ID: created.ID}, {PasskeyXID: created.PasskeyXID}, {CredentialID: []byte{1, 2, 3}}} {
		passkey, err := reader.ReadOne(ctx, query, 0)
		if err != nil || passkey.ID != created.ID || passkey.Name != "phone" || passkey.UserID != user.ID {
			t.Fatalf("read by %+v: %+v, %v", query, passkey, err)
		}
	}
	if _, err := writer.WriteOne(ctx, es.Passkey{
		PasskeyXID:   snowid.NewSnowflake(3, 0).Next(),
		UserID:       user.ID,
		CredentialID: []byte{1, 2, 3},
		PublicKey:    []byte{9},
	}, es.WriteCreate); !errors.Is(err, es.ErrDuplicate) {
		t.Fatalf("the same credential ID twice: %v", err)
	}
	if _, err := writer.WriteOne(ctx, es.Passkey{
		ID:        created.ID,
		Flags:     es.PasskeyFlagDisabled,
		SignCount: 12,
	}, es.WriteUpdate|es.AppendFlag); err != nil {
		t.Fatal(err)
	}
	passkeys, err := (&PasskeyBatchReader{Database: testDB}).ReadAll(ctx, es.Passkey{UserID: user.ID}, es.DefaultPaginator, 0)
	if err != nil || len(passkeys) != 1 {
		t.Fatalf("by user: %d, %v", len(passkeys), err)
	}
	if passkeys[0].SignCount != 12 || !passkeys[0].Present() || passkeys[0].Usable() {
		t.Fatalf("after the update: %+v", passkeys[0])
	}
}

func TestRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	user := newUser(t, "recovery@example.com")
	other := newUser(t, "recovery-other@example.com")
	batch := &RecoveryCodeBatchWriter{
		Database:    testDB,
		SystemClock: testClock,
	}
	writer := &RecoveryCodeWriter{
		Database: testDB,
	}
	replacer := &RecoveryCodeReplacer{
		Database: testDB,
	}
	snowflake := snowid.NewSnowflake(4, 0)
	set := []es.RecoveryCode{
		{RecoveryCodeXID: snowflake.Next(), UserID: user.ID, MAC: "vault:v1:first"},
		{RecoveryCodeXID: snowflake.Next(), UserID: user.ID, MAC: "vault:v1:second"},
	}
	if err := batch.WriteAll(ctx, 0, 0, set, 0); err != nil {
		t.Fatal(err)
	}
	if err := batch.WriteAll(ctx, 0, 0, set[:1], 0); !errors.Is(err, es.ErrDuplicate) {
		t.Fatalf("the same hash twice: %v", err)
	}

	// A recovery code works once and only for its own user.
	use := es.RecoveryCode{UserID: user.ID, MAC: "vault:v1:first", Flags: es.RecoveryCodeFlagUsed}
	if _, err := writer.WriteOne(ctx, use, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryCode); err != nil {
		t.Fatalf("the first use: %v", err)
	}
	if _, err := writer.WriteOne(ctx, use, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryCode); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("the second use: %v, want ErrNoUpdatedRows", err)
	}
	use.UserID = other.ID
	use.MAC = "vault:v1:second"
	if _, err := writer.WriteOne(ctx, use, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryCode); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("a code of another user: %v, want ErrNoUpdatedRows", err)
	}
	if _, err := writer.WriteOne(ctx, use, es.WriteUpdate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("an update that does not say which code: %v, want ErrNoArguments", err)
	}

	// A new set of recovery codes retires the unused codes of the previous set.
	if err := replacer.ReplaceOne(ctx, 0, es.RecoveryCodeFlagUsed, es.RecoveryCode{UserID: user.ID}, es.AllOfUser); err != nil {
		t.Fatal(err)
	}
	use.UserID = user.ID
	if _, err := writer.WriteOne(ctx, use, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryCode); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("a retired code: %v, want ErrNoUpdatedRows", err)
	}
	if err := replacer.ReplaceOne(ctx, 0, es.RecoveryCodeFlagUsed, es.RecoveryCode{UserID: user.ID}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("a replace without AllOfUser: %v, want ErrNoArguments", err)
	}
}

// TestMigrateRunsOnceWhenInstancesStartTogether proves that several instances that call Migrate at the same time all
// succeed and leave the migration lock free.
func TestMigrateRunsOnceWhenInstancesStartTogether(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 6)

	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Migrate(context.Background(), testDB)
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("a parallel migrate failed: %v", err)
		}
	}

	var free sql.NullInt64
	if err := testDB.QueryRow("SELECT IS_FREE_LOCK(?)", migrationLock).Scan(&free); err != nil {
		t.Fatal(err)
	}

	if free.Int64 != 1 {
		t.Fatal("the migration lock must be free after the migrations")
	}
}
