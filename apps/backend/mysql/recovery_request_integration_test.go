//go:build integration

package mysql

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
)

var recoveryRequestSnowflake = snowid.NewSnowflake(3, 0)

// recoveryStores bundles the recovery request stores over one database and one test clock.
type recoveryStores struct {
	clock    *clock.FixedClock
	reader   *RecoveryRequestReader
	writer   *RecoveryRequestWriter
	replacer *RecoveryRequestReplacer
	batch    *RecoveryRequestBatchReader
}

func newRecoveryStores() *recoveryStores {
	fixed := &clock.FixedClock{
		Time: time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC),
	}

	return &recoveryStores{
		clock: fixed,
		reader: &RecoveryRequestReader{
			Database: testDB,
		},
		writer: &RecoveryRequestWriter{
			Database:    testDB,
			SystemClock: fixed,
		},
		replacer: &RecoveryRequestReplacer{
			Database: testDB,
		},
		batch: &RecoveryRequestBatchReader{
			Database: testDB,
		},
	}
}

// create stores an open request of the user whose delay ends after delay. It returns the request and its cancel token.
func (r *recoveryStores) create(t *testing.T, userID uint64, delay time.Duration) (es.RecoveryRequest, []byte) {
	t.Helper()

	hash := sha256.Sum256([]byte(fmt.Sprintf("cancel-%d", recoveryRequestSnowflake.Next())))
	request, err := r.writer.WriteOne(context.Background(), es.RecoveryRequest{
		RecoveryRequestXID: recoveryRequestSnowflake.Next(),
		UserID:             userID,
		CancelHash:         hash[:],
		ReadyAt:            r.clock.Now().Add(delay),
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}

	return request, hash[:]
}

// approve approves the request the way the operator command does.
func (r *recoveryStores) approve(request es.RecoveryRequest) error {
	_, err := r.writer.WriteOne(context.Background(), es.RecoveryRequest{
		RecoveryRequestXID: request.RecoveryRequestXID,
		Flags:              es.RecoveryRequestFlagApproved,
	}, es.WriteUpdate|es.AppendFlag|es.ApproveRecoveryRequest)

	return err
}

// issue stores the hash of a grant on the request, with the given lifetime.
func (r *recoveryStores) issue(request es.RecoveryRequest, grant []byte, ttl time.Duration) error {
	_, err := r.writer.WriteOne(context.Background(), es.RecoveryRequest{
		ID:             request.ID,
		GrantHash:      grant,
		GrantExpiresAt: r.clock.Now().Add(ttl),
	}, es.WriteUpdate|es.IssueRecoveryGrant)

	return err
}

// useUp spends the grant.
func (r *recoveryStores) useUp(grant []byte) error {
	_, err := r.writer.WriteOne(context.Background(), es.RecoveryRequest{
		Flags:     es.RecoveryRequestFlagGranted,
		GrantHash: grant,
	}, es.WriteUpdate|es.AppendFlag|es.UseUpRecoveryGrant)

	return err
}

func grantHash(label string) []byte {
	hash := sha256.Sum256([]byte(fmt.Sprintf("grant-%s-%d", label, recoveryRequestSnowflake.Next())))

	return hash[:]
}

// TestRecoveryRequestCreateAndRead proves that a stored request is found by its user and by its grant hash, that the
// user lookup returns the newest open request, and that a closed request is invisible to the user lookup. A wrong
// pick would let an old or closed request decide a recovery.
func TestRecoveryRequestCreateAndRead(t *testing.T) {
	ctx := context.Background()
	r := newRecoveryStores()
	user := newUser(t, "recovery-read@example.com")

	first, _ := r.create(t, user.ID, time.Hour)
	if first.ID == 0 || !first.CreatedAt.Equal(r.clock.Now()) {
		t.Fatalf("created: %+v", first)
	}

	second, _ := r.create(t, user.ID, time.Hour)
	found, err := r.reader.ReadOne(ctx, es.RecoveryRequest{UserID: user.ID}, 0)
	if err != nil || found.ID != second.ID {
		t.Fatalf("the newest open request must win: %+v, %v", found, err)
	}

	if !found.ReadyAt.Equal(second.ReadyAt) || found.GrantExpiresAt != (time.Time{}) {
		t.Fatalf("read: %+v", found)
	}

	grant := grantHash("read")
	r.clock.Advance(time.Hour)
	if err := r.approve(second); err != nil {
		t.Fatal(err)
	}

	if err := r.issue(second, grant, 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	byGrant, err := r.reader.ReadOne(ctx, es.RecoveryRequest{GrantHash: grant}, 0)
	if err != nil || byGrant.ID != second.ID || !byGrant.GrantExpiresAt.Equal(r.clock.Now().Add(15*time.Minute)) {
		t.Fatalf("by grant hash: %+v, %v", byGrant, err)
	}

	if err := r.useUp(grant); err != nil {
		t.Fatal(err)
	}

	byGrant, err = r.reader.ReadOne(ctx, es.RecoveryRequest{GrantHash: grant}, 0)
	if err != nil || byGrant.Flags&es.RecoveryRequestFlagGranted == 0 {
		t.Fatalf("the grant lookup returns the request whatever its state: %+v, %v", byGrant, err)
	}

	found, err = r.reader.ReadOne(ctx, es.RecoveryRequest{UserID: user.ID}, 0)
	if err != nil || found.ID != first.ID {
		t.Fatalf("a closed request must not be returned: %+v, %v", found, err)
	}

	if _, err := r.reader.ReadOne(ctx, es.RecoveryRequest{GrantHash: grantHash("none")}, 0); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("unknown grant: %v", err)
	}

	if _, err := r.reader.ReadOne(ctx, es.RecoveryRequest{UserID: user.ID + 1_000_000}, 0); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	if _, err := r.reader.ReadOne(ctx, es.RecoveryRequest{}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no arguments: %v", err)
	}
}

// TestRecoveryRequestCancelOnce proves that the cancel token closes the request exactly once and that an unknown token
// changes nothing. A token that worked twice or on a closed request would let a stale email act on the user.
func TestRecoveryRequestCancelOnce(t *testing.T) {
	ctx := context.Background()
	r := newRecoveryStores()
	user := newUser(t, "recovery-cancel@example.com")
	request, cancel := r.create(t, user.ID, time.Hour)

	cancelCall := func(hash []byte) error {
		_, err := r.writer.WriteOne(ctx, es.RecoveryRequest{
			CancelHash: hash,
			Flags:      es.RecoveryRequestFlagCancelled,
		}, es.WriteUpdate|es.AppendFlag|es.CancelRecoveryRequest)

		return err
	}

	if err := cancelCall(grantHash("wrong")); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("an unknown token: %v", err)
	}

	if err := cancelCall(cancel); err != nil {
		t.Fatal(err)
	}

	if err := cancelCall(cancel); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("the second cancel: %v", err)
	}

	if _, err := r.reader.ReadOne(ctx, es.RecoveryRequest{UserID: user.ID}, 0); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("a cancelled request must not be open: %v", err)
	}

	r.clock.Advance(2 * time.Hour)
	if err := r.approve(request); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("a cancelled request must not be approved: %v", err)
	}
}

// TestRecoveryRequestApproveNeedsDelay proves that an operator can approve a request only after its delay ends, only
// while it is open, and that an unknown XID changes nothing. The delay is the time in which the owner can cancel.
func TestRecoveryRequestApproveNeedsDelay(t *testing.T) {
	r := newRecoveryStores()
	user := newUser(t, "recovery-approve@example.com")
	request, _ := r.create(t, user.ID, time.Hour)

	if err := r.approve(request); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("approve before the delay: %v", err)
	}

	r.clock.Advance(time.Hour - time.Second)
	if err := r.approve(request); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("approve one second early: %v", err)
	}

	if err := r.approve(es.RecoveryRequest{RecoveryRequestXID: recoveryRequestSnowflake.Next()}); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("approve an unknown XID: %v", err)
	}

	r.clock.Advance(time.Second)
	if err := r.approve(request); err != nil {
		t.Fatalf("approve at the end of the delay: %v", err)
	}

	found, err := r.reader.ReadOne(context.Background(), es.RecoveryRequest{UserID: user.ID}, 0)
	if err != nil || found.Flags&es.RecoveryRequestFlagApproved == 0 {
		t.Fatalf("after the approval: %+v, %v", found, err)
	}
}

// TestRecoveryRequestGrantNeedsApproval proves that a grant is issued only for an approved, open request. A grant on an
// unapproved request would skip the operator.
func TestRecoveryRequestGrantNeedsApproval(t *testing.T) {
	r := newRecoveryStores()
	user := newUser(t, "recovery-issue@example.com")
	request, _ := r.create(t, user.ID, time.Hour)
	grant := grantHash("issue")

	if err := r.issue(request, grant, time.Hour); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("issue without approval: %v", err)
	}

	r.clock.Advance(time.Hour)
	if err := r.approve(request); err != nil {
		t.Fatal(err)
	}

	if err := r.issue(request, grant, time.Hour); err != nil {
		t.Fatalf("issue after approval: %v", err)
	}

	if err := r.useUp(grantHash("unissued")); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("use up an unknown grant: %v", err)
	}
}

// TestRecoveryGrantUsedOnce proves that a grant works once, also when many callers race for it, and that it does not
// work after its expiry. Two winners would enroll two factors from one approval.
func TestRecoveryGrantUsedOnce(t *testing.T) {
	r := newRecoveryStores()
	user := newUser(t, "recovery-race@example.com")
	request, _ := r.create(t, user.ID, time.Hour)
	r.clock.Advance(time.Hour)
	if err := r.approve(request); err != nil {
		t.Fatal(err)
	}

	grant := grantHash("race")
	if err := r.issue(request, grant, 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	var wins, misses atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			switch err := r.useUp(grant); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, es.ErrNoUpdatedRows):
				misses.Add(1)
			default:
				t.Error(err)
			}
		}()
	}

	close(start)
	wg.Wait()
	if wins.Load() != 1 || misses.Load() != 19 {
		t.Fatalf("exactly one caller must win: %d wins, %d misses", wins.Load(), misses.Load())
	}

	if err := r.useUp(grant); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("a used grant: %v", err)
	}

	expired := newUser(t, "recovery-expired@example.com")
	late, _ := r.create(t, expired.ID, time.Hour)
	r.clock.Advance(time.Hour)
	if err := r.approve(late); err != nil {
		t.Fatal(err)
	}

	lateGrant := grantHash("late")
	if err := r.issue(late, lateGrant, 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	r.clock.Advance(15 * time.Minute)
	if err := r.useUp(lateGrant); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("a grant at its expiry: %v", err)
	}
}

// TestRecoveryRequestReplacerCancelsAll proves that a login-time cancel closes every open request of the user and no
// request of another user, and that it reports when there is nothing to close.
func TestRecoveryRequestReplacerCancelsAll(t *testing.T) {
	ctx := context.Background()
	r := newRecoveryStores()
	user := newUser(t, "recovery-replace@example.com")
	other := newUser(t, "recovery-replace-other@example.com")
	r.create(t, user.ID, time.Hour)
	r.create(t, user.ID, time.Hour)
	r.create(t, other.ID, time.Hour)

	if err := r.replacer.ReplaceOne(ctx, 0, es.RecoveryRequestFlagCancelled, es.RecoveryRequest{UserID: user.ID}, 0); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("without AllOfUser: %v", err)
	}

	if err := r.replacer.ReplaceOne(ctx, 0, es.RecoveryRequestFlagCancelled, es.RecoveryRequest{UserID: user.ID}, es.AllOfUser); err != nil {
		t.Fatal(err)
	}

	if _, err := r.reader.ReadOne(ctx, es.RecoveryRequest{UserID: user.ID}, 0); !errors.Is(err, es.ErrNotFound) {
		t.Fatalf("the user must have no open request: %v", err)
	}

	if _, err := r.reader.ReadOne(ctx, es.RecoveryRequest{UserID: other.ID}, 0); err != nil {
		t.Fatalf("another user must keep the request: %v", err)
	}

	if err := r.replacer.ReplaceOne(ctx, 0, es.RecoveryRequestFlagCancelled, es.RecoveryRequest{UserID: user.ID}, es.AllOfUser); !errors.Is(err, es.ErrNoUpdatedRows) {
		t.Fatalf("no open request: %v", err)
	}
}

// TestRecoveryRequestBatchReader proves that the operator list shows only open requests, oldest first, and pages
// without gaps or repeats. A closed request in the list would invite the operator to approve a dead request.
func TestRecoveryRequestBatchReader(t *testing.T) {
	ctx := context.Background()
	r := newRecoveryStores()

	// Earlier tests leave open requests behind, so the test closes them to count its own.
	if _, err := testDB.ExecContext(ctx, "UPDATE recovery_requests SET flags = flags | ?", es.RecoveryRequestFlagCancelled); err != nil {
		t.Fatal(err)
	}

	var xids []uint64
	for i := range 5 {
		user := newUser(t, fmt.Sprintf("recovery-batch-%d@example.com", i))
		request, _ := r.create(t, user.ID, time.Hour)
		xids = append(xids, request.RecoveryRequestXID)

		if i == 1 {
			_, err := r.writer.WriteOne(ctx, es.RecoveryRequest{
				RecoveryRequestXID: request.RecoveryRequestXID,
				Flags:              es.RecoveryRequestFlagCancelled,
			}, es.WriteUpdate|es.AppendFlag|es.CancelRecoveryRequest)
			if !errors.Is(err, es.ErrNoArguments) {
				t.Fatalf("cancel without a hash: %v", err)
			}

			if err := r.replacer.ReplaceOne(ctx, 0, es.RecoveryRequestFlagCancelled, request, es.AllOfUser); err != nil {
				t.Fatal(err)
			}
		}
	}

	want := []uint64{xids[0], xids[2], xids[3], xids[4]}

	all, err := r.batch.ReadAll(ctx, es.RecoveryRequest{}, es.DefaultPaginator, 0)
	if err != nil {
		t.Fatal(err)
	}

	if got := xidsOf(all); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("open requests, oldest first: got %v, want %v", got, want)
	}

	var paged []uint64
	for page := uint64(1); page <= 3; page++ {
		part, err := r.batch.ReadAll(ctx, es.RecoveryRequest{}, es.PageNumberPagination{Page: page, PageSize: 2}, 0)
		if err != nil {
			t.Fatal(err)
		}

		if page == 3 && len(part) != 0 {
			t.Fatalf("page 3 must be empty: %v", xidsOf(part))
		}

		paged = append(paged, xidsOf(part)...)
	}

	if fmt.Sprint(paged) != fmt.Sprint(want) {
		t.Fatalf("paged: got %v, want %v", paged, want)
	}
}

func xidsOf(requests []es.RecoveryRequest) []uint64 {
	xids := make([]uint64, 0, len(requests))
	for _, request := range requests {
		xids = append(xids, request.RecoveryRequestXID)
	}

	return xids
}
