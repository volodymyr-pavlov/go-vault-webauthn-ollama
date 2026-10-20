//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
)

// testDSN is the DSN of the MySQL database for the integration tests. It points to a container that TestMain
// starts, or to the database that TEST_MYSQL_DSN names.
var testDSN string

func TestMain(m *testing.M) {
	testDSN = os.Getenv("TEST_MYSQL_DSN")
	var purge func()
	if testDSN == "" {
		var err error
		testDSN, purge, err = startMySQL()
		if err != nil {
			log.Fatal(err)
		}
	}
	code := m.Run()
	if purge != nil {
		purge()
	}
	os.Exit(code)
}

// startMySQL runs a MySQL container. It returns the DSN of an empty database and a function that removes the
// container.
func startMySQL() (dsn string, purge func(), err error) {
	// Docker Desktop on macOS keeps its socket in the home directory, not in /var/run.
	endpoint := os.Getenv("DOCKER_HOST")
	if home, err := os.UserHomeDir(); endpoint == "" && err == nil {
		if _, err := os.Stat(home + "/.docker/run/docker.sock"); err == nil {
			endpoint = "unix://" + home + "/.docker/run/docker.sock"
		}
	}
	pool, err := dockertest.NewPool(endpoint)
	if err != nil {
		return "", nil, fmt.Errorf("docker is needed for the integration tests, or TEST_MYSQL_DSN: %w", err)
	}
	if err := pool.Client.Ping(); err != nil {
		return "", nil, fmt.Errorf("docker is needed for the integration tests, or TEST_MYSQL_DSN: %w", err)
	}
	pool.MaxWait = 2 * time.Minute
	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.4",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=test",
			"MYSQL_DATABASE=test",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{
			Name: "no",
		}
	})
	if err != nil {
		return "", nil, fmt.Errorf("start mysql: %w", err)
	}
	if err := container.Expire(600); err != nil {
		return "", nil, fmt.Errorf("set the expiry of the container: %w", err)
	}
	purge = func() {
		_ = pool.Purge(container)
	}
	dsn = fmt.Sprintf("root:test@tcp(127.0.0.1:%s)/test", container.GetPort("3306/tcp"))
	err = pool.Retry(func() error {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.Ping()
	})
	if err != nil {
		purge()
		return "", nil, fmt.Errorf("wait for mysql: %w", err)
	}
	return dsn, purge, nil
}

var (
	userSnowflake    = snowid.NewSnowflake(1, 0)
	requestSnowflake = snowid.NewSnowflake(3, 0)
)

// seedRequest stores a user and an open recovery request whose delay ends after delay. The delay is measured from the
// real clock, because the command reads it.
func seedRequest(t *testing.T, delay time.Duration) es.RecoveryRequest {
	t.Helper()

	ctx := context.Background()
	db, err := mysql.Open(ctx, mysql.OpenOptions{
		DSN: testDSN,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	email := fmt.Sprintf("cmd-%d@example.com", time.Now().UnixNano())
	user, err := (&mysql.UserWriter{
		Database:    db,
		SystemClock: clock.SystemClock{},
		UpdateUserBuilder: &mysql.UpdateUserBuilder{
			QueryBuilder: mysql.NewQueryBuilder(db),
		},
	}).WriteOne(ctx, es.User{
		UserXID:      userSnowflake.Next(),
		Email:        email,
		Handle:       []byte(email + "-handle"),
		PasswordHash: "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA",
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte(email))

	request, err := (&mysql.RecoveryRequestWriter{
		Database:    db,
		SystemClock: clock.SystemClock{},
	}).WriteOne(ctx, es.RecoveryRequest{
		RecoveryRequestXID: requestSnowflake.Next(),
		UserID:             user.ID,
		CancelHash:         hash[:],
		ReadyAt:            time.Now().Add(delay),
	}, es.WriteCreate)
	if err != nil {
		t.Fatal(err)
	}

	return request
}

// list runs the list command and returns the line of the request.
func list(t *testing.T, xid uint64) string {
	t.Helper()

	var out bytes.Buffer
	if err := run(context.Background(), []string{"-mysql", testDSN, "list"}, &out); err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, fmt.Sprintf("%d\t", xid)) {
			return line
		}
	}

	t.Fatalf("request %d is not in the list: %q", xid, out.String())

	return ""
}

// TestListStates proves that the list tells the operator whether a request still waits, is ready for approval or is
// approved. A wrong state would lead the operator to approve too early or to skip a request.
func TestListStates(t *testing.T) {
	waiting := seedRequest(t, time.Hour)
	ready := seedRequest(t, -time.Minute)
	approved := seedRequest(t, -time.Minute)

	if err := run(context.Background(), []string{"-mysql", testDSN, "approve", fmt.Sprint(approved.RecoveryRequestXID)}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		request es.RecoveryRequest
		state   string
	}{
		{waiting, "\twaiting\t"},
		{ready, "\tready for approval\t"},
		{approved, "\tapproved\t"},
	} {
		if line := list(t, test.request.RecoveryRequestXID); !strings.Contains(line, test.state) {
			t.Fatalf("want state %q in %q", test.state, line)
		}
	}
}

// TestApproveRespectsDelay proves that the command refuses to approve before the delay ends and for an unknown XID,
// and approves once the delay has ended. The delay is the time in which the owner can cancel.
func TestApproveRespectsDelay(t *testing.T) {
	ctx := context.Background()
	waiting := seedRequest(t, time.Hour)

	var out bytes.Buffer
	err := run(ctx, []string{"-mysql", testDSN, "approve", fmt.Sprint(waiting.RecoveryRequestXID)}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("approve before the delay: %v, %q", err, out.String())
	}

	if line := list(t, waiting.RecoveryRequestXID); strings.Contains(line, "approved") {
		t.Fatalf("the refused request must stay unapproved: %q", line)
	}

	if err := run(ctx, []string{"-mysql", testDSN, "approve", fmt.Sprint(requestSnowflake.Next())}, &out); err == nil {
		t.Fatal("approve of an unknown XID must fail")
	}

	ready := seedRequest(t, -time.Second)
	if err := run(ctx, []string{"-mysql", testDSN, "approve", fmt.Sprint(ready.RecoveryRequestXID)}, &out); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), fmt.Sprintf("request %d is approved", ready.RecoveryRequestXID)) {
		t.Fatalf("output: %q", out.String())
	}
}

// TestBadArguments proves that the command rejects a missing command, an unknown command, a wrong XID and a wrong
// number of arguments before it changes anything.
func TestBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"-mysql", testDSN},
		{"-mysql", testDSN, "delete"},
		{"-mysql", testDSN, "approve"},
		{"-mysql", testDSN, "approve", "1", "2"},
		{"-mysql", testDSN, "approve", "abc"},
		{"-mysql", testDSN, "approve", "0"},
		{"-nosuchflag"},
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("args %q must fail", args)
		}
	}
}
