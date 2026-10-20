//go:build integration

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// testDB is the database for the integration tests. It is a MySQL container that TestMain starts, or the database
// that TEST_MYSQL_DSN names.
var testDB *sql.DB

// testImage is the official MySQL image for the test container. It is pinned by tag only. The deployment pins the
// same image by digest in scripts/versions.env.
const testImage = "mysql:8.4"

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	var purge func()
	if dsn == "" {
		var err error
		dsn, purge, err = startMySQL()
		if err != nil {
			log.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	db, err := Open(ctx, OpenOptions{
		DSN: dsn,
	})
	cancel()
	if err != nil {
		if purge != nil {
			purge()
		}
		log.Fatal(err)
	}
	testDB = db
	code := m.Run()
	db.Close()
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
		Tag:        testImage[len("mysql:"):],
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
