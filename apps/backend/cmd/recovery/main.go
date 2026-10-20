// Command recovery lets an operator review and approve the recovery requests of users who lost every factor.
//
// A user starts a request through the API. It waits for a delay, during which the owner can cancel it. The operator
// checks the request against what the operator knows about the user, for example with a call or a video check, and then
// approves it. Only an approved request lets the owner claim a grant and enroll a new factor.
//
// Usage:
//
//	recovery [-mysql DSN] list
//	recovery [-mysql DSN] approve XID
//
// Without the flag, the command reads the DSN from the MYSQL_DSN variable.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/mysql"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintln(os.Stderr, "recovery:", err)
		os.Exit(1)
	}
}

// run parses the arguments and runs the command. It writes the result to out.
//
// It returns an error if the arguments are wrong, the database cannot be reached, or the request cannot be approved.
func run(ctx context.Context, args []string, out io.Writer) error {
	set := flag.NewFlagSet("recovery", flag.ContinueOnError)
	dsn := set.String("mysql", os.Getenv("MYSQL_DSN"), "the MySQL data source name, user:password@tcp(host:port)/database (default: the MYSQL_DSN variable)")

	if err := set.Parse(args); err != nil {
		return err
	}

	command := set.Args()
	if len(command) == 0 {
		return errNoCommand
	}

	db, err := mysql.Open(ctx, mysql.OpenOptions{
		DSN: *dsn,
	})
	if err != nil {
		return fmt.Errorf("open the database: %w", err)
	}
	defer db.Close()

	switch command[0] {
	case "list":
		reader := &mysql.RecoveryRequestBatchReader{
			Database: db,
		}

		requests, err := reader.ReadAll(ctx, es.RecoveryRequest{}, es.DefaultPaginator, 0)
		if err != nil {
			return fmt.Errorf("list the requests: %w", err)
		}

		now := time.Now()
		for _, request := range requests {
			state := "waiting"
			switch {
			case request.Flags&es.RecoveryRequestFlagApproved != 0:
				state = "approved"
			case !request.ReadyAt.After(now):
				state = "ready for approval"
			}

			fmt.Fprintf(out, "%d\tuser %d\t%s\tready at %s\n", request.RecoveryRequestXID, request.UserID, state, request.ReadyAt.UTC().Format(time.RFC3339))
		}

		return nil
	case "approve":
		if len(command) != 2 {
			return errApproveArgs
		}

		xid, err := strconv.ParseUint(command[1], 10, 64)
		if err != nil || xid == 0 {
			return fmt.Errorf("%q is not a request XID", command[1])
		}

		writer := &mysql.RecoveryRequestWriter{
			Database:    db,
			SystemClock: clock.SystemClock{},
		}

		_, err = writer.WriteOne(ctx, es.RecoveryRequest{
			RecoveryRequestXID: xid,
			Flags:              es.RecoveryRequestFlagApproved,
		}, es.WriteUpdate|es.AppendFlag|es.ApproveRecoveryRequest)
		if errors.Is(err, es.ErrNoUpdatedRows) {
			return fmt.Errorf("request %d is not open, or its delay has not ended", xid)
		} else if err != nil {
			return fmt.Errorf("approve the request: %w", err)
		}

		fmt.Fprintf(out, "request %d is approved; the owner can claim it now\n", xid)

		return nil
	}

	return fmt.Errorf("unknown command %q: use list or approve XID", command[0])
}
