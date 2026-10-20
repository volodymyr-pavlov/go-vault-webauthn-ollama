package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/ai"
)

func TestAnswerOfSortsTheOutcomeOfARequest(t *testing.T) {
	if got := answerOf(false, nil, time.Second); got.Kind != answerAdvised {
		t.Errorf("advice that does not raise: %+v", got)
	}

	if got := answerOf(true, nil, time.Second); got.Kind != answerRaised {
		t.Errorf("advice that raises: %+v", got)
	}

	if got := answerOf(false, errors.New("connection reset"), time.Second); got.Kind != answerFailed || got.Cause != "connection reset" {
		t.Errorf("a failed request: %+v", got)
	}

	refusal := ai.ErrAdvice

	if got := answerOf(false, refusal, time.Second); got.Kind != answerRefused {
		t.Errorf("a refused response: %+v", got)
	}
}

func TestProgressSurvivesACutRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evaluation.md.progress")

	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	for id, kind := range map[int]string{
		1: answerAdvised,
		2: answerRaised,
		3: answerFailed,
	} {
		if err := saveAnswer(file, id, answer{
			Kind:    kind,
			Latency: time.Duration(id) * time.Second,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A cut can leave half a line at the end.
	if _, err := file.WriteString(`{"id":4,"kind":"adv`); err != nil {
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	done, err := loadProgress(path, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(done) != 3 || done[2].Kind != answerRaised || done[3].Latency != 3*time.Second {
		t.Fatalf("three answers expected, got %+v", done)
	}

	// Without -resume the file starts empty, and a missing file is an empty run.
	if fresh, err := loadProgress(path, false); err != nil || len(fresh) != 0 {
		t.Fatalf("a fresh run: %v %v", fresh, err)
	}

	if raw, err := os.ReadFile(filepath.Clean(path)); err != nil || len(raw) != 0 {
		t.Fatalf("the file must be empty after a fresh start: %q %v", raw, err)
	}

	if missing, err := loadProgress(filepath.Join(t.TempDir(), "none"), true); err != nil || len(missing) != 0 {
		t.Fatalf("a missing file: %v %v", missing, err)
	}
}
