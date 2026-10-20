package snowid

import (
	"sync"
	"testing"
	"time"
)

func TestNextIsUniqueAndOrdered(t *testing.T) {
	s := NewSnowflake(7, 0)
	var prev uint64
	seen := make(map[uint64]struct{}, 10000)
	for i := range 10000 {
		id := s.Next()

		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate at %d: %d", i, id)
		}

		if id <= prev {
			t.Fatalf("not ordered at %d: %d after %d", i, id, prev)
		}

		seen[id] = struct{}{}
		prev = id
	}
}

func TestParse(t *testing.T) {
	before := time.Now().UnixMilli()
	id := NewSnowflake(9, 42).Next()
	after := time.Now().UnixMilli()
	ms, kind, instance, seq := Parse(id)
	if kind != 9 || instance != 42 || seq != 0 || ms < before || ms > after {
		t.Fatalf("Parse: %d, %d, %d, %d", ms, kind, instance, seq)
	}
}

func TestInstancesNeverCollide(t *testing.T) {
	first := NewSnowflake(1, 0)
	second := NewSnowflake(1, 1)
	seen := make(map[uint64]struct{}, 20000)
	for range 10000 {
		for _, id := range []uint64{first.Next(), second.Next()} {
			if _, dup := seen[id]; dup {
				t.Fatalf("the same identifier from two instances: %d", id)
			}

			seen[id] = struct{}{}
		}
	}
}

func TestKindLimit(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a kind above 15 must panic")
		}
	}()
	NewSnowflake(16, 0)
}

func TestInstanceLimit(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("an instance above 63 must panic")
		}
	}()
	NewSnowflake(0, 64)
}

func TestConcurrentCallsNeverRepeat(t *testing.T) {
	s := NewSnowflake(3, 1)
	const workers, each = 16, 5000
	ids := make([][]uint64, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range each {
				ids[w] = append(ids[w], s.Next())
			}
		}()
	}

	wg.Wait()
	seen := make(map[uint64]struct{}, workers*each)
	for _, list := range ids {
		for _, id := range list {
			if _, dup := seen[id]; dup {
				t.Fatalf("duplicate: %d", id)
			}

			seen[id] = struct{}{}
		}
	}
}
