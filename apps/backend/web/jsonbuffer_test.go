package web

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

func TestEncodeJSONMatchesMarshal(t *testing.T) {
	value := map[string]any{
		"a":    []int{1, 2},
		"html": "<b>&",
		"n":    nil,
		"s":    "é ",
	}

	want, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	got, err := EncodeJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	defer bytebufferpool.Put(got)

	if string(got.B) != string(want) {
		t.Fatalf("got %s, want %s", got.B, want)
	}
}

func TestEncodeJSONReturnsTheBufferOnAnError(t *testing.T) {
	if buf, err := EncodeJSON(math.NaN()); err == nil || buf != nil {
		t.Fatalf("an unencodable value gave %v, %v", buf, err)
	}
}

func TestWriteRawKeepsEachBodyAfterTheBufferIsReused(t *testing.T) {
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := range 500 {
				var ctx fasthttp.RequestCtx

				if err := WriteRaw(&ctx, fasthttp.StatusOK, map[string]int{
					"g": g,
					"i": i,
				}); err != nil {
					t.Error(err)
					return
				}

				if got, want := string(ctx.Response.Body()), fmt.Sprintf(`{"g":%d,"i":%d}`, g, i); got != want {
					t.Errorf("got %s, want %s", got, want)
					return
				}
			}
		}()
	}

	wg.Wait()
}

func TestWriteRawWritesNothingWhenTheValueDoesNotEncode(t *testing.T) {
	var ctx fasthttp.RequestCtx

	if err := WriteRaw(&ctx, fasthttp.StatusOK, math.NaN()); err == nil || len(ctx.Response.Body()) != 0 {
		t.Fatalf("got %v and body %q", err, ctx.Response.Body())
	}
}
