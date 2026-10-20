package web

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// fasthttp starts a goroutine that updates the Date header and a worker pool goroutine for each server. They
	// outlive the tests by design and are not leaks.
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.updateServerDate.func1"),
		goleak.IgnoreAnyFunction("github.com/valyala/fasthttp.(*workerPool).Start.func2"),
	)
}
