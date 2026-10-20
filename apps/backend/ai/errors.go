package ai

import "errors"

// ErrModel means that the model is not available in Ollama or has another digest than expected. [Client.Check] returns
// it.
var ErrModel = errors.New("ai: the model is not the expected one")

// ErrStatus means that Ollama answered with an HTTP status other than 200. [Client.Check] and [Client.ReadOne] wrap it
// with the status code.
var ErrStatus = errors.New("ai: unexpected status")

// ErrBreakerOpen means that the circuit breaker of the [Client] is open after repeated failures. [Client.ReadOne]
// returns it without asking the model.
var ErrBreakerOpen = errors.New("ai: the breaker is open")

// ErrBusy means that all request slots of the [Client] are in use. [Client.ReadOne] returns it without asking the
// model.
var ErrBusy = errors.New("ai: every slot is taken")

// ErrAdvice means that the response of the model breaks the rules of [ParseAdvice]. For example, it has a field that is
// not in the expected shape, a value outside its set or a summary that is too long. [ParseAdvice] wraps it with the cause. The
// [Engine] treats a refused response as no advice.
var ErrAdvice = errors.New("ai: the advice is refused")

// ErrInvalidJSON means that a response from Ollama or from the model is not valid JSON.
var ErrInvalidJSON = errors.New("ai: the response is not valid JSON")
