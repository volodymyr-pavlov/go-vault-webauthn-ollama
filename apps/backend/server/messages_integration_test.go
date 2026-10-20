//go:build integration

package server

import (
	"context"
	"sync"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Writer[es.Message] = &messageRecorder{}

// sentMessage is one message that a messageRecorder received.
type sentMessage struct {
	Message es.Message
	Op      es.Op
}

// messageRecorder keeps every message the service sends. Tests read the verification tokens and the notices from it.
type messageRecorder struct {
	mu   sync.Mutex
	sent []sentMessage
}

// WriteOne records the message and sends nothing.
func (r *messageRecorder) WriteOne(_ context.Context, item es.Message, op es.Op) (es.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sentMessage{
		Message: item,
		Op:      op,
	})
	return item, nil
}

// Sent returns a copy of every message sent so far.
func (r *messageRecorder) Sent() []sentMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sentMessage(nil), r.sent...)
}

// lastToken returns the token of the last message with the op that went to the address.
func (r *messageRecorder) lastToken(to string, op es.Op) (string, bool) {
	sent := r.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		if sent[i].Op&op != 0 && sent[i].Message.Email == to {
			return sent[i].Message.Token, true
		}
	}

	return "", false
}

// count returns how many messages with the op went to the address.
func (r *messageRecorder) count(to string, op es.Op) int {
	var n int
	for _, message := range r.Sent() {
		if message.Op&op != 0 && message.Message.Email == to {
			n++
		}
	}

	return n
}
