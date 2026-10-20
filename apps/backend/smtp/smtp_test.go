package smtp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

// mailServer is a minimal SMTP server. It accepts one message at a time and keeps the DATA part that the client
// wrote.
type mailServer struct {
	addr     string
	mu       sync.Mutex
	messages []string
}

func startMailServer(t *testing.T) *mailServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})
	server := &mailServer{
		addr: listener.Addr().String(),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go server.serve(conn)
		}
	}()
	return server
}

func (m *mailServer) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	reply := func(line string) {
		_, _ = conn.Write([]byte(line + "\r\n"))
	}
	reply("220 test")
	var data strings.Builder
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				m.mu.Lock()
				m.messages = append(m.messages, data.String())
				m.mu.Unlock()
				data.Reset()
				reply("250 ok")
				continue
			}

			data.WriteString(line + "\n")
			continue
		}

		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			reply("250 test")
		case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
			reply("250 ok")
		case line == "DATA":
			inData = true
			reply("354 go")
		case line == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func (m *mailServer) Messages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.messages...)
}

func newTestSender(t *testing.T, server *mailServer) *Sender {
	t.Helper()

	client, err := NewClient(Config{
		Addr: server.addr,
		From: "login@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	sender, err := NewSender(client)
	if err != nil {
		t.Fatal(err)
	}

	return sender
}

func TestSendRegistryTokenMessage(t *testing.T) {
	server := startMailServer(t)
	sender := newTestSender(t, server)

	_, err := sender.WriteOne(context.Background(), es.Message{
		Email: "alice@example.com",
		Token: "abcd",
		TTL:   15 * time.Minute,
	}, es.WriteCreate|es.SendRegistryToken)
	if err != nil {
		t.Fatal(err)
	}

	messages := server.Messages()
	if len(messages) != 1 {
		t.Fatalf("messages: %q", messages)
	}

	for _, want := range []string{"From: login@example.com", "To: alice@example.com", "Subject: Verify your registration", "Your verification token is abcd. It is valid for 15m0s."} {
		if !strings.Contains(messages[0], want) {
			t.Fatalf("the message lacks %q: %q", want, messages[0])
		}
	}
}

func TestSendPasskeyMessageNamesThePasskey(t *testing.T) {
	server := startMailServer(t)
	sender := newTestSender(t, server)

	_, err := sender.WriteOne(context.Background(), es.Message{
		Email: "alice@example.com",
		Name:  "laptop",
	}, es.WriteCreate|es.SendPasskeyAdded)
	if err != nil {
		t.Fatal(err)
	}

	messages := server.Messages()
	if len(messages) != 1 || !strings.Contains(messages[0], "A passkey named laptop was added.") {
		t.Fatalf("messages: %q", messages)
	}
}

func TestSendRefusesAnIncompleteMessage(t *testing.T) {
	server := startMailServer(t)
	sender := newTestSender(t, server)
	ctx := context.Background()

	if _, err := sender.WriteOne(ctx, es.Message{Email: "alice@example.com"}, es.WriteCreate); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no message option: %v, want ErrNoArguments", err)
	}

	if _, err := sender.WriteOne(ctx, es.Message{Email: "alice@example.com"}, es.SendRecoveryUsed); !errors.Is(err, es.ErrNoArguments) {
		t.Fatalf("no create option: %v, want ErrNoArguments", err)
	}

	if _, err := sender.WriteOne(ctx, es.Message{}, es.WriteCreate|es.SendRecoveryUsed); !errors.Is(err, ErrNoRecipient) {
		t.Fatalf("no address: %v, want ErrNoRecipient", err)
	}

	if _, err := sender.WriteOne(ctx, es.Message{Email: "alice@example.com"}, es.WriteCreate|es.SendRegistryToken); !errors.Is(err, ErrNoToken) {
		t.Fatalf("no token: %v, want ErrNoToken", err)
	}

	_, err := sender.WriteOne(ctx, es.Message{Email: "alice@example.com\r\nBcc: eve@example.com"}, es.WriteCreate|es.SendRecoveryUsed)
	if !errors.Is(err, ErrNoRecipient) {
		t.Fatalf("a header in the address: %v, want ErrNoRecipient", err)
	}

	if len(server.Messages()) != 0 {
		t.Fatalf("a refused message must not be sent: %q", server.Messages())
	}
}

func TestNewClientNeedsAddressAndSender(t *testing.T) {
	if _, err := NewClient(Config{From: "login@example.com"}); !errors.Is(err, ErrNoAddr) {
		t.Fatalf("no address: %v", err)
	}

	if _, err := NewClient(Config{Addr: "127.0.0.1:25"}); !errors.Is(err, ErrNoFrom) {
		t.Fatalf("no sender: %v", err)
	}
}

func TestSendStopsAtTheDeadlineOfAStalledServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(5 * time.Second)
		}
	}()

	client, err := NewClient(Config{
		Addr: listener.Addr().String(),
		From: "from@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	started := time.Now()

	if err := client.SendMessage(ctx, "to@example.com", "subject", "body"); err == nil {
		t.Fatal("a stalled server must fail the send")
	}

	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the send took %s, want about the deadline of the context", elapsed)
	}
}

func TestMessageHasDateAndMessageID(t *testing.T) {
	client, err := NewClient(Config{
		Addr: "mail.example.com:25",
		From: "from@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	message, err := client.compose("to@example.com", "subject", "body")
	if err != nil {
		t.Fatal(err)
	}

	for _, header := range []string{"\r\nDate: ", "\r\nMessage-ID: <"} {
		if !strings.Contains(message, header) {
			t.Fatalf("the message lacks %q:\n%s", header, message)
		}
	}
}
