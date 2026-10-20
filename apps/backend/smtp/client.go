package smtp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	netsmtp "net/smtp"
	"strings"
	"time"
)

// DialTimeout is the time that a [Client] waits for the connection to the mail server.
const DialTimeout = 10 * time.Second

// SendTimeout is the longest time that a [Client] spends on one message, from the connection to the end of the
// dialogue. A shorter deadline of the context of [Client.SendMessage] wins.
const SendTimeout = 30 * time.Second

// Config holds the settings of a [Client].
type Config struct {
	// Addr is the host and port of the mail server, such as mailpit:1025.
	Addr string

	// From is the sender address of the messages.
	From string

	// StartTLS makes the client upgrade the connection with STARTTLS before it sends anything else. If the server
	// does not offer STARTTLS, the client stops and never continues in plain text. It excludes ImplicitTLS.
	StartTLS bool

	// ImplicitTLS makes the client open the connection with TLS from the first byte, as on port 465. It excludes
	// StartTLS.
	ImplicitTLS bool

	// User and Password are the credentials for SMTP AUTH PLAIN. If User is empty, the client does not authenticate.
	// The client sends them only over a TLS connection, so User needs StartTLS or ImplicitTLS.
	User     string
	Password string

	// TLSServerName is the name that the certificate of the server must match. If it is empty, the host of Addr is
	// used.
	TLSServerName string

	// RootCAs are the authorities that the client trusts for the certificate of the server. If it is nil, the roots
	// of the system are used. Tests set it; the server command does not.
	RootCAs *x509.CertPool
}

// Client sends plain-text messages to a mail server. It opens one connection for each message. [NewClient] builds it.
type Client struct {
	config Config
	host   string
}

// NewClient returns a [Client] for the server in config.
//
// It returns [ErrNoAddr] if the address of the server is empty and [ErrNoFrom] if the sender address is empty. It
// returns [ErrTLSConflict] if both StartTLS and ImplicitTLS are set, and [ErrAuthWithoutTLS] if User is set without
// either of them. It returns another error if the address of the server is not a host and port.
func NewClient(config Config) (*Client, error) {
	if config.Addr == "" {
		return nil, ErrNoAddr
	}

	if config.From == "" {
		return nil, ErrNoFrom
	}

	if config.StartTLS && config.ImplicitTLS {
		return nil, ErrTLSConflict
	}

	if config.User != "" && !config.StartTLS && !config.ImplicitTLS {
		return nil, ErrAuthWithoutTLS
	}

	host, _, err := net.SplitHostPort(config.Addr)
	if err != nil {
		return nil, fmt.Errorf("parse the address of the mail server: %w", err)
	}

	return &Client{
		config: config,
		host:   host,
	}, nil
}

// SendMessage sends a plain-text message with the given subject and body to the recipient to.
//
// It returns [ErrNoRecipient] if to is empty or contains a line break. It returns [ErrNoStartTLS] if StartTLS is set
// and the server does not offer it, and [ErrAuthWithoutTLS] if the connection is not encrypted when the client would
// authenticate. It returns another error if the connection, the authentication or the dialogue with the mail server
// fails, including a server that stops answering: the dialogue ends at the deadline of ctx or after [SendTimeout],
// whichever comes first. The errors never contain the password.
func (c *Client) SendMessage(ctx context.Context, to, subject, body string) error {
	if to == "" || strings.ContainsAny(to, "\r\n") {
		return ErrNoRecipient
	}

	conn, tlsConfig, err := c.dial(ctx)
	if err != nil {
		return err
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	client, err := netsmtp.NewClient(conn, c.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("start the dialogue with the mail server: %w", err)
	}
	defer client.Close()

	if c.config.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return ErrNoStartTLS
		}

		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("upgrade the connection with STARTTLS: %w", err)
		}
	}

	if c.config.User != "" {
		auth := plainAuth{
			user:     c.config.User,
			password: c.config.Password,
		}

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate to the mail server: %w", err)
		}
	}

	if err := client.Mail(c.config.From); err != nil {
		return fmt.Errorf("set the sender: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("set the recipient: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start the message: %w", err)
	}

	message, err := c.compose(to, subject, body)
	if err != nil {
		return err
	}

	if _, err := writer.Write([]byte(message)); err != nil {
		return fmt.Errorf("write the message: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish the message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("end the dialogue with the mail server: %w", err)
	}

	return nil
}

// dial opens the connection to the mail server and sets its deadline. It returns the TLS settings that the dialogue
// uses for STARTTLS.
func (c *Client) dial(ctx context.Context) (net.Conn, *tls.Config, error) {
	dialer := net.Dialer{
		Timeout: DialTimeout,
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: c.host,
		RootCAs:    c.config.RootCAs,
	}
	if c.config.TLSServerName != "" {
		tlsConfig.ServerName = c.config.TLSServerName
	}

	var conn net.Conn

	var err error
	if c.config.ImplicitTLS {
		conn, err = (&tls.Dialer{
			NetDialer: &dialer,
			Config:    tlsConfig,
		}).DialContext(ctx, "tcp", c.config.Addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", c.config.Addr)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("connect to the mail server: %w", err)
	}

	deadline := time.Now().Add(SendTimeout)

	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}

	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("set the deadline of the connection: %w", err)
	}

	return conn, tlsConfig, nil
}

// compose returns the text of the message with its headers, including a Date and a Message-ID.
func (c *Client) compose(to, subject, body string) (string, error) {
	id := make([]byte, 16)

	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("make the message ID: %w", err)
	}

	return "From: " + c.config.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: <" + hex.EncodeToString(id) + "@" + c.host + ">\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		body + "\r\n", nil
}

// plainAuth is the SMTP AUTH PLAIN mechanism. Unlike [netsmtp.PlainAuth], it has no exception for local servers: it
// refuses to send the credentials unless the connection uses TLS.
type plainAuth struct {
	user     string
	password string
}

// Start implements [netsmtp.Auth]. It returns [ErrAuthWithoutTLS] if the connection is not encrypted.
func (a plainAuth) Start(server *netsmtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, ErrAuthWithoutTLS
	}

	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.password), nil
}

// Next implements [netsmtp.Auth]. PLAIN has one step, so any challenge from the server is an error.
func (a plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, ErrUnexpectedChallenge
	}

	return nil, nil
}
