package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	netsmtp "net/smtp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testUser     = "login"
	testPassword = "correct-horse-battery"
)

// testPKI returns the pool that trusts a new test authority and a certificate for localhost that the authority signed.
func testPKI(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return pool, tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}
}

// secureServer is a small ESMTP server for the TLS tests.
type secureServer struct {
	addr     string
	cert     tls.Certificate
	startTLS bool
	implicit bool

	mu       sync.Mutex
	messages int
	authSeen bool
}

func startSecureServer(t *testing.T, cert tls.Certificate, startTLS, implicit bool) *secureServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	server := &secureServer{
		addr:     listener.Addr().String(),
		cert:     cert,
		startTLS: startTLS,
		implicit: implicit,
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

func (s *secureServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	config := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS12,
	}
	encrypted := false

	if s.implicit {
		conn = tls.Server(conn, config)
		encrypted = true
	}

	reader := bufio.NewReader(conn)
	reply := func(line string) {
		_, _ = conn.Write([]byte(line + "\r\n"))
	}

	reply("220 test")

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

				s.mu.Lock()
				s.messages++
				s.mu.Unlock()
				reply("250 ok")
			}

			continue
		}

		switch {
		case strings.HasPrefix(line, "EHLO"):
			reply("250-test")

			if s.startTLS && !encrypted {
				reply("250-STARTTLS")
			}

			reply("250 AUTH PLAIN")
		case line == "STARTTLS":
			reply("220 go ahead")

			conn = tls.Server(conn, config)
			reader = bufio.NewReader(conn)
			encrypted = true
		case strings.HasPrefix(line, "AUTH PLAIN "):
			s.mu.Lock()
			s.authSeen = true
			s.mu.Unlock()

			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			if !encrypted || string(raw) != "\x00"+testUser+"\x00"+testPassword {
				reply("535 authentication failed")
				continue
			}

			reply("235 ok")
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

func (s *secureServer) state() (messages int, authSeen bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.messages, s.authSeen
}

func send(config Config) error {
	client, err := NewClient(config)
	if err != nil {
		return err
	}

	return client.SendMessage(context.Background(), "alice@example.com", "Subject", "Body")
}

func TestStartTLSSendsOverTrustedCertificate(t *testing.T) {
	pool, cert := testPKI(t)
	server := startSecureServer(t, cert, true, false)

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		StartTLS:      true,
		RootCAs:       pool,
		TLSServerName: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}

	if messages, _ := server.state(); messages != 1 {
		t.Fatalf("messages: %d, want 1", messages)
	}
}

func TestStartTLSRefusesAnUntrustedCertificate(t *testing.T) {
	_, cert := testPKI(t)
	otherPool, _ := testPKI(t)
	server := startSecureServer(t, cert, true, false)

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		StartTLS:      true,
		RootCAs:       otherPool,
		TLSServerName: "localhost",
	})
	if err == nil {
		t.Fatal("an untrusted certificate must fail")
	}

	if messages, _ := server.state(); messages != 0 {
		t.Fatalf("messages: %d, want 0", messages)
	}
}

func TestStartTLSRefusesAServerWithoutIt(t *testing.T) {
	pool, cert := testPKI(t)
	server := startSecureServer(t, cert, false, false)

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		StartTLS:      true,
		RootCAs:       pool,
		TLSServerName: "localhost",
	})
	if !errors.Is(err, ErrNoStartTLS) {
		t.Fatalf("%v, want ErrNoStartTLS", err)
	}

	if messages, _ := server.state(); messages != 0 {
		t.Fatalf("a message went out in plain text: %d", messages)
	}
}

func TestAuthIsRefusedWithoutTLS(t *testing.T) {
	_, cert := testPKI(t)
	server := startSecureServer(t, cert, true, false)

	err := send(Config{
		Addr:     server.addr,
		From:     "login@example.com",
		User:     testUser,
		Password: testPassword,
	})
	if !errors.Is(err, ErrAuthWithoutTLS) {
		t.Fatalf("%v, want ErrAuthWithoutTLS", err)
	}

	if _, authSeen := server.state(); authSeen {
		t.Fatal("the server received credentials")
	}
}

func TestPlainAuthRefusesAnUnencryptedConnection(t *testing.T) {
	auth := plainAuth{
		user:     testUser,
		password: testPassword,
	}

	if _, _, err := auth.Start(&netsmtp.ServerInfo{TLS: false}); !errors.Is(err, ErrAuthWithoutTLS) {
		t.Fatalf("%v, want ErrAuthWithoutTLS", err)
	}
}

func TestNewClientRefusesBothTLSModes(t *testing.T) {
	_, err := NewClient(Config{
		Addr:        "mail:587",
		From:        "login@example.com",
		StartTLS:    true,
		ImplicitTLS: true,
	})
	if !errors.Is(err, ErrTLSConflict) {
		t.Fatalf("%v, want ErrTLSConflict", err)
	}
}

func TestAuthPlainAfterStartTLS(t *testing.T) {
	pool, cert := testPKI(t)
	server := startSecureServer(t, cert, true, false)

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		StartTLS:      true,
		RootCAs:       pool,
		TLSServerName: "localhost",
		User:          testUser,
		Password:      testPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	if messages, authSeen := server.state(); messages != 1 || !authSeen {
		t.Fatalf("messages %d, auth %v", messages, authSeen)
	}
}

func TestWrongPasswordIsNotEchoed(t *testing.T) {
	pool, cert := testPKI(t)
	server := startSecureServer(t, cert, true, false)
	wrong := "wrong-password-value"

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		StartTLS:      true,
		RootCAs:       pool,
		TLSServerName: "localhost",
		User:          testUser,
		Password:      wrong,
	})
	if err == nil {
		t.Fatal("a wrong password must fail")
	}

	if strings.Contains(err.Error(), wrong) {
		t.Fatalf("the error echoes the password: %v", err)
	}

	if messages, _ := server.state(); messages != 0 {
		t.Fatalf("messages: %d, want 0", messages)
	}
}

func TestImplicitTLSSends(t *testing.T) {
	pool, cert := testPKI(t)
	server := startSecureServer(t, cert, false, true)

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		ImplicitTLS:   true,
		RootCAs:       pool,
		TLSServerName: "localhost",
		User:          testUser,
		Password:      testPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	if messages, authSeen := server.state(); messages != 1 || !authSeen {
		t.Fatalf("messages %d, auth %v", messages, authSeen)
	}
}

func TestTLSServerNameMustMatchTheCertificate(t *testing.T) {
	pool, cert := testPKI(t)
	server := startSecureServer(t, cert, true, false)

	err := send(Config{
		Addr:          server.addr,
		From:          "login@example.com",
		StartTLS:      true,
		RootCAs:       pool,
		TLSServerName: "mail.example.org",
	})
	if err == nil {
		t.Fatal("a wrong server name must fail")
	}
}
