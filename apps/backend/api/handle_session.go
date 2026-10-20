package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/clock"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/geo"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/metrics"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/snowid"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/validate"
	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

var _ web.Handler = &BeginSessionHandler{}
var _ web.Handler = &RetrieveSessionHandler{}
var _ web.Handler = &TerminateSessionHandler{}

var beginSessionHandlerBodyArgsPool web.Pool[BeginSessionHandlerBodyArgs]

const (
	// DefaultSessionTTL is the default time a session lasts. After it, the device must open a new session and log in
	// again.
	DefaultSessionTTL = 30 * 24 * time.Hour

	// MACKey is the name of the Transit key that makes the keyed hashes of device identifiers, recovery codes,
	// pseudonyms and stand-in handles.
	MACKey = "mac"
)

// SessionResult is the response of POST /session. It holds the external ID of the new session and the time the session
// ends. The session has no token: the device signs every request instead.
type SessionResult struct {
	SessionXID uint64    `json:"session_xid,string"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// BeginSessionHandlerBodyArgs are the arguments of POST /session. DeviceID identifies the device. DeviceKey is the
// Ed25519 public key of the device in standard base64.
type BeginSessionHandlerBodyArgs struct {
	DeviceID  string `json:"device_id"`
	DeviceKey string `json:"device_key"`

	key []byte
}

// DecodeJSON implements [web.JSONDecoder]. It returns [web.ErrUnknownBody] for a member that the arguments do not have.
func (a *BeginSessionHandlerBodyArgs) DecodeJSON(value gjson.Result) error {
	return web.VisitObject(value, func(key string, member gjson.Result) error {
		var err error
		switch key {
		case "device_id":
			a.DeviceID, err = web.JSONString(member)
		case "device_key":
			a.DeviceKey, err = web.JSONString(member)
		default:
			err = web.ErrUnknownBody
		}
		return err
	})
}

// Validate checks the arguments and decodes the device key.
//
// It returns [ErrNoBodyDeviceID] or [ErrMaxLenBodyDeviceID] if the device ID is empty or too long. It returns
// [ErrNoBodyDeviceKey] or [ErrMalformedBodyDeviceKey] if the device key is empty or not an Ed25519 public key in
// base64.
func (a *BeginSessionHandlerBodyArgs) Validate() error {
	a.DeviceID = strings.TrimSpace(a.DeviceID)

	deviceID := validate.Validate{
		Input: a.DeviceID,
		Max:   validate.MaxDeviceIDLength,
	}
	if deviceID.IsEmpty() {
		return ErrNoBodyDeviceID
	}

	if deviceID.TooLong() {
		return ErrMaxLenBodyDeviceID
	}

	if a.DeviceKey == "" {
		return ErrNoBodyDeviceKey
	}

	key, err := base64.StdEncoding.DecodeString(a.DeviceKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return ErrMalformedBodyDeviceKey
	}

	a.key = key

	return nil
}

// BeginSessionHandler handles POST /session. It opens a session for a device with no factor passed yet. Every flow
// starts here.
//
// The request carries the public key of the device and is signed with the private key, which proves that the device
// holds it. The session keeps the key and the SHA-256 hash of the key as its key ID. Later requests are signed in the
// same way and name the key ID, so the session needs no token. If the device opens a new session with the same key, the
// requests that name the key reach the newest session.
type BeginSessionHandler struct {
	SessionWriter    es.Writer[es.Session]
	SessionSnowflake *snowid.Snowflake
	TransitWriter    es.Writer[es.Transit]
	RequestVerifier  es.Reader[es.SignedRequest]
	Locator          *geo.Locator
	SystemClock      clock.Clock

	// SessionTTL is how long the session lasts. Zero means [DefaultSessionTTL].
	SessionTTL time.Duration
}

// ServeHTTP implements [web.Handler]. It responds with status 201 and the new session.
//
// It returns [ErrNoHeaderRequestSignature] or [ErrInvalidRequestSignature] if the request is not signed with the key in
// the body.
func (h *BeginSessionHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	bodyArgs := beginSessionHandlerBodyArgsPool.Get()
	defer beginSessionHandlerBodyArgsPool.Put(bodyArgs)

	if err := web.Unmarshal(ctx, bodyArgs); err != nil {
		return err
	}

	if err := bodyArgs.Validate(); err != nil {
		return err
	}

	if err := verifySignature(ctx, h.RequestVerifier, bodyArgs.key); err != nil {
		return err
	}

	deviceHash, err := macBytesOf(ctx, h.TransitWriter, "device", bodyArgs.DeviceID)
	if err != nil {
		return fmt.Errorf("hash the device identifier: %w", err)
	}

	now := h.SystemClock.Now()

	sessionTTL := h.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = DefaultSessionTTL
	}

	address := h.Locator.Address(ctx)
	place := h.Locator.Place(address)
	keyID := sha256.Sum256(bodyArgs.key)

	session, err := h.SessionWriter.WriteOne(ctx, es.Session{
		SessionXID:   h.SessionSnowflake.Next(),
		Flags:        es.SessionFlagStarted,
		DeviceIDHash: deviceHash,
		DeviceKey:    bodyArgs.key,
		KeyID:        keyID[:],
		IP:           address,
		Country:      place.Country,
		Latitude:     place.Latitude,
		Longitude:    place.Longitude,
		ExpiresAt:    now.Add(sessionTTL),
	}, es.WriteCreate)
	if err != nil {
		return fmt.Errorf("create the session: %w", err)
	}

	return web.Write(ctx, fasthttp.StatusCreated, SessionResult{
		SessionXID: session.SessionXID,
		ExpiresAt:  session.ExpiresAt,
	})
}

// RetrieveSessionHandlerResult is the response of GET /session.
type RetrieveSessionHandlerResult struct {
	SessionXID uint64         `json:"session_xid,string"`
	Flags      es.SessionFlag `json:"flags"`
	UserXID    uint64         `json:"user_xid,string,omitempty"`
	RiskScore  uint8          `json:"risk_score"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

// RetrieveSessionHandler handles GET /session. It returns the state of the session of the request: its external ID,
// flags, user, risk score and expiry time.
type RetrieveSessionHandler struct{}

// ServeHTTP implements [web.Handler].
func (h *RetrieveSessionHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	session, err := Session(ctx)
	if err != nil {
		return err
	}

	user, _ := User(ctx)
	return web.Write(ctx, fasthttp.StatusOK, RetrieveSessionHandlerResult{
		SessionXID: session.SessionXID,
		Flags:      session.Flags,
		UserXID:    user.UserXID,
		RiskScore:  session.RiskScore,
		ExpiresAt:  session.ExpiresAt.UTC(),
	})
}

// TerminateSessionHandler handles DELETE /session. It revokes the session of the request. The
// session middleware refuses a revoked session, so the signed requests of the device stop working at once.
type TerminateSessionHandler struct {
	SessionGroupWriter es.Writer[es.SessionGroup]
	Metrics            *metrics.Metrics
}

// ServeHTTP implements [web.Handler]. It responds with status 204.
func (h *TerminateSessionHandler) ServeHTTP(ctx *fasthttp.RequestCtx) error {
	session, err := Session(ctx)
	if err != nil {
		return err
	}

	_, err = h.SessionGroupWriter.WriteOne(ctx, es.SessionGroup{
		Session: es.Session{
			ID: session.ID,
		},
	}, es.RevokeSession)
	if err != nil {
		return fmt.Errorf("revoke the session: %w", err)
	}

	SetEvent(ctx, es.EventLogout)

	h.Metrics.Session(metrics.SessionRevoked, 1)

	ctx.SetStatusCode(fasthttp.StatusNoContent)
	return nil
}
