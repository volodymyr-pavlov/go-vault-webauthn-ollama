// Package authtest provides a software authenticator for tests. It completes the WebAuthn ceremonies as a browser and a
// passkey do, so the tests run the real [auth.RelyingParty] and the real API without a device.
//
// A test can change the fields of the [Authenticator] between calls to make a response that the server must refuse.
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/tidwall/gjson"
)

// Authenticator holds one credential and completes the ceremonies for it.
type Authenticator struct {
	// RPID and Origin are the relying party ID and the origin that the authenticator signs for. The server checks both.
	RPID   string
	Origin string

	// CredentialID is the ID that the authenticator chose for its credential. The server stores it.
	CredentialID []byte

	// AAGUID names the model of the authenticator. It has 16 bytes or none.
	AAGUID []byte

	// Counter is the signature counter that the next assertion reports. [Authenticator.Assert] adds one to it
	// afterwards, unless FixedCounter is set. Synced passkeys that always report zero behave like that.
	Counter      uint32
	FixedCounter bool

	// UserVerified, BackupEligible and BackedUp are the flags of the next response.
	UserVerified   bool
	BackupEligible bool
	BackedUp       bool

	// key is the private key of the credential.
	key *ecdsa.PrivateKey
}

// NewAuthenticator returns an authenticator for the relying party with the ID rpID and the origin origin. It has a new
// ES256 key and a random credential ID. Like a platform passkey, it verifies the user and can be backed up.
func NewAuthenticator(rpID, origin string) (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make the key: %w", err)
	}

	id := make([]byte, 32)

	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("make the credential ID: %w", err)
	}
	return &Authenticator{
		RPID:           rpID,
		Origin:         origin,
		CredentialID:   id,
		UserVerified:   true,
		BackupEligible: true,
		BackedUp:       true,
		key:            key,
	}, nil
}

// collectedClientData is the client data of a ceremony. The browser builds it, and the authenticator signs its hash.
type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// coseKey is an ES256 public key in the COSE encoding. Integer labels name the key type, the algorithm, the curve and
// the two coordinates.
type coseKey struct {
	Type      int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Curve     int64  `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

// attestationObject is the attestation object of a registration, encoded in CBOR.
type attestationObject struct {
	Format    string   `cbor:"fmt"`
	Statement struct{} `cbor:"attStmt"`
	AuthData  []byte   `cbor:"authData"`
}

// registrationResponse is the body of a registration response, as the browser serializes the credential.
type registrationResponse struct {
	ID                      string              `json:"id"`
	RawID                   string              `json:"rawId"`
	Type                    string              `json:"type"`
	Response                attestationResponse `json:"response"`
	AuthenticatorAttachment string              `json:"authenticatorAttachment"`
	ClientExtensionResults  struct{}            `json:"clientExtensionResults"`
}

// attestationResponse is the response part of a [registrationResponse].
type attestationResponse struct {
	AttestationObject string   `json:"attestationObject"`
	ClientDataJSON    string   `json:"clientDataJSON"`
	Transports        []string `json:"transports"`
}

// assertionResponse is the body of an assertion, as the browser serializes the credential.
type assertionResponse struct {
	ID                      string                 `json:"id"`
	RawID                   string                 `json:"rawId"`
	Type                    string                 `json:"type"`
	Response                authenticatorAssertion `json:"response"`
	AuthenticatorAttachment string                 `json:"authenticatorAttachment"`
	ClientExtensionResults  struct{}               `json:"clientExtensionResults"`
}

// authenticatorAssertion is the response part of an [assertionResponse].
type authenticatorAssertion struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// Challenge returns the challenge in the options that a server sent to begin a ceremony, as the browser reads it.
//
// It returns [ErrNoChallenge] if the options carry no challenge. It returns an error that wraps [ErrInvalidJSON] if the
// options are not valid JSON.
func Challenge(options []byte) (string, error) {
	if !gjson.ValidBytes(options) {
		return "", fmt.Errorf("read the options: %w", ErrInvalidJSON)
	}

	challenge := gjson.GetBytes(options, "publicKey.challenge").String()
	if challenge == "" {
		return "", ErrNoChallenge
	}

	return challenge, nil
}

// Register returns the body of a registration response to challenge. The credential has the attestation format "none".
//
// It returns [ErrCredentialID] if the credential ID is longer than 1023 bytes.
func (a *Authenticator) Register(challenge string) ([]byte, error) {
	// The uncompressed point is the byte 0x04, then X and Y with 32 bytes each.
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode the point: %w", err)
	}

	publicKeyBytes, err := webauthncbor.Marshal(coseKey{
		Type:      int64(webauthncose.EllipticKey),
		Algorithm: int64(webauthncose.AlgES256),
		Curve:     int64(webauthncose.P256),
		X:         point[1:33],
		Y:         point[33:65],
	})
	if err != nil {
		return nil, fmt.Errorf("encode the public key: %w", err)
	}

	length := len(a.CredentialID)
	if length > 1023 {
		return nil, ErrCredentialID
	}

	aaguid := make([]byte, 16)
	copy(aaguid, a.AAGUID)
	attested := make([]byte, 0, 18+length+len(publicKeyBytes))
	attested = append(attested, aaguid...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(length))
	attested = append(attested, a.CredentialID...)
	attested = append(attested, publicKeyBytes...)
	attestationData := a.authData(a.flags()|protocol.FlagAttestedCredentialData, attested)

	clientDataJSON, err := a.clientData("webauthn.create", challenge)
	if err != nil {
		return nil, err
	}

	attestation, err := webauthncbor.Marshal(attestationObject{
		Format:   "none",
		AuthData: attestationData,
	})
	if err != nil {
		return nil, fmt.Errorf("encode the attestation object: %w", err)
	}

	id := base64.RawURLEncoding.EncodeToString(a.CredentialID)
	return json.Marshal(registrationResponse{
		ID:    id,
		RawID: id,
		Type:  "public-key",
		Response: attestationResponse{
			AttestationObject: base64.RawURLEncoding.EncodeToString(attestation),
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			Transports:        []string{"internal"},
		},
		AuthenticatorAttachment: "platform",
	})
}

// Assert returns the body of an assertion to challenge, signed with the key of the credential and carrying userHandle.
// Afterwards it adds one to the counter, unless FixedCounter is set. An empty userHandle is left out of the response.
func (a *Authenticator) Assert(challenge string, userHandle []byte) ([]byte, error) {
	assertionData := a.authData(a.flags(), nil)

	clientDataJSON, err := a.clientData("webauthn.get", challenge)
	if err != nil {
		return nil, err
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(assertionData)+len(clientDataHash))
	signed = append(signed, assertionData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	if !a.FixedCounter {
		a.Counter++
	}

	id := base64.RawURLEncoding.EncodeToString(a.CredentialID)
	response := authenticatorAssertion{
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(assertionData),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSON),
		Signature:         base64.RawURLEncoding.EncodeToString(signature),
	}
	if len(userHandle) != 0 {
		response.UserHandle = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	return json.Marshal(assertionResponse{
		ID:                      id,
		RawID:                   id,
		Type:                    "public-key",
		Response:                response,
		AuthenticatorAttachment: "platform",
	})
}

// flags returns the authenticator flags of the next response.
func (a *Authenticator) flags() protocol.AuthenticatorFlags {
	authFlags := protocol.FlagUserPresent
	if a.UserVerified {
		authFlags |= protocol.FlagUserVerified
	}

	if a.BackupEligible {
		authFlags |= protocol.FlagBackupEligible
	}

	if a.BackedUp {
		authFlags |= protocol.FlagBackupState
	}

	return authFlags
}

// authData returns the authenticator data: the hash of the RP ID, the flags, the counter and the attested credential
// data.
func (a *Authenticator) authData(authFlags protocol.AuthenticatorFlags, attested []byte) []byte {
	hash := sha256.Sum256([]byte(a.RPID))
	data := make([]byte, 0, 37+len(attested))
	data = append(data, hash[:]...)
	data = append(data, byte(authFlags))
	data = binary.BigEndian.AppendUint32(data, a.Counter)
	return append(data, attested...)
}

// clientData returns the client data JSON of a ceremony of the given type.
func (a *Authenticator) clientData(ceremony, challenge string) ([]byte, error) {
	data, err := json.Marshal(collectedClientData{
		Type:      ceremony,
		Challenge: challenge,
		Origin:    a.Origin,
	})
	if err != nil {
		return nil, fmt.Errorf("encode the client data: %w", err)
	}

	return data, nil
}
