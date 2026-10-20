package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ webauthn.User = account{}

// DefaultTimeout is how long a ceremony may take when [RelyingPartyOptions.Timeout] is zero.
const DefaultTimeout = 2 * time.Minute

// RelyingPartyOptions holds the settings of a [RelyingParty].
type RelyingPartyOptions struct {
	// RPID is the relying party ID: the effective domain of the service, such as "example.com".
	RPID string

	// RPName is the name that the browser shows for the relying party.
	RPName string

	// Origins are the origins that may run a ceremony, such as "https://example.com".
	Origins []string

	// Timeout is how long a ceremony may take. Zero means [DefaultTimeout].
	Timeout time.Duration
}

// RelyingParty runs the WebAuthn registration and login ceremonies. [NewRelyingParty] creates it.
type RelyingParty struct {
	web *webauthn.WebAuthn
}

// NewRelyingParty returns a [RelyingParty] for opts. Every ceremony requires user verification and a discoverable
// credential, asks for no attestation, and is refused if it finishes after its timeout.
//
// It returns an error if the library rejects opts.
func NewRelyingParty(opts RelyingPartyOptions) (*RelyingParty, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	web, err := webauthn.New(&webauthn.Config{
		RPID:                  opts.RPID,
		RPDisplayName:         opts.RPName,
		RPOrigins:             opts.Origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    timeout,
				TimeoutUVD: timeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    timeout,
				TimeoutUVD: timeout,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure the relying party: %w", err)
	}

	return &RelyingParty{
		web: web,
	}, nil
}

// account is a user as the library sees it: the opaque handle, the email as the name, and the credentials.
type account struct {
	handle      []byte
	name        string
	credentials []webauthn.Credential
}

// WebAuthnID returns the handle of the user. It implements [webauthn.User].
func (a account) WebAuthnID() []byte {
	return a.handle
}

// WebAuthnName returns the name of the user. It implements [webauthn.User].
func (a account) WebAuthnName() string {
	return a.name
}

// WebAuthnDisplayName returns the same value as [account.WebAuthnName]. It implements [webauthn.User].
func (a account) WebAuthnDisplayName() string {
	return a.name
}

// WebAuthnCredentials returns the credentials of the user. It implements [webauthn.User].
func (a account) WebAuthnCredentials() []webauthn.Credential {
	return a.credentials
}

// BeginRegistration starts the registration of a passkey for user. It returns the options for the browser, and the
// encoded state of the ceremony for the caller to keep on the session.
//
// The options exclude the credentials of the passkeys that the user has, so an authenticator does not register the same
// credential twice. A removed passkey is not excluded.
func (rp *RelyingParty) BeginRegistration(user es.User, passkeys []es.Passkey) (options, state []byte, err error) {
	exclusions := make([]protocol.CredentialDescriptor, 0, len(passkeys))
	for _, passkey := range passkeys {
		if !passkey.Present() {
			continue
		}

		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: passkey.CredentialID,
		}
		for _, transport := range passkey.Transports.Names() {
			descriptor.Transport = append(descriptor.Transport, protocol.AuthenticatorTransport(transport))
		}

		exclusions = append(exclusions, descriptor)
	}

	creation, session, err := rp.web.BeginRegistration(account{
		handle: user.Handle,
		name:   user.Email,
	}, webauthn.WithExclusions(exclusions))
	if err != nil {
		return nil, nil, fmt.Errorf("begin the registration: %w", err)
	}

	options, err = json.Marshal(creation)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the options: %w", err)
	}

	state, err = json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the state: %w", err)
	}

	return options, state, nil
}

// FinishRegistration checks the response of the browser against the state of the ceremony and returns the new passkey.
// The caller sets PasskeyXID, UserID and ID before it stores the passkey.
//
// It returns [ErrVerify] if the response does not verify. The cause is joined to it for the log. It returns another
// error if state cannot be decoded.
func (rp *RelyingParty) FinishRegistration(user es.User, state, response []byte) (es.Passkey, error) {
	var session webauthn.SessionData

	if err := json.Unmarshal(state, &session); err != nil {
		return es.Passkey{}, fmt.Errorf("decode the state: %w", err)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return es.Passkey{}, errors.Join(ErrVerify, err)
	}

	credential, err := rp.web.CreateCredential(account{
		handle: user.Handle,
		name:   user.Email,
	}, session, parsed)
	if err != nil {
		return es.Passkey{}, errors.Join(ErrVerify, err)
	}

	if !credential.Flags.UserVerified {
		return es.Passkey{}, errors.Join(ErrVerify, ErrUserVerification)
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports = append(transports, string(transport))
	}

	var passkeyFlags es.PasskeyFlag
	if credential.Flags.UserPresent {
		passkeyFlags |= es.PasskeyFlagUserPresent
	}

	if credential.Flags.UserVerified {
		passkeyFlags |= es.PasskeyFlagUserVerified
	}

	if credential.Flags.BackupEligible {
		passkeyFlags |= es.PasskeyFlagBackupEligible
	}

	if credential.Flags.BackupState {
		passkeyFlags |= es.PasskeyFlagBackedUp
	}

	return es.Passkey{
		Flags:             passkeyFlags,
		CredentialID:      credential.ID,
		PublicKey:         credential.PublicKey,
		AttestationType:   credential.AttestationType,
		AttestationFormat: credential.AttestationFormat,
		Transports:        es.ParseTransports(transports),
		AAGUID:            credential.Authenticator.AAGUID,
		SignCount:         credential.Authenticator.SignCount,
	}, nil
}

// BeginLogin starts a login for the account with the given handle. It returns the options for the browser, which name
// the credentials in credentialIDs. It also returns the encoded state of the ceremony for the caller to keep on the
// session.
//
// For an unknown account, the caller passes fixed stand-in values, so the options do not show whether the account
// exists.
func (rp *RelyingParty) BeginLogin(handle []byte, credentialIDs [][]byte) (options, state []byte, err error) {
	credentials := make([]webauthn.Credential, 0, len(credentialIDs))
	for _, id := range credentialIDs {
		credentials = append(credentials, webauthn.Credential{
			ID: id,
			Transport: []protocol.AuthenticatorTransport{
				protocol.Internal,
				protocol.Hybrid,
			},
		})
	}

	request, session, err := rp.web.BeginLogin(account{
		handle:      handle,
		credentials: credentials,
	}, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, fmt.Errorf("begin the login: %w", err)
	}

	options, err = json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the options: %w", err)
	}

	state, err = json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the state: %w", err)
	}

	return options, state, nil
}

// BeginDiscoverableLogin starts a login with a passkey that the browser finds by itself, without the address of an
// account. It returns the options for the browser and the encoded state of the ceremony for the caller to keep on the
// session.
//
// The options name no credentials. The passkey names its account in the response.
func (rp *RelyingParty) BeginDiscoverableLogin() (options, state []byte, err error) {
	request, session, err := rp.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, fmt.Errorf("begin the discoverable login: %w", err)
	}

	options, err = json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the options: %w", err)
	}

	state, err = json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the state: %w", err)
	}

	return options, state, nil
}

// FinishLogin checks the assertion of the browser against the state of the ceremony and the usable passkeys of user. It
// returns the passkey that signed, with its counter and backup state updated, and whether the counter went back.
//
// The counter went back if it did not grow and the stored or the received value is not zero. This can mean a cloned
// authenticator. The caller stores the passkey and, if the counter went back, disables it.
//
// It returns [ErrVerify] if the assertion does not verify. The cause is joined to it for the log. It returns another
// error if state cannot be decoded.
func (rp *RelyingParty) FinishLogin(user es.User, passkeys []es.Passkey, state, response []byte) (es.Passkey, bool, error) {
	var session webauthn.SessionData

	if err := json.Unmarshal(state, &session); err != nil {
		return es.Passkey{}, false, fmt.Errorf("decode the state: %w", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return es.Passkey{}, false, errors.Join(ErrVerify, err)
	}

	credential, err := rp.web.ValidateLogin(account{
		handle:      user.Handle,
		name:        user.Email,
		credentials: credentialsOf(passkeys),
	}, session, parsed)
	if err != nil {
		return es.Passkey{}, false, errors.Join(ErrVerify, err)
	}

	return signedPasskey(passkeys, credential, parsed)
}

// FinishDiscoverableLogin checks the assertion of a login that did not name an account. The state is the one that
// [RelyingParty.BeginDiscoverableLogin] returned. The passkey names its account in the response, as the user handle.
// The function lookup returns the user with that handle and the passkeys of the user. The other results are those of
// [RelyingParty.FinishLogin], and the user is added.
//
// It returns [ErrVerify] if the assertion does not verify or if lookup returns [es.ErrNotFound]. It returns any other
// error of lookup as it is.
func (rp *RelyingParty) FinishDiscoverableLogin(
	lookup func(userHandle []byte) (es.User, []es.Passkey, error),
	state, response []byte,
) (es.User, es.Passkey, bool, error) {
	var session webauthn.SessionData

	if err := json.Unmarshal(state, &session); err != nil {
		return es.User{}, es.Passkey{}, false, fmt.Errorf("decode the state: %w", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return es.User{}, es.Passkey{}, false, errors.Join(ErrVerify, err)
	}

	var (
		user      es.User
		passkeys  []es.Passkey
		lookupErr error
	)

	_, credential, err := rp.web.ValidatePasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
		user, passkeys, lookupErr = lookup(userHandle)
		if lookupErr != nil {
			return nil, lookupErr
		}

		return account{
			handle:      user.Handle,
			name:        user.Email,
			credentials: credentialsOf(passkeys),
		}, nil
	}, session, parsed)

	if lookupErr != nil && !errors.Is(lookupErr, es.ErrNotFound) {
		return es.User{}, es.Passkey{}, false, lookupErr
	}

	if err != nil {
		return es.User{}, es.Passkey{}, false, errors.Join(ErrVerify, err)
	}

	signed, regressed, err := signedPasskey(passkeys, credential, parsed)

	return user, signed, regressed, err
}

// credentialsOf returns the usable passkeys as credentials in the form that the library takes.
func credentialsOf(passkeys []es.Passkey) []webauthn.Credential {
	credentials := make([]webauthn.Credential, 0, len(passkeys))
	for _, passkey := range passkeys {
		if !passkey.Usable() {
			continue
		}

		credentials = append(credentials, webauthn.Credential{
			ID:                passkey.CredentialID,
			PublicKey:         passkey.PublicKey,
			AttestationType:   passkey.AttestationType,
			AttestationFormat: passkey.AttestationFormat,
			Flags: webauthn.CredentialFlags{
				UserPresent:    passkey.Flags&es.PasskeyFlagUserPresent != 0,
				UserVerified:   passkey.Flags&es.PasskeyFlagUserVerified != 0,
				BackupEligible: passkey.Flags&es.PasskeyFlagBackupEligible != 0,
				BackupState:    passkey.Flags&es.PasskeyFlagBackedUp != 0,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    passkey.AAGUID,
				SignCount: passkey.SignCount,
			},
		})
	}

	return credentials
}

// signedPasskey returns the passkey that signed, with the backup state and the counter of the credential, and whether
// the counter went back.
//
// It returns [ErrVerify] if the authenticator did not verify the user or the credential is not one of the passkeys.
func signedPasskey(passkeys []es.Passkey, credential *webauthn.Credential, parsed *protocol.ParsedCredentialAssertionData) (es.Passkey, bool, error) {
	if !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return es.Passkey{}, false, errors.Join(ErrVerify, ErrUserVerification)
	}

	for _, passkey := range passkeys {
		if string(passkey.CredentialID) != string(credential.ID) {
			continue
		}

		if credential.Flags.BackupState {
			passkey.Flags |= es.PasskeyFlagBackedUp
		} else {
			passkey.Flags &^= es.PasskeyFlagBackedUp
		}

		passkey.SignCount = credential.Authenticator.SignCount
		return passkey, credential.Authenticator.CloneWarning, nil
	}

	return es.Passkey{}, false, errors.Join(ErrVerify, ErrUnknownCredential)
}
