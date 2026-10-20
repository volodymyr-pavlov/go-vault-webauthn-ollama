package api

import (
	"errors"

	"github.com/valyala/fasthttp"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/web"
)

// The Err...Num constants are the numbers of the API errors. They start at 10000. The number of an error never changes
// after release, because clients and the request log use it.
const (
	ErrNoBodyDeviceIDNum uint16 = iota + 10000
	ErrMaxLenBodyDeviceIDNum
	ErrNoBodyEmailNum
	ErrMalformedBodyEmailNum
	ErrNoBodyPasswordNum
	ErrMinLenBodyPasswordNum
	ErrMaxLenBodyPasswordNum
	ErrNoBodyTokenNum
	ErrMalformedBodyTokenNum
	ErrMalformedBodyCodeNum
	ErrNoBodyNameNum
	ErrMaxLenBodyNameNum
	ErrNoBodyResponseNum
	ErrNoParamPasskeyXIDNum
	ErrUnauthorizedSessionNum
	ErrNotFoundSessionNum
	ErrStaleAuthenticationNum
	ErrAuthenticationFailedNum
	ErrForbiddenOriginNum
	ErrRiskDeniedNum
	ErrPasskeyAccountNum
	ErrLastFactorNum
	ErrAlreadyEnrolledTOTPNum
	ErrNoEnrolledTOTPNum
	ErrNotFoundPasskeyNum
	ErrTooManyRequestsNum
	ErrNoAccountNum
	ErrNoBodyDeviceKeyNum
	ErrMalformedBodyDeviceKeyNum
	ErrNoHeaderRequestSignatureNum
	ErrInvalidRequestSignatureNum
	ErrNoParamSessionXIDNum
	ErrNotFoundDeviceNum
	ErrStaleRequestTimeNum
)

// ErrNoBodyDeviceID is returned when the request body has no device ID.
var ErrNoBodyDeviceID = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyDeviceIDNum,
	Code:    "NO_BODY_DEVICE_ID",
	Message: "The device identifier is not specified.",
}

// ErrMaxLenBodyDeviceID is returned when the device ID in the request body is longer than the limit.
var ErrMaxLenBodyDeviceID = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMaxLenBodyDeviceIDNum,
	Code:    "MAX_LEN_BODY_DEVICE_ID",
	Message: "The device identifier is too long.",
}

// ErrNoBodyEmail is returned when the request body has no email.
var ErrNoBodyEmail = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyEmailNum,
	Code:    "NO_BODY_EMAIL",
	Message: "The email is not specified.",
}

// ErrMalformedBodyEmail is returned when the email in the request body is not a valid address.
var ErrMalformedBodyEmail = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMalformedBodyEmailNum,
	Code:    "MALFORMED_BODY_EMAIL",
	Message: "The email is not an address.",
}

// ErrNoBodyPassword is returned when the request body has no password.
var ErrNoBodyPassword = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyPasswordNum,
	Code:    "NO_BODY_PASSWORD",
	Message: "The password is not specified.",
}

// ErrMinLenBodyPassword is returned when a new password is shorter than the minimum length.
var ErrMinLenBodyPassword = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMinLenBodyPasswordNum,
	Code:    "MIN_LEN_BODY_PASSWORD",
	Message: "The password is too short.",
}

// ErrMaxLenBodyPassword is returned when the password in the request body is longer than [auth.MaxLength].
var ErrMaxLenBodyPassword = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMaxLenBodyPasswordNum,
	Code:    "MAX_LEN_BODY_PASSWORD",
	Message: "The password is too long.",
}

// ErrNoBodyToken is returned when the request body has no token.
var ErrNoBodyToken = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyTokenNum,
	Code:    "NO_BODY_TOKEN",
	Message: "The token is not specified.",
}

// ErrMalformedBodyToken is returned when the verification token in the request body is not 64 hex digits.
var ErrMalformedBodyToken = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMalformedBodyTokenNum,
	Code:    "MALFORMED_BODY_TOKEN",
	Message: "The token is malformed.",
}

// ErrMalformedBodyCode is returned when the code in the request body is not six digits.
var ErrMalformedBodyCode = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMalformedBodyCodeNum,
	Code:    "MALFORMED_BODY_CODE",
	Message: "The code is not six digits.",
}

// ErrNoBodyName is returned when the request body has no passkey name.
var ErrNoBodyName = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyNameNum,
	Code:    "NO_BODY_NAME",
	Message: "The name is not specified.",
}

// ErrMaxLenBodyName is returned when the passkey name in the request body is longer than the limit.
var ErrMaxLenBodyName = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMaxLenBodyNameNum,
	Code:    "MAX_LEN_BODY_NAME",
	Message: "The name is too long.",
}

// ErrNoBodyResponse is returned when the request body has no authenticator response.
var ErrNoBodyResponse = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyResponseNum,
	Code:    "NO_BODY_RESPONSE",
	Message: "The authenticator response is not specified.",
}

// ErrNoParamPasskeyXID is returned when the request path has no passkey xid.
var ErrNoParamPasskeyXID = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoParamPasskeyXIDNum,
	Code:    "NO_PARAM_PASSKEY_XID",
	Message: "The request path must contain a passkey xid.",
}

// ErrUnauthorizedSession is returned when the session does not meet the permission of the endpoint. The session is
// revoked or expired, or it lacks a required flag.
var ErrUnauthorizedSession = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrUnauthorizedSessionNum,
	Code:    "UNAUTHORIZED_SESSION",
	Message: "The session is unauthorized.",
}

// ErrNotFoundSession is returned when no session has the key ID of the request signature.
var ErrNotFoundSession = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrNotFoundSessionNum,
	Code:    "NOT_FOUND_SESSION",
	Message: "The session is not found.",
}

// ErrStaleAuthentication is returned when the endpoint needs a fresh authentication and the last factor of the session
// passed too long ago.
var ErrStaleAuthentication = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrStaleAuthenticationNum,
	Code:    "STALE_AUTHENTICATION",
	Message: "The action needs a fresh authentication.",
}

// ErrAuthenticationFailed is the response to every failed factor. It is the same for a wrong password, a wrong code, a
// bad assertion and a factor that the account does not accept. It is also the same for an account that does not exist.
// The response does not show which one happened.
var ErrAuthenticationFailed = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrAuthenticationFailedNum,
	Code:    "AUTHENTICATION_FAILED",
	Message: "The authentication failed.",
}

// ErrForbiddenOrigin is returned when the Origin header of the request is not in the list of allowed origins.
var ErrForbiddenOrigin = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrForbiddenOriginNum,
	Code:    "FORBIDDEN_ORIGIN",
	Message: "The request comes from an origin the service does not serve.",
}

// ErrRiskDenied is returned when the risk engine refuses a login.
var ErrRiskDenied = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrRiskDeniedNum,
	Code:    "RISK_DENIED",
	Message: "The login was refused. Contact support if this is you.",
}

// ErrPasskeyAccount is returned when an account with a passkey tries to enroll a TOTP factor.
var ErrPasskeyAccount = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrPasskeyAccountNum,
	Code:    "PASSKEY_ACCOUNT",
	Message: "An account with a passkey takes no password or code.",
}

// ErrLastFactor is returned when a request would remove the last factor of the account.
var ErrLastFactor = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrLastFactorNum,
	Code:    "LAST_FACTOR",
	Message: "The last factor cannot be removed. Enroll another one first.",
}

// ErrAlreadyEnrolledTOTP is returned when an account that has a confirmed TOTP factor starts to enroll another one.
var ErrAlreadyEnrolledTOTP = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrAlreadyEnrolledTOTPNum,
	Code:    "ALREADY_ENROLLED_TOTP",
	Message: "A code generator is enrolled already.",
}

// ErrNoEnrolledTOTP is returned when the account has no TOTP factor that waits for confirmation.
var ErrNoEnrolledTOTP = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrNoEnrolledTOTPNum,
	Code:    "NO_ENROLLED_TOTP",
	Message: "No code generator is being enrolled.",
}

// ErrNoAccount is returned when the session is bound to no account, but the endpoint needs one.
var ErrNoAccount = &web.Error{
	Status:  fasthttp.StatusForbidden,
	Num:     ErrNoAccountNum,
	Code:    "NO_ACCOUNT",
	Message: "The session is bound to no account.",
}

// ErrNotFoundPasskey is returned when the account has no passkey with the xid of the request path.
var ErrNotFoundPasskey = &web.Error{
	Status:  fasthttp.StatusNotFound,
	Num:     ErrNotFoundPasskeyNum,
	Code:    "NOT_FOUND_PASSKEY",
	Message: "The passkey is not found.",
}

// ErrTooManyRequests is returned when a client spends its request budget. The response carries a Retry-After header.
var ErrTooManyRequests = &web.Error{
	Status:  fasthttp.StatusTooManyRequests,
	Num:     ErrTooManyRequestsNum,
	Code:    "TOO_MANY_REQUESTS",
	Message: "Too many requests. Try again later.",
}

// ErrNoSession is the error that [Session] returns when no session is stored in the request context.
var ErrNoSession = errors.New("apictx: missing session from context")

// ErrNoUser is the error that [User] returns when no user is stored in the request context.
var ErrNoUser = errors.New("apictx: missing user from context")

// ErrNoBodyDeviceKey is returned when the request body has no device key.
var ErrNoBodyDeviceKey = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoBodyDeviceKeyNum,
	Code:    "NO_BODY_DEVICE_KEY",
	Message: "The device key is not specified.",
}

// ErrMalformedBodyDeviceKey is returned when the device key in the request body is not an Ed25519 public key in base64.
var ErrMalformedBodyDeviceKey = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrMalformedBodyDeviceKeyNum,
	Code:    "MALFORMED_BODY_DEVICE_KEY",
	Message: "The device key must be an Ed25519 public key in base64.",
}

// ErrNoHeaderRequestSignature is returned when a signature header is missing from the request.
var ErrNoHeaderRequestSignature = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrNoHeaderRequestSignatureNum,
	Code:    "NO_HEADER_REQUEST_SIGNATURE",
	Message: "The request must carry the Content-Digest, Signature-Input and Signature headers.",
}

// ErrInvalidRequestSignature is returned when a signature header is malformed, or the signature does not verify.
var ErrInvalidRequestSignature = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrInvalidRequestSignatureNum,
	Code:    "INVALID_REQUEST_SIGNATURE",
	Message: "The request signature is not valid. Sign the request with the key of the session.",
}

// ErrNoParamSessionXID is returned when the request path has no session identifier, or it is not a number.
var ErrNoParamSessionXID = &web.Error{
	Status:  fasthttp.StatusBadRequest,
	Num:     ErrNoParamSessionXIDNum,
	Code:    "NO_PARAM_SESSION_XID",
	Message: "The session identifier is not specified.",
}

// ErrNotFoundDevice is returned when the account has no active session with the identifier of the request path.
var ErrNotFoundDevice = &web.Error{
	Status:  fasthttp.StatusNotFound,
	Num:     ErrNotFoundDeviceNum,
	Code:    "NOT_FOUND_DEVICE",
	Message: "The device is not found.",
}

// ErrStaleRequestTime is returned when the time in the signature is too far from the time of the server. The error
// carries the time of the server in the server_time parameter, in Unix seconds, so that a client with a wrong clock can
// correct it and send the request again.
var ErrStaleRequestTime = &web.Error{
	Status:  fasthttp.StatusUnauthorized,
	Num:     ErrStaleRequestTimeNum,
	Code:    "STALE_REQUEST_TIME",
	Message: "The clock of the device differs from the clock of the server. Set the clock and try again.",
}
