package api

import "github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"

// resourceNames maps the code of each endpoint to its name in the metrics.
var resourceNames = map[es.ResourceCode]string{
	Healthz:                  "healthz",
	BeginSession:             "begin_session",
	RetrieveSession:          "retrieve_session",
	TerminateSession:         "terminate_session",
	BeginRegistry:            "begin_registry",
	CompleteRegistry:         "complete_registry",
	BeginEnrollPasskey:       "begin_enroll_passkey",
	CompleteEnrollPasskey:    "complete_enroll_passkey",
	BeginEnrollTOTP:          "begin_enroll_totp",
	CompleteEnrollTOTP:       "complete_enroll_totp",
	IssueRecoveryCodes:       "issue_recovery_codes",
	BeginAuthorizePasskey:    "begin_authorize_passkey",
	CompleteAuthorizePasskey: "complete_authorize_passkey",
	AuthorizePassword:        "authorize_password",
	AuthorizeTOTP:            "authorize_totp",
	AuthorizeRecovery:        "authorize_recovery",
	RetrievePasskeys:         "retrieve_passkeys",
	RemovePasskey:            "remove_passkey",
	RemoveTOTP:               "remove_totp",
	RequestRecovery:          "request_recovery",
	CancelRecovery:           "cancel_recovery",
	ClaimRecovery:            "claim_recovery",
	GrantRecovery:            "grant_recovery",
	ListSessions:             "list_sessions",
	RemoveSession:            "remove_session",
	BeginRemovePasskey:       "begin_remove_passkey",
	BeginDeleteUser:          "begin_delete_user",
	DeleteUser:               "delete_user",
	ExportUser:               "export_user",
	AddAccount:               "add_account",
	ListAccounts:             "list_accounts",
	RemoveAccount:            "remove_account",
}

// ResourceName returns the name of the endpoint with the code, such as "authorize_password". It returns "unknown" for a
// code that has no name.
func ResourceName(code es.ResourceCode) string {
	if name, ok := resourceNames[code]; ok {
		return name
	}

	return "unknown"
}
