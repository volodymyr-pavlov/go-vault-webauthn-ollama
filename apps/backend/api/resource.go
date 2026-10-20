package api

import "github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"

// These constants are the codes of the endpoints. The code of an endpoint never changes after release, because the
// request log records it.
const (
	Healthz es.ResourceCode = iota + 1
	BeginSession
	RetrieveSession
	TerminateSession
	BeginRegistry
	CompleteRegistry
	BeginEnrollPasskey
	CompleteEnrollPasskey
	BeginEnrollTOTP
	CompleteEnrollTOTP
	IssueRecoveryCodes
	BeginAuthorizePasskey
	CompleteAuthorizePasskey
	AuthorizePassword
	AuthorizeTOTP
	AuthorizeRecovery
	RetrievePasskeys
	RemovePasskey
	RemoveTOTP
	RequestRecovery
	CancelRecovery
	ClaimRecovery
	GrantRecovery
	ListSessions
	RemoveSession
	BeginRemovePasskey
	BeginDeleteAccount
	DeleteAccount
	ExportAccount
)

// CodeToPermission maps the code of each endpoint that needs a session to the permission the session must have.
// [SessionMiddleware] reads it. The endpoints that are not in the map do not use the session middleware.
var CodeToPermission = map[es.ResourceCode]es.Permission{
	RetrieveSession: {
		ResourceCode: RetrieveSession,
		SessionFlag:  es.SessionFlagStarted,
	},
	TerminateSession: {
		ResourceCode: TerminateSession,
		SessionFlag:  es.SessionFlagStarted,
	},
	BeginRegistry: {
		ResourceCode: BeginRegistry,
		SessionFlag:  es.SessionFlagStarted,
		Rules:        es.RuleStrict,
	},
	CompleteRegistry: {
		ResourceCode: CompleteRegistry,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagRegistryBegun,
		Rules:        es.RuleStrict,
	},
	BeginEnrollPasskey: {
		ResourceCode:   BeginEnrollPasskey,
		SessionFlag:    es.SessionFlagStarted,
		SessionAnyFlag: es.SessionFlagEnrollment | es.SessionFlagAuthorized,
		Rules:          es.RuleFresh,
	},
	CompleteEnrollPasskey: {
		ResourceCode:   CompleteEnrollPasskey,
		SessionFlag:    es.SessionFlagStarted | es.SessionFlagChallengeRegistration,
		SessionAnyFlag: es.SessionFlagEnrollment | es.SessionFlagAuthorized,
		Rules:          es.RuleFresh,
	},
	BeginEnrollTOTP: {
		ResourceCode:   BeginEnrollTOTP,
		SessionFlag:    es.SessionFlagStarted,
		SessionAnyFlag: es.SessionFlagEnrollment | es.SessionFlagAuthorized,
		Rules:          es.RuleFresh,
	},
	CompleteEnrollTOTP: {
		ResourceCode:   CompleteEnrollTOTP,
		SessionFlag:    es.SessionFlagStarted,
		SessionAnyFlag: es.SessionFlagEnrollment | es.SessionFlagAuthorized,
		Rules:          es.RuleFresh,
	},
	IssueRecoveryCodes: {
		ResourceCode:   IssueRecoveryCodes,
		SessionFlag:    es.SessionFlagStarted,
		SessionAnyFlag: es.SessionFlagEnrollment | es.SessionFlagAuthorized,
		Rules:          es.RuleFresh,
	},
	BeginAuthorizePasskey: {
		ResourceCode: BeginAuthorizePasskey,
		SessionFlag:  es.SessionFlagStarted,
	},
	CompleteAuthorizePasskey: {
		ResourceCode: CompleteAuthorizePasskey,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagChallengeLogin,
	},
	AuthorizePassword: {
		ResourceCode: AuthorizePassword,
		SessionFlag:  es.SessionFlagStarted,
	},
	AuthorizeTOTP: {
		ResourceCode: AuthorizeTOTP,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagPasswordApproved,
	},
	AuthorizeRecovery: {
		ResourceCode: AuthorizeRecovery,
		SessionFlag:  es.SessionFlagStarted,
	},
	RetrievePasskeys: {
		ResourceCode: RetrievePasskeys,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
	},
	BeginRemovePasskey: {
		ResourceCode: BeginRemovePasskey,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
		Rules:        es.RuleFresh,
	},
	BeginDeleteAccount: {
		ResourceCode: BeginDeleteAccount,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
		Rules:        es.RuleFresh,
	},
	DeleteAccount: {
		ResourceCode: DeleteAccount,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
		Rules:        es.RuleFresh,
	},
	ExportAccount: {
		ResourceCode: ExportAccount,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
		Rules:        es.RuleFresh,
	},
	RemovePasskey: {
		ResourceCode: RemovePasskey,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized | es.SessionFlagChallengeConfirmation,
		Rules:        es.RuleFresh,
	},
	RemoveTOTP: {
		ResourceCode: RemoveTOTP,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
		Rules:        es.RuleFresh,
	},
	RequestRecovery: {
		ResourceCode: RequestRecovery,
		SessionFlag:  es.SessionFlagStarted,
	},
	CancelRecovery: {
		ResourceCode: CancelRecovery,
		SessionFlag:  es.SessionFlagStarted,
	},
	ClaimRecovery: {
		ResourceCode: ClaimRecovery,
		SessionFlag:  es.SessionFlagStarted,
	},
	GrantRecovery: {
		ResourceCode: GrantRecovery,
		SessionFlag:  es.SessionFlagStarted,
	},
	ListSessions: {
		ResourceCode: ListSessions,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
	},
	RemoveSession: {
		ResourceCode: RemoveSession,
		SessionFlag:  es.SessionFlagStarted | es.SessionFlagAuthorized,
		Rules:        es.RuleFresh,
	},
}
