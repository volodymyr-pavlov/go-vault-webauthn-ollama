package es

// ResourceCode identifies one endpoint of the API in the permission table and in the request log.
type ResourceCode uint16

// Permission is the access rule of one endpoint. It says which session flags a request must carry and whether the last
// factor must be fresh.
//
// The session middleware finds the rule by the resource code of the endpoint and checks it before the handler runs. A
// session with no flags, or with [SessionFlagRevoked], always fails, whatever the rule says.
type Permission struct {
	// ResourceCode identifies the endpoint that the rule protects.
	ResourceCode ResourceCode

	// SessionFlag holds the session flags that must all be set. Zero requires none.
	SessionFlag SessionFlag

	// SessionAnyFlag holds session flags of which at least one must be set. Zero requires none. An endpoint that
	// several states may reach, such as the enrollment of a factor, uses it.
	SessionAnyFlag SessionFlag

	// Rules are the extra checks of the rule, as [PermissionRule] bits.
	Rules PermissionRule
}

// PermissionRule is a bit of [Permission.Rules]. A rule adds one check to the session flags of the permission.
type PermissionRule uint8

const (
	// RuleStrict requires the session flags to equal SessionFlag exactly, so an extra flag fails the request. The steps
	// of a flow use it to keep the session on the current step.
	RuleStrict PermissionRule = 1 << iota

	// RuleFresh requires that the last factor of an authorized session passed within the fresh window. Adding or
	// removing a factor uses it. A session in an enrollment state has no factor yet, so the check does not apply to it.
	RuleFresh
)
