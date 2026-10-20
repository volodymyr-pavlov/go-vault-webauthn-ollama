// Package expr holds the fixed SQL statements of the mysql package. Each statement is in its own file and is embedded
// at build time. A statement has ? placeholders, and the stores pass the arguments.
//
// An update that writes only the fields that are set is not here. The stores build it, because its text depends on the
// arguments.
package expr

import _ "embed"

// CreateRecoveryCode inserts one recovery code. RecoveryCodeBatchWriter runs it for each code of a new set.
//
//go:embed create_recovery_code.sql
var CreateRecoveryCode string

// CreateSession inserts one session. SessionWriter and SessionTx run it.
//
//go:embed create_session.sql
var CreateSession string

// CreateUser inserts one user. UserWriter and UserTx run it.
//
//go:embed create_user.sql
var CreateUser string

// CreatePasskey inserts one passkey. PasskeyWriter and PasskeyTx run it.
//
//go:embed create_passkey.sql
var CreatePasskey string

// PasskeyByCredentialID selects the passkey with a credential ID. PasskeyReader and PasskeyTx run it.
//
//go:embed passkey_by_credential_id.sql
var PasskeyByCredentialID string

// PasskeyByID selects the passkey with an internal ID. PasskeyReader and PasskeyTx run it.
//
//go:embed passkey_by_id.sql
var PasskeyByID string

// PasskeyByPasskeyXID selects the passkey with an external ID. PasskeyReader and PasskeyTx run it.
//
//go:embed passkey_by_passkey_xid.sql
var PasskeyByPasskeyXID string

// PasskeysByUser selects one page of the passkeys of a user, oldest first. PasskeyBatchReader runs it.
//
//go:embed passkeys_by_user.sql
var PasskeysByUser string

// ReplaceRecoveryCodeFlagsByUser replaces the flags of all the recovery codes of a user. It clears the old flags and
// sets the new ones. RecoveryCodeReplacer and RecoveryCodeTx run it.
//
//go:embed replace_recovery_code_flags_by_user.sql
var ReplaceRecoveryCodeFlagsByUser string

// ReplaceSessionFlags replaces the flags of one session. It clears the old flags and sets the new ones.
// SessionReplacer and SessionTx run it for one item.
//
//go:embed replace_session_flags.sql
var ReplaceSessionFlags string

// ReplaceSessionFlagsByUser replaces the flags of all the sessions of a user. It clears the old flags and sets the new
// ones. SessionReplacer and SessionTx run it for all the sessions of the user.
//
//go:embed replace_session_flags_by_user.sql
var ReplaceSessionFlagsByUser string

// SessionByID selects the session with an internal ID. SessionReader and SessionTx run it.
//
//go:embed session_by_id.sql
var SessionByID string

// SessionBySessionXID selects the session with an external ID. SessionReader and SessionTx run it.
//
//go:embed session_by_session_xid.sql
var SessionBySessionXID string

// SessionsByIP selects one page of the sessions of an IP address, newest first. SessionBatchReader runs it.
//
//go:embed sessions_by_ip.sql
var SessionsByIP string

// SessionsByIPSince selects one page of the sessions of an IP address created at or after a time, newest first.
// SessionBatchReader runs it.
//
//go:embed sessions_by_ip_since.sql
var SessionsByIPSince string

// SessionsByUser selects one page of the sessions of a user, newest first. SessionBatchReader runs it.
//
//go:embed sessions_by_user.sql
var SessionsByUser string

// SessionsByUserSince selects one page of the sessions of a user created at or after a time, newest first.
// SessionBatchReader runs it.
//
//go:embed sessions_by_user_since.sql
var SessionsByUserSince string

// UseRecoveryCode marks a recovery code as used. It changes a row only if the code with this MAC has not been used
// before. RecoveryCodeWriter and RecoveryCodeTx run it.
//
//go:embed use_recovery_code.sql
var UseRecoveryCode string

// UserByEmail selects the user with an email. UserReader and UserTx run it.
//
//go:embed user_by_email.sql
var UserByEmail string

// UserByHandle selects the user with a WebAuthn user handle. UserReader and UserTx run it.
//
//go:embed user_by_handle.sql
var UserByHandle string

// UserByID selects the user with an internal ID. UserReader and UserTx run it.
//
//go:embed user_by_id.sql
var UserByID string

// UserByIDForUpdate selects the user with an internal ID and locks the row until the transaction ends. UserTx
// runs it.
//
//go:embed user_by_id_for_update.sql
var UserByIDForUpdate string

// UserByUserXID selects the user with an external ID. UserReader and UserTx run it.
//
//go:embed user_by_user_xid.sql
var UserByUserXID string

// UsersWithTOTP selects one page of the users that have a TOTP factor, oldest first. UserBatchReader runs
// it.
//
//go:embed users_with_totp.sql
var UsersWithTOTP string

// ApproveRecoveryRequest adds the approved flag to an open request whose delay has ended.
// RecoveryRequestWriter and RecoveryRequestTx run it.
//
//go:embed approve_recovery_request.sql
var ApproveRecoveryRequest string

// CancelRecoveryRequest adds the cancelled flag to the open request with a cancel hash. RecoveryRequestWriter and
// RecoveryRequestTx run it.
//
//go:embed cancel_recovery_request.sql
var CancelRecoveryRequest string

// CancelRecoveryRequestsByUser adds the cancelled flag to every open request of a user.
// RecoveryRequestReplacer and RecoveryRequestTx run it.
//
//go:embed cancel_recovery_requests_by_user.sql
var CancelRecoveryRequestsByUser string

// CreateRecoveryRequest inserts one recovery request. RecoveryRequestWriter and RecoveryRequestTx run it.
//
//go:embed create_recovery_request.sql
var CreateRecoveryRequest string

// IssueRecoveryGrant stores the grant hash and its expiry on an approved, open request. RecoveryRequestWriter and
// RecoveryRequestTx run it.
//
//go:embed issue_recovery_grant.sql
var IssueRecoveryGrant string

// RecoveryRequestByGrantHash selects the recovery request with a grant hash. RecoveryRequestReader and
// RecoveryRequestTx run it.
//
//go:embed recovery_request_by_grant_hash.sql
var RecoveryRequestByGrantHash string

// RecoveryRequestByUser selects the newest open recovery request of a user. RecoveryRequestReader and RecoveryRequestTx
// run it.
//
//go:embed recovery_request_by_user.sql
var RecoveryRequestByUser string

// RecoveryRequestsOpen selects a page of the open recovery requests, oldest first. RecoveryRequestBatchReader runs
// it.
//
//go:embed recovery_requests_open.sql
var RecoveryRequestsOpen string

// UseUpRecoveryGrant adds the granted flag to an approved, open request with an unexpired grant hash.
// RecoveryRequestWriter and RecoveryRequestTx run it.
//
//go:embed use_up_recovery_grant.sql
var UseUpRecoveryGrant string

// DeleteExpiredSessions deletes the sessions that expired before a time. SessionWriter runs it.
//
//go:embed delete_expired_sessions.sql
var DeleteExpiredSessions string

// PasskeyByCredentialIDForUpdate selects the passkey with a credential ID and locks the row until the transaction ends.
// PasskeyTx runs it.
//
//go:embed passkey_by_credential_id_for_update.sql
var PasskeyByCredentialIDForUpdate string

// PasskeyByIDForUpdate selects the passkey with an internal ID and locks the row until the transaction ends. PasskeyTx
// runs it.
//
//go:embed passkey_by_id_for_update.sql
var PasskeyByIDForUpdate string

// PasskeyByPasskeyXIDForUpdate selects the passkey with an external ID and locks the row until the transaction ends.
// PasskeyTx runs it.
//
//go:embed passkey_by_passkey_xid_for_update.sql
var PasskeyByPasskeyXIDForUpdate string

// RecoveryRequestByGrantHashForUpdate selects the recovery request with a grant hash and locks the row until the
// transaction ends. RecoveryRequestTx runs it.
//
//go:embed recovery_request_by_grant_hash_for_update.sql
var RecoveryRequestByGrantHashForUpdate string

// RecoveryRequestByUserForUpdate selects the newest open recovery request of a user and locks the row until the
// transaction ends. RecoveryRequestTx runs it.
//
//go:embed recovery_request_by_user_for_update.sql
var RecoveryRequestByUserForUpdate string

// ReplacePasskeyFlags replaces the flags of one passkey. It clears the old flags and sets the new ones. PasskeyTx runs
// it.
//
//go:embed replace_passkey_flags.sql
var ReplacePasskeyFlags string

// ReplaceUserFlags replaces the flags of one user. It clears the old flags and sets the new ones. UserTx runs it.
//
//go:embed replace_user_flags.sql
var ReplaceUserFlags string

// SessionByIDForUpdate selects the session with an internal ID and locks the row until the transaction ends. SessionTx
// runs it.
//
//go:embed session_by_id_for_update.sql
var SessionByIDForUpdate string

// SessionBySessionXIDForUpdate selects the session with an external ID and locks the row until the transaction ends.
// SessionTx runs it.
//
//go:embed session_by_session_xid_for_update.sql
var SessionBySessionXIDForUpdate string

// DeleteExpiredHTTPRequests deletes the rows of the request log that are older than a time. HTTPRequestWriter runs it.
//
//go:embed delete_expired_http_requests.sql
var DeleteExpiredHTTPRequests string

// CreateHTTPRequest inserts one row of the log of the requests that the API received. HTTPRequestWriter runs it.
//
//go:embed create_http_request.sql
var CreateHTTPRequest string

// DeleteUserRecoveryRequests deletes the recovery requests of a user. UserGroupWriter runs it when it deletes a user.
//
//go:embed delete_user_recovery_requests.sql
var DeleteUserRecoveryRequests string

// DeleteUserRecoveryCodes deletes the recovery codes of a user. UserGroupWriter runs it when it deletes a user.
//
//go:embed delete_user_recovery_codes.sql
var DeleteUserRecoveryCodes string

// DeleteUserPasskeys deletes the passkeys of a user. UserGroupWriter runs it when it deletes a user.
//
//go:embed delete_user_passkeys.sql
var DeleteUserPasskeys string

// DeleteUserSessions deletes the sessions of a user. UserGroupWriter runs it when it deletes a user.
//
//go:embed delete_user_sessions.sql
var DeleteUserSessions string

// DeleteUser deletes a user by its internal key. UserGroupWriter runs it when it deletes a user.
//
//go:embed delete_user.sql
var DeleteUser string

// EraseUserHTTPRequests removes the user, the address, the user agent and the texts from the request log rows of a user. UserGroupWriter runs it when it deletes a user.
//
//go:embed erase_user_http_requests.sql
var EraseUserHTTPRequests string

// HTTPRequestsByUser selects one page of the request log rows of a user, newest first. HTTPRequestBatchReader runs it.
//
//go:embed http_requests_by_user.sql
var HTTPRequestsByUser string

// CreateAccount inserts one account. AccountGroupWriter runs it.
//
//go:embed create_account.sql
var CreateAccount string

// AccountsByUser selects one page of the accounts of a user, oldest first. AccountBatchReader runs it.
//
//go:embed accounts_by_user.sql
var AccountsByUser string

// AccountByXID selects the account of a user with an external ID. AccountReader runs it.
//
//go:embed account_by_xid.sql
var AccountByXID string

// CountAccountsByUser counts the accounts of a user. AccountGroupWriter runs it after it has locked the user.
//
//go:embed count_accounts_by_user.sql
var CountAccountsByUser string

// DeleteAccount deletes the account of a user with an external ID. AccountGroupWriter runs it.
//
//go:embed delete_account.sql
var DeleteAccount string

// DeleteUserAccounts deletes the accounts of a user. UserGroupWriter runs it when it deletes a user.
//
//go:embed delete_user_accounts.sql
var DeleteUserAccounts string
