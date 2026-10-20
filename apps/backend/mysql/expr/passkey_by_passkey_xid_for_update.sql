SELECT id, passkey_xid, flags, user_id, credential_id, public_key, attestation_type, attestation_format, transports, aaguid, sign_count, name, created_at
FROM passkeys
WHERE passkey_xid = ?
FOR UPDATE
