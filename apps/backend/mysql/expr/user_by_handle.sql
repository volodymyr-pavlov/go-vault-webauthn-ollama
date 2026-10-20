SELECT id, user_xid, flags, email, handle, password_hash, totp_ciphertext, totp_last_step, totp_failures, created_at
FROM users
WHERE handle = ?
