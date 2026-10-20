SELECT id, account_xid, flags, user_id, vault_key, issuer, label, algorithm, digits, period, created_at
FROM accounts
WHERE user_id = ?
ORDER BY id ASC
LIMIT ? OFFSET ?
