SELECT id, account_xid, flags, user_id, vault_key, issuer, label, algorithm, digits, period, created_at
FROM accounts
WHERE account_xid = ?
  AND user_id = ?
