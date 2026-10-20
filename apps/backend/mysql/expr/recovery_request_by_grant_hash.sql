SELECT id, recovery_request_xid, flags, user_id, cancel_hash, grant_hash, grant_expires_at, ready_at, created_at
FROM recovery_requests
WHERE grant_hash = ?
