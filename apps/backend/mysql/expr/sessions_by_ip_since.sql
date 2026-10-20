SELECT id, session_xid, flags, COALESCE(user_id, 0), auth_time, risk_score, failures, device_id_hash, device_key, key_id, ip, country, latitude, longitude, verify_hash, verify_expires_at, challenge, challenge_expires_at, created_at, last_seen_at, expires_at
FROM sessions
WHERE ip = ? AND created_at >= ?
ORDER BY created_at DESC, id DESC
LIMIT ? OFFSET ?
