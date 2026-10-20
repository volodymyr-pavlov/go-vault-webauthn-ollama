UPDATE recovery_requests
SET flags = flags | ?
WHERE grant_hash = ?
  AND flags & ? = ?
  AND flags & ? = 0
  AND grant_expires_at > ?
