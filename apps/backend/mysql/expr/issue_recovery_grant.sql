UPDATE recovery_requests
SET grant_hash = ?, grant_expires_at = ?
WHERE id = ?
  AND flags & ? = ?
  AND flags & ? = 0
