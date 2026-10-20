UPDATE recovery_requests
SET flags = flags | ?
WHERE cancel_hash = ?
  AND flags & ? = 0
