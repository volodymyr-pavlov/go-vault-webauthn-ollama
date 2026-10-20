UPDATE recovery_requests
SET flags = flags | ?
WHERE user_id = ?
  AND flags & ? = 0
