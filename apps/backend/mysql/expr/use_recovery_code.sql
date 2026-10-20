UPDATE recovery_codes
SET flags = flags | ?
WHERE user_id = ?
  AND mac = ?
  AND flags & ? = 0
