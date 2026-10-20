UPDATE recovery_codes
SET flags = (flags & ~?) | ?
WHERE user_id = ?
