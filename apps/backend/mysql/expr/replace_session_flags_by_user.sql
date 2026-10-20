UPDATE sessions
SET flags = (flags & ~?) | ?
WHERE user_id = ?
