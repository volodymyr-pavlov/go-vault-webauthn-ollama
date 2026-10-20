UPDATE sessions
SET flags = (flags & ~?) | ?
WHERE id = ?
