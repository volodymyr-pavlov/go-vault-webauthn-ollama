UPDATE users
SET flags = (flags & ~?) | ?
WHERE id = ?
