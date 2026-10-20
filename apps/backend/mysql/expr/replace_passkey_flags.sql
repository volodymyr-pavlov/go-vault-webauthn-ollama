UPDATE passkeys
SET flags = (flags & ~?) | ?
WHERE id = ?
