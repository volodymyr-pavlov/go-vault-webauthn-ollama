UPDATE recovery_requests
SET flags = flags | ?
WHERE recovery_request_xid = ?
  AND flags & ? = 0
  AND ready_at <= ?
