UPDATE http_requests
SET user_xid    = 0,
    ip          = NULL,
    user_agent  = '',
    event_attrs = '',
    error_text  = ''
WHERE user_xid = ?
