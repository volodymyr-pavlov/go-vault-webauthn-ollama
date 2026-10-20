add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy no-referrer always;
add_header Permissions-Policy "publickey-credentials-create=(self), publickey-credentials-get=(self), camera=(self), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
