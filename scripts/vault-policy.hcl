# The policy of the backend: the Transit operations it needs and nothing else. No path grants read of key
# material, export, backup, rotation or configuration; those are the operator's, through the root token of the
# dev-mode stand and through an admin policy in production.
path "transit/encrypt/totp" {
  capabilities = ["update"]
}

path "transit/decrypt/totp" {
  capabilities = ["update"]
}

path "transit/rewrap/totp" {
  capabilities = ["update"]
}

path "transit/hmac/mac" {
  capabilities = ["update"]
}

