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

# The authenticator keeps the TOTP secrets of the accounts in the TOTP engine of Vault. The backend may create and delete
# a key and read the code of a key. It may not read a key back, list the keys or change the engine: a secret never
# leaves Vault.
path "authenticator/keys/*" {
  capabilities = ["create", "update", "delete"]
}

path "authenticator/code/*" {
  capabilities = ["read"]
}
