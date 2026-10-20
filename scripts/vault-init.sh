#!/bin/sh
# Initializes the dev-mode Vault of the stand: the Transit engine, the two keys, the policy of the backend and its
# AppRole, then hands the backend its identity through the volume /handoff: the role ID in a file, and a wrapping token
# that unwraps to a fresh secret ID. The backend unwraps it at startup, which uses it up; a second unwrap fails, which
# is how a stolen handoff shows. The job runs on every `up`, so a restarted backend gets a fresh token.
#
# Dev mode only. Nothing here is a production setup: production runs Vault with TLS, sealed storage, an audit device
# and an operator-held root, and the policy is applied by an operator, not by a job with the root token.
set -eu

export VAULT_ADDR="${VAULT_ADDR:?}"

# The cluster keeps the root token in a file that its init job wrote. The single-node stand passes it in the environment.
if [ -n "${VAULT_TOKEN_FILE:-}" ]; then
	VAULT_TOKEN="$(cat "$VAULT_TOKEN_FILE")"
fi
export VAULT_TOKEN="${VAULT_TOKEN:?}"

# A wrapping token works once, so every backend needs its own. HANDOFF_COUNT is the number of backends. With one
# backend the file is wrapped_token, and with more it is wrapped_token_1, wrapped_token_2 and so on.
HANDOFF_COUNT="${HANDOFF_COUNT:-1}"

if ! vault secrets list -format=json | grep -q '"transit/"'; then
	vault secrets enable transit
fi

# A derived key uses the context the caller gives as part of the key derivation, so a ciphertext of one user does
# not decrypt with the context of another. None of the keys is exportable, and none allows a plaintext backup.
vault write -f transit/keys/totp type=aes256-gcm96 derived=true exportable=false allow_plaintext_backup=false
vault write -f transit/keys/mac type=hmac key_size=32 exportable=false allow_plaintext_backup=false

vault policy write backend /init/vault-policy.hcl

if ! vault auth list -format=json | grep -q '"approle/"'; then
	vault auth enable approle
fi

# A short token that the backend renews, with a ceiling after which it logs in again with the same secret ID. The
# secret ID itself does not expire and may be reused, so that a backend restarted within the stand can log in again;
# production sets secret_id_num_uses=1 and lets an agent deliver a new one on every start.
vault write auth/approle/role/backend \
	token_policies=backend \
	token_ttl=15m \
	token_max_ttl=4h \
	secret_id_ttl=0 \
	secret_id_num_uses=0

mkdir -p /handoff
chmod 755 /handoff
vault read -field=role_id auth/approle/role/backend/role-id > /handoff/role_id
if [ "$HANDOFF_COUNT" -eq 1 ]; then
	vault write -wrap-ttl=10m -field=wrapping_token -f auth/approle/role/backend/secret-id > /handoff/wrapped_token
else
	n=1
	while [ "$n" -le "$HANDOFF_COUNT" ]; do
		vault write -wrap-ttl=10m -field=wrapping_token -f auth/approle/role/backend/secret-id > "/handoff/wrapped_token_$n"
		n=$((n + 1))
	done
fi
chmod 644 /handoff/*
echo 'vault is initialized: transit keys, the backend policy and the AppRole are in place, the handoff is written'
