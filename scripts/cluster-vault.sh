#!/bin/sh
# Initializes and unseals the three Vault nodes of the cluster and joins them to one Raft group. It is safe to run again:
# after a restart of a node it only unseals the node.
#
# LOCAL ONLY. The single unseal key and the root token go into the volume /cluster, so the cluster starts without a
# person. Production uses several key holders, auto-unseal or a secret manager, and never keeps the root token.
set -eu

KEYS=/cluster/init.json
NODES="vault-1 vault-2 vault-3"

# reachable reports whether the node answers. The exit code 2 of `vault status` means sealed or not initialized, which
# is an answer too.
reachable() {
	vault status -address="http://$1:8200" >/dev/null 2>&1 && return 0
	[ $? -eq 2 ]
}

# flag reads a boolean field of the status of a node.
flag() {
	vault status -address="http://$1:8200" -format=json 2>/dev/null | tr -d ' \n' | grep -q "\"$2\":true"
}

# wait_for runs a command until it succeeds. It gives up after 120 seconds, so a node that never starts fails the job.
wait_for() {
	tries=0
	until "$@"; do
		tries=$((tries + 1))
		if [ "$tries" -gt 120 ]; then
			echo "gave up waiting for: $*" >&2
			exit 1
		fi

		sleep 1
	done
}

for node in $NODES; do
	wait_for reachable "$node"
done

if ! flag vault-1 initialized; then
	vault operator init -address=http://vault-1:8200 -key-shares=1 -key-threshold=1 -format=json > "$KEYS"
	tr -d ' \n' < "$KEYS" | sed 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/' > /cluster/unseal_key
	tr -d ' \n' < "$KEYS" | sed 's/.*"root_token":"\([^"]*\)".*/\1/' > /cluster/root_token
	chmod 600 "$KEYS" /cluster/unseal_key /cluster/root_token
fi

[ -s /cluster/unseal_key ] || { echo 'vault-1 is initialized but the unseal key is not in /cluster: run make cluster-reset' >&2; exit 1; }
KEY="$(cat /cluster/unseal_key)"

if flag vault-1 sealed; then
	vault operator unseal -address=http://vault-1:8200 "$KEY" >/dev/null
fi

wait_for vault status -address=http://vault-1:8200 >/dev/null 2>&1

for node in vault-2 vault-3; do
	if ! flag "$node" initialized; then
		VAULT_TOKEN="$(cat /cluster/root_token)" vault operator raft join -address="http://$node:8200" http://vault-1:8200 >/dev/null
	fi

	if flag "$node" sealed; then
		vault operator unseal -address="http://$node:8200" "$KEY" >/dev/null
	fi
done

# After a restart the node may be a standby for a moment, and a standby cannot list the peers. That is not an error.
VAULT_TOKEN="$(cat /cluster/root_token)" vault operator raft list-peers -address=http://vault-1:8200 2>/dev/null || echo 'vault-1 is not the leader now; run make cluster-status to see the peers'
echo 'the vault cluster is initialized, joined and unsealed'
