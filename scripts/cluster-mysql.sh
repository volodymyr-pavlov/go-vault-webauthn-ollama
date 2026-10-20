#!/bin/sh
# Starts the replication from mysql-primary to mysql-replica with GTIDs and makes the replica read-only. It is safe to
# run again. The replica is a warm standby: the backends write to the primary only. To fail over, run
# `make cluster-promote`.
#
# LOCAL ONLY. The root password is the password of the stand.
set -eu

ROOT="${MYSQL_ROOT_PASSWORD:?}"
REPL="${MYSQL_REPLICATION_PASSWORD:?}"

# wait_for runs a command until it succeeds. It gives up after 120 seconds, so a node that never starts fails the job.
wait_for() {
	tries=0
	until "$@" >/dev/null 2>&1; do
		tries=$((tries + 1))
		if [ "$tries" -gt 60 ]; then
			echo "gave up waiting for: $*" >&2
			exit 1
		fi

		sleep 2
	done
}

for host in mysql-primary mysql-replica; do
	wait_for mysqladmin ping -h "$host" -uroot -p"$ROOT" --silent
done

mysql -h mysql-primary -uroot -p"$ROOT" -e "CREATE USER IF NOT EXISTS 'repl'@'%' IDENTIFIED BY '$REPL'; GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%';"

mysql -h mysql-replica -uroot -p"$ROOT" -e "
STOP REPLICA;
CHANGE REPLICATION SOURCE TO SOURCE_HOST='mysql-primary', SOURCE_USER='repl', SOURCE_PASSWORD='$REPL', SOURCE_AUTO_POSITION=1, GET_SOURCE_PUBLIC_KEY=1;
START REPLICA;
SET PERSIST super_read_only=ON;"

echo 'the replication runs: mysql-replica follows mysql-primary'
