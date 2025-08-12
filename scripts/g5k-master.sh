#!/bin/bash

set -e
source config/g5k/ips.conf

NUM_CLIENTS=3

wait_for_slaves() {
	local COUNT=0
	while [ $COUNT -lt $NUM_CLIENTS ]; do
		socat - TCP-LISTEN:$PORT_MASTER,reuseaddr,shut-down > /dev/null &
		wait $!
		COUNT=$((COUNT+1))
		echo "[MASTER] Serveur $COUNT, ready."
	done
}

start_slaves() {
	echo "GO" | socat - TCP:$IP_BE:$PORT_SLAVE,retry=10,interval=3,shut-down
	echo "GO" | socat - TCP:$IP_IS:$PORT_SLAVE,retry=10,interval=3,shut-down
	echo "GO" | socat - TCP:$IP_FE:$PORT_SLAVE,retry=10,interval=3,shut-down
}

ready_phase() {
	# Phase READY : attendre que tous les nœuds soient prêts
	echo "[MASTER] Attente des noeuds..."
	wait_for_slaves
	echo "[MASTER] Tous les noeuds sont prêts."
}

stress_phase() {
	echo "Démarrage du test de stress..."
	# Envoi du signal  de départ
	start_slaves
}

end_phase() {
	local stress_pid=$1
	echo "[MASTER] Attente des noeuds..."
	wait_for_slaves
	echo "[MASTER] Tous les noeuds ont terminé."
	wait $stress_pid
}

tests() {

	local use_odb=$1
	local test_pid=0
	local range=("16K" "32K" "64K" "128K" "256K")
	cmd="odb"
	if [[ "$use_odb" -eq 0 ]]; then
		cmd="vanilla"
	fi
	
	echo "Starting $cmd tests..."
	
	#wait_for_go
	echo "[MASTER] Start test with aligned buffer, no unaligned sending"
	for size in "${range[@]}"; do
		ready_phase
		stress_phase
		./scripts/g5k-run-benchmark.sh $cmd LOC aligned unaligned-sending $size &
		test_pid=$!
		end_phase $test_pid
	done;

	#wait_for_go
	echo "[MASTER] Start test with aligned buffer, unaligned sending"
	for size in "${range[@]}"; do
		ready_phase
		stress_phase
		./scripts/g5k-run-benchmark.sh $cmd LOC aligned no-unaligned-sending $size &
		test_pid=$!
		end_phase $test_pid
	done;

	#wait_for_go
	echo "[MASTER] Start test with unaligned buffer, no unaligned sending"
	for size in "${range[@]}"; do
		ready_phase
		stress_phase
		./scripts/g5k-run-benchmark.sh $cmd LOC unaligned unaligned-sending $size &
		test_pid=$!
		end_phase $test_pid
	done;

	#wait_for_go
	echo "[MASTER] Start test with unaligned buffer, unaligned sending"
	for size in "${range[@]}"; do
		ready_phase
		stress_phase
		./scripts/g5k-run-benchmark.sh $cmd LOC unaligned no-unaligned-sending $size &
		test_pid=$!
		end_phase $test_pid
	done;

	echo "[MASTER] Test $cmd terminé"
}

tests 0
tests 1

echo "Tous les tests de charge sont terminés."
