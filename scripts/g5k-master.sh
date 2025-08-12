#!/bin/bash

set -e
source config/g5k/ips.conf

NUM_CLIENTS=3
N_TESTS=8
COUNT=0

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
	echo "GO" | socat - $IP_BE:$PORT_SLAVE,retry=10,interval=1,crnl,shut-down
	echo "GO" | socat - $IP_IS:$PORT_SLAVE,retry=10,interval=1,crnl,shut-down
	echo "GO" | socat - $IP_FE:$PORT_SLAVE,retry=10,interval=1,crnl,shut-down
}

for i in $(seq $N_TESTS); do

	# cleaning
	echo "Nettoyage des binaires..."
	make clean-lib
	make clean-bin

	# Phase READY : attendre que tous les nœuds soient prêts
	echo "[MASTER] Attente des noeuds..."
	wait_for_slaves
	
	# Envoi du signal  de départ et mesure du temps
	echo "Démarrage du test de stress..."
	./scripts/g5k-run-benchmark.sh odb LOC unaligned unaligned-sending &
	stress_test_pid=$!
	echo "Test $i fini." 


	# Phase FIN : attendre que tous les nœuds aient terminé
	echo "[MASTER] Attente des noeuds..."
	wait_for_slaves
	wait $stress_test_pid

	# Phase READY : attendre que tous les nœuds soient prêts
	echo "[MASTER] Attente des noeuds..."
	wait_for_slaves
	echo "[MASTER] Test $test terminé"

done

echo "Tous les tests de charge sont terminés."
