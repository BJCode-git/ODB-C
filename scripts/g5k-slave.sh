#!/bin/bash

set -e
source config/g5k/ips.conf

tier="${1:-NONE}"

if [[ "$tier" != "FE" && "$tier" != "IS" && "$tier" != "BE" ]]; then
  echo "Usage: $0 FE|IS|BE"
  exit 1
fi


wait_for_go() {
	MSG=$(socat - TCP-LISTEN:$PORT_SLAVE,reuseaddr,shut-down)
	if [ "$MSG" == "GO" ]; then
		return
	else
		echo "Erreur => Message recu : $MSG"
		exit 1
	fi
}

send_done() {
	echo "DONE" | socat - TCP:$IP_MASTER:$PORT_MASTER,retry=10,interval=1,crnl,shut-down
}

tests() {

	local use_odb=$1
	cmd="odb"
	if [[ "$use_odb" -eq 0 ]]; then
		cmd="vanilla"
	fi
	
	echo "Starting $cmd tests..."
	
	wait_for_go
	echo "Start test with aligned buffer, no unaligned sending"
	./scripts/g5k-run-benchmark.sh $cmd $tier aligned unaligned-sending
	send_done

	wait_for_go
	echo "Start test with aligned buffer, unaligned sending"
	./scripts/g5k-run-benchmark.sh $cmd $tier aligned no-unaligned-sending
	send_done

	wait_for_go
	echo "Start test with unaligned buffer, no unaligned sending"	
	./scripts/g5k-run-benchmark.sh $cmd $tier unaligned unaligned-sending
	send_done

	wait_for_go
	echo "Start test with unaligned buffer, unaligned sending"
	./scripts/g5k-run-benchmark.sh $cmd $tier unaligned no-unaligned-sending
	send_done
}

tests 0
tests 1