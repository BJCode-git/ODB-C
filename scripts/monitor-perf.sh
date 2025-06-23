#!/bin/bash

set -e
# Usage: ./monitor-perf.sh <process_name> <interval_seconds> <duration_seconds> <output_dir>

PROCESS_NAME="$1"
INTERVAL="$2"
DURATION="$3"
CPU_MEASURE_DIR="$4"

if [ -z "$PROCESS_NAME" ] || [ -z "$INTERVAL" ] || [ -z "$DURATION" ] || [ -z "$CPU_MEASURE_DIR" ]; then
    echo "Usage: $0 <process_name> <interval_seconds> <duration_seconds> <output_dir>"
    exit 1
fi

# Trouve les PIDs actifs du processus
PIDS=$(pgrep -x "$PROCESS_NAME")

if [ -z "$PIDS" ]; then
    echo "[ERREUR] Aucun PID trouvé pour le processus '$PROCESS_NAME'"
    exit 1
fi

mkdir -p "$CPU_MEASURE_DIR/logs" "$CPU_MEASURE_DIR/plots"

wait_for=""
for pid in $PIDS; do
    psrecord "$pid" \
        --interval $INTERVAL\
        --duration $DURATION \
        --log "$CPU_MEASURE_DIR/logs/$pid.txt" \
        --plot "$CPU_MEASURE_DIR/plots/$pid.png" &
    wait_for="$wait_for $!"
done

wait $wait_for

echo "Mesures terminées, fichiers logs et plots dans $CPU_MEASURE_DIR"
