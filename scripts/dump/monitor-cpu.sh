#!/bin/bash

# Vérifier les arguments
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <process_name> <duration_in_seconds> <interval_in_seconds> <output_file>"
    exit 1
fi

PROCESS_NAME=$1
DURATION=$2
INTERVAL=$3
OUTPUT_FILE=$4

# Créer/vider le fichier de sortie avec l'entête CSV
echo "Timestamp,PID,%CPU,%MEM" > "$OUTPUT_FILE"

# Obtenir les PIDs
PIDS=$(pgrep -d ',' -x "$PROCESS_NAME")
if [ -z "$PIDS" ]; then
    echo "No process found with name: $PROCESS_NAME"
    exit 1
fi

echo "Monitoring PIDs: $PIDS"
END_TIME=$(($(date +%s%3N) + DURATION * 1000))

while [ "$(date +%s%3N)" -lt "$END_TIME" ]; do
    NOW=$(date +%s.%3N)

    # Exécuter top pour les PIDs (mode batch, trié par PID, sans en-tête)
    top -bn1 -p "$PIDS" | awk -v timestamp="$NOW" '
        BEGIN { skip=1 }
        /^ *PID/ { skip=0; next }
        skip==0 && NF > 0 {
            pid=$1; cpu=$9; mem=$10;
            printf "%s,%s,%s,%s\n", timestamp, pid, cpu, mem;
        }
    ' >> "$OUTPUT_FILE"

    sleep "$INTERVAL"
done

echo "Monitoring completed. Output written to $OUTPUT_FILE"
