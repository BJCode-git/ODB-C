#!/bin/bash

set -e

# Utilise le script ./scripts/test-nginx.sh pour lancer nginx avec ODB et sans Debug
./scripts/launch-nginx-tiers.sh 0 0

# Répertoires et fichiers
LOCUST_FILES_DIR=results/nginx/locust-vanilla
LOCUST_GRAPH_FILES_DIR=results/nginx/graphs-vanilla
CPU_MEASURE_DIR=results/nginx/cpu-conso-vanilla

# Paramètres du test
PROCESS_NAME="nginx"
TEST_DURATION=20  # durée en secondes
TEST_PERIOD=0.1 # période en secondes (100 ms)
LOCUST_USERS=1000
LOCUST_SPAWN_RATE=80

# Nettoyage des anciens résultats
rm -f -r "$LOCUST_FILES_DIR"/* "$LOCUST_GRAPH_FILES_DIR"/* "$CPU_MEASURE_DIR"/*
mkdir -p results/nginx/ "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR" "$CPU_MEASURE_DIR"

# Lancer le monitoring CPU + mémoire pour tous les PIDs nginx
scripts/monitor-perf.sh "$PROCESS_NAME" "$TEST_PERIOD" "$TEST_DURATION" "$CPU_MEASURE_DIR" &

echo "[INFO] Starting Stress Test with Locust..."

# Lancer Locust en arrière-plan
locust -f scripts/locustfile.py \
  --headless \
  -u "$LOCUST_USERS" -r "$LOCUST_SPAWN_RATE" \
  -H http://localhost \
  --run-time "${TEST_DURATION}s" \
  --csv="$LOCUST_FILES_DIR/results" \
  --only-summary &

LOCUST_PID=$!
echo "[INFO] Locust lancé avec PID $LOCUST_PID"

# Attendre la fin du monitoring
MONITOR_PID=$!

# Attendre la fin du test
wait $LOCUST_PID
echo "[INFO] Locust ended."

wait $MONITOR_PID
echo "[INFO] Resources Monitoring ended."

# Générer les graphes Locust
python3 scripts/draw-locust.py "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"
