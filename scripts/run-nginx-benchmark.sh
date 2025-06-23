#!/bin/bash

set -e

# ==== Lecture des arguments ====
mode="${1:-odb}"
tier="${2:-ALL}"

# Vérification des arguments
if [[ "$mode" != "odb" && "$mode" != "vanilla" ]]; then
  echo "Erreur: Le premier argument doit être 'odb' ou 'vanilla'"
  exit 1
fi

if [[ "$tier" != "FE" && "$tier" != "IS" && "$tier" != "BE" && "$tier" != "ALL" ]]; then
  echo "Erreur: Le second argument doit être 'FE', 'IS', 'BE' ou 'ALL'"
  exit 1
fi

# ==== Déterminer les paramètres pour launch-nginx-tiers.sh ====
if [ "$mode" == "odb" ]; then
  use_odb=1
else
  use_odb=0
fi

use_debug=0

# Répertoires et fichiers
LOCUST_FILES_DIR="results/nginx/locust-$mode"
LOCUST_GRAPH_FILES_DIR="results/nginx/graphs-$mode"
CPU_MEASURE_DIR="results/nginx/cpu-conso-$mode"

# Paramètres du test
PROCESS_NAME="nginx"
TEST_DURATION=20  # durée en secondes
TEST_PERIOD=0.1 # période en secondes (100 ms)
LOCUST_USERS=1000
LOCUST_SPAWN_RATE=80

# Nettoyage des anciens résultats
rm -f -r "$LOCUST_FILES_DIR"/* "$LOCUST_GRAPH_FILES_DIR"/* "$CPU_MEASURE_DIR"/*
mkdir -p results/nginx/ "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR" "$CPU_MEASURE_DIR"

# Utilise le script ./scripts/test-nginx.sh pour lancer nginx avec ODB et sans Debug
./scripts/launch-nginx-tiers.sh "$use_odb" "$use_debug" "$tier"

# Lancer le monitoring CPU + mémoire pour tous les PIDs nginx
scripts/monitor-perf.sh "$PROCESS_NAME" "$TEST_PERIOD" "$TEST_DURATION" "$CPU_MEASURE_DIR" &

echo "[INFO] Démarrage du test de charge avec Locust..."
if [[  "$tier" == "FE" || "$tier" == "ALL" ]]; then
echo "[INFO] Démarrage du test de charge avec Locust..."
# Lancer Locust en arrière-plan
locust -f scripts/locustfile.py \
  --headless \
  -u "$LOCUST_USERS" -r "$LOCUST_SPAWN_RATE" \
  -H http://localhost:42000 \
  --run-time "${TEST_DURATION}s" \
  --csv="$LOCUST_FILES_DIR/results" \
  --only-summary &

  LOCUST_PID=$!
  echo "[INFO] Locust lancé avec PID $LOCUST_PID"
fi

MONITOR_PID=$!
echo "[INFO] Surveillance CPU/Mémoire lancée avec PID $MONITOR_PID"

# Attendre la fin du test
if [[ "$tier" == "FE" || "$tier" == "ALL" ]]; then
wait $LOCUST_PID
echo "[INFO] Locust terminé."
fi

wait $MONITOR_PID
echo "[INFO] Monitoring terminé."


# Générer les graphes Locust
python3 scripts/draw-locust.py "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"
