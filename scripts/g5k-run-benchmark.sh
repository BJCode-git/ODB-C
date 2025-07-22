#!/bin/bash

#set -e

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

# Utilise le script suivant pour configurer et lancer nginx
./scripts/g5k-launch-nginx.sh "$use_odb" "$use_debug" "$tier"

for size in "16K" "32K" "64K" "128K" "256K"; do

  echo "[INFO] Démarrage du test de charge Nginx pour la taille $size avec le mode $mode et le tier $tier"
  # Répertoires et fichiers
  RESULTS_DIR="results/nginx"
  LOCUST_FILES_DIR="$RESULTS_DIR/$size/$mode/locust-$tier"
  LOCUST_GRAPH_FILES_DIR="$RESULTS_DIR/$size/$mode/graphs-$tier"
  CPU_MEASURE_DIR="$RESULTS_DIR/$size/$mode/cpu-conso-$tier"
  NGINX_PIDS_FILE="$CPU_MEASURE_DIR/nginx-pids-$tier.txt"

  # Paramètres du test
  PROCESS_NAME="nginx"
  TEST_DURATION=100  # durée en secondes
  TEST_PERIOD=0.1 # période en secondes (100 ms)
  LOCUST_USERS=1000
  LOCUST_SPAWN_RATE=50

  # Nettoyage des anciens résultats
  rm -f -r "$CPU_MEASURE_DIR"/*
  mkdir -p "$RESULTS_DIR" "$CPU_MEASURE_DIR"

  # Sauvegarde les PIDs de Nginx dans le fichier nginx_pids.txt 
  if [[ -f "/run/nginx-backend.pid" ]]; then
    echo "PID nginx-backend: $(cat /run/nginx-backend.pid)" >> "$NGINX_PIDS_FILE"
  fi
  if [[ -f "/run/nginx-frontend.pid" ]]; then
    echo "PID nginx-frontend: $(cat /run/nginx-frontend.pid)" >> "$NGINX_PIDS_FILE"
  fi
  if [[ -f "/run/nginx-inter.pid" ]]; then
    echo "PID nginx-inter: $(cat /run/nginx-inter.pid)" >> "$NGINX_PIDS_FILE"
  fi

  # Lancer le monitoring CPU + mémoire pour tous les PIDs nginx
  scripts/monitor-perf.sh "$PROCESS_NAME" "$TEST_PERIOD" "$TEST_DURATION" "$CPU_MEASURE_DIR" &

  if [[  "$tier" == "FE" || "$tier" == "ALL" ]]; then
  # Nettoyage des anciens résultats
  rm -f -r "$LOCUST_FILES_DIR"/* "$LOCUST_GRAPH_FILES_DIR"/*
  mkdir -p "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"

  echo "[INFO] Démarrage du test de charge avec Locust..."
  # Lancer Locust en arrière-plan
  locust -f scripts/locust/locustfile.py \
    --headless \
    --tags "$size" \
    -u "$LOCUST_USERS" -r "$LOCUST_SPAWN_RATE" \
    -H http://172.16.20.:42000 \
    --run-time "${TEST_DURATION}s" \
    --csv="$LOCUST_FILES_DIR/results" \
    --loglevel=CRITICAL \
    --only-summary &

    LOCUST_PID=$!
    echo "[INFO] Locust lancé avec PID $LOCUST_PID"
  fi

  MONITOR_PID=$!
  echo "[INFO] Surveillance CPU/Mémoire lancée avec PID $MONITOR_PID"

  wait $MONITOR_PID
  echo "[INFO] Monitoring terminé."

  # Attendre la fin du test
  if [[ "$tier" == "FE" || "$tier" == "ALL" ]]; then
    
    wait $LOCUST_PID
    echo "[INFO] Locust terminé."

    # Générer les graphes Locust
    python3 scripts/locust/draw-locust.py "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"
  fi

done;

