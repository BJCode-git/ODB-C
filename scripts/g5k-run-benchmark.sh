#!/bin/bash

#set -e

# ==== Lecture des arguments ====
mode="${1:-odb}"
tier="${2:-ALL}"
alignement="${3:-unaligned}"
unaligned_sending="${4:-unaligned-sending}"

print_usage() {
  echo -e "Usage: $0 \n<mode : odb | vanilla> \n<tier : LOC | FE | IS | BE | ALL> \n<alignement : aligned | unaligned> \n<unaligned_sending : no-unaligned-sending | unaligned-sending>"
}

# Vérification des arguments
if [[ "$mode" != "odb" && "$mode" != "vanilla" ]]; then
  print_usage
  exit 1
fi

if [[ "$tier" != "LOC" && "$tier" != "FE" && "$tier" != "IS" && "$tier" != "BE" && "$tier" != "ALL" ]]; then
  print_usage
  exit 1
fi

if [[ "$alignement" != "aligned" && "$alignement" != "unaligned" ]]; then
  print_usage
  exit 1
fi

if [[ "$unaligned_sending" != "no-unaligned-sending" && "$unaligned_sending" != "unaligned-sending" ]]; then
  print_usage
  exit 1
fi

# ==== Déterminer les paramètres pour launch-nginx-tiers.sh ====
use_debug=0

use_odb=1
if [ "$mode" == "vanilla" ]; then
  use_odb=0
fi

# Paramètres pour launch-nginx-tiers.sh
use_alignement=0
if [ "$alignement" == "aligned" ]; then
  use_alignement=1
fi

use_unaligned_sending=1
if [ "$unaligned_sending" == "no-unaligned-sending" ]; then
  use_unaligned_sending=0
fi

# Paramètres globaux du test
PROCESS_NAME="nginx"
# Répertoires et fichiers
RESULTS_DIR="results/$PROCESS_NAME/$alignement/$unaligned_sending"
TEST_DURATION=100  # durée en secondes
TEST_PERIOD=100    # période en ms
LOCUST_USERS=1000
LOCUST_SPAWN_RATE=50


# Utilise le script suivant pour configurer et lancer nginx
if [[ "$tier" != "LOC" ]]; then
  ./scripts/g5k-launch-nginx.sh "$use_odb" "$use_debug" "$tier" "$use_alignement" "$use_unaligned_sending"
fi

for size in "16K" "32K" "64K" "128K" "256K"; do

  echo "[INFO] Démarrage du test de charge Nginx pour la taille $size avec le mode $mode et le tier $tier"
  

  # Lancer le monitoring CPU + mémoire pour tous les PIDs nginx
  if [[ "$tier" != "LOC" ]]; then

    CPU_MEASURE_DIR="$RESULTS_DIR/$size/$mode/cpu-conso-$tier"
    NGINX_PIDS_FILE="$CPU_MEASURE_DIR/nginx-pids-$tier.txt"

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

    scripts/monitor-perf.sh "$PROCESS_NAME" "$TEST_PERIOD" "$TEST_DURATION" "$CPU_MEASURE_DIR" "$tier" & MONITOR_PID=$!
    echo "[INFO] Surveillance CPU/Mémoire lancée avec PID $MONITOR_PID"
  fi

  if [[  "$tier" == "LOC" || "$tier" == "ALL" ]]; then

    LOCUST_FILES_DIR="$RESULTS_DIR/$size/$mode/locust-$tier"
    LOCUST_GRAPH_FILES_DIR="$RESULTS_DIR/$size/$mode/graphs-$tier"

    # Nettoyage des anciens résultats
    rm -f -r "$LOCUST_FILES_DIR"/* "$LOCUST_GRAPH_FILES_DIR"/*
    mkdir -p "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"

    echo "[INFO] Démarrage du test de charge avec Locust..."
    # Lancer Locust en arrière-plan
    locust -f scripts/locust/locustfile.py \
      --headless \
      --tags "$size" \
      -u "$LOCUST_USERS" -r "$LOCUST_SPAWN_RATE" \
      -H http://IP_FE:42000 \
      --run-time "${TEST_DURATION}s" \
      --csv="$LOCUST_FILES_DIR/results" \
      --loglevel=CRITICAL \
      --only-summary & LOCUST_PID=$!
  
    echo "[INFO] Locust lancé avec PID $LOCUST_PID"
  fi

  # Attendre la fin du monitoring nginx
  if [[ "$tier" != "LOC" ]]; then

    wait $MONITOR_PID
    echo "[INFO] Monitoring terminé."

  fi

  # Attendre la fin du test de charge
  if [[ "$tier" == "LOC" || "$tier" == "ALL" ]]; then
    
    wait $LOCUST_PID
    echo "[INFO] Locust terminé."

    # Générer les graphes Locust
    python3 scripts/locust/draw-locust.py "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"

  fi

done;

echo "[INFO] Tous les tests de charge sont terminés."