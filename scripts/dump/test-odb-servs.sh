#!/bin/bash



for size in 1024 2048 4096 8192 16384 32768 65536 131072
do
  # Utilise le script ./scripts/launch_servers.sh pour lancer nginx avec ODB et sans Debug
  ./scripts/launch_servs.sh 1 $size

  sleep 2

  # Répertoires et fichiers
  BASE_DIR=results/servs-${size}
  LOCUST_FILES_DIR=$BASE_DIR/locust-odb
  LOCUST_GRAPH_FILES_DIR=$BASE_DIR/graphs-odb
  CPU_LOG_FILE=$BASE_DIR/cpu-odb.log
  CPU_GRAPH_DIR=$BASE_DIR/graphs-odb-cpu-conso/

  # Paramètres du test
  PROCESS_NAME="inter"
  TEST_DURATION=20  # durée en secondes
  TEST_PERIOD=0.001 # periode en secondes
  LOCUST_USERS=1000
  LOCUST_SPAWN_RATE=80

  # Nettoyage des anciens résultats
  rm -f -r $LOCUST_FILES_DIR/* $LOCUST_GRAPH_FILES_DIR/* $CPU_LOG_FILE $CPU_GRAPH_DIR/*
  mkdir -p $BASE_DIR $LOCUST_FILES_DIR $LOCUST_GRAPH_FILES_DIR $CPU_GRAPH_DIR

  echo "[INFO] Démarrage du test de charge avec Locust..."

  # Lancer Locust en arrière-plan (durée = TEST_DURATION secondes)
  locust -f scripts/locustfile.py \
    --headless \
    -u $LOCUST_USERS -r $LOCUST_SPAWN_RATE \
    -H http://localhost:10000 \
    --run-time ${TEST_DURATION}s \
    --csv=$LOCUST_FILES_DIR/results \
    --only-summary &

  LOCUST_PID=$!
  echo "[INFO] Locust lancé avec PID $LOCUST_PID"

  # Lancer la surveillance CPU en parallèle (même durée TEST_DURATION)
  scripts/monitor-cpu.sh $PROCESS_NAME $TEST_DURATION $TEST_PERIOD $CPU_LOG_FILE &

  MONITOR_PID=$!
  echo "[INFO] Surveillance CPU lancée avec PID $MONITOR_PID"

  # Attendre la fin de Locust
  wait $LOCUST_PID
  echo "[INFO] Locust terminé."

  # Attendre la fin du monitoring CPU
  wait $MONITOR_PID
  echo "[INFO] Monitoring CPU terminé."

  # Générer les graphes CPU
  python scripts/draw-cpu-conso.py "$CPU_LOG_FILE" "$CPU_GRAPH_DIR"

  # Générer les graphes Locust
  python scripts/draw-locust.py "$LOCUST_FILES_DIR" "$LOCUST_GRAPH_FILES_DIR"

done
