#!/bin/bash

set -e

# ==== Paramètres ====
use_odb="${1:-0}"
use_debugging="${2:-0}"
tier="${3:-ALL}"

# ==== Validation des paramètres ====
if ! [[ "$use_odb" =~ ^[0-9]+$ ]]; then
    echo "Erreur: use_odb doit être un entier"
    exit 1
fi
if ! [[ "$use_debugging" =~ ^[0-9]+$ ]]; then
    echo "Erreur: use_debugging doit être un entier"
    exit 1
fi
if [[ "$tier" != "FE" && "$tier" != "IS" && "$tier" != "BE" && "$tier" != "ALL" ]]; then
    echo "Erreur: tier doit être 'FE', 'IS', 'BE' ou 'ALL'"
    exit 1
fi

use_odb=$(( use_odb > 0 ? 1 : 0 ))
use_debugging=$(( use_debugging > 0 ? 1 : 0 ))

echo "[INFO] ODB: $use_odb | Debug: $use_debugging | Tier ciblé: $tier"
echo "[INFO] Lancement de nginx..."

# ==== Nettoyage ====
echo "[INFO] Killing existing nginx processes..."
sudo kill -9 $(pgrep -x nginx) 2>/dev/null || true

echo "[INFO] Killing processes using the specified ports..."
sudo fuser -k 42000/tcp || echo "Port 42000 libre"
sudo fuser -k 42001/tcp || echo "Port 42001 libre"
sudo fuser -k 42002/tcp || echo "Port 42002 libre"

# ==== Réglages réseau ====
echo "[INFO] Configuration réseau..."
sudo sysctl -w net.ipv4.tcp_rmem="65536 65536 65536"
sudo sysctl -w net.ipv4.tcp_wmem="65536 65536 65536"

# ==== Nettoyage fichiers et SHM ====
echo "[INFO] Suppression des fichiers debug et mémoire partagée..."
rm -f debug/*
ipcrm --all=shm

# ==== Compilation projet ====
echo "[INFO] Compilation du projet..."
sudo make clean-debug && make debug || { echo "❌ Échec compilation principale"; exit 1; }

# ==== Compilation librairies selon le tier ====
build_lib() {
  local tier_name=$1
  echo "[INFO] Compilation de lib/lib${tier_name}_odb.so"
  make USE_STANDALONE=0 USE_ODB="$use_odb" DEBUG="$use_debugging" "lib/lib${tier_name}_odb.so" 1> /dev/null || {
    echo "❌ Échec compilation lib${tier_name}_odb.so"
    exit 1
  }
}

launch_nginx() {
  local tier_name=$1
  local conf_file=$2
  echo "[INFO] Lancement nginx ($tier_name)..."
  sudo -E LD_PRELOAD="./lib/lib${tier_name}_odb.so" nginx -c "$(pwd)/config/$conf_file" || {
    echo "❌ Échec lancement nginx ($tier_name)"
    exit 1
  }
  local serv_pid=$!
  echo "Lauch $tier_name with PID $serv_pid" 
}

#launch_nginx() {
#  local tier_name=$1
#  local conf_file=$2
#  echo "[INFO] Lancement nginx ($tier_name)..."
#
#  if [[ "$tier_name" == "IS" ]]; then
#    echo "[DEBUG] Lancement nginx ($tier_name) avec strace (en background)"
#
#    sudo -E strace -ff -tt -T -e trace=recv,read,recvfrom,recvmsg,epoll_wait,epoll_pwait \
#      -o "strace_${tier_name}" \
#      env LD_PRELOAD="./lib/lib${tier_name}_odb.so" \
#      nginx -c "$(pwd)/config/$conf_file" &
#
#  else
#    sudo -E LD_PRELOAD="./lib/lib${tier_name}_odb.so" nginx -c "$(pwd)/config/$conf_file"
#  fi
#}

case "$tier" in
  "FE"|"ALL")
    build_lib FE
    launch_nginx FE nginx-frontend.conf
    ;;
esac

case "$tier" in
  "IS"|"ALL")
    build_lib IS
    launch_nginx IS nginx-inter.conf
    ;;
esac

case "$tier" in
  "BE"|"ALL")
    build_lib BE
    launch_nginx BE nginx-backend.conf
    ;;
esac

echo "[✅] Nginx lancé avec succès pour tier: $tier"
