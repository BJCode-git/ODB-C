#!/bin/bash

set -e

print_usage() {
  echo "Usage: $0 <use_odb : 0 | 1 > <use_debugging : 0 | 1 > <tier : FE | IS | BE | ALL> <use_alignement : 0 | 1 > <use_send_unaligned : 0 | 1 >"
}

# ==== Paramètres ====
use_odb="${1:-0}"
use_debugging="${2:-0}"
tier="${3:-ALL}"
use_alignement="${4:0}"
use_send_unaligned="${5:-1}"


# ==== Validation des paramètres ====
if ! [[ "$use_odb" =~ ^[0-9]+$ ]]; then
    print_usage
    exit 1
fi
if ! [[ "$use_debugging" =~ ^[0-9]+$ ]]; then
    print_usage
    exit 1
fi
if [[ "$tier" != "FE" && "$tier" != "IS" && "$tier" != "BE" && "$tier" != "ALL" ]]; then
    print_usage
    exit 1
fi

if [[ "$use_alignement" != "0" && "$use_alignement" != "1" ]]; then
    print_usage
    exit 1
fi

if [[ "$use_send_unaligned" != "0" && "$use_send_unaligned" != "1" ]]; then
    print_usage
    exit 1
fi

use_odb=$(( use_odb > 0 ? 1 : 0 ))
use_debugging=$(( use_debugging > 0 ? 1 : 0 ))
use_alignement=$(( use_alignement > 0 ? 1 : 0 ))


echo "[INFO] ODB: $use_odb | Debug: $use_debugging | Tier ciblé: $tier"
echo "[INFO] Lancement de nginx..."

# ==== Nettoyage ====
echo "[INFO] Killing existing nginx processes..."
sudo-g5k kill -9 $(pgrep -x nginx) 2>/dev/null || true

echo "[INFO] Killing processes using the specified ports..."
sudo-g5k fuser -k 42000/tcp || echo "Port 42000 libre"
sudo-g5k fuser -k 42001/tcp || echo "Port 42001 libre"
sudo-g5k fuser -k 42002/tcp || echo "Port 42002 libre"

# ==== Réglages réseau ====
echo "[INFO] Configuration réseau..."
sudo-g5k sysctl -w net.ipv4.tcp_rmem="262144 262144 262144"
sudo-g5k sysctl -w net.ipv4.tcp_wmem="262144 262144 262144"

# ==== Nettoyage fichiers et SHM ====
echo "[INFO] Suppression des fichiers debug"
rm -f debug/*

# ==== Compilation projet ====
echo "[INFO] Compilation du projet..."
sudo-g5k make clean-debug && make debug || { echo "❌ Échec compilation principale"; exit 1; }

# ==== Compilation librairies selon le tier ====

build_slimguard() {
  echo "[INFO] Compilation de lib/libslimguard.so"
  echo "[INFO] pwd: $(pwd)"
  make lib/libSlimGuard.so || { echo "❌ Échec compilation libslimguard.so"; exit 1; }
}

build_lib() {

  if [[ use_alignement -eq 1 ]]; then
    build_slimguard
  fi
  
  if [[ "$use_odb" -eq 0 ]]; then
    return
  fi

  local tier_name=$1
  echo "[INFO] Compilation de lib/lib${tier_name}_odb.so"
  make -j$(nproc) USE_STANDALONE=0 USE_ODB="$use_odb" DEBUG="$use_debugging" USE_UNALIGNED_SENDING="$use_send_unaligned" "lib/lib${tier_name}_odb.so" 1> /dev/null || {
    echo "❌ Échec compilation lib${tier_name}_odb.so"
    exit 1
  }
}

launch_nginx() {
  local tier_name=$1
  local conf_file=$2
  echo "[INFO] Lancement nginx ($tier_name)..."

  LD_PRELOAD=""
  if [[ use_alignement -eq 1 ]]; then
    LD_PRELOAD="$LD_PRELOAD ./lib/libSlimGuard.so"
  fi
  if [[ "$use_odb" -eq 1 ]]; then
    LD_PRELOAD="$LD_PRELOAD ./lib/lib${tier_name}_odb.so"
  fi

  if [[ -n "$LD_PRELOAD" ]]; then
    echo "[INFO] Using LD_PRELOAD=\"$LD_PRELOAD\""
    sudo-g5k -E env LD_PRELOAD="$LD_PRELOAD" nginx -c "$(pwd)/config/g5k/$conf_file" || {
      echo "❌ Échec lancement nginx ($tier_name)"
      exit 1
    }
  else
    sudo-g5k nginx -c "$(pwd)/config/g5k/$conf_file" || {
      echo "❌ Échec lancement nginx ($tier_name)"
      exit 1
    }
  fi
  
  local serv_pid=$!
  echo "Lauch $tier_name with PID $serv_pid" 
}

case "$tier" in
  "FE"|"ALL")
    build_lib FE
    export ODB_CONF_PATH="config/g5k/ODB-FE.conf"
    launch_nginx FE nginx-frontend.conf
    ;;
esac

case "$tier" in
  "IS"|"ALL")
    build_lib IS
    export ODB_CONF_PATH="config/g5k/ODB-IS.conf"
    launch_nginx IS nginx-inter.conf
    ;;
esac

case "$tier" in
  "BE"|"ALL")
    build_lib BE
    export ODB_CONF_PATH="config/g5k/ODB-BE.conf"
    launch_nginx BE nginx-backend.conf
    ;;
esac

echo "[✅] Nginx lancé avec succès pour tier: $tier"
