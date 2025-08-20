#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${1:-.}"
RESULTS_DIR="${2:-results-logs/odb}"

shopt -s nullglob

# Parcourir tous les dossiers logs
while IFS= read -r -d '' logs_dir; do
  # Extraire alignment, sending-mode, taille, tiers
  if [[ "$logs_dir" =~ nginx/([^/]+)/([^/]+)/([^/]+)/odb/cpu-conso-([^/]+)/logs$ ]]; then
    alignment="${BASH_REMATCH[1]}"
    sending_mode="${BASH_REMATCH[2]}"
    taille="${BASH_REMATCH[3]}"
    tiers="${BASH_REMATCH[4]}"
  else
    echo "!! Chemin inattendu, ignoré: $logs_dir" >&2
    continue
  fi

  # Chercher les CSV du format <tiers>_<PID>.csv
  max_pid=-1
  max_csv=""
  for f in "$logs_dir"/${tiers}_*.csv; do
    base="$(basename "$f")"
    # Extraire PID uniquement si le nom correspond exactement à <tiers>_<PID>.csv
    if [[ "$base" =~ ^${tiers}_([0-9]+)\.csv$ ]]; then
      pid="${BASH_REMATCH[1]}"
      if (( pid > max_pid )); then
        max_pid=$pid
        max_csv="$f"
      fi
    fi
  done

  [[ -z "$max_csv" ]] && { echo "!! Aucun CSV avec format ${tiers}_PID.csv pour $logs_dir"; continue; }

  # Copier le CSV vers le dossier résultat
  dest_dir="$RESULTS_DIR/$alignment/$sending_mode"
  mkdir -p "$dest_dir"
  dest="$dest_dir/cpu_logs_${taille}_${tiers}.csv"

  cp -f "$max_csv" "$dest"
  echo "Copié $max_csv → $dest"

done < <(find "$BASE_DIR" -type d -path "*/nginx/*/*/*/odb/cpu-conso-*/logs" -print0)

