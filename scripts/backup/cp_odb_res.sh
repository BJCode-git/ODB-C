#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./collect_cpu_plots.sh [BASE_DIR=. ] [RESULTS_DIR=results/odb]
BASE_DIR="${1:-.}"
RESULTS_DIR="${2:-results/plots-odb}"

shopt -s nullglob

# On cherche tous les dossiers .../nginx/<alignment>/<sending-mode>/<taille>/odb/cpu-conso-<tiers>/plots
while IFS= read -r -d '' plots_dir; do
  # Extraire alignment, sending-mode, taille, tiers via regex, robuste aux préfixes (ex: results-final-odb/)
  if [[ "$plots_dir" =~ nginx/([^/]+)/([^/]+)/([^/]+)/odb/cpu-conso-([^/]+)/plots$ ]]; then
    alignment="${BASH_REMATCH[1]}"
    sending_mode="${BASH_REMATCH[2]}"
    taille="${BASH_REMATCH[3]}"
    tiers="${BASH_REMATCH[4]}"
  else
    echo "!! Chemin inattendu, ignoré: $plots_dir" >&2
    continue
  fi

  # Candidats: <tiers>_<pid> (ignorer *_io, *_sys)
  mapfile -t candidates < <(
    find "$plots_dir" -mindepth 1 -maxdepth 1 -type d \
      -regextype posix-extended -regex ".*/${tiers}_[0-9]+$" | sort
  )
  [[ ${#candidates[@]} -eq 0 ]] && { echo "!! Aucun dossier pid pour $plots_dir"; continue; }

  # Sélection du pid max
  max_dir=""
  max_pid=-1
  for d in "${candidates[@]}"; do
    base="$(basename "$d")"
    pid="${base#${tiers}_}"
    if [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > max_pid )); then
      max_pid=$pid
      max_dir="$d"
    fi
  done
  [[ -z "$max_dir" ]] && { echo "!! Pas de pid max pour $plots_dir"; continue; }

  # Récupérer le PNG (on suppose un seul graph)
  pngs=( "$max_dir"/*.png )
  [[ ${#pngs[@]} -eq 0 ]] && { echo "!! Aucun PNG dans $max_dir"; continue; }
  src="${pngs[0]}"

  # Destination: results/odb/<alignment>/<sending-mode>/cpu_plot_<taille>_<tiers>.png
  dest_dir="$RESULTS_DIR/$alignment/$sending_mode"
  mkdir -p "$dest_dir"
  dest="$dest_dir/cpu_plot_${taille}_${tiers}.png"

  cp -f "$src" "$dest"
  echo "Copié $src → $dest"
done < <(find "$BASE_DIR" -type d -path "*/nginx/*/*/*/odb/cpu-conso-*/plots" -print0)

