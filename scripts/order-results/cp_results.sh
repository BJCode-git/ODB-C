#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./collect_cpu.sh [BASE_DIR=. ] [RESULTS_DIR=results/odb] [MODE=plots|logs]
BASE_DIR="${1:-results}"
PROTO="${2:-odb}"
MODE="${3:-plots}"   # "plots" ou "logs"
RESULTS_DIR="${4:-results}"

shopt -s nullglob

#Determiner le suffixe attendu selon le protocole
if [[ "$PROTO" != "odb" && "$PROTO" != "vanilla" ]]; then
	echo "!! PROTO invalide : $PROTO (attendu: odb ou vanilla)" >&2
	exit 1
fi

# Déterminer le suffixe attendu selon le mode
if [[ "$MODE" == "plots" ]]; then
  subdir="plots"
  out_prefix="cpu_plot"
  out_ext="png"
elif [[ "$MODE" == "logs" ]]; then
  subdir="logs"
  out_prefix="cpu_logs"
  out_ext="csv"
else
  echo "!! MODE invalide : $MODE (attendu: plots ou logs)" >&2
  exit 1
fi

RESULTS_DIR="$RESULTS_DIR/$MODE/$PROTO"

# On cherche tous les dossiers .../nginx/<alignment>/<sending-mode>/<taille>/odb/cpu-conso-<tiers>/$subdir
while IFS= read -r -d '' dir; do
  if [[ "$dir" =~ nginx/([^/]+)/([^/]+)/([^/]+)/$PROTO/cpu-conso-([^/]+)/$subdir$ ]]; then
    alignment="${BASH_REMATCH[1]}"
    sending_mode="${BASH_REMATCH[2]}"
    taille="${BASH_REMATCH[3]}"
    tiers="${BASH_REMATCH[4]}"
  else
    echo "!! Chemin inattendu, ignoré: $dir" >&2
    continue
  fi

  max_pid=-1
  src=""

  if [[ "$MODE" == "plots" ]]; then
    # Chercher dossiers <tiers>_<pid>
    mapfile -t candidates < <(
      find "$dir" -mindepth 1 -maxdepth 1 -type d \
        -regextype posix-extended -regex ".*/${tiers}_[0-9]+$" | sort
    )
    [[ ${#candidates[@]} -eq 0 ]] && { echo "!! Aucun dossier pid pour $dir"; continue; }

    for d in "${candidates[@]}"; do
      pid="${d##*_}"
      if (( pid > max_pid )); then
        max_pid=$pid
        # suppose un seul PNG dans le dossier
        pngs=( "$d"/*.png )
        [[ ${#pngs[@]} -gt 0 ]] && src="${pngs[0]}"
      fi
    done

  else # logs
    for f in "$dir"/${tiers}_*.csv; do
      base="$(basename "$f")"
      if [[ "$base" =~ ^${tiers}_([0-9]+)\.csv$ ]]; then
        pid="${BASH_REMATCH[1]}"
        if (( pid > max_pid )); then
          max_pid=$pid
          src="$f"
        fi
      fi
    done
  fi

  [[ -z "$src" ]] && { echo "!! Aucun fichier trouvé pour $dir"; continue; }

  dest_dir="$RESULTS_DIR/$alignment/$sending_mode"
  mkdir -p "$dest_dir"
  dest="$dest_dir/${out_prefix}_${taille}_${tiers}.${out_ext}"

  cp -f "$src" "$dest"
  echo "Copié $src → $dest"

done < <(find "$BASE_DIR" -type d -path "*/nginx/*/*/*/$PROTO/cpu-conso-*/$subdir" -print0)

