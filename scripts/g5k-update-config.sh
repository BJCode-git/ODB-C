#!/bin/bash
set -e

files=(
    "config/g5k/ODB-FE.conf"
    "config/g5k/ODB-IS.conf"
    "config/g5k/ODB-BE.conf"
    "config/g5k/nginx-frontend.conf"
    "config/g5k/nginx-inter.conf"
    "config/g5k/nginx-backend.conf"
    "scripts/g5k-run-benchmark.sh"
)

# Charger les variables depuis ips.conf
set -a
source config/g5k/ips.conf
set +a

# Remplacement dans chaque fichier
for f in "${files[@]}"; do
    tmpfile=$(mktemp)
    envsubst < "$f" > "$tmpfile"
    mv "$tmpfile" "$f"
done

echo "Configuration mise à jour."