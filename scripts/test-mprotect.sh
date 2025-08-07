set -e

N_TESTS=10000
RES_DIR="results/mprotect"
DATA_FILE="$RES_DIR/mprotect-bench.csv"
PLOT_FILE="$RES_DIR/mprotect-bench.png"

mkdir -p "$RES_DIR"
rm -rf "$RES_DIR/*"

make mprotect-bench
./bin/mprotect-bench -n "$N_TESTS" -f "$DATA_FILE"
python3 scripts/plot-mprotect.py "$DATA_FILE" "$PLOT_FILE"

echo "Mesures terminées, fichiers logs et plots dans $RES_DIR"