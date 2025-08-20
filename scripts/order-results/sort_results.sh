PY_SCRIPT="scripts/order-results/compare_results.py"
CP_SCRIPT="scripts/order-results/cp_results.sh"
LOGS_ODB="results/logs/odb/"
LOGS_VANILLA="results/logs/vanilla/"
CMP_DIR="results/results-cmp"

PY_SCRIPT_QOS="scripts/order-results/compare_qos.py"
O_DIR="results/nginx"
QOS_DIR="results/qos-cmp"

mkdir -p results/logs/odb results/plots/odb
mkdir -p results/logs/vanilla results/plots/vanilla
mkdir -p results/results-cmp
mkdir -p results/qos-cmp

#cleaning
rm -rf results/results-cmp/* results/logs/* results/plots/* results/qos-cmp/*

# Trie des logs et des plots
$CP_SCRIPT "results" "odb" "logs" "results"
$CP_SCRIPT "results" "odb" "plots" "results"
$CP_SCRIPT "results" "vanilla" "logs" "results"
$CP_SCRIPT "results" "vanilla" "plots" "results"


# Comparaison de QOS

echo "Comparaison de QOS"

python3 "$PY_SCRIPT_QOS" \
    "$O_DIR/unaligned/no-unaligned-sending" \
    "odb" \
    "$O_DIR/unaligned/unaligned-sending" \
    "odb" \
    "$QOS_DIR/odb_unaligned_dynamic_vs_anticipated" \
    --title1 "ODB non-aligné dynamique" \
    --title2 "ODB non-aligné anticipation"

python3 "$PY_SCRIPT_QOS" \
    "$O_DIR/aligned/no-unaligned-sending" \
    "odb" \
    "$O_DIR/unaligned/no-unaligned-sending" \
    "odb" \
    "$QOS_DIR/odb_aligned_vs_unaligned_dynamic" \
    --title1 "ODB aligné" \
    --title2 "ODB non-aligné"

python3 "$PY_SCRIPT_QOS" \
    "$O_DIR/aligned/no-unaligned-sending" \
    "vanilla" \
    "$O_DIR/unaligned/no-unaligned-sending" \
    "vanilla" \
    "$QOS_DIR/vanilla_aligned_vs_unaligned" \
    --title1 "vanilla aligné" \
    --title2 "vanilla non-aligné"

python3 "$PY_SCRIPT_QOS" \
    "$O_DIR/unaligned/no-unaligned-sending" \
    "odb" \
    "$O_DIR/unaligned/no-unaligned-sending" \
    "vanilla" \
    "$QOS_DIR/odb_dynamic_vs_vanilla_unaligned" \
    --title1 "ODB non-aligné dynamique" \
    --title2 "vanilla non-aligné"

python3 "$PY_SCRIPT_QOS" \
    "$O_DIR/aligned/no-unaligned-sending" \
    "odb" \
    "$O_DIR/aligned/no-unaligned-sending" \
    "vanilla" \
    "$QOS_DIR/odb_dynamic_vs_vanilla_aligned" \
    --title1 "ODB aligné" \
    --title2 "vanilla aligné"

echo "Comparaison de QOS terminée"

# Comparaison des résultats CPU

echo "Comparaison des résultats CPU"

python3 "$PY_SCRIPT" \
    "$LOGS_ODB/unaligned/no-unaligned-sending" \
    "$LOGS_ODB/unaligned/unaligned-sending" \
    "$CMP_DIR/odb_unaligned_dynamic_vs_anticipated" \
    --title1 "ODB non-aligné dynamique" \
    --title2 "ODB non-aligné anticipation"

python3 "$PY_SCRIPT" \
    "$LOGS_ODB/aligned/no-unaligned-sending" \
    "$LOGS_ODB/unaligned/no-unaligned-sending" \
    "$CMP_DIR/odb_aligned_vs_unaligned_dynamic" \
    --title1 "ODB aligné" \
    --title2 "ODB non-aligné"

python3 "$PY_SCRIPT" \
    "$LOGS_VANILLA/aligned/no-unaligned-sending" \
    "$LOGS_VANILLA/unaligned/no-unaligned-sending" \
    "$CMP_DIR/vanilla_aligned_vs_unaligned" \
    --title1 "vanilla aligné" \
    --title2 "vanilla non-aligné"

python3 "$PY_SCRIPT" \
    "$LOGS_ODB/unaligned/no-unaligned-sending" \
    "$LOGS_VANILLA/unaligned/no-unaligned-sending" \
    "$CMP_DIR/odb_dynamic_vs_vanilla_unaligned" \
    --title1 "ODB non-aligné dynamique" \
    --title2 "vanilla non-aligné"

python3 "$PY_SCRIPT" \
    "$LOGS_ODB/aligned/no-unaligned-sending" \
    "$LOGS_VANILLA/aligned/no-unaligned-sending" \
    "$CMP_DIR/odb_dynamic_vs_vanilla_aligned" \
    --title1 "ODB aligné" \
    --title2 "vanilla aligné"

echo "Comparaison des résultats CPU terminée"