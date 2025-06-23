#!/bin/bash

# Réglages
FRONT_PORT=10000
BACK_PORT=10001
INTER_PORT=10002
DURATION=10         # durée d'observation en secondes
IFACE="lo"          # interface réseau locale
CSV_FILE="results/odb-results.csv"

# En-tête CSV
echo "nb_IS,buf_size,latency,throughput_KBps,total_bytes,duration_s,total_cpu_s,avg_cpu_per_proc_s" > "$CSV_FILE"

function kill_servs(){
    if [ $# -lt 1 ];
    then
        echo "Usage: kill_servs <nb_IS>"
        return
    fi

    if [ $1 -lt 1 ];
    then
        echo "Usage : kill_servs <nb_IS> >= 1 !"
        return
    fi

    local last_IS=$(( $INTER_PORT + $1-1))
    for port in $(seq $FRONT_PORT  $last_IS); do
        echo "Killing process holding port : $port"
        sudo fuser -k $port/tcp
    done
}

function run_test() {
    if [ $# -lt 2 ];
    then
        echo "Usage: run_test <buf_size> <nb_IS>"
        return
    fi
    local buf_size=$1
    local nb_IS=$2

    if [ $nb_IS -lt 1 ];
    then
        echo "Number of IS must be at least 1"
        return
    fi

    echo "Running test with $buf_size and $nb_IS IS"

    local last_IS=$(($nb_IS-1))
    local temp_dir=results/${nb_IS}/${buf_size}
    local PCAP_FILE="$temp_dir/odb_traffic_capture.pcap"
    local WGET_FILE="$temp_dir/odb_wget.save"

    mkdir -p $temp_dir
    kill_servs $nb_IS

    echo "Testing with buffer size $buf_size and $nb_IS IS ..."

    # Lancer le front-end
    make V=1 QUERY_BYTES=$buf_size BUFF_SIZE=$buf_size DEBUG=0 cpu-run-front-end > "log/sh_fe.log" 2>&1 &
    FRONT_PID=$!

    # Lancer le back-end
    make V=1 BUFF_SIZE=$buf_size DEBUG=0 cpu-run-back-end > "log/sh_be.log" 2>&1 &
    BACK_PID=$!

    # Lancer les IS intermédiaires
    if [ $nb_IS -gt 1 ];
    then
        for i in $(seq 1 $last_IS); do 
            make V=1 BUFF_SIZE=$buf_size DEBUG=0 cpu-run-inter$last_IS > "log/sh_inter$i.log" 2>&1  &
        done
    fi

    # Lancer le dernier IS (connecté au BE)
    make V=1 IS_BEGIN_PORT=$(($INTER_PORT+$last_IS)) BUFF_SIZE=$buf_size DEBUG=0 cpu-run-inter > "log/sh_inter0.log" 2>&1  &

    max_port=$(($FRONT_PORT+$nb_IS))
    echo "[INFO] Lancement de tcpdump sur l'interface $IFACE entre $FRONT_PORT et $max_port..."
	sudo tcpdump -i $IFACE portrange $FRONT_PORT-$max_port  -w $PCAP_FILE &
	TCPDUMP_PID=$!

    sleep 5

    # Lancer la requete / réponse en arriere plan
    echo "[INFO] Lancement de wget..."
    wget 127.0.0.1:$FRONT_PORT -O $WGET_FILE > "log/wget.log" 2>&1
    WGET_PID=$!

    wait $WGET_PID
    kill $TCPDUMP_PID

    # Comparatif des resultats
    echo "[INFO] Comparaison des resultats..."
    cmp results/answer.save results/original_data.save > "log/cmp.log" 2>&1
    # Vérification du code de retour de la commande cmp
    if [ $? -eq 0 ]; then
        echo "[INFO] Data Match !"
    else
        echo "[INFO] Data Dismatch !"
    fi

    # Analyse du trafic
    BYTES=$(tcpdump -nn -r "$PCAP_FILE" -tt 2>/dev/null | grep -Eo 'length [0-9]+' | awk '{sum += $2} END {print sum+0}')
    START_TIME=$(tcpdump -nn -r "$PCAP_FILE" -tt 2>/dev/null | head -n 1 | awk '{print $1}')
    END_TIME=$(tcpdump -nn -r "$PCAP_FILE" -tt 2>/dev/null | tail -n 1 | awk '{print $1}')
    DURATION_REAL=$(awk -v start="$START_TIME" -v end="$END_TIME" 'BEGIN {printf "%.6f", end - start}')

    THROUGHPUT=$(awk -v bytes="$BYTES" -v duration="$DURATION_REAL" 'BEGIN {if(duration>0) printf "%.2f", bytes / duration / 1024; else print "0"}')

    # Latence estimée entre envoi et réception d’un paquet TCP
    LATENCY=$(tcpdump -nn -r "$PCAP_FILE" -tt 2>/dev/null | \
    awk '
        /127\.0\.0\.1\.[0-9]+ > 127\.0\.0\.1\.[0-9]+:/ && /Flags \[P\]/ {
            if (start == "") {
                start = $1
            } else {
                end = $1
                latency = end - start
                printf "%.6f", latency
                exit
            }
        }
    ')
    LATENCY=${LATENCY:-0}

    # Temps CPU total
    CPU_FRONT=$(grep -Eo '[0-9]+\.[0-9]+' results/front-end.time | awk '{sum+=$1} END {print sum}')
    CPU_BACK=$(grep -Eo '[0-9]+\.[0-9]+' results/back-end.time | awk '{sum+=$1} END {print sum}')
    CPU_INTER=$(grep -Eo '[0-9]+\.[0-9]+' results/inter.time | awk '{sum+=$1} END {print sum}')

    CPU_TOTAL=$(awk -v a="$CPU_FRONT" -v b="$CPU_BACK" -v c="$CPU_INTER" 'BEGIN {printf "%.6f", a + b + c}')
    NB_PROC=$(($nb_IS + 2))  # front + back + nb_IS
    CPU_AVG=$(awk -v total="$CPU_TOTAL" -v n="$NB_PROC" 'BEGIN {printf "%.6f", total / n}')

    # Ajout au fichier CSV
    echo "$nb_IS,$buf_size,$LATENCY,$THROUGHPUT,$BYTES,$DURATION_REAL,$CPU_TOTAL,$CPU_AVG" >> "$CSV_FILE"


    # Kill server processes
    kill_servs $nb_IS

    # Suppression des fichiers temporaires
    rm -fr $temp_dir
}

clear
for nb_IS in 2 3 4
do

    for size in 1024 2048 4096 8192 16384 32768 65536 131072
    do
        run_test $size $nb_IS
        #exit 0
    done

done