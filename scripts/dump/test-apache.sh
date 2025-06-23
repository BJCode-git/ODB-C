#!/bin/bash

# Si un argument est défini, le récupérer
use_odb=0
if [ -n "$1" ]; then
    use_odb=$1
fi

# Vérifier si use_odb est un nombre
if ! [[ "$use_odb" =~ ^[0-9]+$ ]]; then
    echo "use_odb must be a number"
    exit 1
fi

# Si use_odb est > 0, le définir à 1
if [ "$use_odb" -gt 0 ]; then
    use_odb=1
fi

if [ "$use_odb" -eq 1 ]; then
    echo "Using ODB"
else
    echo "Not using ODB"
fi

echo "Launching Apache...."

# Tuer les processus Apache existants
echo "Killing existing Apache processes..."
sudo kill -9 $(pgrep -x apache2)

# Configurer les paramètres réseau
echo "Configuring network settings..."
sudo sysctl -w net.ipv4.tcp_rmem="8192 87380 16777216"
sudo sysctl -w net.core.rmem_default=1048576

# Nettoyer les fichiers de debug et la mémoire partagée
echo "Cleaning up debug files and shared memory..."
rm -f debug/*
ipcrm --all=shm

# Construire le projet
echo "Building the project..."
sudo make clean-debug && make debug || { echo "Failed to build the project"; exit 1; }

echo "Building ODB library..."
make USE_ODB="$use_odb" DEBUG=1 lib/libnewodb.so || { echo "Failed to build ODB library"; exit 1; }

# Tuer les processus utilisant les ports spécifiés
echo "Killing processes using the specified ports..."
sudo fuser -k 80/tcp || echo "No process using port 80"
sudo fuser -k 8080/tcp || echo "No process using port 8080"
sudo fuser -k 3000/tcp || echo "No process using port 3000"

# Lancer Apache avec la bibliothèque personnalisée
echo "Launching Apache with the custom library..."
sudo LD_PRELOAD=./lib/libnewodb.so apache2 -f $(pwd)/config/apache.conf -D FOREGROUND || { echo "Failed to launch Apache"; exit 1; }

echo "Apache has been successfully launched."