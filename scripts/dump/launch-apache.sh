#!/bin/bash

# If an argument is defined, get it
use_odb=0
use_debugging=0
if [ -n "$1" ]; then
    use_odb=$1
fi

# Check if use_odb is a number
if ! [[ "$use_odb" =~ ^[0-9]+$ ]]; then
    echo "use_odb must be a number"
    exit 1
fi

# If use_odb is > 0, set it to 1
if [ "$use_odb" -gt 0 ]; then
    use_odb=1
fi

if [ "$use_odb" -eq 1 ]; then
    echo "Using ODB"
else
    echo "Not using ODB"
fi

# If an argument is defined, get it
if [ -n "$2" ]; then
    use_debugging=$2
fi

# If use_debugging is > 0, set it to 1
if [ "$use_debugging" -gt 0 ]; then
    use_debugging=1
fi

if [ "$use_debugging" -eq 1 ]; then
    echo "Using Debugging"
else
    echo "Not using Debugging"
fi

echo "Launching Apache...."

# Kill existing Apache processes
echo "Killing existing Apache processes..."
sudo systemctl stop apache2
sudo pkill -9 apache2

# Configure network settings
echo "Configuring network settings..."
sudo sysctl -w net.ipv4.tcp_rmem="8192 87380 16777216"
sudo sysctl -w net.core.rmem_default=1048576

# Clean up debug files and shared memory
echo "Cleaning up debug files and shared memory..."
rm -f debug/*
ipcrm --all=shm

# Build the project
echo "Building the project..."
sudo make clean-debug && make debug || { echo "Failed to build the project"; exit 1; }

echo "Building ODB library..."
make USE_STANDALONE=1 USE_ODB="$use_odb" DEBUG="$use_debugging" lib/libnewodb.so || { echo "Failed to build ODB library"; exit 1; }

# Kill processes using the specified ports
echo "Killing processes using the specified ports..."
sudo fuser -k 80/tcp || echo "No process using port 80"
sudo fuser -k 8080/tcp || echo "No process using port 8080"
sudo fuser -k 3001/tcp || echo "No process using port 3000"

# Launch Apache with the custom library
echo "Launching Apache with the custom library..."
export ODB_CONF_PATH=$(pwd)/config/ODB.conf
sudo LD_PRELOAD=./lib/libnewodb.so apache2 -X -f $(pwd)/config/apache.conf || { echo "Failed to launch Apache"; exit 1; }
echo "Apache has been successfully launched."
