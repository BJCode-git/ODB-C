#!/bin/bash

# If an argument is defined, get it
use_odb=1
BUFF_SIZE=16384
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
	BUFF_SIZE=$2
fi

# Check if BUFF_SIZE is a number
if ! [[ "$BUFF_SIZE" =~ ^[0-9]+$ ]]; then
	echo "BUFF_SIZE must be a number"
	exit 1
fi

sudo fuser -k 10000/tcp || echo "No process using port 10000"
sudo fuser -k 10001/tcp || echo "No process using port 10001"
sudo fuser -k 10002/tcp || echo "No process using port 10002"


# sudo fuser -k 10000/tcp 10001/tcp 10002/tcp

make clean-lib
make ONE_SHOT="1" USE_ODB="$use_odb" BUFF_SIZE=12288 USE_STANDALONE=0 TYPE="txt" run-front-end >> /dev/null &
make ONE_SHOT="1" USE_ODB="$use_odb" BUFF_SIZE=16384 USE_STANDALONE=0 TYPE="txt" run-inter >> /dev/null &
make ONE_SHOT="1" USE_ODB="$use_odb" BUFF_SIZE=12288 USE_STANDALONE=0 TYPE="txt" run-back-end >> /dev/null &
