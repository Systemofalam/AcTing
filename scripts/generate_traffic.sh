#!/bin/bash

# Configuration
NUM_NODES=20
BASE_PORT=5000
CHUNK_COUNT=50

echo "Simulating traffic for $NUM_NODES nodes..."

# Generate traffic
for ((chunk=1; chunk<=CHUNK_COUNT; chunk++)); do
    source_node=$((RANDOM % NUM_NODES + 1))
    target_node=$((RANDOM % NUM_NODES + 1))

    if [ "$source_node" -ne "$target_node" ]; then
        echo "Node $source_node sends chunk $chunk to Node $target_node"
    fi

    sleep 0.1  # Simulate network delay
done

echo "Traffic simulation complete!"
