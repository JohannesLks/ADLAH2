#!/bin/sh
set -e

# Define paths for the original and the container-specific kubeconfig
HOST_KUBECONFIG="/app/kubeconfig_host"
CONTAINER_KUBECONFIG="/app/kubeconfig_container"

# Handle kubeconfig if present; otherwise continue without K8s
if [ -f "$HOST_KUBECONFIG" ]; then
    echo "Creating container-specific kubeconfig..."
    cp "$HOST_KUBECONFIG" "$CONTAINER_KUBECONFIG"
    # Rewrite localhost API server to host.docker.internal for container access (any port)
    sed -E -i 's|server: https://127\.0\.0\.1:([0-9]+)|server: https://host.docker.internal:\1|' "$CONTAINER_KUBECONFIG"
    echo "Kubeconfig modified for container access."
    export KUBECONFIG="$CONTAINER_KUBECONFIG"
elif [ -d "$HOST_KUBECONFIG" ]; then
    # If a directory is mounted, try common filenames
    CANDIDATE_FILE=""
    for fname in config kubeconfig; do
        if [ -f "$HOST_KUBECONFIG/$fname" ]; then
            CANDIDATE_FILE="$HOST_KUBECONFIG/$fname"
            break
        fi
    done
    if [ -n "$CANDIDATE_FILE" ]; then
        echo "Creating container-specific kubeconfig from $CANDIDATE_FILE..."
        cp "$CANDIDATE_FILE" "$CONTAINER_KUBECONFIG"
        sed -E -i 's|server: https://127\.0\.0\.1:([0-9]+)|server: https://host.docker.internal:\1|' "$CONTAINER_KUBECONFIG"
        echo "Kubeconfig modified for container access."
        export KUBECONFIG="$CONTAINER_KUBECONFIG"
    else
        echo "WARNING: Host kubeconfig directory is empty at $HOST_KUBECONFIG. Continuing without Kubernetes access."
    fi
else
    echo "WARNING: Host kubeconfig not found at $HOST_KUBECONFIG. Continuing without Kubernetes access."
fi

# Wait for Elasticsearch to be ready
echo "Waiting for Elasticsearch to become available..."
while ! curl -s -f "http://elasticsearch:9200/_cluster/health?wait_for_status=yellow&timeout=5s" > /dev/null; do
    echo "Elasticsearch is not available yet, sleeping..."
    sleep 5
done
echo "Elasticsearch is up!"

# Execute the main application
echo "Starting RL Agent application..."
exec python3 -u -m rl_agent.main "$@" 