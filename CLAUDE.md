# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is a collection of Kubernetes and container security vulnerability proof-of-concept exploits used for demos and educational purposes. Each CVE directory is self-contained with its own README, manifests, and scripts.

## Architecture

Each PoC is an independent directory containing:
- A `README.md` with step-by-step exploit instructions
- Kubernetes YAML manifests (pods, services, RBAC, network policies, etc.)
- Shell scripts where automation is needed
- Optional `kind-config.yaml` for local cluster setup

There is no build system, test suite, or shared code between PoCs.

## Common Tools and Patterns

- **KinD (Kubernetes in Docker)** is the primary local cluster tool: `kind create cluster --config kind-config.yaml`
- **kubectl** is used for all cluster interaction — applying manifests, exec'ing into pods, checking logs
- **kubectl proxy** is frequently used to expose the API server locally for curl-based exploits
- Several PoCs exploit TOCTOU (time-of-check/time-of-use) race conditions and may require multiple attempts

## CVE Categories

- **Unpatchable Kubernetes vulns**: CVE-2020-8554, CVE-2020-8562, CVE-2021-25740 — design-level issues that can't be fixed without breaking changes
- **SSRF via API server**: CVE-2020-8561 (webhook-based), kinvolk-proxy-exploit (pod annotation-based)
- **Container escape / host file access**: CVE-2021-30465 (runc symlink race), CVE-2022-23648 (containerd volume mount)

## Adding New PoCs

Follow the existing pattern: create a `CVE-YYYY-NNNNN/` directory with a `README.md` documenting prerequisites, setup steps, and expected output. Include all necessary manifests and scripts. Update the root `README.md` with a one-line description.
