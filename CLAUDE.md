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

## PoC Documentation (`pocdocs/`)

HTML explainer documents live in `pocdocs/`, one per PoC variant. See `pocdocs/cve-2021-25740-loadbalancer.html` as the reference example.

### Style and structure

- **Self-contained HTML** — no external dependencies (CSS, JS, fonts, images). Everything is inline.
- **Dark technical theme** — background `#0d1117`, text `#c9d1d9`, monospace accents. Colour palette defined as CSS custom properties in `:root`.
- **Sections**: Header (CVE badge, severity, links) → Background → Diagrams → Attack explanation → Reproduction steps (terminal-style code blocks) → Mitigation.

### Animated SVG diagrams

Diagrams are inline `<svg>` elements with SMIL `<animate>` tags (no JavaScript).

- **Colour conventions**: green (`#3fb950`) for legitimate traffic, red (`#f85149`) for malicious/redirected traffic, blue (`#1f6feb`) for attacker namespace, red (`#da3633`) for victim namespace, orange (`#d29922`) for services/MetalLB, purple (`#bc8cff`) for EndpointSlices.
- **Traffic flow animations**: Use `<circle>` elements as packets moving along each hop. Each packet gets its own `<animate>` for `cx`, `cy`, and `opacity`.
- **Looping**: Use `repeatCount="indefinite"` with the full cycle duration (e.g. `dur="3.6s"`). The actual movement occupies a small fraction of the cycle via `keyTimes`, with the rest as invisible idle time. Stagger packets across hops using `begin` offsets (e.g. `0s`, `0.5s`, `1s`).
- **Pulsing elements**: Use `<animate attributeName="stroke-opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite"/>` to draw attention to key objects like modified EndpointSlices.
- **Arrow markers**: Defined in a `<defs>` block, one per colour (e.g. `#arrowGreen`, `#arrowRed`). Reused across all SVGs via `marker-end="url(#arrowGreen)"`.
- **Layout**: Each diagram should show the full traffic path including all intermediaries (MetalLB, kube-proxy/node, etc.) — don't skip hops even if simplifying.
