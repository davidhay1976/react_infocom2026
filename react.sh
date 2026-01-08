#!/usr/bin/env bash
#
# run_react.sh
# Build the project and launch doca_react with optional Bloom‑filter flags.
#
# Usage:
#   ./run_react.sh [--bloom-size N] [--bloom-swap SECS] [--bloom-type-counting]
#
# Examples:
#   ./run_react.sh                              # use all defaults
#   ./run_react.sh --bloom-size 16384           # override size only
#   ./run_react.sh --bloom-type-counting 1      # counting Bloom filter
#   ./run_react.sh --bloom-size 16k --bloom-swap 5 --bloom-type-counting 2
set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Parse CLI switches
# ---------------------------------------------------------------------------
BLOOM_SIZE=          # empty ⇒ not passed
BLOOM_SWAP=
BLOOM_TYPE_COUNTING=
WORKER_CORES=
TIMEOUT= 

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bloom-size)
        [[ $# -ge 2 ]] || { echo "Missing value for --bloom-size"; exit 1; }
        BLOOM_SIZE="$2"; shift 2 ;;
    -s)
        [[ $# -ge 2 ]] || { echo "Missing value for --bloom-size"; exit 1; }
        BLOOM_SIZE="$2"; shift 2 ;;
    --bloom-swap)
        [[ $# -ge 2 ]] || { echo "Missing value for --bloom-swap"; exit 1; }
        BLOOM_SWAP="$2"; shift 2 ;;
    -i)
        [[ $# -ge 2 ]] || { echo "Missing value for --bloom-swap"; exit 1; }
        BLOOM_SWAP="$2"; shift 2 ;;
    --bloom-type-counting)
        [[ $# -ge 2 ]] || { echo "Missing value for --bloom-type"; exit 1; }
         BLOOM_TYPE_COUNTING="$2"; shift 2 ;;
    -t)
        [[ $# -ge 2 ]] || { echo "Missing value for --bloom-type"; exit 1; }
         BLOOM_TYPE_COUNTING="$2"; shift 2 ;;
    --worker-cores)
        [[ $# -ge 2 ]] || { echo "Missing value for --worker-cores"; exit 1; }
        WORKER_CORES="$2"; shift 2 ;;
    -c)
        [[ $# -ge 2 ]] || { echo "Missing value for --worker-cores"; exit 1; }
        WORKER_CORES="$2"; shift 2 ;;
    --timeout)
        [[ $# -ge 2 ]] || { echo "Missing value for --timeout"; exit 1; }
        TIMEOUT="$2"; shift 2 ;;
    -o)
        [[ $# -ge 2 ]] || { echo "Missing value for --timeout"; exit 1; }
        TIMEOUT="$2"; shift 2 ;;
    -h|--help)
        sed -n '2,20p' "$0"; exit 0 ;;
    *)
        echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# 2. Build (ninja) and cd into ./build
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pushd "$SCRIPT_DIR/.." >/dev/null           # go to project root
ninja -C build/
cd build

# ---------------------------------------------------------------------------
# 3. Assemble the doca_react command
# ---------------------------------------------------------------------------
CMD=(sudo ./doca_react
     -a auxiliary:mlx5_core.sf.4,dv_flow_en=2
     -a auxiliary:mlx5_core.sf.5,dv_flow_en=2
     --main-lcore 0 -- )

[[ -n "$BLOOM_SIZE"          ]] && CMD+=(--bloom-size "$BLOOM_SIZE")
[[ -n "$BLOOM_TYPE_COUNTING" ]] && CMD+=(--bloom-type "$BLOOM_TYPE_COUNTING")
[[ -n "$BLOOM_SWAP"          ]] && CMD+=(--bloom-swap "$BLOOM_SWAP")
[[ -n "$WORKER_CORES"        ]] && CMD+=(--worker-cores "$WORKER_CORES")
[[ -n "$TIMEOUT"             ]] && CMD+=(--timeout "$TIMEOUT")

echo "[+] Running: ${CMD[*]}"
exec "${CMD[@]}"
