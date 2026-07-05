#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' "Usage: build-probe.sh [--detect-only|--attempt] [--allow-network] [--output-dir PATH] [--work-dir PATH]"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MODE="--detect-only"
ALLOW_NETWORK=()
OUTPUT_DIR="${ROOT}/build/wucios/trials/nixos/phase-2"
WORK_DIR="${OUTPUT_DIR}/work"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --detect-only)
      MODE="--detect-only"
      shift
      ;;
    --attempt)
      MODE="--attempt"
      shift
      ;;
    --allow-network)
      ALLOW_NETWORK=(--allow-network)
      shift
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --work-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      WORK_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

python3 "${ROOT}/tools/wucios/trial_collectors/build_probe.py" \
  --candidate nixos \
  "${MODE}" \
  "${ALLOW_NETWORK[@]}" \
  --output-dir "${OUTPUT_DIR}" \
  --work-dir "${WORK_DIR}"
