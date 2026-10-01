#!/usr/bin/env bash
# Backwards-compatible entry point; uses the shared ten-node gossip scenarios.
set -Eeuo pipefail
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/test.sh" gossip
