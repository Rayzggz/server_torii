#!/usr/bin/env bash
# The scenarios with nginx in front: builds nginx with the ngx_torii module, builds Torii,
# and sends every request through an nginx site. See README.md.
#
#   NGX_TORII_SRC=/path/to/ngx_torii bash tests/e2e/nginx.sh [group]
set -Eeuo pipefail
VIA=nginx exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test.sh" "$@"
