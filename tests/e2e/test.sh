#!/usr/bin/env bash
# Linux/Ubuntu WSL entry point. All secrets and traffic are test-only.
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
E2E="$ROOT/tests/e2e"
# shellcheck source=tests/e2e/lib.sh
source "$E2E/lib.sh"
suite=${1:-all}
case "$suite" in
    all) groups=(routing access country flood captcha external syslog gossip crawler reload) ;;
    routing|access|country|flood|captcha|external|syslog|gossip|crawler|reload) groups=("$suite") ;;
    *) printf 'Usage: bash tests/e2e/test.sh [all|routing|access|country|flood|captcha|external|syslog|gossip|crawler|reload]\n' >&2; exit 2 ;;
esac
preflight
setup_cluster
for group in "${groups[@]}"; do
    CURRENT=$group
    log "START $group"
    # shellcheck source=/dev/null
    source "$E2E/scenarios/$group.sh"
    "test_$group"
    alive
    PASSED_GROUPS=$((PASSED_GROUPS + 1))
    log "PASS $group"
done
log "PASS: $PASSED_GROUPS scenario groups, $ASSERTIONS assertions, $NUM_NODES nodes; hCaptcha excluded"
