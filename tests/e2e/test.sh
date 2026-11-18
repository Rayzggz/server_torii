#!/usr/bin/env bash
# Linux/Ubuntu WSL entry point. All secrets and traffic are test-only.
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
E2E="$ROOT/tests/e2e"
# shellcheck source=tests/e2e/lib.sh
source "$E2E/lib.sh"
suite=${1:-all}
# Behind nginx the "nginx" group takes the place of "connector", which speaks the protocol of
# the module itself, and "gossip", whose messages peers exchange without nginx.
case "$VIA" in
    direct) all=(routing connector access country custom_rules flood captcha external syslog gossip crawler reload) ;;
    nginx)
        all=(routing nginx access country custom_rules flood captcha external syslog crawler reload)
        # shellcheck source=tests/e2e/nginx_lib.sh
        source "$E2E/nginx_lib.sh" ;;
    *) printf 'VIA must be direct or nginx\n' >&2; exit 2 ;;
esac
groups=()
if [[ "$suite" == all ]]; then
    groups=("${all[@]}")
else
    for group in "${all[@]}"; do [[ "$group" != "$suite" ]] || groups=("$suite"); done
fi
if (( ${#groups[@]} == 0 )); then
    printf 'Usage: [VIA=%s] bash tests/e2e/test.sh [all|%s]\n' "$VIA" "$(IFS='|'; printf '%s' "${all[*]}")" >&2
    exit 2
fi
preflight
if [[ "$VIA" == nginx ]]; then build_nginx; fi
setup_cluster
if [[ "$VIA" == nginx ]]; then start_nginx; fi
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
if [[ "$VIA" == nginx ]]; then
    nginx_log_clean
    log "PASS: $PASSED_GROUPS scenario groups, $ASSERTIONS assertions, $NUM_NODES nodes behind nginx $NGINX_VERSION; hCaptcha excluded"
else
    log "PASS: $PASSED_GROUPS scenario groups, $ASSERTIONS assertions, $NUM_NODES nodes; hCaptcha excluded"
fi
