#!/usr/bin/env bash
test_custom_rules() {
    local custom=0000000000010000 custom_ip_allow=1000000000010000 custom_flood=0000010000010000 k
    expect 403 1 198.18.3.1 "$custom" '/e2e/cookie?mode=strict' default_site -H 'Cookie: role=blocked'
    expect 200 1 198.18.3.1 "$custom" '/e2e/cookie?mode=other' default_site -H 'Cookie: role=blocked'
    expect 200 1 198.18.3.1 "$custom" '/e2e/cookie?mode=strict' default_site -H 'Cookie: role=allowed'
    expect 403 1 8.8.8.8 "$custom" /e2e/country
    expect 200 "$NUM_NODES" 8.8.8.8 "$custom" /e2e/country
    expect EXTERNAL 1 198.18.3.2 "$custom" /e2e/external
    expect 200 1 198.18.3.3 "$custom" /e2e/continue
    expect CAPTCHA 1 198.18.3.3 0000001000010000 /e2e/continue
    expect 200 1 198.18.3.4 0000001100010000 /e2e/skip
    # Rules are configured but disabled; the feature bit turns them on per request.
    expect 200 1 198.18.0.1 "$ZERO" /neutral default_site -H 'Referer: https://spam.e2e/'
    expect 403 1 198.18.0.1 "$custom" /neutral default_site -H 'Referer: https://spam.e2e/'
    expect 200 1 198.18.0.1 "$custom" /neutral default_site -H 'Referer: https://ok.e2e/'
    # Nginx subrequests are GET; the original method comes from Torii-Original-Method.
    expect 403 1 198.18.0.2 "$custom" /item default_site -H 'Torii-Original-Method: DELETE'
    expect 200 1 198.18.1.2 "$custom" /item default_site -H 'Torii-Original-Method: DELETE'
    expect CAPTCHA 1 198.18.0.3 "$custom" /neutral default_site -A 'Mozilla/5.0 BadBot/1.0'
    # IP allow list runs before custom rules.
    expect 200 1 198.51.100.10 "$custom_ip_allow" /neutral default_site -H 'Referer: https://spam.e2e/'
    # allow ends the pipeline, so the later flood check never counts these requests.
    for ((k=1; k<=7; k++)); do expect 200 1 198.18.2.1 "$custom_flood" /health; done
    # skip HTTPFlood only for API calls carrying a key.
    for ((k=1; k<=7; k++)); do
        expect 200 1 198.18.0.4 "$custom_flood" "/api/v1/$k" default_site -H 'X-Api-Key: e2e'
    done
    for ((k=1; k<=5; k++)); do expect 200 1 198.18.0.5 "$custom_flood" "/api/v1/$k"; done
    expect 429 1 198.18.0.5 "$custom_flood" /api/v1/6
}
