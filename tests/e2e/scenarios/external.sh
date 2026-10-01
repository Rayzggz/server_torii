#!/usr/bin/env bash
test_external() {
    local jar="$RUN/external.cookies" session stamp sig location uri='/return?x=1' bad
    expect EXTERNAL 1 203.0.113.140 0000000100000000
    request 1 /torii/checker_pages/EXTERNAL -H 'Torii-Real-Host: default_site' -H 'Torii-Original-URI: /return' -c "$jar"
    assert_eq "$HTTP_CODE" 302
    location=$(header Location)
    assert_contains "$location" 'https://mitigation.invalid/verify?domain=default_site&session_id='
    assert_contains "$location" '&original_uri=/return&hmac='
    session=$(awk '$6=="__torii_session_id" {print $7}' "$jar")
    [[ -n "$session" ]] || fail 'Missing migration session'
    assert_contains "$(header Set-Cookie)" 'HttpOnly'
    sig=$(hmac "default_site:${session%%:*}:/return" "$EXTERNAL_SECRET")
    assert_contains "$location" "&hmac=$sig"
    stamp=$(date +%s)
    sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET")
    request 1 /torii/external_migration -G -b "$jar" -c "$jar" -H 'Torii-Real-Host: default_site' \
        --data-urlencode "original_uri=$uri" --data-urlencode "timestamp=$stamp" --data-urlencode "hmac=$sig"
    assert_eq "$HTTP_CODE" 302
    assert_eq "$(header Location)" "$uri"
    assert_contains "$(header Set-Cookie)" '__torii_clearance='
    expect 200 1 203.0.113.140 0000000100000000 /neutral default_site -b "$jar"
    for bad in signature expired session unsafe; do
        stamp=$(date +%s); uri=/return; sig=wrong
        case "$bad" in
            expired) stamp=$((stamp-60)); sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET") ;;
            session) sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET") ;;
            unsafe) uri=https://evil.invalid/ ;;
        esac
        local cookies="$jar"
        [[ "$bad" != session ]] || cookies="$RUN/missing.cookies"
        request 1 /torii/external_migration -G -b "$cookies" -H 'Torii-Real-Host: default_site' \
            --data-urlencode "original_uri=$uri" --data-urlencode "timestamp=$stamp" --data-urlencode "hmac=$sig"
        assert_eq "$HTTP_CODE" 400 "$bad callback"
        assert_contains "$HTTP_BODY" E2E-ERROR
        assert_eq "$(header Set-Cookie)" '' 'invalid callback must not mint clearance'
    done
    sleep 6
    expect EXTERNAL 1 203.0.113.140 0000000100000000 /neutral default_site -b "$jar"
    request 1 /torii/checker_pages/403 -H 'Torii-Real-IP: 203.0.113.140'
    assert_eq "$HTTP_CODE" 403
    assert_contains "$HTTP_BODY" 'E2E-403 Node_1 203.0.113.140'
    request 1 /torii/checker_pages/429
    assert_eq "$HTTP_CODE" 429
    assert_contains "$HTTP_BODY" E2E-429
    request 1 /unknown-endpoint
    assert_eq "$HTTP_CODE" 403
    assert_contains "$HTTP_BODY" E2E-403
}
