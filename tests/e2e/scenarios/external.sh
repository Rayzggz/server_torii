#!/usr/bin/env bash
test_external() {
    local jar="$RUN/external.cookies" session stamp sig location uri='/return?x=1' bad
    expect external 1 203.0.113.140 0000000100000000
    # The check itself answers with the redirect to the provider.
    check 1 203.0.113.140 0000000100000000 /return default_site -c "$jar"
    decision external
    location=$(header Location)
    assert_contains "$location" 'https://mitigation.invalid/verify?domain=default_site&session_id='
    assert_contains "$location" '&original_uri=%2Freturn&hmac='
    session=$(awk '$6=="__torii_session_id" {print $7}' "$jar")
    [[ -n "$session" ]] || fail 'Missing migration session'
    assert_contains "$(header Set-Cookie)" 'HttpOnly'
    sig=$(hmac "default_site:${session%%:*}:/return" "$EXTERNAL_SECRET")
    assert_contains "$location" "&hmac=$sig"
    stamp=$(date +%s)
    sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET")
    public 1 /torii/external_migration 203.0.113.140 default_site -G -b "$jar" -c "$jar" \
        --data-urlencode "original_uri=$uri" --data-urlencode "timestamp=$stamp" --data-urlencode "hmac=$sig"
    assert_eq "$HTTP_CODE" 302
    assert_eq "$(header Location)" "$uri"
    assert_contains "$(header Set-Cookie)" '__torii_clearance='
    expect pass 1 203.0.113.140 0000000100000000 /neutral default_site -b "$jar"
    for bad in signature expired session unsafe; do
        stamp=$(date +%s); uri=/return; sig=wrong
        case "$bad" in
            expired) stamp=$((stamp-60)); sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET") ;;
            session) sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET") ;;
            unsafe) uri=https://evil.invalid/ ;;
        esac
        local cookies="$jar"
        [[ "$bad" != session ]] || cookies="$RUN/missing.cookies"
        public 1 /torii/external_migration 203.0.113.140 default_site -G -b "$cookies" \
            --data-urlencode "original_uri=$uri" --data-urlencode "timestamp=$stamp" --data-urlencode "hmac=$sig"
        assert_eq "$HTTP_CODE" 400 "$bad callback"
        assert_contains "$HTTP_BODY" E2E-ERROR
        assert_eq "$(header Set-Cookie)" '' 'invalid callback must not mint clearance'
    done
    sleep 6
    expect external 1 203.0.113.140 0000000100000000 /neutral default_site -b "$jar"
    # Nothing but the connector protocol and the node's own endpoints is served.
    for uri in /unknown-endpoint /torii/checker /torii/checker_pages/403 /torii/captcha; do
        request 1 "$uri"
        assert_eq "$HTTP_CODE" 404 "$uri"
    done
}
