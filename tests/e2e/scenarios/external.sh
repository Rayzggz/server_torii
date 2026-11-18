#!/usr/bin/env bash
test_external() {
    local jar="$RUN/external.cookies" session stamp sig location uri='/return?x=1' bad
    local on=0000001000000000 host=external.test
    expect redirect 1 203.0.113.140 "$on" /neutral "$host"
    # The check itself answers with the redirect to the provider.
    check 1 203.0.113.140 "$on" /return "$host" -c "$jar"
    decision redirect
    location=$(header Location)
    assert_contains "$location" "https://mitigation.invalid/verify?domain=$host&session_id="
    assert_contains "$location" '&original_uri=%2Freturn&hmac='
    session=$(awk '$6=="__torii_session_id" {print $7}' "$jar")
    [[ -n "$session" ]] || fail 'Missing migration session'
    assert_contains "$(header Set-Cookie)" 'HttpOnly'
    sig=$(hmac "$host:${session%%:*}:/return" "$EXTERNAL_SECRET")
    assert_contains "$location" "&hmac=$sig"
    stamp=$(date +%s)
    sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET")
    public 1 /torii/external_migration 203.0.113.140 "$host" -G -b "$jar" -c "$jar" \
        --data-urlencode "original_uri=$uri" --data-urlencode "timestamp=$stamp" --data-urlencode "hmac=$sig"
    assert_eq "$HTTP_CODE" 302
    assert_eq "$(header Location)" "$uri"
    assert_contains "$(header Set-Cookie)" '__torii_clearance='
    expect pass 1 203.0.113.140 "$on" /neutral "$host" -b "$jar"
    for bad in signature expired session unsafe; do
        stamp=$(date +%s); uri=/return; sig=wrong
        case "$bad" in
            expired) stamp=$((stamp-60)); sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET") ;;
            session) sig=$(hmac "$session$stamp$uri" "$EXTERNAL_SECRET") ;;
            unsafe) uri=https://evil.invalid/ ;;
        esac
        local cookies="$jar"
        [[ "$bad" != session ]] || cookies="$RUN/missing.cookies"
        public 1 /torii/external_migration 203.0.113.140 "$host" -G -b "$cookies" \
            --data-urlencode "original_uri=$uri" --data-urlencode "timestamp=$stamp" --data-urlencode "hmac=$sig"
        assert_eq "$HTTP_CODE" 400 "$bad callback"
        assert_contains "$HTTP_BODY" E2E-ERROR
        assert_eq "$(header Set-Cookie)" '' 'invalid callback must not mint clearance'
    done
    sleep 6
    expect redirect 1 203.0.113.140 "$on" /neutral "$host" -b "$jar"
    # A site answers only the endpoints of its own kind of challenge.
    public 1 /torii/external_migration 203.0.113.140 default_site -G --data-urlencode "original_uri=/return"
    assert_eq "$HTTP_CODE" 403 'external callback on a CAPTCHA site'
    public 1 /torii/captcha/challenge 203.0.113.140 "$host"
    assert_eq "$HTTP_CODE" 403 'ALTCHA challenge on an external site'
    assert_contains "$HTTP_BODY" E2E-403
    # Nothing but the connector protocol and the node's own endpoints is served. Behind nginx
    # these are URIs of the application.
    [[ "$VIA" == direct ]] || return 0
    for uri in /unknown-endpoint /torii/checker /torii/checker_pages/403 /torii/captcha; do
        request 1 "$uri"
        assert_eq "$HTTP_CODE" 404 "$uri"
    done
}
