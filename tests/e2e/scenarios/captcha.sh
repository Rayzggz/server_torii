#!/usr/bin/env bash
captcha_session() {
    local jar=$1 host=${2:-default_site}
    request 1 /torii/checker_pages/CAPTCHA -H "Torii-Real-Host: $host" -c "$jar"
    assert_eq "$HTTP_CODE" 503
    assert_contains "$HTTP_BODY" E2E-ALTCHA
    assert_contains "$(header Set-Cookie)" '__torii_session_id='
    assert_contains "$(header Set-Cookie)" 'HttpOnly'
}
solve_altcha() {
    local challenge=$1 nonce salt cost length prefix counter key password deadline=$((SECONDS+90))
    assert_eq "$(jq -r '.parameters.algorithm' <<< "$challenge")" PBKDF2/SHA-512
    nonce=$(jq -r '.parameters.nonce' <<< "$challenge")
    salt=$(jq -r '.parameters.salt' <<< "$challenge")
    cost=$(jq -r '.parameters.cost' <<< "$challenge")
    length=$(jq -r '.parameters.keyLength' <<< "$challenge")
    prefix=$(jq -r '.parameters.keyPrefix' <<< "$challenge")
    for ((counter=0; counter<100000; counter++)); do
        (( SECONDS < deadline )) || fail 'ALTCHA solving exceeded 90 seconds'
        # ALTCHA v2 appends the big-endian uint32 counter to the binary nonce.
        printf -v password '%s%08x' "$nonce" "$counter"
        key=$(openssl kdf -keylen "$length" -kdfopt digest:SHA512 -kdfopt "hexpass:$password" \
            -kdfopt "hexsalt:$salt" -kdfopt "iter:$cost" PBKDF2)
        key=${key//:/}; key=${key//$'\r'/}; key=${key//$'\n'/}; key=${key,,}
        if [[ "$key" == "$prefix"* ]]; then
            SOLUTION=$(jq -cn --argjson challenge "$challenge" --argjson counter "$counter" --arg key "$key" \
                '{challenge:$challenge,solution:{counter:$counter,derivedKey:$key}}')
            return
        fi
    done
    fail 'ALTCHA exhausted bounded search'
}
submit_altcha() {
    local payload=$1 jar=$2 host=${3:-default_site} ip=${4:-203.0.113.130} encoded
    encoded=$(printf '%s' "$payload" | base64 -w 0)
    request 1 /torii/captcha -b "$jar" -c "$jar" -H "Torii-Real-Host: $host" -H "Torii-Real-IP: $ip" \
        --data-urlencode "altcha=$encoded"
    assert_eq "$HTTP_CODE" 200
}
test_captcha() {
    local jar="$RUN/captcha.cookies" other="$RUN/other.cookies" challenge solved malformed session i
    expect CAPTCHA 1 203.0.113.130 0000001000000000
    request 1 /torii/captcha/challenge
    assert_eq "$HTTP_CODE" 403
    request 1 /torii/captcha/challenge -X POST
    assert_eq "$HTTP_CODE" 405
    captcha_session "$jar"
    session=$(awk '$6=="__torii_session_id" {print $7}' "$jar")
    request 1 /torii/checker_pages/CAPTCHA -H 'Torii-Real-Host: default_site' -b "$jar" -c "$jar"
    assert_contains "$(header Set-Cookie)" "__torii_session_id=$session;"
    request 1 /torii/captcha/challenge -H 'Torii-Real-Host: default_site' -b "$jar"
    assert_eq "$HTTP_CODE" 200
    assert_contains "$(header Content-Type)" application/json
    challenge=$HTTP_BODY
    solve_altcha "$challenge"
    solved=$SOLUTION
    malformed=$(jq -c '.solution.counter += 1' <<< "$solved")
    submit_altcha "$malformed" "$jar"
    assert_eq "$HTTP_BODY" "$(jq -r .captcha_invalid "$E2E/fixtures/responses.json")"
    malformed=$(jq -c '.challenge.signature = "invalid"' <<< "$solved")
    submit_altcha "$malformed" "$jar"
    assert_eq "$HTTP_BODY" bad
    request 1 /torii/captcha -H 'Torii-Real-Host: default_site' -b "$jar" --data-urlencode 'altcha=not-base64!'
    assert_eq "$HTTP_CODE" 200
    assert_eq "$HTTP_BODY" bad
    # A valid second session on a different site must not accept the first site's proof.
    captcha_session "$other" exact.e2e.test
    submit_altcha "$solved" "$other" exact.e2e.test
    assert_eq "$HTTP_BODY" badSession
    submit_altcha "$solved" "$jar"
    assert_eq "$HTTP_BODY" "$(jq -r .captcha_success "$E2E/fixtures/responses.json")"
    assert_contains "$(header Set-Cookie)" '__torii_clearance='
    expect 200 1 203.0.113.130 0000001000000000 /neutral default_site -b "$jar"
    expect 200 1 198.51.100.60 0000000001000000 /neutral default_site -b "$jar"
    expect 200 1 203.0.113.130 0000000000100000 /challenge default_site -b "$jar"
    expect CAPTCHA 1 203.0.113.130 0000001000000000 /neutral exact.e2e.test -b "$jar"
    sleep 6
    expect CAPTCHA 1 203.0.113.130 0000001000000000 /neutral default_site -b "$jar"
    captcha_session "$other" failures.test
    request 1 /torii/captcha/challenge -H 'Torii-Real-Host: failures.test' -b "$other"
    assert_eq "$HTTP_CODE" 200
    challenge=$HTTP_BODY
    # Challenge expires independently; a fresh session cannot rescue the old proof.
    sleep 3
    request 1 /torii/captcha/challenge -H 'Torii-Real-Host: failures.test' -b "$other"
    assert_eq "$HTTP_CODE" 403 'expired session'
    solve_altcha "$challenge"
    captcha_session "$other" failures.test
    submit_altcha "$SOLUTION" "$other" failures.test 203.0.113.131
    assert_eq "$HTTP_BODY" bad 'expired challenge'
    for ((i=0; i<3; i++)); do
        request 1 /torii/captcha -H 'Torii-Real-Host: failures.test' -H 'Torii-Real-IP: 203.0.113.132' -d ''
        assert_eq "$HTTP_CODE" 200
        assert_eq "$HTTP_BODY" bad
    done
    expect 403 1 203.0.113.132 0000001000000000 /neutral failures.test
    cluster_decision 403 203.0.113.132
}
