#!/usr/bin/env bash
# Sourced by test.sh when VIA=nginx: builds nginx with the ngx_torii module and puts it in
# front of the nodes, one group of server blocks per node. Every request of the scenarios
# then enters through an nginx site, the way a visitor's request does.
# shellcheck disable=SC2034
NGINX_VERSION=${NGINX_VERSION:-1.28.0}
# The SHA-256 of the source archive, which is compiled and run. Another NGINX_VERSION needs its
# own; an empty NGINX_SHA256 builds the archive unchecked.
if [[ -z ${NGINX_SHA256+set} && "$NGINX_VERSION" == 1.28.0 ]]; then
    NGINX_SHA256=c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a
fi
NGX_TORII_SRC=${NGX_TORII_SRC:-$ROOT/../ngx_torii}
E2E_CACHE=${E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/torii-e2e}
# The application listens on NGINX_BASE_PORT, the sites of node N on NGINX_BASE_PORT+N.
NGINX_BASE_PORT=${NGINX_BASE_PORT:-$((BASE_PORT + 100))}
NGINX_BIN=''
# Site IDs that have a server block of their own; the server name is site_host of the ID.
NGINX_SITES=(default_site exact wildcard failures unknown non200 uri expiry non200expiry uriexpiry external)

# site_host SITE: the server name of the site, the reverse of site_for in lib.sh.
site_host() {
    case "$1" in
        default_site) printf default_site ;;
        exact) printf exact.e2e.test ;;
        wildcard) printf '*.e2e.test' ;;
        *) printf '%s.test' "$1" ;;
    esac
}

# build_nginx: downloads the nginx source once and compiles it with the module. The build is
# kept in E2E_CACHE and made again when the module source changed.
build_nginx() {
    local dir="$E2E_CACHE/nginx-$NGINX_VERSION" archive src log stamp sum
    NGX_TORII_SRC=$(cd "$NGX_TORII_SRC" 2>/dev/null && pwd) \
        || fail "No ngx_torii checkout; set NGX_TORII_SRC to one (default: next to this repository)"
    [[ -f "$NGX_TORII_SRC/config" && -f "$NGX_TORII_SRC/src/ngx_http_torii_module.c" && -f "$NGX_TORII_SRC/conf/torii_endpoints.conf" ]] \
        || fail "NGX_TORII_SRC=$NGX_TORII_SRC is not an ngx_torii checkout"
    NGINX_BIN="$dir/prefix/sbin/nginx"
    stamp="$dir/.built"
    if [[ -x "$NGINX_BIN" && -f "$stamp" && "$(cat "$stamp")" == "$NGX_TORII_SRC" ]] \
        && [[ -z "$(find "$NGX_TORII_SRC/config" "$NGX_TORII_SRC/src" -newer "$stamp" -print -quit)" ]]; then
        log "nginx $NGINX_VERSION with the module is up to date: $NGINX_BIN"
        return
    fi
    log "Building nginx $NGINX_VERSION with the module from $NGX_TORII_SRC"
    mkdir -p "$E2E_CACHE/src"
    archive="$E2E_CACHE/src/nginx-$NGINX_VERSION.tar.gz"
    if [[ ! -f "$archive" ]]; then
        curl --fail --silent --show-error --location --retry 3 -o "$archive.part" \
            "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" \
            || fail "DEPENDENCY: unable to download nginx $NGINX_VERSION"
        mv "$archive.part" "$archive"
    fi
    # Checked on every build, so an archive that changed in the cache is not built either.
    if [[ ! -v NGINX_SHA256 ]]; then
        fail "DEPENDENCY: no checksum known for nginx $NGINX_VERSION; set NGINX_SHA256 (empty to build it unchecked)"
    elif [[ -n "$NGINX_SHA256" ]]; then
        sum=$(sha256sum "$archive") || fail "DEPENDENCY: sha256sum failed on $archive"
        if [[ "${sum%% *}" != "$NGINX_SHA256" ]]; then
            mv -f "$archive" "$archive.rejected"
            fail "DEPENDENCY: nginx $NGINX_VERSION archive has SHA-256 ${sum%% *}, expected $NGINX_SHA256 (kept as $archive.rejected)"
        fi
    else
        log "nginx $NGINX_VERSION archive is built unchecked: NGINX_SHA256 is empty"
    fi
    rm -rf -- "$dir"
    mkdir -p "$dir"
    tar -xzf "$archive" -C "$dir"
    src="$dir/nginx-$NGINX_VERSION"
    log="$dir/build.log"
    # realip gives every test request the client address it names; see start_nginx.
    if ! (
        cd "$src"
        ./configure --prefix="$dir/prefix" --with-http_realip_module --without-http_gzip_module \
            --add-module="$NGX_TORII_SRC"
        make -j"$(nproc 2>/dev/null || echo 2)"
        make install
    ) > "$log" 2>&1; then
        tail -n 30 "$log" >&2
        fail "nginx build failed (log: $log)"
    fi
    printf '%s\n' "$NGX_TORII_SRC" > "$stamp"
}

# start_nginx: writes the configuration and starts nginx in front of the running nodes.
start_nginx() {
    local ngx="$RUN/nginx" i site backend deadline app=$NGINX_BASE_PORT
    mkdir -p "$ngx/logs" "$ngx/conf/torii" "$ngx/conf/nodes"
    cp "$NGX_TORII_SRC/conf/torii_params.conf" "$ngx/conf/torii/"
    {
        cat <<EOF
daemon on;
worker_processes 2;
error_log logs/error.log info;
pid logs/nginx.pid;
events { worker_connections 1024; }
http {
    default_type text/html;
    log_format e2e '\$remote_addr|\$host|\$request_uri|\$status|\$torii_site|\$torii_decision|\$torii_reason';
    access_log logs/access.log e2e;

    # The suite is the only proxy in front of nginx: the client address of a request is the
    # one its X-Forwarded-For names. A connection from any other address keeps its own.
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;

    # The scenarios switch checks per request; a site would write the names here instead.
    torii_features \$http_x_e2e_features;

    upstream e2e_app { server 127.0.0.1:$app; keepalive 16; }

    # The protected application. X-E2E-Status makes it fail, for the traffic analysis.
    server {
        listen 127.0.0.1:$app;
        location / {
            if (\$http_x_e2e_status = 404) { return 404 "APP 404\n"; }
            if (\$http_x_e2e_status = 500) { return 500 "APP 500\n"; }
            return 200 "APP \$request_method \$host \$request_uri\n";
        }
    }
EOF
        for ((i=1; i<=NUM_NODES; i++)); do
            # Every second node is reached over its Unix socket.
            backend="127.0.0.1:$((BASE_PORT+i))"
            (( i % 2 )) || backend="unix:$RUN/node$i/torii.sock"
            printf '    upstream torii_node_%s { server %s; keepalive 8; }\n' "$i" "$backend"
        done
        printf '    include nodes/*.conf;\n}\n'
    } > "$ngx/conf/nginx.conf"

    for ((i=1; i<=NUM_NODES; i++)); do
        # The endpoints as the module ships them, pointed at this node.
        sed "s/torii_backend/torii_node_$i/" "$NGX_TORII_SRC/conf/torii_endpoints.conf" > "$ngx/conf/torii/endpoints_$i.conf"
        cat > "$ngx/conf/torii/site_$i.conf" <<EOF
torii on;
torii_log syslog:server=127.0.0.1:$((BASE_PORT+i));
# What the module decided, for the assertions; the headers of the protocol stay inside.
add_header X-E2E-Decision \$torii_decision always;
add_header X-E2E-Reason \$torii_reason always;
include torii/endpoints_$i.conf;
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host \$host;
location / { proxy_pass http://e2e_app; }
location /e2e-open/ { torii off; proxy_pass http://e2e_app; }
location /e2e-strict/ { torii_features "+challenge"; proxy_pass http://e2e_app; }
location /e2e-relaxed/ { torii_features "-challenge"; proxy_pass http://e2e_app; }
EOF
        {
            # A host no site claims: no torii_site, so Torii uses its default site.
            printf 'server {\n    listen 127.0.0.1:%s default_server;\n    include torii/site_%s.conf;\n}\n' "$((NGINX_BASE_PORT+i))" "$i"
            for site in "${NGINX_SITES[@]}"; do
                printf 'server {\n    listen 127.0.0.1:%s;\n    server_name %s;\n    torii_site %s;\n    include torii/site_%s.conf;\n}\n' \
                    "$((NGINX_BASE_PORT+i))" "$(site_host "$site")" "$site" "$i"
            done
            # Sites Torii does not know: served anyway on the first, refused on the second.
            printf 'server {\n    listen 127.0.0.1:%s;\n    server_name nosite.test;\n    torii_site nonexistent;\n    torii_on_error pass;\n    include torii/site_%s.conf;\n}\n' \
                "$((NGINX_BASE_PORT+i))" "$i"
            printf 'server {\n    listen 127.0.0.1:%s;\n    server_name nosite-deny.test;\n    torii_site nonexistent;\n    include torii/site_%s.conf;\n}\n' \
                "$((NGINX_BASE_PORT+i))" "$i"
        } > "$ngx/conf/nodes/$i.conf"
    done

    "$NGINX_BIN" -p "$ngx" -c conf/nginx.conf -t > "$ngx/logs/test.log" 2>&1 \
        || fail "nginx -t: $(cat "$ngx/logs/test.log")"
    "$NGINX_BIN" -p "$ngx" -c conf/nginx.conf
    deadline=$((SECONDS+20))
    for ((i=1; i<=NUM_NODES; i++)); do
        until curl --silent --noproxy '*' --connect-timeout 1 --max-time 2 \
            "http://127.0.0.1:$((NGINX_BASE_PORT+i))/torii/health_check" > "$RUN/ready"; do
            (( SECONDS < deadline )) || fail "nginx not ready for node $i within 20 seconds"
            sleep 0.2
        done
        assert_contains "$(cat "$RUN/ready")" "sliver=Node_$i" 'readiness identity through nginx'
    done
    log "nginx $NGINX_VERSION serves ${#NGINX_SITES[@]} sites for each of $NUM_NODES nodes on ports $((NGINX_BASE_PORT+1))-$((NGINX_BASE_PORT+NUM_NODES))"
}

stop_nginx() {
    local pidfile="$RUN/nginx/logs/nginx.pid" pid workers worker deadline=$((SECONDS+5))
    [[ -f "$pidfile" ]] || return 0
    pid=$(cat "$pidfile")
    # The workers hold the listening sockets too, and outlive a master that is killed.
    workers=$(pgrep -P "$pid" 2>/dev/null || true)
    kill -QUIT "$pid" 2>/dev/null || return 0
    while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 0.1; done
    kill -0 "$pid" 2>/dev/null || return 0
    # The master first, so it does not start new workers for the ones killed after it.
    kill -KILL "$pid" 2>/dev/null || true
    for worker in $workers; do kill -KILL "$worker" 2>/dev/null || true; done
}

# nginx_log_clean: nginx is still running and logged nothing alarming during the run.
nginx_log_clean() {
    local errors="$RUN/nginx/logs/error.log"
    ASSERTIONS=$((ASSERTIONS+1))
    kill -0 "$(cat "$RUN/nginx/logs/nginx.pid")" 2>/dev/null || fail 'nginx exited during the run'
    ASSERTIONS=$((ASSERTIONS+1))
    if grep -E '\[(alert|emerg|crit)\]' "$errors" > "$RUN/nginx-bad.log"; then
        head -n 20 "$RUN/nginx-bad.log" >&2
        fail 'nginx logged an alert'
    fi
}
