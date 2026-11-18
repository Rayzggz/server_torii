# Migrating to Server Torii 2.0

English | [简体中文](MIGRATION-zh_cn.md)

2.0 is not compatible with 1.x: the configuration files, the Nginx connector, the cookies, the
gossip messages and the log files all changed. There is no mixed mode. Plan one maintenance
window per cluster and do the steps below in order.

Nothing has to be converted by hand line by line: the fastest way is to start from
`config_example/` and carry your values over, using the tables below to find where each one
went. Then let Torii check the result before you start it:

```bash
server_torii -check-config -config /www/server_torii/config
```

It loads everything the server loads at start (the main file, the rules of every site, the list
files, the error pages), prints every problem at once and exits. Torii 2.0 refuses to start on
an unknown key, a missing section or an invalid value, so a 1.x file is rejected, never
half-applied.

## 1. What to do, in order

1. Build the new `ngx_torii` into Nginx and rewrite the Nginx configuration ([section 2](#2-nginx-connector)).
2. Rewrite `torii.yml` ([section 3](#3-toriiyml)).
3. Rewrite the `Server.yml` of every site and check the list files ([section 4](#4-serveryml), [section 5](#5-list-files)).
4. Copy the new error pages ([section 6](#6-error-pages)).
5. Run `-check-config` until it prints `configuration OK`.
6. Stop every node of the cluster, then start the new version on all of them. A 1.x node and
   a 2.0 node ignore each other's gossip.
7. Update whatever reads the logs ([section 8](#8-logs)).

The binary is now built with `go build ./cmd/server_torii`.

## 2. Nginx connector

The connector speaks a new protocol. The `torii_auth_request` directives of 1.x are gone, and
so are the `connecting_*_headers` settings of `torii.yml`: the header names are fixed.

| 1.x | 2.0 |
| --- | --- |
| `torii_auth_request` and an `error_page` round trip | `torii on;` in the location. Torii's page is sent in the same request |
| Site chosen by the `Host` header | `torii_site <id>;` in the server block |
| `Torii-Feature-Control` bit string | `torii_features "-challenge +http_flood";` by name |
| `access_log syslog:...` with a log format for Torii | `torii_log syslog:server=...;`, nothing else |
| Header names set in `torii.yml` | Fixed, in `conf/torii_params.conf` |

Copy `conf/` of the connector to `<nginx conf dir>/torii/` and follow its README. Two things to
watch:

- **The client address must be an IP address.** The connector sends `$remote_addr`, and Torii
  answers 400 to anything else. If Nginx itself receives its clients over a Unix socket (behind
  another proxy), `$remote_addr` is `unix:`: restore the real address with the `realip` module
  first.
- **A site that Nginx names must exist.** A `torii_site` that is not in `torii.yml` gets no
  decision, and `torii_on_error` decides (503 by default). 1.x fell back to the default site.

## 3. `torii.yml`

| 1.x | 2.0 |
| --- | --- |
| `port: "25555"` | `listen: [":25555"]`. A list; `unix:/path` entries are allowed |
| `connecting_host_headers`, `connecting_ip_headers`, `connecting_uri_headers`, `connecting_feature_control_headers` | Removed |
| `sites: - host: "example.com"` | `sites: - id: "example"`. Letters, digits and underscores, at most 32 characters |
| A wildcard host such as `*.example.com` | One site ID, named by `torii_site` in every server block that should use it |
| The site with `host: "default_site"` | Any site, named by `default_site: "<id>"`. Leave it out to give requests without a site no decision |
| `global_secret` needed for gossip | Always required, at least 32 characters. It now also signs the cookies of every site |
| `enable_gossip`, `peers` | Unchanged |
| — | `log_listen`: where request reports are received. Defaults to UDP 127.0.0.1 on the port of the first TCP address in `listen` |
| — | `unix_socket_mode`, `ipv6_prefix`, `log_level` |
| — | `sites: - error_page:` gives a site pages of its own |

The example `global_secret` is public, and whoever knows it can issue clearance cookies: 2.0
refuses to start with it. Generate your own, for example with `openssl rand -hex 16`.
The same value is refused as `altcha_hmac_secret` in `Server.yml`: leave that setting out,
and the ALTCHA challenges are signed with a key derived from `global_secret`.

`/torii/health_check` is reachable through every site, so it only says that the node runs and
which node it is. The counters (`reports_*`, `counter_untracked`) are added for a request that
carries the health key, which is also derived from `global_secret` and the same on every node
of a cluster:

```bash
printf '%s' 'torii health key' | openssl dgst -sha256 -hmac "<global_secret>" | awk '{print substr($NF,1,32)}'
```

Open `/torii/health_check?key=<key>` to see them. The key ends up in the access log of nginx
like any query string; it shows the counters and nothing else.

IPv6 clients are now counted per network, a `/64` unless `ipv6_prefix` says otherwise: rate
limits, temporary blocks and traffic analysis treat the whole network as one client.

## 4. `Server.yml`

**Every section is required**, also for features you do not use: switch them off with
`enabled: false`, and keep the section complete and valid.

### Sections

| 1.x | 2.0 |
| --- | --- |
| `IPAllow`, `IPBlock`, `URLAllow`, `URLBlock` | `lists`: one entry per list, with a `name`, a `type`, a `file` and an `action` |
| `CAPTCHA` and `ExternalMigration` | `challenge`, with `mode: hcaptcha \| altcha \| external`. A site has one challenge |
| `HTTPFlood` | `http_flood` |
| `VerifyBot` | `verify_bot` |
| `AdaptiveTrafficAnalyzer` | `traffic_analyzer`, redesigned: take the section from the example |
| — | `country_rule`, `custom_rules` (new, required) |

### `lists`

1.x read four files with fixed names. 2.0 lists them explicitly, and the order matters: lists
are applied top to bottom and the first one a request is on decides. To keep the 1.x behavior:

```yaml
lists:
  - {name: ip_allow,  enabled: true, type: ip,  file: IP_AllowList.conf,  action: allow}
  - {name: ip_block,  enabled: true, type: ip,  file: IP_BlockList.conf,  action: block}
  - {name: url_allow, enabled: true, type: url, file: URL_AllowList.conf, action: allow}
  - {name: url_block, enabled: true, type: url, file: URL_BlockList.conf, action: block}
```

A list can also carry `action: challenge`, or no action when only custom rules refer to it
(`ip.src in $office`).

### `challenge`

| 1.x | 2.0 |
| --- | --- |
| `CAPTCHA.secret_key` | Removed. Cookies are signed with a key derived from `global_secret` |
| `CAPTCHA.captcha_validate_time: 600` | `clearance_ttl: 10m` |
| `CAPTCHA.captcha_challenge_session_timeout: 120` | `session_ttl: 2m` |
| `CAPTCHA.hcaptcha_secret` | `hcaptcha_secret`, required with `mode: hcaptcha` |
| `CAPTCHA.CaptchaFailureLimit` | `failure_limit` |
| `CAPTCHA.failure_block_duration: 1200` | `failure_block_duration: 20m` |
| `ExternalMigration.enabled: true` | `mode: external` |
| `ExternalMigration.redirect_url` | `redirect_url` |
| `ExternalMigration.secret_key` | `external_secret`, at least 16 characters. It is only the key shared with the provider |
| `ExternalMigration.session_timeout: 1800` | `clearance_ttl: 30m` |

`enabled: true` challenges every client, as `CAPTCHA.enabled: true` did. With
`enabled: false` the section must still be valid: lists, country rules, custom rules and the
traffic analyzer use it to challenge the clients they single out.

The link between Torii and the external provider did not change.

### `http_flood`

| 1.x | 2.0 |
| --- | --- |
| `HTTPFloodSpeedLimit` | `speed_limit` |
| `HTTPFloodSameURILimit` | `same_uri_limit` |
| `HTTPFloodFailureLimit` | `failure_limit` |
| `failure_block_duration: 1200` | `failure_block_duration: 20m` |

The limits of a list are checked in the order written, and two entries with the same window
are rejected.

### `verify_bot`

```yaml
# 1.x                        # 2.0
VerifyBot:                   verify_bot:
  enabled: true                enabled: true
  verify_google_bot: true      bots: [google, bing, baidu, yandex, sogou, apple]
  verify_bing_bot: true
  ...
```

### Durations and rates

Every duration needs a unit: `30s`, `10m`, `2h`, `1h30m`. A bare number such as `600` is
rejected with a message that says so. Rates are unchanged: `"150/10s"`.

## 5. List files

- **URL lists match exactly unless told otherwise.** 1.x guessed: a line with any of
  `. * + ? ( ) [ ] { } | \`, or starting with `^` or ending with `$`, was a regular expression.
  2.0 compares a line with the request URI, query string included, character by character. For
  a regular expression write `regex:` in front: `regex:^/api/v[0-9]+/`. Go through your URL
  lists: a 1.x line such as `/index.html` was a regular expression and is now exact, and
  `^/admin` must become `regex:^/admin`.
- **An invalid line rejects the configuration.** 1.x skipped it.
- IP lists take IPv4 and IPv6 addresses and CIDR ranges.
- Blank lines and lines starting with `#` are skipped.

## 6. Error pages

Copy `CAPTCHA.html` and the new `CAPTCHA_ALTCHA.html` from `config_example/error_page/`:
`CAPTCHA.html` changed, and `mode: altcha` needs the second file. If you changed the 1.x page,
reapply your changes to the new file instead of keeping the old one. A page that is missing is reported as a warning at start and answered with 500 when
it is needed.

## 7. Cookies

Clearance and session cookies have a new format and a new key. Every cookie issued by 1.x is
invalid: each client passes its challenge once more after the upgrade. Nothing has to be done.

All nodes with the same `global_secret` accept each other's cookies.

## 8. Logs

| 1.x | 2.0 |
| --- | --- |
| `<host>/info.log`, `error.log`, `debug.log` | `<site id>/events.log`, with the level in every line |
| `server_torii.log`, free text | `server_torii.log`, same line format as the events |
| — | `log_level: debug \| info \| warn \| error` in `torii.yml`, read again on SIGHUP |

```
2026/11/14 21:31:07 [info] decision ip=203.0.113.9 verdict=block reason=Lists:ip_block method=GET host=example.com uri=/admin ua="curl/8.5.0"
```

- A request that is let through is logged only at the `debug` level.
- SIGHUP opens the log files again. For rotation, rename the files and send SIGHUP; the same
  signal reloads the site rules.
- The reason of a decision names the check and, where there is one, the list or rule:
  `Lists:url_block`, `CustomRules:block-wp-scan`, `HTTPFlood`. The connector exposes it as
  `$torii_reason`.

## 9. Gossip

The message format changed and carries a version. A node ignores messages of another version
and logs `gossip dropped: protocol version differs`. Upgrade all nodes of a cluster together.
Temporary rules are now kept per site; UA rules no longer exist.
