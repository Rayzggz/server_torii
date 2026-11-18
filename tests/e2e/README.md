# Linux end-to-end tests

Run from the repository root:

```bash
bash tests/e2e/test.sh
# equivalent:
make test-e2e
```

The same scenarios can be run with a real nginx in front of the nodes; see
[Through nginx](#through-nginx).

The default starts **10 real Torii processes**, builds the current checkout once,
and exercises HTTP and UDP interfaces. It does not require Docker, Nginx, root,
Python, or hCaptcha credentials. hCaptcha and browser rendering are intentionally
excluded. No traffic is sent to a crawler or mitigation provider: crawler IPs are
passed to local Torii instances in the connector's request headers, and external
mitigation callbacks are signed locally with test secrets.

## Ubuntu / WSL prerequisites

Use an installed Ubuntu WSL distribution. In PowerShell, inspect distributions
with `wsl --list --verbose` and open Ubuntu with `wsl -d Ubuntu`. If WSL is absent,
install Ubuntu using `wsl --install -d Ubuntu` in an administrator terminal and
complete any Windows restart / initial Ubuntu user setup it requests.

Inside Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential ca-certificates curl jq openssl dnsutils iproute2 shellcheck
# Install Go 1.26 or newer if it is not already available; verify with go version.
cd /mnt/c/Users/Roi/GolandProjects/server_torii
bash tests/e2e/test.sh
```

OpenSSL 3+ is required for the ALTCHA PBKDF2 solver. Go may need Internet access
to download module dependencies. The crawler group requires HTTPS access to
Google's official crawler IP list and working forward/reverse DNS. Failure to
obtain and verify a crawler address fails that group as a dependency error;
it is never silently skipped or counted as passing.

For faster compilation in WSL, a checkout on Ubuntu's own filesystem can be used.
All `.sh` fixtures/scripts are committed with LF line endings.

## Groups and settings

```bash
bash tests/e2e/test.sh captcha
bash tests/e2e/test.sh gossip
bash tests/e2e/gossip/test.sh  # compatible old entry point, now ten nodes
BASE_PORT=27000 KEEP_ARTIFACTS=1 bash tests/e2e/test.sh
```

| Group | Assertions |
| --- | --- |
| `routing` | Node identities and health, site selection by ID and the default site, feature overrides |
| `connector` | Connector protocol v1: pass/deny decisions with the page as the response, sites named by ID, feature overrides, error answers without a decision, public endpoints, and the same checks over the Unix socket |
| `access` | IPv4, IPv6 and IPv4-mapped allow/block/challenge lists, exact and `regex:` URL entries, the order of the lists and nonmatches |
| `custom_rules` | Feature-bit gating, Referer/User-Agent/method/IP conditions, block/challenge/allow/log actions, skip HTTPFlood, disabled rules, list precedence |
| `country` | Pinned US/AU/GB database records, default and unknown policies, missing database, rule precedence |
| `flood` | Speed and same-URI boundaries, client isolation, recovery, repeated-failure block and ten-node propagation/expiry, the decision lines in the events log of the site |
| `captcha` | ALTCHA challenge and shell solution, clearance, list integration, tampering, malformed proof, session binding/expiry, challenge/clearance expiry, failure block |
| `external` | A site in the external challenge mode: redirect signature, callback/clearance, invalid signatures/sessions, old timestamps, unsafe redirect, custom pages |
| `syslog` | Request reports over UDP, unknown sites, malformed and legacy-format messages, report counters, below-threshold/healthy controls, non-200 IP blocks, canonicalized URI challenges and propagation/expiry |
| `gossip` | Real-origin propagation, injected-message origin distinction, TTL, deduplication, signature/origin/ID/time validation, private IP, malformed/oversized input, IP/URI snapshots, a dropped UA rule and periodic anti-entropy |
| `crawler` | Official Google range discovery plus forward/reverse DNS, real Googlebot acceptance, spoof rejection, disabled verification, ordinary traffic |
| `reload` | SIGHUP rule reload, log files opened again after a rotation, node isolation, malformed configuration rejection, recovery, retention of an existing GeoIP reader on failed reload |

`NUM_NODES` defaults to `10` (allowed: 3–32). `BASE_PORT` defaults to `25000`;
nodes use TCP **and UDP** ports `BASE_PORT+1` through `BASE_PORT+NUM_NODES`.
Those ports must be free. `KEEP_ARTIFACTS=1` retains artifacts for debugging.
`TMPDIR` selects the temporary directory parent; use a normal local path without
quotes or newlines. The last node deliberately starts without a GeoIP database.

Each group can run independently. Running an individual group is partial
coverage, not a substitute for the default full run. The default stops on the
first failure and returns nonzero; progress identifies the active group and the
number of completed groups/assertions. Transport failures always fail a request.
Short rate windows assume an otherwise reasonably idle laptop.

Propagation rules live for five minutes, with a shared three-minute convergence
deadline to accommodate Torii's random fanout and 30-second anti-entropy timer.
Expiration uses separate short-lived rules on their origin, or direct delivery
to each node for the shared gossip TTL test. A short TTL is not treated as a
reliable deadline for random dissemination. Allow several minutes for a full run.

## Through nginx

```bash
NGX_TORII_SRC=/path/to/ngx_torii bash tests/e2e/nginx.sh          # every group
NGX_TORII_SRC=/path/to/ngx_torii bash tests/e2e/nginx.sh captcha  # one group
# equivalent to the first:
NGX_TORII_SRC=/path/to/ngx_torii make test-e2e-nginx
```

This run compiles nginx with the [ngx_torii](https://github.com/Rayzggz/ngx_torii) module,
builds Torii, starts the same ten nodes and puts one nginx in front of them. Every request
of the scenarios is then an ordinary request to an nginx site: the module checks it with
its node, a request that passes is proxied to an application (another server block of the
same nginx), and one that does not gets Torii's page. No scenario talks to a node.

| What a scenario names | How it reaches Torii through nginx |
| --- | --- |
| Node | The sites of node N listen on `NGINX_BASE_PORT+N`. Odd nodes are reached over TCP, even ones over their Unix socket |
| Host | A server block per site with `server_name` and `torii_site`; a host no block claims gets the default server, which names no site |
| Client address | `X-Forwarded-For`, which nginx (realip module) accepts from 127.0.0.1 only |
| Checks switched per request | `torii_features $http_x_e2e_features;` a site would write the names in its configuration |
| Decision and reason | `add_header X-E2E-Decision $torii_decision` and `X-E2E-Reason $torii_reason`; the headers of the connector protocol never reach a client |
| Request reports (`syslog`) | Real requests the application answers with 404 or 500; nginx sends the reports with `torii_log` |

The endpoints are the module's own `conf/torii_endpoints.conf` and `conf/torii_params.conf`.

The groups are the ones above, with two differences. `nginx` takes the place of
`connector`: the page and headers a client gets, POST and HEAD, the Unix socket, the client
address with and without a trusted proxy, protocol headers sent by a client, `torii off`,
`torii_features` and `torii_on_error` in the configuration, which endpoints of Torii a site
exposes, request reports, and the access log variables. `gossip` is not run: its messages
are exchanged by the nodes without nginx, and a site answers 403 for the gossip endpoint.
Propagation between nodes is still covered, by `flood`, `captcha` and `syslog`. The parts of
`syslog` and `external` that send what nginx never sends (malformed reports, requests to a
node's own port) are skipped. At the end the run fails if nginx exited or logged an alert.

| Setting | Default | Meaning |
| --- | --- | --- |
| `NGX_TORII_SRC` | `../ngx_torii` next to this repository | The module checkout |
| `NGINX_VERSION` | `1.30.7` | Downloaded from nginx.org on the first run |
| `NGINX_SHA256` | that of 1.30.7 | Checked before every build; required with another `NGINX_VERSION`, empty builds unchecked |
| `E2E_CACHE` | `~/.cache/torii-e2e` | Source archive and build; rebuilt when the module source is newer |
| `NGINX_BASE_PORT` | `BASE_PORT+100` | The application's port; node N is at `+N` |

Besides the prerequisites above it needs `make`, a C compiler, `tar` and the PCRE2 headers
(`sudo apt-get install -y build-essential libpcre2-dev`), and Internet access for the nginx
source on the first run. The build log is `$E2E_CACHE/nginx-<version>/build.log`; with
`KEEP_ARTIFACTS=1` the configuration and logs of nginx are in `nginx/` of the artifact directory.

## Fixtures and diagnostics

`fixtures/` contains reusable YAML, IP/URL lists, HTML templates, expected
responses, a request report template, and pinned GeoIP expectations. All secrets
are **public test-only values; never deploy these configurations**. The suite
copies fixtures to a unique temporary directory, generates per-node paths and
peers, and modifies only those copies during reload tests. The existing bundled
GeoIP database is reused without downloading or changing it.

IP lists hold IPv4 and IPv6 networks; IPv4-mapped IPv6 clients are tested against the
IPv4 entries.

The suite prints its artifact directory at startup. It contains per-node
configuration/logs, recorded response headers/bodies, cookie jars, the crawler
range list, and process IDs. All runs (successful, failed, or interrupted) remove
that directory unless `KEEP_ARTIFACTS=1` was explicitly set. Failed runs print
diagnostic log tails before cleanup. EXIT/INT/TERM handlers
terminate and reap only child PIDs owned by the run, with bounded shutdown.
Because Torii listens on all interfaces, use the suite on a development machine;
the harness sends requests only to loopback.

## Validation

```bash
bash -n tests/e2e/test.sh
shellcheck -x tests/e2e/test.sh tests/e2e/nginx.sh tests/e2e/lib.sh tests/e2e/nginx_lib.sh tests/e2e/scenarios/*.sh tests/e2e/gossip/test.sh
go test ./...
bash tests/e2e/test.sh
bash tests/e2e/test.sh  # verify a fresh run has no leftover state
```

To check interruption cleanup, run with `KEEP_ARTIFACTS=1`, interrupt the suite
with Ctrl+C, and verify the PIDs in its retained `pids` file are no longer alive.
Without that option, verify that the artifact directory is removed. To check occupied-port
handling, start one suite and invoke another with the same `BASE_PORT`: the
second must fail before starting nodes and must leave the first running.
