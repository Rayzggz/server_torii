# Linux end-to-end tests

Run from the repository root:

```bash
bash tests/e2e/test.sh
# equivalent:
make test-e2e
```

The default starts **10 real Torii processes**, builds the current checkout once,
and exercises HTTP and UDP interfaces. It does not require Docker, Nginx, root,
Python, or hCaptcha credentials. hCaptcha and browser rendering are intentionally
excluded. No traffic is sent to a crawler or mitigation provider: crawler IPs are
passed to local Torii instances using the configured proxy headers, and external
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
# Install Go 1.25 or newer if it is not already available; verify with go version.
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
| `routing` | Node identities and health, default/exact/wildcard sites, configured header aliases and precedence, feature overrides |
| `access` | IPv4/CIDR and IPv4-mapped IPv6 allow/block/CAPTCHA lists, ignored native IPv6 rules, exact/regex URL rules, overlap precedence and nonmatches |
| `country` | Pinned US/AU/GB database records, default and unknown policies, missing database, rule precedence |
| `flood` | Speed and same-URI boundaries, client isolation, recovery, repeated-failure block and ten-node propagation/expiry |
| `captcha` | ALTCHA challenge and shell solution, clearance, list integration, tampering, malformed proof, session binding/expiry, challenge/clearance expiry, failure block |
| `external` | Redirect signature, callback/clearance, invalid signatures/sessions, old timestamps, unsafe redirect, custom pages |
| `syslog` | UDP input, unknown tags, malformed messages, below-threshold/healthy controls, non-200 IP blocks, canonicalized URI challenges and propagation/expiry |
| `gossip` | Real-origin propagation, injected-message origin distinction, TTL, deduplication, signature/origin/ID/time validation, private IP, malformed/oversized input, IP/UA/URI snapshots and periodic anti-entropy |
| `crawler` | Official Google range discovery plus forward/reverse DNS, real Googlebot acceptance, spoof rejection, disabled verification, ordinary traffic |
| `reload` | SIGHUP rule reload, node isolation, malformed configuration rejection, recovery, retention of an existing GeoIP reader on failed reload |

`NUM_NODES` defaults to `10` (allowed: 3–32). `BASE_PORT` defaults to `25000`;
nodes use TCP **and UDP** ports `BASE_PORT+1` through `BASE_PORT+NUM_NODES`.
Those ports must be free. `KEEP_ARTIFACTS=1` retains successful-run artifacts.
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

## Fixtures and diagnostics

`fixtures/` contains reusable YAML, IP/URL lists, HTML templates, expected
responses, a UDP syslog template, and pinned GeoIP expectations. All secrets
are **public test-only values; never deploy these configurations**. The suite
copies fixtures to a unique temporary directory, generates per-node paths and
peers, and modifies only those copies during reload tests. The existing bundled
GeoIP database is reused without downloading or changing it.

The current IP-list trie intentionally ignores native IPv6 rules. The suite
asserts this existing limitation explicitly; it does not claim native IPv6 list
enforcement. IPv4-mapped IPv6 clients are tested against the IPv4 rules.

The suite prints its artifact directory at startup. It contains per-node
configuration/logs, recorded response headers/bodies, cookie jars, the crawler
range list, and process IDs. Failed and interrupted runs retain that directory.
Successful runs remove it unless retention was requested. EXIT/INT/TERM handlers
terminate and reap only child PIDs owned by the run, with bounded shutdown.
Because Torii listens on all interfaces, use the suite on a development machine;
the harness sends requests only to loopback.

## Validation

```bash
bash -n tests/e2e/test.sh
shellcheck -x tests/e2e/test.sh tests/e2e/lib.sh tests/e2e/scenarios/*.sh tests/e2e/gossip/test.sh
go test ./...
bash tests/e2e/test.sh
bash tests/e2e/test.sh  # verify a fresh run has no leftover state
```

To check interruption cleanup, interrupt a running suite with Ctrl+C and verify
the PIDs in its retained `pids` file are no longer alive. To check occupied-port
handling, start one suite and invoke another with the same `BASE_PORT`: the
second must fail before starting nodes and must leave the first running.
