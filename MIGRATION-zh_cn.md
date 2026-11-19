# 迁移到 Server Torii 2.0

[English](MIGRATION.md) | 简体中文

2.0 与 1.x 不兼容:配置文件、Nginx 连接器、cookie、gossip 消息、日志文件全部变了,没有混合运行的模式。请为每个集群安排一次维护窗口,按下面的顺序操作。

不需要逐行手工转换:最快的做法是从 `config_example/` 出发,把你的值填进去,下面的表格说明每一项搬到了哪里。启动之前先让 Torii 检查一遍:

```bash
server_torii -check-config -config /www/server_torii/config
```

它会按启动时的方式加载全部内容(主配置、每个站点的规则、列表文件、错误页),一次报出所有问题后退出。2.0 遇到不认识的键、缺少的段或非法的值会拒绝启动,所以 1.x 的文件只会被拒绝,不会被套用一半。

## 1. 操作顺序

1. 把新版 `ngx_torii` 编进 Nginx,并重写 Nginx 配置([第 2 节](#2-nginx-连接器))。
2. 重写 `torii.yml`([第 3 节](#3-toriiyml))。
3. 重写每个站点的 `Server.yml`,检查列表文件([第 4 节](#4-serveryml)、[第 5 节](#5-列表文件))。
4. 复制新的错误页([第 6 节](#6-错误页))。
5. 运行 `-check-config`,直到输出 `configuration OK`。
6. 停掉集群的所有节点,再全部启动新版本。1.x 节点和 2.0 节点互相忽略对方的 gossip。
7. 更新读取日志的脚本或工具([第 8 节](#8-日志))。

二进制的构建命令改为 `go build ./cmd/server_torii`。

## 2. Nginx 连接器

连接器换了新协议。1.x 的 `torii_auth_request` 系列指令已删除,`torii.yml` 里的 `connecting_*_headers` 也已删除:请求头的名字现在是固定的。

| 1.x | 2.0 |
| --- | --- |
| `torii_auth_request` 加 `error_page` 二次请求 | 在 location 里写 `torii on;`,Torii 的页面在同一个请求里直接返回 |
| 按 `Host` 请求头选站点 | 在 server 块里写 `torii_site <id>;` |
| `Torii-Feature-Control` 位串 | `torii_features "-challenge +http_flood";`,按名字开关 |
| `access_log syslog:...` 加专用日志格式 | `torii_log syslog:server=...;`,不需要别的配置 |
| 请求头名字在 `torii.yml` 里配置 | 固定,见 `conf/torii_params.conf` |

把连接器的 `conf/` 复制到 `<nginx 配置目录>/torii/`,按它的 README 配置。有两点要注意:

- **客户端地址必须是 IP 地址。** 连接器发送的是 `$remote_addr`,不是 IP 地址时 Torii 返回 400。如果 Nginx 自己是通过 Unix socket 接收客户端连接的(前面还有一层代理),`$remote_addr` 会是 `unix:`,需要先用 `realip` 模块还原真实地址。
- **Nginx 指定的站点必须存在。** `torii_site` 写了 `torii.yml` 里没有的 ID 时,Torii 不给出决策,由 `torii_on_error` 决定(默认返回 503)。1.x 会回退到默认站点。

## 3. `torii.yml`

| 1.x | 2.0 |
| --- | --- |
| `port: "25555"` | `listen: [":25555"]`,是一个列表,可以写 `unix:/path` |
| `connecting_host_headers`、`connecting_ip_headers`、`connecting_uri_headers`、`connecting_feature_control_headers` | 已删除 |
| `sites: - host: "example.com"` | `sites: - id: "example"`,只能用字母、数字和下划线,最长 32 个字符 |
| 通配域名,如 `*.example.com` | 一个站点 ID,每个要用它的 server 块都写 `torii_site` |
| `host: "default_site"` 的站点 | 任意站点,用 `default_site: "<id>"` 指定;不写则没有指定站点的请求得不到决策 |
| `global_secret` 只在 gossip 时需要 | 始终必填,至少 32 个字符;它现在也用来签所有站点的 cookie |
| `enable_gossip`、`peers` | 不变 |
| — | `log_listen`:接收请求报告的地址;默认是 127.0.0.1 的 UDP,端口取 `listen` 里第一个 TCP 地址的端口 |
| — | `unix_socket_mode`、`ipv6_prefix`、`log_level` |
| — | `sites: - error_page:` 给站点配置自己的错误页 |

示例里的 `global_secret` 是公开的,知道它的人可以伪造通行 cookie,所以 2.0 用它会拒绝启动。请自己生成一个,例如 `openssl rand -hex 16`。`Server.yml` 里的 `altcha_hmac_secret` 用这个公开值同样会被拒绝:不写这一项即可,ALTCHA 挑战会用从 `global_secret` 派生的密钥签名。

`/torii/health_check` 通过每个站点都能访问,所以它只说明节点在运行、是哪个节点。计数器(`reports_*`、`counter_untracked`)只在请求带上健康检查密钥时才输出。这个密钥同样从 `global_secret` 派生,集群里每个节点都一样:

```bash
printf '%s' 'torii health key' | openssl dgst -sha256 -hmac "<global_secret>" | awk '{print substr($NF,1,32)}'
```

在浏览器里打开 `/torii/health_check?key=<密钥>` 即可看到。和其他查询参数一样,密钥会出现在 nginx 的访问日志里;它只能用来看计数器。

IPv6 客户端现在按网段计数,默认 `/64`,可用 `ipv6_prefix` 调整:限速、临时封禁和流量分析都把整个网段当作一个客户端。

## 4. `Server.yml`

**每一段都必须写**,包括你不用的功能:用 `enabled: false` 关闭,但这一段仍要完整且合法。

### 段名

| 1.x | 2.0 |
| --- | --- |
| `IPAllow`、`IPBlock`、`URLAllow`、`URLBlock` | `lists`:每个列表一项,有 `name`、`type`、`file`、`action` |
| `CAPTCHA` 和 `ExternalMigration` | `challenge`,用 `mode: hcaptcha \| altcha \| external` 选择;一个站点只有一种挑战 |
| `HTTPFlood` | `http_flood` |
| `VerifyBot` | `verify_bot` |
| `AdaptiveTrafficAnalyzer` | `traffic_analyzer`,已重新设计,请直接从示例里取这一段 |
| — | `country_rule`、`custom_rules`(新增,必填) |

### `lists`

1.x 读取四个固定文件名的列表。2.0 要显式列出来,而且顺序有意义:列表从上到下应用,请求命中的第一个列表生效。要保持 1.x 的行为:

```yaml
lists:
  - {name: ip_allow,  enabled: true, type: ip,  file: IP_AllowList.conf,  action: allow}
  - {name: ip_block,  enabled: true, type: ip,  file: IP_BlockList.conf,  action: block}
  - {name: url_allow, enabled: true, type: url, file: URL_AllowList.conf, action: allow}
  - {name: url_block, enabled: true, type: url, file: URL_BlockList.conf, action: block}
```

列表的动作还可以是 `challenge`;只给自定义规则引用的列表可以不写动作(`ip.src in $office`)。

### `challenge`

| 1.x | 2.0 |
| --- | --- |
| `CAPTCHA.secret_key` | 已删除;cookie 用从 `global_secret` 派生的密钥签名 |
| `CAPTCHA.captcha_validate_time: 600` | `clearance_ttl: 10m` |
| `CAPTCHA.captcha_challenge_session_timeout: 120` | `session_ttl: 2m` |
| `CAPTCHA.hcaptcha_secret` | `hcaptcha_secret`,`mode: hcaptcha` 时必填 |
| `CAPTCHA.CaptchaFailureLimit` | `failure_limit` |
| `CAPTCHA.failure_block_duration: 1200` | `failure_block_duration: 20m` |
| `ExternalMigration.enabled: true` | `mode: external` |
| `ExternalMigration.redirect_url` | `redirect_url` |
| `ExternalMigration.secret_key` | `external_secret`,至少 16 个字符;它只是和外部服务商共享的密钥 |
| `ExternalMigration.session_timeout: 1800` | `clearance_ttl: 30m` |

`enabled: true` 会挑战所有客户端,和原来的 `CAPTCHA.enabled: true` 一样。`enabled: false` 时这一段仍然必须合法:列表、国家规则、自定义规则和流量分析器要用它来挑战被它们选中的客户端。

Torii 与外部服务商之间的对接方式没有变。

### `http_flood`

| 1.x | 2.0 |
| --- | --- |
| `HTTPFloodSpeedLimit` | `speed_limit` |
| `HTTPFloodSameURILimit` | `same_uri_limit` |
| `HTTPFloodFailureLimit` | `failure_limit` |
| `failure_block_duration: 1200` | `failure_block_duration: 20m` |

同一个列表里的限速按书写顺序检查,窗口相同的两条会被拒绝。

`same_uri_key` 是新增的必填项,决定 `same_uri_limit` 把哪些请求算作同一个 URI:

| 取值 | 合并计数的请求 |
| --- | --- |
| `full` | URI 完全相同(含查询串)的请求;这是 1.x 的行为,客户端每次换一个查询串就能绕过限制 |
| `path` | 路径相同的请求,不看查询串 |
| `canonical` | 路径中的 ID 和令牌被掩码后相同的请求,与流量分析器的归并方式一致:`/post/1` 和 `/post/2` |

### `verify_bot`

```yaml
# 1.x                        # 2.0
VerifyBot:                   verify_bot:
  enabled: true                enabled: true
  verify_google_bot: true      bots: [google, bing, baidu, yandex, sogou, apple]
  verify_bing_bot: true
  ...
```

### 时长和限速

所有时长都要带单位:`30s`、`10m`、`2h`、`1h30m`。只写数字(如 `600`)会被拒绝,并有明确提示。限速的写法不变:`"150/10s"`。

## 5. 列表文件

- **URL 列表默认是精确匹配。** 1.x 靠猜:一行里只要有 `. * + ? ( ) [ ] { } | \` 中的任何一个,或以 `^` 开头、以 `$` 结尾,就当作正则表达式。2.0 把一行与请求 URI(含查询串)逐字符比较;要用正则表达式,在前面写 `regex:`,例如 `regex:^/api/v[0-9]+/`。请把 URL 列表过一遍:1.x 里 `/index.html` 这样的行是正则,现在是精确匹配;`^/admin` 要改成 `regex:^/admin`。
- **非法的行会让整个配置被拒绝。** 1.x 会跳过它。
- IP 列表支持 IPv4、IPv6 地址和 CIDR 网段。
- 空行和以 `#` 开头的行会被跳过。

## 6. 错误页

从 `config_example/error_page/` 复制 `CAPTCHA.html` 和新增的 `CAPTCHA_ALTCHA.html`:`CAPTCHA.html` 有改动,`mode: altcha` 需要第二个文件。如果你改过 1.x 的页面,请把改动重新做到新文件上,不要继续用旧文件。缺少的页面在启动时会有一条警告,用到它时返回 500。

## 7. Cookie

通行 cookie 和会话 cookie 换了格式和密钥。1.x 签发的 cookie 全部失效:升级后每个客户端要重新通过一次挑战。不需要做任何操作。

`global_secret` 相同的所有节点互相接受对方签发的 cookie。

## 8. 日志

| 1.x | 2.0 |
| --- | --- |
| `<host>/info.log`、`error.log`、`debug.log` | `<站点 id>/events.log`,每行带级别 |
| `server_torii.log`,自由文本 | `server_torii.log`,行格式与事件日志相同 |
| — | `torii.yml` 里的 `log_level: debug \| info \| warn \| error`,SIGHUP 时重新读取 |

```
2026/11/14 21:31:07 [info] decision ip=203.0.113.9 verdict=block reason=Lists:ip_block method=GET host=example.com uri=/admin ua="curl/8.5.0"
```

- 放行的请求只在 `debug` 级别记录。
- SIGHUP 会重新打开日志文件。轮转日志时先改名,再发 SIGHUP;同一个信号也会重载站点规则。
- 决策的原因写的是检查名,有列表或规则时带上它的名字:`Lists:url_block`、`CustomRules:block-wp-scan`、`HTTPFlood`。连接器里对应变量 `$torii_reason`。

## 9. Gossip

消息格式变了,并带有版本号。节点会忽略其他版本的消息,并记录 `gossip dropped: protocol version differs`。请把一个集群的所有节点一起升级。临时规则现在按站点保存;UA 规则已不存在。
