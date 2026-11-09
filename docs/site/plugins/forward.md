# forward / aliapi

把查询转发给上游 DNS，采用最先返回的有效应答。`aliapi` 是可以在 WebUI 管理上游列表的版本。

**类型**：执行器　**可在 WebUI 调整**：`aliapi` 可以（上游设置）

## 示例

```yaml
- tag: forward_remote
  type: forward
  args:
    concurrent: 2
    upstreams:
      - tag: google
        addr: https://dns.google/dns-query
        dial_addr: 8.8.8.8
      - tag: cloudflare
        addr: tls://1.1.1.1
      - addr: 223.5.5.5
```

在 `sequence` 中调用：

```yaml
- exec: $forward_remote
```

## 参数

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `upstreams` | 列表 | 必填 | 上游列表，至少一个 |
| `concurrent` | 整数 | `1` | 每次同时查询的上游数：`forward` 为 1–3，`aliapi` 为 1–20 |
| `bootstrap` | 地址 | — | 为所有上游解析域名用的 DNS，如 `223.5.5.5:53` |
| `bootstrap_version` | `0` / `4` / `6` | `0` | bootstrap 解析的地址族，`0` 为不限 |

多个上游时，每次从轮转的起点开始取 `concurrent` 个同时查询：有地址的应答最优先，其次是其它有效应答，都失败才返回错误。

### 上游项

| 参数 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `addr` | 字符串 | 必填 | 上游地址，格式见下文 |
| `tag` | 字符串 | — | 名称，用于日志与统计，全局唯一 |
| `dial_addr` | IP | — | 直接连接的 IP，跳过对 `addr` 域名的解析 |
| `bootstrap` / `bootstrap_version` | | 继承 | 覆盖全局设置 |
| `upstream_query_timeout` | 毫秒 | `5000` | 单次查询超时 |
| `insecure_skip_verify` | 布尔 | `false` | 跳过加密上游的证书校验 |
| `enable_http3` | 布尔 | `false` | 对 `https://` 上游使用 HTTP/3 |

## 地址格式

| 写法 | 协议 | 默认端口 |
| --- | --- | --- |
| `223.5.5.5`、`udp://223.5.5.5` | UDP | 53 |
| `tcp://223.5.5.5` | TCP | 53 |
| `tls://1.1.1.1` | DNS over TLS | 853 |
| `https://dns.google/dns-query` | DNS over HTTPS | 443 |
| `h3://dns.example/dns-query` | DNS over HTTPS（HTTP/3） | 443 |
| `quic://dns.example`、`doq://dns.example` | DNS over QUIC | 853 |

`addr` 使用域名时，必须同时提供 `dial_addr` 或 `bootstrap`，否则配置检查不通过。
DoH3 和 DoQ 通过 UDP 直连，默认校验证书。指定 `dial_addr` 时仍使用 `addr` 的主机名校验证书。
`h3://` 和 `https://` 配合 `enable_http3: true` 等价，均固定使用 HTTP/3。

## aliapi

参数与 `forward` 相同，另外支持：

| 参数 | 位置 | 说明 |
| --- | --- | --- |
| `proxy` | 插件 | 引用一个 [`socks5_proxy`](/plugins/settings-objects)，如 `proxy: $main_proxy` |
| `use_proxy` | 上游项 | 该上游经 `proxy` 连接，适用于 TCP、DoT 和使用 HTTP/1.1 或 HTTP/2 的 DoH |
| `show_when` | 插件 | 仅影响 WebUI：满足条件时才显示该上游组，写法同 `matches`，如 `flag dns_mode=fakeip` |

```yaml
- tag: foreign
  type: aliapi
  args:
    concurrent: 2
    proxy: $main_proxy
    upstreams:
      - tag: google
        addr: https://dns.google/dns-query
        dial_addr: 8.8.8.8
        use_proxy: true
```

在 WebUI 保存过上游列表后，该组改用 WebUI 中的列表，所有启用的上游同时查询（最多 20 个）；点「恢复默认」回到 YAML 中的设置。

## 简写

在 `sequence` 中可以直接写地址，不用单独定义插件，多个地址时 `concurrent` 为 3：

```yaml
- exec: forward https://1.1.1.1/dns-query 223.5.5.5
```

## 与 MosDNS 的差异

::: warning 不支持的选项
`enable_pipeline`、正数 `idle_timeout`、`max_conns`、`so_mark`、`bind_to_device`，
写了会在启动时报错，而不是被静默忽略。`forward` 不支持 `socks5`，需要代理请用 `aliapi` 的 `proxy`。
`aliapi` 不支持阿里云签名 API（`account_id` 等字段）。
:::
