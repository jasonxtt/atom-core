# atom 自带的 AtomDNS 配置

来源：`jasonxtt/file` 仓库 `atomdns/config/full/config_rust`（commit `862844a`，配置 schema 7，对应 AtomDNS v0.6.4）。
atom 删除了在线更新和配置包，这份配置随程序一起发布，用户不改。

相对来源的改动（atom 设计文档第 7.1 节）：

- DNS 分流模式固定为 FakeIP：删除 `dns_mode` 开关和 RealIP 的结果序列（`sequence_proxy_realip_*`）。
  `sequence_fakeip_exit` / `sequence_fakeip_addlist_exit` 直接向 `nocnfake` 要 FakeIP。
- 国内域名 FakeIP 固定为关：删除 `cn_fakeip` 开关、`cnfake` 上游组、`cache_cnmihomo` 缓存和所有 `localfake` 序列。
- `nocnfake` 固定为 `udp://127.0.0.1:6666`（sing-box 的 `dns-in`），去掉 `show_when` 和 `proxy`；
  程序拒绝在设置里改它，发往它的查询带 EDNS0 65001 CLEAR。
- 删除专属分流组：不再包含 `sub_config/special_groups.yaml`、`webinfo/special_upstream_groups.json`，
  主流程去掉 `$special_upstream_matcher` 和 `$sequence_special`。
- `main_proxy` 默认 `127.0.0.1:7890`（本机 sing-box 的 mixed 入站）。
- 删除来源包里描述 Go → Rust 迁移的 `README-rust.md`。
- 删除 `realiplist`（mark 9，国外 DNS 解析、返回真实 IP，在 FakeIP 网段分流下等于悄悄直连）和 `cnfakeipfilter`
  （mark 10，只在 `cn_fakeip` 开启时生效）：名单插件、`unified_matcher1` 条目、`rule/` 下的文件、分流分支和只给
  realiplist 用的 `sequence_google_exit`。以后需要"国外 DNS 解析后直连"，用规则表表达。
