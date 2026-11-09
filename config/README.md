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

第 2 步（规则表，atom 设计文档第 3.1、4 节）：

- 新增 `sub_config/atom_rules.yaml`：`atom_rules` 插件（用户规则表）。规则存在 `webinfo/atom_rules.json`，
  自定义规则集存在 `webinfo/atom_rulesets.json` 和 `webinfo/atom_rulesets/<id>-<revision>.txt`，都由 `/api/v1/atom/` 管理，
  这份配置里不放；没有 `atom_rules.json` 时用默认规则表（局域网和私有域名 → 直连，广告 → 屏蔽），第一次修改时才写文件。
- 主流程 `sequence_6666` 和刷新流程 `sequence_requery`：DDNS 之后执行 `$atom_rules`，按 fast_mark 40（屏蔽，`reject 0`）、
  41（代理：A/AAAA 走 `$sequence_fakeip_exit`，查询带 65001 SET 组；其他类型问国外）、42（直连：国内 DNS）分派。
  "记忆无 V4/V6"空答和黑名单屏蔽挪到规则表后面，属于原判断。
- 删除固定的广告屏蔽步骤（fast_mark 5 + `flag block_ads`）和 `block_ads` 开关：广告屏蔽是默认规则表里的一条规则，
  可以被排在前面的直连规则放行。`unified_matcher1` 仍给广告域名打 mark 5（只影响诊断标签）。
- 黑名单、白名单、灰名单、`cuscn`、`cusnocn` 暂时留在原判断里，第 6 步换 WebUI 时并入规则表。

第 3 步（sing-box 配置生成，atom 设计文档第 5、6 节）：

- `sub_config/atom_rules.yaml` 的 `atom_rules` 插件加了 `singbox` 段：sing-box 程序、工作目录（配置根下的 `sing-box/`，
  放 atom 生成的 `config.json` 和 `cache.db`）、重载命令（`systemctl reload-or-restart atom-sing-box.service`）、
  Clash API `127.0.0.1:9090`、FakeIP DNS 入站 `127.0.0.1:6666`（和 `nocnfake` 一致）、本机 AtomDNS `127.0.0.1:53`、
  redirect 7892 / tproxy 7893、默认 resolver 取自 `domestic` 组。节点、组、Final 和 sing-box 设置存在
  `webinfo/atom_proxy.json`，由 `/api/v1/atom/` 管理，这份配置里不放。

第 6 步（自带名单并入规则表，atom 设计文档第 4.4 节）：

- 删除黑名单（`blocklist`，mark 1）、白名单（`whitelist`，mark 8）、灰名单（`greylist`，mark 7）：名单插件、
  `unified_matcher1` 条目、`rule/` 下的三个文件、主流程和刷新流程里的黑名单屏蔽、`process_listed.yaml` /
  `process_ot.yaml` 里的分支，以及 `block_blocklist` 开关。这三份是原作者个人的名单，分享版不带；
  要屏蔽、代理、直连某些域名，在规则表里写规则。不写迁移：atom 还没发布过。
- `cusnocn`（代理修正，mark 15）、`cuscn`（直连修正，mark 13）成为规则表的内置规则集（`atom_rules.yaml` 的 `builtin`），
  默认规则表多两条：代理修正 → 代理到 Final，直连修正 → 直连，排在广告之后、和原来在原判断里的顺序一致。
  `process_listed.yaml` / `process_ot.yaml` 里 13、15 的分支删除（命中的查询已经被规则表处理）。
  插件和 srs 文件保留，`unified_matcher1` 照旧打标；内置规则集可以用 `POST /api/v1/atom/rulesets/{id}/refresh` 重新下载。
- `client_routing` 开关和 `rule/client_ip.txt` 暂不改动（待定）。规则表排在它前面，所以
  "名单内客户端不走代理"的客户端查代理修正里的域名，也会被规则表判成代理。
