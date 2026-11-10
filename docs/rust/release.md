# 发版与手动替换（atomdns）

本文是操作说明，不会自动执行任何发布。契约见 [native-update.md](contracts/native-update.md)；
示例路径（`/usr/local/bin/atomdns`、`/cus/atomdns`）按实际部署替换，文中不含任何生产地址。

## 命名

| 项 | 值 |
| --- | --- |
| 仓库 | `jasonxtt/atomdns` |
| tag / Release 名 | `vX.Y.Z`（只认这一种写法；`rust-v*`、`lite-v*`、`vX.Y`、`vX.Y.Z-rc1` 都会被更新器忽略） |
| 程序 | `atomdns`（`rust/native-host` 的 cargo bin；crate 名仍是 `atomdns-native-host`） |
| 发布包 | `atomdns-linux-amd64.tar.gz`（包内只有一个文件 `atomdns`；v0.5.0 起另有 `-amd64-v3`、`-amd64-musl`、`-arm64`、`-armv7`，在线更新默认只装 `amd64`；`amd64-musl` 在 musl/Alpine 系统上由更新器自动选用；`amd64-v3` 仅在 UI 点“切换到 v3”或已运行 v3 时由更新器安装） |
| 界面包 | `atomdns-webui.tar.gz`（v0.4.0 起；顶层即 `<配置根>/ui/main/` 的文件，`ui-manifest.json` 的 `ui_version` 等于 tag） |
| 清单 | `atomdns-update-manifest.json`（`format 1`、`channel "rust"`、`version` 等于 tag、各发布包的 sha256） |
| 程序自报版本 | `atomdns version` 与 `GET /api/v1/system/health` 的 `version` 都等于 tag |

发布版本的 `native-host` crate 版本（`rust/native-host/Cargo.toml`）应与 tag 一致；非发布构建自报 `v<crate 版本>`。

### 从 rtdns 改名为 atomdns（2026-10-30，一次性手动步骤）

项目由 rtdns 改名 atomdns，**没有桥接发布**：`v0.5.2` 及更早的 rtdns 程序只认 `jasonxtt/rtdns` 的 `rtdns-linux-amd64.tar.gz`，找不到 atomdns 的发布，需要手动换一次。

- 先把 GitHub 仓库改名为 `jasonxtt/atomdns`（旧地址会重定向，但旧程序按旧资产名找不到文件）。
- 在机器上：停服务 → 换程序（`/usr/local/bin/rtdns` → `/usr/local/bin/atomdns`）→ 配置根 `/cus/rtdns` 改为 `/cus/atomdns`（或在新单元里保持旧路径）→ 单元 `rtdns.service` 换成 `atomdns.service` → 启动。
- 指标名由 `mosdns_*` 改为 `atomdns_*`、环境变量由 `MOSDNS_*` 改为 `ATOMDNS_*`：单元里的 `Environment=`、外部抓取/看板要同步改。
- 缓存转储文件格式名 `mosdns_cache_v2` 不变，原有转储可直接读取。

## 发版步骤

1. 确认 `main` 上 `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、
   `cargo test --workspace --no-fail-fast` 全绿，`rust/native-host/Cargo.toml` 的版本等于要发的版本。
2. 在 Linux x86_64 机器上构建（需要 Node 与能联网的 `npm ci`；不要同时跑前端与 Rust 构建）：

   ```bash
   scripts/build-rust-release.sh v0.2.0 release/rust
   ```

   产物：`release/rust/atomdns-linux-amd64.tar.gz`、`release/rust/atomdns-webui.tar.gz`、`release/rust/atomdns-update-manifest.json`。
   脚本会拒绝非 `vX.Y.Z` 的 tag，要求构建出的程序自报版本、界面包的 `ui_version` 都等于 tag，并核对 `scripts/rust-release-metadata.json`
   与 `update/mod.rs` 里的配置包标识和三个资产名（清单的 `artifacts` 必须同时有程序包与界面包）。脚本只构建，不发布。
3. 核对：

   ```bash
   cd release/rust
   sha256sum atomdns-linux-amd64.tar.gz atomdns-webui.tar.gz
   jq '.version, .artifacts' atomdns-update-manifest.json
   tar -tzf atomdns-webui.tar.gz | head
   mkdir -p /tmp/atomdns-verify && tar -xzf atomdns-linux-amd64.tar.gz -C /tmp/atomdns-verify
   /tmp/atomdns-verify/atomdns version
   ```

   sha256 必须与清单一致，`version` 必须等于 tag。
4. 在 GitHub 建 Release（tag 与 Release 同名，不是 draft、不是 prerelease），把上面三个文件作为资产上传，例如：

   ```bash
   gh release create v0.2.0 release/rust/atomdns-linux-amd64.tar.gz release/rust/atomdns-webui.tar.gz release/rust/atomdns-update-manifest.json \
     --repo jasonxtt/atomdns --title v0.2.0 --notes "说明"
   ```

   这是对外发布动作，需要先得到负责人确认。
5. 仅程序改动的发布到第 4 步为止。若本次发布需要新的配置包（结构性改动，`required_config_schema` 与 `config_package_id` 同时提高），
   配置包 `config_rust_up.zip` 放在 file 仓库并由清单的 `config.url` 指向（v0.5.0 前是同一 Release 的资产），按下面的顺序发版（配置包标识 `channel "rust"`、`rust-config-schema-N`、`config_rust_up.zip` 不随改名变化）。

## Docker 镜像（Release 建好之后）

镜像由 Release 文件拼装，见 [docker.md](docker.md) 的“构建与发布”。**发布正式 Release 后 `docker-image.yml` 会自动构建并推送 `jasonxtt/atomdns:vX.Y.Z` 与 `latest`**（需要仓库机密 `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`）；
要先本地检查可运行 `scripts/build-docker-image.sh vX.Y.Z`（不推送）。因此 Release 里必须一次带齐 `config_rust.zip`，建 Release 前先走完“带配置包的发版顺序”第 7 步。镜像要求 Release 带 `config_rust.zip`（其中 `ui/main` 版本等于 tag）和三个静态程序包（`amd64-musl`、`arm64`、`armv7`）。
发布 Release 本身就是对外发布，已需要负责人确认；镜像随之推送不另设确认。

## 带配置包的发版顺序

配置包与界面包放在 file 仓库的 `atomdns/` 目录（v0.5.0 起；布局见该目录的 README）：`config/full/config_rust/` 是配置源，`config/full/config_rust.zip` 是全新安装包，
`config/incremental/config_rust_up.zip` 是在线更新用的增量包，`ui/atomdns-webui.tar.gz` 是最新版的界面包。

1. **出包**：在 file 仓库的 `atomdns/config/incremental/` 运行 `build_config_rust_up.sh`（`SCHEMA`/`PACKAGE_ID` 必须等于 `update/mod.rs` 的 `REQUIRED_CONFIG_SCHEMA`/`REQUIRED_CONFIG_PACKAGE_ID`），
   得到 `config_rust_up.zip`，核对包内 `manifest.json` 的 `config_schema`、`package_id`，以及托管文件列表（含新增文件、不含 `sub_config/special_groups.yaml`）。
2. **提交并推送 file 仓库**，记下提交 ID。清单按 sha256 固定这份包，所以地址必须带**提交 ID**（不要用 `main`），已被某个版本引用的包文件不能再改。
3. **填元数据**：`sha256sum config_rust_up.zip`，把 `scripts/rust-release-metadata.json` 的 `config.url`
   （`https://raw.githubusercontent.com/jasonxtt/file/<提交 ID>/atomdns/config/incremental/config_rust_up.zip`）与 `config.sha256` 填上，`required_config_schema`/`config_package_id` 同步提高。
4. **提交**：版本号（`rust/native-host/Cargo.toml`、`rust/Cargo.lock`）与元数据一起提交。
5. **构建程序与清单**：推送后 `config.url` 已能下载，脚本会自己下载并核对；也可以用本地文件：

   ```bash
   RUST_CONFIG_PACKAGE=/path/to/config_rust_up.zip scripts/build-rust-release.sh vX.Y.Z release/rust
   ```

   脚本核对该文件的 sha256 与包内 manifest 是否等于元数据，通过后清单带 `config{url,sha256}`。
6. **建 Release**：程序包、界面包、清单，加全新安装包 `config_rust.zip`（见下一步）。增量包不再是 Release 资产。
7. **全新安装包与界面**：用同一份 `atomdns-webui.tar.gz` 在 file 仓库运行 `atomdns/config/full/build_config_rust_zip.sh <atomdns-webui.tar.gz>` 重新生成 `config_rust.zip`（带 `ui/main/`），
   并把 `atomdns-webui.tar.gz` 放进 `atomdns/ui/`，提交 file 仓库。Release 建好后，用 `curl -fsSL <config.url> | sha256sum` 再核对一次与元数据一致。
   更新器只在 `applied_config_schema < required_config_schema` 时下载配置包。

v0.5.0 起 `config.url` 指向 file 仓库（此前指向 Release 资产）；已发布的 v0.4.x 与 v0.5.0 的清单仍指向各自 Release 里的包，不受影响。

## v0.6.5 升级须知

- 上游支持 DoH over HTTP/3（`h3://` 或 `https://` 配合 `enable_http3: true`）与 DoQ（`quic://` 或 `doq://`）。可在 YAML 或 WebUI 配置，使用 UDP 直连并默认校验证书。普通 `https://` 继续使用 HTTP/1.1 或 HTTP/2。
- WebUI 增加可选的毛玻璃外观和浏览器本地背景。
- 配置 schema 仍为 7。在线更新替换程序和已安装的 WebUI。全新安装包内含本版 WebUI。
- 降级前，先从 YAML 和已保存的上游设置中移除 DoH3 和 DoQ 条目或改用旧版支持的协议。

## v0.6.4 升级须知（2026-11-06；配置 schema 7：默认只监听 53 与 API，安全模式不再回退国内）

- **配置 schema 7，有新配置包**：在线更新会一并替换配置包管理的 `config_custom.yaml` 与 `sub_config/*.yaml`，并删除 `sub_config/for_singbox.yaml`；更新失败会自动回滚。改过这些文件的，更新前先在「系统管理」导出一份配置备份（Docker 版会把旧文件备份到 `backup/container-schema-…/`）。
  规则、名单、学习结果、缓存、`webinfo/settings.json` 与专属分流组不受影响。
- **默认配置只监听 53（DNS）和 API 端口**：去掉了 2222、3333、4444、3066、3077、3099、3111、7777、8888 这些监听，以及给 Stash、ClashMi、sing-box“回家”和解析节点域名的序列。
  在用这些端口的，升级后要在自己的配置里重新加上对应的 `udp_server`/`tcp_server`（直接改配置包管理的文件会在下次配置包更新时被替换）。
- 程序：`rewrite` 的 `dns` 和 `requery` 新增的 `resolver` 可以写 `$序列名`，在进程内用该序列解析，不占端口、不进查询日志。默认配置的重写与定时刷新都改用这种方式，所以 2222、3066 不再需要。
- 分流：**安全模式**下名单外的域名只问国外 DNS（带 ECS），失败或无结果也不再回退国内；兼容模式不变。DDNS 优先国外解析在安全模式下也只用国外。
  MX、TXT 等其它类型的查询与 A/AAAA 按同样的名单优先级分流；白名单、灰名单、订阅等名单内的域名不再写入“记忆直连/记忆代理”。
- 配置里不再使用 `fast_mark 48`（Go 版快速路径遗留的标记），自己写的规则仍请避开它。
- WebUI：概览统计卡的数字与趋势线同步刷新。
- 文档：新增使用文档站 <https://jasonxtt.github.io/atomdns/>，README 与 Docker Hub 说明重写。
- 资产同 v0.6.3。

## v0.6.3 升级须知（2026-11-03；IP 范围、全局搜索、概览趋势线、Docker 改用 glibc）

- 配置 schema 仍为 6，**没有新配置包**：在线更新换程序，并在已安装 `ui/main` 时一并换成新界面。
- IP 名单支持范围：「客户端 IP」「直连 IP」等 IP 名单的每行可以写单个 IP、网段，或 `起始IP-结束IP`（如 `10.0.0.100-10.0.0.199`，横线两侧可以有空格，IPv4 与 IPv6 都行，两端须同一种）。范围在保存时展开成最少的网段，名单里之后显示的是这些网段。`192.0.2.1 - 备注` 这种“IP 加说明”的写法仍读作单个 IP。
- 页面保存名单时，行末带说明的行（如 `192.0.2.9 - office`）以前会被悄悄丢掉，现在保留前面的 IP。
- 全局搜索（Ctrl/Cmd+K）：除页面外，还能搜设置项、客户端别名与 IP、各手动名单（含专属分流组的名单）、专属分流组和查询日志。IP 按“覆盖”匹配（搜 `10.1.2.3` 能命中 `10.0.0.0/8` 或范围），域名按覆盖它的规则匹配（搜 `a.example.org` 能命中 `domain:example.org`）。选中后跳到对应页面并定位。
- 概览的统计卡改为页面底色，带趋势线（页面自己每 3 秒采样一次）。
- 服务端：解析不了的查询（如问题数为 0）以前不回包，客户端只能等超时；现在 UDP/TCP 都回只含头部的 FORMERR，不支持的操作码回 NOTIMP。回包不会比请求大；短于 12 字节的数据报和本身是响应的包仍不回。
- 文档：`docs/api_reference.md` 说明 `adguard_rule` 的 `@@` 例外规则只在直接 `qname $tag` 引用时生效，经 `domain_mapper`（广告屏蔽开关）时不生效。
- Docker 镜像改用 Debian slim + glibc（glibc 的内存收缩设置让常驻内存少十几 MB）。Release 新增 `atomdns-linux-arm64-gnu.tar.gz`、`atomdns-linux-armv7-gnu.tar.gz`（glibc ≥ 2.35，供镜像和手动安装）；原有的静态 musl `arm64`、`armv7` 包照旧。
- 构建：GitHub Actions 的 `checkout`、`setup-node`、`upload-artifact` 升到 v6。
- 资产：七种程序包（在线更新默认只认 `amd64`）、`atomdns-webui.tar.gz`、清单、全新安装包 `config_rust.zip`。

## v0.6.2 升级须知（2026-11-03；修复重启后运行时间不归零，降低大规则集的内存占用）

- 配置 schema 仍为 6，**没有新配置包**：在线更新换程序，并在已安装 `ui/main` 时一并换成新界面。
- 修复：UI 里点"重启"后，概览页的运行时间和 CPU 累计时间不再沿用旧进程的值（原地重启 `execve` 保持 PID，内核的启动时刻不变；现在以当前程序映像的启动为准）。
- 内存：`adguard_rule` 的直接匹配器（`qname $adguard`）改为紧凑的排序字节池，`domain_mapper` 构建时合并相同结果并借用规则文本。约 100 万行的 AdGuard 列表实测：稳态 139MB → 72MB，启动峰值 740MB → 395MB，点“更新”热重建峰值 1.07GB → 517MB。匹配结果与规则计数不变。
- 资产同 v0.6.1。

## v0.6.1 升级须知（2026-10-30；兼容低版本 Linux，更新器支持切换 v3 与 Alpine）

- 配置 schema 仍为 6，**没有新配置包**。
- 程序包改在 ubuntu-22.04 上构建，glibc 要求从 2.39 降到 2.35，Debian 12 及更新的系统可以直接运行（v0.6.0 的 `amd64` 包在 Debian 12 上报 `GLIBC_2.39 not found`，需要手动换成 v0.6.1 一次）。
- 新增 `atomdns-linux-amd64-musl.tar.gz`（静态 musl），给 Alpine 等 musl 系统；在线更新在 musl 构建或 Alpine 上只装这个包。
- 系统管理里“强制更新”后面新增“切换到 v3”按钮（CPU 支持 x86-64-v3 且当前不是 v3 时出现）；已运行 v3 的程序更新时继续装 v3 包。
- 资产：五种程序包（在线更新默认只认 `amd64`）、`atomdns-webui.tar.gz`、清单、全新安装包 `config_rust.zip`。

## v0.6.0 升级须知（2026-10-30；项目改名 AtomDNS，配置 schema 仍为 6）

- 程序、crate、环境变量（`ATOMDNS_*`）、指标（`atomdns_*`）、发布资产（`atomdns-*`）和更新来源（`jasonxtt/atomdns`）都改名；WebUI 显示 AtomDNS，左上角换成新图标。**没有新配置包**。
- 从 rtdns（≤ v0.5.2 且未改名的程序）升级需要手动换一次，见上文“从 rtdns 改名为 atomdns”；已按那个步骤换成 atomdns 的机器可以直接在线更新到 v0.6.0。
- 全新安装：下载 `config_rust.zip`（配置 + `ui/main/`）和程序包 `atomdns-linux-amd64.tar.gz`，解压配置目录后 `atomdns start -d <目录> -c <目录>/config_custom.yaml`。
- 配置包里的 `config_custom.yaml` 等文件仍有 `/tmp/mosdns.log` 这类旧名字（托管文件，改动需要新配置包，本版未动）。
- 资产：四种程序包（在线更新只认 `amd64`）、`atomdns-webui.tar.gz`、清单、全新安装包 `config_rust.zip`。

## v0.5.2 升级须知（2026-10-30；概览页适配宽屏，仅界面）

- 配置 schema 仍为 6，**没有新配置包**，程序逻辑没有改动：在线更新换程序，并在已安装 `ui/main` 时一并换成新界面。
- 内容区最宽 1600px，更宽的窗口里居中；概览的统计卡增加"运行时间"，共 8 张（宽屏 8 列、中等 4 列、窄屏 2 列）。
- 上游 DNS 统计按卡片宽度逐步显示"分组、类型、地址"列，放得下才显示；分组名简写（国内组、FakeIP组、国外组、ECS组），窄屏仍是一行组标题。
- 分流统计宽卡片里圆环在左、图例在右，更宽时显示次数。顶部的主题按钮只在浅色和深色间切换（"跟随系统"仍在系统管理里选）。
- 资产同 v0.5.0：四种程序包（在线更新只认 `amd64`）、`atomdns-webui.tar.gz`、清单、全新安装包 `config_rust.zip`（已带 v0.5.2 界面）。

## v0.5.1 升级须知（配置 schema 6，2026-10-30；缓存与域名学习的参数可在 WebUI 调整）

### 配置（schema 5 → 6）

- 新配置包 `rust-config-schema-6` 调低 `cache.yaml` 的默认值，并给 7 个缓存、7 条 `route_learn` 规则加了中文 `label`，`flags.yaml` 里两个缓存开关改名（「全局缓存」「分组缓存」，内部名不变）。
- 默认值：

  | 项 | 原值 | 新值 |
  | --- | --- | --- |
  | 7 个缓存的 `lazy_cache_ttl` | 259200000 秒（等于不限） | 604800（7 天） |
  | `cache_all`、`cache_all_noleak` 的 `size` | 20,000,000 | 100,000 |
  | `cache_cn` 的 `size` | 20,000,000 | 50,000 |
  | 其余 4 个缓存的 `size` | 20,000,000 | 20,000 |
  | 7 个缓存的 `dump_interval` | 36000 秒 | 21600（6 小时） |

- **更新到新配置包后，7 个缓存各以空缓存重新开始一次**（容量、保留时长、写盘间隔属于缓存身份）。在 WebUI 里改过的值存在 `webinfo/settings.json`，不受配置包更新影响。
- **手动替换程序时也要换配置包**；只换程序时功能不受影响，但缓存仍按旧默认值（容量 2000 万、保留不限）。

### 新功能

- 「规则设置 › 缓存设置」新增缓存参数：每个缓存可调容量上限、过期缓存保留时长、写盘间隔（高级），保存前确认（会清空该缓存），可恢复默认。专属分流组生成的缓存同样可调（默认 20000 / 7 天 / 6 小时）。
- 「规则设置 › 域名学习」：每类的有效期、容量上限和全局写盘间隔可直接修改，不会清空已学内容（容量调小时保留最近确认的条目）；新增自启动以来的学习/确认/过期/淘汰/清空计数和上次写盘信息。
- 缓存与学习规则可带可选的中文 `label`：缓存统计、缓存参数、条目查看和学习明细的“原因”列显示中文名，不写则显示内部名。
- 接口 `GET/POST/DELETE /api/v1/cache/settings[/{tag}]`、`GET/POST/DELETE /api/v1/learning/settings`，能力名 `cache.settings`、`learning.settings`。

### 回滚风险

- 在 WebUI 里保存过缓存或学习参数后，`settings.json` 多出 `caches` 或 `learning` 段；不认识这两段的旧版本程序会因未知键拒绝启动。**回滚前先在 WebUI 里“恢复默认”，或删除这两段。**

## v0.5.0 升级须知（2026-10-30；WebUI 换新外观，新增多种平台程序包）

- 配置 schema 仍为 5，**没有新配置包**（已发布的 v0.5.0 清单里的 `config` 仍指向 v0.4.2 Release 的 `config_rust_up.zip`；源码里的元数据已改指 file 仓库 `atomdns/config/incremental/` 的同一份文件，下一版起生效）：在线更新换程序，并在已安装 `ui/main` 时一并换成新界面，不动配置文件与用户数据。
- **界面**：整套 WebUI 换了外观（Rosé Pine 配色、明暗两套主题、侧栏二级菜单、移动端底部导航、Ctrl/Cmd+K 搜索页面）；概览、规则设置各页、日志、系统管理的版式都重排过，功能与接口不变。
  没有 `ui/main` 的部署（纯后端）不受影响；外置界面仍可放在 `ui/<名字>/`。
- **程序包**：Release 现在带四种程序包，包内都只有一个文件 `atomdns`：

  | 资产 | 目标 | 说明 |
  | --- | --- | --- |
  | `atomdns-linux-amd64.tar.gz` | x86_64，glibc ≥ 2.35（Debian 12 及更新） | 通用基线；**在线更新只认这一个** |
  | `atomdns-linux-amd64-v3.tar.gz` | x86_64，glibc | `-C target-cpu=x86-64-v3`（需要 AVX2 等，约 2013 年后的 CPU），手动安装，或在 UI 的更新区点“切换到 v3” |
  | `atomdns-linux-arm64.tar.gz` | aarch64，静态 musl | 手动安装；glibc 与 OpenWrt 都能跑 |
  | `atomdns-linux-amd64-musl.tar.gz` | x86_64，静态 musl | Alpine 等 musl 系统（glibc 包在这些系统上无法启动）；在线更新在运行 musl 构建、或发现 `/etc/alpine-release` 时只装这个包，不提供 v3 |
  | `atomdns-linux-armv7.tar.gz` | armv7 硬浮点，静态 musl | 手动安装 |

  非 amd64 平台的在线更新尚未支持（更新器只在 linux x86_64 上可用，清单里多出的包会被忽略）；这些平台升级时下载对应包、替换 `atomdns` 并重启，`ui/main` 用 `atomdns-webui.tar.gz` 手动换。
  musl 包（含 ARM）的内存分配器与 glibc 不同，没有 glibc 专用的 `mallopt`/`malloc_trim` 调优，常驻内存没有按 glibc 的数据测过。
- **构建**：`VARIANTS="amd64 amd64-v3 amd64-musl arm64 armv7" scripts/build-rust-release.sh vX.Y.Z` 一次出齐；ARM 包需要 `cargo-zigbuild` 与 qemu-user binfmt，
  所以统一用 GitHub Actions 的手动工作流 `release-build.yml`（只构建、不发布，产物在 Actions 的 `release-<tag>` 里下载）。

## v0.4.2 升级须知（配置 schema 5，2026-10-29；在线订阅多格式、订阅分组、命中标签改名）

### 配置（schema 4 → 5）

- 新配置包 `rust-config-schema-5` 只把 `rule_set.yaml` 里四个订阅集合的命中标签改名（另有注释同步），**分流判定、优先级与订阅清单都不变**。在线更新会与程序、界面一起应用。
- **手动替换程序时也要换配置包**（同一 Release 的 `config_rust_up.zip`）；只换程序时功能不受影响，但日志仍写旧名称，更新状态提示配置包过旧。

| 订阅集合 | 旧日志标签 | 新名称（日志与界面一致） |
| --- | --- | --- |
| `geosite_cn` | 订阅直连 | 中国域名 |
| `geosite_no_cn` | 订阅代理 | 非中国域名 |
| `cuscn` | 订阅直连补充 | 直连域名 |
| `cusnocn` | 订阅代理补充 | 代理域名 |

已写入的日志保留旧名称；程序同时认新旧名称，统计里新旧名称在旧记录过期前分开计数。

### 在线订阅支持更多格式

- 分流（域名集、IP 集）与请求屏蔽的订阅，除 `.srs` 外支持：文本（`.txt` `.list` `.conf`：域名列表、Clash/Surge/QuantumultX 经典规则、mihomo 写法、dnsmasq、hosts、CIDR）、Clash/mihomo YAML（`payload`）、sing-box JSON 规则集、v2ray `geosite.dat`/`geoip.dat`（按分类整体导入）、mihomo `.mrs`。
- 下载时转换一次并存为规范文本，启动与热应用只读转换后的文件。清单新增可选字段 `format`（`auto` 缺省，另有 `srs`/`text`/`yaml`/`json`/`dat`/`mrs`）与 `category`（`dat` 必填）；WebUI 编辑框有"格式"下拉和"分类"输入。
- 无法表达的规则（进程、端口、逻辑规则等）整条跳过并计数；`regexp` 类规则只在该来源开启"启用正则"时生效。`.dat` 不支持 `@属性` 过滤，`geoip.dat` 的 `reverse_match` 分类会下载失败。`.mrs` 解压上限 64 MiB。
- 新订阅的本地文件沿用地址里的文件名（如 `srs/gfw.mrs`），文件按内容识别。同一个 `geosite.dat` 建多个分类时请给每个订阅不同的本地文件名。
- GitHub 上的文件请用 raw 地址（`raw.githubusercontent.com/...` 或 `.../raw/...`），`.../blob/...` 是网页，下载会失败（旧文件保留）。

### 行为变化

- **请求屏蔽里的 hosts 行现在算拦截**（`0.0.0.0 name`、`127.0.0.1 name` 等按 `full:` 拦截，`localhost` 等跳过）。订阅了 hosts 格式列表的，升级后拦截条数会变多。
- 请求屏蔽订阅下载到零条可用规则时算失败，保留旧文件。

### 界面

- 分流规则页分成三级标签：在线订阅、白/灰名单、FakeIP 过滤（两个 fakeip filter 名单从"运行模式"移来）、直连 IP 与重定向、DDNS 域名。
- 在线订阅分两组：上方**自定义订阅**（直连域名、代理域名，新增只能选这两类）；下方**基础规则**（中国域名、非中国域名、中国 IP），可关闭、可改地址，界面上不能删掉最后一条，改地址有提示、关闭要确认，并可"恢复默认地址"。限制只在界面里，手写配置不受影响。

### 构建

- 新依赖 `ruzstd =0.9.1`（纯 Rust）；从源码构建需要 Rust 1.87 以上。

## v0.4.1 升级须知（2026-10-28；内存优化，仅程序与界面）

- 配置 schema 仍为 4，没有新配置包：在线更新只换程序与 `ui/main`（已安装界面时），不动配置文件与用户数据。
- 常驻内存下降：域名索引池化与审计日志去重，受控测试稳态 RSS −23%（不做操作时约 68 → 52 MiB），热应用峰值约 −17%，日志读/清空/改容量峰值约 −30%；每个应答的 CPU 约 +5.6%。证据见 [10-25-memory-optimization](validation-records/10-25-memory-optimization/README.md)。
- **行为变化**：由 WebUI/接口保存过的上游组（`webinfo/settings.json` 的 `upstreams.<组>`），现在同时向组内**所有启用的上游**并发查询（最多 20 个，与 Go 版一致）；只用 YAML 的组保持自己的 `concurrent`。
  专属分流组同样按启用数并发。想恢复 YAML 的列表与并发数，在上游设置里对该组"恢复默认"。保存与 YAML 相同的列表也会保留为"已管理"。
- 概览"域名统计"改为按完整保留日志计数（以前受排行截断影响会偏小）；DDNS 名单移到"分流规则"页。

## v0.4.0 升级须知（配置 schema 4，2026-10-24；WebUI 拆出程序）

### WebUI 从程序里拆出来

- 程序**不再内嵌 WebUI**。WebUI 是 `<配置根>/ui/main/`，由 `/` 提供（不需要路径前缀）；其它 `ui/<名字>/` 照旧在 `/<名字>/`。没有 `ui/main/` 时 `/` 只显示"没有安装 WebUI"，接口照常（纯后端）。
- 每个 Release 多一个资产 `atomdns-webui.tar.gz`。从 v0.4.0 起，在线更新**只在 `ui/main/` 已存在时**把它与程序、配置包放进同一个事务替换，失败一起回滚；没有 `ui/main/` 的机器保持纯后端。
- 全新安装的 `config_rust.zip` 自带 `ui/main/`。

### 从 v0.3.0 升级（一次性手动步骤）

v0.3.0 的更新器不认识界面资产：它会照常升级程序与配置包（schema 3 → 4），但不会放 `ui/main/`，而 v0.4.0 已不内嵌界面。**先放界面、再在线升级**：

1. 从 v0.4.0 的 Release 下载 `atomdns-webui.tar.gz`，核对 sha256 与同一 Release 的 `atomdns-update-manifest.json` 里 `artifacts["atomdns-webui.tar.gz"].sha256` 一致：

   ```bash
   sha256sum atomdns-webui.tar.gz
   jq -r '.artifacts["atomdns-webui.tar.gz"].sha256' atomdns-update-manifest.json
   ```

2. 解压到配置根（`atomdns start -d` 的目录）下的 `ui/main/`（v0.3.0 会把它当作外置界面挂在 `/main/`，不影响使用）：

   ```bash
   mkdir -p /cus/atomdns/ui/main && tar -xzf atomdns-webui.tar.gz -C /cus/atomdns/ui/main
   ```

3. 在 v0.3.0 的界面里照常"在线更新"到 v0.4.0（自动切换）。
4. 打开 `http://<主机>:<API 端口>/`，系统管理页"界面版本"应为 v0.4.0。

已经先升级了的：`/` 会显示"没有安装 WebUI"，做第 1–2 步后重启一次（`systemctl restart atomdns` 或 `curl -X POST http://127.0.0.1:<API 端口>/api/v1/system/restart`）。
回退到 v0.3.0 时 `ui/main/` 留着无害（v0.3.0 用内嵌界面，把它挂在 `/main/`）。

### 配置（schema 4）

- `ddns_foreign`（DDNS 优先国外解析）移到"运行模式"。
- 上游组可声明 `show_when`：`cnfake` 只在"国内域名 FakeIP"开启时、`nocnfake` 只在"FakeIP 分流"时显示在上游设置与概览（可点"显示未生效的组"查看）；3099 端口（clashmi）不看 `cn_fakeip`，始终使用 `cnfake`。
- 一个上游组至少要保留一个启用的上游：停用或删除最后一个会被明确拒绝（以前停用报看不懂的 400，删除则显示成功、刷新后又回来）。
- 修正：RealIP 分流下，刷新（requery）不再向 sing-box 要 FakeIP 并写进客户端共用的缓存。
- 侧栏"规则设置"的 8 个子项默认收起，点"规则设置"展开/收起。

## v0.3.0 升级须知（配置 schema 3，2026-10-24；功能开关 + UI 重做）

经在线更新升级时，程序与配置包（`rust-config-schema-3`）一起由 update-guard 替换，失败则程序、配置文件、包状态一起回滚。
手动替换程序时必须同时更新配置包：新程序只认 schema 3，旧配置里的 `switchN` 插件或匹配写法在新程序里加载失败。

### 配置与开关

- 包把 `switch1`–`switch17` 换成 `sub_config/flags.yaml` 里的 13 个具名开关（`feature_flag`，见 [native-feature-flags](contracts/native-feature-flags.md)），
  删除 `sub_config/switch.yaml`；`create_if_missing` 为空，`rule/switchN.txt` 是用户数据，包既不创建也不删除。
- 开关值改存 `webinfo/settings.json` 的 `flags` 段（只存与 YAML 默认不同的值）。**首次正常启动**时从 `rule/switchN.txt` 迁移一次；
  在线更新的试运行期间不写盘（`settings.json` 字节不变，所以自动回滚是安全的），由 update-guard 起的最终程序写入。旧的 `rule/switchN.txt` 保留但不再读取。
- 开关可在 WebUI 规则设置各子项顶部切换，也可用 `GET/POST/DELETE /api/v1/flags[/{名字}]`。
  `core_mode`、`dns_mode`、`cn_fakeip` 切换后由程序自己触发一次 requery（清缓存再预热）；自己的配置要同样的联动，在开关的 `args` 里写 `requery_on_change: true`。

### 删除的接口（依赖它们的外置界面会失效）

- `/plugins/switchN/show`、`/plugins/switchN/post`（改用 `/api/v1/flags`）；
- `/api/v1/appearance/*` 与能力 `appearance.server`；
- `POST /api/v1/config/update_from_url`（"应用远程配置"；旧地址返回 404，配置包只随程序在线更新下发）。

调用这些接口的外置界面（旧的 `ilog`、第三方控制台、自写脚本）升级后对应功能会失效，需要改用上面的新接口或停用。"备份配置"保留，下载文件名 `atomdns_backup.zip`。

### 内置 WebUI（v0.3.0 时）

- 侧栏布局：概览、日志、规则设置（8 个子项：运行模式、上游设置、分流规则、请求屏蔽、域名学习、缓存设置、客户端、专属分流组）、系统管理（一页），
  地址形如 `#/overview`、`#/rules/upstream`，刷新保持当前页；`#/rules/rewrite` 跳到 `#/rules/routing`。
- 外观只保留浅色 / 深色 / 跟随系统（存在浏览器里）；背景图、毛玻璃、透明度、文字与按钮颜色已删除。外置 UI 要背景图请放进自己的静态包。
- **浏览器里的旧设置不迁移**（主题、自动刷新、配置目录等 `atomdns*` 键），首次打开新界面按默认值（跟随系统、自动刷新关闭），需要时重新设置一次。
- 概览的实时趋势图已去掉，统计口径仍是审计保留记录；客户端别名从日志页挪到 规则设置 › 客户端；"高级替换规则"面板已删除（原生不支持）；域名学习页新增学习明细。
- 配置包不再附带 `ui/ilog/`；包不管理已部署机器的 `ui/`，已有的 `ui/ilog/` 不受影响。

### 升级后要手动做的事

`webinfo/requeryconfig.json` 是用户数据，包不会改它。新配置里 `cache_cnmihomo` 缓存也要随 requery 保存和清空，请在已有文件里手动补两行（各放在对应数组里，与相邻条目格式相同）：

- `url_actions.save_rules` 加：`"http://127.0.0.1:9099/plugins/cache_cnmihomo/save",`
- `url_actions.flush_rules` 加：`"http://127.0.0.1:9099/plugins/cache_cnmihomo/flush",`

端口照抄已有条目即可：requery 把主机为 `127.0.0.1`、`localhost`、`0.0.0.0`、`::`、`::1` 的 URL 一律当作本机 API，在程序内部执行，不看 URL 里的端口
（WebUI 端口设置改过 API 端口也不影响）。升级后可触发一次 requery，用 `GET /plugins/requery/status` 核对它正常结束。

### 可删除的旧文件（升级并验证后；程序不读也不删）

- `ui/ilog/`、`ui/ron/`、`ui/modify instruction`（旧页面，不用时）；
- 外观：`webinfo/appearance_settings.json`、`appearance_text_settings.json`、`appearance_button_settings.json`、`panel_background.bin`、`panel_background_history/`；
- Go 时代文件：`webinfo/upstream_overrides.json`、`config_overrides.json`、`domain_generation_settings.json`、`config_update_state.json`（Go 版的包状态；atomdns 用 `rust_config_update_state.json`）；
- v0.2.2 起不再读取的旧学习名单：`gen/*list.txt`、`gen/*rule.txt`（**不含** `gen/top_domains.txt`，requery 用它；`gen/route_learner.json` 是现行学习状态，也要保留）。
- `rule/switchN.txt` **建议保留**到确定不再需要降级为止（降级到 v0.2.2 要靠它）。

### 手动降级到 v0.2.2

先停服务，再从 `webinfo/settings.json` 删掉 `flags` 键（v0.2.2 不认识它，会拒绝启动），换回 v0.2.2 程序与 schema 2 的配置包。
`rule/switchN.txt` 仍在，但取值停留在迁移那一刻：降级前若在新程序里改过开关，需要手动把对应文件改成 `A`/`B`（对应关系见 [native-feature-flags](contracts/native-feature-flags.md) 的迁移表）。
删除 `settings.json` 或其 `flags` 键会让下一次启动重新迁移（旧的）开关文件。


## v0.2.2 升级说明（配置 schema 2，2026-10-23，路由学习重做）

- 新程序要求 `rust-config-schema-2` 的配置包；旧 schema 1 的配置（`domain_output` 带 `target_mapper`）在新程序里加载失败。
  经在线更新升级时程序与配置包一起由 update-guard 替换（失败则程序、配置文件、包状态一起回滚）；手动替换程序时必须同时更新配置包。
- 学习名单从零开始：旧的 `gen/*list.txt`、`gen/*rule.txt` 不再被读取，可手动删除；新的学习状态写在 `gen/route_learner.json`（见 [native-route-learner](contracts/native-route-learner.md)）。
- requery 不再清空学习名单。
- 用户数据不动：`webinfo/`（含 `settings.json`、专属分流组 JSON）、`rule/`、`sub_config/special_groups.yaml`（程序生成）都不在包的托管范围内。

已部署的 `v0.2.0` 及之后的 atomdns 会在系统设置里看到新版本，点“立即更新”走带自动回滚的事务（见契约文档）。

## 生产从 rust-v0.1.4 手动替换到 v0.2.0

`rust-v0.1.4` 是手动部署的，内置的更新地址指向旧仓库，且旧仓库从未发布过 `rust-v*`，所以它**不会**自己升级到 `v0.2.0`，需要手动换一次。
换成 `v0.2.0` 之后，在线更新只来自 `jasonxtt/atomdns`。配置、规则、缓存等数据都不用动（`v0.2.0` 是仅程序改动的发布，配置包标识不变）。

1. 把 `atomdns-linux-amd64.tar.gz` 与清单传到服务器的临时目录，核对 sha256（同上第 3 步），解出 `atomdns`，
   并用生产配置预检：

   ```bash
   ./atomdns version
   ./atomdns check -d /cus/atomdns -c config_custom.yaml
   ```

   `check` 必须报告 `gaps=0 cascades=0 globals=0`。
2. 备份旧程序（留着回退用），把新程序放到同目录再原子改名：

   ```bash
   cp -a /usr/local/bin/atomdns /usr/local/bin/atomdns.rust-v0.1.4
   install -m 0755 ./atomdns /usr/local/bin/atomdns.new
   mv /usr/local/bin/atomdns.new /usr/local/bin/atomdns
   ```
3. 重启并验证：

   ```bash
   systemctl restart atomdns
   systemctl is-active atomdns
   curl -s http://127.0.0.1:9099/api/v1/system/health   # "version" 应为 v0.2.0，"ready" 应为 true
   dig @127.0.0.1 example.com +short                     # 能解析
   ```

   在 WebUI 系统设置里点“检查更新”：应显示当前 `v0.2.0`，发布页指向 `jasonxtt/atomdns`，没有可用更新（还没有更高的发布时）。
   `update/installed.json` 此时不存在是正常的（它只记录经更新器安装的版本），第一次在线更新成功后才会出现。
4. 回退（任何一步异常）：

   ```bash
   systemctl stop atomdns
   mv /usr/local/bin/atomdns.rust-v0.1.4 /usr/local/bin/atomdns
   systemctl start atomdns
   ```

   旧程序用同一份配置与数据即可运行；`v0.2.0` 没有改持久化格式。
5. 确认稳定后可删除 `atomdns.rust-v0.1.4`。

## 不属于本流程

- Go 版 MosDNS 的发布、`/Users/tom/github/mosdns` 仓库、旧 Go→Rust 切换工具（`scripts/cutover/`、`tools/cutover/`）：
  这些工具仍按旧程序名和 `rust-v*` 版本格式编写，**不适用于 `v0.2.0` 及之后的程序**；生产已于 2026-10-21 完成切换，它们只作历史与回滚参考。
