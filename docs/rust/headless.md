# 不使用 WebUI 的配置方式

从 v0.4.0 起程序不内嵌 WebUI：WebUI 是配置根目录下的 `ui/main/`（由 `/` 提供）。**没有 `ui/main/` 就是纯后端**：
`/` 只返回一段"没有安装 WebUI"的说明（404），接口、`/metrics` 与其它 `ui/<名字>/` 照常；在线更新也不会创建它
（`ui/main/` 存在时才随程序一起替换）。全新安装包 `config_rust.zip` 自带 `ui/main/`，不要界面就删掉它。
之后需要界面时，把同版本 Release 的 `atom-webui.tar.gz` 解到 `ui/main/` 再重启一次即可（见 [external-ui.md](external-ui.md)）。

YAML 提供默认值。通过 `config_rust_up.zip` 管理的 `config_custom.yaml` 和
`sub_config/*.yaml` 会随配置包更新替换；希望更新后保留的代理、上游列表和 ECS
设置，写在**配置根目录下的 `webinfo/settings.json`**。这个文件不属于配置包的覆盖范围。
只写与 YAML 默认值不同的部分，保留 `"version": 1`，其余部分可以省略。

## 三个最小示例

以下对象名必须替换成你现有 YAML 中的对应 tag；如果对象不存在或类型不对，
`check` 会报错。示例地址使用文档保留网段，实际使用时换成自己的地址。

代理对象 `main_proxy` 的类型须为 `socks5_proxy`，使用方通过 `proxy: $main_proxy`
引用它。修改其地址：

```json
{"version":1,"proxies":{"main_proxy":{"addr":"192.0.2.9:1080"}}}
```

上游对象 `foreign` 的类型须为 `aliapi`。下面替换它的**整个上游列表**，不是追加一项；
要保留的项都需列出，至少有一项 `enabled: true`。`protocol` 可用 `udp`、`tcp`、
`tls`、`https`；`addr` 不带协议时由 `protocol` 补全。`concurrent` 仍取 YAML 的值。

```json
{"version":1,"upstreams":{"foreign":[{"tag":"example_dns","enabled":true,"protocol":"tcp","addr":"203.0.113.53:53","use_proxy":true}]}}
```

这里的 `use_proxy: true` 要求 `foreign` 的 YAML 有 `proxy: $main_proxy`；
不使用代理时设为 `false`。UDP 不使用 SOCKS5。上游列表设置不能与该插件 YAML
中的字面量 `socks5:` 混用。代理地址为空表示直连。

ECS 对象 `client_ecs` 的类型须为 `ecs_address`，使用方通过 `ecs $client_ecs`
或 `ecs_handler` 的 `preset: $client_ecs` 引用它：

```json
{"version":1,"ecs":{"client_ecs":{"addr":"198.51.100.5"}}}
```

三个示例可以合成一个 JSON 对象：`version` 只写一次，`proxies`、`upstreams`、
`ecs` 各保留一份。未指定的对象继续使用 YAML 默认值；删除某个对象的覆盖项即可恢复默认值。
不要把多个 JSON 对象直接拼接成一个文件。手写文件不会自动去除与 YAML 相同的值；
API 保存时会去除这类重复值。

## 校验与生效

例如配置根为 `/etc/atomdns`，主配置为该目录的 `config_custom.yaml`：

```sh
atomdns check -d /etc/atomdns -c config_custom.yaml
```

`check` 只读取并校验，不写文件、不应用到正在运行的进程。确认没有错误后重启你运行的
`atomdns` 进程或服务。直接编辑 JSON 不会自动热加载。

检查输出中的每条 `EFFECTIVE` 行描述最终值及来源，例如：

```text
EFFECTIVE socks5_proxy main_proxy addr=192.0.2.9:1080 source=settings
EFFECTIVE ecs_address client_ecs addr=198.51.100.5 source=settings
```

`source=yaml` 表示来自 YAML 默认值，`source=settings` 表示来自 JSON 覆盖。
对象名和字段以实际输出为准。`GET /api/v1/settings/effective` 也能查看最终值。

需要不重启生效时，可使用已有管理 API：`POST /api/v1/overrides` 设置唯一的代理/ECS
对象（字段 `socks5`、`ecs`），或 `POST /api/v1/upstream/config` 设置上游列表
（字段 `plugin_tag`、`upstreams`）。这些 API 会校验、持久化并热应用；
`overrides` 里的空值表示移除覆盖、回到 YAML 默认值。存在多个代理/ECS 对象时，
该全局入口会报告歧义，应按对象编辑 JSON 后重启。
接口详情与限制见 [设置契约](contracts/native-settings.md)。

## 功能开关

运行模式、屏蔽、缓存、客户端分流等开关是 YAML 里的 `feature_flag`（`config_rust` 在 `sub_config/flags.yaml`），
值写在 `settings.json` 的 `flags` 段：开关写 `true`/`false`，多选一写选项值，只写与 YAML `default` 不同的项。

```json
{"version":1,"flags":{"core_mode":"safe","block_aaaa":true}}
```

`flags` 段即使为空（`"flags": {}`）也要保留：它表示旧的 `rule/switchN.txt` 已经迁移过；删掉它，下次启动会重新按旧文件迁移。
不重启修改用 `POST /api/v1/flags/{名字}`（`{"value": ...}`）或 `DELETE /api/v1/flags/{名字}`（恢复默认），
`GET /api/v1/flags` 列出全部开关的说明、选项、默认值与当前值；`check` 输出 `EFFECTIVE feature_flag ...` 行。
细节见 [开关契约](contracts/native-feature-flags.md)。

## 文件归属

| 内容 | 权威位置与修改方式 |
| --- | --- |
| 默认插件、序列、监听与引用关系 | YAML；配置包管理的文件会随更新替换 |
| 需跨配置包更新保留的代理、ECS、普通 aliapi 上游列表、生成开关及功能开关 | `webinfo/settings.json`；手写后 check、重启，或用已有设置 API |
| 用户规则、IP 名单、学习结果 | YAML 指定的 `rule/`、`gen/` 等文件；不写进 settings，配置包不管理这些用户数据 |
| 专属分流组 | `webinfo/special_upstream_groups.json` 是权威 JSON；通过专属组 API 管理，相关 YAML 由程序生成 |
| WebUI | `ui/main/`（可选）；在线更新只在它存在时替换，配置包不管理 `ui/` |

不要直接修改生成的 `sub_config/special_groups.yaml` 来保存专属组变更，也不要用普通
上游 API 修改专属组拥有的上游。细节见 [专属组契约](contracts/native-special-groups.md)。
原生程序不读取 Go 的旧 `upstream_overrides.json`、`config_overrides.json` 或
`domain_generation_settings.json` 作为这里的设置覆盖。
