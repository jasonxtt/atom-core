# 纯后端运行

不需要 WebUI 时，删除配置目录下的 `ui/main/` 即可。程序照常提供 DNS 与管理接口，`/` 只显示「没有安装 WebUI」。
以后需要界面时，把同版本的 `atom-webui.tar.gz` 解压到 `ui/main/` 并重启一次。

## 修改设置

配置包管理的 YAML 会在更新时被替换，所以要长期保留的修改写在 `webinfo/settings.json`，只写与默认不同的部分：

```json
{
  "version": 1,
  "proxies": { "main_proxy": { "addr": "192.0.2.9:1080" } },
  "ecs": { "client_ecs": { "addr": "198.51.100.5" } },
  "flags": { "core_mode": "safe", "block_aaaa": true }
}
```

| 段 | 内容 |
| --- | --- |
| `proxies` | [`socks5_proxy`](/plugins/settings-objects) 对象的地址 |
| `ecs` | [`ecs_address`](/plugins/settings-objects) 对象的地址 |
| `upstreams` | `aliapi` 上游组的**完整**上游列表（替换，不是追加） |
| `flags` | [功能开关](/guide/flags) 的值 |

上游列表示例：

```json
{
  "version": 1,
  "upstreams": {
    "foreign": [
      { "tag": "example_dns", "enabled": true, "protocol": "tcp", "addr": "203.0.113.53:53", "use_proxy": true }
    ]
  }
}
```

## 校验与生效

```bash
atomdns check -d /cus/atomdns -c config_custom.yaml
```

确认没有错误后重启服务。输出中的 `EFFECTIVE` 行显示每项设置的最终值和来源：

```text
EFFECTIVE socks5_proxy main_proxy addr=192.0.2.9:1080 source=settings
```

不想重启时，可以调用管理接口，修改会校验、保存并立即生效：

| 接口 | 用途 |
| --- | --- |
| `POST /api/v1/overrides` | 设置代理与 ECS（字段 `socks5`、`ecs`） |
| `POST /api/v1/upstream/config` | 设置上游列表（字段 `plugin_tag`、`upstreams`） |
| `POST /api/v1/flags/{名字}` | 设置功能开关（`{"value": ...}`） |
| `GET /api/v1/settings/effective` | 查看最终生效的设置 |

## 文件归属

| 内容 | 位置 |
| --- | --- |
| 插件、序列、监听 | YAML（配置包更新时会被替换） |
| 代理、ECS、上游列表、功能开关 | `webinfo/settings.json` |
| 规则、名单、学习结果 | `rule/`、`gen/` 等目录 |
| 专属分流组 | `webinfo/special_upstream_groups.json`（相关 YAML 由程序生成） |
