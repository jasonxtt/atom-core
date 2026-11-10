# 从 MosDNS 迁移

AtomDNS 沿用 MosDNS v5 的配置语法和插件语义，但它是独立的程序，迁移前请先了解以下几点。

## 能直接沿用的

- 自己写的 YAML 配置：`plugins`、`sequence`、`include` 写法相同，大部分插件参数相同。
- 规则文件：域名表、IP 表、hosts、重定向等文本文件格式不变。
- 在线规则订阅的配置（`rule/` 与 `srs/` 下的清单和规则文件）。

## 不会继承的

缓存、路由学习结果、查询统计都从零开始积累。它们会在使用中重新建立，通常几天内就恢复到原来的水平。

## 建议的迁移方式

1. 用全新安装包 `config_rust.zip` 初始化一个新的配置目录。
2. 在 WebUI 里按原来的习惯重新设置上游、代理、规则订阅和功能开关。
3. 把自己维护的名单（白名单、灰名单、hosts、重定向等）复制到新目录对应位置。
4. 先在另一个端口或另一台机器上试运行，确认分流结果后再切换。

::: tip 先检查再启动
自己写的配置可以先用 `atomdns check` 检查：

```bash
atomdns check -d /cus/atomdns -c config_custom.yaml
```

不支持的插件、参数和写法会逐条列出，指出所在文件和字段。
:::

## 与 MosDNS 的主要差异

| 项目 | AtomDNS |
| --- | --- |
| 配置中的 `log` 段 | 必填 |
| 不认识或不支持的参数 | 启动时报错并指明位置，不会被静默忽略 |
| 相对路径 | 一律相对配置目录（`-d`）解析 |
| `switch1`–`switch17` | 改为具名的 [`feature_flag`](/plugins/feature_flag) |
| 学习名单（`domain_output` 的 `target_mapper` 等） | 改为 [`route_learner`](/plugins/route_learner) |
| 上游协议 | 支持 UDP / TCP / DoT / DoH（含 HTTP/3）/ DoQ |
| `/log` 兼容页面 | 不提供，WebUI 只在 `/` |

各插件页底部的「与 MosDNS 的差异」一节有更细的说明。
