# 自定义 WebUI

程序本身不内嵌界面，界面是配置目录下的静态文件：

| 目录 | 访问地址 |
| --- | --- |
| `ui/main/` | `/` |
| `ui/<名字>/` | `/<名字>/` |

所以可以同时放多套界面，例如把旧版本放在 `ui/old/` 作对比，或放一个自己写的页面。

## 安装

```bash
mkdir -p /cus/atomdns/ui/main
tar -xzf atom-webui.tar.gz -C /cus/atomdns/ui/main
```

安装或更换后**重启一次**，程序在启动时登记各个目录。替换已挂载目录里的文件则立即生效。

## 规则

- 目录名不能是保留名：`root`、`log`、`log1`、`legacy`、`blog`、`assets`、`debug`、`metrics`、`plugins`、`api`、`chunks`。
- 带 `ui-manifest.json` 的目录被当作 AtomDNS 界面包，程序会检查它与当前版本是否匹配，不匹配就不挂载，并在「系统管理」显示原因。
- 不带 `ui-manifest.json` 的目录按普通静态页面提供。
- 在线更新只更新 `ui/main/`，其它目录不动。

## 自己构建

界面源码在仓库的 `webui/` 目录（Vue）：

```bash
cd webui
npm ci
npm run build:package    # 生成 release/atom-webui.tar.gz
```
