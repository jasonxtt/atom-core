# 发版（atom）

atomdns 不再单独发布，也没有在线更新：它和补丁版 sing-box、WebUI 一起打进 atom 的配套包，由 atom 的安装器安装和升级
（设计见 atom 仓库的 `docs/design.md` 第 9.2 节，脚本在 `installer/`）。本文是操作说明，不会自动执行任何发布。

## 构建各部分

1. **atomdns**（Linux x86_64 机器上，Rust 编译放在构建机，不在 Mac 上）：

   ```bash
   BUILD_VERSION=v0.6.4 OUTPUT=release/atomdns scripts/build-rust-native.sh
   ```

   `BUILD_VERSION` 决定 `atomdns version` 的输出；不给就用 `git describe`。
2. **WebUI**：`(cd webui && npm ci && npm run build:package)`，产物 `release/atom-webui.tar.gz`（顶层就是 `<配置根>/ui/main/` 的文件）。
3. **sing-box**（atom 仓库的 `sing-box/` 分支 `atom/fakeip-outbound`，Go 交叉编译）：

   ```bash
   cd sing-box
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
     -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
     -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4-atom $(cat release/LDFLAGS)" -o ../release/sing-box ./cmd/sing-box
   ```

## 组装配套包

```bash
installer/scripts/build-package.sh --version 0.1.0 \
  --atomdns <atomdns> --sing-box <sing-box> --webui <atom-webui.tar.gz> --atomdns-version "$(<atomdns> version)"
```

输出 `installer/dist/atom-0.1.0-linux-amd64.tar.gz`、固定了版本和 sha256 的 `install.sh`、`SHA256SUMS`。
发布（GitHub Release、推送、通知）需要用户明确批准，脚本不做。

## 配置

`config/` 随包发布，用户不改。安装器升级时只覆盖 `config_custom.yaml`、`sub_config/` 和 `rule/atom_catalog.json`，
其余文件（`webinfo/`、每日更新下载的规则和名单、缓存）保留。
