# `agy-switch-cli` 完整使用、配置与部署手册

> 返回首页：[README.md](../README.md) ｜ 技术架构与验收台账：[architecture-and-verification.md](architecture-and-verification.md)

本手册面向所有用户（包括刚开始接触 Linux 命令行的朋友），将每一个核心概念、每一条命令和每一个参数选项逐一拆解说明，不省略中间步骤。手册中的所有示例均使用虚构占位邮箱（如 `alice@example.com`），方便直接对照参考。

---

## 目录

1. [安装指南与架构选型（按步操作）](#1-安装指南与架构选型按步操作)
   - [1.1 按 CPU 架构选择预编译压缩包（全功能合一纯静态单文件）](#11-按-cpu-架构选择预编译压缩包全功能合一纯静态单文件)
   - [1.2 下载、校验与安装步骤](#12-下载校验与安装步骤)
   - [1.3 Arch Linux / EndeavourOS 等 Arch 系发行版（AUR 安装）](#13-arch-linux--endeavouros-等-arch-系发行版aur-安装)
   - [1.4 从源码自行编译（可选，要求 Rust 1.89 及以上）](#14-从源码自行编译可选要求-rust-189-及以上)
2. [上手前必读：四个核心概念](#2-上手前必读四个核心概念)
3. [全局选项与环境变量](#3-全局选项与环境变量)
4. [全量命令与参数详解](#4-全量命令与参数详解)
   - [4.1 环境状态只读巡检：`status`](#41-环境状态只读巡检status)
   - [4.2 登录与 OAuth 授权管理：`auth`（默认免配置粘贴登录）](#42-登录与-oauth-授权管理auth默认免配置粘贴登录)
   - [4.3 账号池管理、批量导入与排序：`accounts`](#43-账号池管理批量导入与排序accounts)
   - [4.4 查看当前身份/可用模型与手动切号：`current` / `switch`](#44-查看当前身份可用模型与手动切号current--switch)
   - [4.5 配额查询与流式联网刷新：`quota` / `refresh`](#45-配额查询与流式联网刷新quota--refresh)
   - [4.6 自动切号规则配置：`policy`（设定规则）](#46-自动切号规则配置policy设定规则)
   - [4.7 指定凭据与后端启动包装器：`run`](#47-指定凭据与后端启动包装器run)
   - [4.8 后台自动切号守护进程：`daemon`（定时巡检与服务安装）](#48-后台自动切号守护进程daemon定时巡检与服务安装)
   - [4.9 SSH 交互式终端看板：`tui`（全键盘可视化操作）](#49-ssh-交互式终端看板tui全键盘可视化操作)
   - [4.10 本地 Token 用量统计与请求明细：`stats summary` / `stats list`](#410-本地-token-用量统计与请求明细stats-summary--stats-list)
5. [标准退出码（`0..=8`）与 `--json` 脚本集成契约](#5-标准退出码08与---json-脚本集成契约)
6. [可选配置文件（`config.json` 代理、后端、通知、外部槽位别名与自定义 OAuth 客户端）](#6-可选配置文件configjson-代理后端通知外部槽位别名与自定义-oauth-客户端)
7. [后台常驻运行指南（`systemd --user` 与无 `systemd` 的 Docker 容器环境）](#7-后台常驻运行指南systemd---user-与无-systemd-的-docker-容器环境)
8. [常见问题解答（FAQ）](#8-常见问题解答faq)
9. [完整卸载与本地遗留文件清理清单](#9-完整卸载与本地遗留文件清理清单)

---

## 1. 安装指南与架构选型（按步操作）

### 1.1 按 CPU 架构选择预编译压缩包（全功能合一纯静态单文件）

在 GitHub Releases 发布页中，每个 CPU 架构均统一提供**单一完整的全功能预编译压缩包**（无需区分服务器版与桌面版，可在终端输入 `uname -m` 确认当前机器架构）：

| 预编译压缩包（按架构区分） | 适用硬件与系统环境 | 内置能力与体积说明 |
| :--- | :--- | :--- |
| **`agy-switch-cli-<版本>-x86_64-unknown-linux-musl.tar.gz`** | 常见 Intel / AMD 64 位云服务器、PC、WSL2 与 Docker 容器（`uname -m` 输出 `x86_64`） | **100% 纯静态单文件 ELF**（约 `14.4 MiB`，压缩包约 `6.1 MiB`，零外部 `.so` 动态库依赖），完整内置核心 CLI、`stats` 本地统计、`tui` 交互看板与纯 Rust D-Bus 系统钥匙串自适应后端 |
| **`agy-switch-cli-<版本>-aarch64-unknown-linux-musl.tar.gz`** | ARM64 云服务器、树莓派与 ARM 容器（`uname -m` 输出 `aarch64`） | **100% 纯静态单文件 ELF**（约 `11.8 MiB`，压缩包约 `5.7 MiB`，零外部 `.so` 动态库依赖），内置与 `x86_64` 完全一致的全量功能 |

- **同一份二进制自动适配无头服务器与图形桌面**：
  - 在远程 SSH 服务器、Docker 容器、无桌面 WSL2 中运行时，默认的 `--backend auto` 会自动使用本地文件后端（`file`），零额外配置。
  - 在开启了 GNOME Keyring 或 KDE Wallet 的 Linux 图形桌面上运行时，默认的 `--backend auto` 会自动检测到本机活跃钥匙串并启用事务性双写模式（`dual`），同步更新系统钥匙串与本地凭据文件，切号后直接运行 `agy` 即刻生效。

### 1.2 下载、校验与安装步骤

可直接在终端中使用 `curl` 按当前机器架构（`uname -m` 自动输出 `x86_64` 或 `aarch64`）拉取压缩包及校验文件并完成安装（新版本发布时请将 `VER` 替换为实际版本号；亦可在浏览器前往 [GitHub Releases](https://github.com/MatrixC7/agy-switch-cli/releases) 手动下载）：

```bash
# 第 1 步：在终端直接下载对应架构的压缩包与 SHA-256 校验文件（需要代理时可先 export https_proxy=... 或给 curl 加 -x）
VER=v1.2.6
ARCH="$(uname -m)"   # x86_64 或 aarch64
curl -fLO "https://github.com/MatrixC7/agy-switch-cli/releases/download/${VER}/agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz"
curl -fLO "https://github.com/MatrixC7/agy-switch-cli/releases/download/${VER}/agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz.sha256"
# 若系统未安装 curl，也可改用 wget：
# wget "https://github.com/MatrixC7/agy-switch-cli/releases/download/${VER}/agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz"
# wget "https://github.com/MatrixC7/agy-switch-cli/releases/download/${VER}/agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz.sha256"

# 第 2 步：校验压缩包完整性（输出显示成功 / OK 即可）
sha256sum -c "agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz.sha256"

# 第 3 步：解压压缩包
tar -xzf "agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz"

# 第 4 步：安装到当前用户的可执行目录 ~/.local/bin（无需 sudo 权限）
mkdir -p ~/.local/bin
install -m 0755 "agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl/agy-switch-cli" ~/.local/bin/agy-switch-cli
```

> **提示：如果输入 `agy-switch-cli --version` 提示 `command not found（找不到命令）` 怎么办？**  
> 这说明 `~/.local/bin` 尚未加入终端的 `PATH` 搜索路径。执行以下两行即可（若你使用的是 `zsh`，请把 `.bashrc` 替换为 `.zshrc`）：
> ```bash
> echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
> source ~/.bashrc
> ```
> 随后再次输入 `agy-switch-cli --version`，看到版本号即表示安装完成。

### 1.3 Arch Linux / EndeavourOS 等 Arch 系发行版（AUR 安装）

如果你使用的是 Arch Linux、EndeavourOS、Manjaro 或其他基于 Arch 的发行版，可以直接通过常见的 AUR 助手一键安装预编译二进制包 `agy-switch-cli-bin`：

```bash
yay -S agy-switch-cli-bin
# 或使用 paru：
# paru -S agy-switch-cli-bin
```

- **免本机编译且支持双架构**：`agy-switch-cli-bin` 直接打包本仓库 GitHub Releases 发布的纯静态全功能 `musl` 压缩包，同时支持 `x86_64` 与 `aarch64` 架构，无需本机安装 Rust 工具链。
- **安装位置与系统文件**：
  - 可执行文件安装至 `/usr/bin/agy-switch-cli`（位于系统默认 `PATH` 中，安装后可直接运行，无需手动修改 `.bashrc` / `.zshrc`）。
  - 开源许可证与第三方组件声明安装至 `/usr/share/licenses/agy-switch-cli-bin/`。
  - 溯源说明与构建清单安装至 `/usr/share/doc/agy-switch-cli-bin/`。
- **后续更新**：新版本发布后，日常随系统更新命令（例如 `yay -Syu` 或 `paru -Syu`）即可自动升级。

### 1.4 从源码自行编译（可选，要求 Rust 1.89 及以上）

```bash
cargo build --release --locked                                       # 默认全功能构建（含核心 CLI + stats + tui + D-Bus 钥匙串后端）
cargo build --release --locked --target x86_64-unknown-linux-musl    # 纯静态 musl 全功能构建
```

---

## 2. 上手前必读：四个核心概念

- **如何在命令中指定账号（`<ID|EMAIL>`）？**
  - 为防止排序变动或账号增删导致命令行序号漂移误触其他账号，所有命令行子命令统一采用与账号终身绑定的精确标识：
    - **直接输入邮箱**（如 `alice@example.com`，不区分大小写，直观且安全）。
    - **输入内部账号 ID**（如 `acc-0001...`，可通过 `accounts list` 查看，用于区分极少数同邮箱重复记录）。
  - 如果你不想在命令行手动输入邮箱，可以直接运行 `agy-switch-cli tui` 打开可视化交互看板，通过上下方向键高亮选中账号后一键完成切号、调序、启停与候选池配置。
- **官方 `agy` 把当前登录账号保存在哪里？（桌面钥匙串 D-Bus 与本地文件的双层优先级机制）**
  - 理解这一机制能彻底解开“为什么在图形桌面上改了文件却没切号”以及“`~/.gemini` 下好几个文件分别是什么”的疑惑。官方 `agy` CLI（以及新版桌面端 Antigravity App）内部采用同一套双层凭据存储逻辑（`composite_token_storage`），读取当前登录账号时按以下固定顺序查找：
  - **第一优先级：Linux 桌面系统钥匙串（D-Bus Secret Service，即 GNOME Keyring 或 KDE Wallet）**
    - 在带有图形界面的 Linux 桌面上，终端环境中存在活跃的本机 Unix D-Bus 会话套接字（`DBUS_SESSION_BUS_ADDRESS` 或 `$XDG_RUNTIME_DIR/bus`）。
    - 官方 `agy` 与桌面端 Antigravity App 都会优先通过 D-Bus 访问系统钥匙串（加密存储在 `~/.local/share/keyrings/` 或 `~/.local/share/kwalletd/` 中），读写标签为 `Password for 'antigravity' on 'gemini'`（属性 `service="gemini", username="antigravity"`）的同一条记录。
    - **核心表现**：在图形桌面上，**Antigravity App 与 `agy` CLI 完全互通共用这同一个钥匙串条目**；只要系统钥匙串处于解锁状态且存有该条目，`agy` 启动时会**直接采用钥匙串里的账号，完全忽略磁盘上的备份文件**。
  - **第二优先级（回退位置）：磁盘凭据槽位文件 `~/.gemini/antigravity-cli/antigravity-oauth-token`（权限 `0600`）**
    - 只有在**没有桌面钥匙串环境**（如远程 SSH 服务器、Docker 容器、无桌面 WSL2）、系统钥匙串中尚未写入该条目，或者显式指定 `file` 后端并通过可选的 `agy-switch-cli --backend file run -- agy` 自动为子进程屏蔽桌面 D-Bus 总线的情况下，`agy` 才会回退去读写磁盘上的 `~/.gemini/antigravity-cli/antigravity-oauth-token`（两处保存的 JSON 内容结构完全相同）。
  - **附：`~/.gemini` 目录下常见凭据文件的区别与清理说明**
    - `~/.gemini/antigravity-cli/antigravity-oauth-token`：官方 `agy` CLI 的标准磁盘凭据槽位文件。
    - `~/.gemini/jetski-standalone-oauth-token`：桌面端 Antigravity App（及 VS Code 中的 Antigravity 扩展插件）在无系统钥匙串环境下的回退凭据文件。
    - `~/.gemini/oauth_creds.json`：**并非**官方 Antigravity App 或 `agy` CLI 使用的凭据文件（在两者的官方二进制中均不存在该文件名）。它通常由 Google Gemini CLI（`gemini` 命令）或其他复用了同源 OAuth `client_id` 的第三方代理/脚本工具生成；保留或删除它均不影响官方 `agy` 当前登录身份。
    - **在有桌面钥匙串的系统上能否删除磁盘凭据文件？** 只要 GNOME Keyring / KDE Wallet 中已存有当前登录记录，手动删掉磁盘上残留的旧 `oauth_creds.json` 或 `antigravity-oauth-token` **文件**不会引起任何报错，官方 App 与 `agy` 会直接按第一优先级从钥匙串正常登录。
  - **切号生效时机**：无论更新的是文件还是钥匙串，切号均对**切换完成之后新启动的 `agy` 命令**（或重启后的桌面端 App）立即生效，**绝不会中途篡改或强行打断正在运行中的 `agy` 会话**。
- **配额池（`Gemini` vs `Claude / GPT`）与双窗口（`Weekly` 周额度 vs `5h` 五小时额度）**
  - Google Antigravity 的额度按**配额池**共享计算：
    - **`Gemini` 池**：常规 Gemini 系列模型共用。
    - **`Claude / GPT` 池**：Claude Sonnet / Opus 与 GPT-OSS 等模型共用。
    - **`Argon` 池**：仅部分灰度测试账号才会被下发。普通商业订阅账号没有该池，`tui` 和 `quota` 会默认将其隐藏，属于正常现象。
  - 每个配额池同时受 **`Weekly`（7 天滚动周总额度）** 和 **`5h`（5 小时短期防刷窗口）** 限制，任意一个窗口降为 `0%` 都会触发限流，因此工具会同时展示这两个窗口。
- **配额缓存保鲜期（`stale`）与 `daemon` 实时刷新机制**
  - 为避免高频请求触发 Google 服务端风控，通用本地配额缓存（`quota` 只读查看与闲置候选账号缓存）的默认保鲜期为 **`1 小时（3600 秒）`**：
    - 距离上次刷新 **1 小时以内**（且未跨过重置时间点），只读查看 `agy-switch-cli quota` 显示为 `known`（新鲜有效）。
    - 超过 **1 小时**后，缓存标为 `stale`。此时手动运行 `agy-switch-cli quota` **依然会正常展示上次缓存的进度表**，并在状态行温和提示可加 `--refresh`（`agy-switch-cli quota --refresh`）联网更新。
  - **后台守护进程 `daemon` 对当前活跃账号采用实时刷新机制**：
    - 常驻 `daemon`（默认每 `180` 秒巡检一次）在每次定时唤醒且不处于冷却期、失败退避或不可用阻断态（`disabled` / `verify-blocked` / `quota_forbidden`）时，都会直接对当前正在消耗的活跃账号执行实时联网配额复核（避免慢轮落盘或负抖动跳过刷新；仅在极短低水位宽限窗口内跳过重复查询，且 `Wait` 模式挂起计划的锁内复验保鲜期随巡检间隔缩放到 `80%`，范围 `1..=3600` 秒），而闲置备用候选号继续沿用 `3600s` 缓存避免高频轰炸。
    - 手动或通过 `cron` 执行 `daemon --once` 时，会对非阻断态的当前活跃账号直接执行一次实时联网配额刷新（仅当本地 `<= 15` 秒前刚确认额度已低于保留线且未过重置点时跳过重复查询）；若此次联网请求、必要摘要获取或源刷新预算超时失败，则严格故障关闭进入 `hold`（`source_refresh_failed: ...`），绝不回退旧缓存误判。

---

## 3. 全局选项与环境变量

以下全局选项可加在任意子命令之前或之后（日常使用保持默认即可，无需填写）：

| 全局选项 | 对应环境变量 | 默认行为与通俗说明 |
| :--- | :--- | :--- |
| `--data-dir <目录路径>` | `AGY_SWITCH_CLI_DATA_DIR` | 指定账号库存储目录。默认位于 `~/.local/share/agy-switch-cli`（目录权限自动设为 `0700`）。 |
| `--proxy <代理地址\|direct>` | `AGY_SWITCH_CLI_PROXY` | 指定访问 Google 的网络代理，支持 `socks5h://127.0.0.1:1080`、`socks://127.0.0.1:1080`、`http://127.0.0.1:7890`、省略协议头的 `127.0.0.1:7890`，或填 `direct` 强制直连。不填时优先读取 `config.json`，其次自动读取并规范化终端环境变量 `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`（注意 Linux 图形界面的“系统代理”不会自动注入终端，若不想每次传 `--proxy`，需在终端导出代理环境变量或写入 `config.json`）。 |
| `--backend <auto\|dual\|file\|keyring>` | `AGY_SWITCH_CLI_BACKEND` | 指定凭据槽位后端模式（严格匹配这 4 个小写字面值，区分大小写且不接受空字符串或外围空白；亦可在 `config.json` 的 `"backend"` 字段持久化），默认为 **`auto`**。四种模式的具体区别见下表。 |
| `--no-remote-version` | — | 关闭联网命令每 24 小时一次的客户端最新版本号缓存查询。 |
| `--json` | — | 输出机器可读的标准 JSON 格式（供自动化脚本解析使用；全屏交互看板 `tui` 与实时监控 `stats ... --watch` 均与 `--json` 互斥，`run` 包装器在启动准备无误后直接透传 `agy` 子进程的标准输入输出）。 |

#### `--backend` 四种凭据后端模式详解

- **`auto`（默认值，日常无需手改）**：
  - 在无桌面钥匙串的 SSH 服务器、Docker 容器或 WSL2 中，自动使用 `file` 模式。
  - 在存在本机活跃 D-Bus 系统钥匙串（GNOME Keyring / KDE Wallet）的 Linux 图形桌面上，自动使用 `dual` 模式。
- **`dual`（显式双写同步）**：
  - 强制要求同时读写系统钥匙串与本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件，并在切号时执行双端原子事务与异常回滚（若当前环境没有可用钥匙串则明确报错退出）。
- **`file`（纯本地文件模式）**：
  - 仅读写本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件，全程不访问或修改系统钥匙串。当通过 `--backend file`、`AGY_SWITCH_CLI_BACKEND=file` 或 `config.json` 中的 `"backend": "file"` **显式指定**为 `file` 模式且宿主环境中存在桌面 D-Bus 会话总线时，可选包装器 `run` 会自动为拉起的 `agy` 子进程注入 `DBUS_SESSION_BUS_ADDRESS=unix:path=/dev/null`，从而将终端 CLI 登录态与图形桌面 App 钥匙串登录态隔离（而无钥匙串服务器上的默认 `auto` 回退不会修改子进程 D-Bus 环境变量，不影响子进程内的 `systemctl --user` 等操作）。
- **`keyring`（纯系统钥匙串模式，零本地文件读写）**：
  - 仅读写系统 D-Bus Secret Service 钥匙串，绝不创建、修改、读取或要求本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件存在（适合已在图形桌面完全使用钥匙串管理登录态、希望保持磁盘上不留明文凭据文件的用户）。

---

## 4. 全量命令与参数详解

### 4.1 环境状态只读巡检：`status`

`status` 用于以纯只读方式（不修改本地账号库、凭据槽位与系统钥匙串，不发起任何网络请求；仅在发现本地官方 `agy` 时创建并随即清理隔离的临时探测目录）对本机运行环境、账号存储库、切号事务日志、生效凭据槽位、后台守护进程运行状态以及本机官方 `agy` 可执行文件做一次快速健康检查：

```bash
agy-switch-cli status          # 纯只读巡检本地环境、存储库与官方 agy 版本
agy-switch-cli status --json   # 输出结构化 JSON 巡检报告
```

标准输出示例：
```text
agy-switch-cli status (v1.2.6)
  Backend:           dual
  Store status:      OK
  Journal status:    Clean
  Slot initialized:  true
  Daemon state:      not running (no service; ready for daemon / --once)
  Antigravity CLI:   /usr/bin/agy v1.5.12
  Antigravity App:   /usr/bin/antigravity v2.33.0
```

#### 输出字段逐行详解

- **标题行 `agy-switch-cli status (v...)`**：显示当前正在运行的 `agy-switch-cli` 自身版本号。
- **`Backend`（当前生效凭据后端）**：综合命令行 `--backend`、环境变量 `AGY_SWITCH_CLI_BACKEND`、`config.json` 与本机环境探测后实际采用的后端模式：
  - `file`：仅读写本地磁盘凭据文件 `~/.gemini/antigravity-cli/antigravity-oauth-token`（无桌面钥匙串的 SSH 服务器、Docker 容器或 WSL2 下默认采用此模式）。
  - `dual`：同时对桌面系统钥匙串（GNOME Keyring / KDE Wallet）与本地凭据文件执行事务性双写（带有活跃钥匙串的 Linux 图形桌面默认采用此模式）。
  - `keyring`：仅读写系统钥匙串，完全不创建或读写本地凭据文件。
- **`Store status`（本地账号库健康度）**：校验数据目录（默认 `~/.local/share/agy-switch-cli`）下的账号索引 `index.json`、各账号文件 `accounts/*.json`、自动切号策略 `policy.json`、可选配置文件 `config.json`、授权暂存记录及历史令牌谱系归档是否完整合法：
  - 全部校验通过时显示 `OK`。
  - 若存在文件损坏、权限异常，或 `policy.json` 中引用了已不存在的候选账号 ID，命令会直接输出具体报错原因并返回退出码 `1`。
- **`Journal status`（切号崩溃恢复日志状态）**：反映内部预写事务日志 `state/switch_journal.json` 的当前状态：
  - `Clean`：常规健康状态，表示没有任何中断残留的切号事务。
  - `AbortedUncommitted`：上次切号在修改外部凭据槽位之前就已经提前退出，外部凭据完好无损；后续你正常执行任意写命令（如 `switch`、`policy set`、`accounts` 等）时会自动清理该记录。
  - `CommittedIndexPending` 或 `RecoveryIncomplete`：上次切号或清槽留下未完成、尚未确认持久化或无法核实的事务（例如中途中断、双写仅更新一侧副本、父目录持久化同步失败，或事务日志元数据损坏/矛盾）。由于 `status` 严格只读不会擅自改写状态，此时会如实报告该状态并返回退出码 `7`；后续执行交互式写命令（如 `agy-switch-cli switch <ID|EMAIL>`、`policy set` 等）会先在持有锁与外部凭据防误覆盖（CAS）保护的前提下尝试对账，只有在能够安全核实事务状态并完成耐久性检查后才会清理日志。若重放后仍返回退出码 `7`，请保留日志并按诊断信息排除底层存储、权限或后端问题后再重试，不要手动删除 `state/switch_journal.json`。
- **`Slot initialized`（官方凭据槽位是否已初始化）**：
  - `true`：当前生效后端中已经存有 `agy` 登录凭据。
  - `false`：全新环境尚未登录或尚未向槽位写入过凭据（属于正常初始状态；若槽位文件存在但 JSON 内容损坏，`status` 会报错并返回退出码 `1`）。
- **`Daemon state`（后台守护进程运行状态、服务托管与健康度）**：在严格零写入的前提下同时核查 `state/daemon_state.json` 合法性（若文件损坏仍返回退出码 `1`）、当前数据目录 `<data_dir>/locks/daemon.lock` 是否由活跃进程持有（绝不创建锁文件）以及当前数据目录是否安装了用户级 `systemd` 服务（严格正向校验磁盘单元中的 `AGY_SWITCH_CLI_DATA_DIR=` 与管理器返回的 `FragmentPath` 一致，且仅以当前目录锁作为本目录运行态依据），清晰区分四种运行状态（`--json` 中通过 `daemon_runtime` 对象输出 `mode`、`running`、`pid`、`systemd_unit_installed`、`systemd_active_state`、`systemd_unit_file_state`、`cooldown_active`、`cooldown_remaining_secs`，同时保留既有的 `daemon_state_ok` 与 `daemon_paused_on_failure`）：
  - `not running (no service; ready for daemon / --once)`（`mode: "not_running"`）：未安装指向当前数据目录的 `systemd --user` 服务且当前没有运行中的 `daemon` 进程，可随时直接运行 `daemon`、`daemon --install` 或单次 `daemon --once`。
  - `running (systemd service, pid=...)`（`mode: "systemd_service"`）：已安装指向当前数据目录的 `systemd --user` 服务，且该服务的活跃 `MainPID` 正持有当前数据目录的 `daemon.lock`。
  - `running (manual/foreground, pid=...)`（`mode: "manual"`）：当前存在通过终端前台、`tmux`、`nohup` 或 `supervisord` 等方式手动运行的 `daemon` 进程持有当前数据目录锁（若同时装有 `systemd` 服务单元会顺带标注 `; systemd service inactive` 等管理器观察态）。
  - `stopped (systemd service inactive|failed; ready for --once)`（`mode: "systemd_stopped"`）：已安装指向当前数据目录的 `systemd --user` 服务单元，但当前数据目录未持有活跃守护进程锁（服务处于停止、失败、管理器不可达，或单元已改指当前目录但先前进程尚未重启；后者会标注 `stopped (systemd service active, no lock held here; ready for --once)` 且 `running: false`），此时可直接执行 `daemon --once` 或按需启动/重启服务。
  - **按需附加后缀**：当 `state/daemon_state.json` 中存在尚未到期的切号冷却时间时，在末尾附加 `· cooldown <剩余时长>`；当连续 **3 次**提交切号失败触发自动熔断暂停（`paused_on_failure=true`）时，附加 `· PAUSED: <N> consecutive failures`（排查修复底层问题后，手动执行一次 `agy-switch-cli switch <ID|EMAIL>` 或 `agy-switch-cli policy set ...` 即可自动解除熔断）。
- **`Antigravity CLI`（本机官方 `agy` 可执行文件探测）**：在独立进程组（`process_group(0)`）与隔离的空临时目录环境中（清空并覆盖 `HOME`、`XDG_*`、`TMPDIR`、`DBUS_SESSION_BUS_ADDRESS` 与 `NO_PROXY=*`，限时 3 秒，超时或退出时向整个子进程组发送 `SIGKILL` 并回收直接子进程）调用本机 `agy --version` 获取路径与版本号（面向本机可信 `agy` 可执行文件的环境变量、临时目录与进程组隔离，不构成操作系统内核级容器命名空间沙盒）：
  - 已正常安装时输出实际路径与版本号，如 `/usr/bin/agy v1.5.12`。
  - 当前 `PATH`（及 `AGY_SWITCH_CLI_AGY_BIN`）中尚未安装官方 `agy` 时显示 `not found in PATH`（不视为报错，退出码仍为 `0`）。
  - 若找到了 `agy` 文件但无法执行、返回非零退出码或超过 3 秒卡死，则输出具体错误并返回退出码 `8`。
- **`Antigravity App`（按需显示，已安装桌面端 Antigravity App 版本只读探测）**：
  - 仅通过纯只读有界文件解析检测本机桌面端安装目录中的 `resources/app.asar`（读取内部 `package.json` / `product.json`）或解包目录中的 `resources/app/{product,package}.json`（支持 `PATH` 中的 `antigravity`、`/opt/Antigravity`、`/usr/share/antigravity` 等常见 Linux 路径及可选环境变量 `AGY_SWITCH_CLI_ANTIGRAVITY_APP_DIR`），**全程不启动任何 Electron/GUI 子进程**。
  - 在检测到桌面端 App 时另起一行输出路径与版本号（如 `/usr/bin/antigravity v2.33.0`）；在无头服务器、Docker 容器或未安装桌面端的机器上自动整行隐藏（`--json` 中通过 `antigravity_app_probe.found: false` 如实呈现），绝不因可选桌面端缺失或不可读而导致 `status` 报错退出。
- **按需出现的底部提示行**（平时环境无异常时不显示）：
  - `Config warning`：`config.json` 文件权限过宽（如 `0644`，建议改为 `chmod 600`）或包含被跳过的无效自定义客户端条目时的温和提示。
  - `Security warning`：`state/pending_auth/*.json` 或 `state/auth_sequence.json` 含有组或其他用户权限位时的安全收紧提示。
  - `D-Bus note`：在存在本机桌面 D-Bus 会话套接字的环境中使用纯 `file` 后端时的说明提示，提醒桌面端钥匙串优先级规则。

---

### 4.2 登录与 OAuth 授权管理：`auth`（默认免配置粘贴登录）

#### 方式一（默认模式，免配置）：手动粘贴回调网址登录

无需本机安装浏览器，也无需配置 SSH 端口转发，直接运行：

```bash
agy-switch-cli auth login --label "primary"
```

按以下三步操作即可完成登录：
1. 终端会打印出一串以 `https://accounts.google.com/...` 开头的授权网址，并等待你粘贴回调结果；
2. 将该网址复制到**任意一台电脑的浏览器**中打开，登录 Google 账号并点击允许授权；
3. 点击允许后，浏览器会跳转到一个无法打开的本地页面（提示“无法访问此网站 / 拒绝连接 `127.0.0.1`”）。这是正常现象，只需把浏览器顶部地址栏中那整串以 `http://127.0.0.1:...` 开头的完整网址复制下来，粘贴回服务器终端并按回车，即可完成登录。

#### 方式二（可选 `--ssh` 监听模式）：适合 SSH 端口转发或本地图形桌面自动回调

如果你希望浏览器点完允许后自动完成回调，可以加上 **`--ssh`** 开启本地回环端口监听：

```bash
# 场景 A：在本地 Linux 桌面终端上使用，加 --ssh --open-browser 自动打开浏览器并在授权后自动完成：
agy-switch-cli auth login --ssh --open-browser --label "desktop"

# 场景 B：通过 SSH 连接远程服务器，先在本地电脑用 `ssh -L 54545:127.0.0.1:54545 user@server` 连接，再在服务器运行：
agy-switch-cli auth login --ssh --port 54545 --label "server"
```

#### `auth` 全部子命令汇总

```bash
# 登录新账号（默认手动粘贴模式；加 --ssh 切换为本地端口监听回调模式）
agy-switch-cli auth login [--ssh] [--port <端口>] [--open-browser] [--label <备注>] [--client <客户端KEY>]

# 已有账号令牌失效（invalid_grant）或权限不足时，原地重新登录更新（支持填邮箱或 ID，保留原有排序和策略设置）
agy-switch-cli auth reauthorize <ID|EMAIL> [--ssh] [--port <端口>] [--open-browser] [--client <客户端KEY>]

# 网络波动时的“防丢号暂存箱”管理：
agy-switch-cli auth pending            # 查看是否有已签发令牌、但因查邮箱超时而暂存的记录（显示本地时区创建时间 YYYY-MM-DD HH:MM）
agy-switch-cli auth pending --resume   # 网络恢复后，继续完成暂存记录的账号绑定（无需重新去浏览器登录）
agy-switch-cli auth pending --purge    # 清空所有暂存记录

# 查看已注册的 OAuth 客户端配置列表（纯只读，零联网、零写文件）
agy-switch-cli auth clients
```

#### `auth clients` 是什么？普通用户需要配置吗？

- **用通俗的话理解 OAuth 客户端（`client_id` + `client_secret`）**：
  - 当一款软件请求登录 Google 账号时，Google 除了验证“你是哪个用户（邮箱）”，还要验证“是哪款软件在请求登录”。这组代表软件身份的编号与密钥就叫 **OAuth 2.0 客户端**（并非你的个人账号密码）。
- **为什么普通用户完全不需要修改任何客户端配置？**
  - 本工具已经内置了与官方 `agy` 完全一致的默认客户端 `antigravity_enterprise`，并默认设为启用状态（前面带 `*` 号）。日常直接执行 `auth login` 或 `accounts add --from-local` 即可开箱使用，无需创建 `config.json`。
- **`auth clients` 的输出含义与使用场景**：
  - 默认运行 `agy-switch-cli auth clients` 会输出：
    ```text
    * antigravity_enterprise  Antigravity Enterprise (builtin)
    ```
    - 开头的 `*` 表示当前未传 `--client` 时默认使用的客户端；
    - `antigravity_enterprise` 是客户端短名称（`key`），`Antigravity Enterprise` 是显示备注名；
    - `(builtin)` 表示程序内置客户端，`(custom)` 表示你在 `config.json` 或环境变量中自行注册的自定义客户端。
  - **什么情况下才会用到它？** Google OAuth 2.0 有一条严格规则：**由哪个 `client_id` 签发的 `refresh_token`，后续刷新续期时就必须继续配对同一个 `client_id` 和 `client_secret`**。如果你手头有通过自建 Google Cloud 项目或其他第三方工具签发的 Token，在按第 `6.3` 节写入 `config.json` 后，就可以运行 `auth clients` 核对自定义客户端是否已成功加载、有没有字段缺失警告。

---

### 4.3 账号池管理、批量导入与排序：`accounts`

#### （1）查看账号列表与调整顺序：`accounts list`

`accounts list` 统一集成了**账号详情展示**与**顺序调整**功能：

```bash
# 1. 直接查看所有账号（纯只读，显示序号、选中星号 *、邮箱、[套餐等级]、备注、状态与内部 ID）：
agy-switch-cli accounts list
# 输出示例：
#  1. * alice@example.com    [Google AI Pro]  (primary)            (acc-0001...)
#  2.   bob@example.com      [Google AI Pro]  (backup)             (acc-0002...)
#  3.   charlie@example.com  [Free Tier]      [disabled]           (acc-0003...)

# 2. 将某一个账号单独移到指定目标槽位（--move 填邮箱或 ID，--to 填目标位置编号 1..N）：
agy-switch-cli accounts list --move charlie@example.com --to 1
agy-switch-cli accounts list --move bob@example.com --to 1

# 3. 一次性按新顺序重排全部账号（须包含每一个已存账号的邮箱或 ID）：
agy-switch-cli accounts list --order bob@example.com charlie@example.com alice@example.com
```

> **提示**：你也可以运行 `agy-switch-cli tui` 进入可视化看板，按 **`[`（上移）** 或 **`]`（下移）** 实时调整顺序。

#### （2）导入本机已登录账号或通过 Refresh Token 添加账号：`accounts add`

> **安全保护说明**：为防止机密 Token 留在终端历史记录（`.bash_history`）或被系统进程表泄露，工具禁止将 Token 直接作为命令行位置参数传入，统一使用清晰一致的 `--from-local`、`--from-file`、`--from-stdin` 或交互式无回显粘贴：

**场景 A：当前设备已登录官方 `agy`（或桌面端与 `agy` 在系统钥匙串中共用条目），一键抓入账号库（`--from-local`）**
```bash
agy-switch-cli accounts add --from-local --label "local"
# 也可指定独立的外部目标应用数据目录（例如第三方 ACP 宿主隔离的 antigravity-acp 目录）：
agy-switch-cli accounts add --from-local --target t3 --label "t3-local"
agy-switch-cli accounts add --from-local --target-dir ~/.t3/userdata/providers/antigravity/ac0a3dfd6dddb20962cecff6ee5fe65e19d3923be20e52c5ab52ff877f7e4c32/antigravity-acp --label "t3-local"
```
- **按当前生效的 `--backend` 模式自动选择读取源**：
  - 在默认的 **`auto`**（桌面有钥匙串时）或 **`dual`** 模式下：程序优先读取系统钥匙串（`Password for 'antigravity' on 'gemini'`，若集合处于锁定状态会按标准接口请求解锁，而日常只读探测 `auto` / `current` / `status` 绝不触发解锁）；若钥匙串中尚无记录，则自动回退读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
  - 在 **`file`** 模式（或无桌面服务器 / 容器环境）下：程序仅读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
  - 在 **`keyring`** 模式下：程序仅读取系统钥匙串，不会回退读取磁盘上的 `antigravity-oauth-token`。
  - 当附加 **`--target <NAME>`** 或 **`--target-dir <DIR>`** 时：程序严格按纯文件只读方式从该外部目录下的 `antigravity-oauth-token` 提取 `refresh_token`，不解析官方钥匙串后端、不触碰系统钥匙串或官方 `~/.gemini/antigravity-cli`（若同时显式传入 `--backend keyring` 则返回用法错误退出码 `2`）；若磁盘上存在未解决的官方 `switch_journal.json`，程序仅做只读检测并保留现场返回退出码 `7`（`pending_official_journal`），要求先用官方入口恢复，绝不在外部导入中自动重放官方切号事务。
  - **支持范围边界**：`--from-local` 严格面向 `agy` CLI 生效凭据源设计，不会读取桌面端 App / VS Code 扩展专用的回退文件 `~/.gemini/jetski-standalone-oauth-token`。若桌面系统未启用钥匙串、且仅存在 `jetski-standalone-oauth-token` 而未登录过 `agy` CLI，请改用 `agy-switch-cli auth login` 登录。
- 读取到 `refresh_token` 后，程序会先在本地预检并准备 `0700/0600` 私有暂存目录与单调授权序号，随后联网核验令牌有效性、拉取对应的真实邮箱并安全落盘（若该邮箱已在库中则自动刷新更新，不会重复建号）。

**场景 B：手动安全粘贴单条 `refresh_token`**
```bash
# 运行后终端会自动关闭字符回显（粘贴时不显示字符属于正常保护），粘贴后按回车即可：
agy-switch-cli accounts add --label "backup"
```

**场景 C：手里有多条裸 `refresh_token`（无需事先知道邮箱），一次性批量添加（`--from-file` / `--from-stdin`）**
1. 新建一个权限为 `0600` 的私密文本文件（例如 `~/tokens.txt`）：
   ```bash
   install -m 0600 /dev/null ~/tokens.txt
   ```
2. 用编辑器打开 `~/tokens.txt`，**每行填写一条 `refresh_token`**（空行与 `#` 开头的注释行会自动忽略；也可在 Token 后空一格写上 `# 备注名`，为该账号单独设置备注，支持英文与中文 UTF-8）：
   ```text
   # 批量导入账号列表
   1//0gAAAAAAAAAAAAAAAAAAAAAA  # primary
   1//0gBBBBBBBBBBBBBBBBBBBBBB  # backup
   1//0gCCCCCCCCCCCCCCCCCCCCCC
   ```
3. 执行以下命令，程序会逐条联网验证令牌、自动查询对应的真实邮箱并安全落盘（导入完成后建议删除明文文本文件）：
   ```bash
   agy-switch-cli accounts add --from-file ~/tokens.txt
   rm -f ~/tokens.txt
   ```
   *(注：同样支持通过标准输入管道传入，如 `cat ~/tokens.txt | agy-switch-cli accounts add --from-stdin`，单次管道输入上限为 `16 KiB`。)*

#### （3）备份导出与离线 JSON 导入（含旧版桌面端迁移）：`accounts export` / `import`

```bash
# 1. 从旧版桌面软件 agy-switch（默认读取 ~/.antigravity_tools）只读迁移账号（不会修改原目录中的任何文件）：
agy-switch-cli accounts import --from-legacy

# 2. 将当前账号库导出为 0600 权限的备份 JSON 文件（因含敏感令牌，须显式加 --include-secrets 确认；加 --accounts 可仅导出指定账号，加 --overwrite 允许覆盖已存在文件）：
agy-switch-cli accounts export --output ~/agy-backup.json --include-secrets [--accounts alice@example.com ...] [--overwrite]

# 3. 从备份 JSON 文件离线导入恢复（须显式传 --from-file；默认跳过本地已有的同邮箱账号，加 --overwrite 才会更新已有账号令牌）：
agy-switch-cli accounts import --from-file ~/agy-backup.json [--overwrite]
```

**`accounts import --from-file <文件.json>` 对 JSON 格式的要求**：
`accounts import --from-file` 为**纯离线快速导入**（不发起网络请求），因此 JSON 中的每个账号对象必须同时包含 `"email"` 和 `"refresh_token"` 两个字段（其余字段均可省略）。它兼容以下两种 JSON 结构：

- **结构一（最简 JSON 数组，便于手工或脚本生成）**：
  ```json
  [
    {
      "email": "alice@example.com",
      "refresh_token": "1//0gxxxx...",
      "custom_label": "primary"
    },
    {
      "email": "bob@example.com",
      "refresh_token": "1//0gyyyy..."
    }
  ]
  ```
- **结构二（`accounts export` 导出的标准备份包格式）**：
  ```json
  {
    "schema_version": 2,
    "accounts": [
      {
        "email": "alice@example.com",
        "refresh_token": "1//0gxxxx...",
        "name": "Alice",
        "custom_label": "primary"
      }
    ]
  }
  ```
*(补充说明：如果手头只有 `refresh_token` 而不知道对应的 `email`，请使用上一小节的 `accounts add --from-file` 联网自动识别邮箱导入。)*

#### （4）启用、禁用与删除账号：`enable` / `disable` / `delete`

```bash
agy-switch-cli accounts disable bob@example.com    # 手动禁用（填邮箱或 ID）
agy-switch-cli accounts enable bob@example.com     # 重新启用（填邮箱或 ID）
agy-switch-cli accounts delete charlie@example.com [--force] [--clear-active-slot]
# 说明：删除当前选中账号需加 --force；加 --clear-active-slot 会一并清理正在生效的同名官方凭据槽位（也可在 tui 看板中按 x 后按 y 交互确认删除）。
```

---

### 4.4 查看当前身份/可用模型与手动切号：`current` / `switch`

#### （1）查看当前账号状态与支持的全部模型：`current`

```bash
agy-switch-cli current
```

输出示例与逐行说明：
```text
Selected account : alice@example.com  [Google AI Pro]  (primary)  (acc-0001...)
Active agy slot  : matched (alice@example.com, expires 2026-11-17 16:00)
Live agy runtime : idle
Supported models : 15 available (cached)
  Gemini     : gemini-2.5-flash, gemini-2.5-flash-lite, gemini-2.5-pro, gemini-3-flash,
               gemini-3.8-flash-high, gemini-3.8-flash-low, gemini-3.8-flash-medium, ...
  Claude/GPT : claude-opus-4-6-thinking, claude-sonnet-4-6, gpt-oss-120b-medium
```
- **`Selected account`**：本地账号库中当前选中的账号、套餐等级、自定义备注与内部 ID。
- **`Active agy slot`**：当前生效凭据槽位中的实际身份状态（仅展示邮箱与换算为本机本地时区的 `YYYY-MM-DD HH:MM` 过期时间；`matched` 表示与选中账号一致，`drifted_known` / `drifted_external` 表示凭据曾被外部改动，`uninitialized` 表示尚未写入凭据）。
- **`Live agy runtime`**：当前系统中是否有正在运行的 `agy` 进程。它共有以下 4 种状态：
  - **`idle`**：当前系统中没有检测到当前用户的 `agy` 进程在运行。
  - **`unmanaged_running (pids=[636233])`**（若同时存在受管进程则附加 `, managed_accounts=[...]`）：表示检测到你直接在终端输入 `agy` 启动的运行中会话（未经可选的 `run -- agy` 包装登记租约，因此称为“未受管运行”）。各部分含义如下：
    - `unmanaged_running`：存在直接裸跑启动的 `agy` 进程，属于完全正常的日常使用状态（由于 `agy` 在启动瞬间将登录凭据加载进自身内存后便不留外部租约标记，且此后磁盘或钥匙串槽位可能已经切换过，工具不会臆测其启动时的登录身份，仅列出对应的进程号）。
    - `pids=[636233]`：当前检测到的未受管 `agy` 进程号（PID）列表。
    - `managed_accounts=[...]`：仅当系统中同时既有直接启动的 `agy`、又有通过 `agy-switch-cli run -- agy` 启动的受管进程时才会出现，用于列出受管进程已登记的账号 ID；平时没有受管进程时会自动省略该字段，保持输出简洁。
  - **`managed_running (count=1, accounts=["acc-0001"], pids=[636240])`**：当前所有运行中的 `agy` 进程均是通过可选的 `agy-switch-cli run -- agy` 启动的，工具通过本地双因子进程租约确切知道运行数量（`count`）、对应的账号 ID（`accounts`）与进程号（`pids`）。
  - **`unverified (...)`**：当前运行环境（如挂载受限的特殊容器）无法完整读取 `/proc` 进程表，工具无法核实是否有 `agy` 正在运行；出于故障关闭安全原则，自动切号与未加 `--allow-running` 的手动切号此时会拒绝盲目改写凭据。
- **`Supported models`**：当前账号可使用的全部模型清单（读取自最近一次配额刷新缓存，自动剔除未开放模型并按模型家族分组展示）。

#### （2）手动切换生效账号：`switch`（运行中进程行为与四种后端模式详解）

`switch` 通过**邮箱**或**账号 ID**精确指定目标账号（日常交互切号也可直接使用 `agy-switch-cli tui`）：

```bash
agy-switch-cli switch bob@example.com                   # 按邮箱立即切换到指定账号（对后续新启动的 agy 生效）
agy-switch-cli switch acc-0002                          # 或按内部账号 ID 切换到指定账号
agy-switch-cli switch bob@example.com --dry-run         # 仅做切换前条件预检，不发网络请求也不修改任何凭据
agy-switch-cli switch bob@example.com --require-idle    # 严格要求当前无任何运行中的 agy 进程才允许切号（适合特殊脚本）
agy-switch-cli switch bob@example.com --allow-running   # 在 /proc 不可读（unverified）的特殊容器环境中显式放行切号
```

- **当已有 `agy` 窗口正在运行时执行 `switch`（或 `tui` 切号）会发生什么？**
  - 默认情况下，检测到正在运行的 `agy` 进程时**不会报错拦截**，而是立即完成凭据切换，并输出一条温和提示：正在运行的旧 `agy` 窗口继续保持其启动时的原账号会话不受打断，而此后新打开的 `agy` 终端窗口将立即使用刚切好的新账号。
  - 如果你的自动化脚本希望“只要有 `agy` 在跑就禁止切号”，可显式加上 `--require-idle`（存在活跃 `agy` 时返回退出码 `8`）；若处于 `/proc` 被屏蔽的特殊容器（`unverified`），默认仍保持故障关闭拦截，确认安全时可加 `--allow-running` 放行（`--require-idle` 与 `--allow-running` 互斥）。
- **当账号处于 `verify-blocked`（`[verification required]`）风控验证状态时**：
  - 当账号因 Google CloudCode 返回 `403 VALIDATION_REQUIRED` 被标为 `verify-blocked` 时，其 OAuth 登录令牌本身仍有效。手动执行 `switch --dry-run` 可正常预检，手动执行 `switch`、`tui` 按 `Enter` 或可选的 `run` 均允许切入该账号以便打开官方 `agy` 完成网页/扫码验证。
  - 人工切入时**不会提前清除** `verify-blocked` 标记，同时会打印操作指引：后台 `daemon` 仍将其严格排除在自动切号候选之外（且当前生效账号处于 `verify-blocked` 时 `daemon` 会自动进入 `hold` 等待而不抢切槽位）。在官方 `agy` 内完成验证后，执行 `agy-switch-cli refresh <ID|EMAIL>`（或在 `tui` 中按 `r`），当最终采用主环境未阻断的有效观测时即自动解除该状态。
  - 被禁用（`disabled`）、令牌已被吊销或缺失 OAuth 权限范围（`scope_reauth_required`）的账号在所有入口仍严格拒绝切换。
- **不同环境与 `--backend` 模式下的切号行为**：
  - **纯无头环境（远程 SSH 服务器、Docker 容器、无桌面 WSL2）**：默认 `auto` 自动采用 `file` 模式，以 `0600` 权限原子替换 `~/.gemini/antigravity-cli/antigravity-oauth-token`，切完直接运行 `agy` 即刻生效。
  - **带有系统钥匙串的 Linux 图形桌面环境（如 KDE Plasma、GNOME）**：
    - **默认用法（`auto` 自动启用 `dual` 事务性双写）**：直接运行 `agy-switch-cli switch bob@example.com`（无需手传额外参数），程序自动对系统钥匙串集合与本地 `antigravity-oauth-token` 执行前置快照、加密更新、双 `fsync` 落盘与双副本一致性回读校验（任一步失败自动双端回滚；若遇到传输中断等不确定状态则保留切换日志并返回退出码 `7`，后续交互式写命令会在安全 CAS 保护下尝试对账，并在安全核实状态与耐久性检查通过后清理日志，详见 [4.1 节 `status`](#41-环境状态只读巡检status) 的 `Journal status` 恢复指引）。切完后在任意终端直接输入 `agy` 立即使用新账号。
    - **仅用钥匙串不留本地文件（`--backend keyring`）**：执行 `agy-switch-cli --backend keyring switch bob@example.com`（或在 `config.json` 中设 `"backend": "keyring"`），程序仅读写系统钥匙串，完全不创建或修改 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
    - **桌面与 CLI 账号隔离（显式 `--backend file` + `run`）**：若希望桌面端 App 保持原钥匙串账号、仅让终端里的 `agy` 换用另一个账号，可执行 `agy-switch-cli --backend file switch bob@example.com` 只改本地文件，再通过可选方式 `agy-switch-cli --backend file run -- agy` 启动（显式选择 `file` 后端时，`run` 会自动为子进程屏蔽桌面钥匙串总线）。

#### （3）管理外部目标目录（`--target` / `--target-dir`，如第三方 ACP 宿主隔离凭据与用量统计）

某些通过 `agy acp --gemini-dir <隔离目录> --app-data-dir <目录名>` 启动本地 `agy` 的第三方工具（例如 `t3code`）会将 Google OAuth 凭据（`antigravity-oauth-token`）与会话数据库（`conversations/*.db`）独立保存在自己的应用数据目录中（格式与官方 `agy` 一致）。为在不耦合任何第三方工具路径的前提下独立管理这些外部目录，以下六个命令统一支持互斥选项 **`--target <NAME>`**（引用 `config.json` 中的 `targets` 别名，详见第 `6.2` 节）与 **`--target-dir <DIR>`**（显式传入目标应用数据目录路径）：

```bash
# 1. 查看外部目录当前挂接的账号身份、到期时间与绑定在该目录的运行中 agy 进程（纯只读）：
agy-switch-cli current --target t3
agy-switch-cli current --target-dir ~/.t3/userdata/providers/antigravity/ac0a3dfd6dddb20962cecff6ee5fe65e19d3923be20e52c5ab52ff877f7e4c32/antigravity-acp

# 2. 独立切换外部目录凭据（不修改官方 ~/.gemini/antigravity-cli、系统钥匙串、index.json 与 daemon 选中态）：
agy-switch-cli switch bob@example.com --target t3 --dry-run
agy-switch-cli switch bob@example.com --target t3 --require-idle
agy-switch-cli switch bob@example.com --target t3 --allow-running

# 3. 查看或联网刷新外部目录账号的双窗口配额（支持池内账号与未入池的纯游离凭据）：
agy-switch-cli quota --target t3                # 池内账号直接读取本地缓存（零网络）；未入池游离文件提示加 --refresh
agy-switch-cli quota --refresh --target t3      # 联网刷新并展示配额（如令牌续期或轮换，经 L1 锁与 CAS 同步回写该文件）
agy-switch-cli refresh --target t3              # 刷新令牌与配额并按需 CAS 回写该文件（未入池游离文件不改动本地 accounts/）

# 4. 将外部目录中已登录的账号反向导入本工具账号池：
agy-switch-cli accounts add --from-local --target t3 --label "t3-account"

# 5. 纯只读零写入统计外部目录中 conversations/*.db 的 Token 用量与 TTFT/TPS（支持 --watch 实时看板）：
agy-switch-cli stats summary --target t3 --range today
agy-switch-cli stats list --target t3 --recent 20
agy-switch-cli stats summary --target t3 --watch
```

- **完全隔离与安全护栏**：
  - **纯文件模式**：所有外部凭据操作均严格仅读写 `<target-dir>/antigravity-oauth-token`，绝不触碰系统 Secret Service 钥匙串，也不受 `config.json` 中为官方 `agy` 配置的 `backend: "dual"` 或 `"keyring"` 影响（仅当同次命令行显式传入 `--backend keyring` 时报用法冲突返回退出码 `2`）。
  - **严格防误操作**：要求目标目录已真实存在（绝不自动 `mkdir -p`），全程使用 `O_NOFOLLOW` 拒绝软链接穿越，拒绝将文件路径（含末尾带 `/antigravity-oauth-token`）传给 `--target-dir`，拒绝与官方 `~/.gemini/antigravity-cli`、`~/.gemini/antigravity` 及本工具自身 `data_dir` / `cache_dir` 碰撞，并在网络刷新前后执行 SHA-256 CAS 比对防止覆盖并发写入。
  - **槽位级精准进程检测**：针对外部目录时，程序仅通过 `/proc/<pid>/cmdline` 解析同 UID `agy` 进程的 `--gemini-dir` 与 `--app-data-dir`（不读取 `/proc/<pid>/environ`），只对真正绑定在该目标目录的运行中 `agy` 进程发出提醒或响应 `--require-idle`，不会被无关的原生终端 `agy` 会话误拦。
  - **运行中 `agy acp` 的生效边界**：与原生 `agy` 相同，已常驻运行中的 `agy acp` 进程会将启动时加载的令牌缓存在内存中，切号后仅对新启动的会话进程生效，且旧常驻进程到期自动续期时可能回写覆盖该凭据文件。
  - **不跨界修改整体状态**：`status`、`daemon`、`tui` 与 `run` 继续专注服务官方 `agy` 槽位，`stats` 默认 `--source all|cli|app` 亦仅统计官方目录（与 `--target` / `--target-dir` 互斥），外部目标不会与官方状态相互污染。
  - **离线身份识别口径（`current` 零网络）**：外部槽位仅以 `refresh_token` SHA-256 指纹与本地账号池精确匹配；对于尚未经本工具切写或导入的游离文件，纯离线只读解析会兼容提取 `id_token` JWT 或新版官方 `agy` 写入的 `id_token_email` 与 `user_tier` 提示（若邮箱与池内账号相同但 `refresh_token` 不同，会同时展示池内邮箱与 ID 提示差异而非冒认池内身份），完整套餐配额与支持模型清单在切号/入池后离线可见，或通过 `quota --refresh` 直接联网查看。

---

### 4.5 配额查询与流式联网刷新：`quota` / `refresh`

```bash
# 1. 查看当前选中账号的本地缓存配额表（纯本地读取，零网络请求）：
agy-switch-cli quota

# 2. 先联网刷新最新配额，再立即打印配额进度表：
agy-switch-cli quota --refresh

# 3. 按邮箱或 ID 查看 / 刷新指定账号：
agy-switch-cli quota bob@example.com
agy-switch-cli quota --refresh bob@example.com

# 4. 一次性查看全部账号，或并发流式刷新全部启用账号（每完成一个账号实时输出 [k/N] 进度）后统一打印：
agy-switch-cli quota --all
agy-switch-cli quota --refresh --all [--concurrency 3]

# 5. 纯联网刷新落盘（批量模式在终端实时流式打印 [k/N] 完成进度，适合快速巡检或脚本调用；--concurrency 可设 1..5，默认 2）：
agy-switch-cli refresh [<ID|EMAIL> | --all] [--concurrency 3]
```

**配额表各列说明**：
```text
Account : alice@example.com  [Google AI Pro]
Status  : known (37.0% effective on all) · updated just now (source: Daily)

  Pool           Window   Remaining            Resets (Local)
  ───────────────────────────────────────────────────────────────────────────
  Gemini         Weekly   [███████░░░]   72%   2026-11-23 19:34  (in 6d 18h)
                 5h       [██████████]  100%   2026-11-17 05:00  (in 4h 30m)
  Claude / GPT   Weekly   [████░░░░░░]   37%   2026-11-21 21:22  (in 4d 20h)
                 5h       [██████████]  100%   2026-11-17 05:00  (in 4h 30m)
```
- `Weekly` 为 7 天滚动周总额度，`5h` 为 5 小时短期恢复窗口；
- `Resets (Local)` 已自动换算为本机所在的本地时区时间（统一格式为 `YYYY-MM-DD HH:MM`），并在括号内附带剩余重置倒计时（`in Xd Yh`）。

---

### 4.6 自动切号规则配置：`policy`（设定规则）

当你拥有多个账号时，可以先通过 `policy` 设定好“低到多少百分比时换号、按什么顺序挑选下一个号”，随后配合第 `4.8` 节的后台守护进程 **`daemon`** 按周期自动巡检并预切号。

#### 双窗口木桶短板评估规则（`min(5h, Weekly)`）

- **`policy` 同时监控双时间窗口**：对于 `--model` 所指定的目标模型池（默认 `all`，或单独指定 `gemini`、`claude`/`3p`、`argon` 及具体模型 ID），系统会**同时读取该池的 `5h`（五小时短期窗口）与 `Weekly`（7 天滚动周窗口）两个剩余百分比**，按木桶短板原理取 **`min(5h, Weekly)`** 作为该账号的有效剩余额度百分比（免费层 `Free` / `Starter` 账号若无 `5h` 桶则直接按 `Weekly` 评估）。
- **触发线与准入线共用同一有效百分比**：
  - 当前生效账号的有效剩余百分比 `min(5h, Weekly) <= --reserve` 时，无论是 `5h` 窗口见底还是周中后期 `Weekly` 周额度见底，都会触发换号评估；
  - 备选账号同样要求 `min(5h, Weekly) >= --minimum` 才具备接班资格。因此默认将 `--reserve` 设为 **`10%`**、`--minimum` 设为 **`30%`**，在重度编码与 `180` 秒巡检间隔下预留充足的提前切号缓冲以减少 `5h` 撞墙，同时确保接班候选号拥有足够续航、不易切入低余量账号后被 `3600` 秒冷却卡住，并保留 `20%` 的安全水位差防止来回震荡（若账号池较小希望更充分用尽残余额度，也可按需通过 `policy set` 下调）。

#### `policy set` 全部参数说明表

| 参数选项 | 可选填的值 | 默认值 | 详细作用与选择建议 |
| :--- | :--- | :---: | :--- |
| **`--enabled`** | `true` 或 `false` | `false` | **自动切号总开关**。开启前候选名单里至少需要包含 1 个账号。 |
| **`--all-candidates`** | 无需填值（直接添加该开关） | — | **一键将当前所有已启用账号（按 `accounts list` 顺序）全部设为候选账号**，免去逐个输入邮箱的步骤。 |
| **`--candidates`** | 空格分隔的 `<ID\|EMAIL>` | 空 | 只希望将部分特定账号放入轮换池时使用，填写对应账号的邮箱或 ID（如 `--candidates alice@example.com bob@example.com`），或在 `tui` 中按 `c` / `C` 键可视化勾选。清空候选池可使用 `--clear-candidates`。 |
| **`--reserve`** | `1` ～ `98`（整数百分比） | **`10`** | **保底警戒线（触发换号线）**。默认 `10`：当正在使用的账号有效剩余额度 `min(5h, Weekly)` 降至 `10%` 或以下（即已消耗 `90%` 以上）时，触发自动换号。 |
| **`--minimum`** | `2` ～ `100`（整数百分比） | **`30`** | **候选接班准入线**。默认 `30`：准备接班的备用账号有效剩余额度 `min(5h, Weekly)` 必须至少达到 `30%` 才会被选中（要求严格大于 `--reserve` 以留出防抖回差）。 |
| **`--strategy`** | `round-robin` 或 `priority` | `round-robin` | **候选账号挑选顺序**（详见表下分点说明）。 |
| **`--mode`** | `immediate` 或 `wait` | `immediate` | **后台 `daemon` 检测到运行中 `agy` 进程时的处理方式**（详见表下分点说明）。 |
| **`--model`** | `all`、`gemini`、`claude`（等价别名 `3p`）、`argon` 或具体模型名 | `all` | **监控的模型池范围**（详见表下分点说明）。 |

- **`--strategy` 候选挑选顺序说明**：
  - `round-robin`（循环轮换，默认）：记录上次切入的账号位置，下次从其后一位开始依次轮流挑选，适合多个账号均匀分摊额度消耗的场景。
  - `priority`（主备优先级）：每次均从候选列表第 1 位开始依次寻找第一个达标的账号，适合有明确主力号并在额度恢复后优先切回主力号的场景。
- **`--mode` 运行中进程处理方式说明**：
  - `immediate`（触线立即更新槽位，默认）：不终止正在运行的 `agy` 进程，在当前账号额度跌破警戒线后立即更新凭据槽位，使后续新启动的 `agy` 直接使用新账号（已运行的旧窗口保持原会话不受影响；遇到 `/proc` 不可读即 `unverified` 状态时保持故障关闭拒绝盲写）。
  - `wait`（等待空闲）：检测到有活跃 `agy` 进程正在运行时暂缓切换，等待所有 `agy` 退出空闲后再写入新凭据。
- **`--model` 监控模型池说明**：
  - `all`（默认）：同时监控所有模型池，任一池跌破警戒线即触发切号。
  - `gemini`：仅监控 Google 自研第一方 Gemini 共享池额度。
  - `claude`（等价别名 `3p`）：仅监控 `Claude / GPT` 第三方共享池额度。

> **名词说明：为什么 `--model 3p` 代表 `Claude / GPT` 池？**
> `3p` 是英文 **`Third-Party`（第三方合作模型）** 的缩写。在 Google CloudCode 后端配额体系中，Google 自家研发的 `Gemini` 系列属于第一方模型（桶标识为 `gemini-weekly` / `gemini-5h`），而由外部合作厂商 Anthropic 提供的 `Claude` 系列与 OpenAI 提供的 `GPT` 系列共用同一个第三方模型配额池，其内部桶标识即为 `3p-weekly` 与 `3p-5h`。因此在命令行中填写 `--model claude` 与 `--model 3p` 完全等价，均监控这整个 `Claude / GPT` 共享池。

#### 水位区间与“无候选账号达到 `minimum`”时的行为说明

以默认的保底警戒线 `--reserve 10`（`10%`）与候选准入线 `--minimum 30`（`30%`）为例，自动切号在不同剩余额度组合下的决策逻辑如下：

- **情况一：当前正在使用的账号有效额度介于 `10%` 与 `30%` 之间（例如剩余 `20%`）**：
  - **不会触发切换，继续稳定使用当前账号**。
  - `--minimum`（`30%`）仅用于筛选“准备新换上来的接班候选账号”，并不会限制已经在用的当前账号；只有当当前账号继续消耗至 **`<= 10%`（`--reserve`）** 时才会开始寻找接班账号。
- **情况二：当前账号已降至 `<= 10%`（如剩余 `6%`），但池中其余候选账号全部 `< 30%`（没有任何候选号达到 `>= 30%`）**：
  - 系统判定为**暂无达标接班候选（`no_qualified_candidate`）**：
    - 后台 `daemon` 会**保持当前账号不变**（不会在两个低余量账号之间来回横跳浪费请求），静默等待任意候选账号跨过 `5h` 或 `Weekly` 重置时间恢复到 `>= 30%` 后再自动切入。
    - 执行 `agy-switch-cli policy eval` 模拟测算时，会清晰显示 `would_switch=false` 与 `reason=source_below_reserve_but_no_qualified_candidate`。
    - **如何手动介入使用那些仅剩 `15% ~ 29%` 的备用号？** 手动切号（`agy-switch-cli switch <ID|EMAIL>` 或 `tui` 中按回车 / `s`）不受 `--minimum` 准入线限制，你随时可以手动切到任意未禁用账号把剩余零头额度用尽。

#### `policy` 常用命令示例

```bash
# 1. 将当前所有启用账号加入候选池并启用自动切号（默认即为 immediate + round-robin，reserve 10% / minimum 30%），重点监控 Claude/GPT 池：
agy-switch-cli policy set --enabled true --all-candidates --model claude

# 2. 如需自定义更保守或更激进的水位线、等待旧 agy 进程全部退出后再切号并采用主备优先级顺序：
agy-switch-cli policy set --mode wait --strategy priority --reserve 15 --minimum 40 --candidates alice@example.com bob@example.com

# 3. 查看当前策略详情、调整候选优先级顺序、或空跑模拟测算当前是否会触发切号：
agy-switch-cli policy show
agy-switch-cli policy order bob@example.com alice@example.com
agy-switch-cli policy eval
```

> **提示**：你也可以在 `agy-switch-cli tui` 看板中按 **`c` 键**增删单个候选账号、按 **`C` 键**一键全选或清空所有未禁用候选账号，并按 **`p` 键**切换自动切号总开关。

---

### 4.7 指定凭据与后端启动包装器：`run`

日常在无头服务器或桌面上完成切号（`tui` 或 `switch`）后，直接输入官方 `agy` 即可使用，无需经过包装命令。`run` 作为**可选的受管凭据与后端启动包装器**，专注解决“启动前指定目标账号凭据”与“图形桌面上强制使用本地文件后端隔离钥匙串”两类确定性需求（不会隐式发起配额查询或按 `policy` 自动换号）：

```bash
# 场景 A：指定本次使用某个邮箱或 ID 对应的账号同步凭据并启动官方 agy（双横杠 `--` 后面接原本的 agy 命令及任意参数）：
agy-switch-cli run --account bob@example.com -- agy
agy-switch-cli run --account bob@example.com -- agy chat "帮我检查这段代码的边界条件"

# 场景 B：在开启了 GNOME Keyring / KDE Wallet 的 Linux 图形桌面上，显式指定 --backend file（或设置 AGY_SWITCH_CLI_BACKEND=file / config.json "backend": "file"），使用本地文件槽位并自动为该 agy 子进程屏蔽桌面钥匙串：
agy-switch-cli --backend file run -- agy

# 场景 C：不传 --account 时，确保当前选中账号的访问令牌有效且已同步至生效槽位，登记受管进程租约后启动 agy：
agy-switch-cli run -- agy
```

**`run` 的确定性工作机制**：
- **纯凭据准备、零配额请求**：若传入 `--account <ID|EMAIL>`，将目标账号凭据同步至当前生效后端槽位；若省略 `--account`，则校验当前选中账号凭据与生效槽位一致（仅在短期访问令牌即将过期时执行一次 OAuth 令牌续期，绝不联网拉取配额或隐式切换其他候选号）。
- **显式 `file` 后端自动隔离桌面钥匙串总线**：
  - 当通过命令行 `--backend file`、环境变量 `AGY_SWITCH_CLI_BACKEND=file` 或 `config.json` 中的 `"backend": "file"` **显式选择 `file` 后端**，且宿主环境中存在桌面会话总线（`DBUS_SESSION_BUS_ADDRESS` 或 `$XDG_RUNTIME_DIR/bus`）时，`run` 自身使用本地 `FileSessionBackend`（全程不触碰桌面钥匙串），并自动将拉起的 `agy` 子进程的 `DBUS_SESSION_BUS_ADDRESS` 设为 `unix:path=/dev/null`，确保终端内的 `agy` 从本地文件槽位读取凭据，而不影响桌面端 App 原有的钥匙串账号。
  - 若保持默认的 `--backend auto`，在无 Secret Service 钥匙串的无头 SSH 服务器上自动回退至 `file` 时，程序**不会**覆盖子进程的 `DBUS_SESSION_BUS_ADDRESS`，从而保证 `agy` 会话内部执行 `systemctl --user` 等用户总线命令完全不受影响。
- **双因子进程租约与退出码透传**：启动前检查 `/proc` 确保不存在未受管运行中的 `agy` 或其他受管账号冲突，拉起子进程后登记 `(pid + starttime)` 租约、转发 `SIGINT` / `SIGTERM` 信号，并在退出时清理租约、原样透传 `agy` 的退出码（桌面文件隔离场景可按需在 `~/.bashrc` 中设置可选别名 `alias agys='agy-switch-cli --backend file run -- agy'`）。

---

### 4.8 后台自动切号守护进程：`daemon`（定时巡检与服务安装）

如果你习惯直接输入裸 `agy` 启动客户端，或有定时任务/自动化脚本反复拉起新的 `agy` 进程，希望后台定期巡检配额并在跌破 `--reserve` 时提前把凭据槽位切换好，可以使用 `daemon` 命令：

- **后台巡检、桌面推送与无头静默边界说明**：
  - `daemon` 在后台定时巡检并按需提前切换凭据槽位，绝不会强行终止或打断你正在交互的 `agy` 进程。
  - **桌面通知与无头自动跳过**：
    - 当运行于存在活跃桌面通知服务（`org.freedesktop.Notifications`，如 KDE Plasma、GNOME 等）的图形环境时，`daemon` 会在**成功自动切号**时发送普通级别提醒（顶部 `↑` 标出新切入账号及其 `5h` / `Weekly` 双窗口余量，下方 `↓` 标出被切出账号），并在**首次触发连续失败熔断暂停**时发送高优先级警告（后续已暂停轮次不再重复弹窗）；发送前会只读查询 `GetCapabilities`，桌面支持 `body-markup` 时自动加粗新账号与新余量两行（并将 `↑` 一并置于加粗块内）、对故障排查指引使用斜体，不支持时退回纯文本：
      ```text
      # 自动切号成功通知示例（支持 body-markup 的桌面会将前两行加粗，其中 `↑` 位于加粗块内）：
      Account Switched
      ↑ bob@example.com
      5h 100% · Weekly 85%
      ↓ alice@example.com
      5h 2% · Weekly 40%

      # 连续失败熔断暂停通知示例（无目标账号时首行合并为 `■ Journal recovery · 1/3 failed`）：
      Auto-Switch Paused
      ■ bob@example.com
      Switch commit · 3/3 failed
      Keyring locked or unavailable.
      Run agy-switch-cli status to inspect.
      ```
    - **默认常驻防漏看与可选自动消失**：所有桌面通知统一附加 `transient=false` 与 `resident=true`。`Account Switched`（普通级别 `urgency=1`）默认使用常驻模式（`expire_timeout=0`，停留在屏幕直至手动关闭，且不附带严重告警标识）；若更习惯桌面默认数秒后自动消失，可在 `config.json` 中设置 `"notifications": { "persistent": false }`（切换为 `expire_timeout=-1`）。`Auto-Switch Paused`（严重级别 `urgency=2`）始终保持常驻（`expire_timeout=0`）。
    - 在无图形界面的 SSH 服务器或容器环境中（即使开启了 `systemd --user` 与 `linger`，只要会话 D-Bus 上没有活跃的通知守护进程），`daemon` 会以只读检测自动静默跳过，不尝试拉起桌面服务也不报错。
    - 如需在桌面环境手动关闭推送，可使用 `--no-notify`（配合 `daemon --install --no-notify` 可持久化写入服务单元）、设置环境变量 `AGY_SWITCH_CLI_NOTIFY=0`，或在 `config.json` 中设置 `"notifications": { "enabled": false }`。
  - 由于官方 `agy` 仅在每次启动时读取一次登录凭据，当你在前台对话中注意到当前账号余量不足而退出重开 `agy`（或者后台脚本发起下一轮新的 `agy` 调用）时，若 `daemon` 已经提前完成了后台预切号，新启动的 `agy` 就会直接使用已经换好的新账号，省去退出后再手动打开 `tui` 刷新切号的步骤；平时也可随时通过 `agy-switch-cli current` 或 `journalctl --user -u agy-switch-cli.service` 查看切号记录。

```bash
# 1. 在支持 systemd 的 Linux 系统上，一键安装并启动开机自启后台用户服务（最简常驻方式）：
agy-switch-cli daemon --install
# 如需自定义后台服务的固定巡检间隔与冷却秒数，可在 --install 时一并传入写入服务文件：
agy-switch-cli daemon --install --interval 300 --cooldown 3600
# 如需在安装/刷新服务时顺带清零历史冷却截止时间（不会将 --reset-cooldown 写入服务单元）：
agy-switch-cli daemon --install --reset-cooldown

# 2. 一键停止、取消自启并安全移除用户级 systemd 服务文件：
agy-switch-cli daemon --uninstall

# 3. 直接在当前终端前台运行守护进程（按默认每 180 秒即 3 分钟巡检一次，切号冷却 3600 秒，每轮打印单行状态日志）：
agy-switch-cli daemon
agy-switch-cli daemon --interval 300 --cooldown 3600

# 4. 仅执行单轮实时核查与按需切换后立即退出（输出本轮结论；适合手动排查或配合 crontab 定时任务）：
agy-switch-cli daemon --once
agy-switch-cli --json daemon --once

# 5. 主动解除当前生效中的切号冷却期（可直接对运行中的 systemd 服务或另一终端的前台 daemon 生效）：
agy-switch-cli daemon --reset-cooldown
agy-switch-cli --json daemon --reset-cooldown
# 若未运行常驻服务，也可在单轮检查前一步清零冷却并立即评估切号：
agy-switch-cli daemon --once --reset-cooldown
```

#### 全部命令选项详解

- **服务管理与运行模式**
  - `--install`（默认关闭，与 `--uninstall`、`--once` 互斥）：检测系统 `systemd --user` 可用性，原子生成 `~/.config/systemd/user/agy-switch-cli.service` 并自动执行 `daemon-reload` 与 `enable --now`（在无 `systemd` 的 Docker 容器中会给出清晰提示并引导参见第 `7.2` 节）。若服务当时已在运行且本次修改了 `--interval`、`--cooldown` 或可执行文件路径，请随后再执行一次 `systemctl --user restart agy-switch-cli.service` 使新启动参数生效。
  - `--uninstall`（默认关闭，与 `--install`、`--once`、`--no-notify`、`--reset-cooldown` 互斥）：先核验 `systemd --user` 管理器加载的服务单元身份；确认指向当前用户的 `agy-switch-cli.service` 时执行 `disable --now`，若服务处于未加载且非活跃态则跳过 `disable --now`，随后防符号链接安全删除本地服务文件并重载 `daemon-reload`。
  - `--once`（默认关闭，与 `--install`、`--uninstall` 互斥）：执行单轮实时评估与按需切换后立即退出，非 `--json` 模式向 `stdout` 输出单行状态结论，`--json` 模式输出标准 JSON 结果信封，适合 `cron` 或单次验证排障。
- **巡检周期、冷却时间与桌面通知**
  - `--interval <秒>`（环境变量 `AGY_SWITCH_CLI_INTERVAL`，默认值 `180` 即 3 分钟，最小 `1`）：后台巡检间隔秒数（常驻模式内置 `±10%` 随机时间抖动，每次合资格的定时唤醒均会直接联网复核当前活跃账号，`Wait` 模式挂起计划的复验保鲜期自动收紧为有效间隔的 `80%`、范围 `1..=3600` 秒）。配合 `daemon --install` 传入时写入服务单元长期生效。
  - `--cooldown <秒>`（环境变量 `AGY_SWITCH_CLI_COOLDOWN`，默认值 `3600` 即 1 小时，要求 `>= 0`）：完成一次自动切号后的冷却保护秒数，冷却期内不再连续触发第二次切换（仅对后续新触发的切号生效，不会追溯清除磁盘中尚未到期的旧冷却截止时间）。配合 `daemon --install` 传入时写入服务单元长期生效。
  - `--reset-cooldown`（默认关闭，与 `--uninstall` 互斥）：显式清零 `state/daemon_state.json` 中已持久化的 `cooldown_until` 冷却截止时间（保持 `0600` 权限，保留 `round-robin` 轮询游标与 `paused_on_failure` 熔断暂停状态；状态文件不存在或本无冷却时幂等成功退出 `0`），支持三种入口：
    - **独立执行 `daemon --reset-cooldown`（支持 `--json`）**：零网络请求、不争抢 `daemon.lock` 单实例锁，可在 `systemd --user` 服务或另一终端前台 `daemon` 正在运行时直接执行，运行中的守护进程会在下一次唤醒时自动脱离冷却（同时受 `L3` 锁重读保护，不会被并发巡检写回旧时间戳）；独立模式不允许与单次运行覆盖参数（`--interval`、`--cooldown`、`--no-notify`、`--mode`、`--strategy`、`--reserve`、`--minimum`、`--model`、`--proxy`）混用，混用会明确报错退出 `2`。
    - **组合单轮 `daemon --once --reset-cooldown`**：获取单实例锁后先清零冷却，再立即执行本轮 7 阶段实时核查与按需切号。
    - **组合安装 `daemon --install --reset-cooldown`**：在安装并启动用户服务前一次性清零历史冷却，且**绝不**将 `--reset-cooldown` 写入 `agy-switch-cli.service` 的 `ExecStart=`。
  - `--no-notify`（环境变量 `AGY_SWITCH_CLI_NOTIFY`，默认开启桌面推送并在无头环境自动静默跳过）：关闭 `daemon` 在切号成功或首次熔断暂停时的 Linux 桌面通知（`--install --no-notify` 会将该参数写入生成的 `systemd` 单元；环境变量支持 `1`/`true`/`yes`/`on` 或 `0`/`false`/`no`/`off`，优先级为 `--no-notify` > `AGY_SWITCH_CLI_NOTIFY` > `config.json` > 默认开启）。
- **单次运行策略内存覆盖（仅对当前前台 `daemon` / `daemon --once` 生效，不会写回 `policy.json` 或 `systemd` 服务文件）**
  - `--mode <immediate|wait>`（环境变量 `AGY_SWITCH_CLI_MODE`，默认读取 `policy.json`）：临时覆盖活跃进程防护模式（`immediate` 允许在已核验的 `agy` 运行时更新槽位供后续新终端使用；`wait` 在检测到 `agy` 运行时推迟切换）。
  - `--strategy <priority|round-robin>`（环境变量 `AGY_SWITCH_CLI_STRATEGY`，默认读取 `policy.json`）：临时覆盖备用账号选择策略（按列表顺序优先或轮询）。
  - `--reserve <1..=98>`（环境变量 `AGY_SWITCH_CLI_RESERVE`，默认读取 `policy.json`）：临时覆盖当前生效账号的触发保留水位百分比。
  - `--minimum <2..=100>`（环境变量 `AGY_SWITCH_CLI_MINIMUM`，默认读取 `policy.json`）：临时覆盖目标候选账号必须达到的最低可用额度百分比（必须严格高于保留水位）。
  - `--model <MODEL>`（环境变量 `AGY_SWITCH_CLI_MODEL`，默认读取 `policy.json`）：临时覆盖监控目标（`all`、`gemini`、`claude`、`argon` 或指定模型 ID）。

> **关于 `--interval`、`--cooldown`、`--reset-cooldown` 及临时覆盖参数的重要说明**：
> - 直接在前台运行 `agy-switch-cli daemon --interval 300 --cooldown 3600`（或附加 `--reserve`、`--mode` 等参数）时，这些命令行参数**仅对当前这一个 `daemon` 进程本次运行生效，不会修改磁盘上的 `policy.json` 或 `config.json`**；关掉该进程后下次裸跑 `daemon` 仍恢复默认巡检 `180` 秒、冷却 `3600` 秒。
> - **为何修改 `--cooldown` 不会立即退出当前冷却期？** 每次自动切号成功后，程序会将绝对冷却截止时间戳（`切号时间 + cooldown`）持久化写入 `state/daemon_state.json`。如需提前解除尚未到期的冷却期，请运行 `agy-switch-cli daemon --reset-cooldown`（或 `daemon --once --reset-cooldown` / `daemon --install --reset-cooldown`）。
> - **如何持久保存巡检间隔与冷却时间？**
>   - 使用 `systemd` 后台服务时：执行 `agy-switch-cli daemon --install --interval 300 --cooldown 3600`，程序会将这两项参数直接写入 `~/.config/systemd/user/agy-switch-cli.service` 的启动命令中长期生效。
>   - 在无 `systemd` 容器中使用 `nohup` / `supervisord` / `tmux` 时：在启动命令中带上 `--interval` / `--cooldown`，或配置环境变量 `AGY_SWITCH_CLI_INTERVAL` 与 `AGY_SWITCH_CLI_COOLDOWN`。
> - **如何持久保存自动切号水位、策略规则与网络代理？** 请分别使用 `agy-switch-cli policy set ...` 将策略规则写入 `policy.json`、在 `config.json` 中写入 `network.proxy_url` 保存代理地址（因此在执行 `daemon --install` 时若误带了 `--reserve` 或 `--proxy` 等单次临时参数，程序会主动提醒先持久保存配置）。

---

### 4.9 SSH 交互式终端看板：`tui`（全键盘可视化操作）

如需在单个界面中总览所有账号额度、调整列表顺序、配置自动切号候选池或手动切号，可运行：

```bash
agy-switch-cli tui
```

#### 界面说明
- **三行独立对齐状态头、`Daemon` 冷却状态与极矮窗口自适应**：
  - 在常规高度（`>= 11` 行）终端中，顶部将生效会话、运行中进程与自动切号策略拆分为 **3 行垂直冒号对齐的独立状态行**（`Session [file|dual|keyring] : ...`、`Runtime : ...`、`Policy : ...`），完整展示每项信息而不会因挤在同一行被截断；在极矮终端分屏（`< 11` 行）下则自动折叠为紧凑单行，确保在任意尺寸下都不超出物理视口边界。
  - 当后台 `daemon` 处于切号冷却期或连续失败熔断暂停时，`Policy` 行末尾自动附加 `· cooldown <剩余时长>` 或 `· PAUSED (run status)`，无需退出看板即可按 `k` 主动解除冷却（不争抢 `daemon.lock`，后台服务运行时同样直接生效）。
  - 在宽度小于 `152` 列的窗口中自动隐藏冗长的 36 位 `ID` 列；当账号数量超出窗口高度时保持顶栏、表头与底栏固定并跟随光标平滑滚动（标题栏显示 `[Showing X-Y of N]`），同时在表格首行/末行内嵌定高的 **`... (<K> more above)`** 与 **`... (<K> more below)`** 折叠提示行，直观指示上/下方仍有隐藏账号且滚动全程总行数恒定不跳动（一屏可完整容纳时不渲染任何 `...` 行）。
- **继承全局 `--backend` 并在顶栏明确标识（无看板内切换热键）**：
  - `tui` 严格继承全局生效后端（默认 `auto` 自动解析为 `Session [file]` 或 `Session [dual]`；若通过 `--backend keyring`、环境变量或 `config.json` 指定了后端，则对应显示 `Session [keyring]` 等标签），不在看板内部设置易误触的后端切换键，保证全局行为一致。
  - 按 `Enter` 或 `s` 切号时，即使当前已有 `agy` 进程正在运行也会立即完成切换，并在底栏温和提示已运行的 `agy` 保持原登录态、新启动的 `agy` 将使用新账号。
- **`#`、`Sel`、`Email`（含备注）与 `Plan`**：
  - `#` 为右对齐账号序号；`Sel` 列依次用 `>` 表示当前光标所在行、`*` 表示当前选中的账号、`+` 表示已用 `Space` 多选标记的账号（如 `>*+`）。
  - `Email` 列在账号设置了自定义备注（`custom_label`）时以 `alice@example.com (primary)` 形式拼接展示（支持英文与中文 UTF-8，与 `accounts list`、`current` 及桌面通知格式一致，按 `l` 可随时在底栏内联修改或清空备注）。
  - `Plan` 列在 `tui` 看板内自动将上游返回的免费层原始全称 `Antigravity Starter Quota`（及 `Starter` / `Free Tier` 等变体）简写为 `Free`，将 `Google AI Pro` / `Ultra` 简写为 `Pro` / `Ultra`（未知新套餐名原样兜底保留）；而在命令行 `accounts list`、`current`、`quota` 及所有 `--json` 输出中则原样保留上游原始 `subscription_tier` 字符串以便精确核对。
- **`Space` 多选联动与底部常驻提醒**：
  - 按 `Space` 可勾选或取消勾选任意多个账号；存在已勾选账号时，标题栏显示 `· <N> marked`，最底行 `Status` 在无临时操作提示时常驻显示 `Marked (<N>): ...  [Esc to clear]`，按 `Esc` 优先一键清空勾选（无勾选时 `Esc` 照常退出看板）。
  - 存在勾选账号时，`o`（导出）、`r`（刷新）、`c`（切换候选资格）、`e`（启用）、`d`（禁用，`>= 2` 个时弹 `y` 确认）与 `x`（删除，始终弹 `y` 确认）均自动作用于全部已勾选账号，且除被删除的账号自动移出外，操作完成后保持原有勾选状态便于连续批处理；无勾选时上述按键仅作用于当前光标高亮行。
- **`i` 账号详情卡片与完整模型翻页**：
  - 按 `i` 将表格区切换为当前高亮账号的只读详情卡片，完整展示邮箱与备注、完整 UUID、套餐与状态/禁用原因、OAuth 客户端与访问令牌到期倒计时、上次刷新时间与来源环境、全部配额池的 `Weekly` / `5h` 进度条与本地重置倒计时，以及按家族分组完整自动换行的支持模型列表（无截断）。
  - 在详情视图中，使用 `←` / `→` 切换上/下一个账号的详情卡片，使用 `↑` / `↓`、`PgUp` / `PgDn` 或 `g` / `G` 在卡片内上下滚动浏览完整模型清单，同样可直接按 `Space`、`l`、`r`、`k`、`Enter`/`s` 操作，按 `i` 或 `Esc` 返回主表。
- **`Gemini (5h / W)` 与 `Claude/GPT (5h / W)`**（窄屏紧凑表头为 `Gemini 5h/W` 与 `Claude/GPT 5h/W`）：斜杠左侧为 `5h`（五小时短期窗口剩余额度），右侧为 `W`（Weekly 周剩余额度），如 `100% /  72%`；单元格内对百分比做了固定宽度字符级填充与居中对齐，使上下各行的百分比与斜杠 `/` 保持严格垂直对齐。灰度专属池 `Argon (W)` 在所有账号均无该池数据时会自动隐藏，存在数据时自动展开。
- **`Policy`**：显示该账号在自动切号候选池中的顺位（如 `cand #1`、`cand #2`，未加入显示 `—`）；若候选池中的某个账号当前处于已禁用（`disabled`）状态，自动切号调度时会自动跳过该账号，并在该列明确标注为 `cand #2 (skip)`。
- **自适应分组底栏、内联输入与二次确认保护**：
  - 在常规窗口高度（`>= 14` 行）下，底部常驻展示两行冒号对齐的分组快捷键帮助（`Keys   : ...` 与 `Manage : ...`）；在矮窗口（`< 14` 行）下自动收拢为高优先级单行帮助，窄屏下自动精简缩写而不越界。
  - 最底行状态栏按优先级显示：内联文本输入（`o`/`O` 导出路径或 `l` 备注编辑，支持 `Ctrl+U` 清空与 UTF-8 字素级 `Backspace`）、`y` 二次确认（导出明文凭据、批量/全部禁用、删号）、临时操作反馈（**3 秒** info / **5 秒** error，含代理环境变量脱敏提示）以及存在勾选时的常驻 `Marked (...)` 摘要。

#### `tui` 完整快捷键一览表

| 按键 | 功能说明 |
| :--- | :--- |
| `↑` / `↓` 或 `PgUp` / `PgDn` | 主表模式：上下移动高亮光标（超出单屏时列表自动跟随滚动，首/末行内嵌定高 `...` 提示）；`i` 详情模式：在详情卡片内部上下滚动查看完整配额与模型列表 |
| `←` / `→` | 仅在 `i` 账号详情模式生效：切换查看上/下一个账号的详情卡片 |
| `g` / `Home` 或 `G` / `End` | 主表模式：跳转到账号列表首行（`g`）/ 末行（`G`）；`i` 详情模式：跳转到卡片顶部/底部 |
| **`Space`（空格）** | 勾选或取消勾选当前高亮账号（`Sel` 列显示 `+`，底栏常驻提示已选账号；按 `Esc` 一键清空全部勾选） |
| **`[`** / **`]`** | 将当前高亮账号上移一位（`[`）/ 下移一位（`]`），实时保存新顺序 |
| `Enter`（回车）或 `s` | 将官方 `agy` 凭据切换到当前高亮账号 |
| **`i`** | 打开或关闭当前高亮账号的只读详情卡片（完整展示重置倒计时、备注、UUID、令牌有效期、状态原因与可滚动的完整支持模型列表） |
| `r` / **`R`** | `r` 刷新已勾选的账号（无勾选时刷新当前高亮账号）；大写 **`R`** 以安全有界并发批量刷新全部未禁用账号（底栏实时显示进度，支持按 `Ctrl+C`、`q`、`Esc` 或发送系统信号随时安全中断并恢复终端） |
| **`c`** / **`C`** | `c` 批量切换已勾选账号的候选资格（无勾选时切换当前高亮账号）；大写 **`C`** 一键将所有未禁用账号按列表顺序加入候选池（若已全在池中，再按 **`C`** 则清空候选池并自动关闭策略总开关） |
| **`p`** | 开启或关闭 `policy` 自动切号总开关 |
| **`k`** | 主动清零后台 `daemon` 当前生效中的切号冷却期（与 `daemon --reset-cooldown` 等价，不争抢 `daemon.lock`，后台服务运行时同样直接生效） |
| `e` / **`E`** | `e` 启用已勾选账号（无勾选时启用当前高亮账号）；大写 **`E`** 无需确认，直接将池中所有处于 `disabled` 状态的账号全部恢复为启用 |
| `d` / **`D`**（必要时配合 **`y`** 确认） | `d` 禁用已勾选账号（勾选 `>= 2` 个时弹出 `y` 确认；无勾选时直接禁用当前高亮账号）；大写 **`D`** 弹出防误触确认提示，按 `y` 禁用全部未禁用账号，按 `Ctrl+C` 退出，按其他键取消 |
| **`l`** | 在底栏内联编辑当前高亮账号的自定义备注（`custom_label`，支持中文输入与 `Ctrl+U` 清空；留空回车清除备注，`Esc` 取消） |
| **`o`** / **`O`**（配合路径确认与 **`y`** 明文确认） | `o` 导出已勾选账号（无勾选时导出当前高亮单账号）；大写 **`O`** 导出库内全部账号。默认预填当前目录下带时间戳的防重名 JSON 路径（可按 `Ctrl+U` 清空并自定义，支持 `~/` 展开；误贴可识别凭据值时实时遮蔽为 `[REDACTED]` 并在进入确认前脱敏拒绝），回车后强制在底栏前置展示明文令牌风险与 `[y/N]` 确认提示（终端过窄无法完整展示风险提示时拒绝确认），按 `y` 以 `0600` 权限原子不覆盖写出标准 v2 备份包（默认通过内核原子不替换提交拒绝覆盖已存在文件，并拒绝软链/FIFO） |
| **`x`** 或 `Delete`（配合 **`y`** 确认） | 删除已勾选账号（无勾选时删除当前高亮账号）：按下后底栏弹出内联确认提示，按 `y` 确认执行删除（若包含当前生效 `*` 账号，确认后会按事务安全清空生效凭据槽位并同步移出策略候选池、账号索引与令牌血统归档；被删 ID 自动从勾选集移出）；按 `Ctrl+C` 立即退出，按其他键取消 |
| `q` 或 `Esc` 或 `Ctrl+C` / `Ctrl+D` | `q` 与 `Ctrl+C` / `Ctrl+D` 退出看板并恢复原终端界面；`Esc` 按当前上下文优先退出内联输入/二次确认、`i` 详情视图或清空已勾选账号，均未激活时退出看板 |

---

### 4.10 本地 Token 用量统计与请求明细：`stats summary` / `stats list`

官方 `agy` CLI（以及桌面端 Antigravity App）每次与模型对话时，都会在本机 `~/.gemini` 目录下的 SQLite 会话数据库（`conversations/*.db`）中记录当次请求的输入 Token、缓存命中 Token、输出 Token 与响应耗时。`agy-switch-cli stats` 提供两个显式子命令（不带子命令的裸 `stats` 会直接提示用法并返回退出码 `2`）：
- **`stats summary`**：按所选时间窗口聚合总输入/输出 Token、上下文缓存命中率、`TTFT`/`TPS` 分位性能指标与分模型汇总表（不传窗口参数时默认为 `--range today`）。
- **`stats list`**：按时间倒序（最新在前）列出单次模型调用明细行，展示时间、模型、总输入、缓存命中、命中率、输出、首字耗时、总耗时、吐字速度与状态（不传窗口参数时默认为 `--recent 10`）。

#### 核心设计边界
- **100% 纯离线、源目录零写入与有界流式扫描**：
  - 全程通过绑定已核验目录句柄的自定义零写入 SQLite VFS（`"agy_pinned_ro"`，叠加 `SQLITE_OPEN_READ_ONLY`、`PRAGMA query_only = true` 与内存临时表 `PRAGMA temp_store = MEMORY`，且仅凭真实 Linux OFD 锁才启用可靠共享内存读锁分支，无 OFD 支持时自动回退堆索引并执行全量元数据与文件头复验）读取本地数据库，每个数据库在单一读事务快照下完成扫描，无论面对普通库、关闭态 WAL 库还是活跃写入中的 WAL 库，均绝不在会话目录创建或修改任何 `-wal` / `-shm` / `-journal` 伴生文件，也不发起任何联网请求。
  - 在标准带索引的官方会话库与归档库上，扫描期采用 `steps` / `gen_metadata` 锁步流式游标、索引归档点查（同时打开的数据库句柄恒定 `<= 2`，即 `O(1)` 描述符占用）与容量上限 `500` 的有界最小堆（`O(500)` 候选内存），避免将全量历史调用全部缓存在内存中；对于缺少索引的异常表结构，不将大 BLOB 投入 SQLite 内存排序器，并施加显式行数预算（默认 `50,000` 行，超限时明确降级计入 `unreadable_databases`）。
  - 在 VFS 实际打开主库与伴生文件时全程强制执行普通文件校验与非阻塞读取，安全跳过符号链接、命名管道以及超过 `64 MiB` 的异常超大记录，并将损坏、无读取权限、超预算无索引表或目录读取异常准确计入 `unreadable_databases`。
- **不做联网 API 费用折算**：
  - Antigravity 订阅按周额度与 5 小时窗口计费，不同订阅套餐并无统一按量单价，因此工具直接展示真实的输入、缓存与输出 Token 数量，不做虚构的美元费用估算。
- **不跨界干预桌面端进程**：
  - `--source app` 仅用于只读统计桌面端留存的会话数据库。
  - 切号与运行控制命令（`switch`、`current`、`run`、`daemon`）始终专注服务无头 `agy` CLI，不会扫描或重启桌面端窗口。

#### 共享参数详解（`stats summary` 与 `stats list` 通用）

- **数据源选择：`--source <all|cli|app>`（默认值为 `all`）或外部目标目录 `--target <NAME>` / `--target-dir <DIR>`**
  - `all`（默认）：
    - 合并扫描当前 `HOME` 内支持的两个官方数据源（`~/.gemini/antigravity-cli/conversations/*.db` 与 `~/.gemini/antigravity/conversations/*.db` 及其 `token_usage_archive.db`），自动按同一会话文件与生成序号去重。
    - 在无桌面的远程 Linux 服务器或容器上，由于不存在 `~/.gemini/antigravity`，默认 `all` 会自动等效读取 `cli`；在同时装有 CLI 与桌面端 App 的机器上，默认直接展示完整结果，无需额外传参。
  - `cli`：仅只读扫描当前 `HOME` 下官方 `agy` CLI 的会话目录 `~/.gemini/antigravity-cli/conversations/*.db`。
  - `app`：
    - 仅只读扫描当前 `HOME` 下桌面端 Antigravity App 的会话目录 `~/.gemini/antigravity/conversations/*.db` 及 `token_usage_archive.db`。
    - 若原实时 `.db` 仍存在于磁盘，程序会从实时库补充提取步骤状态、流式响应延迟与吐字速度；若原实时 `.db` 已被清理而仅存于 `token_usage_archive.db`，`stats list` 会将该行状态标为 `arch`（`--json` 中为 `"archived"`）。
  - `--target <NAME>` / `--target-dir <DIR>`（与 `--source` 互斥）：
    - 复用同一套零写入只读 VFS（`"agy_pinned_ro"`）与 `--watch` 文件元数据指纹机制，仅扫描指定外部应用数据目录下的 `conversations/*.db`（及可选 `token_usage_archive.db`）；人类输出顶部 `Source` 行会将位于当前 `$HOME` 下的目录路径缩写为 `~/` 并在终端较窄时按路径段自动中间省略（极窄窗口下，具名 `--target` 退回纯别名，无别名的 `--target-dir` 退回 `external`）；`--json` 输出中 `source` 标为 `"external"` 并附加完整规范绝对路径的 `target` 元数据；同样拒绝符号链接穿越与官方目录/仓内目录双向重叠碰撞。
- **四组互斥的时间/条数窗口参数**
  - **按最近调用条数截取：`--recent <N>`（`1 <= N <= 500`，仅限完整长选项，无 `-n` 短参数）**
    - 在 `stats list` 中：不传任何窗口参数时，默认即为 `--recent 10`（展示最近 10 次模型调用）。
    - 在 `stats summary` 中：传入 `--recent <N>` 时，严格仅对按时间倒序最新的前 `N` 次调用计算 `Summary`（含 `TTFT`/`TPS` 的 `P10/P50/P90`）与 `Models` 聚合表。
  - **快捷预设、全量历史与任意天数范围：`--range <today|yesterday|<N>d|all>`**
    - 在 `stats summary` 中：不传任何窗口参数时，默认即为 `--range today`（匹配本机今天完整自然日 `00:00:00 ~ 23:59:59` 内的记录）。
    - `yesterday` 仅匹配本机昨天单个完整自然日。
    - `all` 匹配本地会话库中迄今为止留存的全部合法历史记录，并在顶部 `Range` 行与 `--json` 中自动展示实际记录覆盖的最早至最晚本地日期跨度（`stats list --range all` 按最新在前最多展示前 `500` 条并在超出时附带截断说明）。
    - `<N>d`（`1 <= N <= 36500` 的正整数，如 `1d`、`3d`、`7d`、`14d`、`30d`、`90d`）统一按包含本机今天（`today`）在内的最近 `N` 个本地自然日（`[today - (N - 1) .. today]`）计算。
  - **指定单个自然日：`--date <YYYY-MM-DD>`**
    - 精确筛选某一天（如 `--date 2026-11-15`）全天（`00:00:00 ~ 23:59:59`）的记录。
  - **自定义任意起止区间：`--from <YYYY-MM-DD> [--to <YYYY-MM-DD>]`**
    - 筛选从 `--from` 到 `--to`（含首尾两个完整自然日；省略 `--to` 时默认截止到本机今天 `today`）的历史数据。
  - **互斥与校验说明**：`--recent`、`--range`、`--date` 与 `--from/--to` 四组窗口参数彼此互斥，不能混用；非法数值或非法日期格式均返回退出码 `2` 并对输入执行防回显脱敏。
- **终端实时监控模式：`--watch [SECS]`（默认 `2` 秒，可选范围 `1..=3600` 秒）**
  - **停留刷新与零写入元数据指纹跳过**：启用 `--watch` 后，程序切换至终端备用屏幕（不污染原终端滚动历史）并按设定间隔持续巡检本地会话目录；每个周期先执行纯只读、不跟随符号链接的 `stat` 元数据指纹比对，若 `.db` / `-wal` / `-shm` 与归档库均未变动且未跨本地自然日，直接跳过 SQLite 解码，闲置资源开销极低；一旦产生新对话记录、跨过午夜 `00:00` 或终端窗口尺寸变化（`SIGWINCH`），在下一次巡检或当前扫描完成后无闪烁整帧刷新（窗口尺寸变化直接重绘缓存帧）。
  - **交互按键**：
    - `Tab`：在 `summary` 与 `list` 两个实时视图之间即时切换（未显式传窗口参数时，`summary` 沿用默认 `today`，`list` 沿用默认 `recent 10`；已显式传 `--range` / `--date` / `--from` / `--recent` 时两视图共享同一过滤条件）。
    - `r`：立即手动触发一次全量刷新。
    - `q`、`Esc` 或 `Ctrl+C`：干净退出并完整恢复原终端屏幕、光标与回显模式（同样响应 `SIGTERM` / `SIGHUP` / `SIGQUIT` 信号清理）。
  - **使用边界**：`--watch` 要求交互式终端（TTY）且不能与 `--json` 同时使用，违反时返回退出码 `2`。

#### 常用命令示例

```bash
# 1. 默认汇总本机今天（today）在全部数据源（all：CLI + App）中产生的用量与分位性能：
agy-switch-cli stats summary

# 2. 停留在终端实时刷新今日汇总或最近请求列表（默认每 2 秒检查更新，可传自定义秒数，运行中按 Tab 切换视图、r 刷新、q 退出）：
agy-switch-cli stats summary --watch
agy-switch-cli stats list --watch 5 --recent 20

# 3. 查看最近 10 次（默认）或指定最近 N 次（1..=500）模型调用明细：
agy-switch-cli stats list
agy-switch-cli stats list --recent 5
agy-switch-cli stats list --source cli --date 2026-11-19

# 4. 仅针对最近 50 次调用聚合汇总与分位延迟，或按历史天数范围聚合：
agy-switch-cli stats summary --recent 50
agy-switch-cli stats summary --range all
agy-switch-cli stats summary --range 7d
agy-switch-cli stats summary --from 2026-10-01 --to 2026-10-31

# 5. 输出标准 JSON 结构（零本地路径与邮箱泄露，供脚本记录或二次分析）：
agy-switch-cli stats summary --range 7d --json
agy-switch-cli stats list --recent 10 --json
```

#### （A）`stats summary` 终端输出排版与指标含义

常规宽屏终端（列宽 `>= 90` 且内容总宽未超出当前物理列数时）以及管道重定向默认采用双栏 `Summary` 与千分位逗号 `Models` 表：
```text
Source : all (~/.gemini/antigravity-cli + ~/.gemini/antigravity) · 12 db(s) · latest 2026-11-18 16:45
Range  : 7d (2026-11-12 .. 2026-11-18)

Summary
  Total input        : 241.7M (241,693,282)   Total output      : 1.2M (1,188,243)
  Input (cached)     : 204.0M (204,043,786)   Input (uncached)  : 37.6M (37,649,496)
  Cache hit          : 84.4%                  Requests          : 780
  TTFT (P10/P50/P90) : 2.2 / 6.4 / 24.8 s     TPS (P10/P50/P90) : 42.3 / 71.1 / 108.5 t/s

Models (sorted by total tokens)
  Model                           Reqs        Input       Cached    Hit%       Output        Total
  ────────────────────────────────────────────────────────────────────────────────────────────────
  Gemini 4 Carbon (High)           679  220,097,845  184,987,601   84.0%    1,049,520  221,147,365
  Gemini 4 Neon (Orchestrator)      86   20,976,818   18,586,982   88.6%      127,834   21,104,652
```

窄窗口（列宽 `< 90`，或宽屏下千分位数字总长超出终端列数时）会自动收起长路径、将 `Summary` 切换为单列垂直对齐并将 `Models` 数字紧凑化为 `K / M / B` 单位。各指标口径如下：
- **`Summary` 总览区**：
  - `Input (uncached)`：未命中上下文缓存的新增输入 Token（系统提示词与本轮输入之和）。
  - `Input (cached)`：直接命中服务端上下文缓存的输入 Token（`cached_tokens`）。
  - `Total input`：总输入 Token，等于 `Input (uncached) + Input (cached)`。
  - `Total output`：模型总输出 Token（`output_tokens`）。
  - `Cache hit`：上下文缓存命中率，等于 `Input (cached) / Total input`（固定保留一位小数；只要存在未缓存输入即封顶 `99.9%`，总输入为 `0` 时显示 `—`）。
  - `Requests`：所选窗口内的有效模型生成请求总次数。
  - `TTFT (P10/P50/P90)`：首字到达耗时（单位秒 `s`）的 10% / 50% / 90% 分位值。
  - `TPS (P10/P50/P90)`：流式阶段实测输出速度（`= live_output_tokens / live_streaming_duration`，单位 `t/s`）的 `P10 / P50 / P90` 分位值；分子与分母均固定取自实时生成记录的输出量与实时流式时长（即使同次请求的汇总输出量 `Total output` 优先采用了有效归档记录）。
  - **统一性能样本口径（`stats summary` 与 `stats list` 完全一致）**：仅当该次生成步骤为已完成状态（`steps.status == 3`，`DONE`）或经上下文压缩/轨迹清理保留的历史步骤（`steps.status == 5`，`CLEARED`；注：官方写入 `5` 后未单独留存原状态，但仍继续受下述错误、载荷与流式时长门控约束），且 `gen_metadata` 解码有效且无非空白的错误字符串、无非法或超限 `step_payload`（兼容含工具调用与简短回复）、无内部重试退避污染（`retries == 0`）、实时输出 `live_output_tokens > 0`、首字耗时 `ttft > 0` 且实时流式阶段耗时 **`live_streaming_duration >= 1.0s`**（过滤不足 `1.0` 秒的单块缓冲瞬时突发达峰，避免扭曲真实流式速度）时，才纳入实测 `TPS` 计算；明确排除已取消（`status == 6`）、已中断（`status == 12`）、报错与进行中步骤（无合格样本时显示 `—`）。
- **`Models` 分模型汇总表（共 7 列）**：
  - `Model` / `Reqs`：模型名称与该模型在所选窗口内的请求次数。
  - `Input` / `Cached` / `Hit%`：该模型的**总输入 Token**（`= uncached_input + cached_input`，与上方 `Total input` 口径一致）、其中命中缓存的输入 Token，以及精确到一位小数的缓存命中率（`= Cached / Input`；存在未缓存输入时最高封顶 `99.9%`）。
  - `Output` / `Total`：该模型的总输出 Token 与总消耗 Token（`= Input + Output`）。

#### （B）`stats list` 十列紧凑明细表与响应式布局说明

```text
Source : all (~/.gemini/antigravity-cli + ~/.gemini/antigravity) · 12 db(s) · latest 2026-11-19 08:25
Range  : recent 5 (2026-11-18 22:14 .. 2026-11-19 08:25)

Requests (newest first, showing 5)
  Time            Model                          In   Cache   Hit%    Out   TTFT    Dur  TPS  St
  ────────────────────────────────────────────────────────────────────────────────────────────────
  11-19 08:25:28  gemini-pro-orchestrator-neon   591.2K       0   0.0%    209  36.1s  36.9s    —  ok
  11-19 01:58:23  Gemini 4 Carbon (High)         587.1K  584.1K  99.5%   3.4K  15.0s  59.0s   78  ok
```

- **十列字段含义与极窄终端降级说明**：
  - `Time`：请求发起的本机本地时间。宽屏（`>= 95` 列或非 TTY 管道）显示 `MM-DD HH:MM:SS`（跨年份时自动扩展为 `YYYY-MM-DD HH:MM:SS`）；常规窄屏（`< 95` 列且达到十列最小可读宽度时）保留全部 10 列，将时间收紧为 `MM-DD HH:MM` 并动态压缩 `Model` 列宽；若终端宽度低于十列最小可读宽度（例如 `50` 列极窄分屏），自动切换为紧凑多行块格式展示单条请求，确保 `TPS`、`St` 等末尾字段不会被截断丢失。
  - `Model`：实时会话优先采用包含思考强度后缀的展示标签（protobuf field `21`，如 `Gemini 4 Carbon (High)`，与归档库 `token_usage_archive.db` 中的展示口径一致），在部分调用缺失 field `21` 时回退至原始模型 ID（protobuf field `19`，如 `gemini-pro-orchestrator-neon`）；所有名称均经过已知公共模型家族与受限命名语法过滤校验（自动兼容已知家族的新版本模型标签，拒绝本地非公开自由文本、路径、无扩展名文件名、邮箱、URL、IP 或异常字段，不通过者统一回退为 `"Unknown"`）。
  - `In` / `Cache` / `Out`：当次请求的**总输入 Token**（未缓存新增输入与缓存命中输入之和，与 `stats summary` 的 `Input` 口径一致）、其中命中上下文缓存的输入 Token 与总输出 Token（自适应紧凑单位；若存在有效归档记录则优先采用归档中的用量值）。
  - `Hit%`：当次请求的缓存命中率百分比（`= Cache / In`，固定保留一位小数，如 `99.5%`、`91.9%`、`0.0%`）；只要存在未缓存输入（即 `Cache < In` 且 `Cache > 0`），上限封顶为 **`99.9%`**（防止 `99.96%` 四舍五入误显示为 `100.0%`），仅当全部输入均命中缓存（`In == Cache` 且 `Cache > 0`）时才显示 `100.0%`（总输入 `In == 0` 时显示 `—`）。
  - `TTFT` / `Dur`：首字到达耗时与请求总耗时（`Dur = ttft + streaming_duration`，流式时长缺省时取 `ttft`）。
  - `TPS`：无单位后缀的四舍五入整数吐字速度（`= live_output_tokens / live_streaming_duration`，始终使用实时记录的输出量与实时流式时长；当 `Out` 取自有效归档记录时，`Out` 可以与 `TPS` 的分子不同）；采用与 `stats summary` 完全统一的事件时间戳与过滤条件（接受已完成 `steps.status == 3` 与经压缩/清理的历史步骤 `steps.status == 5`，严格排除 `6` 取消、`12` 中断与报错/进行中步骤，同时要求 `gen_metadata` 解码有效且无非空白的错误字符串、无非法/超限 `step_payload`、`retries == 0`、实时输出 `live_output_tokens > 0`、`ttft > 0` 且 **`live_streaming_duration >= 1.0s`**），包含工具调用回合与流式回复，流式阶段不足 `1.0s` 或不满足条件时显示 `—`。
  - `St`：请求状态简码，实时库映射为 `ok`（已完成 `status=3`）、`clr`（已压缩/清理出活跃上下文的历史步骤 `status=5`，JSON 为 `cleared`）、`err`（报错或无效 `status=4/7`，或 `gen_metadata` 含非空白错误字符串/解码失败）、`canc`（已取消 `status=6`，JSON 为 `canceled`）、`intr`（已中断 `status=12`，JSON 为 `interrupted`）、`run`（进行中或排队中）、`unk`（缺失或未识别的状态值），仅存于历史归档库且原实时 `.db` 已移除的记录显示为 `arch`。
- **上限截断说明**：按日期区间（`--range` / `--date` / `--from`）查询 `stats list` 时，最多输出最新的 `500` 条记录；若匹配总数超过 `500` 条，表头会自动注明 `(newest first, showing 500 of <总数> — capped at 500)`。
- **`stats summary --json` 与 `stats list --json` 机器输出说明（`schema_version: 1`）**：
  - **共享顶层字段**：`source`（官方模式为 `"all"` / `"cli"` / `"app"`，外部目录模式为 `"external"`）、可选 `target`（仅在显式传入 `--target` / `--target-dir` 时出现，包含 `{"name": "<别名或null>", "target_dir": "<规范绝对路径>"}`）、`range`（当使用 `--recent` 时为 `{"kind": "recent", "recent": N, "from": ..., "to": ...}`）、`databases_scanned`、`generations_scanned`、`skipped_large_records`、`unreadable_databases`、`last_activity`、`range_last_activity` 与 `generated_at`。
  - **`stats summary --json` 专属字段**：输出 `summary`、`performance` 与 `models` 数组（每项含 `model`、`request_count`、`total_input_tokens`、`uncached_input_tokens`、`cached_input_tokens`、`cache_hit_ratio`、`cache_hit_percent`、`output_tokens`、`total_tokens`）。
  - **`stats list --json` 专属字段**：输出 `total_matching`、`shown_count`、`truncated` 与 `items` 数组（每项含 `timestamp`、`local_time`、`model`、`uncached_input_tokens`、`cached_input_tokens`、`total_input_tokens`、`cache_hit_ratio`、`cache_hit_percent`、`output_tokens`、`total_tokens`、`ttft_seconds`、`duration_seconds`、`output_tps`、`status`）。
  - **隐私与模型名过滤约束**：在默认官方模式（`--source all|cli|app`）下，结构中不导出 `source_key`、本机路径或账号邮箱；显式使用外部 `--target` / `--target-dir` 时，JSON 顶层 `target.target_dir` 及外部目录初始化/I/O 错误诊断会包含所指定的外部绝对路径，对外分享前请先脱敏。模型名经已知公共模型家族与受限语法过滤，仅保留符合公共模型命名规范的标签，其余统一回退为 `"Unknown"`。

---

## 5. 标准退出码（`0..=8`）与 `--json` 脚本集成契约

添加 `--json` 后，机器输出契约按命令性质分类如下：

- **特殊命令与 `daemon` 三类输出说明**
  - **`tui` 与 `stats ... --watch`**：全屏交互终端界面，均与 `--json` 互斥并直接返回退出码 `2`。
  - **`run -- agy ...`**：在前置凭据准备、锁检查或进程检查失败时向 `stderr` 输出结构化错误信封；前置准备成功后直接将标准输入输出交给 `agy` 子进程并原样透传其退出码。
  - **`daemon --install --json`、`daemon --uninstall --json` 与 `daemon --reset-cooldown --json`**：属于一次性单目标管理命令，成功时向 `stdout` 输出包含 `"schema_version": 1, "ok": true` 的结果信封并返回退出码 `0`（其中 `daemon --install --json` 返回 `enabled_and_started` 与 `active_state` 以准确区分已启动 `active` 与启动中 `activating`；独立 `daemon --reset-cooldown --json` 返回 `cooldown_reset`、`cooldown_was_active`、`previous_cooldown_until` 字段，且 `daemon --install --reset-cooldown --json` 亦附加该三项字段），失败或参数非法时向 `stderr` 输出结构化错误信封并返回非零退出码。
  - **`daemon --once --json`**：单轮巡检完成后向 `stdout` 输出包含 `"schema_version": 1, "ok": true, "daemon": { ... }` 的结构化结果信封（包含 `outcome`、`phase`、不含本机路径的固定结构化 `reason`、`source_account_id`、`source_remaining_percentage`、`source_refreshed`、`target_account_id` 等字段）并返回退出码 `0`（仅当收到外部终止信号提前取消时静默返回 `0`）。
  - **前台常驻 `daemon --json`**：为避免多轮循环向 `stdout` 连续输出多个根 JSON 对象破坏单 JSON 解析，常驻模式在 `--json` 下保持正常轮次静默，仅在启动校验失败、单实例锁冲突或致命错误时向 `stderr` 输出错误信封并返回非零退出码；需要查看逐轮巡检日志时请在非 `--json` 模式下运行（或通过 `journalctl --user -u agy-switch-cli.service -f` 查看标准输出记录）。

- **单目标命令与前置参数/文件校验**
  - **执行成功时**：将结果信封（包含 `"schema_version": 1, "ok": true`）输出至 `stdout`，并返回退出码 `0`。
  - **执行失败时**：将结构化错误信封（包含 `"schema_version": 1, "ok": false, "error_code": "...", "message": "..."`）输出至 `stderr`，并返回对应的非零退出码（`1..=8`）。
  - **单启用账号刷新例外**：当执行 `refresh --all` 或 `quota --refresh --all` 但本地实际仅有 1 个未禁用账号、且该唯一账号刷新失败时，同样直接按单目标失败在 `stderr` 输出 `"ok": false` 信封并返回对应错误退出码。

- **多条目批量写入与批量联网命令**（包含 2 条及以上令牌的 `accounts add --from-file/--from-stdin`、涉及多账号的 `refresh --all` 与 `quota --refresh --all`，以及 `auth pending --resume`）
  - **汇总输出位置**：`--json` 模式下保持过程静默（不输出流式 `[k/N]` 进度文本），全部执行完毕后在 `stdout` 输出汇总信封（`"schema_version": 1, "ok": true`，此时 `stderr` 保持为空）。
  - **各命令的失败明细字段**：
    - 批量 `accounts add`：包含 `failed_count` 计数与 `failures` 数组。
    - 多账号 `refresh --all` 与 `auth pending --resume`：包含 `failures` 数组。
    - 多账号 `quota --refresh --all`：包含 `refresh_failures` 数组。
  - **进程退出码**：若其中任何一条遇到令牌已由远端签发但本地未能持久化（`issued_token_unpersisted`）等需恢复状态，立即按结构化错误信封返回退出码 `7`（`PartialCommitOrRecovery`）；其余常规单条失败情形统一汇总后返回退出码 `1`（`GeneralOrDataError`）。
  - **脚本判定方式**：自动化脚本应同时检查进程退出码是否为 `0`，以及 `stdout` 汇总对象中的失败明细字段（`failed_count` 或 `failures` / `refresh_failures` 数组长度）。

- **离线批量导入与只读巡检 / 统计聚合**
  - **`status --json`**：在 `stdout` 输出包含 `"schema_version": 1, "ok": true` 的只读健康巡检对象，除存储、事务日志与凭据槽位状态外，保留既有 `daemon_state_ok`、`daemon_paused_on_failure` 与 `agy_probe`，并包含结构化守护进程运行态 `daemon_runtime`（`mode` 取值为 `"not_running"` / `"systemd_service"` / `"manual"` / `"systemd_stopped"`，附 `running`、`pid`、`systemd_unit_installed`、`systemd_active_state`、`systemd_unit_file_state`、`cooldown_active`、`cooldown_remaining_secs`）以及可选桌面端探测 `antigravity_app_probe`（含 `checked`、`found`，检测到时附 `path` 与 `version`）。
  - **`accounts import --from-file ... --json`**：当导入文件本身可读且 JSON 结构合法时，将逐条导入、跳过与失败统计（`report.failed_count` 与 `report.failures`）输出至 `stdout` 并返回退出码 `0`；若文件无法打开或 JSON 语法损坏，则在 `stderr` 输出错误信封并返回非零退出码。
  - **只读 `quota --all --json`（不带 `--refresh`）**：作为全库本地缓存状态聚合接口返回退出码 `0`，脚本应读取每个账号对象内的 `evaluation` 字段判断单账号是否新鲜可用；而单账号严格查询 `quota [<ID|EMAIL>] --json` 在缓存处于 `Stale`、`Unknown` 或 `Unavailable` 时则严格返回退出码 `4`。
  - **只读 `stats summary --json` 与 `stats list --json`**：扫描本地会话 SQLite 数据库并在 `stdout` 输出 `schema_version: 1` 对象（`summary` 含 `summary`/`performance`/`models`，`list` 含 `items`/`total_matching`/`truncated`），返回退出码 `0`（若传入非法窗口参数或互斥组合则在 `stderr` 输出错误信封并返回退出码 `2`）。

进程退出码定义如下：

| 退出码 | 名称 | 代表的含义与处理建议 |
| :---: | :--- | :--- |
| `0` | `Ok` | 执行成功（`run -- agy` 模式下原样透传 `agy` 子进程退出码） |
| `1` | `GeneralOrDataError` | 本地文件损坏、磁盘权限错误，或批量操作中存在失败项 |
| `2` | `InvalidUsageOrAmbiguous` | 命令参数有误、策略阈值冲突（如 `minimum <= reserve`），或同名邮箱需改用 ID 区分 |
| `3` | `AccountNotFound` | 找不到指定账号，或尚未设置当前选中账号 |
| `4` | `QuotaUnavailableOrStale` | 目标账号尚无配额缓存，或在 `--json` 严格模式下缓存已过期/未知（加 `--refresh` 刷新即可） |
| `5` | `LockBusyOrConflict` | 并发锁繁忙，或安全拦截了使用已淘汰旧令牌覆盖新令牌的操作 |
| `6` | `AuthOrClientError` | OAuth 授权失败、令牌已被撤销（运行 `auth reauthorize` 重新授权即可恢复） |
| `7` | `PartialCommitOrRecovery` | 上次切号或清槽中途留下未完成日志，或远端已签发新令牌但本地落盘失败（修复磁盘条件后执行 `switch <ID\|EMAIL>` 等交互式写命令自动安全对账，或按提示重新授权恢复） |
| `8` | `EnvironmentNotReady` | `/proc` 不可读、传了 `--require-idle`（或使用 `run`）时检测到正在运行的 `agy` 进程、无可用 `systemd`、钥匙串后端未就绪，或本机已安装的 `agy --version` 探测失败 |

---

## 6. 可选配置文件（`config.json` 代理、后端、通知、外部槽位别名与自定义 OAuth 客户端）

`~/.local/share/agy-switch-cli/config.json` 是**完全可选**的配置文件。默认情况下该文件不存在，所有功能均可直接使用（程序已内置与官方 `agy` 一致的默认 OAuth 客户端 `antigravity_enterprise`）。只有当你遇到以下五类需求时，才需要手动创建它：

- **固定网络代理**：在 Linux 环境下，图形界面的“系统代理”设置并不会自动注入命令行终端或后台 `daemon` 服务的环境变量中。如果你不想每次在命令行手敲 `--proxy`，也不想每次新开终端都手动执行 `export https_proxy=...`，可以将代理地址写入 `config.json` 实现跨终端与后台守护进程的永久生效（此外，若终端环境变量中的代理格式异常而被忽略，人类输出模式会在联网时打印仅含变量名的脱敏提示）。
- **固定凭据后端模式**：希望跨所有终端与后台服务统一固定使用 `keyring`（纯钥匙串零本地文件）、`file`（纯本地文件）或 `dual`（强制双写），而非每次手动传 `--backend`。
- **控制桌面切号通知**：在 Linux 图形桌面上开关 `daemon` 的原生桌面通知推送（`notifications.enabled`），以及设置切号通知默认常驻屏幕或按桌面默认超时自动消失（`notifications.persistent`）。
- **配置外部目标目录别名（`targets`）**：为第三方工具（如 `t3code` 等通过 `agy acp --gemini-dir` 隔离凭据与会话数据库的宿主）冗长的应用数据目录路径定义简短别名，配合 `--target <NAME>` 在 `switch`、`current`、`quota`、`refresh`、`accounts add --from-local` 与 `stats summary/list` 中统一复用（详见下方 `6.2` 节）。
- **自定义 OAuth 客户端（进阶场景）**：你手头拥有由其他 Google Cloud OAuth 客户端签发的 `refresh_token`，或者希望使用自建 OAuth 客户端进行登录（详见下方 `6.3` 节零基础完整拆解）。

> **文件权限要求**：由于 `config.json` 中可能包含带密码的代理地址或 `client_secret` 密钥，创建时请将文件权限设为仅当前用户可读写的 `0600`（若权限过宽如 `0644`，`status` 与联网命令会输出安全提示，执行 `chmod 600 ~/.local/share/agy-switch-cli/config.json` 即可收紧权限）：
> ```bash
> install -m 0600 /dev/null ~/.local/share/agy-switch-cli/config.json
> ```

### 6.1 场景一：配置固定网络代理、凭据后端或桌面通知（最常见用法）

如果只需要配置网络代理、凭据后端或桌面通知，无需填写 `oauth` 部分，写入以下内容即可：

```json
{
  "schema_version": 1,
  "backend": "auto",
  "network": {
    "proxy_url": "socks5h://127.0.0.1:1080",
    "no_proxy": "internal.corp,10.0.0.0/8"
  },
  "notifications": {
    "enabled": true,
    "persistent": true
  }
}
```

- **`backend`**（可选）：固定指定凭据槽位后端（仅支持 `"auto"`、`"dual"`、`"file"`、`"keyring"` 四种值，省略时默认为 `"auto"`）。例如在桌面上若希望纯走钥匙串不在磁盘生成文件可设为 `"keyring"`，若希望只改磁盘文件而不碰系统钥匙串则可设为 `"file"`。生效优先级为：`命令行 --backend > AGY_SWITCH_CLI_BACKEND 环境变量 > config.json > 默认 auto`。
- **`network.proxy_url`**：支持 `http://`、`https://`、`socks5://`、`socks5h://`（或 `socks://`，由代理端解析远端域名，可避免本地 DNS 污染）、省略协议头的 `127.0.0.1:1080`，以及 `"direct"`（强制直连，忽略系统代理环境变量）。代理生效优先级为：`命令行 --proxy > AGY_SWITCH_CLI_PROXY > config.json > 系统环境变量（HTTPS_PROXY / HTTP_PROXY / ALL_PROXY）`。
- **`network.no_proxy`**：可选，逗号分隔的不走代理域名或网段列表。注意本机环回地址（`127.0.0.1`、`localhost`、`[::1]`，如 `--ssh` 登录回调监听端口）始终自动直连，不会被代理拦截。
- **`notifications.enabled`**（可选，省略时默认为 `true`）：控制 `daemon` 是否发送 Linux 桌面通知（`org.freedesktop.Notifications`）。无头服务器或无活跃桌面通知服务时会自动静默跳过；若希望在图形桌面上彻底关闭推送，可设为 `false`。生效优先级为：`命令行 --no-notify > AGY_SWITCH_CLI_NOTIFY 环境变量 > config.json > 默认开启`。
- **`notifications.persistent`**（可选，省略时默认为 `true`）：控制 `Account Switched` 切号成功通知（普通级别 `urgency=1`）的停留方式。设为 `true`（默认）时以 `expire_timeout=0` 常驻屏幕直至手动关闭，避免错过切号提醒；设为 `false` 时改为 `expire_timeout=-1`，交由桌面通知服务按默认数秒自动消失。`Auto-Switch Paused` 熔断暂停警告（严重级别 `urgency=2`）始终以 `expire_timeout=0` 常驻显示。

### 6.2 场景二：配置外部目标目录别名（`targets`）

当你需要通过 `--target <NAME>` 独立操作某个外部应用数据目录（例如 `t3code` 默认实例下的 `antigravity-acp` 目录，其中同时包含 `antigravity-oauth-token` 与 `conversations/*.db`，路径中的 `ac0a3dfd...` 为固定字符串 `"antigravity"` 的 SHA-256 哈希）时，可在 `config.json` 中添加可选的 `targets` 映射：

```json
{
  "schema_version": 1,
  "targets": {
    "t3": "~/.t3/userdata/providers/antigravity/ac0a3dfd6dddb20962cecff6ee5fe65e19d3923be20e52c5ab52ff877f7e4c32/antigravity-acp"
  }
}
```

- **别名键名规则**：长度为 `1..=64` 个 ASCII 字符，须以字母或数字开头，其余仅允许字母、数字、`-`、`_`、`.`，且不可使用保留名 `default`。
- **路径值规则**：必须为绝对路径（`/` 开头）或家目录相对路径（`~/` 开头，按当前已解析的 `HOME` 展开），指向应用数据目录本身（不要在末尾附加 `/antigravity-oauth-token`）；不允许指向官方 `~/.gemini/antigravity-cli`、`~/.gemini/antigravity` 或本工具自身的 `data_dir` / `cache_dir`。
- 配置完成后即可在 `switch`、`current`、`quota`、`refresh`、`accounts add --from-local` 以及 `stats summary/list [--watch]` 中直接使用 `--target t3`，无需每次输入完整路径。

### 6.3 场景三：零基础读懂并注册自定义 OAuth 客户端（完整字段详解）

#### 先搞懂背景原理：什么是 OAuth 客户端？为什么会有“令牌绑定规则”？

- **OAuth 客户端（`client_id` + `client_secret`）的通俗含义**：
  - 在 Google OAuth 2.0 授权体系中，每一次登录与令牌续期都同时涉及两方身份：一方是**你的个人 Google 账号**（如 `alice@example.com`），另一方是**发起登录请求的客户端应用身份**（由一串公开的客户端编号 `client_id` 和配对的应用密钥 `client_secret` 组成，在 Google Cloud Console 控制台中申请创建）。
- **Google 的刷新令牌严格绑定规则（核心原因）**：
  - 当你完成一次登录拿到一条长期有效的 `refresh_token` 时，Google 服务端会将这条 `refresh_token` 与当时签发它的那个 `client_id` 永久绑定。
  - 后续每隔 1 小时用 `refresh_token` 换取新的短期访问令牌（`access_token`）时，**必须提交当年签发它的同一组 `client_id` 与 `client_secret`**；如果换用另一组客户端去刷新，Google 会直接拒绝并返回 `unauthorized_client` 或 `invalid_client` 错误。
- **为什么绝大多数用户完全不需要折腾这一节？**
  - 本工具已经内置了官方 `agy` 使用的标准客户端（标识为 `antigravity_enterprise`）。只要你的账号是通过本工具直接 `auth login` 登录的，或者是从官方 `agy` / 原桌面版 `agy-switch` 导入的，内置客户端开箱即匹配，**无需填写任何 `oauth` 配置**。
- **什么具体场景下才需要注册自定义 OAuth 客户端？**
  - **场景 A**：你在自己的 Google Cloud 项目中自建了一套 OAuth 2.0 客户端凭据，希望用自己的客户端登录或管理账号；
  - **场景 B**：你手头有一批由企业内部平台或其他第三方兼容工具签发的 `refresh_token`，需要将签发它们的那组 `client_id` 与 `client_secret` 登记进来，才能让本工具正常帮它们自动续期。

如果需要额外注册自定义 OAuth 客户端，可按如下完整结构编写：

```json
{
  "schema_version": 1,
  "network": {
    "proxy_url": "socks5h://127.0.0.1:1080"
  },
  "oauth": {
    "active_client_key": "antigravity_enterprise",
    "required_scopes": [
      "openid",
      "https://www.googleapis.com/auth/cloud-platform"
    ],
    "clients": [
      {
        "key": "my_custom_oauth",
        "label": "My Custom GCP OAuth",
        "client_id": "1234567890-example.apps.googleusercontent.com",
        "client_secret": "<YOUR_OAUTH_CLIENT_SECRET>",
        "request_scopes": [
          "openid",
          "https://www.googleapis.com/auth/userinfo.email",
          "https://www.googleapis.com/auth/userinfo.profile",
          "https://www.googleapis.com/auth/cloud-platform"
        ],
        "required_scopes": [
          "openid",
          "https://www.googleapis.com/auth/cloud-platform"
        ]
      }
    ]
  }
}
```

#### `oauth` 配置段全部字段说明

| 字段路径 | 是否必填 | 默认值 | 详细作用说明 |
| :--- | :---: | :--- | :--- |
| **`oauth.active_client_key`** | 可选 | `"antigravity_enterprise"` | **全局默认客户端标识**。保持 `"antigravity_enterprise"`（或直接省略该字段）即默认使用内置官方客户端；若改为下方 `clients` 里注册的某个 `key`（如 `"my_custom_oauth"`），则执行 `auth login` 或 `accounts add` 未传 `--client` 时默认使用该自定义客户端。 |
| **`oauth.required_scopes`** | 可选 | `["openid", ".../cloud-platform"]` | **全局最低必需权限（Scope）列表**。当某个账号记录了实际获授权限但缺少列表中的必需项时，切号与刷新会提前拦截并提示运行 `auth reauthorize` 补齐授权。一般保持默认或省略即可。 |
| **`oauth.clients[].key`** | 注册时必填 | — | **客户端唯一短名称**（字母、数字、`-` 或 `_`，自动转为小写，如 `"my_custom_oauth"`）。用于在命令行通过 `--client <KEY>` 指定该客户端，并持久化记录在对应账号的令牌元数据中。*(若将 `key` 设为 `"antigravity_enterprise"`，则会覆盖内置同名客户端的参数。)* |
| **`oauth.clients[].client_id`** | 注册时必填 | — | Google Cloud Console 中创建的 OAuth 2.0 客户端 ID（通常以 `.apps.googleusercontent.com` 结尾）。 |
| **`oauth.clients[].client_secret`** | 注册时必填 | — | 与上述 `client_id` 配对的客户端密钥（Client Secret）。程序内部对所有日志与调试输出均做了自动脱敏处理，不会回显该密钥原文。 |
| **`oauth.clients[].label`** | 可选 | 同 `key` | 便于区分的显示备注名，会在运行 `agy-switch-cli auth clients` 时展示。 |
| **`oauth.clients[].request_scopes`** | 可选 | 内置标准 Scope 集 | 使用该客户端执行 `auth login` / `reauthorize` 跳转浏览器登录时，向 Google 申请的权限列表。无特殊需求时直接省略即可。 |
| **`oauth.clients[].required_scopes`** | 可选 | 继承外层 `oauth.required_scopes` | 单独针对该客户端生效的最低必需权限列表；省略时自动沿用外层 `oauth.required_scopes`。 |

#### 如何验证与使用自定义客户端

1. **检查配置是否生效**：保存 `config.json` 后运行以下命令，确认新客户端已出现在列表中（带 `*` 号的为当前默认生效客户端）且无格式警告：
   ```bash
   agy-switch-cli auth clients
   ```
2. **为指定账号绑定自定义客户端**：登录或添加由该客户端签发的账号时加上 `--client <KEY>`：
   ```bash
   agy-switch-cli auth login --client my_custom_oauth --label "custom-oauth"
   agy-switch-cli accounts add --client my_custom_oauth
   ```
   绑定完成后，该账号档案会自动记住 `oauth_client_key = "my_custom_oauth"`，后续日常执行 `switch`、`quota --refresh`、`run` 或 `daemon` 自动续期时都会自动匹配这组客户端凭据，无需每次重复传入 `--client`（即使混用多个不同客户端签发的账号也能各自独立续期）。
3. **无文件环境变量注入方式（适合 Docker 容器）**：除了写 `config.json`，也可以通过环境变量动态注入（优先级高于 `config.json`）：
   - `ANTIGRAVITY_OAUTH_CLIENTS="key|client_id|client_secret|label"`（多项之间用分号 `;` 分隔）；
   - `ANTIGRAVITY_OAUTH_CLIENT_KEY="<KEY>"`（指定默认客户端短名称）；
   - `ANTIGRAVITY_REQUIRED_SCOPES="openid https://www.googleapis.com/auth/cloud-platform"`（全局最低必需 Scope 列表，支持空格、逗号 `,` 或分号 `;` 分隔）。

---

## 7. 后台常驻运行指南（`systemd --user` 与无 `systemd` 的 Docker 容器环境）

`agy-switch-cli daemon` 本身设计为标准前台长运行进程（内置 `daemon.lock` 单实例互斥锁与 `SIGTERM` 优雅退出机制），不自行向后台分裂（fork）。下面分别说明在带有 `systemd` 的常规 Linux 系统上，以及在**没有 `systemd` 的 Docker 容器（如远程开发容器、云算力容器、WSL 精简环境）**中，如何让 `daemon` 在后台稳定常驻运行。

### 7.1 常规 Linux 系统（使用 `daemon --install` 管理 `systemd --user` 用户级服务）

在支持 `systemd` 的 Linux 服务器或桌面上，建议使用**当前普通用户的 `--user` 服务**（而非 `root` 系统级服务）来托管 `daemon`。这样可以保证后台服务与你平时运行 `agy` 的终端共享同一个 `$HOME` 目录、相同的文件属主与一致的 `~/.gemini/antigravity-cli` 凭据路径，避免因 `root` 权限写出普通用户无权读取的文件。

程序内置了 `daemon --install` 与 `daemon --uninstall`，无需手动复制修改服务模板文件即可一键完成部署（若当前处于无 `systemd` 的 Docker 容器或精简 WSL 中，`daemon --install` 会自动识别并提示改用下方第 `7.2` 节方案）：

```bash
# 第 1 步：启动服务前，先确认已添加账号并开启了自动切号策略（默认 reserve 10% / minimum 30%）
agy-switch-cli policy set --enabled true --all-candidates
agy-switch-cli policy show

# 第 2 步：一键生成 ~/.config/systemd/user/agy-switch-cli.service 并自动设置开机自启 + 立即启动
# （程序会自动写入当前可执行文件真实路径、数据目录与最小权限沙盒边界；也可附加 --interval / --cooldown 固化间隔）
agy-switch-cli daemon --install

# 第 3 步：允许当前用户的后台服务在断开 SSH 连接后继续保持运行（远程服务器建议执行）
sudo loginctl enable-linger "$USER"

# 日常运维与卸载命令：
systemctl --user status agy-switch-cli.service        # 查看服务当前运行状态
journalctl --user -u agy-switch-cli.service -f        # 实时查看巡检与切号日志
systemctl --user restart agy-switch-cli.service       # 修改 config.json 后重启服务
agy-switch-cli daemon --uninstall                     # 停止服务、取消开机自启并移除 unit 文件
```

#### 生成的 `agy-switch-cli.service` 内容与路径适配规则

- **自动适配真实可执行文件路径（不写死 `~/.local/bin`）**：
  - 执行 `agy-switch-cli daemon --install` 时，程序通过 Linux 内核接口 `/proc/self/exe` 动态读取当前运行二进制的真实绝对路径并写入服务单元的 `ExecStart=` 字段。
  - 在 Arch Linux / EndeavourOS 上通过 AUR 安装后，写入的启动命令为 `/usr/bin/agy-switch-cli daemon`；若通过预编译包或源码手动安装至 `~/.local/bin`，则写入 `~/.local/bin/agy-switch-cli daemon`（若安装时附加了 `--backend`、`--interval`、`--cooldown`、`--no-notify`，也会一并固化至 `ExecStart=`；若附加 `--reset-cooldown`，仅在启动前一次性清零历史冷却，绝不写入 `ExecStart=`）。
- **切换安装方式或修改启动参数后的刷新方法**：
  - 若你先前使用 `~/.local/bin/agy-switch-cli` 执行过 `daemon --install`，随后改用 AUR 安装并删除了 `~/.local/bin/agy-switch-cli`，只需在新安装环境再次运行一次 `agy-switch-cli daemon --install`，服务单元中的 `ExecStart=` 即会自动刷新为 `/usr/bin/agy-switch-cli`；若旧服务当时仍在运行，随后补执行 `systemctl --user restart agy-switch-cli.service` 即可平滑切换至新二进制与新参数。
- **内置最小权限沙盒与目录边界**：
  - 自动生成的单元文件内置 `UMask=0077`、`Restart=on-failure`（`RestartSec=10`）、`Environment="RUST_LOG=agy_switch_cli=info"`、数据目录 `AGY_SWITCH_CLI_DATA_DIR`（及自定义 `XDG_CACHE_HOME` 时的对齐环境变量），并启用 `NoNewPrivileges=true`、`PrivateTmp=true`（非 `/tmp` 环境时）、`ProtectSystem=strict` 与 `ReadWritePaths=`（仅放行官方槽位目录 `~/.gemini/antigravity-cli`、独立数据目录与全局锁/缓存目录）。
  - 如需查看本机当前实际生成的完整单元内容，可执行 `systemctl --user cat agy-switch-cli.service`。

### 7.2 无 `systemd` 的 Docker 容器环境（后台常驻替代方案）

大多数 Docker 容器（如 VS Code DevContainer、各类云端 GPU 容器）没有以 `systemd` 作为一号进程，执行 `systemctl` 会报错提示不支持。由于 `agy-switch-cli daemon` 内置了**独占单实例锁**（若后台已有实例在运行，重复启动的新进程会自动退出，不会跑出多个重复进程），在容器内你可以按环境条件任选以下四种方式达到与 `systemd` 相同的后台常驻效果：

*(前置提示：在极精简的基础容器镜像中若遇到 HTTPS 证书报错，请先通过包管理器安装 `ca-certificates` 根证书包。)*

#### 方式一：`nohup` 纯后台挂起 + 登录自动拉起（零额外依赖，所有容器通用）

无需安装任何第三方工具，直接将 `daemon` 挂入后台并将日志输出到私有文件即可：

```bash
# 1. 创建私有日志目录并启动后台守护进程（断开当前终端后依然继续运行）
mkdir -p -m 0700 ~/.local/state/agy-switch-cli
RUST_LOG=agy_switch_cli=info nohup ~/.local/bin/agy-switch-cli daemon \
  >> ~/.local/state/agy-switch-cli/daemon.log 2>&1 </dev/null &

# 2. 查看后台进程是否在运行：
pgrep -fa "agy-switch-cli daemon"

# 3. 实时查看巡检与切号日志（按 Ctrl+C 仅退出日志查看，不会停掉后台进程）：
tail -f ~/.local/state/agy-switch-cli/daemon.log

# 4. 需要停止后台守护进程时，发送优雅终止信号：
pkill -TERM -f "agy-switch-cli daemon"
```

**进阶技巧（容器重启后打开终端自动后台拉起）**：容器重启后后台进程会被清空，你可以把下面这段检活代码追加到容器内的 `~/.bashrc` 末尾。每次进入容器终端时若检测到 `daemon` 未运行就会自动在后台静默拉起（配合程序内置的 `daemon.lock` 文件锁，即使同时打开多个终端窗口也只会保留唯一一个实例）：

```bash
# 追加到 ~/.bashrc，实现进入容器自动确保后台 daemon 在线
if ! pgrep -f "$HOME/.local/bin/agy-switch-cli daemon" >/dev/null 2>&1; then
  mkdir -p -m 0700 "$HOME/.local/state/agy-switch-cli"
  RUST_LOG=agy_switch_cli=info nohup "$HOME/.local/bin/agy-switch-cli" daemon \
    >> "$HOME/.local/state/agy-switch-cli/daemon.log" 2>&1 </dev/null &
fi
```

#### 方式二：使用 `tmux` 后台会话托管（方便随时切入查看）

如果容器内安装了常用的 `tmux`，可以用一个命名后台会话来承载 `daemon`：

```bash
# 在后台创建名为 agy-daemon 的会话并运行守护进程
tmux new-session -d -s agy-daemon 'RUST_LOG=agy_switch_cli=info ~/.local/bin/agy-switch-cli daemon'

# 随时切入查看实时输出（看完了按 Ctrl+B 松开后再按 D 即可退回后台，进程继续运行）
tmux attach -t agy-daemon

# 停止并关闭该后台会话
tmux kill-session -t agy-daemon
```

#### 方式三：使用 `supervisord` 托管（支持异常退出自动拉起，最接近 `systemd`）

许多云端开发容器或算力镜像预装了 `supervisor` 进程管理器。如果你希望获得与 `systemd` 完全一致的**开机自启 + 异常退出自动重启（`autorestart`）**能力，可创建配置文件 `/etc/supervisor/conf.d/agy-switch-cli.conf`（请将示例中的 `appuser` 与 `/home/appuser` 替换为你容器内实际运行 `agy` 的用户名和主目录）：

```ini
[program:agy-switch-cli]
command=/home/appuser/.local/bin/agy-switch-cli daemon
user=appuser
environment=HOME="/home/appuser",RUST_LOG="agy_switch_cli=info"
autostart=true
autorestart=true
startsecs=3
stopsignal=TERM
stdout_logfile=/home/appuser/.local/state/agy-switch-cli/daemon.log
redirect_stderr=true
```

保存后（先确保日志目录 `mkdir -p -m 0700 ~/.local/state/agy-switch-cli` 已存在），执行以下命令加载并管理：

```bash
supervisorctl reread
supervisorctl update
supervisorctl status agy-switch-cli    # 查看运行状态
supervisorctl restart agy-switch-cli   # 重启后台守护进程
supervisorctl stop agy-switch-cli      # 停止后台守护进程
```

#### 方式四：配合容器内的 `cron` 定时执行单次检查（无常驻进程）

如果容器内已经运行了 `cron` 定时任务服务，而你不想保留长驻后台进程，也可以利用 `daemon --once`（执行完单轮检查与按需切号后立即退出）配合 `crontab -e` 添加一条每小时执行一次的规则：

```cron
0 * * * * RUST_LOG=agy_switch_cli=info $HOME/.local/bin/agy-switch-cli daemon --once >> $HOME/.local/state/agy-switch-cli/daemon.log 2>&1
```

---

## 8. 常见问题解答（FAQ）

- **问：`auth login` 点完允许后，浏览器跳到 `127.0.0.1` 提示“无法访问此网站”，是否代表登录失败？**
  - **答**：没有失败。默认的免配置登录模式不需要在本地电脑启动监听服务，授权码已经包含在浏览器顶部地址栏那串 `http://127.0.0.1:...` 网址中。将该网址完整复制并粘贴回终端按回车即可完成登录。
- **问：登录或批量添加账号时遇到网络波动，查询邮箱信息超时报错，刚换出的令牌会丢失吗？**
  - **答**：不会丢失。新令牌在签发瞬间已以 `0600` 权限暂存在本地 `state/pending_auth/` 目录中。待网络恢复后，执行 `agy-switch-cli auth pending --resume` 即可继续完成绑定。
- **问：在 Linux 图形桌面上使用 `--backend file` 执行了 `switch`，为什么直接输入 `agy` 仍在使用旧账号？**
  - **答**：图形桌面的系统钥匙串（GNOME Keyring / KDE Wallet）读取优先级高于本地 `antigravity-oauth-token` 文件。如果你显式指定了 `--backend file`（或在 `config.json` 中固定了 `"backend": "file"`），程序只会更新本地文件而不修改系统钥匙串。可通过以下任一方式处理：
    - 恢复默认的 `--backend auto`（或显式使用 `--backend dual` / `--backend keyring`），程序会自动同步更新桌面系统钥匙串，切完直接输入 `agy` 即可。
    - 若你确实希望保留桌面钥匙串原账号不动、仅让终端里的 `agy` 使用新文件槽位，则在启动时使用可选方式 `agy-switch-cli --backend file run -- agy`（显式指定 `file` 后端时会自动为子进程屏蔽桌面钥匙串）。
- **问：我已经开启了桌面代理软件的“系统代理”，为什么在终端里不加 `--proxy` 直接运行联网命令（如 `quota --refresh` 或 `accounts add`）仍然提示网络连接失败？**
  - **答**：在 Linux 系统中，图形界面的“系统代理”只修改桌面配置，不会自动向新打开的命令行终端注入代理环境变量。按你的使用场景任选以下三种方式即可解决：
    - **单次临时使用**：在命令中直接加上 `--proxy http://127.0.0.1:7890`（请替换为实际代理端口）。
    - **当前终端内免重复传参**：在当前终端执行 `export https_proxy=http://127.0.0.1:7890`（或将其写入 `~/.bashrc` / `~/.zshrc`）。
    - **所有终端与后台 `daemon` 持久生效**：按第 `6.1` 节编辑 `~/.local/share/agy-switch-cli/config.json`，写入 `"network": { "proxy_url": "http://127.0.0.1:7890" }`。
- **问：某个账号刷新后显示 `verify-blocked`（`[verification required]`），应该怎么解锁？**
  - **答**：该状态表示 Google CloudCode 返回了 `403 VALIDATION_REQUIRED`，需要在官方 `agy` 中打开验证链接完成扫码或网页安全核验（重新授权 `auth reauthorize` 无法代替网页验证）。按三步即可解锁：
    - 直接使用 `agy-switch-cli switch <ID|EMAIL>`（或在 `tui` 中选中后按 `Enter`，或用可选的 `run --account <ID|EMAIL> -- agy`）切入该账号（人工切号会放行，同时保留 `verify-blocked` 标记确保后台 `daemon` 不会误选或抢切槽位）。
    - 启动官方 `agy`，按界面提示打开网页或扫码完成 Google 安全验证。
    - 验证完成后执行 `agy-switch-cli refresh <ID|EMAIL>`（或在 `tui` 按 `r`），当最终采用主环境未阻断的有效观测后即自动清除 `verify-blocked` 标记并恢复参与自动切号。
- **问：日常使用时，手动切号、可选的 `run` 包装启动与后台 `daemon` 各自适合什么场景？**
  - **答**：三种方式定位清晰，可按实际需求选用：
    - **交互式看板或手动切号（`tui` / `switch`）**：适合日常按需查看额度并手动切换账号，切完直接运行 `agy` 即可。
    - **可选启动包装器 `run`**：适合单次临时指定某个账号（`run --account <ID|EMAIL> -- agy`），或在图形桌面上通过 `--backend file run -- agy` 将终端 `agy` 登录态与桌面端钥匙串隔离。
    - **后台守护进程 `daemon`**：适合已配置 `policy` 且希望后台静默监控额度、在触及保留线时提前换好凭据槽位，省去重开 `agy` 时手动进看板切号的步骤。
- **问：为什么在命令里调小了 `--cooldown`，后台 `daemon` 仍然提示处于冷却期？如何立即解除冷却？**
  - **答**：每次自动切号提交后，程序会将绝对冷却截止时间戳（`切号时间 + cooldown`）持久化保存在 `state/daemon_state.json` 中，调小 `--cooldown` 仅对之后新触发的切号生效，不会追溯改写尚未到期的旧截止时间。按运行场景任选以下方式即可立即解除冷却：
    - **已有 `systemd --user` 服务或另一终端前台 `daemon` 正在运行**：直接执行 `agy-switch-cli daemon --reset-cooldown`（零网络请求、不冲突单实例锁，运行中的守护进程在下一次唤醒时自动脱离冷却）。
    - **使用单次巡检或 `cron`**：执行 `agy-switch-cli daemon --once --reset-cooldown`，在单轮核查前一步清零冷却并立即评估切号。
    - **重新部署或刷新 `systemd` 服务**：执行 `agy-switch-cli daemon --install --reset-cooldown`，在预检通过后一次性清零旧冷却（该参数不会写入 `ExecStart=`）。
- **问：桌面切号成功通知默认会一直停留在屏幕上，能否改为数秒后自动消失或彻底关闭？**
  - **答**：为防止在后台自动切号时错过提醒，`Account Switched` 默认采用常驻显示（`expire_timeout=0`，不附带严重告警标识）。你可以按习惯自由调整：
    - **改为桌面默认数秒后自动消失**：在 `~/.local/share/agy-switch-cli/config.json`（权限 `0600`）中添加 `"notifications": { "persistent": false }`（切回 `expire_timeout=-1`；熔断暂停警告 `Auto-Switch Paused` 仍保持常驻）。
    - **彻底关闭桌面通知**：在 `config.json` 中设置 `"notifications": { "enabled": false }`，或启动 `daemon` 时传入 `--no-notify`（也可执行 `agy-switch-cli daemon --install --no-notify` 后配合 `systemctl --user restart agy-switch-cli.service` 生效）。

---

## 9. 完整卸载与本地遗留文件清理清单

在 Linux 系统中，包管理器（如 `pacman`、`yay`、`paru`）或手动删除二进制文件都只负责移除“程序本身”，**不会自动删除你主目录（`~`）下的个人配置与数据文件夹**，这是 Linux 防止更新或重装软件时误删用户数据的通用保护机制。如果你希望在卸载 `agy-switch-cli` 时连同本地账号库、缓存与服务配置一并清理干净，请按以下四个步骤操作。

### 第 1 步：停止并移除后台守护服务（若从未启用 `daemon` 可跳过）

- **通过 `systemd --user` 安装过后台服务的环境**：务必先在卸载程序之前执行一键卸载服务命令：
  ```bash
  agy-switch-cli daemon --uninstall
  ```
  该命令会自动停止运行中的后台服务、取消开机自启、安全删除 `~/.config/systemd/user/agy-switch-cli.service`，并通知 `systemd` 重载配置。
- **在无 `systemd` 容器环境中手动配置过后台常驻的情况**（参见第 `7.2` 节）：按你当时选用的托管方式停止进程并移除对应自启项：
  - 使用 `nohup`：执行 `pkill -TERM -f "agy-switch-cli daemon"`，并删除 `~/.bashrc` 中你追加的自动拉起片段。
  - 使用 `tmux`：执行 `tmux kill-session -t agy-daemon`。
  - 使用 `supervisord`：执行 `supervisorctl stop agy-switch-cli`，随后移除 `/etc/supervisor/conf.d/agy-switch-cli.conf` 并执行 `supervisorctl reread && supervisorctl update`。
  - 使用 `cron`：执行 `crontab -e` 删除包含 `agy-switch-cli daemon --once` 的定时任务行。

### 第 2 步：移除可执行程序本身（按当初的安装方式二选一）

- **手动安装（下载预编译包或源码编译）**：
  ```bash
  rm -f ~/.local/bin/agy-switch-cli
  ```
  如果你当初将二进制放到了自定义目录（而非 `~/.local/bin`），可先执行 `command -v agy-switch-cli` 确认准确路径后再删除。
- **Arch Linux / EndeavourOS（通过 AUR 安装）**：
  ```bash
  yay -Rns agy-switch-cli-bin
  # 或使用 paru / pacman：
  # paru -Rns agy-switch-cli-bin
  # sudo pacman -Rns agy-switch-cli-bin
  ```
  包管理器会自动移除 `/usr/bin/agy-switch-cli`、`/usr/share/licenses/agy-switch-cli-bin/` 与 `/usr/share/doc/agy-switch-cli-bin/`。

### 第 3 步：彻底清理本工具在主目录下生成的全部文件（可选）

如果你日后还可能重装，建议在执行第 2 步卸载程序前先导出备份（`agy-switch-cli accounts export --output backup.json --include-secrets`，并确认命令成功返回且备份文件已生成后再清理数据目录）；若确认不再保留任何数据，可参考下表逐一或一键清理：

| 本地路径（括号内为自定义环境变量时的对应位置） | 存放内容与用途说明 | 是否建议删除 |
| :--- | :--- | :--- |
| `~/.local/share/agy-switch-cli/`<br>（或 `$XDG_DATA_HOME/agy-switch-cli/`、`--data-dir` 指定目录） | 本工具的独立数据目录：包含账号索引 `index.json`、各账号 OAuth 凭据 `accounts/*.json`、自动切号策略 `policy.json`、可选代理/客户端配置 `config.json`、事务状态 `state/` 与目录锁 `locks/`。 | 彻底卸载不再使用时可删 |
| `~/.cache/agy-switch-cli/`<br>（或 `$XDG_CACHE_HOME/agy-switch-cli/`） | 缓存与全局跨目录锁：包含官方客户端版本号缓存 `ua_version_cache.json` 以及账号槽位/钥匙串锁 `locks/`。 | 彻底卸载时可安全删除 |
| `~/.config/systemd/user/agy-switch-cli.service`<br>（或 `$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service`） | 用户级 `systemd` 服务单元文件（第 1 步执行 `daemon --uninstall` 时已自动清除；若先卸载了程序，可检查确认其已不存在）。 | 彻底卸载时应删除 |
| `~/.local/state/agy-switch-cli/` | 仅在无 `systemd` 的容器环境中按第 `7.2` 节手动重定向保存 `daemon.log` 时才会存在；标准环境下不会创建该目录。 | 若存在且无需查日志可删 |

确认无需保留本工具保存的账号库与缓存后，在终端执行以下一条命令即可全部清理：

```bash
rm -rf ~/.local/share/agy-switch-cli ~/.cache/agy-switch-cli ~/.local/state/agy-switch-cli
```

### 第 4 步：明确哪些外部目录属于官方 `agy` 或上游工具（默认无需删除）

以下路径不属于 `agy-switch-cli` 的安装残留，卸载本工具时保留它们可以确保你的官方 `agy` 继续保持当前账号正常登录，避免误删工作环境：

- **官方 `agy` 生效凭据槽位与系统钥匙串**：
  - 磁盘槽位文件：`~/.gemini/antigravity-cli/antigravity-oauth-token`（以及对话历史数据库 `~/.gemini/antigravity-cli/`、`~/.gemini/antigravity/`）。
  - 图形桌面系统钥匙串（GNOME Keyring / KDE Wallet）中标签为 `Password for 'antigravity' on 'gemini'`（属性 `service="gemini", username="antigravity"`）的条目。
  - 这些位置保存的是官方 `agy` 自身当前正在使用的登录身份；只有当你希望连同官方 `agy` 一起退出登录时，才需要自行删除它们。
- **上游桌面端数据目录 `~/.antigravity_tools/`**：
  - 这是桌面端工具 `agy-switch` 自身的存储目录；`agy-switch-cli` 仅在执行 `accounts import --from-legacy` 时以只读方式读取该目录，从未向其中写入或修改任何文件。
