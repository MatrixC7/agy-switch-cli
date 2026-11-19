# `agy-switch-cli` 完整使用、配置与部署手册

> 返回首页：[README.md](../README.md) ｜ 技术架构与验收台账：[architecture-and-verification.md](architecture-and-verification.md)

本手册面向所有用户（包括刚开始接触 Linux 命令行的朋友），将每一个核心概念、每一条命令和每一个参数选项逐一拆解说明，不省略中间步骤。手册中的所有示例均使用虚构占位邮箱（如 `alice@example.com`），方便直接对照参考。

---

## 目录

1. [安装指南与架构选型（按步操作）](#1-安装指南与架构选型按步操作)
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
6. [可选配置文件（`config.json` 网络代理与自定义 OAuth 客户端）](#6-可选配置文件configjson-网络代理与自定义-oauth-客户端)
7. [后台常驻运行指南（`systemd --user` 与无 `systemd` 的 Docker 容器环境）](#7-后台常驻运行指南systemd---user-与无-systemd-的-docker-容器环境)
8. [常见问题解答（FAQ）](#8-常见问题解答faq)

---

## 1. 安装指南与架构选型（按步操作）

### 1.1 按 CPU 架构选择预编译压缩包（全功能合一纯静态单文件）

在 GitHub Releases 发布页中，每个 CPU 架构均统一提供**单一完整的全功能预编译压缩包**（无需区分服务器版与桌面版，可在终端输入 `uname -m` 确认当前机器架构）：

| 预编译压缩包（按架构区分） | 适用硬件与系统环境 | 内置能力与体积说明 |
| :--- | :--- | :--- |
| **`agy-switch-cli-<版本>-x86_64-unknown-linux-musl.tar.gz`** | 常见 Intel / AMD 64 位云服务器、PC、WSL2 与 Docker 容器（`uname -m` 输出 `x86_64`） | **100% 纯静态单文件 ELF**（约 `12.3 MiB`，零外部 `.so` 动态库依赖），完整内置核心 CLI、`stats` 本地统计、`tui` 交互看板与纯 Rust D-Bus 系统钥匙串自适应后端 |
| **`agy-switch-cli-<版本>-aarch64-unknown-linux-musl.tar.gz`** | ARM64 云服务器、树莓派与 ARM 容器（`uname -m` 输出 `aarch64`） | **100% 纯静态单文件 ELF**（约 `10.9 MiB`，零外部 `.so` 动态库依赖），内置与 `x86_64` 完全一致的全量功能 |

- **同一份二进制自动适配无头服务器与图形桌面**：
  - 在远程 SSH 服务器、Docker 容器、无桌面 WSL2 中运行时，默认的 `--backend auto` 会自动使用本地文件后端（`file`），零额外配置。
  - 在开启了 GNOME Keyring 或 KDE Wallet 的 Linux 图形桌面上运行时，默认的 `--backend auto` 会自动检测到本机活跃钥匙串并启用事务性双写模式（`dual`），同步更新系统钥匙串与本地凭据文件，切号后直接运行 `agy` 即刻生效。

### 1.2 下载、校验与安装步骤

以常见的 `x86_64` 架构为例（新版本发布时请将文件名中的版本号替换为实际下载的版本号）：

```bash
# 第 1 步：校验压缩包完整性（输出显示成功 / OK 即可）
sha256sum -c agy-switch-cli-v1.2.0-x86_64-unknown-linux-musl.tar.gz.sha256

# 第 2 步：解压压缩包
tar -xzf agy-switch-cli-v1.2.0-x86_64-unknown-linux-musl.tar.gz

# 第 3 步：安装到当前用户的可执行目录 ~/.local/bin（无需 sudo 权限）
mkdir -p ~/.local/bin
install -m 0755 agy-switch-cli-v1.2.0-x86_64-unknown-linux-musl/agy-switch-cli ~/.local/bin/agy-switch-cli
```

> **提示：如果输入 `agy-switch-cli --version` 提示 `command not found（找不到命令）` 怎么办？**  
> 这说明 `~/.local/bin` 尚未加入终端的 `PATH` 搜索路径。执行以下两行即可（若你使用的是 `zsh`，请把 `.bashrc` 替换为 `.zshrc`）：
> ```bash
> echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
> source ~/.bashrc
> ```
> 随后再次输入 `agy-switch-cli --version`，看到版本号即表示安装完成。

### 1.3 从源码自行编译（可选，要求 `rustc >= 1.89`）

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
- **“1 小时配额缓存保鲜期（`stale`）”机制**
  - 为避免高频请求触发 Google 服务端风控，本地配额缓存的默认保鲜期设为 **`1 小时（3600 秒）`**：
    - 距离上次刷新 **1 小时以内**（且未跨过重置时间点），缓存状态为 `known`（新鲜有效），自动切号无需重复请求网络。
    - 超过 **1 小时**后，缓存标为 `stale`。此时手动运行 `agy-switch-cli quota` **依然会正常展示上次缓存的进度表**，并在状态行温和提示可加 `--refresh`（`agy-switch-cli quota --refresh`）联网更新；而后台自动切号守护进程 `daemon` 遇到 `stale` 时会先自动联网刷新一次最新额度，再决定是否切号。

---

## 3. 全局选项与环境变量

以下全局选项可加在任意子命令之前或之后（日常使用保持默认即可，无需填写）：

| 全局选项 | 对应环境变量 | 默认行为与通俗说明 |
| :--- | :--- | :--- |
| `--data-dir <目录路径>` | `AGY_SWITCH_CLI_DATA_DIR` | 指定账号库存储目录。默认位于 `~/.local/share/agy-switch-cli`（目录权限自动设为 `0700`）。 |
| `--proxy <代理地址\|direct>` | `AGY_SWITCH_CLI_PROXY` | 指定访问 Google 的网络代理，支持 `socks5h://127.0.0.1:1080`、`socks://127.0.0.1:1080`、`http://127.0.0.1:7890`、省略协议头的 `127.0.0.1:7890`，或填 `direct` 强制直连。不填时优先读取 `config.json`，其次自动读取并规范化终端环境变量 `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`（注意 Linux 图形界面的“系统代理”不会自动注入终端，若不想每次传 `--proxy`，需在终端导出代理环境变量或写入 `config.json`）。 |
| `--backend <auto\|dual\|file\|keyring>` | `AGY_SWITCH_CLI_BACKEND` | 指定凭据槽位后端模式（严格匹配这 4 个小写字面值，区分大小写且不接受空字符串或外围空白；亦可在 `config.json` 的 `"backend"` 字段持久化），默认为 **`auto`**。四种模式的具体区别见下表。 |
| `--no-remote-version` | — | 关闭联网命令每 24 小时一次的客户端最新版本号缓存查询。 |
| `--json` | — | 输出机器可读的标准 JSON 格式（供自动化脚本解析使用；全屏交互看板 `tui` 与 `json` 互斥，`run` 包装器在启动准备无误后直接透传 `agy` 子进程的标准输入输出）。 |

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

`status` 用于以 100% 纯只读方式（不创建或修改任何文件与钥匙串条目，不发起任何网络请求）对本机运行环境、账号存储库、切号事务日志、生效凭据槽位、后台守护进程运行状态以及本机官方 `agy` 可执行文件做一次快速健康检查：

```bash
agy-switch-cli status          # 纯只读巡检本地环境、存储库与官方 agy 版本
agy-switch-cli status --json   # 输出结构化 JSON 巡检报告
```

标准输出示例：
```text
agy-switch-cli status (v1.2.0)
  Backend:           dual
  Store status:      OK
  Journal status:    Clean
  Slot initialized:  true
  Daemon state:      OK (paused_on_failure=false)
  Official agy:      /usr/bin/agy v1.5.9
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
  - `CommittedIndexPending` 或 `RecoveryIncomplete`：上次切号或清槽中途被系统信号中断（例如双写后端中仅更新了一侧副本）。由于 `status` 严格只读不会擅自改写状态，此时会如实报告该状态并返回退出码 `7`；你只需执行一次手动切号（如 `agy-switch-cli switch <ID|EMAIL>`）或其他交互式写命令，程序便会在持有锁与外部凭据防误覆盖（CAS）保护的前提下自动完成双端对账修复。
- **`Slot initialized`（官方凭据槽位是否已初始化）**：
  - `true`：当前生效后端中已经存有 `agy` 登录凭据。
  - `false`：全新环境尚未登录或尚未向槽位写入过凭据（属于正常初始状态；若槽位文件存在但 JSON 内容损坏，`status` 会报错并返回退出码 `1`）。
- **`Daemon state`（后台守护进程状态文件健康度）**：检查 `state/daemon_state.json` 是否可读合法，正常时显示 `OK (paused_on_failure=false)` 或 `OK (paused_on_failure=true)`：
  - `OK`：表示状态文件结构正常（尚未运行过 `daemon` 时同样视为正常的默认初始态；若文件损坏则返回退出码 `1`）。
  - `paused_on_failure=false`：正常工作状态，后台 `daemon`（若已启动）会按设定周期正常巡检并在低额度时自动切号。
  - `paused_on_failure=true`：**连续失败自动熔断暂停状态**。当后台 `daemon` 连续 **3 次**提交切号失败（例如遇到磁盘只读、系统钥匙串异常断开或存在未决恢复日志）时，会自动将该标志置为 `true` 并暂停后续自动切号尝试，防止在故障状态下死循环重试。排查修复底层环境问题后，手动执行一次 `agy-switch-cli switch <ID|EMAIL>` 或 `agy-switch-cli policy set ...` 即可自动解除该熔断标记（恢复为 `false`）。
- **`Official agy`（本机官方 `agy` 可执行文件探测）**：在独立进程组（`process_group(0)`）与隔离的空临时目录环境中（清空并覆盖 `HOME`、`XDG_*`、`TMPDIR`、`DBUS_SESSION_BUS_ADDRESS` 与 `NO_PROXY=*`，限时 3 秒，超时或退出时向整个子进程组发送 `SIGKILL` 并回收直接子进程）调用本机 `agy --version` 获取路径与版本号（面向本机可信 `agy` 可执行文件的环境变量、临时目录与进程组隔离，不构成操作系统内核级容器命名空间沙盒）：
  - 已正常安装时输出实际路径与版本号，如 `/usr/bin/agy v1.5.9`。
  - 当前 `PATH`（及 `AGY_SWITCH_CLI_AGY_BIN`）中尚未安装官方 `agy` 时显示 `not found in PATH`（不视为报错，退出码仍为 `0`）。
  - 若找到了 `agy` 文件但无法执行、返回非零退出码或超过 3 秒卡死，则输出具体错误并返回退出码 `8`。
- **按需出现的底部提示行**（平时环境无异常时不显示）：
  - `Config warning`：`config.json` 文件权限过宽（如 `0644`，建议改为 `chmod 600`）或包含被跳过的无效自定义客户端条目时的温和提示。
  - `Security warning`：`state/pending_auth/*.json` 或 `state/auth_sequence.json` 含有组或其他用户权限位时的安全收紧提示。
  - `D-Bus note`：在存在本机桌面 D-Bus 会话套接字的环境中使用纯 `file` 后端时的说明提示，提醒桌面端钥匙串优先级规则。

---

### 4.2 登录与 OAuth 授权管理：`auth`（默认免配置粘贴登录）

#### 方式一（默认模式，免配置）：手动粘贴回调网址登录

无需本机安装浏览器，也无需配置 SSH 端口转发，直接运行：

```bash
agy-switch-cli auth login --label "主力号"
```

按以下三步操作即可完成登录：
1. 终端会打印出一串以 `https://accounts.google.com/...` 开头的授权网址，并等待你粘贴回调结果；
2. 将该网址复制到**任意一台电脑的浏览器**中打开，登录 Google 账号并点击允许授权；
3. 点击允许后，浏览器会跳转到一个无法打开的本地页面（提示“无法访问此网站 / 拒绝连接 `127.0.0.1`”）。这是正常现象，只需把浏览器顶部地址栏中那整串以 `http://127.0.0.1:...` 开头的完整网址复制下来，粘贴回服务器终端并按回车，即可完成登录。

#### 方式二（可选 `--ssh` 监听模式）：适合 SSH 端口转发或本地图形桌面自动回调

如果你希望浏览器点完允许后自动完成回调，可以加上 **`--ssh`** 开启本地回环端口监听：

```bash
# 场景 A：在本地 Linux 桌面终端上使用，加 --ssh --open-browser 自动打开浏览器并在授权后自动完成：
agy-switch-cli auth login --ssh --open-browser --label "本地号"

# 场景 B：通过 SSH 连接远程服务器，先在本地电脑用 `ssh -L 54545:127.0.0.1:54545 user@server` 连接，再在服务器运行：
agy-switch-cli auth login --ssh --port 54545 --label "服务器号"
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
  - **什么情况下才会用到它？** Google OAuth 2.0 有一条严格规则：**由哪个 `client_id` 签发的 `refresh_token`，后续刷新续期时就必须继续配对同一个 `client_id` 和 `client_secret`**。如果你手头有通过自建 Google Cloud 项目或其他第三方工具签发的 Token，在按第 `6.2` 节写入 `config.json` 后，就可以运行 `auth clients` 核对自定义客户端是否已成功加载、有没有字段缺失警告。

---

### 4.3 账号池管理、批量导入与排序：`accounts`

#### （1）查看账号列表与调整顺序：`accounts list`

`accounts list` 统一集成了**账号详情展示**与**顺序调整**功能：

```bash
# 1. 直接查看所有账号（纯只读，显示序号、选中星号 *、邮箱、[套餐等级]、备注、状态与内部 ID）：
agy-switch-cli accounts list
# 输出示例：
#  1. * alice@example.com    [Google AI Pro]  (主力号)             (acc-0001...)
#  2.   bob@example.com      [Google AI Pro]  (备用号)             (acc-0002...)
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
agy-switch-cli accounts add --from-local --label "本机当前账号"
```
- **按当前生效的 `--backend` 模式自动选择读取源**：
  - 在默认的 **`auto`**（桌面有钥匙串时）或 **`dual`** 模式下：程序优先读取系统钥匙串（`Password for 'antigravity' on 'gemini'`，若集合处于锁定状态会按标准接口请求解锁，而日常只读探测 `auto` / `current` / `status` 绝不触发解锁）；若钥匙串中尚无记录，则自动回退读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
  - 在 **`file`** 模式（或无桌面服务器 / 容器环境）下：程序仅读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
  - 在 **`keyring`** 模式下：程序仅读取系统钥匙串，不会回退读取磁盘上的 `antigravity-oauth-token`。
  - **支持范围边界**：`--from-local` 严格面向 `agy` CLI 生效凭据源设计，不会读取桌面端 App / VS Code 扩展专用的回退文件 `~/.gemini/jetski-standalone-oauth-token`。若桌面系统未启用钥匙串、且仅存在 `jetski-standalone-oauth-token` 而未登录过 `agy` CLI，请改用 `agy-switch-cli auth login` 登录。
- 读取到 `refresh_token` 后，程序会先在本地预检并准备 `0700/0600` 私有暂存目录与单调授权序号，随后联网核验令牌有效性、拉取对应的真实邮箱并安全落盘（若该邮箱已在库中则自动刷新更新，不会重复建号）。

**场景 B：手动安全粘贴单条 `refresh_token`**
```bash
# 运行后终端会自动关闭字符回显（粘贴时不显示字符属于正常保护），粘贴后按回车即可：
agy-switch-cli accounts add --label "备用号"
```

**场景 C：手里有多条裸 `refresh_token`（无需事先知道邮箱），一次性批量添加（`--from-file` / `--from-stdin`）**
1. 新建一个权限为 `0600` 的私密文本文件（例如 `~/tokens.txt`）：
   ```bash
   install -m 0600 /dev/null ~/tokens.txt
   ```
2. 用编辑器打开 `~/tokens.txt`，**每行填写一条 `refresh_token`**（空行与 `#` 开头的注释行会自动忽略；也可在 Token 后空一格写上 `# 备注名`，为该账号单独设置备注）：
   ```text
   # 批量导入账号列表
   1//0gAAAAAAAAAAAAAAAAAAAAAA  # 一号主力
   1//0gBBBBBBBBBBBBBBBBBBBBBB  # 二号备用
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
      "custom_label": "主力号"
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
        "custom_label": "主力号"
      }
    ]
  }
  ```
*(补充说明：如果手头只有 `refresh_token` 而不知道对应的 `email`，请使用上一小节的 `accounts add --from-file` 联网自动识别邮箱导入。)*

#### （4）启用、禁用与删除账号：`enable` / `disable` / `delete`

```bash
agy-switch-cli accounts disable bob@example.com --reason "留作月底备用"   # 手动禁用（填邮箱或 ID）
agy-switch-cli accounts enable bob@example.com                           # 重新启用（填邮箱或 ID）
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
Selected account : alice@example.com  [Google AI Pro]  (主力号)  (acc-0001...)
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
- **不同环境与 `--backend` 模式下的切号行为**：
  - **纯无头环境（远程 SSH 服务器、Docker 容器、无桌面 WSL2）**：默认 `auto` 自动采用 `file` 模式，以 `0600` 权限原子替换 `~/.gemini/antigravity-cli/antigravity-oauth-token`，切完直接运行 `agy` 即刻生效。
  - **带有系统钥匙串的 Linux 图形桌面环境（如 KDE Plasma、GNOME）**：
    - **默认用法（`auto` 自动启用 `dual` 事务性双写）**：直接运行 `agy-switch-cli switch bob@example.com`（无需手传额外参数），程序自动对系统钥匙串集合与本地 `antigravity-oauth-token` 执行前置快照、加密更新、双 `fsync` 落盘与双副本一致性回读校验（任一步失败自动双端回滚；若遇到传输中断等不确定状态则保留切换日志并返回退出码 `7`，后续任意交互式写命令会在安全 CAS 保护下自动完成对账恢复）。切完后在任意终端直接输入 `agy` 立即使用新账号。
    - **仅用钥匙串不留本地文件（`--backend keyring`）**：执行 `agy-switch-cli --backend keyring switch bob@example.com`（或在 `config.json` 中设 `"backend": "keyring"`），程序仅读写系统钥匙串，完全不创建或修改 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
    - **桌面与 CLI 账号隔离（显式 `--backend file` + `run`）**：若希望桌面端 App 保持原钥匙串账号、仅让终端里的 `agy` 换用另一个账号，可执行 `agy-switch-cli --backend file switch bob@example.com` 只改本地文件，再通过可选方式 `agy-switch-cli --backend file run -- agy` 启动（显式选择 `file` 后端时，`run` 会自动为子进程屏蔽桌面钥匙串总线）。

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
  - 备选账号同样要求 `min(5h, Weekly) >= --minimum` 才具备接班资格。因此默认将 `--reserve` 设为 **`5%`**、`--minimum` 设为 **`15%`**，既能让每个账号消耗满 `95%` 以上充分榨干额度，又能确保周中后期仅剩十几个百分点周额度的账号依然能被自动轮换利用，同时保留 `10%` 的安全水位差防止来回震荡。

#### `policy set` 全部参数说明表

| 参数选项 | 可选填的值 | 默认值 | 详细作用与选择建议 |
| :--- | :--- | :---: | :--- |
| **`--enabled`** | `true` 或 `false` | `false` | **自动切号总开关**。开启前候选名单里至少需要包含 1 个账号。 |
| **`--all-candidates`** | 无需填值（直接添加该开关） | — | **一键将当前所有已启用账号（按 `accounts list` 顺序）全部设为候选账号**，免去逐个输入邮箱的步骤。 |
| **`--candidates`** | 空格分隔的 `<ID\|EMAIL>` | 空 | 只希望将部分特定账号放入轮换池时使用，填写对应账号的邮箱或 ID（如 `--candidates alice@example.com bob@example.com`），或在 `tui` 中按 `c` / `C` 键可视化勾选。清空候选池可使用 `--clear-candidates`。 |
| **`--reserve`** | `1` ～ `98`（整数百分比） | **`5`** | **保底警戒线（触发换号线）**。默认 `5`：当正在使用的账号有效剩余额度 `min(5h, Weekly)` 降至 `5%` 或以下（即已消耗 `95%` 以上）时，触发自动换号。 |
| **`--minimum`** | `2` ～ `100`（整数百分比） | **`15`** | **候选接班准入线**。默认 `15`：准备接班的备用账号有效剩余额度 `min(5h, Weekly)` 必须至少达到 `15%` 才会被选中（要求严格大于 `--reserve` 以留出防抖回差）。 |
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

以默认的保底警戒线 `--reserve 5`（`5%`）与候选准入线 `--minimum 15`（`15%`）为例，自动切号在不同剩余额度组合下的决策逻辑如下：

- **情况一：当前正在使用的账号有效额度介于 `5%` 与 `15%` 之间（例如剩余 `10%`）**：
  - **不会触发切换，继续稳定使用当前账号**。
  - `--minimum`（`15%`）仅用于筛选“准备新换上来的接班候选账号”，并不会限制已经在用的当前账号；只有当当前账号继续消耗至 **`<= 5%`（`--reserve`）** 时才会开始寻找接班账号。
- **情况二：当前账号已降至 `<= 5%`（如剩余 `3%`），但池中其余候选账号全部 `< 15%`（没有任何候选号达到 `>= 15%`）**：
  - 系统判定为**暂无达标接班候选（`no_qualified_candidate`）**：
    - 后台 `daemon` 会**保持当前账号不变**（不会在两个只剩百分之几的低额度账号之间来回横跳浪费请求），静默等待任意候选账号跨过 `5h` 或 `Weekly` 重置时间恢复到 `>= 15%` 后再自动切入。
    - 执行 `agy-switch-cli policy eval` 模拟测算时，会清晰显示 `would_switch=false` 与 `reason=source_below_reserve_but_no_qualified_candidate`。
    - **如何手动介入使用那些仅剩 `8% ~ 14%` 的备用号？** 手动切号（`agy-switch-cli switch <ID|EMAIL>` 或 `tui` 中按回车 / `s`）不受 `--minimum` 准入线限制，你随时可以手动切到任意未禁用账号把剩余零头额度用尽。

#### `policy` 常用命令示例

```bash
# 1. 将当前所有启用账号加入候选池并启用自动切号（默认即为 immediate + round-robin，reserve 5% / minimum 15%），重点监控 Claude/GPT 池：
agy-switch-cli policy set --enabled true --all-candidates --model claude

# 2. 如需自定义更保守的水位线、等待旧 agy 进程全部退出后再切号并采用主备优先级顺序：
agy-switch-cli policy set --mode wait --strategy priority --reserve 10 --minimum 25 --candidates alice@example.com bob@example.com

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

- **静默预切号工作方式与生效边界说明**：
  - `daemon` 采用纯粹的**后台静默预切号**设计，不发送任何桌面弹窗或终端广播通知，也不会强行终止你正在交互的 `agy` 进程。
  - 由于官方 `agy` 仅在每次启动时读取一次登录凭据，当你在前台对话中注意到当前账号余量不足而退出重开 `agy`（或者后台脚本发起下一轮新的 `agy` 调用）时，若 `daemon` 已经提前完成了后台预切号，新启动的 `agy` 就会直接使用已经换好的新账号，省去退出后再手动打开 `tui` 刷新切号的步骤；平时也可随时通过 `agy-switch-cli current` 或 `journalctl --user -u agy-switch-cli.service` 查看切号记录。

```bash
# 1. 在支持 systemd 的 Linux 系统上，一键安装并启动开机自启后台用户服务（最简常驻方式）：
agy-switch-cli daemon --install
# 如需自定义后台服务的固定巡检间隔与冷却秒数，可在 --install 时一并传入写入服务文件：
agy-switch-cli daemon --install --interval 7200 --cooldown 3600

# 2. 一键停止、取消自启并安全移除用户级 systemd 服务文件：
agy-switch-cli daemon --uninstall

# 3. 直接在当前终端前台运行守护进程（按默认每 3600 秒即 1 小时巡检一次，切号冷却 3600 秒）：
agy-switch-cli daemon
agy-switch-cli daemon --interval 7200 --cooldown 3600

# 4. 仅执行单轮“检查 -> 按需刷新 -> 按需切号”后立即退出（适合配合 crontab 定时任务）：
agy-switch-cli daemon --once
```

| 参数选项 | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :---: | :--- |
| `--install` | — | 关闭 | 检测系统 `systemd --user` 可用性，原子生成 `~/.config/systemd/user/agy-switch-cli.service` 并自动执行 `daemon-reload` 与 `enable --now`（与 `--uninstall`、`--once` 互斥；在无 `systemd` 的 Docker 容器中会给出清晰提示并引导参见第 `7.2` 节） |
| `--uninstall` | — | 关闭 | 自动执行 `disable --now`、防符号链接安全删除 `agy-switch-cli.service` 并重载 `daemon-reload`（与 `--install`、`--once` 互斥） |
| `--interval <秒>` | `AGY_SWITCH_CLI_INTERVAL` | `3600`（1 小时） | 后台巡检间隔秒数（内置 `±10%` 随机时间抖动，保持温和低频访问） |
| `--cooldown <秒>` | `AGY_SWITCH_CLI_COOLDOWN` | `3600`（1 小时） | 完成一次自动切号后的冷却保护时间（秒），冷却期内不再连续触发第二次切换 |
| `--once` | — | 关闭 | 仅执行单轮评估与切换后立即退出（与 `--install`、`--uninstall` 互斥） |
| `--mode <immediate\|wait>` | `AGY_SWITCH_CLI_MODE` | 读取 `policy.json` | 仅对当前前台 `daemon` / `daemon --once` 运行生效的内存临时覆盖参数（由守护引擎在运行期解析，不会写回 `policy.json` 或 `systemd` 单元文件） |
| `--strategy <priority\|round-robin>` | `AGY_SWITCH_CLI_STRATEGY` | 读取 `policy.json` | 仅对当前前台 `daemon` / `daemon --once` 运行生效的候选选择策略内存覆盖参数，不会写回 `policy.json` |
| `--reserve <1..=98>` | `AGY_SWITCH_CLI_RESERVE` | 读取 `policy.json` | 仅对当前前台 `daemon` / `daemon --once` 运行生效的触发水位内存覆盖参数，不会写回 `policy.json` |
| `--minimum <2..=100>` | `AGY_SWITCH_CLI_MINIMUM` | 读取 `policy.json` | 仅对当前前台 `daemon` / `daemon --once` 运行生效的候选最低门槛内存覆盖参数，不会写回 `policy.json` |
| `--model <MODEL>` | `AGY_SWITCH_CLI_MODEL` | 读取 `policy.json` | 仅对当前前台 `daemon` / `daemon --once` 运行生效的监控池或模型内存覆盖参数，不会写回 `policy.json` |

> **关于 `--interval`、`--cooldown` 及临时覆盖参数是否持久保存的重要说明**：
> - 直接在前台运行 `agy-switch-cli daemon --interval 7200 --cooldown 3600`（或附加 `--reserve`、`--mode` 等参数）时，这些命令行参数**仅对当前这一个 `daemon` 进程本次运行生效，不会修改磁盘上的 `policy.json` 或 `config.json`**；关掉该进程后下次裸跑 `daemon` 仍恢复默认 `3600` 秒。
> - **如何持久保存巡检间隔与冷却时间？**
>   - 使用 `systemd` 后台服务时：执行 `agy-switch-cli daemon --install --interval 7200 --cooldown 3600`，程序会将这两项参数直接写入 `~/.config/systemd/user/agy-switch-cli.service` 的启动命令中长期生效。
>   - 在无 `systemd` 容器中使用 `nohup` / `supervisord` / `tmux` 时：在启动命令中带上 `--interval` / `--cooldown`，或配置环境变量 `AGY_SWITCH_CLI_INTERVAL` 与 `AGY_SWITCH_CLI_COOLDOWN`。
> - **如何持久保存自动切号水位、策略规则与网络代理？** 请分别使用 `agy-switch-cli policy set ...` 将策略规则写入 `policy.json`、在 `config.json` 中写入 `network.proxy_url` 保存代理地址（因此在执行 `daemon --install` 时若误带了 `--reserve` 或 `--proxy` 等单次临时参数，程序会主动提醒先持久保存配置）。

---

### 4.9 SSH 交互式终端看板：`tui`（全键盘可视化操作）

如需在单个界面中总览所有账号额度、调整列表顺序、配置自动切号候选池或手动切号，可运行：

```bash
agy-switch-cli tui
```

#### 界面说明
- **三行独立对齐状态头与极矮窗口自适应**：
  - 在常规高度（`>= 11` 行）终端中，顶部将生效会话、运行中进程与自动切号策略拆分为 **3 行垂直冒号对齐的独立状态行**（`Session [file|dual|keyring] : ...`、`Runtime : ...`、`Policy : ...`），完整展示每项信息而不会因挤在同一行被截断；在极矮终端分屏（`< 11` 行）下则自动折叠为紧凑单行，确保在任意尺寸下都不超出物理视口边界。
  - 在宽度小于 `152` 列的窗口中自动隐藏冗长的 36 位 `ID` 列；当账号数量超出窗口高度时保持顶栏、表头与底栏固定并跟随光标平滑滚动（标题栏显示 `[Showing X-Y of N]`），同时在表格首行/末行内嵌定高的 **`... (<K> more above)`** 与 **`... (<K> more below)`** 折叠提示行，直观指示上/下方仍有隐藏账号且滚动全程总行数恒定不跳动（一屏可完整容纳时不渲染任何 `...` 行）。
- **继承全局 `--backend` 并在顶栏明确标识（无看板内切换热键）**：
  - `tui` 严格继承全局生效后端（默认 `auto` 自动解析为 `Session [file]` 或 `Session [dual]`；若通过 `--backend keyring`、环境变量或 `config.json` 指定了后端，则对应显示 `Session [keyring]` 等标签），不在看板内部设置易误触的后端切换键，保证全局行为一致。
  - 按 `Enter` 或 `s` 切号时，即使当前已有 `agy` 进程正在运行也会立即完成切换，并在底栏温和提示已运行的 `agy` 保持原登录态、新启动的 `agy` 将使用新账号。
- **`#`、`Sel` 与 `Plan`**：
  - `#` 为右对齐账号序号，`>` 表示当前光标所在行，`*` 表示当前选中的账号。
  - `Plan` 列在 `tui` 看板内自动将上游返回的免费层原始全称 `Antigravity Starter Quota`（及 `Starter` / `Free Tier` 等变体）简写为 `Free`，将 `Google AI Pro` / `Ultra` 简写为 `Pro` / `Ultra`（未知新套餐名原样兜底保留）；而在命令行 `accounts list`、`current`、`quota` 及所有 `--json` 输出中则原样保留上游原始 `subscription_tier` 字符串以便精确核对。
- **`Gemini (5h / W)` 与 `Claude/GPT (5h / W)`**（窄屏紧凑表头为 `Gemini 5h/W` 与 `Claude/GPT 5h/W`）：斜杠左侧为 `5h`（五小时短期窗口剩余额度），右侧为 `W`（Weekly 周剩余额度），如 `100% /  72%`；单元格内对百分比做了固定宽度字符级填充与居中对齐，使上下各行的百分比与斜杠 `/` 保持严格垂直对齐。灰度专属池 `Argon (W)` 在所有账号均无该池数据时会自动隐藏，存在数据时自动展开。
- **`Policy`**：显示该账号在自动切号候选池中的顺位（如 `cand #1`、`cand #2`，未加入显示 `—`）；若候选池中的某个账号当前处于已禁用（`disabled`）状态，自动切号调度时会自动跳过该账号，并在该列明确标注为 `cand #2 (skip)`。
- **自适应分组底栏与二次确认保护**：
  - 在常规窗口高度（`>= 14` 行）下，底部常驻展示两行冒号对齐的分组快捷键帮助（`Keys   : ↑/↓ select · g/G top/end · [/] reorder · Enter/s switch · q/Esc quit` 与 `Manage : r/R refresh · c/C cand · p policy · e/E enable · d/D disable · x delete`）；在矮窗口（`< 14` 行）下自动收拢为高优先级单行帮助，即使在中等宽度终端中也优先保留 `g/G`、`[/]`、`e/E`、`d/D` 与 `x` 的功能词说明。
  - 最底行状态栏实时显示批量刷新进度、内联二次确认提示（按 `D` 全部禁用或按 `x` 删号时）或最近一次操作反馈（若联网时检测到格式异常的代理环境变量被忽略，也会在底栏附带仅含变量名的脱敏提示），并在 **3 秒**（报错信息 **5 秒**）后自动清空。

#### `tui` 完整快捷键一览表

| 按键 | 功能说明 |
| :--- | :--- |
| `↑` / `↓` 或 `PgUp` / `PgDn` | 上下移动高亮光标（超出单屏时列表自动跟随滚动，首/末行内嵌定高 `...` 提示） |
| `g` / `Home` 或 `G` / `End` | 快速将高亮光标跳转到列表首行（`g`）/ 末行（`G`） |
| **`[`** / **`]`** | 将当前高亮账号上移一位（`[`）/ 下移一位（`]`），实时保存新顺序 |
| `Enter`（回车）或 `s` | 将官方 `agy` 凭据切换到当前高亮账号 |
| `r` / **`R`** | `r` 联网刷新当前高亮账号配额；大写 **`R`** 以安全有界并发批量刷新全部未禁用账号（底栏实时显示进度，支持按 `Ctrl+C`、`q`、`Esc` 或发送系统信号随时安全中断并恢复终端） |
| **`c`** / **`C`** | `c` 增删当前高亮账号的候选资格；大写 **`C`** 一键将所有未禁用账号按列表顺序加入候选池（若所有未禁用账号均已在候选池中，再按 **`C`** 则清空候选池并自动关闭策略总开关） |
| **`p`** | 开启或关闭 `policy` 自动切号总开关 |
| `e` / **`E`** | `e` 启用当前高亮账号；大写 **`E`** 无需确认，直接将池中所有处于 `disabled` 状态的账号全部恢复为启用 |
| `d` / **`D`**（配合 **`y`** 确认） | `d` 手动禁用当前高亮账号；大写 **`D`** 在底栏弹出防误触确认提示（`Disable all <N> account(s)? Press 'y' to confirm (any other key cancels).`），按 `y` 确认将全部未禁用账号设为手动禁用，按 `Ctrl+C` 直接退出看板，按 `Esc`、`q`、`Ctrl+D` 等其他键取消且不退出看板 |
| **`x`** 或 `Delete`（配合 **`y`** 确认） | 删除当前高亮账号：按下后底栏弹出内联确认提示，按 `y` 确认执行删除（若目标为当前生效 `*` 账号，确认后会按事务安全清空生效凭据槽位并同步移出策略候选池、账号索引与令牌血统归档）；按 `Ctrl+C` 直接退出看板，按 `Esc`、`q`、`Ctrl+D` 等其他键取消且不退出看板 |
| `q` 或 `Esc` 或 `Ctrl+C` / `Ctrl+D` | 退出看板并恢复原终端界面（内联确认期间仅 `Ctrl+C` 立即退出，`Esc`、`q` 与 `Ctrl+D` 优先取消确认） |

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

- **数据源选择：`--source <all|cli|app>`（默认值为 `all`）**
  - `all`（默认）：
    - 合并扫描当前 `HOME` 内支持的两个数据源（`~/.gemini/antigravity-cli/conversations/*.db` 与 `~/.gemini/antigravity/conversations/*.db` 及其 `token_usage_archive.db`），自动按同一会话文件与生成序号去重。
    - 在无桌面的远程 Linux 服务器或容器上，由于不存在 `~/.gemini/antigravity`，默认 `all` 会自动等效读取 `cli`；在同时装有 CLI 与桌面端 App 的机器上，默认直接展示完整结果，无需额外传参。
  - `cli`：仅只读扫描当前 `HOME` 下官方 `agy` CLI 的会话目录 `~/.gemini/antigravity-cli/conversations/*.db`。
  - `app`：
    - 仅只读扫描当前 `HOME` 下桌面端 Antigravity App 的会话目录 `~/.gemini/antigravity/conversations/*.db` 及 `token_usage_archive.db`。
    - 若原实时 `.db` 仍存在于磁盘，程序会从实时库补充提取步骤状态、流式响应延迟与吐字速度；若原实时 `.db` 已被清理而仅存于 `token_usage_archive.db`，`stats list` 会将该行状态标为 `arch`（`--json` 中为 `"archived"`）。
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

#### 常用命令示例

```bash
# 1. 默认汇总本机今天（today）在全部数据源（all：CLI + App）中产生的用量与分位性能：
agy-switch-cli stats summary

# 2. 查看最近 10 次（默认）或指定最近 N 次（1..=500）模型调用明细：
agy-switch-cli stats list
agy-switch-cli stats list --recent 5
agy-switch-cli stats list --source cli --date 2026-11-19

# 3. 仅针对最近 50 次调用聚合汇总与分位延迟，或按历史天数范围聚合：
agy-switch-cli stats summary --recent 50
agy-switch-cli stats summary --range all
agy-switch-cli stats summary --range 7d
agy-switch-cli stats summary --from 2026-10-01 --to 2026-10-31

# 4. 输出标准 JSON 结构（零本地路径与邮箱泄露，供脚本记录或二次分析）：
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
  Gemini 4 Hydrogen (XHigh)         86   20,976,818   18,586,982   88.6%      127,834   21,104,652
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
  - `TPS (P10/P50/P90)`：流式阶段实测输出速度（`= output_tokens / streaming_duration`，单位 `t/s`）的 `P10 / P50 / P90` 分位值。
  - **统一性能样本口径（`stats summary` 与 `stats list` 完全一致）**：只要当次生成步骤正常完成（未处于报错 `err`、取消 `canc` 或运行中 `run` 状态，兼容含工具调用与简短回复）、无内部重试退避污染（`retries == 0`）、总输出 `output_tokens > 0`、首字耗时 `ttft > 0` 且流式阶段耗时 **`streaming_duration >= 1.0s`**（过滤不足 `1.0` 秒的单块缓冲瞬时突发达峰，避免扭曲真实流式速度），即纳入实测 `TPS` 计算（无合格样本时显示 `—`）。
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
  11-19 08:25:28  Gemini 4 Carbon (High)     591.2K       0   0.0%    209  36.1s  36.9s    —  ok
  11-19 01:58:23  Gemini 4 Carbon (High)     587.1K  584.1K  99.5%   3.4K  15.0s  59.0s   78  ok
```

- **十列字段含义与极窄终端降级说明**：
  - `Time`：请求发起的本机本地时间。宽屏（`>= 95` 列或非 TTY 管道）显示 `MM-DD HH:MM:SS`（跨年份时自动扩展为 `YYYY-MM-DD HH:MM:SS`）；常规窄屏（`< 95` 列且达到十列最小可读宽度时）保留全部 10 列，将时间收紧为 `MM-DD HH:MM` 并动态压缩 `Model` 列宽；若终端宽度低于十列最小可读宽度（例如 `50` 列极窄分屏），自动切换为紧凑多行块格式展示单条请求，确保 `TPS`、`St` 等末尾字段不会被截断丢失。
  - `Model`：仅输出匹配已知公共模型 ID 或公开模型家族标签语法的名称，其余本地非公开自由文本、路径、无扩展名文件名或异常字段均统一回退为 `"Unknown"`。
  - `In` / `Cache` / `Out`：当次请求的**总输入 Token**（未缓存新增输入与缓存命中输入之和，与 `stats summary` 的 `Input` 口径一致）、其中命中上下文缓存的输入 Token 与总输出 Token（自适应紧凑单位）。
  - `Hit%`：当次请求的缓存命中率百分比（`= Cache / In`，固定保留一位小数，如 `99.5%`、`91.9%`、`0.0%`）；只要存在未缓存输入（即 `Cache < In` 且 `Cache > 0`），上限封顶为 **`99.9%`**（防止 `99.96%` 四舍五入误显示为 `100.0%`），仅当全部输入均命中缓存（`In == Cache` 且 `Cache > 0`）时才显示 `100.0%`（总输入 `In == 0` 时显示 `—`）。
  - `TTFT` / `Dur`：首字到达耗时与请求总耗时（`Dur = ttft + streaming_duration`，流式时长缺省时取 `ttft`）。
  - `TPS`：无单位后缀的四舍五入整数吐字速度（`= output_tokens / streaming_duration`）；采用与 `stats summary` 完全统一的事件时间戳与过滤条件（严格要求已完成步骤 `steps.status == 3`、无非法/超限 `step_payload`、`retries == 0`、`output_tokens > 0`、`ttft > 0` 且 **`streaming_duration >= 1.0s`**），包含工具调用回合与流式回复，流式阶段不足 `1.0s` 或不满足条件时显示 `—`。
  - `St`：请求状态简码，实时库映射为 `ok`（已完成 `status=3`）、`err`（报错或无效）、`canc`（取消或中断）、`run`（进行中或排队中）、`unk`（缺失或未识别的状态值），仅存于历史归档库且原实时 `.db` 已移除的记录显示为 `arch`。
- **上限截断说明**：按日期区间（`--range` / `--date` / `--from`）查询 `stats list` 时，最多输出最新的 `500` 条记录；若匹配总数超过 `500` 条，表头会自动注明 `(newest first, showing 500 of <总数> — capped at 500)`。
- **`stats summary --json` 与 `stats list --json` 机器输出说明（`schema_version: 1`）**：
  - 两者共享顶层 `source`、`range`（当使用 `--recent` 时为 `{"kind": "recent", "recent": N, "from": ..., "to": ...}`）、`databases_scanned`、`generations_scanned`、`skipped_large_records`、`unreadable_databases`、`last_activity`、`range_last_activity` 与 `generated_at`。
  - `stats summary --json` 输出 `summary`、`performance` 与 `models`（每项含 `model`、`request_count`、`total_input_tokens`、`uncached_input_tokens`、`cached_input_tokens`、`cache_hit_ratio`、`cache_hit_percent`、`output_tokens`、`total_tokens`）；`stats list --json` 输出 `total_matching`、`shown_count`、`truncated` 与 `items` 数组（每项含 `timestamp`、`local_time`、`model`、`uncached_input_tokens`、`cached_input_tokens`、`total_input_tokens`、`cache_hit_ratio`、`cache_hit_percent`、`output_tokens`、`total_tokens`、`ttft_seconds`、`duration_seconds`、`output_tps`、`status`），结构中不导出 `source_key`、本机路径或账号邮箱，模型名经严格公开白名单收敛至已知公共模型或 `"Unknown"`。

---

## 5. 标准退出码（`0..=8`）与 `--json` 脚本集成契约

添加 `--json` 后，机器输出契约按命令性质分类如下：

- **特殊命令与 `daemon` 三类输出说明**
  - **`tui`**：全屏交互终端界面，与 `--json` 互斥并直接返回退出码 `2`。
  - **`run -- agy ...`**：在前置凭据准备、锁检查或进程检查失败时向 `stderr` 输出结构化错误信封；前置准备成功后直接将标准输入输出交给 `agy` 子进程并原样透传其退出码。
  - **`daemon --install --json` 与 `daemon --uninstall --json`**：服务安装与卸载属于一次性单目标管理命令，成功时向 `stdout` 输出包含 `"schema_version": 1, "ok": true` 的结果信封并返回退出码 `0`，失败时向 `stderr` 输出结构化错误信封并返回非零退出码。
  - **前台 `daemon --json` 与 `daemon --once --json`**：后台与单轮巡检采用静默执行设计，**不按轮向 `stdout` 输出 JSON 信封**（空闲、单轮完成或收到退出信号正常停止时两流保持静默并返回退出码 `0`）；仅当启动参数非法、策略校验失败、单实例锁冲突或运行期致命错误发生时向 `stderr` 输出结构化 JSON 错误信封并返回对应非零退出码（日常运维日志可在非 `--json` 模式下通过 `RUST_LOG` 输出至 `stderr`）。

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

- **离线批量导入与只读全量统计聚合**
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

## 6. 可选配置文件（`config.json` 网络代理与自定义 OAuth 客户端）

`~/.local/share/agy-switch-cli/config.json` 是**完全可选**的配置文件。默认情况下该文件不存在，所有功能均可直接使用（程序已内置与官方 `agy` 一致的默认 OAuth 客户端 `antigravity_enterprise`）。只有当你遇到以下三类需求时，才需要手动创建它：

- **固定网络代理**：在 Linux 环境下，图形界面的“系统代理”设置并不会自动注入命令行终端或后台 `daemon` 服务的环境变量中。如果你不想每次在命令行手敲 `--proxy`，也不想每次新开终端都手动执行 `export https_proxy=...`，可以将代理地址写入 `config.json` 实现跨终端与后台守护进程的永久生效（此外，若终端环境变量中的代理格式异常而被忽略，人类输出模式会在联网时打印仅含变量名的脱敏提示）。
- **固定凭据后端模式**：希望跨所有终端与后台服务统一固定使用 `keyring`（纯钥匙串零本地文件）、`file`（纯本地文件）或 `dual`（强制双写），而非每次手动传 `--backend`。
- **自定义 OAuth 客户端（进阶场景）**：你手头拥有由其他 Google Cloud OAuth 客户端签发的 `refresh_token`，或者希望使用自建 OAuth 客户端进行登录（详见下方 `6.2` 节零基础完整拆解）。

> **文件权限要求**：由于 `config.json` 中可能包含带密码的代理地址或 `client_secret` 密钥，创建时请将文件权限设为仅当前用户可读写的 `0600`（若权限过宽如 `0644`，`status` 与联网命令会输出安全提示，执行 `chmod 600 ~/.local/share/agy-switch-cli/config.json` 即可收紧权限）：
> ```bash
> install -m 0600 /dev/null ~/.local/share/agy-switch-cli/config.json
> ```

### 6.1 场景一：仅配置固定网络代理或凭据后端（最常见用法）

如果只需要配置网络代理或凭据后端，无需填写 `oauth` 部分，写入以下最简内容即可：

```json
{
  "schema_version": 1,
  "backend": "auto",
  "network": {
    "proxy_url": "socks5h://127.0.0.1:1080",
    "no_proxy": "internal.corp,10.0.0.0/8"
  }
}
```

- **`backend`**（可选）：固定指定凭据槽位后端（仅支持 `"auto"`、`"dual"`、`"file"`、`"keyring"` 四种值，省略时默认为 `"auto"`）。例如在桌面上若希望纯走钥匙串不在磁盘生成文件可设为 `"keyring"`，若希望只改磁盘文件而不碰系统钥匙串则可设为 `"file"`。生效优先级为：`命令行 --backend > AGY_SWITCH_CLI_BACKEND 环境变量 > config.json > 默认 auto`。
- **`network.proxy_url`**：支持 `http://`、`https://`、`socks5://`、`socks5h://`（或 `socks://`，由代理端解析远端域名，可避免本地 DNS 污染）、省略协议头的 `127.0.0.1:1080`，以及 `"direct"`（强制直连，忽略系统代理环境变量）。代理生效优先级为：`命令行 --proxy > AGY_SWITCH_CLI_PROXY > config.json > 系统环境变量（HTTPS_PROXY / HTTP_PROXY / ALL_PROXY）`。
- **`network.no_proxy`**：可选，逗号分隔的不走代理域名或网段列表。注意本机环回地址（`127.0.0.1`、`localhost`、`[::1]`，如 `--ssh` 登录回调监听端口）始终自动直连，不会被代理拦截。

### 6.2 场景二：零基础读懂并注册自定义 OAuth 客户端（完整字段详解）

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
   agy-switch-cli auth login --client my_custom_oauth --label "自建客户端账号"
   agy-switch-cli accounts add --client my_custom_oauth
   ```
   绑定完成后，该账号档案会自动记住 `oauth_client_key = "my_custom_oauth"`，后续日常执行 `switch`、`quota --refresh`、`run` 或 `daemon` 自动续期时都会自动匹配这组客户端凭据，无需每次重复传入 `--client`（即使混用多个不同客户端签发的账号也能各自独立续期）。
3. **无文件环境变量注入方式（适合 Docker 容器）**：除了写 `config.json`，也可以通过环境变量 `ANTIGRAVITY_OAUTH_CLIENTS="key|client_id|client_secret|label"`（多项之间用分号 `;` 分隔，优先级高于 `config.json`）与 `ANTIGRAVITY_OAUTH_CLIENT_KEY="<KEY>"` 动态注入。

---

## 7. 后台常驻运行指南（`systemd --user` 与无 `systemd` 的 Docker 容器环境）

`agy-switch-cli daemon` 本身设计为标准前台长运行进程（内置 `daemon.lock` 单实例互斥锁与 `SIGTERM` 优雅退出机制），不自行向后台分裂（fork）。下面分别说明在带有 `systemd` 的常规 Linux 系统上，以及在**没有 `systemd` 的 Docker 容器（如远程开发容器、云算力容器、WSL 精简环境）**中，如何让 `daemon` 在后台稳定常驻运行。

### 7.1 常规 Linux 系统（使用 `daemon --install` 管理 `systemd --user` 用户级服务）

在支持 `systemd` 的 Linux 服务器或桌面上，建议使用**当前普通用户的 `--user` 服务**（而非 `root` 系统级服务）来托管 `daemon`。这样可以保证后台服务与你平时运行 `agy` 的终端共享同一个 `$HOME` 目录、相同的文件属主与一致的 `~/.gemini/antigravity-cli` 凭据路径，避免因 `root` 权限写出普通用户无权读取的文件。

程序内置了 `daemon --install` 与 `daemon --uninstall`，无需手动复制修改服务模板文件即可一键完成部署（若当前处于无 `systemd` 的 Docker 容器或精简 WSL 中，`daemon --install` 会自动识别并提示改用下方第 `7.2` 节方案）：

```bash
# 第 1 步：启动服务前，先确认已添加账号并开启了自动切号策略（默认 reserve 5% / minimum 15%）
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

*(注：仓库内的 [`deploy/agy-switch-cli.service`](../deploy/agy-switch-cli.service) 同步保留了标准单元模板供审阅或手工定制参考。)*

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
- **问：日常使用时，手动切号、可选的 `run` 包装启动与后台 `daemon` 各自适合什么场景？**
  - **答**：三种方式定位清晰，可按实际需求选用：
    - **交互式看板或手动切号（`tui` / `switch`）**：适合日常按需查看额度并手动切换账号，切完直接运行 `agy` 即可。
    - **可选启动包装器 `run`**：适合单次临时指定某个账号（`run --account <ID|EMAIL> -- agy`），或在图形桌面上通过 `--backend file run -- agy` 将终端 `agy` 登录态与桌面端钥匙串隔离。
    - **后台守护进程 `daemon`**：适合已配置 `policy` 且希望后台静默监控额度、在触及保留线时提前换好凭据槽位，省去重开 `agy` 时手动进看板切号的步骤。
