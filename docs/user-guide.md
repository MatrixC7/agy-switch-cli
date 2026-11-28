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
2. [上手前必读：核心概念与合规风控边界](#2-上手前必读核心概念与合规风控边界)
3. [全局选项与环境变量](#3-全局选项与环境变量)
4. [全量命令与参数详解](#4-全量命令与参数详解)
   - [4.1 环境状态只读巡检：`status`](#41-环境状态只读巡检status)
   - [4.2 登录与 OAuth 授权管理：`auth`（默认免配置粘贴登录）](#42-登录与-oauth-授权管理auth默认免配置粘贴登录)
   - [4.3 账号池管理、批量导入与排序：`accounts`](#43-账号池管理批量导入与排序accounts)
   - [4.4 查看当前身份/模型分组与手动切号：`current` / `switch`](#44-查看当前身份模型分组与手动切号current--switch)
   - [4.5 配额查询与官方 CLI 委托刷新：`quota` / `refresh`](#45-配额查询与官方-cli-委托刷新quota--refresh)
   - [4.6 指定凭据与后端启动包装器：`run`](#46-指定凭据与后端启动包装器run)
   - [4.7 SSH 交互式终端看板：`tui`（全键盘可视化操作）](#47-ssh-交互式终端看板tui全键盘可视化操作)
   - [4.8 本地 Token 用量统计与请求明细：`stats summary` / `stats list`](#48-本地-token-用量统计与请求明细stats-summary--stats-list)
5. [标准退出码（`0..=8`）与 `--json` 脚本集成契约](#5-标准退出码08与---json-脚本集成契约)
6. [可选配置文件（`config.json` 代理、后端与自定义 OAuth 客户端）](#6-可选配置文件configjson-代理后端与自定义-oauth-客户端)
7. [常见问题解答（FAQ）](#7-常见问题解答faq)
8. [完整卸载与本地遗留文件清理清单](#8-完整卸载与本地遗留文件清理清单)

---

## 1. 安装指南与架构选型（按步操作）

### 1.1 按 CPU 架构选择预编译压缩包（全功能合一纯静态单文件）

在 GitHub Releases 发布页中，每个 CPU 架构均统一提供**单一完整的全功能预编译压缩包**（无需区分服务器版与桌面版，可在终端输入 `uname -m` 确认当前机器架构）：

| 预编译压缩包（按架构区分） | 适用硬件与系统环境 | 内置能力与体积说明 |
| :--- | :--- | :--- |
| **`agy-switch-cli-<版本>-x86_64-unknown-linux-musl.tar.gz`** | 常见 Intel / AMD 64 位云服务器、PC、WSL2 与 Docker 容器（`uname -m` 输出 `x86_64`） | **100% 纯静态单文件 ELF**（约 `12.5 MiB`，压缩包约 `5.7 MiB`，零外部 `.so` 动态库依赖），完整内置核心 CLI、`stats` 本地统计、`tui` 交互看板与纯 Rust D-Bus 系统钥匙串自适应后端 |
| **`agy-switch-cli-<版本>-aarch64-unknown-linux-musl.tar.gz`** | ARM64 云服务器、树莓派与 ARM 容器（`uname -m` 输出 `aarch64`） | **100% 纯静态单文件 ELF**（约 `11.0 MiB`，压缩包约 `5.4 MiB`，零外部 `.so` 动态库依赖），内置与 `x86_64` 完全一致的全量功能 |

- **同一份二进制自动适配无头服务器与图形桌面**：
  - 在远程 SSH 服务器、Docker 容器、无桌面 WSL2 中运行时，默认的 `--backend auto` 会自动使用本地文件后端（`file`），零额外配置。
  - 在开启了 GNOME Keyring 或 KDE Wallet 的 Linux 图形桌面上运行时，默认的 `--backend auto` 会自动检测到本机活跃钥匙串并启用事务性双写模式（`dual`），同步更新系统钥匙串与本地凭据文件，切号后直接运行 `agy` 即刻生效。

### 1.2 下载、校验与安装步骤

可直接在终端中使用 `curl` 按当前机器架构（`uname -m` 自动输出 `x86_64` 或 `aarch64`）拉取压缩包及校验文件并完成安装（新版本发布时请将 `VER` 替换为实际版本号；亦可在浏览器前往 [GitHub Releases](https://github.com/MatrixC7/agy-switch-cli/releases) 手动下载）：

```bash
# 第 1 步：在终端直接下载对应架构的压缩包与 SHA-256 校验文件（需要代理时可先 export https_proxy=... 或给 curl 加 -x）
VER=v1.3.0
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

## 2. 上手前必读：核心概念与合规风控边界

- **如何在命令中指定账号（`<ID|EMAIL>`）？**
  - 为防止排序变动或账号增删导致命令行序号漂移误触其他账号，所有命令行子命令统一采用与账号终身绑定的精确标识：
    - **直接输入邮箱**（如 `alice@example.com`，不区分大小写，直观且安全）。
    - **输入内部账号 ID**（如 `acc-0001...`，可通过 `accounts list` 查看，用于区分极少数同邮箱重复记录）。
  - 如果你不想在命令行手动输入邮箱，可以直接运行 `agy-switch-cli tui` 打开可视化交互看板，通过上下方向键高亮选中账号后一键完成切号、调序、启停与导出。
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
  - **切号生效时机**：无论裸命令行 `agy` 还是通过 ACP 协议接入的客户端，均在进程启动或新建对话 Worker 时一次性加载凭据并常驻内存（不会按每轮提问重读磁盘或钥匙串）。因此，切换凭据槽位均对**切换完成之后新启动的 `agy` 命令（或新开的对话）**立即生效，**绝不会中途篡改或强行打断正在运行中的 `agy` 会话**。
- **配额池（`Gemini` vs `Claude / GPT`）与双窗口（`Weekly` 周额度 vs `5h` 五小时额度）**
  - Google Antigravity 的额度按**配额池**共享计算：
    - **`Gemini` 池**：常规 Gemini 系列模型共用。
    - **`Claude / GPT` 池**：Claude Sonnet / Opus 与 GPT-OSS 等模型共用。
    - **`Argon` 池**：仅部分灰度测试账号才会被下发。普通商业订阅账号没有该池，`tui` 和 `quota` 会默认将其隐藏，属于正常现象。
  - 每个配额池按官方 `/usage` 实际返回的窗口桶展示与评估：存在 **`Weekly`（7 天滚动周总额度）** 与 **`5h`（5 小时短期防刷窗口）** 两个窗口时取短板 `min(Weekly, 5h)`，仅返回 `Weekly` 桶时直接按 `Weekly` 评估（不再展示不可靠的订阅 `Plan` 名称）。
- **按需官方 CLI 委托查额与配额缓存保鲜期（`stale`）**
  - 为彻底避免直连 Google 内部接口的风险，本工具的配额刷新（`quota --refresh`、`refresh` 与 `tui` 中的 `r`）仅在用户手动触发时委托本机已安装的官方 `agy -p "/usage" --output-format json < /dev/null`，**仅针对当前官方活跃槽位**查询最新配额（零对话落盘、零 token 消耗；尚未消耗的满额桶若返回 Unix Epoch 0 重置时间，工具自动归一化展示为 `—` 而不会误判过期）。
  - 本地配额缓存（`quota` 只读查看与休眠账号缓存）的默认保鲜期为 **`1 小时（3600 秒）`**：
    - 距离上次刷新 **1 小时以内**（且未跨过重置时间点），只读查看 `agy-switch-cli quota` 显示为 `known`（新鲜有效）。
    - 超过 **1 小时**后，缓存标为 `stale`。此时手动运行 `agy-switch-cli quota` **依然会正常展示上次缓存的进度表**，并在状态行温和提示可加 `--refresh`（`agy-switch-cli quota --refresh`）委托官方 `agy` 更新当前活跃槽位。
- **合规边界与账号风控说明（`agy -p "/usage"`、ACP、多账号切换与降风险实践）**
  - **风险分层与已移除的高危路径**：
    - 第三方客户端直连 Google 内部后端配额接口、伪造内部客户端请求头、借助后台无人值守守护进程定时轮询切号，或通过非官方代理/桥接层转发消费级 OAuth 令牌，明确违反 Google Antigravity 附加服务条款（第 6 节），属于自动化反滥用清扫（`403 PERMISSION_DENIED` / `TOS_VIOLATION`）的高风险来源。本工具已彻底移除全部内部接口直连、客户端标识伪造及后台自动切号守护进程。
  - **官方 CLI 委托查额（`agy -p "/usage"`）与 ACP 场景的残余风险**：
    - **技术实现口径**：本工具的实时查额统一委托本机已安装的官方 `agy -p "/usage" --output-format json < /dev/null`（打印模式内置斜杠命令，非 `agy acp`，当前 ACP 协议尚未暴露额度 RPC）。
    - **条款与风控灰区**：从 Google 消费级订阅条款（`oauth-personal`）的严格口径看，官方主要面向交互式 `agy` 与受支持 IDE 的薄客户端集成。无论是由第三方工具程序化调用 `agy -p "/usage"`，还是在外部编排框架中封装 `agy acp` 驱动自动化循环，都**不能保证零风控风险**，仍可能被判定为第三方工具包装或非交互式自动化访问。
  - **多账号切换与同机并发风险**：
    - 个人消费级订阅均按单人单账号配额模型授权。在同一台机器上并发运行多个消费级账号或高频切换本地槽位以规避 `5h` / `Weekly` 限流，均存在触发 Google 自动化反滥用检测的风险。
  - **触发风控后的影响范围与申诉规则**：
    - 一旦触发 `TOS_VIOLATION`（HTTP `403 PERMISSION_DENIED`），停用范围通常会联动波及同一账号下的 **Antigravity、Gemini CLI 与 Gemini Code Assist** 等同源开发者服务层（通常不会直接停用 Gmail、Google Drive 等主站基础个人服务，但相关 AI 编码服务权限会被冻结）。
    - 按 Google 现行处理惯例，首次触发第三方工具风控通常有一次通过官方表单提交申诉并承诺停止使用非官方工具的恢复机会；**二次重复违规可能导致相关开发者服务被永久停用**。
  - **建议的低风险使用习惯与官方替代方案**：
    - **纯离线功能优先**：日常凭据备份、本地只读 `stats` 统计与低频手动 `switch` / `accounts add --from-local` 均为纯本地零网络操作，不产生额外远端特征。
    - **控制按需查额频率**：避免短时间内反复执行 `quota --refresh`、`refresh` 或在 `tui` 中频繁按 `r`。
    - **避免同机多账号并发**：不要在同一台宿主机上同时并行跑多个不同消费级账号的自动化任务。
    - **自动化与多 Agent 场景改用官方 API 凭据**：如果你的核心需求是脚本编排、CI/CD 集成或外部多 Agent 调度，请使用 Google 官方面向程序化访问的 **Google AI Studio API Key（`GEMINI_API_KEY`）** 或 **Vertex AI / Gemini Enterprise** 商业凭据，切勿复用个人消费级 OAuth 订阅。

---

## 3. 全局选项与环境变量

以下全局选项可加在任意子命令之前或之后（日常使用保持默认即可，无需填写）：

| 全局选项 | 对应环境变量 | 默认行为与通俗说明 |
| :--- | :--- | :--- |
| `--data-dir <目录路径>` | `AGY_SWITCH_CLI_DATA_DIR` | 指定账号库存储目录。默认位于 `~/.local/share/agy-switch-cli`（目录权限自动设为 `0700`）。 |
| `--proxy <代理地址\|direct>` | `AGY_SWITCH_CLI_PROXY` | 指定显式 `auth` 登录/重授权与裸 `refresh_token` 导入访问 Google 标准 OAuth 端点的网络代理，支持 `socks5h://127.0.0.1:1080`、`socks://127.0.0.1:1080`、`http://127.0.0.1:7890`、省略协议头的 `127.0.0.1:7890`，或填 `direct` 强制直连。不填时优先读取 `config.json`，其次自动读取并规范化终端环境变量 `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`（注意 Linux 图形界面的“系统代理”不会自动注入终端，若不想每次传 `--proxy`，需在终端导出代理环境变量或写入 `config.json`）。 |
| `--backend <auto\|dual\|file\|keyring>` | `AGY_SWITCH_CLI_BACKEND` | 指定凭据槽位后端模式（严格匹配这 4 个小写字面值，区分大小写且不接受空字符串或外围空白；亦可在 `config.json` 的 `"backend"` 字段持久化），默认为 **`auto`**。四种模式的具体区别见下表。 |
| `--json` | — | 输出机器可读的标准 JSON 格式（供自动化脚本解析使用；全屏交互看板 `tui` 与实时监控 `stats ... --watch` 均与 `--json` 互斥，`run` 包装器在启动准备无误后直接透传 `agy` 子进程的标准输入输出）。 |

#### `--backend` 四种凭据后端模式详解

- **`auto`（默认值，日常无需手改）**：
  - 在无桌面钥匙串的 SSH 服务器、Docker 容器或 WSL2 中，自动使用 `file` 模式。
  - 在存在本机活跃 D-Bus 系统钥匙串（GNOME Keyring / KDE Wallet）的 Linux 图形桌面上，自动使用 `dual` 模式。
- **`dual`（显式双写同步）**：
  - 强制要求同时读写系统钥匙串与本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件，并在切号时执行双端原子事务与异常回滚（若当前环境没有可用钥匙串则明确报错退出）。
- **`file`（纯本地文件模式）**：
  - 仅读写本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件，全程不访问或修改系统钥匙串。当通过 `--backend file`、`AGY_SWITCH_CLI_BACKEND=file` 或 `config.json` 中的 `"backend": "file"` **显式指定**为 `file` 模式且宿主环境中存在桌面 D-Bus 会话总线时，拉起官方 `agy` 子进程的入口（包括可选包装器 `run` 以及委托查额的 `quota --refresh` / `refresh` / `tui`）都会自动为 `agy` 子进程注入 `DBUS_SESSION_BUS_ADDRESS=unix:path=/dev/null`，从而确保 `agy` 严格读写本地文件槽位而与图形桌面 App 钥匙串登录态隔离（而无钥匙串服务器上的默认 `auto` 回退不会修改子进程 D-Bus 环境变量，不影响子进程内的 `systemctl --user` 等操作）。
- **`keyring`（纯系统钥匙串模式，零本地文件读写）**：
  - 仅读写系统 D-Bus Secret Service 钥匙串，绝不创建、修改、读取或要求本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件存在（适合已在图形桌面完全使用钥匙串管理登录态、希望保持磁盘上不留明文凭据文件的用户）。

---

## 4. 全量命令与参数详解

### 4.1 环境状态只读巡检：`status`

`status` 用于以纯只读方式（不修改本地账号库、凭据槽位与系统钥匙串，不发起任何网络请求；仅在发现本地官方 `agy` 时创建并随即清理隔离的临时探测目录）对本机运行环境、账号存储库、切号事务日志、生效凭据槽位以及本机官方 `agy` 可执行文件做一次快速健康检查：

```bash
agy-switch-cli status          # 纯只读巡检本地环境、存储库与官方 agy 版本
agy-switch-cli status --json   # 输出结构化 JSON 巡检报告
```

标准输出示例：
```text
agy-switch-cli status (v1.3.0)
  Backend:           dual
  Store status:      OK
  Journal status:    Clean
  Slot initialized:  true
  Antigravity CLI:   /usr/bin/agy v1.5.17
  Antigravity App:   /usr/bin/antigravity v2.33.0
```

#### 输出字段逐行详解

- **标题行 `agy-switch-cli status (v...)`**：显示当前正在运行的 `agy-switch-cli` 自身版本号。
- **`Backend`（当前生效凭据后端）**：综合命令行 `--backend`、环境变量 `AGY_SWITCH_CLI_BACKEND`、`config.json` 与本机环境探测后实际采用的后端模式：
  - `file`：仅读写本地磁盘凭据文件 `~/.gemini/antigravity-cli/antigravity-oauth-token`（无桌面钥匙串的 SSH 服务器、Docker 容器或 WSL2 下默认采用此模式）。
  - `dual`：同时对桌面系统钥匙串（GNOME Keyring / KDE Wallet）与本地凭据文件执行事务性双写（带有活跃钥匙串的 Linux 图形桌面默认采用此模式）。
  - `keyring`：仅读写系统钥匙串，完全不创建或读写本地凭据文件。
- **`Store status`（本地账号库健康度）**：校验数据目录（默认 `~/.local/share/agy-switch-cli`）下的账号索引 `index.json`、各账号文件 `accounts/*.json`、可选配置文件 `config.json`、授权暂存记录及历史令牌谱系归档是否完整合法（从 `v1.2.x` 升级残留的旧 `policy.json` 与 `state/daemon_state.json` 会被静默忽略）：
  - 全部校验通过时显示 `OK`。
  - 若存在文件损坏或权限异常，命令会直接输出具体报错原因并返回退出码 `1`。
- **`Journal status`（切号崩溃恢复日志状态）**：反映内部预写事务日志 `state/switch_journal.json` 的当前状态：
  - `Clean`：常规健康状态，表示没有任何中断残留的切号事务。
  - `AbortedUncommitted`：上次切号在修改外部凭据槽位之前就已经提前退出，外部凭据完好无损；后续你正常执行任意写命令（如 `switch`、`accounts` 等）时会自动清理该记录。
  - `CommittedIndexPending` 或 `RecoveryIncomplete`：上次切号或清槽留下未完成、尚未确认持久化或无法核实的事务（例如中途中断、双写仅更新一侧副本、父目录持久化同步失败，或事务日志元数据损坏/矛盾）。由于 `status` 严格只读不会擅自改写状态，此时会如实报告该状态并返回退出码 `7`；后续执行交互式写命令（如 `agy-switch-cli switch <ID|EMAIL>`、`accounts enable` 等）会先在持有锁与外部凭据防误覆盖（CAS）保护的前提下尝试对账，只有在能够安全核实事务状态并完成耐久性检查后才会清理日志。若重放后仍返回退出码 `7`，请保留日志并按诊断信息排除底层存储、权限或后端问题后再重试，不要手动删除 `state/switch_journal.json`。
- **`Slot initialized`（官方凭据槽位是否已初始化）**：
  - `true`：当前生效后端中已经存有 `agy` 登录凭据。
  - `false`：全新环境尚未登录或尚未向槽位写入过凭据（属于正常初始状态；若槽位文件存在但 JSON 内容损坏，`status` 会报错并返回退出码 `1`）。
- **`Antigravity CLI`（本机官方 `agy` 可执行文件探测）**：在独立进程组（`process_group(0)`）与隔离的空临时目录环境中（清空并覆盖 `HOME`、`XDG_*`、`TMPDIR`、`DBUS_SESSION_BUS_ADDRESS` 与 `NO_PROXY=*`，限时 3 秒，超时或退出时向整个子进程组发送 `SIGKILL` 并回收直接子进程）调用本机 `agy --version` 获取路径与版本号（面向本机可信 `agy` 可执行文件的环境变量、临时目录与进程组隔离，不构成操作系统内核级容器命名空间沙盒）：
  - 已正常安装时输出实际路径与版本号，如 `/usr/bin/agy v1.5.17`。
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

# 已有账号令牌失效（invalid_grant）或权限不足时，原地重新登录更新（支持填邮箱或 ID，保留原有排序和备注设置）
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
  - **什么情况下才会用到它？** Google OAuth 2.0 有一条严格规则：**由哪个 `client_id` 签发的 `refresh_token`，后续在显式 `auth` 换码或裸令牌导入时就必须继续配对同一个 `client_id` 和 `client_secret`**。如果你手头有通过自建 Google Cloud 项目或其他第三方工具签发的 Token，在按第 `6.2` 节写入 `config.json` 后，就可以运行 `auth clients` 核对自定义客户端是否已成功加载、有没有字段缺失警告。

---

### 4.3 账号池管理、批量导入与排序：`accounts`

#### （1）查看账号列表与调整顺序：`accounts list`

`accounts list` 统一集成了**账号详情展示**与**顺序调整**功能：

```bash
# 1. 直接查看所有账号（纯只读，显示序号、选中星号 *、邮箱、备注、状态与内部 ID）：
agy-switch-cli accounts list
# 输出示例：
#  1. * alice@example.com    (primary)            (acc-0001...)
#  2.   bob@example.com      (backup)             (acc-0002...)
#  3.   charlie@example.com  [disabled]           (acc-0003...)

# 2. 将某一个账号单独移到指定目标槽位（--move 填邮箱或 ID，--to 填目标位置编号 1..N）：
agy-switch-cli accounts list --move charlie@example.com --to 1
agy-switch-cli accounts list --move bob@example.com --to 1

# 3. 一次性按新顺序重排全部账号（须包含每一个已存账号的邮箱或 ID）：
agy-switch-cli accounts list --order bob@example.com charlie@example.com alice@example.com
```

> **提示**：你也可以运行 `agy-switch-cli tui` 进入可视化看板，按 **`[`（上移）** 或 **`]`（下移）** 实时调整顺序。

#### （2）导入本机已登录账号或通过 Refresh Token 添加账号：`accounts add`

> **安全保护说明**：为防止机密 Token 留在终端历史记录（`.bash_history`）或被系统进程表泄露，工具禁止将 Token 直接作为命令行位置参数传入，统一使用清晰一致的 `--from-local`、`--from-file`、`--from-stdin` 或交互式无回显粘贴：

**场景 A：当前设备已登录官方 `agy`（或桌面端与 `agy` 在系统钥匙串中共用条目），纯本地离线抓入账号库（`--from-local`）**
```bash
agy-switch-cli accounts add --from-local --label "local"
```
- **按当前生效的 `--backend` 模式自动选择读取源**：
  - 在默认的 **`auto`**（桌面有钥匙串时）或 **`dual`** 模式下：程序优先读取系统钥匙串（`Password for 'antigravity' on 'gemini'`，若集合处于锁定状态会按标准接口请求解锁，而日常只读探测 `auto` / `current` / `status` 绝不触发解锁）；若钥匙串中尚无记录，则自动回退读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
  - 在 **`file`** 模式（或无桌面服务器 / 容器环境）下：程序仅读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
  - 在 **`keyring`** 模式下：程序仅读取系统钥匙串，不会回退读取磁盘上的 `antigravity-oauth-token`。
  - **支持范围边界**：`--from-local` 严格面向官方 `agy` CLI 生效凭据源设计，不会读取桌面端 App / VS Code 扩展专用的回退文件 `~/.gemini/jetski-standalone-oauth-token`。若桌面系统未启用钥匙串、且仅存在 `jetski-standalone-oauth-token` 而未登录过 `agy` CLI，请改用 `agy-switch-cli auth login` 登录。
- **100% 纯本地离线入库（零网络请求）**：读取本地完整凭据载荷后，程序直接从 `id_token` JWT 或官方 `agy 1.5+` 写入的紧凑字段 `id_token_email` 中提取邮箱，并同步记录当前活跃槽位的切入时间戳（供 `tui` `Last Used (dur)` 列展示），全程不发起任何 OAuth 网络请求（若该邮箱已在库中则按令牌谱系防回退规则安全更新，不会重复建号；若极少数早期本地凭据文件缺失邮箱元数据，程序会给出清晰报错提示改用 `agy-switch-cli auth login` 或先启动一次官方 `agy`）。

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

### 4.4 查看当前身份/模型分组与手动切号：`current` / `switch`

#### （1）查看当前账号状态与模型分组：`current`

```bash
agy-switch-cli current
```

输出示例与逐行说明：
```text
Selected account : alice@example.com  (primary)  (acc-0001...)
Active agy slot  : matched (alice@example.com, expires 2026-11-17 16:00)
Live agy runtime : idle
Model groups     : 2 group(s) (from official agy /usage)
  Gemini Models         : Gemini 4 Hydrogen, Gemini 3.8 Flash
  Claude and GPT models : Claude Sonnet 4.6, Claude Opus 4.6, GPT-OSS 120B
```
- **`Selected account`**：本地账号库中当前选中的账号、自定义备注与内部 ID。
- **`Active agy slot`**：当前生效凭据槽位中的实际身份状态（仅展示邮箱与换算为本机本地时区的 `YYYY-MM-DD HH:MM` 过期时间；`matched` 表示与选中账号一致，`drifted_known` / `drifted_external` 表示凭据曾被外部改动，`uninitialized` 表示尚未写入凭据）。
- **`Live agy runtime`**：当前系统中是否有正在运行的 `agy` 进程。它共有以下 4 种状态：
  - **`idle`**：当前系统中没有检测到当前用户的 `agy` 进程在运行。
  - **`unmanaged_running (pids=[636233])`**（若同时存在受管进程则附加 `, managed_accounts=[...]`）：表示检测到你直接在终端输入 `agy` 启动的运行中会话（未经可选的 `run -- agy` 包装登记租约，因此称为“未受管运行”）。各部分含义如下：
    - `unmanaged_running`：存在直接裸跑启动的 `agy` 进程，属于完全正常的日常使用状态（由于 `agy` 在启动瞬间将登录凭据加载进自身内存后便不留外部租约标记，且此后磁盘或钥匙串槽位可能已经切换过，工具不会臆测其启动时的登录身份，仅列出对应的进程号）。
    - `pids=[636233]`：当前检测到的未受管 `agy` 进程号（PID）列表。
    - `managed_accounts=[...]`：仅当系统中同时既有直接启动的 `agy`、又有通过 `agy-switch-cli run -- agy` 启动的受管进程时才会出现，用于列出受管进程已登记的账号 ID；平时没有受管进程时会自动省略该字段，保持输出简洁。
  - **`managed_running (count=1, accounts=["acc-0001"], pids=[636240])`**：当前所有运行中的 `agy` 进程均是通过可选的 `agy-switch-cli run -- agy` 启动的，工具通过本地双因子进程租约确切知道运行数量（`count`）、对应的账号 ID（`accounts`）与进程号（`pids`）。
  - **`unverified (...)`**：当前运行环境（如挂载受限的特殊容器）无法完整读取 `/proc` 进程表，工具无法核实是否有 `agy` 正在运行；出于故障关闭安全原则，未加 `--allow-running` 的手动切号此时会拒绝盲目改写凭据。
- **`Model groups` / `Supported models`**：采用官方 `agy -p "/usage"` 观测时，自动剥离描述开头冗余的 `Models within this group:` 前缀（不篡改磁盘原文）并按组名最大宽度对齐冒号展示；若账号仍保留旧版逐模型缓存则按家族分组展示 `Supported models`。

#### （2）手动切换生效账号：`switch`（纯本地离线切槽、切出前回采与四种后端模式详解）

`switch` 通过**邮箱**或**账号 ID**精确指定目标账号（日常交互切号也可直接使用 `agy-switch-cli tui`），全程**纯本地零网络操作**（不再调用 OAuth 续期接口，由官方 `agy` 在启动时自主按需续期）：

```bash
agy-switch-cli switch bob@example.com                   # 按邮箱立即离线切换到指定账号（对后续新启动的 agy 生效）
agy-switch-cli switch acc-0002                          # 或按内部账号 ID 切换到指定账号
agy-switch-cli switch bob@example.com --dry-run         # 仅做切换前条件预检，不发网络请求也不修改任何凭据
agy-switch-cli switch bob@example.com --require-idle    # 严格要求当前无任何运行中的 agy 进程才允许切号（适合特殊脚本）
agy-switch-cli switch bob@example.com --allow-running   # 在 /proc 不可读（unverified）的特殊容器环境中显式放行切号
```

- **切出前自动本地回采同步（Pre-Switch Sync-Back）与切换时间记账**：
  - 每次切出当前账号 A 之前，程序在 `L1` 槽位锁内会先纯本地检查当前官方槽位/钥匙串中的凭据：若可确认为账号 A（按 `refresh_token` 指纹或当前 `selected_account_id` 配合本地 `id_token` / `id_token_email` 邮箱一致）且官方 `agy` 在运行期间刷新了更新鲜的 `access_token` 或轮换了新的 `refresh_token`，程序会先在 `L3` 写锁内将最新令牌安全合并回 `accounts/<A>.json`（保留 `66,048` 级已淘汰谱系防回退），再原子写入目标账号 B。
  - 提交阶段在同一个 `L3` 写锁事务内同步更新切出账号的 `last_switched_out_at` 与切入账号的 `last_switched_in_at`（用于 `tui` 主表 `Last Used (dur)` 列展示；若切出前槽位被外部登录替换则不会伪造原账号的 `last_switched_out_at`）。
- **当已有 `agy` 窗口正在运行时执行 `switch`（或 `tui` 切号）会发生什么？**
  - 默认情况下，检测到正在运行的 `agy` 进程时**不会报错拦截**，而是立即完成凭据切换，并输出一条温和提示：正在运行的旧 `agy` 窗口继续保持其启动时的原账号会话不受打断，而此后新打开的 `agy` 终端窗口（或 ACP 客户端新开的对话）将立即使用刚切好的新账号。
  - 如果你的自动化脚本希望“只要有 `agy` 在跑就禁止切号”，可显式加上 `--require-idle`（存在活跃 `agy` 时返回退出码 `8`）；若处于 `/proc` 被屏蔽的特殊容器（`unverified`），默认仍保持故障关闭拦截，确认安全时可加 `--allow-running` 放行（`--require-idle` 与 `--allow-running` 互斥）。
- **当账号处于 `verify-blocked`（`[verification required]`）风控验证状态时**：
  - 当账号因 Google 返回 `403 VALIDATION_REQUIRED` 被标为 `verify-blocked` 时，其 OAuth 登录令牌本身仍有效。手动执行 `switch --dry-run` 可正常预检，手动执行 `switch`、`tui` 按 `Enter` 或可选的 `run` 均允许切入该账号以便打开官方 `agy` 完成网页/扫码验证。
  - 人工切入时**不会提前清除** `verify-blocked` 标记，同时会打印操作指引。在官方 `agy` 内完成验证后，直接执行 `agy-switch-cli refresh`（或在 `tui` 中停在当前活跃 `*` 行按 `r`），当官方 `agy -p "/usage"` 返回未阻断的有效观测时即自动解除该状态。
  - 被禁用（`disabled`）、令牌已被吊销或缺失 OAuth 权限范围（`scope_reauth_required`）的账号在所有入口仍严格拒绝切换。
- **不同环境与 `--backend` 模式下的切号行为**：
  - **纯无头环境（远程 SSH 服务器、Docker 容器、无桌面 WSL2）**：默认 `auto` 自动采用 `file` 模式，以 `0600` 权限原子替换 `~/.gemini/antigravity-cli/antigravity-oauth-token`，切完直接运行 `agy` 即刻生效。
  - **带有系统钥匙串的 Linux 图形桌面环境（如 KDE Plasma、GNOME）**：
    - **默认用法（`auto` 自动启用 `dual` 事务性双写）**：直接运行 `agy-switch-cli switch bob@example.com`（无需手传额外参数），程序自动对系统钥匙串集合与本地 `antigravity-oauth-token` 执行前置快照、加密更新、双 `fsync` 落盘与双副本一致性回读校验（任一步失败自动双端回滚；若遇到传输中断等不确定状态则保留切换日志并返回退出码 `7`，后续交互式写命令会在安全 CAS 保护下尝试对账，并在安全核实状态与耐久性检查通过后清理日志，详见 [4.1 节 `status`](#41-环境状态只读巡检status) 的 `Journal status` 恢复指引）。切完后在任意终端直接输入 `agy` 立即使用新账号。
    - **仅用钥匙串不留本地文件（`--backend keyring`）**：执行 `agy-switch-cli --backend keyring switch bob@example.com`（或在 `config.json` 中设 `"backend": "keyring"`），程序仅读写系统钥匙串，完全不创建或修改 `~/.gemini/antigravity-cli/antigravity-oauth-token`。
    - **桌面与 CLI 账号隔离（显式 `--backend file` + `run`）**：若希望桌面端 App 保持原钥匙串账号、仅让终端里的 `agy` 换用另一个账号，可执行 `agy-switch-cli --backend file switch bob@example.com` 只改本地文件，再通过可选方式 `agy-switch-cli --backend file run -- agy` 启动（显式选择 `file` 后端时，`run` 会自动为子进程屏蔽桌面钥匙串总线）。

---

### 4.5 配额查询与官方 CLI 委托刷新：`quota` / `refresh`

所有联网配额刷新均仅在用户按需触发时通过本机官方 `agy -p "/usage" --output-format json < /dev/null` 执行，且**严格仅支持刷新当前官方活跃槽位**（绝不在后台批量扫描休眠账号）；评估默认直接覆盖全部配额池（`all`）：

```bash
# 1. 纯只读查看当前选中账号的本地缓存配额表（零网络请求）：
agy-switch-cli quota

# 2. 委托官方 `agy -p "/usage"` 刷新当前活跃官方槽位的最新配额，并立即打印配额进度表：
agy-switch-cli quota --refresh

# 3. 纯只读查看指定账号或全部账号的本地缓存配额表（零网络请求）：
agy-switch-cli quota bob@example.com
agy-switch-cli quota --all

# 4. 委托官方 `agy -p "/usage"` 刷新当前活跃官方槽位并落盘（顺带纯本地回采最新令牌）：
agy-switch-cli refresh
# 也可显式传入当前活跃账号的邮箱或 ID 做安全核对（若传入的不是当前活跃账号，将直接提示用法错误并返回退出码 2）：
agy-switch-cli refresh alice@example.com
```

- **单槽刷新边界说明**：
  - `quota --refresh --all`、`quota <ID|EMAIL> --refresh`、`refresh --all`、`refresh <非活跃账号>` 与 `--concurrency` 均不受支持；传入这些组合会明确报错并返回退出码 `2`。
  - 若需要刷新某个休眠账号的配额，请先通过 `agy-switch-cli switch <ID|EMAIL>` 切入该账号，再执行 `agy-switch-cli quota --refresh` 或 `agy-switch-cli refresh`。
  - 显式指定 `--backend file` 且宿主存在桌面 D-Bus 总线时，委托调用 `agy -p "/usage"` 会自动注入 `DBUS_SESSION_BUS_ADDRESS=unix:path=/dev/null`，确保 `agy` 读取的是本地文件槽位。

**配额表各列说明**：
```text
Account : alice@example.com
Status  : known (97.0% effective on all) · updated just now (source: OfficialCli)

  Pool           Window   Remaining            Resets (Local)
  ───────────────────────────────────────────────────────────────────────────
  Gemini         Weekly   [██████████]   97%   2026-12-03 15:17  (in 5d 21h)
                 5h       [██████████]   97%   2026-11-27 19:18  (in 1h 04m)
  Claude / GPT   Weekly   [██████████]  100%   —
                 5h       [██████████]  100%   —
```
- `Weekly` 为 7 天滚动周总额度，`5h` 为 5 小时短期恢复窗口（若官方 `/usage` 仅返回 `Weekly` 桶，则直接按 `Weekly` 展示与评估）；
- `Resets (Local)` 已自动换算为本机所在的本地时区时间（统一格式为 `YYYY-MM-DD HH:MM`），并在括号内附带剩余重置倒计时（`in Xd Yh`）；满额尚未消耗的桶（官方返回 Unix Epoch 0）展示为 `—`。

---

### 4.6 指定凭据与后端启动包装器：`run`

日常在无头服务器或桌面上完成切号（`tui` 或 `switch`）后，直接输入官方 `agy` 即可使用，无需经过包装命令。`run` 作为**可选的受管凭据与后端启动包装器**，专注解决“启动前指定目标账号凭据”与“图形桌面上强制使用本地文件后端隔离钥匙串”两类确定性需求：

```bash
# 场景 A：指定本次使用某个邮箱或 ID 对应的账号同步凭据并启动官方 agy（双横杠 `--` 后面接原本的 agy 命令及任意参数）：
agy-switch-cli run --account bob@example.com -- agy
agy-switch-cli run --account bob@example.com -- agy chat "帮我检查这段代码的边界条件"

# 场景 B：在开启了 GNOME Keyring / KDE Wallet 的 Linux 图形桌面上，显式指定 --backend file（或设置 AGY_SWITCH_CLI_BACKEND=file / config.json "backend": "file"），使用本地文件槽位并自动为该 agy 子进程屏蔽桌面钥匙串：
agy-switch-cli --backend file run -- agy

# 场景 C：不传 --account 时，确保当前选中账号凭据已同步至生效槽位，登记受管进程租约后启动 agy：
agy-switch-cli run -- agy
```

**`run` 的确定性工作机制**：
- **纯本地离线凭据准备、零网络请求**：若传入 `--account <ID|EMAIL>`，纯本地离线将目标账号凭据同步至当前生效后端槽位（切出前自动回采原槽位最新令牌）；若省略 `--account`，则校验当前选中账号凭据与生效槽位一致（全程零 OAuth `/token` 网络调用，由官方 `agy` 启动时自行按需续期，绝不隐式拉取配额或自动切换账号）。
- **显式 `file` 后端自动隔离桌面钥匙串总线**：
  - 当通过命令行 `--backend file`、环境变量 `AGY_SWITCH_CLI_BACKEND=file` 或 `config.json` 中的 `"backend": "file"` **显式选择 `file` 后端**，且宿主环境中存在桌面会话总线（`DBUS_SESSION_BUS_ADDRESS` 或 `$XDG_RUNTIME_DIR/bus`）时，`run` 自身使用本地 `FileSessionBackend`（全程不触碰桌面钥匙串），并自动将拉起的 `agy` 子进程的 `DBUS_SESSION_BUS_ADDRESS` 设为 `unix:path=/dev/null`，确保终端内的 `agy` 从本地文件槽位读取凭据，而不影响桌面端 App 原有的钥匙串账号。
  - 若保持默认的 `--backend auto`，在无 Secret Service 钥匙串的无头 SSH 服务器上自动回退至 `file` 时，程序**不会**覆盖子进程的 `DBUS_SESSION_BUS_ADDRESS`，从而保证 `agy` 会话内部执行 `systemctl --user` 等用户总线命令完全不受影响。
- **双因子进程租约与退出码透传**：启动前检查 `/proc` 确保不存在未受管运行中的 `agy` 或其他受管账号冲突，拉起子进程后登记 `(pid + starttime)` 租约、转发 `SIGINT` / `SIGTERM` 信号，并在退出时清理租约、原样透传 `agy` 的退出码（桌面文件隔离场景可按需在 `~/.bashrc` 中设置可选别名 `alias agys='agy-switch-cli --backend file run -- agy'`）。

---

### 4.7 SSH 交互式终端看板：`tui`（全键盘可视化操作）

如需在单个界面中总览当前活跃号的双窗口详细配额、查看各账号最近使用与单次停留时长、调整列表顺序、查看详情卡片或离线切号，可运行：

```bash
agy-switch-cli tui
```

#### 界面布局说明（活跃号按池分行头部 + 精简 `Last Used (dur)` 主表）

- **顶部状态与活跃号 `Quota` 头部（极矮终端自动折叠）**：
  - 在常规高度（`>= 14` 行）终端中，顶部以垂直冒号对齐方式展示 `Session [file|dual|keyring] : ...`、`Runtime : ...`，紧接着展示**当前活跃官方槽位账号（`*`）**的无边框按池分行 `Quota (<age>)` 头部：
    ```text
    Quota (2m ago) : Gemini      5h  97% (1h04m)  · Weekly  97% (5d21h)
                     Claude/GPT  5h 100% (—)      · Weekly 100% (—)
    ```
    其中灰度池 `Argon` 仅在活跃账号存在该池数据时出现；满额未消耗桶的重置时间展示为 `(—)`；若发生外部漂移且当前槽位不匹配任何已存账号，顶部显示 `— (no active account)` 且不将任何行标为 `*`。
  - 在较矮终端（`7–13` 行）下，`Quota` 头部自动折叠为单行摘要（如 `Quota (2m ago) : Gem 97%/97% · 3P 100%/100%`）保住主表行；在 `< 11` 行分屏下顶部状态进一步折叠为紧凑单行；在 `< 7` 行极矮高度下隐藏独立头部，采用单行退化列表展示账号邮箱、`Last Used (dur)` 与状态，确保在任意尺寸下都不超出物理视口边界。
  - 在宽度小于 `152` 列的窗口中自动隐藏冗长的 36 位 `ID` 列；当账号数量超出窗口高度时保持顶栏、表头与底栏固定并跟随光标平滑滚动（标题栏显示 `[Showing X-Y of N]`），同时在表格首行/末行内嵌定高的 **`... (<K> more above)`** 与 **`... (<K> more below)`** 折叠提示行，滚动全程总行数恒定不跳动。
- **继承全局 `--backend` 并在顶栏明确标识（无看板内切换热键）**：
  - `tui` 严格继承全局生效后端（默认 `auto` 自动解析为 `Session [file]` 或 `Session [dual]`；若通过 `--backend keyring`、环境变量或 `config.json` 指定了后端，则对应显示 `Session [keyring]` 等标签），不在看板内部设置易误触的后端切换键，保证全局行为一致。
  - 按 `Enter` 或 `s` 纯本地离线切号时（切出前自动回采原槽位最新令牌并记录切出/切入时间），即使当前已有 `agy` 进程正在运行也会立即完成切换，并在底栏温和提示已运行的 `agy` 保持原登录态、新启动的 `agy` 将使用新账号。
- **精简主表列结构（`# | Sel | [ID] | Email | Last Used (dur) | State`）**：
  - `#` 为右对齐账号序号；`Sel` 列依次用 `>` 表示当前光标所在行、`*` 表示当前活跃选中账号、`+` 表示已用 `Space` 多选标记的账号（如 `>*+`）。
  - `Email` 列在账号设置了自定义备注（`custom_label`）时以 `alice@example.com (primary)` 形式拼接展示（支持英文与中文 UTF-8，按 `l` 可随时在底栏内联修改或清空备注）。
  - **`Last Used (dur)` 列（带 `24h` / `12h` 上限的单次停留时长）**：
    - **当前活跃账号（`*`）**：显示 `active (<1m)` / `active (42m)` / `active (3h15m)` / `active (2d4h)`；从 `v1.2.7` 升级尚无 `last_switched_in_at` 字段时干净显示 `active`；系统时钟回拨兜底显示 `active`。
    - **休眠账号在 `24h` 内切出且单次停留 `dur = out_at - in_at <= 12h`**：显示 `1m ago (40m)` / `12m ago (<1m)` / `6h ago (1h20m)`，一目了然看到多久前用过、那次用了多久。
    - **休眠账号距今 `> 24h` 或单次停留 `> 12h`（可能包含休眠/过夜挂机）**：省略括号避免误导，直接显示 `1m ago` / `3d ago`。
    - **从未切入使用的新号**：显示 `never`；从 `v1.2.7` 升级且有历史 `last_used` 的账号回退显示距今时间（如 `2h ago` / `5d ago`，无括号）；时钟回拨兜底显示 `just now`。
    - **外部漂移保护**：当外部登录导致槽位与库内账号均不匹配时，不将任何行标为 `*` 或 `active`。
  - **`State` 列**：显示账号健康状态（`ok`、`disabled` 或 `verify-blocked`）。
- **`Space` 多选联动（与 `r` 刷新严格解耦）**：
  - 按 `Space` 可勾选或取消勾选任意多个账号；存在已勾选账号时，标题栏显示 `· <N> marked`，最底行 `Status` 在无临时操作提示时常驻显示 `Marked (<N>): ...  [Esc to clear]`，按 `Esc` 优先一键清空勾选（无勾选时 `Esc` 照常退出看板）。
  - 存在勾选账号时，`o`（导出）、`e`（启用）、`d`（禁用，`>= 2` 个时弹 `y` 确认）与 `x`（删除，始终弹 `y` 确认）均自动作用于全部已勾选账号，且除被删除的账号自动移出外，操作完成后保持原有勾选状态便于连续批处理；无勾选时上述按键仅作用于当前光标高亮行。
  - **`r` 仅刷新当前活跃 `*` 账号**：只有在光标停留在当前活跃 `*` 账号行（或在 `i` 详情视图查看当前活跃账号）时按 `r`，才会委托本机官方 `agy -p "/usage"` 刷新该活跃槽位；在休眠账号上按 `r` 不会发起任何请求，只在底栏温和提示先按 `s` 切换至该账号再按 `r` 刷新。
- **`i` 账号详情卡片与时效/模型分组展示**：
  - 按 `i` 将表格区切换为当前高亮账号的只读详情卡片，完整展示邮箱与备注、完整 UUID、状态与 `Last used`、禁用或验证原因、OAuth 客户端与访问令牌到期倒计时、上次刷新时间与来源环境、全部配额池的 `Weekly` / `5h` 进度条与本地重置倒计时（满额未消耗桶显示 `resets —`），以及对齐后的 `Groups` 模型分组说明（自动剥离 `Models within this group:` 前缀）或旧版逐模型清单。
  - **快照后继续使用提示**：若该账号在最后一次刷新配额之后又被切出使用（`last_switched_out_at > quota.last_updated + 60s`），详情卡片的 `Updated` 行末尾会诚实追加 **`(used after snapshot · out Xm ago)`**，提醒缓存配额可能已低于显示值。
  - 在详情视图中，使用 `←` / `→` 切换上/下一个账号的详情卡片，使用 `↑` / `↓`、`PgUp` / `PgDn` 或 `g` / `G` 在卡片内上下滚动，按 `i` 或 `Esc` 返回主表；详情页底栏仅在当前查看的是活跃 `*` 账号时显示 `r refresh`。
- **自适应分组底栏、内联输入与二次确认保护**：
  - 在常规窗口高度（`>= 14` 行）下，底部常驻展示两行冒号对齐的分组快捷键帮助（`Keys   : ...` 与 `Manage : r refresh (on *) · ...`）；在矮窗口（`< 14` 行）下自动收拢为高优先级单行帮助，窄屏下自动精简缩写而不越界。
  - 最底行状态栏按优先级显示：内联文本输入（`o`/`O` 导出路径或 `l` 备注编辑，支持 `Ctrl+U` 清空与 UTF-8 字素级 `Backspace`）、`y` 二次确认（导出明文凭据、批量/全部禁用、删号）、临时操作反馈（**3 秒** info / **5 秒** error）以及存在勾选时的常驻 `Marked (...)` 摘要。

#### `tui` 完整快捷键一览表

| 按键 | 功能说明 |
| :--- | :--- |
| `↑` / `↓` 或 `PgUp` / `PgDn` | 主表模式：上下移动高亮光标（超出单屏时列表自动跟随滚动，首/末行内嵌定高 `...` 提示）；`i` 详情模式：在详情卡片内部上下滚动查看完整配额与模型/分组说明 |
| `←` / `→` | 仅在 `i` 账号详情模式生效：切换查看上/下一个账号的详情卡片 |
| `g` / `Home` 或 `G` / `End` | 主表模式：跳转到账号列表首行（`g`）/ 末行（`G`）；`i` 详情模式：跳转到卡片顶部/底部 |
| **`Space`（空格）** | 勾选或取消勾选当前高亮账号（`Sel` 列显示 `+`，底栏常驻提示已选账号；按 `Esc` 一键清空全部勾选；作用于 `o`/`e`/`d`/`x`，不与 `r` 联动） |
| **`[`** / **`]`** | 将当前高亮账号上移一位（`[`）/ 下移一位（`]`），实时保存新顺序 |
| `Enter`（回车）或 `s` | 纯本地离线将官方 `agy` 凭据切换到当前高亮账号（切出前自动本地回采原槽位最新令牌并记录切换时间戳） |
| **`i`** | 打开或关闭当前高亮账号的只读详情卡片（完整展示重置倒计时、备注、UUID、令牌有效期、`Last used`、快照后使用提示与可滚动的模型/分组说明） |
| **`r`** | 仅当光标停在当前活跃（`*`）账号行（或在 `i` 详情页查看当前活跃账号）时，委托官方 `agy -p "/usage"` 刷新其最新配额并回采令牌（支持按 `Ctrl+C`、`q`、`Esc` 或发送系统信号随时安全中断并恢复终端）；在休眠账号上按 `r` 不发请求，并在底栏提示先按 `s` 切换再刷新 |
| `e` / **`E`** | `e` 启用已勾选账号（无勾选时启用当前高亮账号）；大写 **`E`** 无需确认，直接将池中所有处于 `disabled` 状态的账号全部恢复为启用 |
| `d` / **`D`**（必要时配合 **`y`** 确认） | `d` 禁用已勾选账号（勾选 `>= 2` 个时弹出 `y` 确认；无勾选时直接禁用当前高亮账号）；大写 **`D`** 弹出防误触确认提示，按 `y` 禁用全部未禁用账号，按 `Ctrl+C` 退出，按其他键取消 |
| **`l`** | 在底栏内联编辑当前高亮账号的自定义备注（`custom_label`，支持中文输入与 `Ctrl+U` 清空；留空回车清除备注，`Esc` 取消） |
| **`o`** / **`O`**（配合路径确认与 **`y`** 明文确认） | `o` 导出已勾选账号（无勾选时导出当前高亮单账号）；大写 **`O`** 导出库内全部账号。默认预填当前目录下带时间戳的防重名 JSON 路径（可按 `Ctrl+U` 清空并自定义，支持 `~/` 展开；误贴可识别凭据值时实时遮蔽为 `[REDACTED]` 并在进入确认前脱敏拒绝），回车后强制在底栏前置展示明文令牌风险与 `[y/N]` 确认提示（终端过窄无法完整展示风险提示时拒绝确认），按 `y` 以 `0600` 权限原子不覆盖写出标准 v2 备份包（默认通过内核原子不替换提交拒绝覆盖已存在文件，并拒绝软链/FIFO） |
| **`x`** 或 `Delete`（配合 **`y`** 确认） | 删除已勾选账号（无勾选时删除当前高亮账号）：按下后底栏弹出内联确认提示，按 `y` 确认执行删除（若包含当前生效 `*` 账号，确认后会按事务安全清空生效凭据槽位并同步清理账号索引与令牌血统归档；被删 ID 自动从勾选集移出）；按 `Ctrl+C` 立即退出，按其他键取消 |
| `q` 或 `Esc` 或 `Ctrl+C` / `Ctrl+D` | `q` 与 `Ctrl+C` / `Ctrl+D` 退出看板并恢复原终端界面；`Esc` 按当前上下文优先退出内联输入/二次确认、`i` 详情视图或清空已勾选账号，均未激活时退出看板 |

---

### 4.8 本地 Token 用量统计与请求明细：`stats summary` / `stats list`

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
  - 切号与运行控制命令（`switch`、`current`、`run`）始终专注服务无头 `agy` CLI，不会扫描或重启桌面端窗口。

#### 共享参数详解（`stats summary` 与 `stats list` 通用）

- **数据源选择：`--source <all|cli|app>`（默认值为 `all`）**
  - `all`（默认）：
    - 合并扫描当前 `HOME` 内支持的两个官方数据源（`~/.gemini/antigravity-cli/conversations/*.db` 与 `~/.gemini/antigravity/conversations/*.db` 及其 `token_usage_archive.db`），自动按同一会话文件与生成序号去重。
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
  - **共享顶层字段**：`source`（`"all"` / `"cli"` / `"app"`）、`range`（当使用 `--recent` 时为 `{"kind": "recent", "recent": N, "from": ..., "to": ...}`）、`databases_scanned`、`generations_scanned`、`skipped_large_records`、`unreadable_databases`、`last_activity`、`range_last_activity` 与 `generated_at`。
  - **`stats summary --json` 专属字段**：输出 `summary`、`performance` 与 `models` 数组（每项含 `model`、`request_count`、`total_input_tokens`、`uncached_input_tokens`、`cached_input_tokens`、`cache_hit_ratio`、`cache_hit_percent`、`output_tokens`、`total_tokens`）。
  - **`stats list --json` 专属字段**：输出 `total_matching`、`shown_count`、`truncated` 与 `items` 数组（每项含 `timestamp`、`local_time`、`model`、`uncached_input_tokens`、`cached_input_tokens`、`total_input_tokens`、`cache_hit_ratio`、`cache_hit_percent`、`output_tokens`、`total_tokens`、`ttft_seconds`、`duration_seconds`、`output_tps`、`status`）。
  - **隐私与模型名过滤约束**：结构中不导出 `source_key`、本机路径或账号邮箱。模型名经已知公共模型家族与受限语法过滤，仅保留符合公共模型命名规范的标签，其余统一回退为 `"Unknown"`。

---

## 5. 标准退出码（`0..=8`）与 `--json` 脚本集成契约

添加 `--json` 后，机器输出契约按命令性质分类如下：

- **特殊交互与包装命令说明**
  - **`tui` 与 `stats ... --watch`**：全屏交互终端界面，均与 `--json` 互斥并直接返回退出码 `2`。
  - **`run -- agy ...`**：在前置凭据准备、锁检查或进程检查失败时向 `stderr` 输出结构化错误信封；前置准备成功后直接将标准输入输出交给 `agy` 子进程并原样透传其退出码。

- **单目标命令与前置参数/文件校验**（包括单槽 `refresh` 与 `quota --refresh`）
  - **执行成功时**：将结果信封（包含 `"schema_version": 1, "ok": true`）输出至 `stdout`，并返回退出码 `0`。
  - **执行失败时**：将结构化错误信封（包含 `"schema_version": 1, "ok": false, "error_code": "...", "message": "..."`）输出至 `stderr`，并返回对应的非零退出码（`1..=8`）。

- **多条目批量写入命令**（包含 2 条及以上令牌的 `accounts add --from-file/--from-stdin` 以及 `auth pending --resume`）
  - **汇总输出位置**：`--json` 模式下全部执行完毕后在 `stdout` 输出汇总信封（`"schema_version": 1, "ok": true`，此时 `stderr` 保持为空）。
  - **各命令的失败明细字段**：
    - 批量 `accounts add`：包含 `failed_count` 计数与 `failures` 数组。
    - `auth pending --resume`：包含 `failures` 数组。
  - **进程退出码**：若其中任何一条遇到令牌已由远端签发但本地未能持久化（`issued_token_unpersisted`）等需恢复状态，立即按结构化错误信封返回退出码 `7`（`PartialCommitOrRecovery`）；其余常规单条失败情形统一汇总后返回退出码 `1`（`GeneralOrDataError`）。
  - **脚本判定方式**：自动化脚本应同时检查进程退出码是否为 `0`，以及 `stdout` 汇总对象中的失败明细字段（`failed_count` 或 `failures` 数组长度）。

- **离线批量导入与只读巡检 / 统计聚合**
  - **`status --json`**：在 `stdout` 输出包含 `"schema_version": 1, "ok": true` 的只读健康巡检对象，包含 `backend`、`store_ok`、`journal_status`、`slot_initialized`、`agy_probe` 以及可选桌面端探测 `antigravity_app_probe`（含 `checked`、`found`，检测到时附 `path` 与 `version`）。
  - **`accounts import --from-file ... --json`**：当导入文件本身可读且 JSON 结构合法时，将逐条导入、跳过与失败统计（`report.failed_count` 与 `report.failures`）输出至 `stdout` 并返回退出码 `0`；若文件无法打开或 JSON 语法损坏，则在 `stderr` 输出错误信封并返回非零退出码。
  - **只读 `quota --all --json`（不带 `--refresh`）**：作为全库本地缓存状态聚合接口返回退出码 `0`，脚本应读取每个账号对象内的 `evaluation` 字段判断单账号是否新鲜可用；而单账号严格查询 `quota [<ID|EMAIL>] --json` 在缓存处于 `Stale`、`Unknown` 或 `Unavailable` 时则严格返回退出码 `4`。
  - **只读 `stats summary --json` 与 `stats list --json`**：扫描本地会话 SQLite 数据库并在 `stdout` 输出 `schema_version: 1` 对象（`summary` 含 `summary`/`performance`/`models`，`list` 含 `items`/`total_matching`/`truncated`），返回退出码 `0`（若传入非法窗口参数或互斥组合则在 `stderr` 输出错误信封并返回退出码 `2`）。

进程退出码定义如下：

| 退出码 | 名称 | 代表的含义与处理建议 |
| :---: | :--- | :--- |
| `0` | `Ok` | 执行成功（`run -- agy` 模式下原样透传 `agy` 子进程退出码） |
| `1` | `GeneralOrDataError` | 本地文件损坏、磁盘权限错误，或批量操作中存在失败项 |
| `2` | `InvalidUsageOrAmbiguous` | 命令参数有误、互斥选项冲突，或同名邮箱需改用 ID 区分 |
| `3` | `AccountNotFound` | 找不到指定账号，或尚未设置当前选中账号 |
| `4` | `QuotaUnavailableOrStale` | 目标账号尚无配额缓存，或在 `--json` 严格模式下缓存已过期/未知（加 `--refresh` 刷新即可） |
| `5` | `LockBusyOrConflict` | 并发锁繁忙，或安全拦截了使用已淘汰旧令牌覆盖新令牌的操作 |
| `6` | `AuthOrClientError` | OAuth 授权失败、令牌已被撤销（运行 `auth reauthorize` 重新授权即可恢复） |
| `7` | `PartialCommitOrRecovery` | 上次切号或清槽中途留下未完成日志，或远端已签发新令牌但本地落盘失败（修复磁盘条件后执行 `switch <ID\|EMAIL>` 等交互式写命令自动安全对账，或按提示重新授权恢复） |
| `8` | `EnvironmentNotReady` | `/proc` 不可读、传了 `--require-idle`（或使用 `run`）时检测到正在运行的 `agy` 进程、钥匙串后端未就绪，或本机已安装的 `agy --version` 探测失败 |

---

## 6. 可选配置文件（`config.json` 代理、后端与自定义 OAuth 客户端）

`~/.local/share/agy-switch-cli/config.json` 是**完全可选**的配置文件。默认情况下该文件不存在，所有功能均可直接使用（程序已内置与官方 `agy` 一致的默认 OAuth 客户端 `antigravity_enterprise`；从 `v1.2.x` 升级残留的 `"notifications"`、`"targets"` 等已废弃未知字段以及磁盘旧 `policy.json` / `state/daemon_state.json` 均会自动静默忽略而不会报错）。只有当你遇到以下三类需求时，才需要手动创建它：

- **固定网络代理**：在 Linux 环境下，图形界面的“系统代理”设置并不会自动注入命令行终端的环境变量中。如果你希望显式 `auth` 登录/重授权与裸令牌导入免重复传 `--proxy`，可以将代理地址写入 `config.json` 实现跨终端持久生效（若终端环境变量中的代理格式异常而被忽略，人类输出模式会在联网时打印仅含变量名的脱敏提示）。
- **固定凭据后端模式**：希望跨所有终端统一固定使用 `keyring`（纯钥匙串零本地文件）、`file`（纯本地文件）或 `dual`（强制双写），而非每次手动传 `--backend`。
- **自定义 OAuth 客户端（进阶场景）**：你手头拥有由其他 Google Cloud OAuth 客户端签发的 `refresh_token`，或者希望使用自建 OAuth 客户端进行登录（详见下方 `6.2` 节零基础完整拆解）。

> **文件权限要求**：由于 `config.json` 中可能包含带密码的代理地址或 `client_secret` 密钥，创建时请将文件权限设为仅当前用户可读写的 `0600`（若权限过宽如 `0644`，`status` 与联网命令会输出安全提示，执行 `chmod 600 ~/.local/share/agy-switch-cli/config.json` 即可收紧权限）：
> ```bash
> install -m 0600 /dev/null ~/.local/share/agy-switch-cli/config.json
> ```

### 6.1 场景一：配置固定网络代理或凭据后端（最常见用法）

如果只需要配置网络代理或凭据后端，无需填写 `oauth` 部分，写入以下内容即可：

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
   agy-switch-cli auth login --client my_custom_oauth --label "custom-oauth"
   agy-switch-cli accounts add --client my_custom_oauth
   ```
   绑定完成后，该账号档案会自动记住 `oauth_client_key = "my_custom_oauth"`，后续执行 `auth reauthorize` 或 `auth pending --resume` 时会自动匹配这组客户端凭据，无需每次重复传入 `--client`。
3. **无文件环境变量注入方式（适合 Docker 容器）**：除了写 `config.json`，也可以通过环境变量动态注入（优先级高于 `config.json`）：
   - `ANTIGRAVITY_OAUTH_CLIENTS="key|client_id|client_secret|label"`（多项之间用分号 `;` 分隔）；
   - `ANTIGRAVITY_OAUTH_CLIENT_KEY="<KEY>"`（指定默认客户端短名称）；
   - `ANTIGRAVITY_REQUIRED_SCOPES="openid https://www.googleapis.com/auth/cloud-platform"`（全局最低必需 Scope 列表，支持空格、逗号 `,` 或分号 `;` 分隔）。

---

## 7. 常见问题解答（FAQ）

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
    - **跨终端持久生效**：按第 `6.1` 节编辑 `~/.local/share/agy-switch-cli/config.json`，写入 `"network": { "proxy_url": "http://127.0.0.1:7890" }`。
- **问：某个账号刷新后显示 `verify-blocked`（`[verification required]`），应该怎么解锁？**
  - **答**：该状态表示 Google 返回了 `403 VALIDATION_REQUIRED`，需要在官方 `agy` 中打开验证链接完成扫码或网页安全核验（重新授权 `auth reauthorize` 无法代替网页验证）。按三步即可解锁：
    - 直接使用 `agy-switch-cli switch <ID|EMAIL>`（或在 `tui` 中选中后按 `Enter`，或用可选的 `run --account <ID|EMAIL> -- agy`）切入该账号（人工切号会放行，同时保留 `verify-blocked` 标记）。
    - 启动官方 `agy`，按界面提示打开网页或扫码完成 Google 安全验证。
    - 验证完成后执行 `agy-switch-cli refresh`（或在 `tui` 中停在当前活跃 `*` 行按 `r`），当官方 `agy -p "/usage"` 返回未阻断的有效观测后即自动清除 `verify-blocked` 标记。
- **问：日常使用时，手动切号（`tui` / `switch`）与可选的 `run` 包装启动各自适合什么场景？**
  - **答**：两种方式定位清晰，可按实际需求选用：
    - **交互式看板或手动切号（`tui` / `switch`）**：适合日常按需查看额度、管理账号并离线切换槽位，切完直接运行 `agy` 即可。
    - **可选启动包装器 `run`**：适合单次临时指定某个账号（`run --account <ID|EMAIL> -- agy`），或在图形桌面上通过 `--backend file run -- agy` 将终端 `agy` 登录态与桌面端钥匙串隔离。
- **问：从 `v1.2.x` 升级后，旧版本的 `daemon` / `policy` 命令与 `systemd` 服务如何处理？**
  - **答**：官方 `agy` 与 ACP 客户端均在启动或新建对话时一次性加载内存凭据，后台定时切换无法在运行中的对话内热续命，且定时程序化查额与自动轮换会显著放大条款风控暴露面，因此已移除 `daemon` 与 `policy` 子命令。历史磁盘中残留的 `policy.json`、`state/daemon_state.json` 以及 `config.json` 内的 `"notifications"` / `"targets"` 字段会被自动静默忽略，账号库可零报错直接升级。若你在 `v1.2.x` 曾安装过用户级 `systemd` 服务，只需按下方第 `8` 节第 1 步停用并删除旧单元文件即可。

---

## 8. 完整卸载与本地遗留文件清理清单

在 Linux 系统中，包管理器（如 `pacman`、`yay`、`paru`）或手动删除二进制文件都只负责移除“程序本身”，**不会自动删除你主目录（`~`）下的个人配置与数据文件夹**，这是 Linux 防止更新或重装软件时误删用户数据的通用保护机制。无论你是从 `v1.2.x` 升级后仅清理旧版后台服务，还是准备彻底卸载 `agy-switch-cli`，均可按以下四个步骤操作。

### 第 1 步：清理 `v1.2.x` 历史版本遗留的后台服务（升级或卸载前可选）

- **曾在 `v1.2.x` 安装过 `systemd --user` 后台服务的环境**：新版已移除 `daemon` 子命令，直接执行以下三条标准 `systemctl` 命令即可停用、取消自启并删除旧服务单元（同时兼容默认 `~/.config` 与自定义 `$XDG_CONFIG_HOME` 路径）：
  ```bash
  systemctl --user disable --now agy-switch-cli.service 2>/dev/null || true
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/agy-switch-cli.service"
  systemctl --user daemon-reload 2>/dev/null || true
  ```
- **曾在无 `systemd` 容器环境中手动配置过 `v1.2.x` `daemon` 常驻的情况**：按当时选用的托管方式停止旧进程并移除自启项：
  - 使用 `nohup`：执行 `pkill -TERM -f "agy-switch-cli daemon"`，并删除 `~/.bashrc` 中追加的自动拉起片段。
  - 使用 `tmux`：执行 `tmux kill-session -t agy-daemon`。
  - 使用 `supervisord`：执行 `supervisorctl stop agy-switch-cli`，移除 `/etc/supervisor/conf.d/agy-switch-cli.conf` 后执行 `supervisorctl reread && supervisorctl update`。
  - 使用 `cron`：执行 `crontab -e` 删除包含 `agy-switch-cli daemon` 的定时任务行。
- **可选清理历史废弃状态文件（仅升级后保留账号库时适用）**：历史残留的 `~/.local/share/agy-switch-cli/policy.json` 与 `~/.local/share/agy-switch-cli/state/daemon_state.json` 已被自动忽略，也可随时手动执行 `rm -f ~/.local/share/agy-switch-cli/policy.json ~/.local/share/agy-switch-cli/state/daemon_state.json` 清理干净（不会影响任何账号数据）。

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
| `~/.local/share/agy-switch-cli/`<br>（或 `$XDG_DATA_HOME/agy-switch-cli/`、`--data-dir` 指定目录） | 本工具的独立数据目录：包含账号索引 `index.json`、各账号 OAuth 凭据 `accounts/*.json`、可选代理/客户端配置 `config.json`、事务状态 `state/` 与目录锁 `locks/`（以及升级可能残留的旧 `policy.json` / `state/daemon_state.json`）。 | 彻底卸载不再使用时可删 |
| `~/.cache/agy-switch-cli/`<br>（或 `$XDG_CACHE_HOME/agy-switch-cli/`） | 全局跨目录锁目录：包含账号槽位锁与钥匙串锁 `locks/`。 | 彻底卸载时可安全删除 |
| `~/.config/systemd/user/agy-switch-cli.service`<br>（或 `$XDG_CONFIG_HOME/systemd/user/agy-switch-cli.service`） | `v1.2.x` 历史版本遗留的用户级 `systemd` 服务单元文件（若按第 1 步清理则已删除）。 | 升级或彻底卸载时应删除 |
| `~/.local/state/agy-switch-cli/` | 仅在 `v1.2.x` 容器环境中手动重定向保存过旧 `daemon.log` 时才会存在；当前版本不会创建该目录。 | 若存在且无需查日志可删 |

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
