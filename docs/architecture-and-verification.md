# `agy-switch-cli` 技术架构、安全机制与验收台账

> 返回首页：[README.md](../README.md) ｜ 完整使用与部署手册：[user-guide.md](user-guide.md) ｜ 重构溯源声明：[PROVENANCE.md](../PROVENANCE.md)

本文档面向希望深入了解 `agy-switch-cli` 内部工作原理、并发安全机制、崩溃恢复协议及质量验证边界的用户与维护者，系统说明本项目的工程架构与实测验收数据。

---

## 目录

1. [设计目标与核心架构边界（做什么 / 不做什么）](#1-设计目标与核心架构边界做什么--不做什么)
2. [代码模块分层全景与职责导览](#2-代码模块分层全景与职责导览)
3. [三域存储拓扑、磁盘状态文件与安全 I/O 防护](#3-三域存储拓扑磁盘状态文件与安全-io-防护)
4. [并发控制、崩溃对账与防令牌回退协议](#4-并发控制崩溃对账与防令牌回退协议)
5. [CloudCode 配额观测链路、四态评估与自动切号引擎](#5-cloudcode-配额观测链路四态评估与自动切号引擎)
6. [秘密零回显防护与终端信号安全](#6-秘密零回显防护与终端信号安全)
7. [跨平台构建矩阵、性能基准与诚实验收边界台账](#7-跨平台构建矩阵性能基准与诚实验收边界台账)

---

## 1. 设计目标与核心架构边界（做什么 / 不做什么）

`agy-switch-cli` 源自混合桌面项目 `agy-switch` 的领域规则提炼，但在工程架构上针对 **Linux 无头环境（远程 SSH 服务器、Docker 容器、WSL2 与自动化流水线）** 进行了从零重构。

### 1.1 核心架构取舍

| 维度 | 传统桌面端方案 | `agy-switch-cli` 无头架构设计 |
| :--- | :--- | :--- |
| **运行形态与系统依赖** | 依赖 Tauri / GTK / WebKitGTK / X11 / Wayland 及系统动态库 | **零 GUI 动态库依赖**，预编译 `musl` 二进制为 100% 纯静态单文件 ELF（`NEEDED = 0`） |
| **目标客户端范围** | 同时尝试操作桌面 App、VS Code / IDE 的 `state.vscdb` SQLite 数据库与网页注入 | **切号与运行控制专注官方无头 `agy` CLI**（不修改 IDE `state.vscdb`，不注入脚本，不干预桌面进程）；`stats` 仅以纯只读方式汇总本地 `conversations/*.db` 用量 |
| **切号生效方式** | 通过强杀并重启桌面客户端进程来切换会话 | **非侵入式原子替换凭据槽位**：仅对切换完成后新启动的 `agy` 进程生效，绝不强行中断正在运行中的 `agy` 任务 |
| **桌面钥匙串兼容** | 绑定系统 `libsecret` 动态库 | 统一单包内置纯 Rust `zbus` 协议栈，支持 `auto`（默认，无头自动走 `file`、活跃桌面钥匙串自动走 `dual` 事务性双写）、`dual`、`file`、`keyring` 四种后端模式（显式指定 `file` 后端配合 `run` 时自动为子进程屏蔽桌面钥匙串总线） |

### 1.2 切号生效语义与进程边界

- **凭据生效机制**：官方 `agy` 在启动阶段读取登录凭据（存在活跃桌面 D-Bus Secret Service 的图形会话中优先查询系统钥匙串，否则读取 `~/.gemini/antigravity-cli/antigravity-oauth-token`）。`switch` 提交成功代表目标账号凭据已完成原子写入并通过生效后端全部应有副本的回读核验。
- **运行中会话保护与故障关闭边界**：
  - 已经启动并正在运行的 `agy` 进程在内存中持有其启动时加载的身份会话，本工具不会向运行中的 `agy` 进程注入信号或篡改其内存状态。
  - 执行手动 `switch` 或在 `tui` 中按 `Enter`/`s` 切号时，若 `/proc` 已核验到活跃 `agy` 进程正在运行，默认会立即更新凭据槽位并输出清晰提示，说明已运行的旧 `agy` 窗口保持原登录态、后续新启动的 `agy` 会话将使用新账号（如自动化脚本需要严格空闲才能切号，可传 `--require-idle` 返回退出码 `8`）。
  - 若受限环境无法完整读取 `/proc`（`RuntimeState::Unverified`），未显式传入 `--allow-running` 的手动切号与可选包装器 `run -- agy`（含检测到未受管运行中 `agy` 进程时）均严格按故障关闭拒绝改写并返回退出码 `8`；后台自动切号 `daemon` 同样保持故障关闭绝不盲写，并在轮次报告中进入 `hold`（固定原因 `process_state_unverified`，单轮 `--once` 正常汇报并退出 `0`）。

---

## 2. 代码模块分层全景与职责导览

全工程为单一纯 Rust 包（无前端工程与 C/GUI 胶水层），内部遵循严格的单向依赖分层：

```mermaid
flowchart TD
    CLI["交互入口层<br/>src/main.rs · src/cli/* · src/tui/mod.rs"]
    APP["应用编排与只读分析层<br/>src/switching/* · src/quota/* · src/oauth/* · src/stats/*"]
    INFRA["存储、会话与传输基础设施层<br/>src/store/* · src/session/* · src/transport/*"]
    DOMAIN["纯函数领域模型层<br/>src/domain/* · src/paths.rs · src/error.rs"]

    CLI --> APP
    CLI --> INFRA
    APP --> INFRA
    APP --> DOMAIN
    INFRA --> DOMAIN
```

### 2.1 `src/` 目录模块速查表

| 模块路径 | 核心职责说明 |
| :--- | :--- |
| `main.rs` / `lib.rs` / `paths.rs` | 原始 `args_os` 非 UTF-8 安全入口、目录解析（支持 `--data-dir` 与 XDG 规范）与顶层信号退出码映射 |
| `error.rs` | 统一错误类型 `CliError`、稳定退出码枚举 `ExitCode`（`0..=8`）以及基于语法结构的 `clap` 参数与 JSON 解析错误脱敏器 |
| `domain/account.rs` | 账号记录 `AccountRecord`、暂存授权记录 `PendingAuthRecord`、单调世代判定纯函数与跨机备份包 `TransferBundle` 结构 |
| `domain/token.rs` | OAuth 令牌模型 `TokenRecord`（自定义 `Debug` 隐藏所有令牌字段）与 SHA-256 刷新令牌摘要计算 |
| `domain/quota.rs` | 配额池分类（`Gemini` / `ThirdParty` / `Argon`）、四态配额评估纯函数 `evaluate_account_quota`（默认 `3600s` 保鲜期，识别 `Free` 与 `Antigravity Starter Quota` 免 `5h` 桶评估） |
| `domain/policy.rs` / `config.rs` / `clock.rs` | 自动切号策略模型与逐字段校验器、`config.json` 配置解析（`Debug` 自动脱敏密钥与代理口令）、基于纯 Rust `jiff` 的严格 RFC 3339 / 本地时区 / `YYYY-MM-DD` 自然日工具与测试时钟 |
| `store/locks.rs` | 基于 POSIX `flock` + 线程级顺序守卫的四级单向锁实现（`L1`、`PendingAuthLock`、`L2`、`L3`）与 `DaemonInstanceLock` |
| `store/fs_atomic.rs` | 全深度祖先符号链接拦截、`O_NOFOLLOW \| O_NONBLOCK` 有界普通文件读取、临时文件与父目录双 `fsync` 原子写入及故障注入钩子 |
| `store/repository.rs` / `transfer.rs` | 账号库事务读写、单调授权序号 `auth_sequence.json`、两级轮换指纹谱系归档、备份包导入导出与旧桌面端只读迁移 |
| `session/backend.rs` / `payload.rs` | 官方凭据 JSON 序列化校验、`auto` 自适应探测、`file` 纯文件后端、`dual` 钥匙串+文件事务性双写后端、`keyring` 纯钥匙串零磁盘写入后端，以及 `--from-local` 本机已登录凭据提取器 |
| `session/journal.rs` / `process.rs` | 三阶段崩溃恢复日志 `switch_journal.json` 内置写前自愈 CAS 对账机、`/proc` 故障关闭进程扫描与双因子（`pid + starttime`）进程租约 |
| `transport/client.rs` / `proxy.rs` / `user_agent.rs` | 基于 `reqwest` + `rustls` 的 HTTP 传输抽象、系统代理环境变量自动规范化与异常项容错隔离（支持 `socks5h`/`socks`、裸 `host:port` 与精确 `url::Host` 本地回环直连分流）、`antigravity/hub/<ver>` 请求标识管理与隔离沙盒下的本机官方 `agy` 版本探测 |
| `oauth/registry.rs` / `flow.rs` / `refresh.rs` | 内置与自定义 OAuth 客户端注册表、PKCE（`S256`）授权流、全入口 `/token` 签发后立即 `0600` 落盘与并发防回退续期闭环 |
| `quota/client.rs` / `fusion.rs` | 单环境隔离的 CloudCode 三步配额拉取（`Daily -> Sandbox -> Production`）、401 单次强刷重试与双窗口配额融合 |
| `switching/executor.rs` / `runner.rs` / `daemon.rs` / `notify.rs` / `systemd.rs` | 切号与事务性删号核心执行器、指定凭据与显式 `file` 后端自动隔离 D-Bus 的 `run -- agy` 受管包装启动器、七阶段静默自动切号守护引擎（含 `--reset-cooldown` 与普通状态回写竞态防覆盖）、纯 Rust D-Bus 桌面通知分发器（无头零自动激活与默认常驻可选配置），以及带沙盒安全转义与防符号链接保护的 `daemon --install` / `--uninstall` 用户级服务管理器 |
| `stats/{mod,readonly_vfs,watch}.rs` | 纯离线零写入的本地 SQLite 会话库扫描器（自定义 `"agy_pinned_ro"` VFS 绑定 `openat` 目录句柄）、有效归档优先与实时回退去重、逐片段独立 Protobuf 帧校验、自然日与 `--recent <N>` 有界最小堆（`O(500)`）窗口下的 `stats summary` 聚合与 `stats list` 十列明细渲染，以及基于只读 `stat` 元数据指纹跳过解码的 `--watch [SECS]` 实时终端看板 |
| `cli/*` / `tui/mod.rs` | 规范化长选项参数定义（无短参数、无隐藏兼容别名、严格 `<ID\|EMAIL>` 选择器）、只读 `status` 巡检、流式 `[k/N]` 批量刷新、无回显私密令牌读取器、物理白名单 DTO 渲染器，以及支持 `↑/↓` 选行与内嵌定高 `...` 滚动提示、`[/]` 调序、`e/E` 与 `d/D` 单条/全局启停、`x`+`y` 事务删号及双行分组底栏的 SSH 交互式终端看板 |

---

## 3. 三域存储拓扑、磁盘状态文件与安全 I/O 防护

### 3.1 三域物理隔离设计

为保持官方 `agy` 目录干净，并允许同一台机器上的不同 `--data-dir` 实例安全协调对同一个官方凭据文件的访问，磁盘路径划分为三个职责分明的域：

| 存储域 | 默认路径 | 权限要求 | 存放内容与设计目的 |
| :--- | :--- | :---: | :--- |
| **1. 独立账号仓库域 (`data_dir`)** | `$XDG_DATA_HOME/agy-switch-cli`<br>（回退 `~/.local/share/agy-switch-cli`） | 目录 `0700`<br>文件 `0600` | 存放账号库、策略、配置及所有内部事务状态与中下层文件锁 |
| **2. 全局锁与缓存域 (`cache_dir`)** | `$XDG_CACHE_HOME/agy-switch-cli`<br>（回退 `~/.cache/agy-switch-cli`） | 目录 `0700`<br>文件 `0600` | 存放跨 `--data-dir` 共享互斥的顶层槽位锁 `locks/slot-<sha256>.lock`、钥匙串锁 `locks/keyring-<uid>.lock` 及 24 小时客户端版本缓存 `ua_version_cache.json` |
| **3. 官方凭据生效位 (`active_slot`)** | `~/.gemini/antigravity-cli/antigravity-oauth-token` | 文件 `0600` | 官方 `agy` 实际消费的凭据文件。本工具绝不在该目录内创建 `.lock` 文件，确保官方客户端目录始终洁净 |

`data_dir` 内部文件布局如下：

```text
~/.local/share/agy-switch-cli/          (0700)
├── index.json                          (0600) 账号排列顺序、当前选中账号 ID 与单调版本号 revision
├── policy.json                         (0600) 自动切号开关、阈值、策略、候选账号列表与 revision
├── config.json                         (0600, 可选) 固定网络代理、凭据后端、桌面通知与自定义 OAuth 客户端配置
├── accounts/                           (0700)
│   └── <account_id>.json               (0600) 单账号令牌、配额缓存、授权世代与近 512 条已淘汰令牌摘要
└── state/                              (0700)
    ├── switch_journal.json             (0600, 仅切号瞬态存在) 切号事务崩溃恢复日志
    ├── daemon_state.json               (0600) 守护进程冷却截止时间、轮询游标与连续失败暂停标志
    ├── auth_sequence.json              (0600) 全局单调递增的授权签发序号（摆脱系统时钟回拨影响）
    ├── pending_auth/<id>.json          (0600) 已从 Google 换出令牌但尚未完成 userinfo 入库的暂存保险箱
    ├── pending_lineage/<id>.json       (0600) 暂存记录在续期过程中产生的中间轮换摘要链
    ├── token_lineage/<id>.json         (0600) 超出 512 条上限后的历史淘汰令牌摘要溢出归档（上限 65,536 条）
    ├── leases/<pid>.json               (0600) 受管 `run -- agy` 子进程的双因子（pid + starttime）活跃租约
    └── locks/                          (0700) PendingAuthLock、L2 单账号刷新锁、L3 仓库写锁与 Daemon 单实例锁
```

### 3.2 防御性文件 I/O 机制（`store/fs_atomic.rs`）

所有受管配置文件、账号文件与导入读取路径均经过以下四层底层防护：
- **链式自顶向下 `openat` 非符号链接目录核验**：从受管根目录自顶向下逐级通过 `openat(O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` 获取真实目录句柄，任何一层出现符号链接或非目录项均立即拒绝操作，防止越界访问预期目录之外的对象。
- **父目录句柄直开与 `(dev, ino)` 锚定**：在已校验的父目录句柄内直接调用 `openat` 打开叶子文件，并结合 `fstatat(AT_SYMLINK_NOFOLLOW)` 核对设备号与 inode 一致性，消除路径检查与实际打开之间的竞态窗口（TOCTOU）。
- **非阻塞有界普通文件读取**：使用 `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` 打开文件并验证 `file_type().is_file()`，若异常环境在状态文件路径放置了无写端命名管道（FIFO）或设备节点，可在毫秒级立即识别并报错退出，不会导致进程挂起；同时严格限制单文件最大读取字节数防止内存耗尽。
- **双 `fsync` 原子替换写入**：所有状态更新均先在同一父目录下创建带随机后缀的 `0600` 临时文件，写满后先对临时文件执行 `sync_all()`（`fsync`），再执行 POSIX 原子 `rename` 覆盖目标文件，最后对父目录句柄再次执行 `fsync`，确保断电或内核崩溃后不会出现半写损坏的 JSON 文件。

### 3.3 官方客户端双层凭据存储与事务性双写机制（`session/backend.rs`）

官方 `agy` CLI（及新版独立桌面端 Antigravity App）内部共用同一套双层凭据存储（`composite_token_storage.go`）与同一组 OAuth `client_id`，按以下固定优先级定位当前登录凭据：

- **第一优先级：Linux 桌面系统钥匙串（D-Bus Secret Service）**
  - 当会话中存在已校验的本机 Unix D-Bus 套接字且运行着 GNOME Keyring 或 KDE Wallet（`org.freedesktop.secrets`）时，官方 `agy` 与桌面端 Antigravity App 均优先读写钥匙串 `login` / `default` 集合中属性为 `service="gemini", username="antigravity"`（显示名 `Password for 'antigravity' on 'gemini'`）的加密条目。
  - 只要钥匙串已解锁且存在该条目，官方客户端在启动阶段直接采用钥匙串中的凭据，不再读取磁盘文件；即便手动清理磁盘上的旧凭据文件，官方客户端与本工具的钥匙串后端均能正常按第一优先级读取当前身份。
- **第二优先级：磁盘凭据文件回退层**
  - 当环境不存在桌面钥匙串（如纯无头 SSH 服务器、Docker 容器、无桌面 WSL2）、钥匙串中无对应条目，或显式指定 `file` 后端并通过可选的 `run` 自动将子进程 `DBUS_SESSION_BUS_ADDRESS` 定向至 `/dev/null` 时，`agy` CLI 回退读写 `~/.gemini/antigravity-cli/antigravity-oauth-token`（桌面端 Antigravity App 与 VS Code 中的 Antigravity 扩展插件则回退读写 `~/.gemini/jetski-standalone-oauth-token`；而常见的 `~/.gemini/oauth_creds.json` 并非官方 Antigravity App 或 `agy` CLI 读写的槽位）。
- **统一全特性发行包与四种清晰后端模式（`auto` / `dual` / `file` / `keyring`）**
  - 默认编译特性统一为 `default = ["tui", "stats", "secret-service-backend"]`，使每个目标架构仅提供单一完整的预编译纯静态二进制（`x86_64` `musl` 约 `14.4 MiB`、`aarch64` `musl` 约 `11.8 MiB`，零外部 `.so` 共享库依赖），免去服务器版与桌面版的选包负担；从源码编译时仍可通过 `--no-default-features` 构建纯 Rust 最小无头核，或按需单独组合 `tui`、`stats`、`secret-service-backend` 特性。
  - 全局 `--backend`（以及 `AGY_SWITCH_CLI_BACKEND` 与 `config.json` `"backend"`）提供四种边界明确的模式：
    - `auto`（默认）：先解析并锚定父目录句柄校验本机真实 Unix 域套接字（拒绝 `tcp:`、`unixexec:` 等非本机端点，并在连接后核对套接字 inode 与内核 `SO_PEERCRED` 有效 UID 一致），再绑定该端点在严格 `1500ms` 墙钟上限内以只读不解锁方式探测 `org.freedesktop.secrets` 是否持有持久化集合——检测到活跃桌面钥匙串时自动启用 `dual`，无钥匙串服务器自动回退至 `file`。
    - `dual`：显式执行钥匙串与本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 事务性双写。
    - `file`：仅读写本地 `~/.gemini/antigravity-cli/antigravity-oauth-token`，全程不连接 D-Bus 系统钥匙串。
    - `keyring`：仅读写 D-Bus Secret Service 系统钥匙串，绝不创建、修改、读取或要求本地 `~/.gemini/antigravity-cli/antigravity-oauth-token` 存在，同时完整保留跨多个钥匙串集合（`login` / `default`）的日志对账与失败回滚保护。
  - 当通过 `--backend file`、`AGY_SWITCH_CLI_BACKEND=file` 或 `config.json` `"backend": "file"` **显式指定** `file` 后端且宿主存在桌面会话总线（`DBUS_SESSION_BUS_ADDRESS` 或 `$XDG_RUNTIME_DIR/bus`）时，可选包装器 `run` 会自动将拉起的 `agy` 子进程 `DBUS_SESSION_BUS_ADDRESS` 设为 `unix:path=/dev/null`；而默认 `--backend auto` 在无钥匙串服务器上回退至 `file` 时不会修改子进程的 `DBUS_SESSION_BUS_ADDRESS`，确保子进程内的 `systemctl --user` 不受影响。
  - 执行切号写入时，`SecretServiceSessionBackend` 在持有全局 `L1` 槽位锁与 UID 级钥匙串锁的前提下记录各应有副本（各钥匙串集合及 `dual` 模式下的磁盘文件）的前置缺失状态与摘要，依次更新并回读校验；若任意阶段出错，按前置快照逐一回滚全部受管副本并核验（在 `dual` 模式的本地文件回滚中，若既有文件耐久确认失败，执行原子覆盖写前会再次复验 D-Bus 墙钟取消门控 `MutationGate`，阻止超时后的晚写行为），仅在全部应有副本确认一致后才清理 `switch_journal.json`，任何不确定或分叉状态均保留日志并返回退出码 `7`（后续任意交互式写命令会在安全 CAS 保护下自动完成多副本对账自愈）。

### 3.4 本地会话 SQLite 零写入统计与明细边界防护（`stats/{mod,readonly_vfs}.rs`）

`agy-switch-cli stats summary` 与 `stats list`（受默认特性 `stats` 控制，静态内嵌 `rusqlite` `bundled` SQLite3 源码）提供完全离线、源目录零写入副作用的本地 Token 聚合统计与最近调用明细查询：

- **可信目录句柄绑定与自定义零写入 VFS（`"agy_pinned_ro"`）**：
  - 拒绝相对 `HOME` 输入，所有数据库路径严格基于规范化绝对路径 `HeadlessPaths.home_dir` 自顶向下通过链式 `openat` 绑定真实目录句柄（`~/.gemini/antigravity-cli/conversations/*.db`、`~/.gemini/antigravity/conversations/*.db` 与 `token_usage_archive.db`），确保自动化沙盒测试与宿主机真实会话目录完全物理隔离，且错误消息采用固定路径类别而不回显本机绝对路径。
  - 通过注册自定义只读 VFS `"agy_pinned_ro"`，将已通过 `openat(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)` 核验普通文件身份的主库描述符直接交付给 SQLite，并使 `-wal`、`-shm`、`-journal` 的每次存在性检查、打开与只读共享内存映射（`PROT_READ`）全部约束在同一 `dir_fd` 下执行，同时关闭 URI 解释并将临时存储强制置于受界进程内存（`PRAGMA temp_store = MEMORY`）。
  - 面对已正常关闭且目录中无伴生文件的 WAL 模式数据库（以及不支持 Linux OFD 锁的降级环境），VFS 提供零字节虚拟只读 WAL 与堆内存 WAL 索引（`SQLITE_READONLY_CANTINIT`），仅凭真实 Linux OFD 共享锁（`F_OFD_SETLK`）同时持有 DMS 与 `WAL_READ_LOCK` 才进入可靠 mmap 分支；在无 OFD 或无 `-shm` 锁定的读事务提交统计前，始终重验主库与伴生文件的目录项、`(dev, ino, size, mtime, ctime)` 元数据以及主库、`-wal` 与 `-journal` 的有限文件头（不比较 `-shm` 内容；若扫描中途有新写者挂载则自动退避重试），确保在普通回滚库、关闭态 WAL 库、崩溃残留 WAL 库与并发活跃写入/检查点 WAL 库上均实现 **100% 源目录零文件创建、零字节修改与单一快照一致性**。
- **锁步流式关联、索引归档点查、有界最小堆（`O(500)`）与异常无索引预算保护**：
  - 在标准带索引的官方库与归档库上，通过 `steps` / `gen_metadata` 双游标锁步扫描、索引归档点查（同时打开的数据库句柄恒定 `<= 2`，即 `O(1)` 描述符占用）与容量上限 `500` 的有界最小堆完成聚合与最近明细筛选，无需将全量步骤或归档事件驻留内存；遇到缺少索引的异常表结构时，先仅按 `(rowid, idx)` 在显式行数预算（默认 `50,000` 行）内排序再逐行按 `rowid` 读取（绝不将大 BLOB 投入 SQLite 内存排序器），超出预算时明确降级计入 `unreadable_databases`，并将目录迭代错误、损坏文件与权限/I/O 异常统一计入 `unreadable_databases`。
  - 在 SQL 层通过 `typeof(...)` 与 `octet_length(...)` 严格校验列类型与字节上限（过滤 `> 64 MiB` 的异常 `gen_metadata.data` 并区分显式 `NULL` 与超限/非 BLOB 的 `step_payload`）。
- **逐片段 Protobuf 帧校验、有效归档优先去重、统一性能采样与十列响应式明细**：
  - 零外部生成代码的内联 Protobuf 解码器施加 29 位字段号上限（`1..=536,870,911`），区分“字段缺失”与“帧/编码损坏”，在重复子消息拼接前对每个独立片段先行完成帧完整性校验，并对标量字段遵循标准 `Last-One-Wins` 语义。
  - `--source` 默认设为 `all`（无桌面服务器自动等效扫描 `cli`，桌面环境合并汇总 `cli + app`；亦支持显式指定 `cli` 或 `app`）。扫描 `all` 或 `app` 时，按 `(source_key, generation_idx)` 执行有效归档优先去重（若归档行无效则自动回退采用同键有效实时记录，且归档总额仅由三项 Token 明细重算而不依赖可空的冗余 `total_tokens` 列），并按 `antigravity/*` 与 `antigravity-cli/*` 前缀严格隔离归档记录。
  - **统一性能采样与响应式渲染（`stats summary` 与 `stats list` 共用谓词）**：
    - 两者共用同一条记录解码、事件时间与实测 `TPS`（`= live_output_tokens / live_streaming_duration`）过滤谓词：严格要求已完成步骤 `steps.status == 3`、`gen_metadata` 无错误字段、无非法或超限 `step_payload`、`retries == 0`、实时输出 `live_output_tokens > 0`、`ttft > 0` 且 `live_streaming_duration >= 1.0s`（兼容含工具调用与常规流式回复），状态简码覆盖 `ok` / `err` / `canc` / `run` / `unk` / `arch`。
    - `stats summary` 线性插值输出 `TTFT` 与 `TPS` 的 `P10 / P50 / P90` 分位值，并在 `Models` 七列表中统一展示 `Input`（总输入）、`Cached` 与一位小数 `Hit%`（存在未缓存输入时封顶 `99.9%`）。
    - `stats list` 输出十列紧凑明细表，常规窄屏保留十列并收紧时间与模型列宽，低于十列最小可读宽度的极窄终端自动切换紧凑多行块格式，避免截去 `TPS` 与 `St`。
  - 四组互斥窗口参数统一校验：`--recent <N>`（`1..=500`，`stats list` 默认 `10`）、`--range <today|yesterday|<N>d|all>`（`stats summary` 默认 `today`）、`--date <YYYY-MM-DD>` 与 `--from <YYYY-MM-DD> [--to <YYYY-MM-DD>]`。

---

## 4. 并发控制、崩溃对账与防令牌回退协议

### 4.1 四级单向锁顺序（编译期与运行期双重防死锁）

当后台守护进程 `daemon`、受管启动器 `run`、交互式看板 `tui` 与命令行手动 `refresh`/`switch` 同时运行时，系统通过严格的单向锁获取顺序避免死锁：

```mermaid
flowchart LR
    L1["L1: ActiveSlotLock<br/>跨目录全局凭据槽位互斥锁"] --> PA["PendingAuthLock<br/>单条暂存授权生命周期锁"]
    PA --> L2["L2: AccountRefreshLock<br/>单账号异步 OAuth 刷新互斥锁"]
    L2 --> L3["L3: StoreWriteLock<br/>本地账号库同步事务写锁"]
```

- **单向获取不变量**：任何线程一旦持有低层级锁（例如已持有 `L2` 或 `L3`），若试图反向获取高层级锁（如 `L1` 或阻塞等待另一把 `PendingAuthLock`），线程局部锁栈守卫会立即在运行期拦截报错。
- **L3 纯同步闭包约束**：`with_store_write_lock` 在 Rust 类型签名上仅接受同步闭包 `FnOnce(&StoreWriteTx<'_>)`，不接受 `async` Future，从编译器层面保证了持有仓库写锁期间绝不会跨越任何网络 `.await` 等待。
- **锁文件持久化不删除**：所有 `.lock` 文件在释放 `flock` 时仅关闭文件描述符而不执行 `unlink`，避免并发进程锁在不同 inode 上导致互斥失效。

### 4.2 三阶段切号事务日志与崩溃恢复（`session/journal.rs`）

切换账号需要同时更新“外部官方凭据槽位（及可选系统钥匙串）”和“内部 `index.json` 选中记录”，这两处位于不同目录，无法用单次文件系统 `rename` 原子完成。为此系统引入了预写日志 `switch_journal.json`：

1. **阶段一（`Prepared`）**：在持有 `L1` 锁的前提下，分别读取所有生效副本（磁盘槽位与可选系统钥匙串）的前置缺失状态与 SHA-256 指纹，连同事务后端标识一并持久化至 `switch_journal.json`。
2. **阶段二（更新外部槽位并核验全部副本）**：将新账号凭据写入官方生效位（启用双写时依次更新钥匙串与磁盘文件，任一副本落盘或同步出错时同步回滚全部副本并核验），确认全部应有副本摘要均匹配 `target_slot_digest` 后推进事务阶段。
3. **阶段三（提交内部索引并清理日志）**：获取 `L3` 写锁更新 `index.json` 的 `selected_account_id`，最后在确认全部应有副本状态一致的前提下删除 `switch_journal.json`。

**崩溃恢复与多副本外部漂移保护（CAS）**：
- 若进程在阶段一刚写完、尚未改动槽位时遭遇 `SIGKILL` 或断电，下次对账时核实全部事务副本仍匹配各自的前置状态，直接清理未提交日志即可无损恢复。
- 若进程在阶段二已完成全部副本写入、`index.json` 更新前崩溃，下次对账核实全部应有副本均等于 `target_slot_digest` 时，才会自动前滚补齐 `index.json` 并清理日志。
- 若仅部分副本写入导致钥匙串与磁盘不一致：
  - 只读命令 `status` 返回退出码 `7`；
  - 无人值守后台 `daemon` 保留日志并进入持久故障暂停（`paused_on_failure`，单轮 `--once` 以固定原因码汇报并退出 `0`）；
  - 交互式写命令（`switch`、`policy set`、`accounts` 等）在满足同后端或超集后端且通过逐集合 CAS 保护与隐藏集合校验的前提下尝试同步修复双端副本（手动 `switch` 同时基于钉扎目录 FD 清理本工具已过期的残留临时文件并解除 `daemon` 暂停标记，若这两项辅助操作失败均明确报错而不伪装为已恢复）。
- 若 `switch_journal.json` 内容损坏、schema 版本不符或副本元数据不完整/矛盾（含文件副本记录 `file.prev_uniform = false`），程序一律保留现场绝不在单后端下擅自清除（`status` 与交互式写命令返回退出码 `7`，后台 `daemon` 进入 `paused_on_failure` 并以固定 `corrupted_switch_journal` 或 `incomplete_switch_recovery` 原因码汇报）。
- 若崩溃后用户在外部登录了第三个新账号，写前对账机不会盲目用旧快照覆盖用户刚在外部登录的新凭据，而是自动保护该外部凭据或遇到双外部冲突时保留现场返回退出码 `7`。

### 4.3 零丢码暂存、授权世代（`auth_seq`）与两级防回退谱系

Google OAuth 刷新令牌在轮换或重新授权时，一旦服务端 `/token` 接口返回了新令牌，旧令牌可能立即作废。如果在拿到新令牌之后、查询用户邮箱（`userinfo`）时发生网络中断或用户按了 `Ctrl+C`，常规实现就会把刚拿到的新令牌丢在内存里导致账号报废。本工具采用三项机制彻底解决该问题：

- **兑换前存储预检与签发后即时 `0600` 落盘**：无论是 `auth login`、`auth reauthorize`、`accounts add`（含 `--from-local`）还是后台续期，在发起 `/token` 网络请求前均先通过短同步 `L3` 预检私有目录可写性并预留单调 `auth_seq`（绝不跨网络等待持有 `L3`）；`/token` 响应返回后第一时间将新令牌以 `0600` 权限写入 `state/pending_auth/<id>.json`（或原地合并进账号记录），随后才去请求 `userinfo` 接口（若极端存储故障导致兑换后未能落盘，则显式返回退出码 `7` 脱敏恢复状态）。即使 `userinfo` 阶段网络当场断开，用户稍后运行 `auth pending --resume` 即可无损完成绑定。
- **单调授权世代（`auth_seq` 与 `auth_generation`）**：每次新授权暂存时，从 `state/auth_sequence.json` 分配全局单调递增的序号 `auth_seq`；绑定入库时推进账号的 `auth_generation`（与日常自动续期的 `token_version` 严格区分）。当一个因锁竞争滞后的旧 `pending` 记录苏醒时，在发起网络请求前和写库前都会检查世代号，一旦发现目标账号已经完成了更新一轮的授权，立即零网络开销安全退出，不会把账号回退到旧令牌。若 `reauthorize` 过程中用户误登了另一个邮箱，系统会立即为该暂存记录打上 `email_mismatch = true` 隔离标记，既不污染原账号谱系，也不误删异号有效令牌。
- **两级轮换指纹谱系（`66,048` 次历史追溯）**：账号文件内联保留最近 `512` 条已淘汰刷新令牌的 SHA-256 摘要，超出部分自动归档至 `state/token_lineage/<id>.json`（容量 `65,536` 条）。当用户拿一份几个月前导出的旧备份包执行 `accounts import --from-file <路径> --overwrite` 时，系统能准确识别出备份里的旧令牌属于已被轮换淘汰的历史祖先并予以拦截。

---

## 5. CloudCode 配额观测链路、四态评估与自动切号引擎

### 5.1 单环境隔离的三步配额观测协议（`quota/client.rs`）

- **环境优先级与单环境隔离**：默认按官方客户端实际消费额度的 **`Daily`（`daily-cloudcode-pa.googleapis.com`） -> `Sandbox` -> `Production`（`cloudcode-pa.googleapis.com`）** 顺序探测。每个候选环境独立查询其自身的 `:loadCodeAssist`（获取项目 ID 与订阅层级）、`:fetchAvailableModels`（获取模型目录与单模型主配额）和 `:retrieveUserQuotaSummary`（获取 `Weekly` 与 `5h` 配额池摘要），绝不把不同环境的层级或摘要桶混合拼接成虚假数据。
- **协议头与残缺摘要兜底**：发送与官方 Hub 一致的 `antigravity/hub/<version> (os_type=linux; arch=amd64|arm64)` 请求标识，确保服务端完整下发 Gemini 共享池与可能存在的 `Argon` 独立周池。若某环境 HTTP 200 响应仅包含第三方 `Claude/GPT` 组而缺失 `Gemini` 池，系统会将其暂存为完整单环境保底结果并继续向后探测（即使中间环境遇到目录/摘要 HTTP `404`、通用 `403`、`429`/`5xx` 或目录 JSON 解析异常也会继续探测后续环境）；仅当后续环境返回包含 `Gemini` 池的完整摘要时才整体采用后者，否则安全回退返回首环境的保底观测。
- **401 强刷闭环与阻断分类**：配额请求若在任意环境遇到 HTTP 401 或 `ACCESS_TOKEN_SCOPE_INSUFFICIENT`（权限范围不足），均作为账号级鉴权错误立即处理（其中 HTTP 401 会在 `L2 -> L3` 锁保护下执行至多 **1 次**强制 OAuth 令牌续期并重放请求，轮换新令牌立即持久化，绝不以旧 partial 观测吞没鉴权错误）；若遇 `VALIDATION_REQUIRED`（需网页安全验证），则立即停止向后探测——当前尚无有效单环境观测时精确记录验证阻断证据，若前序环境已成功取得 HTTP 200 单环境保底观测则优先保留该有效观测。

### 5.2 四态配额评估模型（`domain/quota.rs`）

评估函数 `evaluate_account_quota` 纯函数化输出四种确定性状态：
- **`Known { remaining_percentage }`**：缓存在保鲜期内（默认 `<= 3600` 秒）、所有相关配额桶的 `reset_time > 当前时间`，且数据完整有效。有效剩余百分比取 `min(周额度, 5h 额度, 模型主观测额度)` 的木桶短板值（其中同环境确认的 `Free` 层级允许无 `5h` 桶；`Argon` 为独立周池；带 `-disabled` 后缀的模型保持未知态不借用共享池）。
- **`Stale { reason }`**：缓存距今已超过 `3600` 秒（`stale_quota`），或任一配额桶已跨过重置时间点（`reset_deadline_passed`，在重新联网确认前绝不盲目假定远端已恢复为 100%）。
- **`Unknown { reason }`**：尚未拉取过配额、缺失核心窗口桶，或存在冲突桶数据。
- **`Unavailable { reason }`**：账号已被禁用、处于网页安全验证阻断期，或配额接口返回全环境 HTTP 403 Forbidden。

### 5.3 受管启动 `run` 与七阶段守护引擎 `daemon`

- **双因子防 PID 复用租约（`session/process.rs`）**：`run -- agy` 启动子进程后，读取 `/proc/<pid>/stat`（反向定位最后一个 `)` 以抵御包含空格或括号的特殊进程名）提取第 22 字段内核启动时钟滴答 `starttime`，将 `(pid, proc_starttime_ticks, account_id)` 写入 `state/leases/<pid>.json`。即使子进程异常崩溃且 Linux 内核稍后将该 PID 分配给了其他无关进程，由于 `starttime` 不匹配，旧租约会被立即识别为已失效而不会阻塞守护进程；若容器完全屏蔽了 `/proc` 导致进程状态无法核实，系统按**故障关闭（Fail-Closed）**拒绝盲目切号。
- **七阶段守护状态机（`switching/daemon.rs`）与桌面通知 / 冷却重置协同（`switching/notify.rs`、`switching/systemd.rs`）**：
  - **基础节律、脱敏与通知**：每轮默认巡检间隔 `180s ± 10%`、切号冷却 `3600s`、默认策略水位 `reserve = 10%` / `minimum = 30%`。非 `--json` 模式每轮向 `stdout` 实时刷新带本地时间戳的单行决策日志，`daemon --once --json` 与 `daemon --reset-cooldown --json` 输出标准结果信封；轮次报告、`daemon_state.json` 新写原因及 `--once`/常驻单轮错误出口均收敛为不含本机路径的固定机器错误码并附 `agy-switch-cli status` 指引（历史遗留带路径 `paused_reason` 仅清洗输出而不改写旧状态字节）。桌面通知统一附带 `transient=false` 与 `resident=true`，切号通知（`urgency=1`）默认常驻（`expire_timeout=0`，可在 `config.json` 中设 `notifications.persistent = false` 切回 `-1`），熔断暂停警告（`urgency=2`）始终常驻（`expire_timeout=0`）且正文使用无路径短句。
  - **全场景主动解除冷却（`--reset-cooldown`）与并发防覆盖**：独立 `daemon --reset-cooldown` 不请求 `DaemonInstanceLock` 与凭据后端、零网络请求，仅在 `L3` 锁内原子清零 `cooldown_until`（保留轮询游标与 `paused_on_failure`）；`--once --reset-cooldown` 在持实例锁后于单轮评估前清零；`--install --reset-cooldown` 在参数、管理器与目标 unit 目录预检均通过后一次性清零且永不写入 `ExecStart=`。普通状态回写 `persist_status` 在 `L3` 锁内重读磁盘，绝不以旧内存快照覆写外部已清零的 `cooldown_until = 0`（仅 Stage 7 专用 `persist_commit_status` 写入新冷却截止时间）。
  - **单轮七阶段流转**：
    1. `Observe`：对账日志、检查冷却与暂停状态；常驻定时唤醒与 `--once` 对非 `Unavailable` 活跃账号直接执行实时联网刷新（仅当本地处于短低水位宽限窗口——`--once` 为 `<= 15s`、常驻模式为 `min(15s, source_max_age - 1)` 且已确认 `<= reserve` 并未跨重置点——或处于失败退避期时跳过重复查询）；`--once` 源刷新失败或预算超时统一映射为 `source_refresh_failed: ...` 故障关闭，绝不回退旧缓存；`source_max_age = clamp(80% * max(interval, 5), 1, 3600)` 用于约束 `Wait` 模式挂起计划的源复验保鲜期。
    2. `Evaluate`：若当前账号额度已知且高于 `reserve_percentage`，直接进入下轮休眠；`validation_blocked` 账号保持 `UncertainHold` 不抢切，并继续严格排除在候选池与 Stage 5/6 提交外。
    3. `Prepare`：当前账号确已跌破 `reserve_percentage` 时，记录此刻的 `index.revision` 与 `policy.revision` 快照，按默认的 `round-robin` 或 `priority` 顺序受控刷新探测未禁用候选账号直至找到首个 `>= candidate_min_percentage` 的达标目标（闲置候选沿用 `3600s` 缓存）。
    4. `Guard`：先核验 `/proc` 与版本快照（若期间 `index.revision`、`policy.revision` 或槽位指纹变更则立即作废旧计划）；随后在默认 `immediate` 模式下不中断运行中的 `agy` 进程而直接进入重验与切槽，在 `wait` 模式下检测到活跃 `agy` 时暂缓等待空闲；无论何种模式，遇 `/proc` 不可读（`RuntimeState::Unverified`）均严格故障关闭绝不盲写。
    5. `Revalidate`：在持有 `L1` 锁后、提交槽位前重新核对未决日志、`index.revision`、`policy.revision`、槽位指纹、目标可用性及高优先级候选状态，若已过时则立即取消切换计划。
    6. `Commit`：在 `L1` 锁下原子提交切号并通过 Stage 7 专用回写写入新冷却截止时间；连续 3 次提交失败自动置 `paused_on_failure = true` 保护停机。
    7. `Sleep`：可被 `SIGTERM` / `SIGINT` 毫秒级唤醒并优雅退出。

---

## 6. 秘密零回显防护与终端信号安全

- **命令行与错误通道精确白名单脱敏**：
  - `accounts add` 物理上不设明文 Token 位置参数；程序入口使用 `std::env::args_os()`，遇到非法非 UTF-8 字节参数时直接返回脱敏用法错误（退出码 `2`）而不会触发 panic 或回显原始字节。
  - 自定义 `clap` 错误格式化器严格比对实际已注册的字面子命令词、选项旗标与占位符白名单，任何未知参数、未注册选项或 `--flag=secret` 内联值一律固定替换为 `[REDACTED]`；所有含环境变量绑定的参数均启用 `hide_env_values = true`，防止 `--help` 把当前环境变量中的值打印到终端。
  - JSON 反序列化错误仅提取行号、列号与分类描述，D-Bus 未分类异常映射为固定错误类别，避免直接透传外部错误正文。
- **DTO 字段白名单与动态文本归一化**：
  - 所有对外展示与 `--json` 序列化均通过独立的只读视图结构体（`AccountViewDto`、`QuotaViewDto`、`SelectedAccountBriefDto`、`StatsViewDto`、`StatsListViewDto`）转换，结构体字段层面不包含 `access_token`、`refresh_token`、`id_token`、`client_secret` 或本机文件路径；对于源自本地数据库的 `StatsViewDto.models[].model` 与 `StatsListViewDto.items[].model`，仅放行严格匹配已知公共模型 ID 或公开家族标签语法的值，其余任何本地自然语言文本、无扩展名文件名、路径、邮箱、URL 或凭据前缀均统一回退为 `"Unknown"`。
- **终端 `ECHO` 与备用屏幕信号级恢复**：
  - 无回显密码输入（`secret_input.rs`）与交互式看板（`tui/mod.rs`）同时部署了 Rust RAII `Drop` 守卫与异步信号安全的 POSIX `sigaction` 处理器（覆盖 `SIGINT`、`SIGTERM`、`SIGHUP`、`SIGQUIT`）。即使进程在等待输入或全屏看板期间收到外部终止信号，也会先恢复原始 `termios` 回显属性并退出备用屏幕，不会把用户的 SSH 终端留在盲打乱码状态。

---

## 7. 跨平台构建矩阵、性能基准与诚实验收边界台账

### 7.1 四目标 × 三特性档 Release 产物实测矩阵

**基准测量环境**：Linux `x86_64`（EndeavourOS，`rustc 1.100.0` 主工具链 + 精确最低支持版本 `rustc 1.89.0` MSRV 工具链，`cargo-deny 0.22.0`，`zig 0.17.1` + `cargo-zigbuild`，`qemu-aarch64-static`；Release 编译配置为 `lto = "thin"`、`codegen-units = 1`、`strip = "symbols"`）。

| 目标三元组 (`--target`) | 精简最小核 (`--no-default-features`) | 无钥匙串裁剪档 (`--no-default-features --features tui,stats`) | 默认统一发行版 (`default`: 全特性合一) | ELF 链接属性与 `readelf` 核验结果 |
| :--- | :---: | :---: | :---: | :--- |
| **`x86_64-unknown-linux-gnu`** | `~8.2 MiB` | `~10.8 MiB` | `~13.2 MiB` | 动态链接 glibc：仅依赖 `libc.so.6`、`libm.so.6`、`libgcc_s.so.1`、`ld-linux-x86-64.so.2`（**0 桌面/GUI/外部 SQLite 库**） |
| **`x86_64-unknown-linux-musl`** | `~7.9 MiB` | `~10.0 MiB` | `~14.4 MiB` | **`static-pie` 完全静态 ELF**：无 `PT_INTERP`、**`0` 个 `NEEDED` 共享库**；本机原生三特性档全量测试通过 |
| **`aarch64-unknown-linux-musl`** | `~6.9 MiB` | `~8.9 MiB` | `~11.8 MiB` | **`statically linked` 完全静态 ARM64 ELF**：无 `PT_INTERP`、**`0` 个 `NEEDED` 共享库**；通过 QEMU 用户态端到端冒烟 |
| **`aarch64-unknown-linux-gnu`** | `~7.2 MiB` | `~9.5 MiB` | `~11.6 MiB` | 动态链接 ARM64 glibc：仅依赖基础 C/数学运行库（**0 桌面/GUI/外部 SQLite 库**）；通过 QEMU 用户态端到端冒烟 |

### 7.2 本机原生运行性能指标（`x86_64`）

| 指标项 | 工程设计目标 | 本机实测范围（`gnu` / `musl`） | 测量方法说明 |
| :--- | :---: | :---: | :--- |
| **只读命令进程启动耗时（页缓存热态）** | `P95 < 15 ms` | **`P50 ~5.5–5.6 ms` / `P95 ~6.0–6.3 ms`** | 3 次预热后连续拉起 50 个新子进程端到端计时（含 `/proc` 实时扫描） |
| **前台 `daemon` 空闲常驻内存 (`VmRSS`)** | `< 15 MB` | **`gnu`: `~9.9 MiB` / `musl`: `~8.7 MiB`** | 全特性档空闲监控态读取 `/proc/<pid>/status` 中 `VmRSS` |
| **GUI / 桌面 / `libdbus` 动态库依赖数** | `0` | **全部 12 份 Release 产物均为 `0`** | `readelf -l` + `readelf -d` 逐份静态扫描核验 |

### 7.3 验收证据范围与待外部闭环事项（诚实状态台账）

下表区分**已在自动化测试与云端 CI 中实测验证的范围**与**受运行环境限制仍需持续关注的边界事项**：

| 验证领域 | 已完成的验证范围 | 边界说明与后续关注项 |
| :--- | :--- | :--- |
| **构建、MSRV 与云端 CI 门禁** | 本机隔离沙盒与 GitHub Actions 云端（`Ubuntu 26.04` 5 项门禁作业）均已实测通过：`cargo fmt --check`、`rustc 1.100.0` 与最低 MSRV `rustc 1.89.0` 三特性档零警告 `clippy`、三特性档全量单元与集成测试（含 `--test-threads=32` 并发交错压测）、`x86_64` 与 `aarch64` 纯静态 `musl` 构建及 QEMU 端到端正负向冒烟（见 [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)）。 | 云端与本机针对 `aarch64` 的自动化运行验证基于 QEMU 用户态仿真完成，不等同于原生物理 ARM64 服务器硬件上的高负载压测。 |
| **官方 `agy` 契约与在线协议** | 已基于隔离临时 `HOME`、本地 HTTP/SOCKS5 Mock 服务及私有 Mock D-Bus Secret Service 完整验证凭据读写、双写回滚、PKCE 换码、401 强刷闭环、`Daily` 优先单环境配额融合与 3p-only 残缺摘要保底逻辑，并经维护者实机验证真实配额刷新与切号流程。 | Google CloudCode 内部接口（如 `:retrieveUserQuotaSummary` 的配额池命名与请求头策略）并非公开固定规范，若未来上游服务端调整返回结构，需随版本迭代同步适配。 |
| **并发锁、崩溃恢复与防回退** | 已通过多轮独立第三方零信任代码审计，自动化测试覆盖跨目录混合后端 `L1` 锁互斥、四级锁序防死锁、`PendingAuthLock` 与 `auth_seq` 跨 pending 忙锁防回退、`email_mismatch` 异号保护、全深度符号链接与 FIFO 非阻塞拦截、真实子进程 `SIGKILL` 崩溃日志写前安全自愈恢复，以及 `66,048` 级轮换谱系防旧备份覆盖（注：当既有 `index.json` 文件内容损坏而非缺失时，写前对账会安全拒绝盲目覆盖并保留现场供人工核查）。 | 进程级故障注入与 `SIGKILL` 测试验证了应用层协议的一致性，不等同于物理断电或底层存储介质硬件损坏场景下的全矩阵测试。 |
| **许可证与第三方依赖审计** | 完整保留 `CC-BY-NC-SA-4.0` [`LICENSE`](../LICENSE) 与 [`PROVENANCE.md`](../PROVENANCE.md)，已将全仓时间库从 `chrono` 一次性迁移至 `jiff 0.2`（移除 `RUSTSEC-2026-0543` 豁免），引入 `rusqlite 0.43`（内嵌 `SQLite 3.54+`），通过在线 `cargo deny check advisories bans licenses sources` 四项全检（0 安全漏洞）。 | 默认启用的 `secret-service-backend` 特性所用 `secret-service 5.2.0` 经 `zbus 5.19.0` 传递依赖 3 个已合并至 `zbus 6.0` 的子包（`RUSTSEC-2026-0370`/`0371`/`0372` 仓库合并维护提示，无安全漏洞；`--no-default-features` 等裁剪构建不引入该依赖链），已在 [`deny.toml`](../deny.toml) 中记录说明，待 `secret-service 6.0` 稳定发布后升级移除。 |
