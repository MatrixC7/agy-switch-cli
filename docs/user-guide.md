# `agy-switch-cli` 完整使用、配置与部署手册

> 返回首页：[README.md](../README.md) ｜ 技术架构与验收台账：[architecture-and-verification.md](architecture-and-verification.md)

---

## 目录

1. [版本选型与安装（标准版 vs `-all-features` 全特性版）](#1-版本选型与安装标准版-vs--all-features-全特性版)
2. [全局选项与环境变量](#2-全局选项与环境变量)
3. [全量命令详解](#3-全量命令详解)
4. [标准退出码（`0..=8`）与 `--json` 脚本集成契约](#4-标准退出码08与---json-脚本集成契约)
5. [可选配置文件（`config.json` 代理与自定义 OAuth 客户端）](#5-可选配置文件configjson-代理与自定义-oauth-客户端)
6. [后台守护进程部署（`systemd --user` 与容器）](#6-后台守护进程部署systemd---user-与容器)
7. [常见场景与故障排查](#7-常见场景与故障排查)

---

## 1. 版本选型与安装（标准版 vs `-all-features` 全特性版）

### 1.1 预编译包两类特性的核心区别

在 GitHub Releases 中，每种 CPU 架构（`x86_64` 与 `aarch64`）都提供了**不带 `-all-features` 的标准版**和**带 `-all-features` 的全特性版**（两者均为 100% 纯静态 `musl` 二进制，无需任何系统动态库）：

| 对比维度 | 标准版（默认特性 `tui`） | 全特性版（`-all-features`，额外含 `secret-service-backend`） |
| :--- | :--- | :--- |
| **包含功能** | 全部核心无头 CLI 命令 + SSH 终端看板 `tui` | 标准版全部功能 + **Linux 桌面钥匙串（D-Bus `org.freedesktop.secrets`）双写同步** |
| **可用 `--backend`** | `file`（默认，仅读写 `~/.gemini/antigravity-cli/antigravity-oauth-token`） | `file`（默认）**或** `secret-service`（同时写入桌面钥匙串与凭据文件，失败自动回滚） |
| **二进制体积** | 更轻量（`x86_64` `8.01 MiB` / `aarch64` `6.57 MiB`） | 略大（`x86_64` `10.23 MiB` / `aarch64` `8.43 MiB`，内置纯 Rust `zbus` 协议栈） |
| **推荐人群** | **95% 的服务器、容器、WSL2 用户，以及使用 `run --isolate-dbus` 的桌面用户** | 在 Linux 图形桌面终端里直接裸敲 `agy`、且桌面开启了 GNOME Keyring / KWallet 的用户 |

#### 典型场景举例
- **场景 A（远程云服务器 / Docker / WSL2）—— 选标准版**：  
  您通过 SSH 登录一台 Ubuntu / Debian 云服务器运行 `agy`。服务器上没有图形桌面钥匙串，官方 `agy` 只读取 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件，下载**标准版**最精简干净。
- **场景 B（Linux 图形桌面 + 受管包装启动）—— 选标准版即可**：  
  您在 EndeavourOS（KDE/GNOME）桌面上使用，但平时习惯通过 `agy-switch-cli run --isolate-dbus -- agy` 启动 `agy`。`--isolate-dbus` 会自动为子进程隔离桌面 D-Bus，强制官方 `agy` 读取切好的文件凭据，标准版完全够用。
- **场景 C（Linux 图形桌面 + 习惯直接裸敲 `agy`）—— 选 `-all-features` 全特性版**：  
  官方 `agy` 在检测到桌面存在活跃 D-Bus Secret Service（如 GNOME Keyring / KDE Wallet）时，会**优先读取钥匙串里的凭据**而忽略本地文件。如果您在桌面终端里不想加前缀包装、想直接敲 `agy`，可下载 **`-all-features` 版**，切号时执行：
  ```bash
  agy-switch-cli --backend secret-service switch work@example.com
  ```
  它会同时更新桌面钥匙串和凭据文件，随后您直接输入 `agy` 即可使用新账号。

### 1.2 下载安装预编译静态包

```bash
# 1. 校验压缩包完整性（以 x86_64 标准版为例）
sha256sum -c agy-switch-cli-v1.0.0-x86_64-unknown-linux-musl.tar.gz.sha256

# 2. 解压并安装到用户目录（或 /usr/local/bin）
tar -xzf agy-switch-cli-v1.0.0-x86_64-unknown-linux-musl.tar.gz
mkdir -p ~/.local/bin
install -m 0755 agy-switch-cli-v1.0.0-x86_64-unknown-linux-musl/agy-switch-cli ~/.local/bin/agy-switch-cli
```

### 1.3 从源码编译（要求 `rustc >= 1.89`）

```bash
# 1. 默认构建（推荐：核心 CLI + SSH 终端看板 tui）
cargo build --release --locked

# 2. 极简无头构建（移除 crossterm / comfy-table 依赖，仍保留基于 libc::termios 的安全无回显输入）
cargo build --release --locked --no-default-features

# 3. 全特性构建（额外启用 --backend secret-service 双写支持）
cargo build --release --locked --all-features

# 4. 完全静态 musl 构建（跨全 Linux 发行版通用）
cargo build --release --locked --target x86_64-unknown-linux-musl
# ARM64 静态交叉构建（需安装 cargo-zigbuild 与 zig）：
cargo zigbuild --release --locked --target aarch64-unknown-linux-musl
```

---

## 2. 全局选项与环境变量

以下全局选项可附加在任意子命令之前或之后：

| 全局选项 | 对应环境变量 | 说明 |
| :--- | :--- | :--- |
| `--data-dir <PATH>` | `AGY_SWITCH_CLI_DATA_DIR` | 指定独立账号库目录（默认 `$XDG_DATA_HOME/agy-switch-cli`，回退 `~/.local/share/agy-switch-cli`） |
| `--proxy <URL\|direct>` | `AGY_SWITCH_CLI_PROXY` | 显式指定网络代理（支持 `http://`、`https://`、`socks5://`、`socks5h://` 或强制直连 `direct`） |
| `--backend <file\|secret-service>` | — | 指定凭据生效后端（默认 `file`；`secret-service` 需全特性构建） |
| `--no-remote-version` | — | 禁用联网命令启动时的可选远端 User-Agent 版本号缓存查询 |
| `--json` | — | 启用机器可读 JSON 输出模式（`schema_version: 1`） |

---

## 3. 全量命令详解

### 3.1 环境诊断与恢复（`doctor`）

```bash
# 只读全面体检（检查账号库、策略、暂存授权、崩溃日志、权限及活跃 D-Bus 风险）
agy-switch-cli doctor

# 同时在隔离临时 HOME 中探测本机已安装的官方 agy 客户端版本兼容性
agy-switch-cli doctor --verify-agy

# 自动对账未完成的切换日志（switch_journal.json）、修复权限为 0600/0700、清理失效策略候选与守护暂停状态
agy-switch-cli doctor --fix
```

### 3.2 无头 OAuth 2.0 授权管理（`auth`）

```bash
# 方式 A：SSH 端口转发回调登录（默认监听本地随机回环端口，可在本地浏览器通过 SSH -L 完成授权）
agy-switch-cli auth login --label "主力账号"

# 方式 B：纯无头手动粘贴模式（无需端口转发！在任意电脑浏览器完成授权后，将跳转失败页面的完整 localhost URL 粘贴回终端即可）
agy-switch-cli auth login --manual --label "服务器账号"

# 对已有账号重新授权（例如令牌被撤销 invalid_grant 或缺少必需 Scope 时原地更新，保留原账号 ID 与策略绑定）
agy-switch-cli auth reauthorize <ID|EMAIL> [--manual]

# 查看、断点恢复或清空因网络中断保存在 state/pending_auth/ 中的暂存已签发令牌
agy-switch-cli auth pending
agy-switch-cli auth pending --resume
agy-switch-cli auth pending --purge

# 查看当前已注册的 OAuth 客户端配置列表（自动脱敏密钥）
agy-switch-cli auth clients
```

### 3.3 账号池管理（`accounts`）

> **安全红线**：为防止 `ps` 进程表或 Shell 历史记录泄露令牌，本项目**严禁**通过命令行位置参数传递明文 Refresh Token！

```bash
# 列出本地保存的所有账号（支持 --json）
agy-switch-cli accounts list

# 安全添加 Refresh Token 的三种方式：
agy-switch-cli accounts add --label "备用号"                      # 1. 交互式终端无回显输入（自动屏蔽回显并在 Ctrl+C 时恢复）
printf '%s\n' "$MY_RT" | agy-switch-cli accounts add --stdin     # 2. 标准输入单行管道
agy-switch-cli accounts add --token-file ~/.secrets/rt.txt       # 3. 从 0600 私有普通文件读取

# 导入备份包或从旧版桌面端目录（~/.antigravity_tools）只读迁移：
# （默认跳过已存在的同账号，绝不修改原目录；显式加 --overwrite 也会自动拦截已轮换淘汰的旧备份令牌）
agy-switch-cli accounts import backup.json [--overwrite]
agy-switch-cli accounts import --from-legacy [LEGACY_DIR] [--overwrite]

# 导出账号备份包（因含敏感刷新令牌，必须显式声明 --include-secrets，导出文件强制 0600 权限）
agy-switch-cli accounts export --output ~/agy-backup.json --include-secrets [--ids <ID|EMAIL...>] [--force]

# 调整默认顺序、启用/手动禁用、删除账号
agy-switch-cli accounts order <ID_1> <ID_2> ...
agy-switch-cli accounts enable <ID|EMAIL>
agy-switch-cli accounts disable <ID|EMAIL> [--reason "留作月底备用"]
agy-switch-cli accounts delete <ID|EMAIL> [--force] [--clear-active-slot]
```

### 3.4 三态身份观察、手动切号与受管执行（`status` / `current` / `switch` / `run`）

```bash
# 查看三重身份状态：1. 账号库记录选中账号；2. 官方凭据槽位实际身份（识别外部漂移）；3. 当前运行中的 agy 进程状态
agy-switch-cli status [--json]

# 纯只读查看本地选中账号（零网络、零磁盘写入）
agy-switch-cli current [--json]

# 手动切换到指定账号（若检测到已有运行中的 agy 进程默认安全拒绝并返回退出码 8，可通过 --allow-running 显式放行）
agy-switch-cli switch <ID|EMAIL> [--dry-run] [--allow-running]

# 【最推荐】启动前自动选号受管包装运行（透传子进程真实退出码，支持 --isolate-dbus 屏蔽桌面钥匙串干扰）
agy-switch-cli run [--account <ID|EMAIL>] [--isolate-dbus] -- agy <AGY_ARGS...>
```

### 3.5 配额查看与联网刷新（`quota` / `refresh`）

```bash
# 纯只读读取本地缓存的配额快照（零网络请求）
agy-switch-cli quota [<ID|EMAIL> | --all] [--json]

# 显式联网刷新 OAuth 令牌与 CloudCode 实时配额（默认并发度受控，范围 1..=5）
agy-switch-cli refresh [<ID|EMAIL> | --all] [--concurrency 3] [--json]
```

### 3.6 自动切号策略与前台守护进程（`policy` / `daemon` / `tui`）

```bash
# 查看或修改自动切号策略（阈值校验满足 reserve < minimum）
agy-switch-cli policy show [--json]
agy-switch-cli policy set --enabled true --strategy priority --mode wait \
  --reserve 15 --minimum 35 --model all --candidates <ID_1> <ID_2>

# 空跑模拟评估当前策略会做出什么切号决策（零副作用）
agy-switch-cli policy eval [--json]

# 启动七阶段前台自动切号守护进程（或加 --once 执行单轮巡检后退出，适合配合 cron / systemd timer）
agy-switch-cli daemon [--interval 180] [--cooldown 300] [--once]

# 打开 SSH 交互式终端实时看板（支持按 r 刷新、s 切号、q 或 Esc 退出）
agy-switch-cli tui
```

---

## 4. 标准退出码（`0..=8`）与 `--json` 脚本集成契约

- 开启 `--json` 后：成功时向 `stdout` 输出单个格式化 JSON 对象（顶层含 `"schema_version": 1, "ok": true`）；失败时向 `stderr` 输出单行结构化错误 JSON（顶层含 `"schema_version": 1, "ok": false, "exit_code": ..., "error_code": ..., "message": ...`）。
- 交互式提示与授权 URL 在 `--json` 模式下会定向输出至独立的 `/dev/tty` 终端控制通道，保证 `stdout` / `stderr` 管道 100% 纯净可解析。

| 退出码 | 枚举名称 | 含义与自动化处理建议 |
| :---: | :--- | :--- |
| `0` | `Ok` | 执行成功（`run` 模式下透传子进程 `agy` 的退出码） |
| `1` | `GeneralOrDataError` | 本地数据损坏、I/O 权限拒绝或常规运行时错误 |
| `2` | `InvalidUsageOrAmbiguous` | 命令行参数错误（含非 UTF-8 参数）、策略参数不合法，或邮箱匹配到多个账号 |
| `3` | `AccountNotFound` | 指定账号不存在，或尚未设置选中账号 |
| `4` | `QuotaUnavailableOrStale` | 目标账号无配额缓存、配额已过重置时间（`Stale`）或核心模型额度未知 |
| `5` | `LockBusyOrConflict` | 另一进程正持有槽位锁/存储锁、并发 CAS 冲突，或拒绝旧令牌覆盖已轮换新令牌 |
| `6` | `AuthOrClientError` | OAuth 授权失败、令牌已失效（`invalid_grant`）、缺少必需 Scope 或客户端不匹配 |
| `7` | `PartialCommitOrRecovery` | 切换日志处于待对账状态（`CommittedIndexPending` / `RecoveryIncomplete`）；运行 `doctor --fix` 即可恢复 |
| `8` | `EnvironmentNotReady` | 官方 `agy` 目录未就绪、存在运行中 `agy` 进程、`/proc` 不可读（故障关闭），或后端未就绪 |

---

## 5. 可选配置文件（`config.json` 代理与自定义 OAuth 客户端）

如需固定网络代理或自定义企业 OAuth 客户端，可在 `<data_dir>/config.json`（默认 `~/.local/share/agy-switch-cli/config.json`，权限建议设为 `0600`）中配置：

```json
{
  "schema_version": 1,
  "network": {
    "proxy_url": "socks5h://127.0.0.1:1080",
    "no_proxy": "internal.corp,10.0.0.0/8"
  },
  "oauth": {
    "active_client_key": "antigravity_enterprise",
    "required_scopes": [
      "openid",
      "https://www.googleapis.com/auth/cloud-platform"
    ],
    "clients": []
  }
}
```

- **代理生效优先级**：命令行 `--proxy <URL|direct>`（或 `AGY_SWITCH_CLI_PROXY`） > `config.json` 中的 `network.proxy_url` > 系统环境变量 `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`。
- **安全回环直连**：基于 `url::Host` 精确解析目标主机，真实本地回环地址（`127.0.0.0/8`、`localhost`、`[::1]`）始终强制直连，避免本地 OAuth 回调被外部代理劫持。

---

## 6. 后台守护进程部署（`systemd --user` 与容器）

### 6.1 使用 `systemd --user` 常驻运行（推荐）

仓库内已提供加固版服务模板 [`deploy/agy-switch-cli.service`](../deploy/agy-switch-cli.service)：

```bash
# 确保二进制已安装到 ~/.local/bin/agy-switch-cli（若安装在其他路径请相应调整模板中的 ExecStart）
mkdir -p ~/.config/systemd/user
cp deploy/agy-switch-cli.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now agy-switch-cli.service

# 查看运行状态与实时日志
systemctl --user status agy-switch-cli.service
journalctl --user -u agy-switch-cli.service -f

# 如需退出 SSH 后依然保持用户级守护进程运行，请开启 linger：
sudo loginctl enable-linger "$USER"
```

### 6.2 容器环境部署注意事项

- 直接以前台进程运行 `agy-switch-cli daemon`，并搭配 `tini`、`dumb-init` 或容器平台 PID 1 信号转发，以确保 `SIGTERM` / `SIGINT` 能优雅停止守护进程。
- 挂载到 `~/.gemini/antigravity-cli`、`~/.local/share/agy-switch-cli` 与 `~/.cache/agy-switch-cli` 的存储卷必须支持标准 POSIX `flock` 文件锁（避免使用不支持本地文件锁的旧版无锁 NFS 挂载）。

---

## 7. 常见场景与故障排查

1. **登录或添加账号时换码成功，但因网络抖动查 `userinfo` 报错了，令牌会丢吗？**  
   不会。`/token` 签发后新令牌已第一时间加密权限（`0600`）保存在 `state/pending_auth/` 中。网络恢复后直接运行 `agy-switch-cli auth pending --resume` 即可完成绑定，无需重新授权。
2. **`doctor` 报告退出码 `7`（`pending_journal_reconciliation`）怎么办？**  
   说明上一次切号在崩溃或断电瞬间停在了中间阶段。直接执行 `agy-switch-cli doctor --fix`，工具会根据实时槽位摘要 CAS 自动前滚或安全回滚对账。
3. **`doctor` 提示检测到活跃的 `DBUS_SESSION_BUS_ADDRESS` 套接字警告？**  
   说明当前处于桌面或开启了用户级 D-Bus 的会话中，官方 `agy` 可能会优先读取系统钥匙串。您只需二选一：
   - 方法一（最简单）：使用 `agy-switch-cli run --isolate-dbus -- agy` 启动客户端；
   - 方法二：改用 `-all-features` 版二进制并加上 `--backend secret-service` 执行切换。
