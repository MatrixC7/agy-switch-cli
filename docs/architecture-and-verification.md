# `agy-switch-cli` 技术架构、安全机制与验收台账

> 返回首页：[README.md](../README.md) ｜ 完整使用与部署手册：[user-guide.md](user-guide.md) ｜ 重构溯源声明：[PROVENANCE.md](../PROVENANCE.md)

---

## 1. v1 核心架构契约（做什么 / 不做什么）

1. **纯无头零 GUI 架构**：不启动任何桌面窗口或系统托盘，不链接 `GTK` / `WebKitGTK` / `X11` / `Wayland` / `libdbus` 动态库，不读写桌面端 IDE 的 `state.vscdb` SQLite 数据库，不注入客户端网页脚本，也不伪造桌面设备指纹（`DeviceProfile`）。
2. **切号生效语义（核心事实）**：
   - `switch` 成功提交表示目标账号凭据已安全写入官方生效位 `~/.gemini/antigravity-cli/antigravity-oauth-token`（权限 `0600`）并完成本地索引对账。
   - **默认仅对切换完成后新启动的 `agy` 进程生效**。已经运行中的 `agy` 进程会保留其启动时加载的内存会话；v1 不会热篡改运行中进程的身份，也不会中断正在执行的任务。
3. **双因子防 PID 复用租约**：`agy-switch-cli run -- agy ...` 在启动前检查配额与令牌时效，按需先行切号，并登记双因子进程租约（`pid` + `/proc/<pid>/stat` 第 22 字段内核启动时钟滴答 `starttime`）；当 `/proc` 被挂载策略屏蔽或不可读时，自动按**故障关闭（Fail-Closed，退出码 `8`）**拒绝盲目切号。

---

## 2. 三域存储拓扑与四级单向锁状态机

### 2.1 存储与锁目录规范

| 作用域 | 默认路径 | 权限 | 用途说明 |
| :--- | :--- | :---: | :--- |
| **独立账号仓库 (`data_dir`)** | `$XDG_DATA_HOME/agy-switch-cli`<br>（回退 `~/.local/share/agy-switch-cli`） | 目录 `0700`<br>文件 `0600` | 存放 `index.json`、`accounts/<id>.json`、`policy.json`、可选 `config.json`、`state/switch_journal.json`、`state/daemon_state.json`、`state/auth_sequence.json`、`state/leases/<pid>.json`、`state/pending_auth/<id>.json`、`state/pending_lineage/<id>.json`、`state/token_lineage/<id>.json` 及 `PendingAuthLock` / L2 / L3 锁 |
| **全局锁与缓存域 (`cache_dir`)** | `$XDG_CACHE_HOME/agy-switch-cli`<br>（回退 `~/.cache/agy-switch-cli`） | `0700` | 存放跨 `--data-dir` 与双后端统一互斥的 **L1 `ActiveSlotLock`**（`locks/slot-<sha256>.lock` 及可选 `locks/keyring-<uid>.lock`）和 24h UA 版本缓存 |
| **官方凭据生效位 (`active_slot`)** | `~/.gemini/antigravity-cli/antigravity-oauth-token` | `0600` | 官方 `agy` 凭据文件（保持目录 **100% 纯净**，绝不在该目录内遗留 `.lock` 或 `.tmp` 文件） |

### 2.2 四级锁顺序、授权世代 CAS 与防回退不变量

- **严格单向锁序**：全代码库强制遵循 **`L1 (ActiveSlotLock) → PendingAuthLock (with_pending_auth_lock) → L2 (with_account_refresh_lock) → L3 (with_store_write_lock)`**：
  - `L1` 在 `file` 与 `secret-service` 双后端下始终首先锁定同一物理槽位锁，永不 `unlink` 锁文件；
  - `PendingAuthLock` 串行协调单条 `pending_auth` 记录的全生命周期，绝不在持 `L2` / `L3` 时阻塞等待另一把 `PendingAuthLock`；
  - `L2` 守卫与单账号异步刷新/重授权作用域一对一绑定；
  - `L3` 仅接受同步闭包 `FnOnce(&StoreWriteTx<'_>)`，从 Rust 编译期根除跨 `.await` 持写锁。
- **单调授权世代（`auth_seq` / `auth_generation`）与异号保护**：
  - 每次 `/token` 新签发暂存记录时，在 `L3` 内分配全局单调递增的 `auth_seq`（持久化于 `state/auth_sequence.json` 并纳入 `PendingAuthRecord` 指纹 CAS，暂存续期不改写，彻底摆脱秒级墙钟依赖）；
  - 账号记录维护已生效授权世代 `auth_generation`（与日常自动续期 `merge_refreshed_token` 的 `token_version` 严格解耦）。当并发忙锁的旧 `pending` 在新授权生效后获得 `L2` 时，在发起任何网络请求前及 `L3` 提交前双重识别世代过时，零网络请求吸收其历史摘要并 CAS 清理，绝不回退新令牌；
  - 若重授权在 `userinfo` 阶段证实误登了其他邮箱（`reauthorize_email_mismatch`），立即标记 `email_mismatch = true` 予以隔离保护，绝不误删异号令牌或污染原账号谱系。
- **两级轮换指纹归档与全深度防软链读写**：
  - `accounts/<id>.json` 内联保留最近 `512` 条已淘汰 `refresh_token` SHA-256 摘要，溢出部分持久归档至 `state/token_lineage/<id>.json`（最多 `65,536` 条，合计可精确追溯 **`66,048` 次**轮换）；一旦超出总容量上限则标记 `truncated = true`，对无法证明回滚安全的 `--overwrite` 执行故障关闭拒绝；
  - 全部受管读写路径自根目录起逐级执行 `lstat` 校验，通过 `O_PATH | O_DIRECTORY | O_NOFOLLOW` 锚定父目录句柄与文件 `(dev, ino)`，并以 `O_NOFOLLOW | O_NONBLOCK` 有界读取普通文件（毫秒级拒绝任意深层符号链接穿越与无写端 FIFO 阻塞），写入采用临时文件 `fsync` + 原子 `rename` + 父目录 `fsync`。

---

## 3. 本机 Release 实测基准、跨平台静态矩阵与 ELF 检查

**实测环境口径**：
- **操作系统 / 内核 / 架构**：Linux `7.3.4-zen2-1-zen`（`x86_64`，glibc `2.44`，musl `1.2.x`，`qemu-aarch64-static` 用户态仿真）
- **双工具链核验**：`rustc 1.100.0 (0ef1bc386 2026-11-09)`（主测量）与精确最低 MSRV `rustc 1.89.0 (29483883e 2025-08-04)`；依赖审计工具 `cargo-deny 0.20.2`、`cargo-audit 0.23.0`
- **构建配置**：`--release --locked`（`lto = "thin"`，`codegen-units = 1`，`strip = "symbols"`）
- **测量限制说明**：启动耗时为预热后连续启动新子进程（进程冷启动、OS 页缓存热态）的本机实测，不等同于清空磁盘页缓存的冷盘启动或高并发网络负载表现；`aarch64` 运行验证通过 `qemu-aarch64-static` 在宿主机用户态完成，不等同于原生物理 ARM64 硬件基准。

### 3.1 四目标 × 三特性档 Release 产物矩阵（全部零 GUI / 零 `libdbus` 动态依赖）

| 目标三元组 (`--target`) | 精简无头 (`--no-default-features`) | 默认含 `tui` | 全特性 (`--all-features`) | ELF 链接属性与 `readelf` 核验结果 |
| :--- | :---: | :---: | :---: | :--- |
| **`x86_64-unknown-linux-gnu`** | `8,037,744 B` (`7.67 MiB`) | `8,285,248 B` (`7.90 MiB`) | `10,609,712 B` (`10.12 MiB`) | 动态链接 glibc：仅 `libc.so.6`、`libm.so.6`、`libgcc_s.so.1`、`ld-linux-x86-64.so.2`（**0 桌面库**） |
| **`x86_64-unknown-linux-musl`** | `8,157,952 B` (`7.78 MiB`) | `8,403,776 B` (`8.01 MiB`) | `10,732,128 B` (`10.23 MiB`) | **`static-pie` 完全静态 ELF**：无 `PT_INTERP`、**`0` 个 `NEEDED` 共享库**；本机原生三特性档全量测试（78 / 79 / 81）全绿 |
| **`aarch64-unknown-linux-musl`** | `6,681,128 B` (`6.37 MiB`) | `6,893,056 B` (`6.57 MiB`) | `8,840,928 B` (`8.43 MiB`) | **`statically linked` 完全静态 ARM64 ELF**：无 `PT_INTERP`、**`0` 个 `NEEDED` 共享库**；通过 `qemu-aarch64-static` 端到端正负向冒烟 |
| **`aarch64-unknown-linux-gnu`** | `6,953,792 B` (`6.63 MiB`) | `7,216,024 B` (`6.88 MiB`) | `9,183,912 B` (`8.76 MiB`) | 动态链接 ARM64 glibc：仅 `libc.so.6`、`libm.so.6`、`libgcc_s.so.1`（**0 桌面库**）；通过 `qemu-aarch64-static -L /usr/aarch64-linux-gnu` 端到端正负向冒烟 |

### 3.2 本机原生运行性能指标（`x86_64` GNU 与静态 `musl`）

| 指标项 | 工程目标 | 本机实测范围（`gnu` / `musl`） | 测量方法与说明 |
| :--- | :---: | :---: | :--- |
| **新进程启动耗时 (`status --json`, 页缓存热态)** | `P95 < 15 ms` | **`P50 ~5.5–5.6 ms` / `P95 ~6.0–6.3 ms`** | 3 次预热后连续启动 50 个新子进程端到端计时（含真实 `/proc` 扫描） |
| **前台 `daemon` 空闲常驻内存 (`VmRSS`)** | `< 15 MB` | **`gnu`: `~9.9 MiB` / `musl`: `~8.7 MiB`** | 全特性档空库空闲态读取 `/proc/<pid>/status` 中 `VmRSS` |
| **GUI / 桌面 / `libdbus` 动态库依赖数** | `0` | **全部 12 份 Release 产物均为 `0`** | `readelf -l` + `readelf -d` 逐份核验 |

---

## 4. 验收证据范围与待外部闭环事项（诚实状态台账）

下表严格区分**“已在本机隔离自动化测试中实测验证的范围”**与**“受环境/授权限制尚未闭环、不得视为已通过的事项”**：

| 领域 | 本机已完成的自动化验证范围 | 尚未完成 / 待外部环境闭环的限制项 |
| :--- | :--- | :--- |
| **二进制无头性、MSRV 与跨平台矩阵** | 已在本机隔离沙盒下实测通过：`cargo fmt --check`；`rustc 1.100.0` 与最低 MSRV **`rustc 1.89.0`** 双编译器下的三特性档 `clippy -D warnings`、三特性档全量测试（78 / 79 / 81）及 `--test-threads=64` 并发压力复跑；**`x86_64-unknown-linux-musl`** 静态二进制原生三特性档全量测试；`x86_64`/`aarch64` × `gnu`/`musl` 共 12 份 Release 产物的 ELF 静态性/零桌面库检查，以及 `aarch64`（`musl` 与 `gnu`）在 `qemu-aarch64-static` 下的只读零副作用、异常参数脱敏、导入导出与 FIFO 防阻塞验证（[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) 已配置 5 大云端门禁作业）。 | 远端 GitHub Actions 托管 Runner 尚待仓库推送后实跑；`aarch64` 当前通过 `qemu-aarch64-static` 用户态仿真验证，尚未在真实物理 ARM64 服务器硬件及 Debian / Ubuntu / Alpine 多发行版真实容器矩阵上执行完整信号/PTY 压力回归。 |
| **官方 `agy` 客户端契约** | 已核对 `1.5.7` 常量提示，并在隔离临时 `HOME` 与私有 Mock D-Bus `org.freedesktop.secrets` 下验证文件槽位及双写/回滚状态机。 | **未执行真实账号在线全周期验收**：官方 `agy` 在无 D-Bus 环境下的真实过期令牌自刷新写回、真实 Google 服务端对 `scope` 组合的接受度及真实桌面多凭据源冲突，须使用专门授权的可处置测试账号在隔离容器中补测。 |
| **锁层级、持久化与崩溃对账** | 已覆盖跨 `--data-dir` 与 `file`/`secret-service` 混合后端 `L1` 互斥、`PendingAuthLock`、单调暂存序号 `auth_seq` 与账号授权世代 `auth_generation`（含跨 pending 忙锁交错防回退与 `email_mismatch` 异号保护）、`L2`/`L3` 类型级顺序与防跨 `await` 守卫、全深度祖先符号链接拦截与父句柄锚定非阻塞普通文件读取、真正 `SIGKILL` 子进程崩溃恢复、外部槽位漂移 CAS 保护、删除账号策略同步、`doctor` 如实诊断 `daemon_state` / `auth_sequence` 错误，以及两级归档轮换指纹防 `--overwrite` 回退（注：当既存 `index.json` 内容损坏而非缺失时，`doctor --fix` 会安全拒绝自动覆盖并保留现场供人工核查）。 | 软件级故障注入与本地 `SIGKILL` 测试不等同于真实物理断电、内核崩溃或底层文件系统介质损坏的全矩阵验证。 |
| **OAuth、配额与守护进程** | 基于本地 Mock 与私有 SOCKS5 服务验证 PKCE (`S256`)、真实 `url::Host` Loopback 校验、`add`/`login`/`reauthorize`/`refresh`/`pending --resume` 全入口 `/token` 后立即落盘与并发防回退、并发 `Manual` 禁用保留、状态写盘 I/O 错误传播、单环境配额隔离、缺失 `primary` 保持 `Unknown`、`Scope`/`VALIDATION_REQUIRED` 阻断保留、`daemon` 决策版本快照与真实时钟 `Revalidate`、`/proc` 不可读故障关闭及 `--once` 信号停机。 | 未连接 Google 生产 OAuth / CloudCode 服务，也未测试企业真实 HTTPS MITM 代理或自定义根证书环境。 |
| **秘密隔离与终端恢复** | 已验证非 UTF-8 `argv` 安全拒绝（退出码 `2` 且不回显原字节）、显式 `--help` 隐藏环境变量值（`hide_env_values`）、未知 OAuth 错误码白名单、损坏 JSON 行列脱敏、选择器形态校验不回显、`HttpRequest` URL Debug 脱敏、`--json` 纯净错误信封，以及 `secret_input` 与 `tui` 在真实 PTY 下的 `SIGINT`/`SIGTERM` 回显恢复。 | 发布前仍建议结合独立秘密扫描工具对历史提交与构建归档执行持续复核。 |
| **许可证与依赖合规** | 已保留逐字节一致的 `CC-BY-NC-SA-4.0` [`LICENSE`](../LICENSE) 与可追溯 [`PROVENANCE.md`](../PROVENANCE.md)，并在本机实测通过 `cargo deny check advisories bans licenses sources`（`advisories ok, bans ok, licenses ok, sources ok`，覆盖全部 4 个 Linux 目标与全特性）及 `cargo audit`（0 安全漏洞）。 | 可选特性 `secret-service 5.2.0`（6.0 尚处 RC 阶段）经 `zbus 5.19.0` 传递引入 3 个已并入 `zbus 6.0` 的子包（`RUSTSEC-2026-0370`/`0371`/`0372` 架构合并 `unmaintained` 提示，非安全漏洞），已在 [`deny.toml`](../deny.toml) 中逐条注明原因豁免，待上游 `secret-service 6.0` 稳定发布后应升级并移除豁免。 |
