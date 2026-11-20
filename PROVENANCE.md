# 代码来源溯源、署名与结构性修改说明（`PROVENANCE.md`）

> **合规声明**：本文档旨在履行 **知识共享 署名-非商业性使用-相同方式共享 4.0 国际公共许可证（`CC-BY-NC-SA-4.0`）** 第 3(a) 条（署名 / Attribution）与第 3(b) 条（相同方式共享 / ShareAlike）规定的衍生作品说明义务。本文档属于工程来源记录，不构成专业法律意见。

---

## 1. 上游来源与许可证信息

- **上游项目名称**：`agy-switch`（“Local Antigravity account switching and usage dashboard”）
- **上游公开仓库**：<https://github.com/anglee0323/agy-switch>
- **上游仓库维护者 / 署名**：`anglee0323` 及 `agy-switch` 项目贡献者（上游 `src-tauri/Cargo.toml` 声明 `authors = ["you"]`）
- **提炼基线提交（Commit SHA）**：[`e5c8eaf5f7d24b6609a33956cdff5103fd9e61ad`](https://github.com/anglee0323/agy-switch/commit/e5c8eaf5f7d24b6609a33956cdff5103fd9e61ad)（对应上游版本 `4.10.15`）
- **适用许可证**：[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (`CC-BY-NC-SA-4.0`)](https://creativecommons.org/licenses/by-nc-sa/4.0/) —— 官方完整英文法律文本逐字节原样保留于仓库根目录 [`LICENSE`](LICENSE) 文件中（SHA-256：`6f0afc78b16f446941c6201dcc0a53e1d19dcb96b9fc2ccb497b1bf029aa3512`）。
- **非商业性使用限制（NonCommercial）**：根据 `CC-BY-NC-SA-4.0` 许可条款，对本项目的复制、改编与分发**仅限于非商业目的**。任何商业发行、付费托管服务或企业商业环境使用，均须事先向上游著作权人另行取得书面商业授权；严禁将衍生作品改标为 MIT / Apache-2.0 或宣称无商业使用限制。

---

## 2. 衍生重构范围（`agy-switch` → `agy-switch-cli`）

`agy-switch-cli` 是从混合桌面工程 `agy-switch`（基线 `e5c8eaf5f7d24b6609a33956cdff5103fd9e61ad`）中提炼核心领域知识并面向 **Linux 无头环境（SSH、容器、CI）** 全面重构的独立单包 Rust CLI 工程。

在提炼过程中，彻底剥离并排除了以下桌面端耦合及无效代码：
- `tauri` 框架、GTK / WebKitGTK / X11 / Wayland 图形界面与系统托盘模块；
- 桌面端 IDE 的 `state.vscdb` SQLite 数据库注入与 Protobuf 编解码模块；
- 桌面设备指纹伪造（`DeviceProfile`）与客户端网页脚本注入模块；
- 上游仓库中未挂载进模块树的孤立实验文件（如 `src-tauri/src/cli/agy_session 2.rs`）。

---

## 3. 模块映射与结构性缺陷修复台账

| 上游参考路径（基线 `e5c8eaf5`） | 新工程 `agy-switch-cli` 模块 | 重构内容与关键缺陷修复说明 |
| :--- | :--- | :--- |
| `src-tauri/src/models/{account,token,quota}.rs` | `src/domain/{account,clock,config,token,quota}.rs` | 拆分为带显式 `schema_version: 1` 的无头领域模型（`StoreIndex`、`AccountRecord`、`TokenRecord`、`PendingAuthRecord`、`QuotaObservation`、`HeadlessConfig`、`TransferBundle`）与可注入 `Clock` 抽象；新增结构化禁用原因 `DisableReasonCode`、实际获授权限 `granted_scopes`、两级已轮换 `refresh_token` 指纹台账（`512` 内联摘要 + `65,536` 溢出持久归档）、单调暂存授权序号 `auth_seq` / 账号级授权世代 `auth_generation` 与 `PendingAuthRecord` CAS 指纹、单环境来源 `source_env`/`tier_source_env`；为所有凭据及含密配置手工实现脱敏 `fmt::Debug`。 |
| `src-tauri/src/modules/auto_switch.rs`（校验与 `remaining` 算法） | `src/domain/quota.rs`<br>`src/domain/policy.rs` | 纯函数化提炼四态配额评估 `QuotaEval`（`Known`、`Unknown`、`Stale`、`Unavailable`），完整支持 Argon 独立周池、`-disabled` 模型未知态隔离、同环境 `Free` 层级规则、8 跳模型转发、`reset_time <= now` 判过期（`Stale`）及 `min(weekly, 5h, model_primary)` 共同约束（严禁借共享摘要池把缺失的 `primary` 额度虚标为 `Known`）；将笼统策略报错拆分为逐字段精确提示。 |
| `src-tauri/src/cli/switch_lock.rs` | `src/store/locks.rs` | 重构为类型系统强制单向获取的四级物理/异步资源锁（`L1 → PendingAuthLock → L2 → L3`）：**L1 `ActiveSlotLock`** 统一锁定 `~/.cache/agy-switch-cli/locks/slot-<sha256>.lock`（覆盖跨 `--data-dir` 及 `file`/`dual`/`keyring` 全后端互斥，保持 `~/.gemini/antigravity-cli/` 100% 纯净且永不 `unlink` 锁文件）；**`PendingAuthLock`** 串行协调暂存授权记录全生命周期；**L2 `with_account_refresh_lock`** 强制绑定异步作用域并串行化单账号刷新/导入/重授权；**L3 `with_store_write_lock`** 仅暴露同步闭包接口，从编译期根除跨 `.await` 持锁。 |
| `src-tauri/src/utils/fs.rs`<br>`src-tauri/src/modules/cli_credentials.rs` | `src/store/fs_atomic.rs`<br>`src/session/{backend,payload,journal}.rs` | 统一提供全深度祖先 `lstat` 核验、父目录 `O_PATH \| O_DIRECTORY \| O_NOFOLLOW` 句柄/`inode` 锚定与 `O_NOFOLLOW \| O_NONBLOCK` 非阻塞普通文件有界读取（拒绝任意层符号链接与 FIFO 阻塞）；修复非法 `expiry_timestamp` 静默回退缺陷；实现文件与父目录双 `fsync` 及回读校验；提供 `auto`、`dual`、`file`、`keyring` 四种清晰凭据后端模式；引入校验实时多副本摘要 CAS 的 `switch_journal.json` 对账协议，准确区分退出码 `0`、`5`、`7`，保护有效外部漂移槽位且严禁回滚已轮换的新 `refresh_token`。 |
| `src-tauri/src/modules/{account,migration}.rs` | `src/store/{repository,transfer}.rs` | 采用独立数据目录（`~/.local/share/agy-switch-cli`），增加旧桌面版目录防误写保护、只读迁移 `--from-legacy`、默认跳过重复账号的导入保护（显式 `--overwrite` 亦在 `L2` 锁内校验内联与 `state/token_lineage/` 归档指纹，暂存授权多轮轮换中间指纹持久记录于 `state/pending_lineage/` 并随绑定合并，归档截断时按故障关闭拒绝无法证明安全的覆盖）、删除账号同步清理策略与归档文件，以及强制 `--include-secrets` 与 `0600` 权限的私有导出。 |
| `src-tauri/src/constants.rs`<br>`src-tauri/src/utils/{http,proxy}.rs` | `src/transport/{client,proxy,user_agent}.rs` | 定义 `HttpTransport` Trait（`HttpRequest` Debug 清除 URL 查询串/片段/认证信息）与离线确定性 `MockTransport`；重构无头代理路由（支持 `--proxy`、`config.json`、标准代理环境变量、`socks5h://` 远程 DNS，并基于 `url::Host` 精确识别真实 Loopback 直连）；采用真实 `compare_semver` 计算 UA 版本上界。 |
| `src-tauri/src/modules/{oauth,oauth_server}.rs` | `src/oauth/{registry,flow,refresh}.rs` | 补齐带 RFC 7636 PKCE（`S256`）与单值 `state` 严格校验的 `auth login` / `auth reauthorize`；所有 `/token` 入口（`refresh`、`accounts add`、`auth login`、`auth reauthorize`、`auth pending --resume`）均在辅助 `userinfo` 前立即持久化新令牌，并通过 `PendingAuthLock`、单调 `auth_seq` / 账号 `auth_generation` 双重世代校验（`L2` 获取后 + `L3` 提交前）及 `L3` 指纹 CAS（`verify_pending_auth_cas` / `remove_pending_auth_cas`）杜绝同 ID 或跨 ID 忙锁恢复旧快照覆盖新令牌；严格执行 RFC 6749 Client 绑定、OAuth 错误码白名单脱敏、并发 `Manual` 禁用保留及状态落盘 I/O 错误显式传播。 |
| `src-tauri/src/modules/quota.rs` | `src/quota/{client,fusion}.rs`<br>`src/transport/user_agent.rs` | 建立对齐官方客户端的单环境隔离配额观测链路（`Daily → Sandbox → Production` 优先序 + `antigravity/hub/<ver>` 请求标识，并对仅含 `3p` 池的残缺摘要执行不跨环境拼接的降级兜底，严禁跨环境复用 `Free` 层级或摘要池）；打通全部三类端点 HTTP 401 单次受锁强刷闭环；优先保留 `ACCESS_TOKEN_SCOPE_INSUFFICIENT` 与 `VALIDATION_REQUIRED` 账户级阻断证据，拒绝将混合瞬态故障 `[503, 503, 403]` 误判为永久 Forbidden。 |
| `src-tauri/src/modules/auto_switch.rs` | `src/switching/{executor,runner,daemon,systemd}.rs` | 新增受管包装器 `run -- agy` 及双因子进程租约（`pid + starttime`，`/proc` 不可读时按故障关闭判 `Unverified`）；手动 `switch`/`tui` 默认在已核验 `agy` 运行态下即时更新槽位并输出非阻断提示（保留 `--require-idle` 严格空闲校验与 `Unverified` 故障关闭）；重构前台七阶段 `daemon` 状态机，在 `Observe/Evaluate` 捕获决策版本快照、在 `L1` 锁内按真实提交时刻重验 `reset`/时效、`--once` 与常驻共享 `SIGINT`/`SIGTERM` 优雅停机保护，并提供带沙盒安全转义与防符号链接保护的 `daemon --install` / `--uninstall` 用户级 `systemd` 服务管理。 |
| `src-tauri/src/cli/{mod,output,picker}.rs` | `src/main.rs`<br>`src/cli/{args,secret_input,dto,commands}.rs`<br>`src/tui/mod.rs` | 基于 `args_os` 拦截非 UTF-8 参数防启动 panic 泄密，对环境变量选项设置 `hide_env_values` 防 `--help` 回显；规范化全命令长选项参数并移除明文 Token 位置参数，选择器形态校验且不回显原文，JSON 反序列化错误仅报行列类型；只读 `status` 如实暴露 `daemon_state` 异常与本机 `agy` 版本状态；基于 `libc::termios` + 信号处理器实现无回显输入；严格分离交互提示与 `--json` 机器协议；`tui` 支持 `↑/↓` 选行、`[/]` 调序、`x`+`y` 事务删号并集成外部 `SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT` 终端回显恢复。 |
| `src-tauri/src/modules/native_token_stats.rs`（参考上游 `v4.10.17` `1f8085e`） | `src/stats/{mod,readonly_vfs}.rs` | 重构为纯离线零写入的 `stats summary` 与 `stats list` 子命令模块：基于 `HeadlessPaths.home_dir` 绝对路径自顶向下通过 `openat` 绑定受信任目录句柄，实现自定义零写入 SQLite VFS（`"agy_pinned_ro"`），使主库、`-wal`、`-shm` 与 `-journal` 全程受同一目录句柄、普通文件类型与非阻塞检查约束（且仅凭真实 Linux OFD 锁才启用可靠共享内存读锁分支，无 OFD 支持时自动回退堆索引并复验主库及伴生文件的目录项、文件身份与元数据，同时比较主库、`-wal` 与 `-journal` 的有限文件头，不比较 `-shm` 内容），在关闭态或活跃态 WAL 库上均保持源目录零伴生文件创建与零字节写入；采用锁步流式游标、索引归档点查（`O(1)` 描述符占用）与异常无索引表行预算降级保护，并在 SQL 层按字节长度预拦截超大记录；支持 `--source all\|cli\|app`（默认 `all`）有效归档优先与实时库回退去重、逐片段独立 Protobuf 帧校验、基于已知公共模型 ID 与家族受限语法的归一化过滤（放行符合命名规范的已知家族标签，其余非公开文本一律回退 `"Unknown"`）、统一口径的流式 `TTFT`/`TPS`（`P10/P50/P90`，严格要求已完成步骤 `status = 3`、合法帧结构与零重试退避，兼容含工具调用与常规流式回复）、十列最近调用明细（极窄终端自动切换紧凑多行块以免截断 `TPS`/`St`）及宽窄终端自适应排版，共享 `--recent <N>`、`--range <today\|yesterday\|<N>d\|all>`、`--date`、`--from` 四组互斥窗口。 |
| `tests/fixtures/quota-pool-cases.json` | `tests/fixtures/quota-pool-cases.json` | 迁移并扩展配额池分类与边界回归测试夹具。 |

---

## 4. 第三方依赖许可证与分发义务说明

本项目本身遵循 [`CC-BY-NC-SA-4.0`](LICENSE)。`Cargo.lock` 锁定的全部第三方 Rust 依赖库（覆盖 `x86_64-unknown-linux-gnu`、`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-gnu`、`aarch64-unknown-linux-musl` 四个目标及全部特性档）均采用与无头源码/二进制非商业分发兼容的开源许可证，并已通过本机 `cargo-deny 0.21.0`（`cargo deny check advisories bans licenses sources`）实测核验（详见 [`deny.toml`](deny.toml) 及 [`.github/workflows/ci.yml`](.github/workflows/ci.yml) 中的自动化门禁作业）：

- **密码学与 TLS 组件**：`ring 0.17.14`（原生 SPDX：`Apache-2.0 AND ISC`，包含源自 BoringSSL 与 Fiat-Crypto 的 Apache-2.0 / ISC / MIT 许可代码与版权声明）、`rustls 0.23`（`Apache-2.0 OR ISC OR MIT`）、`rustls-webpki`（`ISC`）。
- **异步运行时、HTTP 与命令行基础库**：`tokio`（`MIT`）、`reqwest`（`MIT OR Apache-2.0`）、`clap`（`MIT OR Apache-2.0`）、`serde` / `serde_json`（`MIT OR Apache-2.0`）、`jiff`（`MIT OR Unlicense`）、`url`（`MIT OR Apache-2.0`）、`uuid`（`Apache-2.0 OR MIT`）。
- **默认内置与可选特性依赖说明**：`rusqlite` / `libsqlite3-sys`（`MIT`，内嵌公共领域 SQLite3 C 源码）、`crossterm`（`MIT`）、`comfy-table`（`MIT`）、`unicode-width`（`MIT OR Apache-2.0`）、`unicode-segmentation`（`MIT OR Apache-2.0`）、`secret-service 5.2.0` / `zbus 5.19.0`（`MIT` / `Apache-2.0 OR MIT`）。默认特性 `default = ["tui", "stats", "secret-service-backend"]` 将上述纯 Rust / 内嵌 C 组件统一打包进标准发行版（同时保留 `--no-default-features` 最小纯 Rust 构建）；其中 `secret-service 5.2.0`（当前最新稳定版；`6.0` 尚处 RC 阶段）经 `zbus 5.19.0` 传递引入的 `zvariant`、`zbus_names`、`zvariant_derive` 存在 3 条架构合并类 `unmaintained` 提示（`RUSTSEC-2026-0370`/`0371`/`0372`，因相关子包已并入 `zbus 6.0`，并非安全漏洞），已在 [`deny.toml`](deny.toml) 中逐条注明豁免原因，待 `secret-service 6.0` 稳定发布后升级移除。

**二进制发布包合规清单**：每次公开发布预编译产物时，压缩包内须同时附带根目录 [`LICENSE`](LICENSE)（SHA-256：`6f0afc78b16f446941c6201dcc0a53e1d19dcb96b9fc2ccb497b1bf029aa3512`）、本文件 [`PROVENANCE.md`](PROVENANCE.md)、第三方依赖完整版权与许可证全文（`THIRD_PARTY_NOTICES.txt`）、对应的 Git Commit SHA 以及各平台产物文件的 SHA-256 校验值。
