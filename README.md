# `agy-switch-cli`

面向 **Linux 无头环境（SSH 服务器、Docker 容器、WSL2、CI）** 的官方 Antigravity CLI（`agy`）多账号管理、配额巡检与自动/手动凭据切换工具。

> [!IMPORTANT]
> **开源许可证与非商业使用声明（`CC-BY-NC-SA-4.0`）**  
> 本项目基于上游 [`agy-switch`](https://github.com/anglee0323/agy-switch)（基线提交 [`e5c8eaf5`](https://github.com/anglee0323/agy-switch/commit/e5c8eaf5f7d24b6609a33956cdff5103fd9e61ad)，v4.10.15）独立重构衍生，遵循 **`CC-BY-NC-SA-4.0`（署名-非商业性使用-相同方式共享 4.0）**。复制、修改与再分发**仅限非商业用途**；商业场景使用须事先取得上游著作权人书面授权。详见 [`LICENSE`](LICENSE) 与 [`PROVENANCE.md`](PROVENANCE.md)。

---

## 核心特性

- **纯无头零桌面依赖**：彻底剥离 Tauri / GTK / WebKit，预编译 `musl` 产物为 **100% 纯静态单文件 ELF**，在各类 `x86_64` 与 `aarch64` Linux 发行版上开箱即用。
- **无浏览器 OAuth 登录与零丢码保护**：支持 SSH 端口转发或 `--manual` 手动粘贴回调 URL 登录；令牌签发后立即以 `0600` 权限落盘并建立两级防回退指纹库，网络中断可通过 `auth pending --resume` 无损续传。
- **安全的受管启动与后台自动切号**：
  - *重要事实*：切换凭据槽位默认**对切换后新启动的 `agy` 进程生效**，不会篡改或打断正在运行中的 `agy` 会话。
  - 推荐使用 `agy-switch-cli run -- agy` 启动前自动评估配额并切号，或配合 `systemd --user` 运行 `daemon` 前台守护进程与 `tui` 终端看板。

---

## 安装

### 方式一：下载预编译纯静态二进制（推荐）

前往 Releases 页面下载对应架构的 `.tar.gz` 包（大多数服务器 / 容器 / WSL2 用户下载**不带 `-all-features` 的标准版**即可；若在开启了 GNOME Keyring / KWallet 的 Linux 图形桌面终端里直接裸敲 `agy`，可选 `-all-features` 版配合 `--backend secret-service` 使用）：

```bash
sha256sum -c agy-switch-cli-v1.0.0-x86_64-unknown-linux-musl.tar.gz.sha256
tar -xzf agy-switch-cli-v1.0.0-x86_64-unknown-linux-musl.tar.gz
mkdir -p ~/.local/bin
install -m 0755 agy-switch-cli-v1.0.0-x86_64-unknown-linux-musl/agy-switch-cli ~/.local/bin/agy-switch-cli
```

### 方式二：从源码编译（要求 Linux + `rustc >= 1.89`）

```bash
cargo build --release --locked
install -m 0755 target/release/agy-switch-cli ~/.local/bin/agy-switch-cli
```

---

## 五分钟快速上手

```bash
# 1. 环境体检与官方 agy 版本探测
agy-switch-cli doctor --verify-agy

# 2. 登录添加账号（纯远程服务器可加 --manual 手动粘贴回调 URL）
agy-switch-cli auth login --manual --label "主力账号"
# 或从原桌面版 ~/.antigravity_tools 只读迁移已有账号（不修改原目录）：
# agy-switch-cli accounts import --from-legacy

# 3. 联网拉取所有账号的实时 CloudCode 配额
agy-switch-cli refresh --all

# 4. 查看当前身份状态与缓存配额
agy-switch-cli status
agy-switch-cli quota --all

# 5. 【推荐】使用受管包装模式启动官方 agy（低配额时启动前自动切号）
agy-switch-cli run -- agy
```

---

## 常用命令速查

| 命令                                                   | 用途说明                                                                           |
|:------------------------------------------------------ |:---------------------------------------------------------------------------------- |
| `agy-switch-cli doctor [--fix]`                        | 诊断本地存储、权限、D-Bus 环境，并对账修复未完成的切换日志                         |
| `agy-switch-cli auth login [--manual]`                 | 通过 PKCE (`S256`) 添加新 Google 账号（重新授权用 `auth reauthorize <ID\|EMAIL>`） |
| `agy-switch-cli accounts list / add / import / export` | 管理账号池（安全输入 Refresh Token、导入导出加密权限备份包）                       |
| `agy-switch-cli status` / `quota --all`                | 只读查看三重身份状态与本地配额缓存（联网更新用 `refresh --all`）                   |
| `agy-switch-cli switch <ID\|EMAIL>`                    | 手动切换当前生效账号（对后续新启动的 `agy` 进程生效）                              |
| `agy-switch-cli run [--isolate-dbus] -- agy ...`       | 启动前按策略自动选号并登记双因子进程租约                                           |
| `agy-switch-cli policy set ...` / `daemon`             | 配置自动切号水位策略与运行前台自动切号守护进程                                     |
| `agy-switch-cli tui`                                   | 打开 SSH 交互式终端实时监控看板                                                    |

*(所有业务子命令均支持 `--json` 机器可读输出与 `0..=8` 稳定退出码。)*

---

## 详细文档导航

- **[完整使用、配置与部署手册 (`docs/user-guide.md`)](docs/user-guide.md)**：标准版与全特性版选型实例、全量命令与退出码参考、`config.json` 代理配置、`systemd --user` 部署及常见故障排查。
- **[技术架构、安全机制与验收台账 (`docs/architecture-and-verification.md`)](docs/architecture-and-verification.md)**：目录拓扑、四级单向锁与授权世代防回退设计、4 目标 × 3 档 Release 体积/性能矩阵及诚实验收边界说明。
- **[重构溯源与第三方合规声明 (`PROVENANCE.md`)](PROVENANCE.md)** ＆ **[许可证全文 (`LICENSE`)](LICENSE)**。

---

## 致谢

- **上游项目致谢**：感谢 [`anglee0323/agy-switch`](https://github.com/anglee0323/agy-switch) 及其贡献者提供的原始领域探索与桌面端参考实现。
- **AI 协同研发与独立安全审查致谢**：
  - **Gemini 4 Carbon**：负责本项目的独立无头架构重构、四级锁与防回退核心代码实现、全套自动化测试矩阵、跨架构纯静态构建及全中文工程文档编写；
  - **GPT 6.1 Sol**：担任独立第三方首席发版签核审计师，对本项目执行了四轮零信任源码深审、并发交错与故障注入探针验证及合规放行签核；
  - 由项目维护者提供需求定义、构建验证环境与全流程统筹把关。
