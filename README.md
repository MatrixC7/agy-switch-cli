# `agy-switch-cli`

面向 **Linux 无头环境（SSH 服务器、Docker 容器、WSL2、CI）** 的官方 Antigravity CLI（`agy`）多账号管理、配额巡检与自动/手动凭据切换工具。

> [!IMPORTANT]
> **开源许可证与非商业使用声明（`CC-BY-NC-SA-4.0`）**  
> 本项目基于上游 [`agy-switch`](https://github.com/anglee0323/agy-switch)（基线提交 [`e5c8eaf5`](https://github.com/anglee0323/agy-switch/commit/e5c8eaf5f7d24b6609a33956cdff5103fd9e61ad)，v4.10.15）独立重构衍生，遵循 **`CC-BY-NC-SA-4.0`（署名-非商业性使用-相同方式共享 4.0）**。复制、修改与再分发**仅限非商业用途**；商业场景使用须事先取得上游著作权人书面授权。详见 [`LICENSE`](LICENSE) 与 [`PROVENANCE.md`](PROVENANCE.md)。

---

## 核心特性

- **纯静态单包全特性开箱即用**：彻底剥离 Tauri / GTK / WebKit，每个架构仅提供**单一完整预编译 `musl` 压缩包**（100% 纯静态单文件 ELF，零外部 `.so` 依赖），同时内置全部 CLI 命令、本地用量统计 `stats`、SSH 交互式看板 `tui` 与纯 Rust D-Bus 系统钥匙串协议栈；默认 `--backend auto` 在无头服务器自动使用本地文件模式（`file`），在 Linux 图形桌面自动启用钥匙串与文件事务性双写（`dual`），亦支持显式指定 `file`、`keyring` 或 `dual`。
- **无浏览器 OAuth 登录与零丢码保护**：默认免端口监听直接粘贴回调 URL 登录（亦可加 `--ssh` 开启本地端口转发回调）；令牌签发后立即以 `0600` 权限落盘并建立两级防回退指纹库，网络中断可通过 `auth pending --resume` 无损续传。
- **灵活的手动与自动切号方式**：
  - *重要事实*：切换凭据槽位**对切换后新启动的 `agy` 进程立即生效**，已运行中的旧 `agy` 会话保持启动时的登录态而不被打断。
  - 既可通过 `tui` 终端看板或 `switch` 随时切号后直接运行 `agy`，也可通过 `daemon --install` 一键配置 `systemd --user` 后台巡检服务（或使用可选的 `agy-switch-cli run` 指定 `--account` / `--backend file` 包装启动 `agy`）。

---

## 安装

### 方式一：下载预编译纯静态二进制（推荐）

可直接在终端按当前 CPU 架构（`uname -m` 自动输出 `x86_64` 或 `aarch64`）从 Releases 下载对应的 `.tar.gz` 压缩包与校验文件（也可在浏览器访问 Releases 页面手动下载），无论在远程 SSH 服务器、Docker 容器、WSL2 还是开启了 GNOME Keyring / KDE Wallet 的 Linux 图形桌面上均可直接使用：

```bash
VER=v1.2.6
ARCH="$(uname -m)"   # x86_64 或 aarch64
curl -fLO "https://github.com/MatrixC7/agy-switch-cli/releases/download/${VER}/agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz"
curl -fLO "https://github.com/MatrixC7/agy-switch-cli/releases/download/${VER}/agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz.sha256"

sha256sum -c "agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz.sha256"
tar -xzf "agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl.tar.gz"
mkdir -p ~/.local/bin
install -m 0755 "agy-switch-cli-${VER}-${ARCH}-unknown-linux-musl/agy-switch-cli" ~/.local/bin/agy-switch-cli
```

### 方式二：Arch Linux / EndeavourOS 等 Arch 系发行版（AUR）

已发布 AUR 二进制包 `agy-switch-cli-bin`（直接复用本仓库 Releases 中的纯静态全功能预编译包，安装至 `/usr/bin/agy-switch-cli`，可随系统更新一并升级）：

```bash
yay -S agy-switch-cli-bin
# 或使用 paru：
# paru -S agy-switch-cli-bin
```

### 方式三：从源码编译（要求 Linux + `rustc >= 1.89`）

```bash
cargo build --release --locked
install -m 0755 target/release/agy-switch-cli ~/.local/bin/agy-switch-cli
```

---

## 五分钟快速上手

```bash
# 1. 环境状态只读巡检与官方 agy 版本自动探测
agy-switch-cli status

# 2. 登录添加账号（默认零配置手动粘贴回调 URL；如需本地监听可加 --ssh）
agy-switch-cli auth login --label "primary"
# 若本机官方 agy 已登录（或桌面端与 agy 在系统钥匙串中共用登录条目），也可读取当前 agy 凭据入库（不读取桌面端独立的 jetski-standalone-oauth-token 回退文件）：
# agy-switch-cli accounts add --from-local --label "local"
# 或从原桌面版 ~/.antigravity_tools 只读迁移已有账号（不修改原目录）：
# agy-switch-cli accounts import --from-legacy

# 3. 联网流式刷新（实时打印 [k/N] 进度）并查看所有账号的最新配额进度表
agy-switch-cli quota --refresh --all

# 4. 查看当前生效账号、运行状态与该账号支持的全部模型列表
agy-switch-cli current

# 5. 打开交互式看板管理与切号，之后直接运行 agy 即可（也可用可选的 `agy-switch-cli run` 指定账号或 `file` 后端包装启动）
agy-switch-cli tui
```

*(网络代理提示：Linux 图形界面的“系统代理”不会自动注入终端环境。若需走代理连接 Google，单次命令可加 `--proxy http://127.0.0.1:7890`，当前终端免重复传参可执行 `export https_proxy=http://127.0.0.1:7890`，需要跨终端与后台 `daemon` 持久生效则将其写入 `~/.local/share/agy-switch-cli/config.json`，详见使用手册第 6 节。)*

---

## 常用命令速查

| 命令                                                   | 用途说明                                                                           |
|:------------------------------------------------------ |:---------------------------------------------------------------------------------- |
| `agy-switch-cli status`                                | 只读巡检生效后端、本地仓库、事务日志、槽位初始化、守护进程运行/服务状态、本机官方 `agy` 与已安装桌面端 Antigravity App 版本 |
| `agy-switch-cli auth login [--ssh]`                    | 通过 PKCE (`S256`) 添加新 Google 账号（默认粘贴回调 URL；重新授权用 `reauthorize`） |
| `agy-switch-cli accounts list / add / import / export` | 查看账号详情与排序（`--move`/`--order`）、导入本机或外部目标目录已登录号（`--from-local [--target \| --target-dir]`）或文件/标准输入 Token（`--from-file`/`--from-stdin`）、导入导出备份 |
| `agy-switch-cli current [--target \| --target-dir]`     | 查看当前生效身份、运行中进程状态及该账号支持的全部模型清单（可选指向外部目标应用数据目录） |
| `agy-switch-cli quota [--refresh] [--all \| --target \| --target-dir]` | 查看双窗口（`Weekly` + `5h`）配额进度表（加 `--refresh` 先流式联网刷新再展示；支持直接查询外部目标目录及未入池游离文件） |
| `agy-switch-cli refresh [--all \| --target \| --target-dir]` | 批量流式联网刷新账号 OAuth 令牌与远端配额（终端实时输出 `[k/N]` 进度），或刷新并回写指定外部目标目录 |
| `agy-switch-cli stats summary / list [--watch] [--target \| --target-dir]` | 纯本地只读聚合模型 Token 用量与 `TTFT`/`TPS` 分位统计（`summary`），或列出最近请求明细（`list`），支持 `--watch [秒数]` 实时看板刷新（按 `Tab` 切换视图）与外部目标目录统计 |
| `agy-switch-cli switch <ID\|EMAIL> [--target \| --target-dir]` | 手动切换生效账号（默认 `auto` 自动适配无头 `file` 与桌面钥匙串 `dual` 双写；加 `--target` / `--target-dir` 可独立切写外部目标目录而不影响官方槽与 `daemon`） |
| `agy-switch-cli policy set --all-candidates ...`       | 配置自动切号水位策略（默认 `reserve = 10%`、`minimum = 30%`，配合 `daemon` 后台自动巡检切号） |
| `agy-switch-cli daemon [--install \| --uninstall \| --reset-cooldown]` | 运行后台自动切号守护进程（默认每 `180` 秒巡检、切号冷却 `3600` 秒；支持 `--reset-cooldown` 主动解除冷却期；桌面切号/熔断通知默认常驻，可在 `config.json` 调整或用 `--no-notify` 关闭，无头环境自动静默），或安装/卸载 `systemd --user` 服务 |
| `agy-switch-cli [--backend file] run [--account ...] -- agy ...` | 可选方式：按指定账号或指定后端包装启动 `agy`；显式启用 `file` 后端时自动为子进程屏蔽桌面 D-Bus 钥匙串 |
| `agy-switch-cli tui`                                   | 打开 SSH 交互式终端看板（支持 `↑/↓` 与 `g/G` 浏览、`Space` 多选联动、`[/]` 调序、`i` 可滚动详情/重置倒计时、`r/R` 刷新、`c/C/p` 策略、`k` 清冷却、`e/E` 与 `d/D` 启停、`l` 改备注、`o/O` `0600` 导出与 `x`+`y` 删号） |

**关于 `--json` 机器输出与 `0..=8` 稳定退出码的边界说明**：
- 全屏交互看板 `tui` 与实时刷新模式 `stats ... --watch` 均与 `--json` 互斥并返回退出码 `2`。
- 可选包装器 `run` 在前置准备失败时向 `stderr` 输出错误信封，就绪后直接继承子进程标准输入输出并透传其退出码。
- `daemon --install --json`、`daemon --uninstall --json`、`daemon --reset-cooldown --json` 与单轮 `daemon --once --json` 向 `stdout` 输出标准 `schema_version: 1` JSON 信封（单轮被外部信号提前取消时静默返回 `0`）；常驻 `daemon --json` 正常轮次保持静默，仅在启动、策略、锁或运行期致命错误时向 `stderr` 输出错误信封。
- 其余子命令均按 `schema_version: 1` 契约向 `stdout` 输出标准 JSON 信封。

---

## 详细文档导航

- **[完整使用、配置与部署手册 (`docs/user-guide.md`)](docs/user-guide.md)**：安装指南、四种凭据后端（`auto`/`dual`/`file`/`keyring`）、全量命令与退出码参考、`config.json` 代理与自定义 OAuth 客户端配置、`daemon --install` 与容器常驻方案、常见问题排查及完整卸载清单。
- **[技术架构、安全机制与验收台账 (`docs/architecture-and-verification.md`)](docs/architecture-and-verification.md)**：目录拓扑、四级单向锁与授权世代防回退设计、跨架构 Release 体积/性能矩阵及诚实验收边界说明。
- **[重构溯源与第三方合规声明 (`PROVENANCE.md`)](PROVENANCE.md)** ＆ **[许可证全文 (`LICENSE`)](LICENSE)**。

---

## 卸载与本地残留清理

如需卸载本工具，建议按“停服务 → 删程序 → 清理自有数据目录”三步操作：

```bash
# 1. 如曾安装后台定时服务，先停用并移除 systemd user unit
agy-switch-cli daemon --uninstall

# 2. 按安装方式卸载可执行文件（二选一）
rm -f ~/.local/bin/agy-switch-cli    # 手动解压或源码编译安装
# yay -Rns agy-switch-cli-bin        # AUR 安装（或使用 paru / sudo pacman -Rns）

# 3. 按需清理本工具自有的本地数据、锁与缓存目录（不会影响官方 ~/.gemini 目录）
rm -rf ~/.local/share/agy-switch-cli ~/.cache/agy-switch-cli ~/.local/state/agy-switch-cli
```

完整目录清单、系统钥匙串及避免误删官方 `~/.gemini` 凭据的详细说明见[完整使用手册第 9 节](docs/user-guide.md#9-完整卸载与本地遗留文件清理清单)。

---

## 致谢

- **上游项目致谢**：感谢 [`anglee0323/agy-switch`](https://github.com/anglee0323/agy-switch) 及其贡献者提供的原始领域探索与桌面端参考实现。
- **AI 协同研发与独立安全审查致谢**：
  - **Gemini 4 Carbon/Neon**：负责本项目的独立无头架构重构、四级锁与防回退核心代码实现、全套自动化测试矩阵、跨架构纯静态构建及全中文工程文档编写；
  - **GPT 6.1 Sol/6.2 Sol**：担任独立第三方首席发版签核审计师，对本项目执行了多轮零信任源码深审、并发交错与故障注入探针验证及合规放行签核；
  - 由项目维护者提供需求定义、构建验证环境与全流程统筹把关。
