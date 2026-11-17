# `agy-switch-cli` 完整使用、配置与部署手册

> 返回首页：[README.md](../README.md) ｜ 技术架构与验收台账：[architecture-and-verification.md](architecture-and-verification.md)

本手册面向所有用户（包括刚开始接触 Linux 命令行的朋友），将每一个核心概念、每一条命令和每一个参数选项逐一拆解说明，不省略中间步骤。手册中的所有示例均使用虚构占位邮箱（如 `alice@example.com`），方便直接对照参考。

---

## 目录

1. [版本选型与安装指南（按步操作）](#1-版本选型与安装指南按步操作)
2. [上手前必读：四个核心概念](#2-上手前必读四个核心概念)
3. [全局选项与环境变量](#3-全局选项与环境变量)
4. [全量命令与参数详解](#4-全量命令与参数详解)
   - [4.1 环境体检与自动修复：`doctor`](#41-环境体检与自动修复doctor)
   - [4.2 登录与 OAuth 授权管理：`auth`（默认免配置粘贴登录）](#42-登录与-oauth-授权管理auth默认免配置粘贴登录)
   - [4.3 账号池管理、批量导入与排序：`accounts`](#43-账号池管理批量导入与排序accounts)
   - [4.4 查看当前身份/可用模型与手动切号：`current` / `switch`](#44-查看当前身份可用模型与手动切号current--switch)
   - [4.5 配额查询与联网刷新：`quota` / `refresh`](#45-配额查询与联网刷新quota--refresh)
   - [4.6 自动切号规则配置：`policy`（设定规则）](#46-自动切号规则配置policy设定规则)
   - [4.7 受管启动包装器：`run`（按需触发自动切号，免后台轮询）](#47-受管启动包装器run按需触发自动切号免后台轮询)
   - [4.8 后台自动切号守护进程：`daemon`（定时巡检触发）](#48-后台自动切号守护进程daemon定时巡检触发)
   - [4.9 SSH 交互式终端看板：`tui`（全键盘可视化操作）](#49-ssh-交互式终端看板tui全键盘可视化操作)
5. [标准退出码（`0..=8`）与 `--json` 脚本集成契约](#5-标准退出码08与---json-脚本集成契约)
6. [可选配置文件（`config.json` 网络代理与自定义客户端）](#6-可选配置文件configjson-网络代理与自定义客户端)
7. [后台常驻部署（`systemd --user` 与 Docker 容器）](#7-后台常驻部署systemd---user-与-docker-容器)
8. [常见问题解答（FAQ）](#8-常见问题解答faq)

---

## 1. 版本选型与安装指南（按步操作）

### 1.1 选择合适的预编译压缩包（标准版 vs `-all-features` 全特性版）

在 GitHub Releases 发布页中，提供了按 **CPU 架构**（常见电脑与云服务器为 `x86_64`，树莓派与 ARM 云服务器为 `aarch64`，可在终端输入 `uname -m` 确认）以及 **是否带 `-all-features` 后缀** 区分的 4 个压缩包。它们均为 **100% 纯静态单文件程序**，解压即可运行，不依赖系统动态库。

两者的唯一区别在于**是否支持同步修改 Linux 图形桌面的系统钥匙串（Keyring）**：

| 对比维度 | 标准版（文件名不带 `-all-features`） | 全特性版（文件名带 `-all-features`） |
| :--- | :--- | :--- |
| **包含功能** | 全部 CLI 命令 + SSH 交互式终端看板 `tui` | 标准版全部功能 + **Linux 桌面系统钥匙串（GNOME Keyring / KDE Wallet）双写同步** |
| **支持的 `--backend`** | `file`（默认，仅读写 `~/.gemini/antigravity-cli/antigravity-oauth-token` 文件） | `file`（默认）**或** `secret-service`（同时更新系统钥匙串与凭据文件，失败自动回滚） |
| **适用人群** | **绝大多数场景首选**：远程 SSH 服务器、Docker 容器、Windows WSL2，以及在桌面上使用 `run --isolate-dbus` 启动 `agy` 的用户 | 在带有图形界面的 Linux 桌面上使用，且习惯在终端里**直接裸敲 `agy`**（不加任何包装前缀）的用户 |

### 1.2 下载、校验与安装步骤

假设你下载的是 `x86_64` 标准版（新版本发布时请将文件名中的版本号替换为实际下载的版本号）：

```bash
# 第 1 步：校验压缩包完整性（输出显示成功 / OK 即可）
sha256sum -c agy-switch-cli-v1.1.0-x86_64-unknown-linux-musl.tar.gz.sha256

# 第 2 步：解压压缩包
tar -xzf agy-switch-cli-v1.1.0-x86_64-unknown-linux-musl.tar.gz

# 第 3 步：安装到当前用户的可执行目录 ~/.local/bin（无需 sudo 权限）
mkdir -p ~/.local/bin
install -m 0755 agy-switch-cli-v1.1.0-x86_64-unknown-linux-musl/agy-switch-cli ~/.local/bin/agy-switch-cli
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
cargo build --release --locked                                       # 默认构建（核心 CLI + tui 看板）
cargo build --release --locked --no-default-features                 # 极简构建（移除 tui 依赖）
cargo build --release --locked --all-features                        # 全特性构建（含 secret-service 钥匙串后端）
cargo build --release --locked --target x86_64-unknown-linux-musl    # 纯静态 musl 构建
```

---

## 2. 上手前必读：四个核心概念

1. **如何在命令中指定账号（`<ID|EMAIL>`）？**  
   为防止排序变动或账号增删导致命令行序号漂移误触其他账号，所有命令行子命令统一采用与账号终身绑定的精确标识：
   - **直接输入邮箱**（如 `alice@example.com`，不区分大小写，直观且安全）；
   - **输入内部账号 ID**（如 `acc-0001...`，可通过 `accounts list` 查看，用于区分极少数同邮箱重复记录）。  
   如果你不想在命令行手动输入邮箱，可以直接运行 `agy-switch-cli tui` 打开可视化交互看板，通过上下方向键高亮选中账号后一键完成切号、调序、启停与候选池配置。
2. **切换账号后什么时候生效？**  
   执行切号更新的是磁盘上的官方凭据槽位文件（`~/.gemini/antigravity-cli/antigravity-oauth-token`）。
   - 它对**切换完成之后新启动的 `agy` 命令**立即生效；
   - 它**不会中途篡改或强行打断另一个终端窗口里正在运行的 `agy`**，从而保证正在执行的任务不受影响。
3. **配额池（`Gemini` vs `Claude / GPT`）与双窗口（`Weekly` 周额度 vs `5h` 五小时额度）**：  
   Google Antigravity 的额度按**配额池**共享计算：
   - **`Gemini` 池**：常规 Gemini 系列模型共用；
   - **`Claude / GPT` 池**：Claude Sonnet / Opus 与 GPT-OSS 等模型共用；
   - **`Argon` 池**：仅部分灰度测试账号才会被下发。普通商业订阅账号没有该池，`tui` 和 `quota` 会默认将其隐藏，属于正常现象。  
   每个配额池同时受 **`Weekly`（7 天滚动周总额度）** 和 **`5h`（5 小时短期防刷窗口）** 限制，任意一个窗口降为 `0%` 都会触发限流，因此工具会同时展示这两个窗口。
4. **“1 小时配额缓存保鲜期（`stale`）”机制**：  
   为避免高频请求触发 Google 服务端风控，本地配额缓存的默认保鲜期设为 **`1 小时（3600 秒）`**：
   - 距离上次刷新 **1 小时以内**（且未跨过重置时间点），缓存状态为 `known`（新鲜有效），自动切号无需重复请求网络；
   - 超过 **1 小时**后，缓存标为 `stale`。此时手动运行 `agy-switch-cli quota` **依然会正常展示上次缓存的进度表**，并在状态行温和提示可加 `-r`（`agy-switch-cli quota -r`）联网更新；而自动切号功能（`run` 和 `daemon`）遇到 `stale` 时会先自动联网刷新一次最新额度，再决定是否切号。

---

## 3. 全局选项与环境变量

以下全局选项可加在任意子命令之前或之后（日常使用保持默认即可，无需填写）：

| 全局选项 | 对应环境变量 | 默认行为与通俗说明 |
| :--- | :--- | :--- |
| `--data-dir <目录路径>` | `AGY_SWITCH_CLI_DATA_DIR` | 指定账号库存储目录。默认位于 `~/.local/share/agy-switch-cli`（目录权限自动设为 `0700`）。 |
| `--proxy <代理地址\|direct>` | `AGY_SWITCH_CLI_PROXY` | 指定访问 Google 的网络代理，如 `--proxy socks5h://127.0.0.1:1080` 或 `--proxy http://127.0.0.1:7890`；填 `direct` 表示强制直连。不填时自动读取 `config.json` 或系统 `HTTPS_PROXY` / `ALL_PROXY`。 |
| `--backend <file\|secret-service>` | — | 默认为 `file`；安装了 `-all-features` 版且需要同步更新 Linux 桌面钥匙串时可设为 `secret-service`。 |
| `--no-remote-version` | — | 关闭联网命令每 24 小时一次的客户端最新版本号缓存查询。 |
| `--json` | — | 输出机器可读的标准 JSON 格式（供自动化脚本解析使用）。 |

---

## 4. 全量命令与参数详解

### 4.1 环境体检与自动修复：`doctor`

用于检查本地账号库、策略配置、文件权限、崩溃恢复日志以及桌面钥匙串环境是否正常：

```bash
agy-switch-cli doctor                # 纯只读全面体检（不修改任何文件）
agy-switch-cli doctor --verify-agy   # 体检的同时，探测本机官方 agy 命令路径与版本兼容性
agy-switch-cli doctor --fix          # 自动修复权限、对账未完成的切换日志、清理失效策略候选 ID
```

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

# 查看已注册的 OAuth 客户端配置列表
agy-switch-cli auth clients
```

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

> **提示**：你也可以运行 `agy-switch-cli tui` 进入可视化看板，按 **`K`（上移）** 或 **`J`（下移）** 实时调整顺序。

#### （2）通过 Refresh Token 添加单个或多个账号：`accounts add`

> **安全保护说明**：为防止机密 Token 留在终端历史记录（`.bash_history`）或被系统进程表泄露，工具禁止将 Token 直接作为命令行位置参数传入，而是提供支持**单条无回显输入**和**多条文件批量导入**的安全方式：

**场景 A：手动安全粘贴单条 `refresh_token`**
```bash
# 运行后终端会自动关闭字符回显（粘贴时不显示字符属于正常保护），粘贴后按回车即可：
agy-switch-cli accounts add --label "备用号"
```

**场景 B：手里有多条裸 `refresh_token`（无需事先知道邮箱），一次性批量添加**
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
   agy-switch-cli accounts add --token-file ~/tokens.txt
   rm -f ~/tokens.txt
   ```
   *(注：同样支持通过标准输入管道传入，如 `cat ~/tokens.txt | agy-switch-cli accounts add --stdin`，单次管道输入上限为 `16 KiB`。)*

#### （3）备份导出与离线 JSON 导入（含旧版桌面端迁移）：`accounts export` / `import`

```bash
# 1. 从旧版桌面软件 agy-switch（默认读取 ~/.antigravity_tools）只读迁移账号（不会修改原目录中的任何文件）：
agy-switch-cli accounts import --from-legacy

# 2. 将当前账号库导出为 0600 权限的备份 JSON 文件（因含敏感令牌，须显式加 --include-secrets 确认）：
agy-switch-cli accounts export --output ~/agy-backup.json --include-secrets [--ids alice@example.com ...] [--force]

# 3. 从备份 JSON 文件离线导入恢复（默认跳过本地已有的同邮箱账号；加 --overwrite 才会更新已有账号令牌）：
agy-switch-cli accounts import ~/agy-backup.json [--overwrite]
```

**`accounts import <文件.json>` 对 JSON 格式的要求**：  
`accounts import` 为**纯离线快速导入**（不发起网络请求），因此 JSON 中的每个账号对象必须同时包含 `"email"` 和 `"refresh_token"` 两个字段（其余字段均可省略）。它兼容以下两种 JSON 结构：

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
*(补充说明：如果手头只有 `refresh_token` 而不知道对应的 `email`，请使用上一小节的 `accounts add --token-file` 联网自动识别邮箱导入。)*

#### （4）启用、禁用与删除账号：`enable` / `disable` / `delete`

```bash
agy-switch-cli accounts disable bob@example.com --reason "留作月底备用"   # 手动禁用（填邮箱或 ID）
agy-switch-cli accounts enable bob@example.com                           # 重新启用（填邮箱或 ID）
agy-switch-cli accounts delete charlie@example.com [--force] [--clear-active-slot]
# 说明：删除当前选中账号需加 --force；加 --clear-active-slot 会一并清理正在生效的同名官方凭据文件。
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
- **`Selected account`**：当前选中的账号、套餐等级、自定义备注与内部 ID。
- **`Active agy slot`**：官方 `agy` 凭据文件中的实际身份状态（仅展示邮箱与换算为本机本地时区的 `YYYY-MM-DD HH:MM` 过期时间；`matched` 表示已同步一致，`drifted_known` / `drifted_external` 表示凭据文件曾被外部改动，`uninitialized` 表示尚未初始化凭据文件）。
- **`Live agy runtime`**：当前系统中是否有正在运行的 `agy` 进程（`idle` 表示空闲）。
- **`Supported models`**：当前账号可使用的全部模型清单（读取自最近一次配额刷新缓存，自动剔除未开放模型并按模型家族分组展示）。

#### （2）手动切换生效账号：`switch`

`switch` 通过**邮箱**或**账号 ID**精确指定目标账号（日常交互切号也可直接使用 `agy-switch-cli tui`）：

```bash
agy-switch-cli switch bob@example.com                   # 按邮箱切换到指定账号
agy-switch-cli switch acc-0002                          # 或按内部账号 ID 切换到指定账号
agy-switch-cli switch bob@example.com --dry-run         # 仅做切换前条件预检，不发网络请求也不修改文件
agy-switch-cli switch bob@example.com --allow-running   # 即使当前有正在运行的旧 agy 进程，也允许更新槽位供后续新窗口使用
```

---

### 4.5 配额查询与联网刷新：`quota` / `refresh`

```bash
# 1. 查看当前选中账号的本地缓存配额表（纯本地读取，零网络请求）：
agy-switch-cli quota

# 2. 先联网刷新最新配额，再立即打印配额进度表（-r 是 --refresh 的简写）：
agy-switch-cli quota -r

# 3. 按邮箱或 ID 查看 / 刷新指定账号：
agy-switch-cli quota bob@example.com
agy-switch-cli quota -r bob@example.com

# 4. 一次性查看全部账号，或并发刷新全部启用账号后统一打印（--concurrency 可调并发数 1..5，默认 2）：
agy-switch-cli quota --all
agy-switch-cli quota -r --all [--concurrency 3]

# 5. 纯后台联网刷新落盘（不打印进度表，适合自动化脚本调用）：
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

当你拥有多个账号时，可以先通过 `policy` 设定好“低到多少百分比时换号、按什么顺序挑选下一个号”。规则设定完成后，既可以通过下一节的 **`run`（每次启动 `agy` 前按需自动检查切号）** 来触发，也可以通过 **`daemon`（后台每小时定时巡检切号）** 来触发。

#### `policy set` 全部参数说明表

| 参数选项 | 可选填的值 | 默认值 | 详细作用与选择建议 |
| :--- | :--- | :---: | :--- |
| **`--enabled`** | `true` 或 `false` | `false` | **自动切号总开关**。开启前候选名单里至少需要包含 1 个账号。 |
| **`--all-candidates`** | 无需填值（直接添加该开关） | — | **一键将当前所有已启用账号（按 `accounts list` 顺序）全部设为候选账号**，免去逐个输入邮箱的步骤。 |
| **`--candidates`** | 空格分隔的 `<ID\|EMAIL>` | 空 | 只希望将部分特定账号放入轮换池时使用，填写对应账号的邮箱或 ID（如 `--candidates alice@example.com bob@example.com`），或在 `tui` 中按 `c` / `C` 键可视化勾选。清空候选池可使用 `--clear-candidates`。 |
| **`--reserve`** | `1` ～ `98`（整数百分比） | `10` | **保底警戒线（触发换号线）**。例如设为 `15`：当正在使用的账号剩余额度降至 `15%` 或以下时，触发自动换号。 |
| **`--minimum`** | `2` ～ `100`（整数百分比） | `30` | **候选接班准入线**。准备接班的备用账号剩余额度必须至少达到该百分比（如 `>= 30%`）才会被选中。<br>*要求 `--minimum` 严格大于 `--reserve`，是为了留出安全水位差，防止两个低额度账号之间发生反复来回切换。* |
| **`--strategy`** | `round-robin` 或 `priority` | `round-robin` | **候选账号挑选顺序**：<br>• **`round-robin`（循环轮换，默认）**：记录上次切入的账号位置，下次从其后一位开始依次轮流挑选。适合多个账号均匀分摊额度消耗的场景。<br>• **`priority`（主备优先级）**：每次均从候选列表第 1 位开始依次寻找第一个达标的账号。适合“有明确主力号，主力号额度恢复后优先用回主力号”的场景。 |
| **`--mode`** | `immediate` 或 `wait` | `immediate` | **后台 `daemon` 检测到正在运行的 `agy` 进程时的处理方式**：<br>• **`immediate`（触线立即更新槽位，默认）**：绝不强杀正在运行的 `agy` 进程，但在检测到当前账号额度跌破警戒线后立即更新磁盘凭据槽位，使后续新打开的终端窗口直接使用新账号（已运行的旧窗口仍保持原会话不受影响；若遇到 `/proc` 不可读即 `unverified` 状态，仍保持故障关闭拒绝盲写）。<br>• **`wait`（等待空闲）**：检测到有活跃 `agy` 进程正在运行时暂缓切换，等所有 `agy` 退出空闲后再写入新凭据。 |
| **`--model`** | `all`、`gemini`、`claude`、`argon` 或具体模型名 | `all` | **监控的模型池范围**：<br>• **`all`（默认）**：同时监控所有模型池，任一池跌破警戒线即触发切号；<br>• **`gemini`**：仅监控 Gemini 共享池额度；<br>• **`claude`**（或 `3p`）：仅监控 Claude / GPT 池额度（日常以使用 Claude 为主时推荐选此项）。 |

#### `policy` 常用命令示例

```bash
# 1. 将当前所有启用账号加入候选池（默认即为 immediate + round-robin），监控 Claude 额度，低于 15% 时轮流切到 >=35% 的账号：
agy-switch-cli policy set --enabled true --all-candidates --reserve 15 --minimum 35 --model claude

# 2. 若希望等待旧 agy 进程全部退出后再切号，并采用主备优先级顺序：
agy-switch-cli policy set --mode wait --strategy priority --candidates alice@example.com bob@example.com

# 3. 查看当前策略详情、调整候选优先级顺序、或空跑模拟测算当前是否会触发切号：
agy-switch-cli policy show
agy-switch-cli policy order bob@example.com alice@example.com
agy-switch-cli policy eval
```

> **提示**：你也可以在 `agy-switch-cli tui` 看板中按 **`c` 键**增删单个候选账号、按 **`C` 键**一键全选或清空所有未禁用候选账号，并按 **`p` 键**切换自动切号总开关。

---

### 4.7 可选受管启动包装器：`run`（启动前按需自动切号）

除了通过 `tui` 或 `switch` 切号后直接运行 `agy` 之外，如果你不想常驻后台进程、但又希望在每次启动 `agy` 前顺带做一次低配额检查与自动切号，也可以使用 `run` 包装方式启动：

```bash
# 以受管包装方式启动官方 agy（双横杠 `--` 后面接原本的 agy 命令及任意参数）：
agy-switch-cli run -- agy
agy-switch-cli run -- agy chat "帮我检查这段代码的边界条件"

# 在开启了 GNOME Keyring / KWallet 的 Linux 图形桌面上，加 --isolate-dbus 自动为子进程屏蔽桌面钥匙串干扰：
agy-switch-cli run --isolate-dbus -- agy

# 本次启动前临时指定切换到某个邮箱或 ID 对应的账号：
agy-switch-cli run --account bob@example.com -- agy
```

**`run` 的主要作用**：
1. **无需常驻后台 `daemon` 也能实现自动切号**：平时后台不产生任何定时联网请求；仅在你执行 `run` 准备启动 `agy` 时检查当前账号额度（若缓存未超过 1 小时则直接读取本地缓存），若低于 `--reserve` 警戒线便在启动前自动切入达标的候选账号。
2. **令牌保鲜与进程租约登记**：启动前自动确认访问令牌有效，并为该 `agy` 子进程登记身份租约，退出后原样透传 `agy` 的退出码。你可以在 `~/.bashrc` 中设置别名 `alias agys='agy-switch-cli run --isolate-dbus -- agy'` 以简化日常输入。

---

### 4.8 后台自动切号守护进程：`daemon`（定时巡检触发）

如果你习惯直接输入裸 `agy` 启动客户端，或有其他自动化任务调用 `agy`，希望后台定期巡检配额并提前切换好凭据槽位，可以使用 `daemon` 命令：

```bash
# 按默认防风控参数启动（默认每 3600 秒即 1 小时巡检一次，切号后冷却 3600 秒即 1 小时）：
agy-switch-cli daemon

# 自定义巡检间隔与冷却时间（单位为秒，例如每 2 小时巡检一次）：
agy-switch-cli daemon --interval 7200 --cooldown 3600

# 仅执行单轮“检查 -> 按需刷新 -> 按需切号”后立即退出（适合配合 crontab 定时任务）：
agy-switch-cli daemon --once
```

| 参数选项 | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :---: | :--- |
| `--interval <秒>` | `AGY_SWITCH_CLI_INTERVAL` | `3600`（1 小时） | 后台巡检间隔秒数（内置 `±10%` 随机时间抖动，保持温和低频访问） |
| `--cooldown <秒>` | `AGY_SWITCH_CLI_COOLDOWN` | `3600`（1 小时） | 完成一次自动切号后的冷却保护时间（秒），冷却期内不再连续触发第二次切换 |
| `--once` | — | 关闭 | 仅执行单轮评估与切换后立即退出 |
| `--mode` / `--strategy` / `--reserve` / `--minimum` / `--model` | — | 读取 `policy.json` | 仅对本次运行生效的内存临时覆盖参数，不会修改磁盘上的 `policy.json` |

---

### 4.9 SSH 交互式终端看板：`tui`（全键盘可视化操作）

如需在单个界面中总览所有账号额度、调整列表顺序、配置自动切号候选池或手动切号，可运行：

```bash
agy-switch-cli tui
```

#### 界面说明
- **自适应窗口尺寸与滚动视口**：看板实时适配当前终端宽高并响应窗口缩放；顶栏 `Session:` 精简展示当前槽位邮箱与本机本地时区过期时间（`YYYY-MM-DD HH:MM`）；在宽度小于 `152` 列的常规或窄屏窗口中会自动隐藏冗长的 36 位 `ID` 列以保持每账号单行清晰排版，当账号数量超出当前窗口高度时会自动保持顶栏、表头与底栏固定，并跟随光标平滑上下滚动（顶部标题栏同步显示 `[Showing X-Y of N]` 范围提示）；在极窄或极矮的终端分屏中还会自动降级为紧凑单行焦点视图，确保不超出物理宽高且当前光标所在账号始终可见。
- **`#`、`Sel` 与 `Plan`**：`#` 为右对齐账号序号；`>` 表示当前光标所在行，`*` 表示当前选中的账号；`Plan` 列在所有宽度下自动去除 `Google AI` / `AI` 等冗余前缀，统一简写为 `Free` / `Pro` / `Ultra`（未知新套餐名原样兜底保留）。
- **`Gemini (5h / W)` 与 `Claude/GPT (5h / W)`**（窄屏紧凑表头为 `Gemini 5h/W` 与 `Claude/GPT 5h/W`）：斜杠左侧为 `5h`（五小时短期窗口剩余额度），右侧为 `W`（Weekly 周剩余额度），如 `100% /  72%`；单元格内对百分比做了固定宽度字符级填充与居中对齐，使上下各行的百分比与斜杠 `/` 保持严格垂直对齐。灰度专属池 `Argon (W)` 在所有账号均无该池数据时会自动隐藏，存在数据时自动展开。
- **`Policy`**：显示该账号在自动切号候选池中的顺位（如 `cand #1`、`cand #2`，未加入显示 `—`）；若候选池中的某个账号当前处于已禁用（`disabled`）状态，自动切号调度时会自动跳过该账号，并在该列明确标注为 `cand #2 (skip)`。顶部状态栏同步显示 `Policy: ON / off` 及当前模式与策略。
- **双行固定底栏**：上一行常驻显示自适应宽度的按键提示（包含 `r/R` 与 `c/C`），下一行显示实时批量刷新进度或最近一次操作反馈，并在 **3 秒**（报错信息 **5 秒**）后自动清空。

#### `tui` 完整快捷键一览表

| 按键 | 功能说明 |
| :--- | :--- |
| `↑` / `↓` 或 `k` / `j` 或 `PgUp` / `PgDn` | 上下移动高亮光标（超出单屏时列表自动跟随滚动） |
| `g` / `Home` 或 `G` / `End` | 快速将高亮光标跳转到列表首行（`g`）/ 末行（`G`） |
| **`K` / `J`**（`Shift+k/j`）或 **`Shift+↑` / `Shift+↓`** | 将当前高亮账号上移一位 / 下移一位（实时保存新顺序） |
| `Enter`（回车）或 `s` | 将官方 `agy` 凭据切换到当前高亮账号 |
| `r` / **`R`** | `r` 联网刷新当前高亮账号配额；大写 **`R`** 以安全有界并发批量刷新全部未禁用账号（底栏实时显示进度，支持按 `Ctrl+C`、`q`、`Esc` 或发送系统信号随时安全中断并恢复终端） |
| **`c`** / **`C`** | `c` 增删当前高亮账号的候选资格；大写 **`C`** 一键将所有未禁用账号按列表顺序加入候选池（若所有未禁用账号均已在候选池中，再按 **`C`** 则清空候选池并自动关闭策略总开关） |
| **`p`** | 开启或关闭 `policy` 自动切号总开关 |
| `e` / `d` | 启用（Enable）/ 手动禁用（Disable）当前高亮账号 |
| `q` 或 `Esc` 或 `Ctrl+C` | 退出看板并恢复原终端界面 |

---

## 5. 标准退出码（`0..=8`）与 `--json` 脚本集成契约

添加 `--json` 后，机器输出契约按命令性质分为以下三类：

- **单目标命令与前置参数/文件校验**
  - **执行成功时**：将结果信封（包含 `"schema_version": 1, "ok": true`）输出至 `stdout`，并返回退出码 `0`。
  - **执行失败时**：将结构化错误信封（包含 `"schema_version": 1, "ok": false, "error_code": "...", "message": "..."`）输出至 `stderr`，并返回对应的非零退出码（`1..=8`）。
  - **单启用账号刷新例外**：当执行 `refresh --all` 或 `quota -r --all` 但本地实际仅有 1 个未禁用账号、且该唯一账号刷新失败时，同样直接按单目标失败在 `stderr` 输出 `"ok": false` 信封并返回对应错误退出码。

- **多条目批量写入与批量联网命令**（包含 2 条及以上令牌的 `accounts add --token-file/--stdin`、涉及多账号的 `refresh --all` 与 `quota -r --all`，以及 `auth pending --resume`）
  - **汇总输出位置**：逐条独立执行并在 `stdout` 输出汇总信封（`"schema_version": 1, "ok": true`，此时 `stderr` 保持为空）。
  - **各命令的失败明细字段**：
    - 批量 `accounts add`：包含 `failed_count` 计数与 `failures` 数组；
    - 多账号 `refresh --all` 与 `auth pending --resume`：包含 `failures` 数组；
    - 多账号 `quota -r --all`：包含 `refresh_failures` 数组。
  - **进程退出码**：只要汇总结果中存在至少 1 条失败项，进程退出码统一返回 `1`（`GeneralOrDataError`）。
  - **脚本判定方式**：自动化脚本应同时检查进程退出码是否为 `0`，以及 `stdout` 汇总对象中的失败明细字段（`failed_count` 或 `failures` / `refresh_failures` 数组长度）。

- **离线批量导入与只读全量配额聚合**
  - **`accounts import --json`**：当导入文件本身可读且 JSON 结构合法时，将逐条导入、跳过与失败统计（`report.failed_count` 与 `report.failures`）输出至 `stdout` 并返回退出码 `0`；若文件无法打开或 JSON 语法损坏，则在 `stderr` 输出错误信封并返回非零退出码。
  - **只读 `quota --all --json`（不带 `-r`）**：作为全库本地缓存状态聚合接口返回退出码 `0`，脚本应读取每个账号对象内的 `evaluation` 字段判断单账号是否新鲜可用；而单账号严格查询 `quota [<ID|EMAIL>] --json` 在缓存处于 `Stale`、`Unknown` 或 `Unavailable` 时则严格返回退出码 `4`。

进程退出码定义如下：

| 退出码 | 名称 | 代表的含义与处理建议 |
| :---: | :--- | :--- |
| `0` | `Ok` | 执行成功（`run -- agy` 模式下原样透传 `agy` 子进程退出码） |
| `1` | `GeneralOrDataError` | 本地文件损坏、磁盘权限错误，或批量操作中存在失败项 |
| `2` | `InvalidUsageOrAmbiguous` | 命令参数有误、策略阈值冲突（如 `minimum <= reserve`），或同名邮箱需改用 ID 区分 |
| `3` | `AccountNotFound` | 找不到指定账号，或尚未设置当前选中账号 |
| `4` | `QuotaUnavailableOrStale` | 目标账号尚无配额缓存，或在 `--json` 严格模式下缓存已过期/未知（加 `-r` 刷新即可） |
| `5` | `LockBusyOrConflict` | 并发锁繁忙，或安全拦截了使用已淘汰旧令牌覆盖新令牌的操作 |
| `6` | `AuthOrClientError` | OAuth 授权失败、令牌已被撤销（运行 `auth reauthorize` 重新授权即可恢复） |
| `7` | `PartialCommitOrRecovery` | 上次切号中途断电或异常退出留下未完成日志，运行 `agy-switch-cli doctor --fix` 即可恢复 |
| `8` | `EnvironmentNotReady` | 存在正在运行的 `agy` 进程阻止了静默切号、`/proc` 不可读，或后端环境未就绪 |

---

## 6. 可选配置文件（`config.json` 网络代理与自定义 OAuth 客户端）

`~/.local/share/agy-switch-cli/config.json` 是**完全可选**的配置文件。默认情况下该文件不存在，所有功能均可直接使用（程序已内置与官方 `agy` 一致的默认 OAuth 客户端 `antigravity_enterprise`）。只有当你遇到以下两类需求时，才需要手动创建它：

1. **固定网络代理**：本机需要通过固定的 HTTP 或 SOCKS5 代理连接 Google 服务，希望写入配置文件省去每次加 `--proxy` 参数；
2. **自定义 OAuth 客户端（进阶场景）**：你手头拥有由其他 Google Cloud OAuth 客户端（例如企业自建项目或其他兼容客户端）签发的 `refresh_token`，或者希望使用自建 OAuth 客户端进行登录。根据 OAuth 2.0 协议规范，由哪个 `client_id` 签发的 `refresh_token` 在刷新续期时必须继续搭配同一个 `client_id` 与 `client_secret` 使用，此时即可将其注册到 `oauth.clients` 中。

> **文件权限要求**：由于 `config.json` 中可能包含带密码的代理地址或 `client_secret` 密钥，创建时请将文件权限设为仅当前用户可读写的 `0600`（若权限过宽如 `0644`，程序会输出安全提示，可执行 `chmod 600` 或 `agy-switch-cli doctor --fix` 收紧权限）：
> ```bash
> install -m 0600 /dev/null ~/.local/share/agy-switch-cli/config.json
> ```

### 6.1 场景一：仅配置固定网络代理（最常见用法）

如果只需要配置网络代理，无需填写 `oauth` 部分，写入以下最简内容即可：

```json
{
  "schema_version": 1,
  "network": {
    "proxy_url": "socks5h://127.0.0.1:1080",
    "no_proxy": "internal.corp,10.0.0.0/8"
  }
}
```

- **`network.proxy_url`**：支持 `http://`、`https://`、`socks5://`、`socks5h://`（由代理端解析远端域名，可避免本地 DNS 污染）以及 `"direct"`（强制直连，忽略系统代理环境变量）。代理生效优先级为：`命令行 --proxy > config.json > 系统环境变量（HTTPS_PROXY / HTTP_PROXY / ALL_PROXY）`。
- **`network.no_proxy`**：可选，逗号分隔的不走代理域名或网段列表。注意本机环回地址（`127.0.0.1`、`localhost`、`[::1]`，如 `--ssh` 登录回调监听端口）始终自动直连，不会被代理拦截。

### 6.2 场景二：注册并使用自定义 OAuth 客户端（完整字段详解）

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
   绑定完成后，该账号档案会自动记住 `oauth_client_key = "my_custom_oauth"`，后续日常执行 `switch`、`quota -r`、`run` 或 `daemon` 自动续期时都会自动匹配这组客户端凭据，无需每次重复传入 `--client`（即使混用多个不同客户端签发的账号也能各自独立续期）。
3. **无文件环境变量注入方式（适合 Docker 容器）**：除了写 `config.json`，也可以通过环境变量 `ANTIGRAVITY_OAUTH_CLIENTS="key|client_id|client_secret|label"`（多项之间用分号 `;` 分隔，优先级高于 `config.json`）与 `ANTIGRAVITY_OAUTH_CLIENT_KEY="<KEY>"` 动态注入。

---

## 7. 后台常驻运行指南（`systemd --user` 与无 `systemd` 的 Docker 容器环境）

`agy-switch-cli daemon` 本身设计为标准前台长运行进程（内置 `daemon.lock` 单实例互斥锁与 `SIGTERM` 优雅退出机制），不自行向后台分裂（fork）。下面分别说明在带有 `systemd` 的常规 Linux 系统上，以及在**没有 `systemd` 的 Docker 容器（如远程开发容器、云算力容器、WSL 精简环境）**中，如何让 `daemon` 在后台稳定常驻运行。

### 7.1 常规 Linux 系统（使用 `systemd --user` 用户级服务）

在支持 `systemd` 的 Linux 服务器或桌面上，建议使用**当前普通用户的 `--user` 服务**（而非 `root` 系统级服务）来托管 `daemon`。这样可以保证后台服务与你平时运行 `agy` 的终端共享同一个 `$HOME` 目录、相同的文件属主与一致的 `~/.gemini/antigravity-cli` 凭据路径，避免因 `root` 权限写出普通用户无权读取的文件。

仓库内的 [`deploy/agy-switch-cli.service`](../deploy/agy-switch-cli.service) 已预设好崩溃自动重启（`Restart=on-failure`）与最小权限沙盒边界：

```bash
# 第 1 步：启动服务前，先确认已添加账号并开启了自动切号策略
agy-switch-cli policy set --enabled true --all-candidates --reserve 15 --minimum 35
agy-switch-cli policy show

# 第 2 步：安装用户级 service 文件（若你的二进制不在 ~/.local/bin，请先相应调整 service 文件中的 ExecStart 路径）
mkdir -p ~/.config/systemd/user
cp deploy/agy-switch-cli.service ~/.config/systemd/user/

# 第 3 步：重载配置并设置开机自启 + 立即后台运行
systemctl --user daemon-reload
systemctl --user enable --now agy-switch-cli.service

# 第 4 步：允许当前用户的后台服务在断开 SSH 连接后继续保持运行（远程服务器建议执行）
sudo loginctl enable-linger "$USER"

# 日常运维常用命令：
systemctl --user status agy-switch-cli.service        # 查看服务当前运行状态
journalctl --user -u agy-switch-cli.service -f        # 实时查看巡检与切号日志
systemctl --user restart agy-switch-cli.service       # 修改 config.json 后重启服务
systemctl --user disable --now agy-switch-cli.service # 停止并取消开机自启
```

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

1. **问：`auth login` 点完允许后，浏览器跳到 `127.0.0.1` 提示“无法访问此网站”，是否代表登录失败？**  
   **答**：没有失败。默认的免配置登录模式不需要在本地电脑启动监听服务，授权码已经包含在浏览器顶部地址栏那串 `http://127.0.0.1:...` 网址中。将该网址完整复制并粘贴回终端按回车即可完成登录。
2. **问：登录或批量添加账号时遇到网络波动，查询邮箱信息超时报错，刚换出的令牌会丢失吗？**  
   **答**：不会丢失。新令牌在签发瞬间已以 `0600` 权限暂存在本地 `state/pending_auth/` 目录中。待网络恢复后，执行 `agy-switch-cli auth pending --resume` 即可继续完成绑定。
3. **问：在 Linux 图形桌面上执行了 `switch`，但直接输入 `agy` 为什么仍在使用旧账号？**  
   **答**：这是因为图形桌面的系统钥匙串（GNOME Keyring / KWallet）读取优先级高于本地凭据文件。可通过以下任一方式解决：① 使用 `agy-switch-cli run --isolate-dbus -- agy` 启动；② 安装 `-all-features` 版二进制并执行 `agy-switch-cli --backend secret-service switch <邮箱或ID>`。
4. **问：日常使用时，手动切号、`run` 包装启动与后台 `daemon` 该如何选择？**  
   **答**：三种方式均可按个人习惯选用：若平时习惯直接输入 `agy` 且切号时打开面板看一眼即可，直接使用 `agy-switch-cli tui` 最直观简单；若配好了 `policy` 且不想开后台常驻进程，可用 `agy-switch-cli run -- agy` 在启动前按需检查切号；若习惯直接输入裸 `agy` 又希望后台自动提前换好账号，则可开启每小时巡检一次的 `daemon`。
