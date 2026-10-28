# file.kiwi Downloader — 维护评审（v0.2.0）

> 面向对象：半年后接手这个项目的人（很可能是你自己，而你已经忘光了）。
> 目标：**能在 30 分钟内看懂结构、知道改哪里会炸、知道怎么验证没改坏。**
>
> 本文不重复"怎么用"，用法见 `dist/README.txt`。本文讲"为什么这么写"和"哪里脆"。

---

## 1. 项目定位

一个**非官方**的 file.kiwi 分享链接下载器，demo 级。

| 是 | 不是 |
|---|---|
| 本地解密（零知识，密钥只在 URL `#` 片段） | 不是通用网盘客户端 |
| 两种下载引擎：内置 / 托管 aria2 | 不支持上传 |
| 六个平台单文件二进制（Node SEA：win/linux/macos × x64/arm64） | 不支持带密码链接 |
| 单文件夹、少量文件 | 不是生产级断点续传服务 |

**风险基线**：这是逆向出来的协议，**没有任何公开契约保证**。服务端改一个字段，整个工具就废。第 5 节列了所有假设点。

---

## 2. 目录与文件角色（先看这张表）

```
filekiwi/
├── cli.js            29.5 KB  ★ 唯一权威实现（单文件、零依赖、CJS）
├── build.mjs          发布构建脚本（打版本补丁 → SEA → 注入 → 打包）
├── README.txt         用户文档（构建时替换 {{VERSION}} / {{DATE}}）
├── sea-config.json    0.1 KB  Node SEA 打包配置（main = cli.js，本地调试用）
├── package.json       构建期依赖声明（仅 postject，用于注入 SEA blob）
├── package-lock.json  锁定 postject 版本，CI 用 npm ci
├── .gitignore         忽略 dist/ build/ node_modules/ *.exe
├── .github/workflows/
│   ├── build.yml      可复用构建（windows-latest）
│   ├── release.yml    正式发布（tag 或手动）
│   └── nightly.yml    每日滚动 pre-release
├── docs/MAINTENANCE.md 本文
├── dist/              发布产物（git 忽略）
├── build/             构建中间物（git 忽略）
├── .cache/node/       跨架构构建时下载的官方 Node（git 忽略）
├── filekiwi.exe       本地构建产物（git 忽略）
├── sea-prep.blob      构建中间产物（git 忽略）
├── ece.mjs            1.8 KB  ECE 解密（早期 ESM 版，被 cli.js 内联取代）
├── probe.mjs          4.6 KB  早期探测器（依赖 ece.mjs）
├── serve.mjs          9.9 KB  早期代理（依赖 ece.mjs，已被 cli.js serve 取代）
├── ece.py             2.3 KB  Python 版解密（未跑通，cryptography 装不上）
└── p1_get.py          5.6 KB  Python 串行对照组（同上，跑不起来）
```

**必须知道的现实**：
- `cli.js` 是唯一能用的东西。其余 `.mjs` / `.py` 是探索期产物，**逻辑已经和 cli.js 漂移**（`serve.mjs` 对非法 Range 返回 200，`cli.js` 返回 416）。
- 建议：把 `ece.mjs / probe.mjs / serve.mjs / ece.py / p1_get.py` 移到 `legacy/` 或删掉；`filekiwi.exe` 和 `sea-prep.blob` 加进 `.gitignore`。现在这样，新人分不清哪份是真的。

---

## 3. 架构

```
                 ┌──────────────────────────────────────────┐
  share URL ────▶│ loadEntries()                            │
  (#secretKey)   │  parseShare → listFiles → decryptStream   │
                 └───────────────┬──────────────────────────┘
                                 │ entries[]: {fid,size,chunks,chunksize,sname,dd,key}
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
      ┌────────────────────┐          ┌──────────────────────────┐
      │ internal engine    │          │ aria2 engine             │
      │ downloadInternal() │          │ startProxy() + Aria2     │
      │ 8MiB 段 + 位图     │          │ 本地 HTTP 代理 ← aria2c  │
      └─────────┬──────────┘          └────────────┬─────────────┘
                │                                  │
                └──────────────┬───────────────────┘
                               ▼
                    plainRange(e, start, end)        ← 唯一的数据出口
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
              recordStream()        (chunk/record 映射)
                    │
              openRange() → signChunk() → R2 presigned GET
                    │
              decryptRecord()  (AES-128-GCM, 64 KiB/条)
```

**关键设计决策：所有字节都必须经过 `plainRange()`。** 两个引擎唯一的区别是"谁来驱动它"：内置引擎自己开 worker 循环，aria2 引擎通过 localhost HTTP + Range 驱动。这条约束保证了加新引擎时不用重写解密。

---

## 4. 不变量（改代码前必须守住）

### 4.1 ECE 参数（硬编码在 `cli.js:26-28`）

| 常量 | 值 | 含义 |
|---|---|---|
| `RS` | 65536 | 线上每条 record 的字节数 |
| `HDR` | 21 | salt(16) + rs(4) + idlen(1) |
| `CAP` | 65519 | 每条 record 的明文上限 = `RS - 16(tag) - 1(delimiter)` |

密文长度公式（**验证协议是否变化的免费探针**）：

```js
ctLen(chunk) = HDR + plainLen + 17 * ceil(plainLen / CAP)
```

实测吻合：`21 + 10592232 + 17×162 = 10595007` = R2 返回的 `Content-Length`。
**如果哪天这个等式不成立了** → 说明服务端改了加密参数，`decryptRecord` 必然全错。

### 4.2 每个 chunk 是独立流

- 每个 chunk 有自己的 21 字节头（自己的 salt）
- record 序号 `seq` **从 0 重新开始**（nonce 由 seq 决定）
- 每个 chunk 的**最后一条 record** delimiter 是 `0x02`，其余是 `0x01`
- 明文记录 = `data || delimiter || 零填充`，解完必须 unpad

写这段代码最容易犯的错：**把 chunk 当成一个连续大流**（seq 不清零）→ 全盘 GCM 报错。

### 4.3 偏移映射

```
chunk   = min(floor(offset / chunksize), chunks-1)
q       = offset - chunk*chunksize
record  = floor(q / CAP)
in-rec  = q % CAP
```

`plainRange(e, start, end)` 用半开区间 `[start, end)`。**HTTP 层是闭区间**，`startProxy` 里做了 `endIncl + 1` 转换——历史 bug：忘了 +1 会少一个字节，忘了在 record 层 unpad 会每 65519 字节多注入一个 `0x01`（长度对、内容错、sha256 才炸）。

### 4.4 代理契约（aria2 依赖这些，改错了它就不干活）

| 项 | 要求 | 违反后果 |
|---|---|---|
| `Content-Length` | **明文**长度 | aria2 无法分段，退化为单连接 |
| `Accept-Ranges` | `bytes` | 同上 |
| `Range` 请求 | 必须 206 + `Content-Range` | 返回 200 会让 aria2 从 0 重下 |
| 开放区间 `bytes=N-` | 支持 | 续传失效 |
| 非法区间 | 416 + `bytes */size` | aria2 报错信息难懂 |
| 客户端断开 | abort 上游 | 白白读完整文件（曾实测放大 3 倍流量） |
| 慢客户端 | `drain` 背压 | 内存暴涨 |

### 4.5 分段完成 = 写完 + GCM 通过

`downloadInternal` 的位图 `done[seg]` 只在**整段写完后**置位并落盘 sidecar。
**绝不能改回"用文件大小当进度"**——并发写会让文件大小虚高，续传时把空洞当有效数据，静默输出坏文件（v0.1.0 的真实缺陷，已用实验复现）。

### 4.6 aria2 托管

- `--no-conf`：不读用户配置（否则用户的 `rpc-listen-port`/`dir` 会打架）
- 私有端口 + 随机 `--rpc-secret`
- `--stop-with-process=<pid>`：主进程死，aria2 跟着死（防残留）
- 结束时 `aria2.shutdown`（优雅，会写 `.aria2` 控制文件）

---

## 5. 外部依赖与易变点（★ = 最可能变）

### 5.1 file.kiwi 公开 API

| 端点 | 用途 | 备注 |
|---|---|---|
| `GET /api/files/list?roomid=` | 列文件 | ★ 返回 `filesize/chunks/chunksize/sname/dd/expire/expireview`，**无鉴权** |
| `POST /api/getdlurl` | 换签名 | ★ body 需要 `{id,idf,sname,dd,chunks,chunk,usepoint:false}`；`dd`/`sname` 语义未知，只能原样回传 |
| `GET {head}/{00001..}` | 取密文 | ★ 需 `?X-Amz-Signature={dlist[0]}&{dntail}`；签名 TTL 6000 s；**HEAD 返回 403**（签名只覆盖 GET） |

**端口假设**：`files.list` 的 `roomid` = URL 路径第一段；`fid` = `files` 对象的 key。

**如果 API 变了，先从这两个函数下手**：`listFiles()`（`cli.js:85`）、`signChunk()`（`cli.js:93`）。

### 5.2 加密协议

基于 `wormhole-crypto`（Firefox Send 血统）的 RFC 8188 aes128gcm：
- HKDF-SHA256，info = `Content-Encoding: aes128gcm\0` / `Content-Encoding: nonce\0`
- nonce = HKDF 输出 12 字节，**末 4 字节 XOR seq**
- AES-GCM，16 字节 tag，无 AAD

**如果解密突然全炸**：先算 4.1 的长度公式。公式对 → 参数没变，查 key/fragment；公式不对 → 协议改了，别修代码，先逆向。

### 5.3 aria2

- 最低 1.18 左右（`--stop-with-process`、RPC），实测 1.36.0
- RPC 方法：`aria2.getVersion / addUri / tellStatus / shutdown`
- 错误码映射见 `ARIA2_ERRORS`（`cli.js:472`）

### 5.4 Node 运行时

- 依赖：`fetch`、`AbortSignal.any`（Node 20.3+）、`crypto.hkdfSync`、`fs.promises.FileHandle`
- 打包用 Node SEA，**Node 版本决定 exe 体积和行为**，升级前先看第 11 节

---

## 6. 状态文件

| 文件 | 由谁写 | 含义 | 删了会怎样 |
|---|---|---|---|
| `X.part` | internal | 半成品明文 | 重下 |
| `X.part.json` | internal | `{size, seg, done: [bool...]}` 位图 | 重下（安全，只是浪费） |
| `X.aria2` | aria2 | aria2 自己的控制文件 | aria2 重下 |
| `X` | 两者 | 成品 | — |

**注意**：两个引擎的中间文件互不识别。用 internal 下到一半改用 aria2，会从零开始（aria2 看 `X.part` 不认）。

---

## 7. 失败模式矩阵

| 现象 | 可能原因 | 定位 |
|---|---|---|
| `no files — link expired...` | 链接过期/被删/roomid 错 | `files/list` 返回空 |
| `URL has no #secretKey` | 聊天软件吃掉了 `#` | 用户重新复制 |
| `password-protected links...` | 链接是 `#key,password` | 未实现 |
| `bad delimiter at record N` | 偏移映射错 / 不是 ECE 流 | 查 4.1 公式 |
| `unable to authenticate data` | key 错 / seq 错 / chunk 边界错 | 先 probe 单块 |
| `chunk N range X-Y: HTTP 403` | 签名过期且重签失败 | 重签逻辑 `openRange` |
| `chunk N: upstream ended early` | R2 返回短读 | 网络/超时 |
| aria2 `error 13` | 文件已存在且不允许覆盖 | 已有 skip 逻辑，检查 `--only` |
| aria2 `error 32` | `--expect-sha256` 不匹配 | 传输损坏或源变更 |
| aria2 起不来 | 端口/权限/路径 | `Aria2.start()` 的 stderr 拼进异常 |
| 下载卡住不动 | 上游挂起 | 已加 30 s 超时；internal 引擎无重试 |
| exe 被 SmartScreen 拦 | 未签名 | 正常，让用户选"仍要运行" |

---

## 8. 已知债务

### 正确性
1. **多 chunk 未验证**（最重要）。只用一个 `chunks=1` 的 10 MB 样本测过。跨 chunk 拼接、每 chunk 独立 seq、末块短 record —— 代码写了，没跑过真实数据。
2. **internal 引擎无分段重试**。单次网络抖动 → 整轮失败（aria2 引擎有 `--max-tries=5`）。
3. **`--conn` 与 aria2 的 `split` 直接透传**，没有按文件大小做合理性约束（小文件开 32 连接会适得其反）。
4. **sha256 校验是"下载后全量重读"**。50 GB 会多花几分钟 IO。应做成 `--no-hash` 或边下边算。

### 可维护性
5. **`cli.js` 单文件约 700 行**。ECE / API / 代理 / 两个引擎 / CLI 全在一起。SEA 只支持单入口，所以要拆模块必须引入打包器（esbuild）。
6. **无自动化测试**。所有验证靠手工（见第 10 节）。
7. ~~构建不可复现~~ → 已由 `build.mjs` + 三个 workflow 解决（见第 11 节）；仍缺 CI 里的真实下载冒烟测试。
8. **三份漂移的实现**（`serve.mjs` / `probe.mjs` / `*.py`）。
9. **无 `package.json` / `LICENSE`**（`.gitignore` 已补）。

### 体验
10. **`--engine auto` 是默认**：同一份 exe 在不同机器上行为不同（有/无 aria2），支持成本翻倍。建议文档里显式提醒。
11. **进度条不判断 TTY**，重定向到文件会刷几千个 `\r`。
12. **`serve` 永不退出**（`await new Promise(() => {})`），只能 Ctrl+C，没有优雅关闭。
13. **文件名未处理 Windows 保留名**（`CON`、`NUL`、`COM1`）。

### 分发
14. **exe 67 MB + 未签名**。SmartScreen 拦截、杀软误报都是现实问题。
15. **SEA 注入破坏 Authenticode**（构建时 postject 会警告），无法简单签名。

---

## 9. 变更指南（改哪里会炸）

| 你想改 | 需要动 | 注意 |
|---|---|---|
| 分段大小（默认 8 MiB） | `SEG_SIZE`（`cli.js:31`） | 已有 `.part.json` 会因 `seg` 不匹配而失效 → 触发重下（安全） |
| 换并发模型 | `downloadInternal` 的 `queue/worker`（`cli.js:355-440`） | 必须保持"整段完成才置位" |
| 加一个新命令 | `main()` 分发 + `usage()` | SEA 下 `process.argv` 正常 |
| 改代理行为 | `startProxy()`（`cli.js:273`） | **aria2 引擎和 `serve` 共用**，改完两边都要回归 |
| 换 API 端点 | `listFiles` / `signChunk` | 只有这两处联网 |
| 支持密码链接 | `parseShare` + `keysFor` | 密码参与 key 派生，需要逆向 |
| 升级 Node | `sea-config.json` + 重建 | 新 Node 的 SEA 要求可能变（如 `require` 语义） |
| 拆模块 | 引入 esbuild → 输出单 CJS | 拆完再打包，SEA 只认单入口 |

---

## 10. 验证手册（回归清单）

### 10.1 固定基准（每次改完都跑）

需要一个可用链接。用 `probe` 记录：`filesize`、`chunks`、`chunksize`、`sha256`（第一次 `get` 后记下来）。之后所有测试都对这一个 sha256。

```powershell
.\filekiwi.exe probe "<link>"
.\filekiwi.exe get "<link>" -o t1 --engine internal --conn 4
.\filekiwi.exe get "<link>" -o t2 --engine aria2  --conn 8
Get-FileHash t1\* -Algorithm SHA256   # 两者必须相同
```

### 10.2 必测的四个边界

1. **单字节边界**：`curl -r 0-0` → 应 206 + `Content-Range: bytes 0-0/<size>`
2. **末尾**：`curl -r <size-16>-` → 16 字节，不多不少
3. **越界**：`curl -r <size>-` → 416
4. **中断**：下到一半 Ctrl+C，重跑 → internal 应打印 `resuming: N/M segments already complete`

### 10.3 位图续传的毒丸测试（验证第 4.5 节没被改坏）

```powershell
# 1. 完整下一份，改名成 .part
# 2. 把尾部 5 MiB 清零
# 3. 写 sidecar，标记前 5 段有效（seg 用 1 MiB 便于测试）
$env:FK_SEG_SIZE="1048576"
'{"size":<size>,"seg":1048576,"done":[true,true,true,true,true,false,...]}' > X.part.json
# 4. 重跑，必须打印 resuming: 5/N，且最终 sha256 正确
```

> 这条测试是项目里唯一"能证明续传不损坏数据"的手段，别删。

### 10.4 可自动化（还没做）

- ECE 已知向量（拿一个 chunk 的密文 + 期望明文，单测 `decryptRecord`）
- `plainRange` 随机区间 vs 全量下载对拍（属性测试，最容易抓偏移 bug）
- 代理契约测试（起 `startProxy`，用 curl 打 4 种 Range）

---

## 11. 发布流程

版本号沿用 **yt-dlp 的规则**（tag 不带 `v`）：

| 渠道 | 版本格式 | tag | 发布类型 |
|---|---|---|---|
| stable | `YYYY.MM.DD`（同日第二次发版用 `YYYY.MM.DD.N`） | 同版本号 | 正式 release |
| nightly | `YYYY.MM.DD.HHMMSS`（UTC） | `nightly`（每次滚动覆盖） | pre-release |

版本号**不写死在仓库里**：`cli.js` 顶部的 `VERSION`/`CHANNEL` 是开发占位值，
`build.mjs` 在构建时把它替换进 `build/cli.js` 再打包（等价于 yt-dlp 的
`devscripts/update-version.py` 生成 `version.py`）。

### 本地构建（在目标平台的宿主机上）

```powershell
npm ci                                    # 装 postject（版本锁在 package-lock.json）
node build.mjs --version 2026.10.27 --channel stable --target win-x64 --git-head $(git rev-parse --short HEAD)
# 产物：dist/filekiwi-2026.10.27-win-x64.zip + dist/SHA2-256SUMS.win-x64
```

`build.mjs` 会依次做：校验版本 → 打补丁 → `--experimental-sea-config` →
准备目标架构的 Node 基底 → `postject` 注入（版本与 `package.json` 核对）→
平台相关收尾（macOS ad-hoc 签名 / POSIX chmod）→ 打包 → 算 `SHA2-256SUMS.<target>`。

**跨架构可以，跨 OS 不行**（`build.mjs` 会直接报错）：SEA 本质是往某个 Node 二进制里塞 blob，
所以 arm64 产物是"下载官方 arm64 Node + 注入同一个 blob"得到的；而 macOS 必须在 macOS 上
签名、Windows 用 zip/PowerShell、POSIX 用 tar 保执行位。

### 矩阵

| target | runner | 基底 | 说明 |
|---|---|---|---|
| `win-x64` | windows-latest | 宿主 node | 冒烟测试跑得动 |
| `win-arm64` | windows-latest | 下载 `node-v<V>-win-arm64` | 交叉注入 |
| `linux-x64` | ubuntu-latest | 宿主 node | 冒烟测试跑得动 |
| `linux-arm64` | ubuntu-latest | 下载 `node-v<V>-linux-arm64` | 交叉注入 |
| `macos-x64` | macos-13 | 宿主 node | 原生 + ad-hoc 签名 |
| `macos-arm64` | macos-14 | 宿主 node | 原生 + ad-hoc 签名 |

> SEA blob 与架构无关的前提：`useSnapshot` / `useCodeCache` 都是 `false`（见 `build.mjs`）。
> 如果哪天打开了 snapshot，跨架构注入就会失效。

`collect` job 把六个 artifact 收齐，重新算一份统一的 `SHA2-256SUMS` 再交给发布 job。

### CI

| 工作流 | 触发 | 行为 |
|---|---|---|
| `.github/workflows/build.yml` | 被下面两个调用 | 6 个 target 矩阵构建 → 冒烟测试 → 汇总校验和 |
| `.github/workflows/release.yml` | 推 `YYYY.MM.DD` 形式的 tag；或手动 dispatch | 解析版本 → 构建 → 打 tag（手动时）→ `gh release create` |
| `.github/workflows/nightly.yml` | 每天 04:00 UTC；或手动 | 生成 `YYYY.MM.DD.HHMMSS` → 删除旧 `nightly` → 重建 pre-release |

发一个正式版（两种方式）：

```bash
git tag 2026.10.27 && git push origin 2026.10.27   # 方式一：推 tag
# 方式二：Actions → Release → Run workflow → version 留空（用当天 UTC 日期）
```

### 发布前检查

- `node --check cli.js`
- 本机跑一次 `--engine internal` 和 `--engine aria2`，sha256 一致
- 下完 `ps`/`Get-Process aria2c` 应为 0
- 解压对应格式（zip / tar.gz），从**别的目录**运行 `filekiwi --version`（确认没有相对路径依赖）
- `SHA2-256SUMS` 与产物对得上
- arm64 产物至少在一台真机（或 `windows-11-arm` runner）上跑一次 `--version` + 一次小文件下载

### 注意事项

- CI 里 Node 版本是**固定**的（`20.18.0`）：所有产物都是"复制该版本 Node 再注入"，改版本等于换全部产物。
- `postject` 版本也固定（`1.0.0-alpha.6`），`build.mjs` 启动时与 `package.json` 核对。
- SEA **不能跨 OS**（Windows 主机出不了 Linux 产物），但**可以跨架构**（x64 机器能出 arm64）。
- 注入会破坏原有签名：Windows 上 `postject` 会警告 `signature seems corrupted`（预期）；
  macOS 上则是先 `codesign --remove-signature`、注入后 `codesign --sign -` 做 ad-hoc 签名。
- macOS 产物未做公证（notarization），首次运行可能需要 `xattr -d com.apple.quarantine`。

---

## 12. 决策记录

| 决策 | 原因 | 代价 |
|---|---|---|
| 用 Node SEA 而不是重写 .NET/Go | 复用已验证的 JS 逻辑，零依赖 | 67 MB、未签名、SEA 实验特性 |
| 解密做在代理里，而不是 PostProcessor | 流式、磁盘 1x、aria2 直接可用 | 要维护一个 HTTP 服务 |
| 分段固定 8 MiB + 位图 | 唯一能安全续传的做法 | 需要 sidecar 文件 |
| `--engine auto` 默认 | 用户装了 aria2 就自动享受多连接 | 跨机器行为不一致 |
| 逐 record 流式解密（不是攒窗口） | TTFB 从"下载 4 MiB 的时间"降到 1 个 RTT | 代码复杂度略高 |
| 签名按 chunk 缓存 | 每 4 MiB 一次 API 调用会拖慢并可能触发限流 | Map 需要淘汰策略 |

---

## 13. 如果只做三件事

1. **加一个多 chunk 的真实样本测试**（第 8.1 条）——这是最大的未知。
2. **把 4 份实现收敛成 1 份 + 加 3 个自动化测试**（第 8.5/8.6/8.8 条）。
3. 发布链路已经自动化（`build.mjs` + GitHub Actions），下一步是把第 10.2/10.3 节的手工回归也搬进 CI。

其余都可以等真有用户反馈再说。

---

*最后更新：v0.2.0。维护者接手时请先读第 3、4 节，再跑第 10.1 节的四步验证。*
