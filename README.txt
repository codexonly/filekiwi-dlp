filekiwi {{VERSION}} — file.kiwi 分享链接下载器（非官方 demo）
================================================================

构建日期：{{DATE}}

单文件可执行程序，无需安装 Node / Python。
内置解密（RFC 8188 aes128gcm），密钥只存在于链接的 # 片段里，服务器拿不到明文。

支持的平台（同一套代码，按目标平台打包）

  win-x64 / win-arm64        filekiwi.exe        （zip）
  linux-x64 / linux-arm64    filekiwi            （tar.gz）

  不提供 macOS 构建。

Linux 第一次运行：

  tar -xzf filekiwi-<版本>-<平台>.tar.gz
  chmod +x filekiwi
  ./filekiwi --version

两种下载引擎，一个参数切换：

  --engine internal   程序自己下载
  --engine aria2      程序自动拉起 aria2c、自己分配私有 RPC 端口、
                      自己收进度、下完自己关掉 —— 不需要你先开任何服务
  --engine auto       有 aria2c 就用 aria2，没有就用 internal（默认）


用法
----

  filekiwi.exe probe <链接>
      列出文件、解密文件名、验证第一块能否解开。

  filekiwi.exe get <链接> [-o 目录] [选项]
      下载。支持并发、断点续传、sha256 输出与校验。

  filekiwi.exe serve <链接> [--port 8770]
      只起本地解密代理，不再自动下载（给手动实验/其他工具用）。

get 选项
  -o, --dir <path>         输出目录（默认当前目录）
      --only <text>        只下载文件名包含该文字的文件
      --conn <n>           并发连接数（默认 8，最大 32）
      --engine <mode>      internal | aria2 | auto（默认 auto）
      --aria2c <path>      指定 aria2c 路径（默认自动探测 PATH / D:\aria2 等）
      --expect-sha256 <hex>  结束后校验，不一致则退出码 1


示例
----

  filekiwi.exe probe "https://file.kiwi/<roomid>#<secretKey>"

  rem 自动选择引擎（装了 aria2 就用 aria2）
  filekiwi.exe get "https://file.kiwi/<roomid>#<secretKey>" -o D:\downloads

  rem 强制内置引擎，16 连接
  filekiwi.exe get "..." -o D:\downloads --engine internal --conn 16

  rem 强制 aria2 引擎（程序自动管理进程，无需手动启动）
  filekiwi.exe get "..." -o D:\downloads --engine aria2 --conn 16

  rem 下载后校验
  filekiwi.exe get "..." --expect-sha256 <sha256>


aria2 引擎怎么工作
------------------

  1. 探测 aria2c（--aria2c > 环境变量 ARIA2C > PATH > 常见安装目录）
  2. 随机挑一个空闲端口，用 --no-conf 启动一个私有 aria2 实例
     （不看你的 aria2.conf，不会和你已有的下载器抢端口）
  3. 把内置解密代理的 localhost URL 通过 JSON-RPC 交给它
  4. 每 300ms 拉一次 tellStatus 显示进度
  5. 结束（成功/失败/Ctrl+C）时调用 aria2.shutdown 优雅退出；
     另外启动时带了 --stop-with-process=<本进程PID>，
     就算主进程被强杀，aria2 也会跟着退出，不会留后台残留


续传
----

  internal 引擎：固定 8 MiB 分段 + 旁挂 .part.json 位图。
      只有"整段写完且每条 64 KiB 记录都通过 GCM 校验"的段才会被标记完成，
      所以并发下载中途断掉也不会把空洞当成已完成数据。

  aria2 引擎：用 aria2 自己的 .aria2 控制文件。

  两者都支持：重跑同一条命令即可接着下。
  注意两个引擎的中间文件互不识别（internal 的 .part 不能给 aria2 续）。


已知限制
--------

  * 只用 10 MB、单 chunk 的样本实测；多 chunk / 几十 GB 未验证。
  * 不支持带密码的链接（会明确报错）。
  * aria2 引擎需要本机已安装 aria2c（程序会自己找，但不会帮你装）。
  * 免费下载窗口：<10GB 48h，10–20GB 12h，>=20GB 6h，过期后无法下载。
  * exe 未签名（node.exe 注入），Windows SmartScreen 可能提示 → “更多信息 → 仍要运行”。
  * 不提供 macOS 构建（SEA 产物需要 ad-hoc 签名，未纳入 CI）。
  * arm64 版本是在 x64 机器上把 blob 注入官方 arm64 Node 生成的，
    未在真实 arm64 硬件上跑过（CI 里也没有 arm 冒烟测试）。
  * 需要能访问 file.kiwi 和 *.r2.cloudflarestorage.com。
  * 控制台中文乱码先执行 chcp 65001。

  合规提醒：只下载你有权访问的内容，注意分享方的服务条款。


文件清单
--------

  filekiwi.exe     单文件可执行程序（内含 Node 运行时）
  cli.js           源码（单文件、零依赖，可直接 node cli.js 运行）
  README.txt       本文件
  build-info.txt   版本 / 渠道 / git commit / 构建环境
