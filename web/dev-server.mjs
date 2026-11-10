/**
 * 开发态 dev server（Tauri `devUrl` 指向它，实现前端热更）。
 *
 * 为什么**不引 vite**（这是本节最重要的设计取舍，勿"优化"掉）：
 *  - 本 web 工程是「零运行时依赖 + 手写 CSS + 原生 DOM」的极简基线，
 *    package.json 只有 esbuild 与 typescript 两个 devDependency；
 *    引 vite 会连带 rollup / postcss / es 系列传递依赖，破坏零依赖哲学，
 *    且在没有离线 registry 的环境上直接触发联网安装（构建不可复现）。
 *  - 本工程连 vite.config.ts 都没有，vite 的「约定式入口 + 插件链」在这里
 *    全无收益：我们只需要「一个入口打包 + 三个静态文件」。
 *  - esbuild 本身自带 watch（context().watch()），用它就能实现「改源码 → 重建 → 浏览器刷新」，
 *    消费面（打包语义）与 build-baseline.mjs 完全一致。
 *
 * 🔴 与 build-baseline.mjs 的口径对齐（最容易埋的坑：dev 看着正常、build 出来挂）：
 *  - 入口固定 src/baseline/main.ts，产物名 main.js（outdir 模式下由入口名推导）；
 *  - bundle / format=esm / target=es2020 / legalComments=none 四项**必须**与 build 脚本同值：
 *    这四项决定产物语义（模块形态、降级目标、注释剥离），一旦分叉就会出现
 *    「dev 能跑、npm run build 产物行为不同」的诡异问题；
 *  - **刻意不同**的只有两项，且只影响可调试性、不影响语义：
 *      minify: false（dev 保留可读代码）、sourcemap: 'inline'（devtools 可直接看 .ts）。
 *  - 产物目录刻意用 `.dev-out/` 而非 `dist-baseline/`：build-baseline.mjs 开工第一步是
 *    `rm -rf dist-baseline`，若两者共用目录，一次 `npm run build` 就会把 dev server
 *    正在服务的产物删掉（Windows 上还会因文件占用直接报 EBUSY）。
 *
 * 端口为何固定 1420：
 *  - Tauri 官方 dev server 惯例端口，生态里不与其他工具抢；
 *  - 本项目其它常驻服务的端口已占用 5610/5611/5612（demo 三端口）与 8080 之外的段位，
 *    1420 与之无冲突；
 *  - 关键：端口要同时写进三处（本脚本、tauri.conf.json 的 devUrl、CSP 白名单），
 *    固定值才能做「三方一致性自检」；随机端口会让 CSP 与 devUrl 静默失配。
 *    因此端口被占用时**必须显式失败**，绝不自动换端口开个"看起来成功"的服务。
 */

import { context } from 'esbuild'
import http from 'node:http'
import { promises as fs, createReadStream } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))

/** esbuild dev 产物目录（与 build-baseline 的 dist-baseline 刻意分离，见文件头注释） */
const DEV_OUT = path.join(here, '.dev-out')
/** tauri.conf.json：位于仓库根下的 crates/hd-host/，与 web/ 同级 */
const TAURI_CONF = path.join(here, '..', 'crates', 'hd-host', 'tauri.conf.json')

const DEFAULT_PORT = 1420
const PORT = readPortArg()
const DEV_ORIGIN = `http://localhost:${PORT}`

/**
 * 后端（harness_go 服务端）默认基址：127.0.0.1:5611，与 hd-host 的
 * `bootstrap::default_http_url()` 保持同源同端口（那里刻意用 127.0.0.1 而非 localhost）。
 *
 * 为什么 dev server 要反代 /healthz（这条极易被忽略）：
 * baseline 的 `probeServer()` 用 `location.origin + '/healthz'` 探测（见 src/baseline/main.ts），
 * 这在 prod 下 origin 就是后端，天然正确；但 dev 态 origin 变成 `http://localhost:1420`，
 * 探测会打到本 dev server 身上 → 404 → 界面永远显示「服务端不可达」，把真实状态掩盖成假故障。
 * 因此这里把 /healthz 反代到真后端：后端活着就透传真 JSON，死了就 502 且如实说明。
 * 🔴 绝不返回伪造的 `{"status":"ok"}`：伪装健康是本项目明令禁止的（tone 语义同理）。
 */
const BACKEND_ORIGIN = readArg('--backend') ?? 'http://127.0.0.1:5611'

/** 只接受本机 Host，防 DNS rebinding；同时兼容 localhost 解析成 ::1 的情况 */
const ALLOWED_HOSTS = new Set([
  `localhost:${PORT}`,
  `127.0.0.1:${PORT}`,
  `[::1]:${PORT}`,
])

/** 静态源文件白名单：dev server 只对外暴露这三个 + esbuild 产物，绝不整目录静态托管 web/ */
const STATIC_ROUTES = new Map([
  ['/', { file: path.join(here, 'index.html'), type: 'text/html; charset=utf-8', injectReload: true }],
  ['/index.html', { file: path.join(here, 'index.html'), type: 'text/html; charset=utf-8', injectReload: true }],
  ['/styles.css', { file: path.join(here, 'styles.css'), type: 'text/css; charset=utf-8', injectReload: false }],
])

/** esbuild 产物路由（outdir/dev 双形态一致：入口 main.ts → main.js） */
const BUNDLE_ROUTES = new Map([
  ['/main.js', { file: path.join(DEV_OUT, 'main.js'), type: 'application/javascript; charset=utf-8' }],
])

/**
 * 热重载客户端：挂在 SSE 上，收到 reload 就整页刷新。
 * 用外部脚本而不是内联 script，是为了不必往 CSP 里加 'unsafe-inline'（同源 'self' 即可覆盖）。
 */
const RELOAD_CLIENT = `// dev-only 热重载客户端（由 dev-server.mjs 提供，不进生产产物）
(() => {
  const es = new EventSource('/__dev/events')
  es.addEventListener('reload', (ev) => {
    // 首次连接（reason=initial）不刷新，避免打开页面就自我重载一次
    if (ev.data === 'initial') return
    location.reload()
  })
  es.addEventListener('build-error', () => {
    // 构建失败时保留当前页面，只打日志：刷新会把用户手上的界面清空且看不到原因
    console.error('[hd-dev] 构建失败，详见 dev server 终端输出')
  })
  es.onerror = () => {
    // SSE 断开（dev server 重启）后浏览器会自动重连，这里刻意不弹窗
  }
})()
`

/** 已连接的 SSE 客户端；每个重建周期结束向它们广播 */
const clients = new Set()

/**
 * dev 态实际生效的 CSP 字符串（来源：tauri.conf.json 的 devCsp，缺省回落 csp）。
 *
 * 🔴 为什么必须由 dev server 亲自下发（这是本项最容易漏的一个坑）：
 * Tauri 2 只在壳自己的 asset 协议返回 HTML 时注入 CSP
 * （tauri-2.x `manager/mod.rs::get_asset` 的 `csp_header` 路径）。dev 态页面由本 dev server
 * 用 http 提供，壳**不会**替我们补这个头 —— 也就是说光改 tauri.conf.json 的 devCsp 只是
 * 「纸面一致」，实际热更态并没有任何 CSP 在生效。故这里读同一份配置并原样下发，
 * 让「配置怎么写 = 运行时就是什么」，改一处即可，不产生第二份手抄的 CSP。
 *
 * 每次请求都重新读文件（不缓存）：dev 期改 devCsp 应当立即生效，
 * 一个几百字节的 JSON 解析在本机毫无成本，缓存反而会制造"改了没用"的困惑。
 *
 * 读不到/解析失败时返回 undefined → 不发头（fail-open）：dev 态优先保证可用，
 * 但要打出告警，绝不静默假装有策略。
 */
async function loadDevCsp() {
  try {
    const conf = await readTauriConf()
    const security = conf.app?.security ?? {}
    const effective = security.devCsp ?? security.csp
    if (typeof effective === 'string' && effective.trim() !== '') return effective
  } catch {
    // 落到下面的统一告警
  }
  console.warn('[hd-dev] 未能从 tauri.conf.json 取到 CSP，本次响应不下发 CSP 头')
  return undefined
}

/** 通用 `--key value` 取值；缺省返回 undefined（不用默认值区分「没传」与「传了空」） */
function readArg(flag) {
  const idx = process.argv.indexOf(flag)
  return idx === -1 ? undefined : process.argv[idx + 1]
}

function readPortArg() {
  const raw = readArg('--port')
  if (raw === undefined) return DEFAULT_PORT
  const num = Number(raw)
  if (!Number.isInteger(num) || num <= 0 || num > 65535) {
    console.error(`[hd-dev] --port 取值非法：${raw}`)
    process.exit(1)
  }
  return num
}

/* ------------------------------------------------------------------ *
 * 1. esbuild：与 build-baseline.mjs 同口径 + watch + 重建广播
 * ------------------------------------------------------------------ */

/** 重建完成后的广播插件；initial 标记用于让首帧构建不触发页面刷新 */
let firstBuildDone = false

/**
 * 首帧构建的挂起点。
 *
 * main() 用它把「已启动」日志推到产物**真正落地之后**：否则会出现
 * 「控制台已打印已启动，页面 /main.js 却 404」的误导（首帧构建是异步的）。
 */
let resolveFirstBuild = null
const firstBuildLanded = new Promise((resolve) => {
  resolveFirstBuild = resolve
})

/** 只结算一次：首帧之后的 rebuild 不该再影响启动流程 */
function settleFirstBuild(ok) {
  if (!resolveFirstBuild) return
  const done = resolveFirstBuild
  resolveFirstBuild = null
  done({ ok })
}

const reloadPlugin = {
  name: 'hd-dev-reload',
  setup(build) {
    build.onEnd((result) => {
      if (result.errors.length > 0) {
        // 不退出进程：语法错是开发态常态，保持 watch 让用户改完自动恢复
        console.error(`[hd-dev] 构建失败（${result.errors.length} 个错误），等待修复…`)
        broadcast('build-error', 'error')
        // 失败也要结算：否则 main() 会永远等不到首帧，连启动日志都打不出来
        settleFirstBuild(false)
        return
      }
      const reason = firstBuildDone ? 'rebuild' : 'initial'
      firstBuildDone = true
      if (result.warnings.length > 0) {
        console.warn(`[hd-dev] 构建告警 ${result.warnings.length} 条`)
      }
      broadcast(reason, reason)
      settleFirstBuild(true)
    })
  },
}

function broadcast(event, data) {
  for (const res of clients) {
    res.write(`event: ${event}\ndata: ${data}\n\n`)
  }
}

/* ------------------------------------------------------------------ *
 * 2. HTTP：静态白名单 + 产物 + SSE
 * ------------------------------------------------------------------ */

async function serveFile(res, filePath, type, { injectReload = false, csp } = {}) {
  try {
    if (injectReload) {
      const html = await fs.readFile(filePath, 'utf8')
      const tag = '<script type="module" src="/__dev/reload.js"></script>'
      // 注入到 </body> 之前；找不到 </body> 就退化为直接追加（畸形 HTML 也要能开发）
      const out = html.includes('</body>')
        ? html.replace('</body>', `  ${tag}\n  </body>`)
        : `${html}\n${tag}\n`
      const headers = {
        'Content-Type': type,
        // dev 态禁用缓存：否则改了 index.html 刷新看到的还是旧的
        'Cache-Control': 'no-store',
      }
      // 只有 HTML 文档能带 CSP（对 .js/.css 加无意义且会误导排障）
      if (csp) headers['Content-Security-Policy'] = csp
      res.writeHead(200, headers)
      res.end(out)
      return
    }

    await fs.stat(filePath) // 先探测，避免 createReadStream 的头已发出去才报错
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' })
    createReadStream(filePath).pipe(res)
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end(`404 not found: ${path.basename(filePath)}`)
  }
}

function openEventStream(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    // WebView2 下不加这行也能工作，但在部分代理/安全软件环境里会被缓冲成"一直不刷新"
    'X-Accel-Buffering': 'no',
  })
  // 首次连上先握个手，让浏览器认为连接已建立
  res.write('event: reload\ndata: initial\n\n')
  clients.add(res)

  // 心跳：防中间层按空闲超时掐断长连接（25s 远小于常见 60s 阈值）
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 25_000)

  const cleanup = () => {
    clearInterval(heartbeat)
    clients.delete(res)
  }
  req.on('close', cleanup)
  req.on('error', cleanup)
}

/**
 * 反代后端健康探针。
 *
 * 只放行 `/healthz` 一个路径（白名单，不做通用代理）：dev server 的职责是服务前端，
 * 不是当通用 HTTP 代理 —— 通用代理会顺带暴露后端全部鉴权端点给任意本机页面。
 * 用原生 fetch（Node 20 内置）而不是 node:http.request：少一层事件式样板，超时也能用 AbortSignal 表达。
 */
async function proxyHealthz(res) {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), 3000)
  try {
    const upstream = await fetch(`${BACKEND_ORIGIN}/healthz`, {
      signal: ac.signal,
      // 不转发浏览器的 Cookie/鉴权头：/healthz 是公开探针，转发反会带来凭据泄露面
      headers: { accept: 'application/json' },
    })
    const body = await upstream.text()
    res.writeHead(upstream.status, {
      'Content-Type': upstream.headers.get('content-type') ?? 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      // 让前端 devtools 一眼看出这是反代结果而非本 dev server 自己答的
      'X-HD-Dev-Proxy': BACKEND_ORIGIN,
    })
    res.end(body)
  } catch (err) {
    const aborted = err instanceof Error && err.name === 'AbortError'
    // 如实报故障：前端 probeServer 会把非 2xx 判成 down，界面显示「服务端不可达」——这正是事实
    res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
    res.end(
      JSON.stringify({
        status: 'dev-proxy-error',
        detail: aborted
          ? `后端探针超时（>3s）：${BACKEND_ORIGIN}/healthz`
          : `后端不可达：${BACKEND_ORIGIN}/healthz（${err.message}）`,
      }),
    )
  } finally {
    clearTimeout(timer)
  }
}

const server = http.createServer(async (req, res) => {
  const host = req.headers.host ?? ''
  if (!ALLOWED_HOSTS.has(host)) {
    // 非法 Host 直接拒绝：dev server 虽然只在开发态运行，也不该被任意站点跨源读写
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end('403 invalid host')
    return
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD' })
    res.end('405 method not allowed')
    return
  }

  const pathname = decodeURIComponent(new URL(req.url ?? '/', DEV_ORIGIN).pathname)

  if (pathname === '/__dev/events') {
    openEventStream(req, res)
    return
  }
  if (pathname === '/healthz') {
    await proxyHealthz(res)
    return
  }
  if (pathname === '/__dev/reload.js') {
    res.writeHead(200, {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-store',
    })
    res.end(RELOAD_CLIENT)
    return
  }

  const staticRoute = STATIC_ROUTES.get(pathname)
  if (staticRoute) {
    await serveFile(res, staticRoute.file, staticRoute.type, {
      injectReload: staticRoute.injectReload,
      // 只有 HTML 需要 CSP；由同一份 tauri.conf.json 驱动（见 loadDevCsp 注释）
      csp: staticRoute.injectReload ? await loadDevCsp() : undefined,
    })
    return
  }

  const bundleRoute = BUNDLE_ROUTES.get(pathname)
  if (bundleRoute) {
    await serveFile(res, bundleRoute.file, bundleRoute.type)
    return
  }

  // 兜底：esbuild 若将来开启 splitting/chunk，产物文件名不会回到白名单里。
  // 这里只放行「形如 <name>.js 且确实存在于 DEV_OUT」的文件，
  // 且用 basename 比对，杜绝 ../ 路径穿越（dev server 不以「只要没报错」为安全依据）。
  if (/^\/[A-Za-z0-9._-]+\.js$/.test(pathname)) {
    const candidate = path.join(DEV_OUT, path.basename(pathname))
    await serveFile(res, candidate, 'application/javascript; charset=utf-8')
    return
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
  res.end(`404 not found: ${pathname}`)
})

/* ------------------------------------------------------------------ *
 * 3. tauri.conf.json 三方一致性自检（devUrl ↔ CSP ↔ beforeDevCommand）
 *    热更能否真正生效，取决于这三个东西同时正确；漏一个都是"看似启动成功、实际白屏/IPC 被拦"。
 * ------------------------------------------------------------------ */

/**
 * 读取并解析 tauri.conf.json（统一入口）。
 *
 * 显式剥离 UTF-8 BOM：Windows 上记事本/PowerShell 重写会把 BOM 塞回文件头，
 * 而 `JSON.parse` 遇到 BOM 会直接抛 "Unexpected token '﻿'"——
 * 报错信息完全看不出是 BOM 问题，实测踩过一次。这里一次性抹平。
 */
async function readTauriConf() {
  const raw = await fs.readFile(TAURI_CONF, 'utf8')
  return JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw)
}

async function checkTauriConf() {
  const problems = []
  let conf
  try {
    conf = await readTauriConf()
  } catch (err) {
    problems.push(`无法读取/解析 ${TAURI_CONF}：${err.message}`)
    return problems
  }

  const build = conf.build ?? {}
  const security = conf.app?.security ?? {}
  const csp = typeof security.csp === 'string' ? security.csp : ''
  const devCsp = typeof security.devCsp === 'string' ? security.devCsp : ''

  if (build.devUrl !== DEV_ORIGIN) {
    problems.push(`build.devUrl = ${JSON.stringify(build.devUrl)}，应为 "${DEV_ORIGIN}"`)
  }
  if (typeof build.beforeDevCommand !== 'string' || build.beforeDevCommand.trim() === '') {
    problems.push('缺少 build.beforeDevCommand（Tauri dev 不会自动拉起本 dev server）')
  } else if (!build.beforeDevCommand.includes('dev-server.mjs') && !/run\s+dev/.test(build.beforeDevCommand)) {
    problems.push(`build.beforeDevCommand 未指向本 dev server：${build.beforeDevCommand}`)
  }
  if (build.frontendDist !== 'ui') {
    problems.push(`build.frontendDist = ${JSON.stringify(build.frontendDist)}，应为 "ui"（生产仍用它）`)
  }

  // dev 态实际生效的 CSP：有 devCsp 用 devCsp，否则回落到 csp（Tauri 2 语义）
  const effective = devCsp || csp
  if (!effective) {
    problems.push('app.security.csp 为空：dev 态页面将不受约束（也可能被 WebView 默认策略拦 IPC）')
  } else {
    const connect = /(?:^|;)\s*connect-src([^;]*)/.exec(effective)?.[1] ?? ''
    const hasOrigin =
      connect.includes(DEV_ORIGIN) || connect.includes(`http://127.0.0.1:${PORT}`) || connect.includes("'self'")
    if (!hasOrigin) {
      problems.push(`CSP 的 connect-src 未放行 ${DEV_ORIGIN}（IPC/健康探测会被拦）`)
    }
    if (!/ipc:/.test(connect) || !/http:\/\/ipc\.localhost/.test(connect)) {
      problems.push('CSP 的 connect-src 缺少 ipc: / http://ipc.localhost（Tauri IPC 通道）')
    }
    const defaultSrc = /(?:^|;)\s*default-src([^;]*)/.exec(effective)?.[1] ?? ''
    const scriptSrc = /(?:^|;)\s*script-src([^;]*)/.exec(effective)?.[1] ?? ''
    if (!defaultSrc.includes("'self'") && !scriptSrc.includes("'self'")) {
      // 注意：本工程刻意不写死 script-src，让 default-src 'self' 生效以保证 Tauri 自动注入 nonce 的机制不被破坏
      problems.push("CSP 的 default-src 未含 'self'（devUrl 源加载自身脚本会被拦）")
    }
  }
  return problems
}

/* ------------------------------------------------------------------ *
 * 4. 启动
 * ------------------------------------------------------------------ */

async function main() {
  // 🔴 顺序不变量（修复 D1，勿"优化"回原样）：
  //   listen → 只读自检 → 清产物 → 首帧构建 → 打印就绪
  // 为什么 listen 必须排在 fs.rm(DEV_OUT) 之前：
  //   DEV_OUT 是被**所有**本工程 dev server 实例共享的同一目录。若先 rm 再 listen，
  //   那么"端口已被占用"这件事要到 listen 阶段才暴露，而那时本进程已经把
  //   **正在运行的那个实例**的产物整个删掉了 —— 存活实例不会退出，但它的
  //   /main.js 从此永久 404（watch 只响应源文件内容变更，不会自愈）。
  //   典型案例：Tauri beforeDevCommand 重复拉起、两个终端并行 npm run dev。
  //   故先把「本进程到底能不能用这个端口」这个廉价且无副作用的问题问清楚，
  //   确认成功后才有资格动任何共享状态的磁盘内容。
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    // 不绑 host = 双栈监听：Windows 上 `localhost` 可能解析为 ::1，
    // 若只绑 127.0.0.1 会出现「devUrl 打不开但控制台没报错」。可达范围由 Host 头白名单收紧。
    server.listen(PORT, resolve)
  })

  // 自检是纯只读的，且最便宜、最能提前暴露"热更注定失效"，故放在任何磁盘写入之前
  const problems = await checkTauriConf()

  // 端口已确认归本进程所有，此处清空才是安全的：
  // 避免残留旧 bundle 被误当成本次构建结果（只在启动时清，watch 期间不动）
  await fs.rm(DEV_OUT, { recursive: true, force: true })

  const ctx = await context({
    entryPoints: [path.join(here, 'src/baseline/main.ts')],
    outdir: DEV_OUT, // 与 build 脚本的 outfile 等价：入口名 main.ts → main.js
    bundle: true,
    format: 'esm', // ← 与 build-baseline.mjs 同值（语义项，勿改）
    target: ['es2020'], // ← 同上
    legalComments: 'none', // ← 同上
    minify: false, // dev 期保留可读代码（仅影响体积，不影响语义）
    sourcemap: 'inline', // dev 期可断点到 .ts（仅影响调试体验，不影响语义）
    logLevel: 'warning', // 构建日志由 reloadPlugin 统一输出，避免双份噪音
    plugins: [reloadPlugin],
  })
  await ctx.watch() // 立即开始首帧构建并进入监听（首帧是异步的，见下）

  // 等首帧真正落地再报"就绪"：否则控制台说已启动、页面却 404（误导排障）
  const { ok } = await firstBuildLanded

  // 打印顺序刻意让「dev server 已启动」排在三方自检之后：
  // 一旦自检不一致，开发者会先看到具体问题，再看到（已降级为警告的）启动结论。
  if (problems.length === 0) {
    console.log('[hd-dev] 自检 tauri.conf.json：devUrl / CSP / beforeDevCommand 三方一致 ✅')
  } else {
    console.warn('[hd-dev] ⚠️ tauri.conf.json 自检发现不一致（热更会失效，请修正后重试）：')
    for (const p of problems) console.warn(`[hd-dev]   - ${p}`)
  }
  console.log('[hd-dev] dev server 已启动 ' + DEV_ORIGIN)
  console.log(`[hd-dev] 页面：${DEV_ORIGIN}/`)
  if (ok) {
    console.log(`[hd-dev] 产物：${path.relative(here, DEV_OUT)}（esbuild watch 中，改 src/** 自动重建并刷新）`)
  } else {
    // 首帧就构建失败：不能谎报产物就绪，但也不退出（改完源码会自动恢复）
    console.warn(
      `[hd-dev] 产物：${path.relative(here, DEV_OUT)} 首次构建未成功，页面暂时拿不到 /main.js（改好源码后自动重建）`,
    )
  }
  console.log('[hd-dev] 按 Ctrl+C 退出')
}

/** 端口占用等致命错误：必须显式失败并给出可操作提示，绝不静默换端口 */
function fatal(err) {
  if (err && err.code === 'EADDRINUSE') {
    console.error(`[hd-dev] 端口 ${PORT} 已被占用：本端口与 tauri.conf.json 的 devUrl 及 CSP 白名单绑定，`)
    console.error('[hd-dev] 不能自动改用其它端口。请先结束占用该端口的进程，或用 --port 改端口并同步更新配置。')
  } else {
    console.error('[hd-dev] 启动失败：', err)
  }
  process.exit(1)
}

process.on('uncaughtException', fatal)
process.on('unhandledRejection', fatal)

main().catch(fatal)
