/**
 * 基线界面入口（对应设计文档 §14.5 H1）。
 *
 * ## 定位
 * 「内置最小基线 + 远程热更」中的**内置**那半：不承诺功能完整，只保证四件事——
 *   ① 能渲染（哪怕脚本挂了也有静态骨架兜住）；
 *   ② 能展示连接错误态（服务端不可达时给明确文案，绝不白屏）；
 *   ③ 能提示需要更新（壳能力缺失时按钮置灰 + reason）；
 *   ④ 能打开设置页。
 *
 * ## 为什么全是原生 DOM
 * 体积预算 ≤0.6MB 且要被打进客户端二进制 —— 一个 React + 组件库起步就是 150KB+。
 * 这张界面只有 3 个按钮 2 个状态块，原生 DOM 足够，且零运行时依赖（不会被
 * 远程热更的依赖版本拖累）。
 *
 * ## 为什么先把骨架写在 index.html
 * 本文件只做「增强」。若它加载失败（旧壳 CSP、资源 404、运行期异常），静态 HTML
 * 仍能让用户看到标题与说明。白屏是最坏结果，任何兜底都优于白屏。
 */

import { COMMANDS, NO_TAURI_REASON, call, probeMany, type CapState } from '../desktop/tauriBridge'

/** 服务端探测超时：3s（§14.5 明确指定）。桌面壳启动即探测，不能长时间挂着转圈 */
const HEALTH_TIMEOUT_MS = 3000

/** 服务端探测结果。用判别式联合而非多字段布尔，避免出现「不可达却又有版本号」的非法态 */
type ServerState =
  | { kind: 'ok'; version: string; protocol: string }
  | { kind: 'down'; detail: string }

/** /healthz 响应体最小子集（字段名属外部契约，见 harness_go internal/observ/observ.go） */
interface HealthBody {
  status?: string
  version?: string
  protocol_version?: string
}

/* ============ DOM 小工具 ============ */

function el<T extends HTMLElement>(selector: string): T | null {
  return document.querySelector<T>(selector)
}

/** 写状态卡：state 驱动左侧色条，cls 驱动文字颜色 */
function setStatus(
  root: HTMLElement | null,
  state: 'checking' | 'ok' | 'warn' | 'error',
  text: string,
  tone: 'ok' | 'error' | 'muted' = 'muted',
): void {
  if (!root) return
  root.dataset['state'] = state
  const detail = root.querySelector<HTMLElement>('.line-detail')
  if (!detail) return
  detail.textContent = text
  detail.className = `line-detail is-${tone}`
}

/* ============ 服务端探测 ============ */

/**
 * 探测服务端健康度。
 *
 * 用 `location.origin + '/healthz'` 而不是写死 host：壳会在不同端口/协议下加载本页
 * （dev 走 vite、prod 走壳内 http/asset 协议），与前端既有 `toAbsolute`
 * （${location.origin}${path}，见 harness_go/web/src/lib/api.ts）保持同一约定。
 *
 * 任何异常（超时 / 网络错误 / 非 2xx / 非 JSON）都归一成 `down` 而**不抛**：
 * 这是兜底界面，它自己没有「上一级」可以接错误。
 */
async function probeServer(): Promise<ServerState> {
  const origin = location.origin
  // 边界：以 file:// 或自定义 asset 协议加载时 origin 可能为 "null"，
  // 拼出来是 "null/healthz"，fetch 只会给出难以解释的报错。提前判掉，给一句人话。
  if (!origin || origin === 'null' || origin === 'file://') {
    return { kind: 'down', detail: '页面以本地文件方式加载，无法定位服务端地址' }
  }
  const url = `${origin}/healthz`
  // AbortController 而非 Promise.race：race 之后的请求仍会跑完并占连接，
  // abort 能真正掐掉（壳内单页场景下这点资源也值得省）。
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), HEALTH_TIMEOUT_MS)
  try {
    const res = await fetch(url, { signal: ac.signal, cache: 'no-store' })
    if (!res.ok) return { kind: 'down', detail: `HTTP ${res.status}` }
    const body = (await res.json()) as HealthBody
    if (body.status && body.status !== 'ok') {
      return { kind: 'down', detail: `状态 ${body.status}` }
    }
    return {
      kind: 'ok',
      version: body.version ?? '未知',
      protocol: body.protocol_version ?? '未知',
    }
  } catch (err) {
    // 超时表现为 AbortError；网络错误表现为 TypeError。文案里区分开，便于用户自查
    const aborted = err instanceof Error && err.name === 'AbortError'
    return {
      kind: 'down',
      detail: aborted ? `${HEALTH_TIMEOUT_MS / 1000}s 超时` : '网络不可达',
    }
  } finally {
    clearTimeout(timer)
  }
}

/* ============ 能力探测与按钮门禁 ============ */

/** 界面上的三个按钮 → 对应壳命令（单一数据源，避免 HTML 与逻辑漂移） */
const BUTTON_COMMANDS = [COMMANDS.checkUpdate, COMMANDS.openSettings, COMMANDS.openLogs] as const

/**
 * 把能力状态落到按钮上：**可用才放开点击，不可用就置灰并写明 reason**。
 *
 * 这是 §14.6 的核心体验取舍：远程 UI 可能比壳新，旧壳缺命令是常态。
 * 「点了才报错」会让用户以为程序坏了；「置灰 + 说明请升级」则是可解释的降级。
 */
function applyCapability(states: Map<string, CapState>): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('button[data-cmd]')
  buttons.forEach((btn) => {
    const cmd = btn.dataset['cmd'] ?? ''
    const state = states.get(cmd)
    const reasonBox = el<HTMLElement>(`[data-reason-for="${cmd}"]`)

    if (state && state.ok) {
      btn.disabled = false
      btn.removeAttribute('title')
      if (reasonBox) reasonBox.textContent = ''
      return
    }

    // 兜底：未探测到该命令也按不可用处理（fail-closed，与 hd-core Guarded 同一取向）
    const reason = state ? state.reason : '能力未探测，暂不可用'
    btn.disabled = true
    btn.setAttribute('title', reason)
    if (reasonBox) reasonBox.textContent = reason
  })
}

/** 能力区总览文案：区分「浏览器端」「壳太旧」「部分可用」三档 */
function summarizeCapability(states: Map<string, CapState>): void {
  const root = el<HTMLElement>('#capability-status')
  const entries = [...states.values()]
  const okCount = entries.filter((s) => s.ok).length

  if (okCount === entries.length && entries.length > 0) {
    setStatus(root, 'ok', '客户端能力清单已就绪，全部功能可用。', 'ok')
    return
  }
  if (okCount === 0) {
    const first = entries[0]
    const reason = first && !first.ok ? first.reason : '未知原因'
    // 浏览器端不是「故障」，因此用 warn 而不是 error
    const inBrowser = reason === NO_TAURI_REASON
    setStatus(
      root,
      inBrowser ? 'warn' : 'error',
      inBrowser
        ? `${NO_TAURI_REASON}：本机能力不可用，仅可查看当前页面信息。`
        : `${reason}。本机功能已置灰，避免点击后才报错。`,
      inBrowser ? 'muted' : 'error',
    )
    return
  }
  setStatus(
    root,
    'warn',
    `部分能力不可用（可用 ${okCount}/${entries.length}），不可用项已置灰并标注原因。`,
    'muted',
  )
}

/* ============ 诊断信息 ============ */

function renderDiagnostics(server: ServerState, hasTauri: boolean): void {
  const box = el<HTMLElement>('#diag')
  if (!box) return
  const parts = [
    `页面 ${location.href}`,
    `运行形态 ${hasTauri ? '桌面客户端' : '浏览器'}`,
    `服务端 ${server.kind === 'ok' ? `v${server.version}（协议 ${server.protocol}）` : `不可达：${server.detail}`}`,
  ]
  box.textContent = parts.join(' · ')
}

/* ============ 按钮行为 ============ */

/**
 * 绑定按钮点击。所有壳调用只走 `call()`（它永不 throw），因此这里没有 try/catch；
 * 只要拿到 null 就翻译成一句人话提示。
 */
function bindActions(): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('button[data-cmd]')
  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      void handleAction(btn)
    })
  })
}

const ACTION_FEEDBACK: Record<string, string> = {
  [COMMANDS.checkUpdate]: '已请求检查更新（若壳返回新版本会另行提示）',
  [COMMANDS.openSettings]: '已请求打开设置页',
  [COMMANDS.openLogs]: '已请求打开日志',
}

async function handleAction(btn: HTMLButtonElement): Promise<void> {
  const cmd = btn.dataset['cmd'] ?? ''
  const reasonBox = el<HTMLElement>(`[data-reason-for="${cmd}"]`)
  // 置灰期间不应触发，但双击/键盘仍可能挤进来；再判一次最稳
  if (btn.disabled) return

  const result = await call<unknown>(cmd)
  if (!reasonBox) return
  // 用 reason 行复用为「操作反馈」：不新增 DOM 结构，减少基线维护面
  reasonBox.textContent =
    result === null
      ? `命令 ${cmd} 未成功（详见开发者控制台），请重试或升级客户端`
      : (ACTION_FEEDBACK[cmd] ?? `命令 ${cmd} 已执行`)
}

/* ============ 启动 ============ */

export async function bootstrap(): Promise<void> {
  const hasTauri = typeof (globalThis as { __TAURI__?: unknown }).__TAURI__ === 'object'

  // 两个探测并行：壳能力走 IPC（快），服务端走网络（可能 3s）。
  // 串行会让用户先看 3s 空白，这段等待在兜底界面上尤其刺眼。
  const serverPromise = probeServer()
  const capPromise = probeMany(BUTTON_COMMANDS)

  bindActions()

  // 先把能力结果落地（通常 IPC 先回），用户最快的可点反馈来自这里
  const states = await capPromise
  applyCapability(states)
  summarizeCapability(states)

  const server = await serverPromise
  if (server.kind === 'ok') {
    setStatus(
      el<HTMLElement>('#server-status'),
      'ok',
      `服务端可达：v${server.version}（协议 ${server.protocol}）。远程 UI 可正常加载。`,
      'ok',
    )
  } else {
    // §14.5 要求原文照抄这句 —— 它是用户在此状态下唯一能看懂的解释
    setStatus(
      el<HTMLElement>('#server-status'),
      'error',
      `服务端不可达，当前为内置基线，仅可查看本地信息（${server.detail}）`,
      'error',
    )
  }

  renderDiagnostics(server, hasTauri)
}

// module 脚本天然 defer，DOM 已解析完毕；再判一次是为了兼容被动态 import 的场景
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => void bootstrap(), { once: true })
} else {
  void bootstrap()
}
