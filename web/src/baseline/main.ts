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

import {
  COMMANDS,
  NO_TAURI_REASON,
  call,
  probe,
  probeMany,
  type CapState,
} from '../desktop/tauriBridge'
import { describeActionResult, toneToReasonClass } from '../desktop/actionFeedback'
import { describe, describeWithRestarts, type PhaseTone } from '../desktop/runnerPhase'

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
const BUTTON_COMMANDS = [
  COMMANDS.checkUpdate,
  COMMANDS.openSettings,
  COMMANDS.openLogs,
  // 解绑按钮也要参与能力探测：壳太旧时它必须置灰，而不是点了才报错。
  COMMANDS.unpairDevice,
] as const

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
      if (reasonBox) {
        reasonBox.textContent = ''
        // 重置色调类：否则上一次操作留下的 is-ok/is-warn/is-error 会残留到下一次反馈上
        reasonBox.className = 'reason'
      }
      return
    }

    // 兜底：未探测到该命令也按不可用处理（fail-closed，与 hd-core Guarded 同一取向）
    // 置灰原因是「需要看一眼的降级」而非故障：沿用 reason 行默认的 warn 色。
    const reason = state ? state.reason : '能力未探测，暂不可用'
    btn.disabled = true
    btn.setAttribute('title', reason)
    if (reasonBox) {
      reasonBox.textContent = reason
      reasonBox.className = 'reason'
    }
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

/* ============ 执行引擎状态 ============ */

/** `runner_status` 的响应形状（字段名属后端契约，见 hd-host/src/commands.rs）。 */
interface RunnerStatusBody {
  state?: string
  restarts?: number
  last_heartbeat_ms?: number
}

/**
 * 读取并渲染执行引擎状态。
 *
 * 失败时**不显示「未知错误」**：拿不到状态最常见的原因是壳太旧（没有
 * `runner_status` 这个 command），此时一句「请升级客户端」比报错有用得多。
 * 判定依据用 `probe()` 而不是猜错误文本 —— 与按钮置灰共用同一套能力清单。
 */
async function renderRunnerStatus(): Promise<void> {
  const root = el<HTMLElement>('#runner-status')
  if (!root) return

  const cap = await probe(COMMANDS.runnerStatus)
  if (!cap.ok) {
    setStatus(root, 'warn', cap.reason, 'muted')
    return
  }

  const raw = await call<RunnerStatusBody>(COMMANDS.runnerStatus)
  if (raw === null) {
    // 命令存在但调用失败：IPC 层异常，与「壳太旧」区分开。
    setStatus(root, 'error', '读取执行引擎状态失败（详见开发者控制台）', 'error')
    return
  }

  const d = describe(raw.state)
  const restarts = typeof raw.restarts === 'number' ? raw.restarts : 0
  let text = describeWithRestarts(raw.state, restarts)

  // 给「需要等待」的中间态补一句安心的说明，避免用户以为要手动操作。
  if (d.transient) {
    text += '，正在自动恢复，请稍候'
  }
  // 外部实例在跑时，本窗口改配置不生效 —— 必须说破，否则用户会反复点设置。
  if (raw.state === 'externally_running') {
    text += '。本窗口仅做状态监护，请在那个实例中修改配置'
  }

  // `PhaseTone` 有 muted（中性态），而 `setStatus` 的 state 只接受
  // checking/ok/warn/error —— 中性态在卡片色条上没有独立样式，
  // 映射到 checking（同样是无色条的灰态）。
  setStatus(root, toneToState(d.tone), text, toneToText(d.tone))
}

/** 把相位的语义色调映射到状态卡的 `data-state`（决定左侧色条）。 */
function toneToState(tone: PhaseTone): 'ok' | 'warn' | 'error' | 'checking' {
  switch (tone) {
    case 'ok':
      return 'ok'
    case 'warn':
      return 'warn'
    case 'error':
      return 'error'
    case 'muted':
      // 中性态没有专属色条，复用 checking 的灰态。
      return 'checking'
  }
}

/**
 * 把相位的语义色调映射到**文字**色调。
 *
 * 文字只有三档（ok / error / muted），没有 warn —— 这是刻意的：
 * `backoff`（重连中）、`needs_pairing`（待配对）这类"需要人看一眼但不算故障"
 * 的状态，用灰字配黄色条的组合表达，比整行飘红更准确。红字留给真正的故障。
 */
function toneToText(tone: PhaseTone): 'ok' | 'error' | 'muted' {
  switch (tone) {
    case 'ok':
      return 'ok'
    case 'error':
      return 'error'
    case 'warn':
    case 'muted':
      return 'muted'
  }
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
  [COMMANDS.unpairDevice]: '已解除配对：设备令牌已清除，请重新输入配对码完成绑定',
  // 工作区设置是**三态**命令（见 handleWorkspaceRootsResult），这里的文案只覆盖
  // 「已保存并同步」那一档；另两档由判据分支给出，故不放进这张表。
  [COMMANDS.setWorkspaceRoots]: '已保存并同步到执行引擎',
}

/**
 * 把一次操作的结果渲染到 reason 行，色调由 `describeActionResult` 判定。
 *
 * 🔴 为什么必须三态：后端 `set_workspace_roots` 的「已保存但未同步给执行引擎」
 * 是 `Ok(pushed=false, warning=...)`，不是 `Err`。若把它和 `null` 混为一谈，
 * 用户会看到「命令未成功」，而事实是配置**已经保存**了 —— 直接矛盾。
 * 所以 `pushed=false` 必须用 warn 色 + 后端下发的人话，而不是红字。
 *
 * 判定逻辑本身在 `desktop/actionFeedback.ts`（纯函数，可穷举单测）；
 * 这里只负责把结果写进 DOM，不做任何判断。
 */
function applyActionResult(cmd: string, raw: unknown, reasonBox: HTMLElement): void {
  const feedback = describeActionResult(cmd, raw, ACTION_FEEDBACK[cmd] ?? `命令 ${cmd} 已执行`)
  reasonBox.textContent = feedback.text
  reasonBox.className = toneToReasonClass(feedback.tone)
}

/**
 * 需要二次确认的命令及其确认文案。
 *
 * 为什么确认放在这里而不是 HTML 的 `onclick`：确认文案要与命令名**同源维护**，
 * 分散到 HTML 里一旦命令改名就会漏掉提示（用户可能就此误删了凭据）。
 *
 * 解除配对是**不可逆**的（密钥链条目被删除后无法恢复），因此必须拦一道。
 */
const CONFIRM_PROMPTS: Record<string, string> = {
  [COMMANDS.unpairDevice]:
    '确定要解除配对吗？\n\n' +
    '这会清除本机保存的设备令牌，且无法撤销。\n' +
    '解除后需要重新获取配对码才能继续使用本设备。',
}

async function handleAction(btn: HTMLButtonElement): Promise<void> {
  const cmd = btn.dataset['cmd'] ?? ''
  const reasonBox = el<HTMLElement>(`[data-reason-for="${cmd}"]`)
  // 置灰期间不应触发，但双击/键盘仍可能挤进来；再判一次最稳
  if (btn.disabled) return

  // 不可逆操作先确认。用户取消时保持原状态，不写任何反馈文案
  // （写「已取消」会让 reason 行看起来像出过错）。
  const prompt = CONFIRM_PROMPTS[cmd]
  if (prompt && !globalThis.confirm(prompt)) return

  const result = await call<unknown>(cmd)
  if (!reasonBox) return
  // 用 reason 行复用为「操作反馈」：不新增 DOM 结构，减少基线维护面。
  // 三档判定集中在 applyActionResult（ok / warn / error），红字只留给真故障。
  applyActionResult(cmd, result, reasonBox)

  // 解绑成功后刷新两张状态卡：相位已切到 needs_pairing、能力门禁也可能随之变化。
  if (cmd === COMMANDS.unpairDevice && result !== null) {
    await refreshStatusPanels()
  }
}

/* ============ 启动 ============ */

/**
 * 刷新两张设备侧状态卡（执行引擎 + 能力门禁）。
 *
 * 抽成函数供两处复用：首次启动、以及解绑成功后（相位变了、能力可能也变了）。
 * 不并入 `bootstrap` 是因为解绑后的刷新**不该重跑服务端探测** ——
 * 那会白等最多 3s，而服务端连通性并没有因为解绑而改变。
 */
async function refreshStatusPanels(): Promise<void> {
  // 两张卡并行：都属于本机 IPC，串行没有收益。
  await Promise.all([renderRunnerStatus(), refreshCapability()])
}

/** 重新探测能力并刷新按钮门禁与总览文案。 */
async function refreshCapability(): Promise<void> {
  const states = await probeMany(BUTTON_COMMANDS)
  applyCapability(states)
  summarizeCapability(states)
}

export async function bootstrap(): Promise<void> {
  const hasTauri = typeof (globalThis as { __TAURI__?: unknown }).__TAURI__ === 'object'

  // 三个探测并行：壳能力走 IPC（快），服务端走网络（可能 3s）。
  // 串行会让用户先看 3s 空白，这段等待在兜底界面上尤其刺眼。
  const serverPromise = probeServer()
  const capPromise = refreshCapability()
  // 执行引擎状态也走 IPC，与能力探测同时发起。
  const runnerPromise = renderRunnerStatus()

  bindActions()

  // 先把能力结果落地（通常 IPC 先回），用户最快的可点反馈来自这里
  await capPromise

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

  // 引擎状态与诊断信息都依赖前面几步的结果，放最后收尾。
  await runnerPromise
  renderDiagnostics(server, hasTauri)
}

// module 脚本天然 defer，DOM 已解析完毕；再判一次是为了兼容被动态 import 的场景
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => void bootstrap(), { once: true })
} else {
  void bootstrap()
}
