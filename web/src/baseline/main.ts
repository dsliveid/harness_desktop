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
  callResult,
  hasTauriRuntime,
  listenOpenSettings,
  normalizeCheckUpdateResult,
  probe,
  probeMany,
  type CallResult,
  type CapState,
} from '../desktop/tauriBridge'
import { describeActionResultV2, toneToReasonClass } from '../desktop/actionFeedback'
import { bondVisibility, parseDeviceStatus, presentBond } from '../desktop/deviceBond'
import {
  DEFAULT_SERVER_URL,
  describePairedSuccess,
  normalizePairCode,
  validatePairing,
} from '../desktop/pairingForm'
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

/** 界面上的按钮 → 对应壳命令（单一数据源，避免 HTML 与逻辑漂移） */
const BUTTON_COMMANDS = [
  COMMANDS.checkUpdate,
  COMMANDS.openSettings,
  COMMANDS.openLogs,
  // 进入主界面：手动兜底导航入口（配对/自续成功时壳会自动导航，这里是重试通道）。
  COMMANDS.openWebUi,
  // 原生登录（契约一）：登录只在原生，基线页表单提交走这个命令。
  COMMANDS.signIn,
  // 解绑按钮也要参与能力探测：壳太旧时它必须置灰，而不是点了才报错。
  COMMANDS.unpairDevice,
  // 配对按钮同理：旧壳没有 pair_device 时必须置灰并说明，而不是点了才失败。
  COMMANDS.pairDevice,
  // 登出按钮：旧壳没有 sign_out 时置灰（与解绑区分，不能混淆两者）
  COMMANDS.signOut,
] as const

/**
 * 业务前置条件：**能力可用 ≠ 此刻允许操作**。
 *
 * 能力探测只回答「这个壳有没有实现该命令」；「解除配对」还额外要求本机已配对，
 * 「立即配对」还额外要求表单输入合法。缺了这一层，就会出现「本机压根没配对，
 * 却摆着一个可点的解除配对」的荒谬界面（真实缺陷，见 `desktop/deviceBond.ts`）。
 *
 * 返回 `null` 表示无额外限制；否则给出置灰原因与色调。
 * 抽成独立函数是为了让两个门禁（能力 / 业务）的优先级一目了然：
 * **能力不足优先报能力不足**（提示升级客户端更有用），business 仅在能力通过后才生效。
 *
 * @param formReason 配对表单的校验结果（`null` 表示合法）
 */
function businessGate(
  cmd: string,
  bond: ReturnType<typeof presentBond> | null,
  formReason: string | null,
): { text: string; tone: 'ok' | 'warn' | 'error' } | null {
  // 解除配对：要求已配对
  if (cmd === COMMANDS.unpairDevice) {
    // 尚未读到设备状态（首帧竞态）：不放行，等 device_status 回来再刷新。
    if (!bond) return { text: '正在读取设备绑定状态…', tone: 'warn' }
    if (bond.canUnpair) return null
    return { text: bond.text, tone: bond.tone }
  }

  // 立即配对：要求表单输入合法
  if (cmd === COMMANDS.pairDevice) {
    if (formReason !== null) return { text: formReason, tone: 'warn' }
    return null
  }

  // 登录：要求表单两项非空（与配对同款「能力 ≠ 此刻允许」分层）。
  // formReason 现在是「配对表单 OR 登录表单」 whichever 有校验失败；
  // 登录卡片不可见时它的 reason 由 renderDeviceBinding 恢复空白，互不干扰。
  if (cmd === COMMANDS.signIn) {
    const signInReason = refreshSignInValidation()
    if (signInReason !== null) return { text: signInReason, tone: 'warn' }
    return null
  }

  // 退出登录：要求「已配对且已登录」（没登录就无从登出）
  if (cmd === COMMANDS.signOut) {
    if (!bond) return { text: '正在读取设备绑定状态…', tone: 'warn' }
    if (bond.canSignOut) return null
    return { text: bond.text, tone: bond.tone }
  }

  return null
}

/**
 * 把能力状态与业务前置条件落到按钮上：**两者都通过才放开点击**。
 *
 * 这是 §14.6 的核心体验取舍：远程 UI 可能比壳新，旧壳缺命令是常态。
 * 「点了才报错」会让用户以为程序坏了；「置灰 + 说明原因」则是可解释的降级。
 *
 * @param bond     当前设备绑定呈现；`null` 表示尚未读到（首帧）
 * @param formReason 配对表单校验失败原因；`null` 表示表单合法
 * @param busy     正在提交的命令名（提交期间该按钮保持禁用，防重复提交）
 */
function applyCapability(
  states: Map<string, CapState>,
  bond: ReturnType<typeof presentBond> | null,
  formReason: string | null,
  busy: string | null,
): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('button[data-cmd]')
  buttons.forEach((btn) => {
    const cmd = btn.dataset['cmd'] ?? ''
    const state = states.get(cmd)
    const reasonBox = el<HTMLElement>(`[data-reason-for="${cmd}"]`)

    // ⓪ 提交中：该按钮保持禁用。配对会拉起 Runner，重复提交有真实副作用。
    if (busy === cmd) {
      btn.disabled = true
      btn.setAttribute('title', '正在提交…')
      if (reasonBox) {
        reasonBox.textContent = '正在提交…'
        reasonBox.className = 'reason'
      }
      return
    }

    // ① 能力门禁：壳太旧 / 未探测到 → 置灰
    if (!state || !state.ok) {
      // 兜底：未探测到该命令也按不可用处理（fail-closed，与 hd-core Guarded 同一取向）
      const reason = state ? state.reason : '能力未探测，暂不可用'
      btn.disabled = true
      btn.setAttribute('title', reason)
      if (reasonBox) {
        reasonBox.textContent = reason
        reasonBox.className = 'reason'
      }
      return
    }

    // ② 业务门禁：能力有，但此刻不该开放（如未配对时的解除配对）
    const gate = businessGate(cmd, bond, formReason)
    if (gate) {
      btn.disabled = true
      btn.setAttribute('title', gate.text)
      if (reasonBox) {
        reasonBox.textContent = gate.text
        reasonBox.className = toneToReasonClass(gate.tone)
      }
      return
    }

    // ③ 两道门都通过：放开点击
    btn.disabled = false
    btn.removeAttribute('title')
    if (reasonBox) {
      reasonBox.textContent = ''
      // 重置色调类：否则上一次操作留下的 is-ok/is-warn/is-error 会残留到下一次反馈上
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

/**
 * 诊断行已渲染过的快照（供 check_update 拿到壳版本后重绘诊断行）。
 *
 * 模块级可变量是刻意的：bootstrap 只跑一次，之后的重绘来源只有按钮交互
 * （check_update），不存在并发渲染交错。
 */
let lastServer: ServerState = { kind: 'down', detail: '尚未探测' }
let lastHasTauri = false
/** check_update 探到的壳版本（null = 还没点过/失败，诊断行不展示）。 */
let shellVersionSeen: string | null = null

function renderDiagnostics(server: ServerState, hasTauri: boolean): void {
  const box = el<HTMLElement>('#diag')
  if (!box) return
  lastServer = server
  lastHasTauri = hasTauri
  const parts = [
    `页面 ${location.href}`,
    `运行形态 ${hasTauri ? '桌面客户端' : '浏览器'}`,
    `服务端 ${server.kind === 'ok' ? `v${server.version}（协议 ${server.protocol}）` : `不可达：${server.detail}`}`,
  ]
  // 壳版本只在点过「检查更新」后出现：它是用户验证「启动的是不是最新构建」的
  // 直接证据（对照 workspace Cargo.toml 的 version）。
  if (shellVersionSeen) parts.push(`壳 v${shellVersionSeen}`)
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
 * 绑定按钮点击与配对表单输入。所有壳调用只走 `callResult()`（它永不 throw），
 * 因此这里没有 try/catch；结果一律翻译成一句人话提示。
 */
function bindActions(): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('button[data-cmd]')
  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      void handleAction(btn)
    })
  })

  // 配对表单即时校验：边输入边更新门禁，不等到点击才报错。
  for (const id of ['#pair-server', '#pair-code', '#pair-name']) {
    el<HTMLInputElement>(id)?.addEventListener('input', () => {
      // 配对码即时归一（转大写、去空格与连字符）。用户在输入框里看到的就是
      // 将要提交的值，避免「看着像输对了，实际带着小写字母被后端拒掉」。
      const codeInput = el<HTMLInputElement>('#pair-code')
      if (codeInput) {
        const normalized = normalizePairCode(codeInput.value)
        if (normalized !== codeInput.value.toUpperCase()) {
          codeInput.value = normalized
        }
      }
      refreshActionsWithCurrentState()
      // 状态未就绪时（首帧）直接走一遍完整刷新，保证 reason 行有内容
      if (!lastCapStates) void refreshBindingAndCapability()
    })
  }

  // 登录表单即时校验：与配对表单同款取向（边输入边更新门禁）。
  for (const id of ['#sign-username', '#sign-password']) {
    el<HTMLInputElement>(id)?.addEventListener('input', () => {
      refreshActionsWithCurrentState()
    })
    // 密码框回车直接提交（对齐移动端 onFieldSubmitted）。
    el<HTMLInputElement>(id)?.addEventListener('keydown', (ev) => {
      if ((ev as KeyboardEvent).key === 'Enter') {
        const btn = document.querySelector<HTMLButtonElement>('button[data-cmd="sign_in"]')
        if (btn && !btn.disabled) void handleAction(btn)
      }
    })
  }

  // 服务端地址预填默认值。
  // 为什么不只依赖 HTML 的 value 属性：远程热更下发的 HTML 未必带这个属性，
  // 而地址留空会让用户以为「不填不行」。由 JS 兜底可确保默认值一定可见。
  const serverInput = el<HTMLInputElement>('#pair-server')
  if (serverInput && serverInput.value.trim() === '') {
    serverInput.value = DEFAULT_SERVER_URL
  }
}

const ACTION_FEEDBACK: Record<string, string> = {
  [COMMANDS.checkUpdate]: '已请求检查更新（若壳返回新版本会另行提示）',
  [COMMANDS.openSettings]: '已请求打开设置页',
  [COMMANDS.openLogs]: '已请求打开日志',
  [COMMANDS.openWebUi]: '正在打开主界面…（已配对且登录态有效时免登录直达）',
  // 登录成功走专门分支（submitSignIn）给出带账号名的文案；这里是兜底。
  [COMMANDS.signIn]: '已提交登录',
  [COMMANDS.unpairDevice]: '已解除配对：设备令牌已清除，请重新输入配对码完成绑定',
  [COMMANDS.signOut]: '已退出登录：设备仍保持绑定，已返回设置界面，可重新登录',
  // 工作区设置是**三态**命令（见 handleWorkspaceRootsResult），这里的文案只覆盖
  // 「已保存并同步」那一档；另两档由判据分支给出，故不放进这张表。
  [COMMANDS.setWorkspaceRoots]: '已保存并同步到执行引擎',
}

/**
 * 把一次操作的结果渲染到 reason 行，色调由 `describeActionResultV2` 判定。
 *
 * 🔴 为什么必须三态：后端 `set_workspace_roots` 的「已保存但未同步给执行引擎」
 * 是 `Ok(pushed=false, warning=...)`，不是 `Err`。若把它和 `null` 混为一谈，
 * 用户会看到「命令未成功」，而事实是配置**已经保存**了 —— 直接矛盾。
 * 所以 `pushed=false` 必须用 warn 色 + 后端下发的人话，而不是红字。
 *
 * 判定逻辑本身在 `desktop/actionFeedback.ts`（纯函数，可穷举单测）；
 * 这里只负责把结果写进 DOM，不做任何判断。
 */
function applyActionResult<T>(cmd: string, result: CallResult<T>, reasonBox: HTMLElement): void {
  const feedback = describeActionResultV2(
    cmd,
    result,
    ACTION_FEEDBACK[cmd] ?? `命令 ${cmd} 已执行`,
  )
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

/** 正在提交的命令名（`null` 表示空闲）。用于提交期间禁用按钮，防重复提交 */
let busyCommand: string | null = null

/**
 * 读取配对表单三个输入框的当前值。
 *
 * 抽成函数是因为它被两处用到：即时校验（`input` 事件）与提交（点击）。
 * 两处各写一遍必然漂移 —— 而漂移的后果是「校验通过但提交值不同」这种极难查的错。
 */
function readPairingInput(): { code: string; name: string; serverUrl: string } {
  return {
    code: el<HTMLInputElement>('#pair-code')?.value ?? '',
    name: el<HTMLInputElement>('#pair-name')?.value ?? '',
    serverUrl: el<HTMLInputElement>('#pair-server')?.value ?? '',
  }
}

/** 清掉所有输入框的校验高亮 */
function clearInvalidMarks(): void {
  for (const id of ['#pair-server', '#pair-code', '#pair-name']) {
    el<HTMLInputElement>(id)?.classList.remove('is-invalid')
  }
}

/**
 * 即时校验配对表单并刷新「立即配对」按钮的门禁。
 *
 * 为什么不等到点击才校验：与既有「先 probe 再决定是否可点，绝不靠 try/catch 事后兜底」
 * 同一取向。用户边输入边看到「配对码需 6-12 位」，比点一下才被拒要顺畅得多。
 *
 * @returns 校验失败时的原因（`null` 表示合法），供 `applyCapability` 复用
 */
function refreshPairingValidation(): string | null {
  const input = readPairingInput()
  const result = validatePairing(input)

  clearInvalidMarks()

  if (result.ok) return null

  // 只在对应输入框上挂高亮：错误原因写在 reason 行，视觉上只需指出是哪个框
  const fieldId =
    result.field === 'code'
      ? '#pair-code'
      : result.field === 'name'
        ? '#pair-name'
        : '#pair-server'
  el<HTMLInputElement>(fieldId)?.classList.add('is-invalid')

  return result.reason
}

/**
 * 执行真实配对。
 *
 * ## 与其它命令的差别
 *
 * `pair_device` 需要**带参数**（code / name / serverBaseUrl），不能像其它按钮那样
 * 只传命令名。参数必须来自表单，且提交前再校验一次 —— 不经校验就把原始输入发给壳，
 * 会让服务端收到垃圾数据（后端虽有校验，但那是最后一道，不是第一道）。
 *
 * ## 为什么用 `serverBaseUrl` 而不是 `server_base_url`
 *
 * Tauri 的参数名由 Rust 侧 `pair_device(..., server_base_url: Option<String>)` 决定，
 * 而 Tauri 默认把 snake_case 映射为 **camelCase** 供 JS 侧使用。传错名字的后果是
 * 参数被静默忽略 → 地址永远回落默认值（跨机部署静默失效，极难查）。
 */
async function submitPairing(reasonBox: HTMLElement): Promise<void> {
  const result = validatePairing(readPairingInput())
  if (!result.ok) {
    reasonBox.textContent = result.reason
    reasonBox.className = toneToReasonClass('error')
    return
  }

  busyCommand = COMMANDS.pairDevice
  refreshActionsWithCurrentState()

  // ⚠️ 这里刻意不用 `try/finally` + `return` 的写法：
  // `try` 里的 `return` 会先跑 `finally`、然后**直接返回**，导致写在 finally
  // 之后的「补写失败原因」永远不执行（这个坑真实踩到过一次，症状是失败提示为空）。
  // 用显式分支收口，把「刷新」放在唯一的出口处。
  let outcome: { ok: true; text: string } | { ok: false; text: string }
  try {
    const r = await callResult<unknown>(COMMANDS.pairDevice, {
      code: result.code,
      name: result.name,
      // 壳的参数是 Option<String>：这里总是传（已归一）的地址，
      // 让「留空用默认」的逻辑收敛在前端一处，而不是依赖壳的缺省行为。
      serverBaseUrl: result.serverUrl,
    })
    outcome = r.ok
      ? { ok: true, text: describePairedSuccess(r.value) }
      : { ok: false, text: r.reason }
  } catch (err) {
    // `callResult` 契约上永不 throw，这里只是最后一道兜底：
    // 宁可说「未知失败」，也不要让按钮永久停在「提交中」。
    outcome = { ok: false, text: `配对失败：${String(err)}` }
  }

  busyCommand = null
  // 无论成败都刷新：成功时区块要切换成「已绑定」，失败时要把按钮门禁恢复。
  await refreshStatusPanels()

  // 🔴 结果文案必须在刷新**之后**写。
  //
  // 因为 `refreshStatusPanels` 会重算按钮门禁，而门禁会把 reason 行覆盖成
  // 「请输入配对码」这类前置提示 —— 用户刚看到的「配对码无效或已过期」会被
  // 瞬间抹掉，等于什么都没告诉他（真实踩到的缺陷）。
  reasonBox.textContent = outcome.text
  reasonBox.className = toneToReasonClass(outcome.ok ? 'ok' : 'error')
}

/**
 * 执行原生登录（契约一）。
 *
 * 与 submitPairing 同款结构：提交中置 busy → 刷新门禁 → 显式分支收口写反馈
 * （try/finally + return 会吞掉补写，历史踩过的坑不复述）。
 *
 * 成功文案带账号名：用户要能确认「以谁的身份登录」；signedIn=false（Cookie
 * 写入失败等降级）不算失败，但必须说清「下次启动会自动重试」。
 */
async function submitSignIn(reasonBox: HTMLElement): Promise<void> {
  const username = el<HTMLInputElement>('#sign-username')?.value ?? ''
  const password = el<HTMLInputElement>('#sign-password')?.value ?? ''

  // 前端先拦空输入：空值连 IPC 都不必发（与壳侧校验同口径）。
  if (username.trim() === '' || password === '') {
    reasonBox.textContent = username.trim() === '' ? '请输入用户名' : '请输入密码'
    reasonBox.className = toneToReasonClass('warn')
    return
  }

  busyCommand = COMMANDS.signIn
  refreshActionsWithCurrentState()

  let outcome: { ok: boolean; text: string }
  try {
    const result = await callResult<unknown>(COMMANDS.signIn, { username, password })
    if (result.ok) {
      const info = normalizeSignInResult(result.value)
      outcome = info?.signedIn
        ? {
            ok: true,
            text: `登录成功${info.userLabel ? `（${info.userLabel}）` : ''}，正在进入主界面…`,
          }
        : { ok: true, text: '登录成功，但内置页面凭据未能本次写入；下次启动会自动重试' }
    } else {
      outcome = { ok: false, text: result.reason }
    }
  } catch (err) {
    outcome = { ok: false, text: `登录失败：${String(err)}` }
  }

  busyCommand = null
  // 成功与否都刷新：成功后登录卡片要隐藏、登出按钮要出现、主界面即将导航。
  await refreshStatusPanels()
  reasonBox.textContent = outcome.text
  reasonBox.className = toneToReasonClass(outcome.ok ? 'ok' : 'error')
}

/** 读取登录表单当前输入（供门禁复用） */
function readSignInInput(): { username: string; password: string } {
  return {
    username: el<HTMLInputElement>('#sign-username')?.value ?? '',
    password: el<HTMLInputElement>('#sign-password')?.value ?? '',
  }
}

/**
 * 登录表单校验（前端第一道，壳侧还有第二道）：两项非空才放行。
 * @returns 失败原因（`null` = 合法）
 */
function refreshSignInValidation(): string | null {
  const input = readSignInInput()
  const usernameEmpty = input.username.trim() === ''
  const passwordEmpty = input.password === ''
  el<HTMLInputElement>('#sign-username')?.classList.toggle('is-invalid', usernameEmpty)
  el<HTMLInputElement>('#sign-password')?.classList.toggle('is-invalid', passwordEmpty)
  if (usernameEmpty) return '请输入用户名'
  if (passwordEmpty) return '请输入密码'
  return null
}

/**
 * 归一 `sign_in` 响应（宽松，永不 throw —— 对齐 normalizeCheckUpdateResult）。
 */
function normalizeSignInResult(raw: unknown): { signedIn: boolean; userLabel: string | null } | null {
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as { signed_in?: unknown; user_label?: unknown }
  return {
    signedIn: rec.signed_in === true,
    userLabel:
      typeof rec.user_label === 'string' && rec.user_label.trim() !== ''
        ? rec.user_label.trim()
        : null,
  }
}

async function handleAction(btn: HTMLButtonElement): Promise<void> {
  const cmd = btn.dataset['cmd'] ?? ''
  const reasonBox = el<HTMLElement>(`[data-reason-for="${cmd}"]`)
  // 置灰期间不应触发，但双击/键盘仍可能挤进来；再判一次最稳
  if (btn.disabled) return

  // 配对走独立路径：它是唯一需要多参数的命令，且成功后要切换整块 UI
  if (cmd === COMMANDS.pairDevice) {
    if (!reasonBox) return
    await submitPairing(reasonBox)
    return
  }

  // 登录走独立路径：同样需要多参数，成功后要切换整块 UI 并自动进主界面。
  if (cmd === COMMANDS.signIn) {
    if (!reasonBox) return
    await submitSignIn(reasonBox)
    return
  }

  // 不可逆操作先确认。用户取消时保持原状态，不写任何反馈文案
  // （写「已取消」会让 reason 行看起来像出过错）。
  const prompt = CONFIRM_PROMPTS[cmd]
  if (prompt && !globalThis.confirm(prompt)) return

  // 🔴 必须用 callResult 而非 call：本命令后端签名是 `Result<(), String>`，
  // 成功时序列化出来就是 null。若用 call()，成功与失败都得到 null，
  // 界面会在**操作已经成功**的情况下报「未成功」（真实事故，见 tauriBridge.CallResult 文档）。
  const result = await callResult<unknown>(cmd)
  if (!reasonBox) return

  // check_update 特殊处理：它有**结构化返回体**（壳版本/通道），把版本写进
  // 诊断行，让「run.sh 是否构建出了最新壳」可被肉眼验证 —— 这正是用户排障
  // 「客户端版本过低误报」时的第一判据。
  if (cmd === COMMANDS.checkUpdate && result.ok) {
    const info = normalizeCheckUpdateResult(result.value)
    if (info) {
      shellVersionSeen = info.shellVersion
      renderDiagnostics(lastServer, lastHasTauri)
    }
  }

  // 用 reason 行复用为「操作反馈」：不新增 DOM 结构，减少基线维护面。
  // 三档判定集中在 describeActionResultV2（ok / warn / error），红字只留给真故障。
  applyActionResult(cmd, result, reasonBox)

  // 解绑/登出成功后刷新状态卡：
  // - 解绑：相位已切到 needs_pairing，绑定状态与按钮门禁都变了；
  // - 登出：signed_in 变 false，登出按钮该消失、文案要改成「需要登录一次」。
  // 判定用 result.ok —— 不能再写 `result !== null`：成功返回 null 的场景会漏刷新。
  if ((cmd === COMMANDS.unpairDevice || cmd === COMMANDS.signOut) && result.ok) {
    await refreshStatusPanels()
    // 刷新会按门禁重写 reason 行（登出按钮会更成「尚未登录」的说明），
    // 但用户刚点的这次操作结果更该被看到，故在刷新后重新落实文案。
    applyActionResult(cmd, result, reasonBox)
  }
}

/* ============ 设备绑定 ============ */

/**
 * 读取设备绑定状态并渲染「设备绑定」卡片 + 配对表单的显隐。
 *
 * 🔴 这个函数的存在本身就是缺陷修复：基线界面原先从未调用 `device_status`，
 * 于是「解除配对」按钮的可点性只受能力探测控制，未配对时也照样可点。
 * 现在它同时驱动**两个互斥区块**（配对表单 / 解除配对）的显隐。
 *
 * @returns 当前呈现方案（供按钮门禁复用），读取失败时返回 unknown 态
 */
async function renderDeviceBinding(): Promise<ReturnType<typeof presentBond>> {
  const raw = await callResult<unknown>(COMMANDS.deviceStatus)
  const state = parseDeviceStatus(raw)
  const view = presentBond(state)
  const visibility = bondVisibility(state)

  // 区块互斥：未配对显示配对表单、已配对显示解除配对。
  // 同屏同时出现「立即配对」和「解除配对」会让用户不知道该点哪个。
  const pairingSection = el<HTMLElement>('#pairing')
  if (pairingSection) pairingSection.hidden = !visibility.showPairingForm
  // 原生登录卡片（契约一）：已配对未登录时显示，与配对/解除配对互斥。
  const signInSection = el<HTMLElement>('#sign-in')
  if (signInSection) signInSection.hidden = !visibility.showSignIn
  const bindingSection = el<HTMLElement>('#device-binding')
  if (bindingSection) bindingSection.hidden = !visibility.showUnpair
  // 登出行：仅在「已配对且已登录」时出现。未登录就无从登出，
  // 显示一个永远置灰的按钮只会让人困惑（为什么点了没反应）。
  const signOutRow = el<HTMLElement>('#sign-out-row')
  if (signOutRow) signOutRow.hidden = !visibility.showSignOut

  // 卡片标题：把「已绑定 / 未绑定」直接写进标题，用户不必去读下面那行小字。
  const title = document.querySelector<HTMLElement>('#device-binding .line-title')
  if (title) title.textContent = view.title

  const reasonBox = el<HTMLElement>(`[data-reason-for="${COMMANDS.unpairDevice}"]`)
  if (reasonBox) {
    reasonBox.textContent = view.text
    reasonBox.className = toneToReasonClass(view.tone)
  }

  // 配对表单出现后，立即按当前（预填的）输入算一次门禁，
  // 否则「立即配对」会停在 HTML 里的初始 disabled 上，用户还以为不许点。
  if (visibility.showPairingForm) refreshPairingValidation()
  // 登录卡片同理：显示时立即校验一次，让「登录」按钮立即反映当前输入状态。
  if (visibility.showSignIn) refreshSignInValidation()

  return view
}

/* ============ 启动 ============ */

/**
 * 刷新设备侧状态卡（执行引擎 + 设备绑定 + 能力门禁）。
 *
 * 抽成函数供两处复用：首次启动、以及配对/解绑成功后（相位变了、绑定状态变了、
 * 能力门禁也可能随之变化）。不并入 `bootstrap` 是因为解绑后的刷新**不该重跑
 * 服务端探测** —— 那会白等最多 3s，而服务端连通性并没有因为解绑而改变。
 */
async function refreshStatusPanels(): Promise<void> {
  // 三张卡并行：都属于本机 IPC，串行没有收益。
  await Promise.all([renderRunnerStatus(), refreshBindingAndCapability()])
}

/**
 * 用**当前已知状态**重算按钮门禁（不重新发 IPC）。
 *
 * 用途：提交中的按钮要立刻置灰防重复提交，此时不必再问壳一遍能力
 * （能力在运行期不会变，且多一次 IPC 只会让界面迟滞）。
 * 代价是要缓存上一次探测结果 —— 见 `lastCapStates`。
 */
function refreshActionsWithCurrentState(): void {
  if (!lastCapStates) return
  const bond = lastBond
  applyCapability(lastCapStates, bond, refreshPairingValidation(), busyCommand)
}

/** 上一次的能力探测结果（供 `refreshActionsWithCurrentState` 复用） */
let lastCapStates: Map<string, CapState> | null = null
/** 上一次的绑定呈现 */
let lastBond: ReturnType<typeof presentBond> | null = null

/**
 * 刷新「设备绑定」卡片 + 按钮门禁（两者强耦合，必须一起刷新）。
 *
 * 顺序有讲究：**先取绑定状态再算能力门禁**。因为 `applyCapability` 需要
 * 「当前是否已配对」来做业务门禁，若并行发起，能力先回时会拿不到绑定状态，
 * 短暂出现「解除配对可点」的错误中间态。
 */
async function refreshBindingAndCapability(): Promise<void> {
  const bond = await renderDeviceBinding()
  const states = await probeMany(BUTTON_COMMANDS)
  lastBond = bond
  lastCapStates = states
  // 表单校验结果参与门禁：它决定「立即配对」是否可点
  applyCapability(states, bond, refreshPairingValidation(), busyCommand)
  summarizeCapability(states)
}

export async function bootstrap(): Promise<void> {
  // 运行形态判定必须与桥接层同源：自己手写 `typeof __TAURI__ === 'object'` 会把
  // 「只有 __TAURI_INTERNALS__ 的壳」误判成浏览器，于是按钮全灰、诊断却写着
  // 「运行形态 浏览器」—— 两种自相矛盾的结论同时出现在同一屏。
  const hasTauri = hasTauriRuntime()

  // 三个探测并行：壳能力走 IPC（快），服务端走网络（可能 3s）。
  // 串行会让用户先看 3s 空白，这段等待在兜底界面上尤其刺眼。
  const serverPromise = probeServer()
  const capPromise = refreshBindingAndCapability()
  // 执行引擎状态也走 IPC，与能力探测同时发起。
  const runnerPromise = renderRunnerStatus()

  bindActions()

  // 壳的「打开设置」事件联动：聚焦并滚动到设置区块（无 Tauri 环境自动 no-op）。
  void listenOpenSettings(() => {
    const settings = el<HTMLElement>('#settings')
    if (settings) {
      settings.scrollIntoView({ behavior: 'smooth', block: 'start' })
      settings.setAttribute('tabindex', '-1')
      settings.focus({ preventScroll: true })
    }
  })

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
