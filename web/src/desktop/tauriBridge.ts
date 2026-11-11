/**
 * tauriBridge —— 桌面端「本机能力」的唯一下行入口（对应设计文档 §14.6 H2）。
 *
 * ## 为什么要有这一层
 * 桌面端 UI 是「内置最小基线 + 远程热更」：远程下发的 UI 可能比用户当前安装的
 * 客户端壳更新，于是它会去调一个**旧壳并不存在的 command**。若直接在业务代码里
 * 裸调 `window.__TAURI__.core.invoke`，结果是「点一下 → 抛出 → 界面卡在错误态」。
 *
 * 这与前端既有的 hostStatus 约定冲突（harness_go/web/src/lib/workspaceHost.ts：
 * 能力不足时返回 canList=false + reason，让 UI **提前置灰并说明原因**）。本文件把
 * 同一套契约搬到桌面端：**先 probe 再决定是否可点，绝不靠 try/catch 事后兜底**。
 *
 * ## 三条铁律
 * 1. **禁止裸 invoke**：业务代码只允许走 `call()`。它永不 throw —— 失败一律返回 null
 *    并 console.warn，UI 侧只需处理「有没有值」，不必包 try/catch（也就不会因为
 *    一个可选命令失败而炸掉整屏）。
 * 2. **list_commands 是能力探测锚点，永不删除**（§14.6.3）。旧壳只要还实现它，
 *    任何新 UI 都能自证「我能不能用某能力」；一旦删除，所有降级判断失效。
 * 3. **降级而非报错**：宁可按钮置灰 + 文案「请升级客户端」，也不要让用户点了才报错
 *    ——「宁可置灰也不要打开后报错」是 workspaceHost 已确立的既有约定。
 */

/** 能力状态：与 HostStatus 的 `canList + reason` 同构，只是收窄成可穷尽的联合类型 */
export type CapState = { ok: true } | { ok: false; reason: string }

/** 命令入参：Tauri 只接受可序列化的扁平对象 */
export type InvokeArgs = Record<string, unknown>

/**
 * 与 hd-host 壳约定的命令名。
 * 壳侧尚未实现时，probe 会如实返回降级 reason，UI 提前置灰 —— 因此这里可以
 * 放心把「未来命令」先写进来，不会造成运行时炸裂。
 */
export const COMMANDS = {
  /** 🔴 能力探测锚点，永不删除（§14.6.3）。返回当前壳支持的命令名清单。 */
  listCommands: 'list_commands',
  /** 检查更新（远程 UI 热更 / 壳版本） */
  checkUpdate: 'check_update',
  /** 打开设置页 */
  openSettings: 'open_settings',
  /** 打开日志目录 / 日志面板 */
  openLogs: 'open_logs',
  /** 进入主界面：导航到服务端 Web UI（手动兜底入口，配对后免登录直达） */
  openWebUi: 'open_web_ui',
  /**
   * 原生登录（契约一，2026-11）：登录只在原生（基线页表单），WebView 内不放
   * 登录表单。密码只经 IPC 进 Rust，不落 JS 侧任何存储。
   */
  signIn: 'sign_in',
  /** 返回基线页（契约三）：从服务端 Web UI 回到设置/登录界面。 */
  openBaseline: 'open_baseline',
  /** 设备/配对状态（`paired` / `online` / `device_id` …） */
  deviceStatus: 'device_status',
  /** Runner 生命周期快照（`state` / `restarts` / `last_heartbeat_ms`） */
  runnerStatus: 'runner_status',
  /** 启动流程走到哪一步（`state` / `detail`） */
  bootState: 'get_boot_state',
  /**
   * 真实配对（异步）：输入配对码与服务端地址 → 换 token → 落密钥链 → 拉起 Runner。
   *
   * 参数 `{ code, name, serverBaseUrl }` 见 `pairingForm.validatePairing` 的输出；
   * `serverBaseUrl` 是**可选**的：壳缺省会回落 `http://127.0.0.1:5611`。
   */
  pairDevice: 'pair_device',
  /**
   * 退出登录（**保留设备绑定**）。
   *
   * 与 `unpairDevice` 严格正交（对齐移动端 `signOut` / `resetPairing`）：
   * - 登出：清会话令牌 + Cookie，设备仍配对、执行引擎继续在线，重新登录即可。
   * - 解绑：清设备令牌 + 会话令牌，相位回到「需要配对」。
   *
   * 把登出做成「连设备一起解绑」是移动端已踩过并修正的坑：用户只想换账号，
   * 却被迫重新找配对码。
   */
  signOut: 'sign_out',
  /** 工作区白名单读写 */
  getWorkspaceRoots: 'get_workspace_roots',
  setWorkspaceRoots: 'set_workspace_roots',
  /**
   * 解除配对（**不可逆**）：停 Runner → 清密钥链令牌 → 切「需要配对」。
   *
   * 这是客户端侧唯一能让「主动解约」成立的入口。调用前 UI 必须二次确认 ——
   * 清掉的令牌无法恢复，用户只能重新走配对码流程。
   */
  unpairDevice: 'unpair_device',
} as const

/** 所有已知命令名 */
export type ShellCommand = (typeof COMMANDS)[keyof typeof COMMANDS]

/* ============ 运行环境探测 ============ */

/** Tauri 的 invoke 签名（v1/v2 出参一致，故只约束最小可用形状） */
interface InvokeFn {
  <T>(cmd: string, args?: InvokeArgs): Promise<T>
}

/**
 * 壳注入到页面的全局对象形状：
 *  - v2：`__TAURI__.core.invoke`
 *  - v1：`__TAURI__.tauri.invoke`
 *  - 兜底：`__TAURI__.invoke`（自研 shim / 单测注入）
 * 三种都接住，是为了让同一份基线能跑在新旧两代壳上。
 */
interface TauriGlobalLike {
  core?: { invoke?: InvokeFn }
  tauri?: { invoke?: InvokeFn }
  invoke?: InvokeFn
}

interface BridgeHost {
  __TAURI__?: TauriGlobalLike
  /** Tauri 2 内部桥（与 `withGlobalTauri` 无关，始终注入），仅作兜底，见 `resolveInvoke` */
  __TAURI_INTERNALS__?: { invoke?: InvokeFn }
}

/**
 * 取当前可用的 invoke。
 * 用 globalThis 而不是 window：单测在 Node 里跑（无 window），同一份文件两边通用。
 *
 * ## 为什么要读 `__TAURI_INTERNALS__`（🔴 真实事故留下的兜底）
 *
 * `window.__TAURI__` **不是** Tauri 2 的默认产物：它由 `tauri.conf.json` 的
 * `app.withGlobalTauri` 控制，而该项 `#[serde(default)]` **默认为 false**。
 * 本项目就曾漏配它，症状极具误导性 —— 壳明明起来了，界面却整齐地显示
 * 「当前为浏览器端（未运行在桌面客户端内）」，所有本机能力按钮一起置灰。
 *
 * 而 `__TAURI_INTERNALS__` 由 WebView 初始化脚本**无条件**注入（Tauri 2 的 IPC 一切
 * 都靠它：连 `@tauri-apps/api` 的 `invoke` 也只是转调它）。把它作为最后一条通道，
 * 意味着「壳内就一定探得到」，不再让本机能力的存活系于一个容易被忘掉的配置项。
 *
 * 它是内部 API（名字带 INTERNALS），形状可能随小版本变化，故：只在前面所有
 * 公开入口都取不到时才用，且仅取 `invoke` 一个成员，不外扩。
 */
function resolveInvoke(): InvokeFn | null {
  const g = globalThis as unknown as BridgeHost
  const t = g.__TAURI__
  if (t && typeof t === 'object') {
    const candidate = t.core?.invoke ?? t.tauri?.invoke ?? t.invoke
    if (typeof candidate === 'function') return candidate
  }

  const internals = g.__TAURI_INTERNALS__
  if (internals && typeof internals === 'object' && typeof internals.invoke === 'function') {
    // bind 到 internals：内部实现随时可能改写成依赖 this 的形态，
    // 取出裸函数再调用会静默丢失接收者。
    return internals.invoke.bind(internals)
  }

  return null
}

/**
 * 是否运行在桌面客户端壳内。
 *
 * 诊断信息与能力汇总要回答的正是这个问题，而它与 `resolveInvoke() !== null`
 * 完全等价 —— 因此只暴露一个判定入口，避免 `main.ts` 与桥接层各自手写
 * `typeof __TAURI__ === 'object'` 而出现「按钮可用、诊断却写着浏览器」的自相矛盾。
 */
export function hasTauriRuntime(): boolean {
  return resolveInvoke() !== null
}

/* ============ 能力清单解析与缓存 ============ */

/**
 * 解析 list_commands 的返回值。
 * 故意做成宽松解析：壳侧可能回 `string[]`，也可能回 `{supported: string[]}`
 * （未来还想加版本号字段）。契约形状不确定时，宁可多兼容一种也不要在 UI 层抛错。
 *
 * @returns 命令名数组；无法识别时返回 null（= 「读不出能力清单」，按全降级处理）
 */
export function normalizeSupported(raw: unknown): string[] | null {
  const takeArray = (v: unknown): string[] | null => {
    if (!Array.isArray(v)) return null
    // 过滤掉非字符串元素，避免后续 includes 被脏数据带偏
    return v.filter((x): x is string => typeof x === 'string')
  }
  const direct = takeArray(raw)
  if (direct) return direct
  if (raw && typeof raw === 'object') {
    const rec = raw as Record<string, unknown>
    return takeArray(rec.supported) ?? takeArray(rec.commands)
  }
  return null
}

/** 能力清单缓存（一次会话只问壳一次；壳的能力在运行期不会变） */
let supportedCache: Promise<string[] | null> | null = null

/** 清空能力缓存（单测用；也供「用户点了检查更新后重新探测」这类场景使用） */
export function resetCapabilityCache(): void {
  supportedCache = null
}

/**
 * 读取壳支持的命令清单。
 * 失败返回 null（而不是抛），并**清掉缓存** —— 偶发的 invoke 异常不该让所有按钮
 * 在本次会话里永久置灰，下次 probe 会重新问一次。
 */
function loadSupported(invoke: InvokeFn): Promise<string[] | null> {
  if (supportedCache) return supportedCache
  const task = (async (): Promise<string[] | null> => {
    try {
      const raw = await invoke<unknown>(COMMANDS.listCommands, {})
      const list = normalizeSupported(raw)
      if (!list) {
        console.warn('[tauriBridge] list_commands 返回值无法识别，按「无可用能力」降级')
      }
      return list
    } catch (err) {
      // 壳太旧 / 命令被删 / IPC 异常，一律降级；不要向上抛
      console.warn('[tauriBridge] list_commands 调用失败，按「无可用能力」降级：', err)
      supportedCache = null
      return null
    }
  })()
  supportedCache = task
  return task
}

/* ============ 对外唯一 API ============ */

export const NO_TAURI_REASON = '当前为浏览器端（未运行在桌面客户端内）'

/**
 * 探测单个命令是否可用。
 *
 * 无 `__TAURI__` → 「当前为浏览器端」（这是基线在 http 页面里被直接打开的正常情形，
 * 不是错误）；有壳但清单里没有 → 提示版本过低并给出缺失的命令名，便于用户/客服定位。
 */
export async function probe(cmd: string): Promise<CapState> {
  const invoke = resolveInvoke()
  if (!invoke) return { ok: false, reason: NO_TAURI_REASON }

  const supported = await loadSupported(invoke)
  if (!supported) {
    return {
      ok: false,
      reason: `无法获取客户端能力清单（缺 ${COMMANDS.listCommands}），请升级客户端`,
    }
  }
  if (!supported.includes(cmd)) {
    return { ok: false, reason: `客户端版本过低（缺 ${cmd}），请升级客户端` }
  }
  return { ok: true }
}

/** 批量探测：UI 一次渲染要把多个按钮的状态都算出来，逐条 probe 会串行等 IPC */
export async function probeMany(cmds: readonly string[]): Promise<Map<string, CapState>> {
  const pairs = await Promise.all(cmds.map(async (c) => [c, await probe(c)] as const))
  return new Map(pairs)
}

/* ============ 具体命令的返回体契约 ============ */

/**
 * `set_workspace_roots` 的响应 —— 后端 `WorkspaceRootsResult`（见 hd-host/src/commands.rs）。
 *
 * ## 为什么是「两个布尔 + 一句人话」而不是 `string[]`
 *
 * 「配置已保存、但没能同步给执行引擎」既不是成功也不是失败：配置确实落库了。
 * 后端把它做成 `Ok` 里的 `pushed=false` + `warning`，正是为了让这里能**区分三态**：
 *
 * | 情况                    | `call()` 得到      | UI 该用的色调 |
 * | ----------------------- | ------------------ | ------------- |
 * | 未在壳内 / 校验类真失败 | `null`             | error（红）   |
 * | 已保存但未下发          | `{pushed: false}`  | warn（黄）    |
 * | 已保存并同步            | `{pushed: true}`   | ok（绿）      |
 *
 * 若后端仍用 `Err` 送这条信息，Tauri 会让 promise reject → `call()` 归一成 `null`
 * → 界面只能说「命令未成功」，与「配置其实已保存」直接矛盾。
 */
export interface WorkspaceRootsResult {
  /** 归一后的工作区根（前端据此刷新面包屑，别用自己那份原始输入） */
  roots: string[]
  /** 是否已成功下发给执行引擎 */
  pushed: boolean
  /** `pushed === false` 时给人看的说明；成功时为 `null` */
  warning: string | null
}

/**
 * `unpair_device` 的响应 —— 后端 `UnpairResult`（见 hd-host/src/commands.rs）。
 *
 * ## 为什么不是 `Result<(), String>`
 *
 * 「本地凭据已清、但没能通知服务端」既非成功也非失败：本机已经解绑（目标达成），
 * 但服务端设备列表可能还挂着这台机器。用 `Err` 送这句话会 reject → `call()` 归一成
 * `null` → 界面只能说「命令未成功」，与「本地已解绑」直接矛盾（同一坑见 workspace 三态）。
 */
export interface UnpairResult {
  /** 服务端是否已确认吊销本设备 */
  serverUnpaired: boolean
  /** 未确认时给人看的说明；已确认时为 `null` */
  warning: string | null
}

/**
 * 宽松解析 `UnpairResult`（壳侧版本不一致时可能没有这个形状）。
 *
 * 返回 `null` 表示「这不是解绑结果」（旧壳返回 `null`/`undefined` 的 unit）——
 * 调用方据此回落到普通成功文案，而不是把旧壳当失败。
 */
export function normalizeUnpairResult(raw: unknown): UnpairResult | null {
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as Record<string, unknown>
  // `server_unpaired` 是判别字段：没有它就不是本契约
  if (typeof rec['server_unpaired'] !== 'boolean') return null
  const warning = typeof rec['warning'] === 'string' ? rec['warning'] : null
  return { serverUnpaired: rec['server_unpaired'], warning }
}

/**
 * 宽松解析 `WorkspaceRootsResult`（壳侧版本不一致时可能缺字段/形状不同）。
 *
 * 返回 `null` 表示「这不是工作区结果」—— 调用方据此回落到普通命令的成功文案，
 * 而不是把一个畸形对象当成功展示。刻意不抛：与 `call()` 的「永不 throw」同取向。
 */
export function normalizeWorkspaceRootsResult(raw: unknown): WorkspaceRootsResult | null {
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as Record<string, unknown>
  // `pushed` 是这个契约的判别字段：没有它就不是工作区结果
  if (typeof rec['pushed'] !== 'boolean') return null
  const roots = Array.isArray(rec['roots'])
    ? rec['roots'].filter((r): r is string => typeof r === 'string')
    : []
  const warning = typeof rec['warning'] === 'string' ? rec['warning'] : null
  return { roots, pushed: rec['pushed'], warning }
}

/** 壳 → 前端的「打开设置」事件名（与 hd-host commands.rs 的 OPEN_SETTINGS_EVENT 对齐）。 */
export const OPEN_SETTINGS_EVENT = 'hd://open-settings'

/** 壳 → 前端事件监听的宽泛形状（Tauri 全局注入，无类型时降级为 no-op）。 */
interface TauriEventLike {
  listen: (event: string, handler: (e: unknown) => void) => Promise<() => void>
}

/**
 * 监听壳发出的「打开设置」事件（open_settings command 的页内联动）。
 *
 * 壳内没有独立设置窗口：`open_settings` = 前置主窗口 + 发本事件。
 * 前端收到后滚动/聚焦设置区块。无 Tauri 环境（浏览器）直接跳过 —— 这是正常降级，
 * 浏览器里本就不存在「壳的前置窗口」这回事。
 */
export async function listenOpenSettings(onEvent: () => void): Promise<void> {
  const globalLike = globalThis as unknown as { __TAURI__?: { event?: TauriEventLike } }
  const listen = globalLike.__TAURI__?.event?.listen
  if (!listen) return
  try {
    await listen(OPEN_SETTINGS_EVENT, () => onEvent())
  } catch (err) {
    console.warn('[tauriBridge] 监听 open-settings 事件失败（不影响其它功能）：', err)
  }
}

/**
 * 宽松解析 `check_update` 的响应（壳侧版本不一致时可能缺字段/形状不同）。
 *
 * 返回 `null` 表示「这不是检查更新结果」——调用方回落到通用成功文案。
 * 刻意不抛：与 `call()` 的「永不 throw」同取向。
 */
export interface CheckUpdateResult {
  /** 壳版本（与 device_status.app_version 同源），诊断行据此展示「壳 vX.Y.Z」。 */
  shellVersion: string
  /** 更新通道（当前恒为 dev：本项目尚无发布分发，「更新」= 重新构建壳）。 */
  channel: string
  /** 是否有可用更新（当前阶段恒 false，字段预留给未来发布流程）。 */
  updateAvailable: boolean
}

export function normalizeCheckUpdateResult(raw: unknown): CheckUpdateResult | null {
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as Record<string, unknown>
  if (typeof rec['shell_version'] !== 'string') return null
  return {
    shellVersion: rec['shell_version'],
    channel: typeof rec['channel'] === 'string' ? rec['channel'] : 'dev',
    updateAvailable: rec['update_available'] === true,
  }
}

/**
 * 检查更新：取壳版本与通道（当前 dev 阶段 = 版本对比提示，不做下载安装）。
 * 返回 `null` 表示命令失败（无壳 / 壳太旧 / IPC 异常）。
 */
export async function checkUpdate(): Promise<CheckUpdateResult | null> {
  const raw = await call<unknown>(COMMANDS.checkUpdate)
  return normalizeCheckUpdateResult(raw)
}

/**
 * 打开设置（轻实现）：壳会前置主窗口并发出 `${OPEN_SETTINGS_EVENT}` 事件；
 * 返回 `null` 表示命令失败。事件监听见 `main.ts`。
 */
export async function openSettings(): Promise<boolean> {
  return (await call<unknown>(COMMANDS.openSettings)) !== null
}

/**
 * 打开日志目录：壳侧定位并创建（若缺）`<系统配置目录>/harness_desktop/logs`
 * 后用系统文件管理器打开。返回 `null` 表示命令失败。
 */
export async function openLogs(): Promise<boolean> {
  return (await call<unknown>(COMMANDS.openLogs)) !== null
}

/**
 * 进入主界面：壳把主窗口导航到服务端 Web UI。
 *
 * 已配对且登录态有效时是**免登录直达**（hg_sess Cookie 由壳维护）；
 * 未登录时会看到服务端登录页。返回 `null` 表示命令失败（无壳 / 壳太旧）。
 */
export async function openWebUi(): Promise<boolean> {
  return (await call<unknown>(COMMANDS.openWebUi)) !== null
}

/** `sign_in` 响应（对齐 Rust `SignInResponse`） */
export interface SignInResult {
  /** 是否已进入登录态（`false` = Cookie 写入失败等降级，界面保持表单） */
  signedIn: boolean
  /** 已登录账号展示名（未登录为 null） */
  userLabel: string | null
}

/**
 * 原生登录（契约一）：提交用户名/密码，成功后壳落 vault + Cookie 并自动进主界面。
 *
 * 返回 `null` 表示命令失败（无壳 / 壳太旧 / 服务端拒绝 —— 后两者的错误文案
 * 由 callResult 的 reason 呈现，这里不用区分）。成功也未必已导航：
 * `signedIn=false` 是合法降级（Cookie 写入失败，重启自续会补）。
 */
export async function signIn(username: string, password: string): Promise<SignInResult | null> {
  const raw = await call<unknown>(COMMANDS.signIn, { username, password })
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as { signed_in?: unknown; user_label?: unknown }
  return {
    signedIn: rec.signed_in === true,
    userLabel: typeof rec.user_label === 'string' && rec.user_label.trim() !== '' ? rec.user_label.trim() : null,
  }
}

/**
 * 返回基线页（契约三）：从服务端 Web UI 回到设置/登录界面。
 * 主要供服务端 SPA 浮标调用；返回 `null` 表示命令失败。
 */
export async function openBaseline(): Promise<boolean> {
  return (await call<unknown>(COMMANDS.openBaseline)) !== null
}

/**
 * 设置工作区白名单并下发（**唯一入口**，禁止业务代码裸调 invoke）。
 *
 * 返回 `null` 有两种可能（都是「本次没成功」）：无壳/壳太旧、或后端校验类真失败
 * （空列表、路径不是目录、无法归一）。后端「已保存但未下发」不会走到这里，
 * 它是 `pushed=false` 的**成功**返回，由 UI 用 warn 色表达。
 */
export async function setWorkspaceRoots(roots: string[]): Promise<WorkspaceRootsResult | null> {
  const raw = await call<unknown>(COMMANDS.setWorkspaceRoots, { roots })
  return normalizeWorkspaceRootsResult(raw)
}

/**
 * `callResult` 的返回类型 —— 把「调用失败」与「成功返回空值」彻底分开。
 *
 * ## 🔴 为什么必须新增这一层（真实事故）
 *
 * `call<T>()` 成功时原样返回壳的值，失败时返回 `null`。问题在于：**Rust 的
 * `Result<(), String>` 成功时序列化出来就是 `null`**。于是同一个 `null` 双载了
 * 两种完全相反的语义：
 *
 * | 实际情况                       | `call()` 得到 | 旧判定结果 |
 * | ------------------------------ | ------------- | ---------- |
 * | 命令成功，后端返回 `()`        | `null`        | ❌ 报「未成功」 |
 * | 无壳 / 命令不存在 / 壳内 Err   | `null`        | ✅ 报「未成功」 |
 *
 * 事故现场正是 `unpair_device`（`Result<(), String>`）：后端日志已打出
 * 「已解除配对」（`Ok(())` 路径），前端却提示「命令 unpair_device 未成功」。
 * 任何返回 unit 的命令都会 100% 误报失败，所以这必须在桥接层根治，
 * 而不是在每个调用点猜「这个命令会不会返回 null」。
 *
 * 判据只认 `ok` 字段：`ok === true` 时 `value` 即使是 `null`/`undefined`
 * 也是**成功**。
 */
export type CallResult<T> = { ok: true; value: T } | { ok: false; reason: string }

/**
 * 执行本机命令并返回**带成败标记**的结果。
 *
 * 与 `call()` 的唯一区别：它不把失败压成 `null`，而是给出 `{ ok: false, reason }`。
 * 凡是「需要区分成功与失败」的调用点（尤其是向用户回报操作结果的场景）都应走这里。
 *
 * 永不 throw，reason 已是可展示的人话。
 */
export async function callResult<T>(cmd: string, args?: InvokeArgs): Promise<CallResult<T>> {
  const invoke = resolveInvoke()
  if (!invoke) {
    console.warn(`[tauriBridge] 无 __TAURI__，跳过命令 ${cmd}（浏览器端不具备本机能力）`)
    return { ok: false, reason: NO_TAURI_REASON }
  }
  try {
    const value = await invoke<T>(cmd, args ?? {})
    return { ok: true, value }
  } catch (err) {
    console.warn(`[tauriBridge] 命令 ${cmd} 执行失败：`, err)
    return { ok: false, reason: describeInvokeError(err) }
  }
}

/**
 * 把 invoke 抛出的错误转成一句能直接展示的人话。
 *
 * Tauri 的 reject 值可能是字符串（`Err(String)` 的命令）、Error 对象，
 * 或 `{ message }` 形状的 IPC 包装。统统收拢成字符串，且**不把内部的
 * 序列化细节暴露给用户**（例如 "Command unpair_device not found" 直接照搬
 * 对用户没意义，故加中文前缀但保留原文便于支持排查）。
 */
function describeInvokeError(err: unknown): string {
  const raw =
    typeof err === 'string'
      ? err
      : err instanceof Error
        ? err.message
        : typeof (err as { message?: unknown })?.message === 'string'
          ? String((err as { message: string }).message)
          : ''
  const detail = raw.trim()
  return detail === '' ? '本机命令调用失败（详见开发者控制台）' : `本机命令调用失败：${detail}`
}

/**
 * 执行本机命令 —— 基线/远程 UI 的调用入口（**语义收窄版**）。
 *
 * 契约：永不 throw 到 UI。任何失败（无壳、命令不存在、壳内业务失败）都返回 null，
 * 由调用方当作「本次操作没成功」处理并自行给文案。这样业务代码不必写 try/catch，
 * 也不会出现「一个可选能力失败导致整屏错误」。
 *
 * ⚠️ **不要用它判断操作成败**：`null` 既可能是失败，也可能是命令成功但返回了
 * unit。需要成败结论时请用 [`callResult`]。
 */
export async function call<T>(cmd: string, args?: InvokeArgs): Promise<T | null> {
  const r = await callResult<T>(cmd, args)
  return r.ok ? r.value : null
}
