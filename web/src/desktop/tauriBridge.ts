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
  /** 设备/配对状态（`paired` / `online` / `device_id` …） */
  deviceStatus: 'device_status',
  /** Runner 生命周期快照（`state` / `restarts` / `last_heartbeat_ms`） */
  runnerStatus: 'runner_status',
  /** 启动流程走到哪一步（`state` / `detail`） */
  bootState: 'get_boot_state',
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
}

/**
 * 取当前可用的 invoke。
 * 用 globalThis 而不是 window：单测在 Node 里跑（无 window），同一份文件两边通用。
 */
function resolveInvoke(): InvokeFn | null {
  const g = globalThis as unknown as BridgeHost
  const t = g.__TAURI__
  if (!t || typeof t !== 'object') return null
  const candidate = t.core?.invoke ?? t.tauri?.invoke ?? t.invoke
  return typeof candidate === 'function' ? candidate : null
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
 * 执行本机命令 —— **基线/远程 UI 的唯一调用入口**。
 *
 * 契约：永不 throw 到 UI。任何失败（无壳、命令不存在、壳内业务失败）都返回 null，
 * 由调用方当作「本次操作没成功」处理并自行给文案。这样业务代码不必写 try/catch，
 * 也不会出现「一个可选能力失败导致整屏错误」。
 */
export async function call<T>(cmd: string, args?: InvokeArgs): Promise<T | null> {
  const invoke = resolveInvoke()
  if (!invoke) {
    console.warn(`[tauriBridge] 无 __TAURI__，跳过命令 ${cmd}（浏览器端不具备本机能力）`)
    return null
  }
  try {
    return await invoke<T>(cmd, args ?? {})
  } catch (err) {
    console.warn(`[tauriBridge] 命令 ${cmd} 执行失败，已降级为 null：`, err)
    return null
  }
}
