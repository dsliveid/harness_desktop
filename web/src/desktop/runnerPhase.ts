/**
 * Runner 生命周期相位的 UI 投影（纯函数，零依赖，可在 Node 里单测）。
 *
 * ## 为什么要单独一个文件
 *
 * 后端 `lifecycle.rs` 的 `RunnerPhase` 是**唯一事实源**，它有三个特点：
 *
 * 1. 变体多（8 个），且其中 3 个是本轮新增的（`idle` / `needs_pairing` /
 *    `externally_running`）。旧版前端只认 `running` / `stopped`，遇到新值会
 *    落进默认分支，把「邮件待配对」显示成未知错误。
 * 2. 同一个相位在不同语境下的**语义强弱不同**：`backoff` 是「正在自愈中」，
 *    属于正常过程；`gave_up` 才是「需要人介入」。UI 若一律用红色，会把正常
 *    重启风暴式地报成故障，用户会去点重启，反而打断自愈。
 * 3. 「能不能干活」与「是不是有故障」是两件事：`externally_running` 时本机
 *    确实能执行任务（由另一个实例负责），但本窗口改配置不生效。
 *
 * 因此映射规则集中在这里，由单元测试钉死；`main.ts` 只负责渲染。
 *
 * ## 与后端字符串的契约
 *
 * `RunnerPhase::as_str` 返回的字面量是**稳定契约**（后端有测试断言），
 * 本文件按字面量匹配。若后端新增相位而此处未跟进，`describe()` 会走到
 * 兜底分支并明确标注「未知相位」，不会静默显示成健康状态。
 */

/** 后端 `runner_status.state` 的已知取值（与 `RunnerPhase::as_str` 一一对应）。 */
export const RUNNER_PHASES = [
  'idle',
  'needs_pairing',
  'running',
  'stopped',
  'backoff',
  'gave_up',
  'shutting_down',
  'externally_running',
] as const

export type RunnerPhase = (typeof RUNNER_PHASES)[number]

/** UI 状态灯的语义色调。与既有 `setStatus` 的 state 参数同一套词汇。 */
export type PhaseTone = 'ok' | 'warn' | 'error' | 'muted'

/** 一个相位的展示描述。 */
export interface PhaseDescriptor {
  /** 人类可读的短标签（如「运行中」）。 */
  label: string
  /** 状态灯色调。 */
  tone: PhaseTone
  /**
   * 本相位下“本机此刻是否真的能执行任务”。
   *
   * 注意与「是否健康」区分：`externally_running` 是**能干活但不归我管**，
   * 因此 `canWork=true` 而 `tone='warn'`。
   */
  canWork: boolean
  /** 是否属于「自愈过程中的正常中间态」（决定要不要提示用户等待）。 */
  transient: boolean
}

/**
 * 判断字符串是否是我们认识的相位。
 *
 * 用于把后端返回的任意字符串收窄成联合类型，避免 `as RunnerPhase` 硬转。
 */
export function isRunnerPhase(v: unknown): v is RunnerPhase {
  return typeof v === 'string' && (RUNNER_PHASES as readonly string[]).includes(v)
}

/**
 * 把相位映射成展示描述。
 *
 * 未知值不会抛错也不会伪装成健康态 —— 返回一个明确的「未识别」描述。
 * 这是本文件的**核心不变量**：任何未知输入都必须让用户看出“状态没读明白”，
 * 而不是看到一片绿色以为一切正常。
 */
export function describe(phase: unknown): PhaseDescriptor {
  switch (phase) {
    case 'running':
      return { label: '运行中', tone: 'ok', canWork: true, transient: false }

    case 'idle':
      // 启动编排尚未跑完。不能报错：这是首帧的正常状态。
      return { label: '启动中', tone: 'muted', canWork: false, transient: true }

    case 'needs_pairing':
      // 不是故障，是需要用户操作。
      return { label: '待配对', tone: 'warn', canWork: false, transient: false }

    case 'backoff':
      // 正在退避重连：属于自愈过程，不要用红色吓人。
      return { label: '重连中', tone: 'warn', canWork: false, transient: true }

    case 'gave_up':
      // 重试预算耗尽，必须人工介入（检查服务端 / 杀软 / 是否被删）。
      return { label: '已停止重试', tone: 'error', canWork: false, transient: false }

    case 'stopped':
      return { label: '已停止', tone: 'muted', canWork: false, transient: false }

    case 'shutting_down':
      return { label: '正在退出', tone: 'muted', canWork: false, transient: true }

    case 'externally_running':
      // 本机确实在执行任务，但由**另一个实例**负责：能干活，但本窗口改配置不生效。
      return { label: '由其他实例运行', tone: 'warn', canWork: true, transient: false }

    default:
      return {
        label: '状态未识别',
        tone: 'error',
        canWork: false,
        transient: false,
      }
  }
}

/**
 * 拼一句面向用户的完整说明（相位 + 重启次数）。
 *
 * `restarts` 是从进程启动至今的累计重启次数。它只在**确实发生过重启**时才有
 * 意义 —— 为 0 时不要显示「已重启 0 次」，那会让用户以为这是可调参数。
 */
export function describeWithRestarts(phase: unknown, restarts: number): string {
  const d = describe(phase)
  if (!Number.isFinite(restarts) || restarts <= 0) return d.label
  return `${d.label}（已重启 ${restarts} 次）`
}
