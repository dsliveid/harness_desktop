/**
 * 按钮操作的反馈文案与色调（纯函数，对应设计文档 §14.5 的「操作反馈」）。
 *
 * ## 为什么单独一个模块
 *
 * 这与 `runnerPhase.ts` 同一取向：**判据**（这条结果属于哪一态）是纯逻辑，
 * 与「往哪个 DOM 节点写字」解耦。分开之后三态分支能被穷举单测钉死，
 * 而不必去驱动一个 DOM 桩点按钮（那种测试一旦 HTML 结构变动就整片失效）。
 *
 * ## 三态从哪来
 *
 * `set_workspace_roots` 的返回是 `WorkspaceRootsResult`（`{ roots, pushed, warning }`）：
 *
 * | 后端结果                                  | `call()` 拿到      | 这里判出 |
 * | ----------------------------------------- | ------------------ | -------- |
 * | 下发成功                                  | `pushed: true`     | ok       |
 * | 已保存但未下发（Runner 未跑 / 写管道失败） | `pushed: false`    | warn     |
 * | 校验类真失败（空列表 / 非目录 / 无法归一） | `null`             | error    |
 * | 无壳（浏览器端 / 壳太旧）                 | `null`             | error    |
 *
 * 🔴 中间那档是本次改造的核心：改造前后端用 `Err(PushFailed)` 送这句话，Tauri 会让
 * promise reject，`tauriBridge.call()` 按铁律归一成 `null`，于是界面只能说
 * 「命令未成功」——而事实是配置**已经保存**。现在它是 `Ok` 里的降级标记，
 * 这话必须用 **warn 色**（不是红字）说出：已保存但未下发不是故障。
 */

import { normalizeWorkspaceRootsResult, type WorkspaceRootsResult } from './tauriBridge'

/** 反馈色调：与基线状态卡的 `toneToState` / `toneToText` 沿用同一套语义 */
export type FeedbackTone = 'ok' | 'warn' | 'error'

/** 一次操作该显示什么、用什么色调 */
export interface ActionResultFeedback {
  /** 写到 reason 行的人话 */
  text: string
  /** ok = 真成功；warn = 已保存但未下发（非故障）；error = 真失败 */
  tone: FeedbackTone
}

/** 中间档（`pushed === false` 且后端没给文案时的兜底），措辞必须说清「配置没丢」 */
export const DEGRADED_PUSH_FALLBACK =
  '工作区配置已保存，但未能同步到执行引擎，请重试或重启客户端'

/**
 * 把一次命令结果翻译成「文案 + 色调」。
 *
 * @param cmd           命令名（仅用于拼装通用文案）
 * @param raw           `tauriBridge.call()` 的返回值；`null` 表示失败/无壳
 * @param successText   该命令在真成功时的文案（`ACTION_FEEDBACK[cmd]`）
 */
export function describeActionResult(
  cmd: string,
  raw: unknown,
  successText: string,
): ActionResultFeedback {
  if (raw === null) {
    // error：真失败（或壳缺失），用户必须做点什么才算完
    return {
      text: `命令 ${cmd} 未成功（详见开发者控制台），请重试或升级客户端`,
      tone: 'error',
    }
  }

  const ws: WorkspaceRootsResult | null = normalizeWorkspaceRootsResult(raw)
  if (ws && !ws.pushed) {
    // warn：配置已保存，只是还没同步给执行引擎。**不是故障**，绝不飘红。
    // 文案优先用后端下发的那句 —— 它才知道失败的具体原因（未运行 / 写管道坏）。
    const warning = ws.warning?.trim() ?? ''
    return { text: warning !== '' ? warning : DEGRADED_PUSH_FALLBACK, tone: 'warn' }
  }

  // ok：真成功（含 pushed=true，以及「该命令没有三态契约」的普通命令）
  return { text: successText, tone: 'ok' }
}

/** 色调 → reason 行的文字类名（`is-ok` / `is-warn` / `is-error`） */
export function toneToReasonClass(tone: FeedbackTone): string {
  return `reason is-${tone}`
}
