/**
 * 设备绑定状态 —— 决定「解除配对」按钮到底该不该可点。
 *
 * ## 为什么单独一个模块（真实缺陷复盘）
 *
 * 基线界面原先**从未调用过 `device_status`**：「设备绑定」卡片是纯静态 HTML，
 * 按钮可点性只由「能力探测」决定（壳支持 `unpair_device` 就放开）。于是出现
 * 一个显然荒谬的界面 —— **本机压根没配对，却摆着一个可点的「解除配对」**。
 *
 * 用户点下去，后端执行的是「停 Runner → 清空一个本来就空的凭据 → 把相位硬切
 * NeedsPairing」，属于无意义甚至有害的操作（可能覆盖真实的启动状态）。
 *
 * 结论：**「能力可用」不等于「此刻允许操作」**。能力探测回答「这个壳有没有这个功能」，
 * 业务前置条件回答「这个功能此刻该不该开放」，两者必须分开算再取交集。
 *
 * ## 为什么做成纯函数
 *
 * 与 `runnerPhase.ts` / `actionFeedback.ts` 同一取向：判据是纯逻辑，可穷举单测，
 * 不必驱动 DOM 桩。本文件只回答「这份 device_status 响应意味着什么」。
 */

/** 是否已配对：三态而非布尔 —— 「读不出来」必须与「确定未配对」区分 */
export type BondState =
  /** 已配对：vault 里有令牌 */
  | {
      kind: 'paired'
      deviceId: string | null
      online: boolean
      /**
       * 是否已登录（配对时服务端一并下发了用户会话）。
       *
       * 为什么它不是 BondState 的第四种 kind：登录态与绑定态是**正交**的两个维度，
       * 拆成 kind 会让四种组合（已配对未登录 / 已配对已登录 …）各自需要一份呈现逻辑，
       * 而实际差异仅是「要不要提示去登录」一句话。故作为 paired 分支内的附加事实。
       *
       * 缺失时按 false 处理：服务端老版本不返回该字段，此时提示「未登录」是安全方向
       * （最坏情况是多一句提示，而不是让用户带着错误预期去点按钮）。
       */
      signedIn: boolean
      /** 已登录账号展示名（未登录 / 未上报为 null） */
      userLabel: string | null
      /**
       * 会话为何不可用（后端 `device_status.session_invalid`）：
       * `expired` / `revoked` / `owner_unknown` / `network` / `unknown`；
       * 没有失效事实（或已恢复登录）为 `null`。
       *
       * ## 为什么必须有这个字段
       *
       * 会话默认 7 天过期。启动时若自动续期失败，后端会清掉本地会话，于是
       * `signedIn` 变 false —— 但「为什么掉了」在界面上原本**完全不可见**：
       * 用户只看到「尚未登录，需要先登录一次」，会误以为自己被登出或密码错了，
       * 而真实原因可能是「设备令牌被吊销，必须重新配对」。
       *
       * 这两个场景用户要做的事完全不同（一个去登录、一个去重新配对），
       * 所以必须把原因原样带上来。
       */
      sessionInvalid: string | null
    }
  /** 未配对：明确没有令牌，此时**不得**开放解除配对 */
  | { kind: 'unpaired' }
  /** 读不出：命令失败或响应形状不认识。按 fail-closed 处理，同样不开放 */
  | { kind: 'unknown'; reason: string }

/** `device_status` 的响应形状（字段名属后端契约，见 hd-host/src/commands.rs） */
interface DeviceStatusBody {
  paired?: unknown
  online?: unknown
  device_id?: unknown
  /** 是否已登录（有用户会话令牌）。与 `paired` **正交**：已配对不等于已登录。 */
  signed_in?: unknown
  /** 已登录账号的展示名（后端只回展示名，绝不回令牌） */
  user_label?: unknown
  /**
   * 会话不可用的原因短串（`expired` / `revoked` / `owner_unknown` / `network` / `unknown`）。
   *
   * 后端只在「确实没有可用会话」时才回值；可选字段，缺省即无失效事实。
   */
  session_invalid?: unknown
  /**
   * 当前生效的服务端基址（如 `http://192.168.1.5:5611`）。
   *
   * **非凭据**，可安全回显。改造前界面上完全看不到「我在连哪台」，
   * 这字段是唯一的自证入口（也用于「服务端连接」卡片的输入框预填）。
   */
  server_base_url?: unknown
}

/**
 * 宽松解析 `device_status` 响应。
 *
 * 为什么宽松：远程热更的 UI 可能跑在旧壳上，字段可能缺失或改名。宁可按「未知」
 * 降级，也不要因一个可选字段缺失就把整张卡片渲染成错误态。
 *
 * @param raw `callResult` 的结果；`ok === false` 直接归一成 unknown
 */
export function parseDeviceStatus(
  raw: { ok: true; value: unknown } | { ok: false; reason: string },
): BondState {
  if (!raw.ok) {
    return { kind: 'unknown', reason: raw.reason.trim() || '无法读取设备状态' }
  }

  const body = raw.value
  // 边界：unit 返回（null）或非对象 —— 说明这个壳的 device_status 没有按契约回字段。
  if (!body || typeof body !== 'object') {
    return {
      kind: 'unknown',
      reason: '设备状态响应格式不可识别（客户端版本可能过低）',
    }
  }

  const rec = body as DeviceStatusBody
  // 🔴 `paired` 是本契约的判别字段：没有它就无从判断，绝不能默认为 false。
  // 默认 false 会让「读不出来」被当成「确定未配对」，从而错误地隐藏配对入口。
  if (typeof rec.paired !== 'boolean') {
    return {
      kind: 'unknown',
      reason: '设备状态缺少 paired 字段（客户端版本可能过低）',
    }
  }

  if (!rec.paired) return { kind: 'unpaired' }

  return {
    kind: 'paired',
    deviceId: typeof rec.device_id === 'string' && rec.device_id !== '' ? rec.device_id : null,
    online: rec.online === true,
    // 与 paired 正交的登录态：严格只认 `true`，其余（缺失 / 非布尔）一律视为未登录。
    signedIn: rec.signed_in === true,
    userLabel:
      typeof rec.user_label === 'string' && rec.user_label.trim() !== ''
        ? rec.user_label.trim()
        : null,
    // 失效原因同样宽松：只接受非空字符串，其余（缺失 / 非字符串 / 空白）一律 null。
    // 不在这里校验枚举取值 —— 前端按"认识的分支给精确文案，不认识的回落到通用文案"处理，
    // 这样后端新增一种原因时界面不会崩，最多是文案退化成通用版。
    sessionInvalid:
      typeof rec.session_invalid === 'string' && rec.session_invalid.trim() !== ''
        ? rec.session_invalid.trim()
        : null,
  }
}

/**
 * 卡片区块的显隐：配对表单与解除配对**互斥**。
 *
 * ## 为什么必须互斥（与「未配对不该显示解除配对」是同一条原则的镜像）
 *
 * 上一轮修掉了「没配对却摆着可点的解除配对」；对称地，**已配对时也不该出现配对表单**
 * —— 同屏同时出现「立即配对」和「解除配对」，用户根本不知道该点哪个。
 *
 * 由 `device_status.paired` 单一事实源驱动，而不是靠两处各自判断。
 */
export interface BondVisibility {
  /** 是否显示配对表单（服务端地址 / 配对码 / 设备名） */
  showPairingForm: boolean
  /**
   * 是否显示「服务端连接」配置区（2026-11 新增）。
   *
   * 恒为真：服务端地址是**随时可查可改**的配置项，不限配对态。
   * 改造前它只在配对时出现一次，配对成功后界面上彻底看不到「我连的是哪台」，
   * 换 IP 只能靠「解除配对」——把一个配置项变成了破坏性操作。
   */
  showServerConfig: boolean
  /** 是否显示解除配对区块 */
  showUnpair: boolean
}

/**
 * 由绑定状态推导区块显隐。
 *
 * 注意 `unknown` 的特殊处理：读不出状态时**两个都显示**并不是好主意
 * （用户会看到两块并存）。这里选择显示配对表单 —— 因为「未配对或读不出」
 * 下用户最可能的诉求就是完成配对；而解除配对在读不出时本就该禁用，
 * 一并隐藏反而更清晰。
 *
 * ## 2026-11：登录表单与登出按钮已从这里移除
 *
 * 桌面端「绑定即登录」：配对码由已登录账号在服务端签发，配对响应里携带来
 * 用户会话（`user_token`），壳写进密钥链并注入 Cookie。所以不存在需要用户
 * 在客户端输账号密码的环节，也不存在「已登录想退出」的独立诉求。
 * 会话过期由设备令牌自动续期解决（见 hd-host `plan_reinject_step`），
 * 而不是把用户推回一个登录表单 —— 后者正是本轮修的用户反馈。
 */
export function bondVisibility(state: BondState): BondVisibility {
  switch (state.kind) {
    case 'paired':
      return {
        showPairingForm: false,
        showServerConfig: true,
        showUnpair: true,
      }
    case 'unpaired':
      return { showPairingForm: true, showServerConfig: true, showUnpair: false }
    case 'unknown':
      return { showPairingForm: true, showServerConfig: true, showUnpair: false }
  }
}

/**
 * 「设备绑定」卡片的完整呈现方案：标题、按钮是否可点、文案、色调。
 *
 * 把「该显示什么」一次算清，而不是散在 DOM 代码里 if/else —— 这样单测能穷举
 * 三种状态各自的文案与门禁，且不会出现「按钮置灰了但 reason 行还写着上一条反馈」。
 */
export interface BondPresentation {
  /** 卡片标题后缀（如「设备绑定 · 未绑定」） */
  title: string
  /** 解除配对按钮是否允许点击 */
  canUnpair: boolean
  /** reason 行的文案 */
  text: string
  /** reason 行的色调（对应 `is-ok` / `is-warn` / `is-error`） */
  tone: 'ok' | 'warn' | 'error'
}

/** 未配对时的固定说明 —— 单测与 UI 共用同一份文案，避免两处措辞漂移 */
export const UNPAIRED_HINT = '当前未配对，无需解除。请先输入配对码完成设备绑定。'

/**
 * 「会话失效」的原因 → 给用户的一句话说明。
 *
 * ## 为什么要分这么细（而不是统一「请重新登录」）
 *
 * 用户在这个状态的下一步动作完全不同：
 * - `expired` / `network`：会话过期或这次没连上 → **多半下次启动自动续期就好**
 *   （壳会用设备令牌换新会话，无需用户做任何事）；
 * - `revoked` / `owner_unknown` / `server_unpaired`：设备令牌被吊销 / 服务端
 *   不认这台设备 → **重试无用，必须重新配对**。
 *
 * ## 🔴 为什么文案里不再出现「请重新登录」
 *
 * 桌面端没有账号登录入口（绑定即登录，见 bondVisibility 文档）。若这里还写
 * 「重新登录」，用户会在界面上**找不到**任何能登录的地方 —— 这是纯粹的误导。
 * 会话恢复的路径只有两条：自动续期（过期/网络）与重新配对（吊销）。
 */
export function sessionInvalidHint(reason: string | null): string {
  switch (reason) {
    case 'expired':
      return '会话已过期，正在用本机设备令牌自动续期（无需操作）。'
    case 'network':
      return '暂时连不上服务端，无法自动续期会话；网络恢复后会自动重试。'
    case 'revoked':
      return '设备授权已被服务端吊销，重试无效，需重新输入配对码绑定本机。'
    case 'server_unpaired':
      // 服务端主动解除了本设备绑定（管理端删除 / 别人帮你解绑）——
      // 必须直说「服务端已解除」，否则用户会以为是自己点错了什么。
      return '服务端已解除本设备绑定，请重新输入配对码完成绑定。'
    case 'owner_unknown':
      return '服务端无法确认本机归属的账号，需重新配对绑定账号后再使用。'
    default:
      return '会话已失效，正在尝试自动恢复；若反复失败请重新配对。'
  }
}

/**
 * 由绑定状态推导卡片呈现。
 *
 * 三态对应三种截然不同的用户动作：
 * - unpaired → 引导「去配对」，隐藏解除按钮（禁用而非移除，保持布局稳定）
 * - paired   → 允许解除（不可逆，点击时仍会二次确认）
 * - unknown  → 说明读不出来，同样禁用解除（fail-closed）
 */
export function presentBond(state: BondState): BondPresentation {
  switch (state.kind) {
    case 'unpaired':
      return {
        title: '设备绑定 · 未绑定',
        canUnpair: false,
        text: UNPAIRED_HINT,
        tone: 'warn',
      }
    case 'paired': {
      const id = state.deviceId ?? '（设备 ID 未上报）'
      const onlineText = state.online ? '在线' : '离线'
      // 账号信息只作为**只读事实**展示（「以谁的身份在用」），不再引导任何登录动作。
      // 未登录还要再分两种（会话 7 天过期 + 续期失败的真实场景）：
      // ① 从来没有会话（旧服务端 / 历史配对码）→ 壳会用设备令牌自动换一次；
      // ② 有过会话但失效了（sessionInvalid 非空）→ 要看原因，吊销类必须重新配对。
      const account = state.signedIn
        ? `已登录${state.userLabel ? `为 ${state.userLabel}` : ''}，进入内置页面无需再次登录。`
        : state.sessionInvalid
          ? sessionInvalidHint(state.sessionInvalid)
          : '会话正在自动恢复（用本机设备令牌换取），无需手动登录。'
      // 失效且不可自愈（吊销 / 归属未知 / 服务端解绑）→ 色调转 warn：这不只是
      // 一个提示，而是一个需要用户动手的状态。可自愈的过期/网络问题仍保持 ok 色，
      // 免得用户每次开机都被一条黄字吓到。
      const faultNeedsAction =
        state.sessionInvalid === 'revoked' ||
        state.sessionInvalid === 'owner_unknown' ||
        state.sessionInvalid === 'server_unpaired'
      return {
        title: '设备绑定 · 已绑定',
        canUnpair: true,
        text: `已绑定设备 ${id}（${onlineText}）。${account}解除后将清除本机令牌，需重新配对。`,
        tone: faultNeedsAction ? 'warn' : 'ok',
      }
    }
    case 'unknown':
      return {
        title: '设备绑定 · 状态未知',
        canUnpair: false,
        text: `${state.reason}：为避免误操作，解除配对已置灰。`,
        tone: 'error',
      }
  }
}
