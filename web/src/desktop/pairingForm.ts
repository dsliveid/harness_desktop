/**
 * 配对表单的判据层 —— 输入归一与校验（纯函数）。
 *
 * ## 为什么需要这个模块（真实需求）
 *
 * 基线界面长期**没有任何配对入口**：它只提示「请先输入配对码完成设备绑定」，
 * 却没有输入框，用户卡在首页无法继续。而壳实际已注册了完整的 `pair_device`
 * （真实网络配对 → 落密钥链 → 拉起 Runner），只是前端从未调用过它。
 *
 * 同时界面上也**没有服务端地址输入**。壳的 `pair_device` 支持 `server_base_url`
 * 可选参数（缺省回落 `http://127.0.0.1:5611`），但没有输入项就意味着：
 * **只要服务端不跑在本机 5611 端口，用户就完全没法配对**。
 *
 * ## 为什么判据必须与 DOM 分离
 *
 * 沿用 `deviceBond.ts` / `actionFeedback.ts` 的既有分层：判据是纯逻辑，可穷举单测。
 * 上一轮的教训很具体 —— 门禁判断写进 DOM 代码后，两处各自改 `disabled` 会互相覆盖，
 * 且无法穷举测试。
 *
 * ## 校验口径必须与 Rust 一致（否则前端放行、后端拒绝）
 *
 * `hd-host/src/commands.rs` 的 `validate_pair_input`：
 * - 配对码长度 6~12，且**只允许 ASCII 大写字母与数字**
 * - 设备名 trim 后不得为空
 *
 * 前端提前拦一道，避免把明显的垃圾输入打到服务端日志。但**前端不是安全边界** ——
 * 后端那份校验才是权威，这里只是体验优化。
 */

/** 服务端地址缺省值 —— 必须与 `hd-host/src/bootstrap.rs::default_http_url()` 同源 */
export const DEFAULT_SERVER_URL = 'http://127.0.0.1:5611'

/** 设备名缺省值：设备名只用于服务端展示，强制用户起名是多余摩擦 */
export const DEFAULT_DEVICE_NAME = 'harness-desktop'

/** 配对码长度范围（对齐 Rust 的 PAIR_CODE_MIN_LEN / PAIR_CODE_MAX_LEN） */
export const PAIR_CODE_MIN_LEN = 6
export const PAIR_CODE_MAX_LEN = 12

/**
 * 归一配对码：去空白、转大写、剔除连字符。
 *
 * 为什么剔除连字符：服务端生成的配对码是纯字母数字，用户手抄时极易按
 * 「AB12-CD34」的分组习惯加连字符。与其报「格式非法」让用户自己找原因，
 * 不如直接容忍这种写法 —— 归一后仍然非法才是真错。
 */
export function normalizePairCode(raw: string): string {
  return raw
    .trim()
    .toUpperCase()
    .replace(/[\s-]/g, '')
}

/**
 * 归一服务端地址。
 *
 * 容忍三种常见写法，统一成 `http://host:port`：
 * - `192.168.1.5`            → `http://192.168.1.5:5611`（补 scheme 与默认端口）
 * - `192.168.1.5:5611`       → `http://192.168.1.5:5611`
 * - `http://host:5611/`      → `http://host:5611`（去尾斜杠，否则拼接会出双斜杠）
 *
 * 为什么必须在前端补 scheme：后端 `PairingClient::new(base)` 只做字符串拼接。
 * 用户填 `192.168.1.5:5611` 直接拼会得到非法 URL，错误信息还很难懂。
 *
 * @returns `{ ok: true, url }` 或 `{ ok: false, reason }`
 */
export function normalizeServerUrl(
  raw: string,
): { ok: true; url: string } | { ok: false; reason: string } {
  const text = raw.trim()
  // 留空 = 用默认（本机自用场景下用户直接点「立即配对」即可）
  if (text === '') return { ok: true, url: DEFAULT_SERVER_URL }

  // 无 scheme 时补 http://。注意不能用「是否含 ':'」判断：
  // 端口本身带冒号（192.168.1.5:5611），按 '://' 判断才准确。
  const withScheme = text.includes('://') ? text : `http://${text}`

  let parsed: URL
  try {
    parsed = new URL(withScheme)
  } catch {
    return { ok: false, reason: `服务端地址无法解析：${raw.trim()}` }
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: `服务端地址只支持 http/https，当前为 ${parsed.protocol}` }
  }
  if (parsed.hostname === '') {
    return { ok: false, reason: '服务端地址缺少主机名' }
  }

  // 🔴 端口缺省时补项目默认端口 5611（对齐 harness_go 的 Server.Addr = :5611）。
  // 只在 http 且用户没写端口时补：https 补 5611 几乎肯定是错的。
  let port = parsed.port
  if (port === '' && parsed.protocol === 'http:') port = '5611'

  const host = port === '' ? parsed.hostname : `${parsed.hostname}:${port}`
  // 只保留 origin：用户可能粘贴成 `http://host:5611/api/v1/...`，
  // 那段路径由后端自己拼，带上会拼出错误地址。
  return { ok: true, url: `${parsed.protocol}//${host}` }
}

/** 校验结果：成功时给出可直接交给壳的参数 */
export type PairingFormResult =
  | {
      ok: true
      /** 交给壳的配对码（已归一） */
      code: string
      /** 交给壳的设备名（已归一，空则用默认值） */
      name: string
      /** 交给壳的服务端基址（已归一） */
      serverUrl: string
    }
  | {
      ok: false
      /** 出错的字段名，便于 UI 聚焦到具体输入框 */
      field: 'code' | 'name' | 'serverUrl'
      /** 给人看的原因 */
      reason: string
    }

/**
 * 校验整张配对表单。
 *
 * 顺序说明：**先校验地址**。因为地址非法时后面的配对码校验毫无意义
 * （用户连目标服务端都没写对），且地址错误最常见（跨机部署时手填）。
 */
export function validatePairing(input: {
  code: string
  name: string
  serverUrl: string
}): PairingFormResult {
  const server = normalizeServerUrl(input.serverUrl)
  if (!server.ok) {
    return { ok: false, field: 'serverUrl', reason: server.reason }
  }

  const code = normalizePairCode(input.code)
  if (code === '') {
    return { ok: false, field: 'code', reason: '请输入配对码' }
  }
  if (code.length < PAIR_CODE_MIN_LEN || code.length > PAIR_CODE_MAX_LEN) {
    return {
      ok: false,
      field: 'code',
      reason: `配对码需 ${PAIR_CODE_MIN_LEN}-${PAIR_CODE_MAX_LEN} 位，当前 ${code.length} 位`,
    }
  }
  // 只允许大写字母与数字：服务端按此格式生成，出现其他字符说明手抄错了
  if (!/^[A-Z0-9]+$/.test(code)) {
    return { ok: false, field: 'code', reason: '配对码只能包含大写字母与数字' }
  }

  const trimmedName = input.name.trim()
  const name = trimmedName === '' ? DEFAULT_DEVICE_NAME : trimmedName

  return { ok: true, code, name, serverUrl: server.url }
}

/**
 * 配对成功后应展示的提示。
 *
 * ## 为什么要看 `signed_in`（对接「免二次登录」特性）
 *
 * 后端 `StartPairingResponse` 现在除了 `message` 还回 `signed_in` / `user_label`：
 * 服务端签发用户会话时 `signed_in = true`（`hg_sess` 已写进 WebView，用户进内置页面
 * **不用再登录**）；旧服务端 / historical 配对码则不签发，此时 `signed_in = false`
 * 是**合法降级**，不是错误。
 *
 * 后端注释明确要求：`signed_in == false` 时 UI 应提示「配对成功，请去 Web UI 登录」，
 * 而不是报错、也不能只说「配对成功」让用户以为进去就能用 —— 那会让他在下一页
 * 撞上一个登录框却不知道为什么。
 *
 * ## 取文案的优先级
 *
 * 1. `signed_in === true` → 优先用后端 `message`（它知道细节），否则给「已自动登录」
 * 2. `signed_in === false` → 在 `message` 后追加「需要登录一次」的补充说明
 * 3. `signed_in` 缺失（旧壳）→ 只回 `message`，**不臆测**登录态
 *
 * 第 3 条是关键：旧壳没有这个字段时，擅自说「需要登录」或「已登录」都可能误导。
 */
export function describePairedSuccess(raw: unknown): string {
  const fallback = '配对成功，设备已绑定'

  if (!raw || typeof raw !== 'object') return fallback

  const rec = raw as { message?: unknown; signed_in?: unknown; user_label?: unknown }
  const message =
    typeof rec.message === 'string' && rec.message.trim() !== '' ? rec.message.trim() : fallback

  // 缺失/非布尔：旧壳，不臆测登录态（见上面第 3 条）
  if (typeof rec.signed_in !== 'boolean') return message

  if (rec.signed_in) {
    const label =
      typeof rec.user_label === 'string' && rec.user_label.trim() !== ''
        ? rec.user_label.trim()
        : null
    // 后端 message 通常已含「已启动」这类信息，这里只补账号归属
    return label ? `${message}（已自动登录为 ${label}）` : `${message}（已自动登录）`
  }

  // 合法降级：不是失败，但要提前说清下一步该做什么
  return `${message}；尚未登录，请在打开的内置页面中登录一次`
}
