/**
 * deviceBond 单测：穷举「已配对 / 未配对 / 读不出」三态与按钮门禁。
 *
 * ## 这份测试为哪个真实缺陷而写
 *
 * 基线界面原先**从未调用 `device_status`**，「设备绑定」卡片是纯静态 HTML，
 * 「解除配对」按钮的可点性只由**能力探测**决定。于是本机明明没配对，
 * 界面上却摆着一个可点的「解除配对」，用户点下去才发现在做无意义的事。
 *
 * 根因是概念混淆：**「能力可用」≠「此刻允许操作」**。
 * 本文件把「此刻该不该开放」这条判据钉死，任何回退都会立刻红。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

const here = path.dirname(fileURLToPath(import.meta.url))
const MOD = pathToFileURL(path.join(here, '.build/deviceBond.mjs')).href

const load = () => import(MOD)

/* ============ parseDeviceStatus：宽松解析 ============ */

test('已配对：paired=true 解析出 deviceId 与在线状态', async () => {
  const { parseDeviceStatus } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, online: true, device_id: 'dev-abc' },
  })

  assert.deepEqual(state, {
    kind: 'paired',
    deviceId: 'dev-abc',
    online: true,
    signedIn: false,
    userLabel: null,
    sessionInvalid: null,
  })
})

test('已配对但 deviceId 缺失/为空：归一成 null 而不是空字符串', async () => {
  const { parseDeviceStatus } = await load()

  const missing = parseDeviceStatus({ ok: true, value: { paired: true, online: false } })
  assert.equal(missing.kind, 'paired')
  assert.equal(missing.deviceId, null)

  const empty = parseDeviceStatus({
    ok: true,
    value: { paired: true, device_id: '', online: false },
  })
  assert.equal(empty.deviceId, null)
})

test('未配对：paired=false → unpaired（这是「不允许解除配对」的判据）', async () => {
  const { parseDeviceStatus } = await load()

  const state = parseDeviceStatus({ ok: true, value: { paired: false, online: false } })
  assert.deepEqual(state, { kind: 'unpaired' })
})

test('🔴 读不出 vs 未配对必须区分：缺 paired 字段归一成 unknown，绝不能默认 false', async () => {
  const { parseDeviceStatus } = await load()

  // 若这里误判成 unpaired，「读不出来」就会被当成「确定没配对」，
  // 从而错误地隐藏配对入口 —— 这是比多显示一个按钮更糟的后果。
  const noField = parseDeviceStatus({ ok: true, value: { online: true } })
  assert.equal(noField.kind, 'unknown')
  assert.match(noField.reason, /paired/)

  // paired 类型不对（字符串）同样不可信
  const wrongType = parseDeviceStatus({ ok: true, value: { paired: 'true' } })
  assert.equal(wrongType.kind, 'unknown')
})

test('读不出：unit 返回（null）与非法形状都归一成 unknown 并给出原因', async () => {
  const { parseDeviceStatus } = await load()

  const nullValue = parseDeviceStatus({ ok: true, value: null })
  assert.equal(nullValue.kind, 'unknown')

  const scalar = parseDeviceStatus({ ok: true, value: 'nope' })
  assert.equal(scalar.kind, 'unknown')

  // 命令本身失败：reason 原样带上，便于支持排查
  const failed = parseDeviceStatus({ ok: false, reason: '客户端版本过低（缺 device_status）' })
  assert.equal(failed.kind, 'unknown')
  assert.match(failed.reason, /device_status/)
})

/* ============ presentBond：卡片呈现与按钮门禁 ============ */

test('🔴 未配对：解除配对按钮必须不可点 + 引导去配对', async () => {
  const { presentBond, UNPAIRED_HINT } = await load()

  const view = presentBond({ kind: 'unpaired' })

  // 核心断言：这就是「没配对却显示解除配对」的直接防线
  assert.equal(view.canUnpair, false)
  assert.match(view.title, /未绑定/)
  assert.equal(view.text, UNPAIRED_HINT)
  // 未配对不是故障，用 warn 而非 error
  assert.equal(view.tone, 'warn')
})

test('已配对：允许解除，文案含设备 ID 与在线状态', async () => {
  const { presentBond } = await load()

  const online = presentBond({ kind: 'paired', deviceId: 'dev-1', online: true, signedIn: true, userLabel: null })
  assert.equal(online.canUnpair, true)
  assert.match(online.text, /dev-1/)
  assert.match(online.text, /在线/)
  assert.match(online.title, /已绑定/)
  assert.equal(online.tone, 'ok')

  const offline = presentBond({ kind: 'paired', deviceId: 'dev-2', online: false, signedIn: true, userLabel: null })
  assert.match(offline.text, /离线/)
})

test('已配对但未上报 deviceId：文案给出占位而不是 undefined', async () => {
  const { presentBond } = await load()

  const view = presentBond({ kind: 'paired', deviceId: null, online: true, signedIn: false, userLabel: null })
  assert.doesNotMatch(view.text, /undefined|null/)
  assert.match(view.text, /未上报/)
})

test('读不出：同样阻止解除（fail-closed），并用 error 色说明原因', async () => {
  const { presentBond } = await load()

  const view = presentBond({ kind: 'unknown', reason: '设备状态缺少 paired 字段（客户端版本可能过低）' })

  assert.equal(view.canUnpair, false)
  assert.match(view.title, /状态未知/)
  assert.match(view.text, /paired/)
  assert.equal(view.tone, 'error')
})

test('三态的 canUnpair 恰好只有「已配对」为 true（穷举，防新增态漏处理）', async () => {
  const { presentBond } = await load()

  const cases = [
    { state: { kind: 'paired', deviceId: 'd', online: true, signedIn: true, userLabel: null }, expected: true },
    { state: { kind: 'unpaired' }, expected: false },
    { state: { kind: 'unknown', reason: 'x' }, expected: false },
  ]

  for (const { state, expected } of cases) {
    assert.equal(
      presentBond(state).canUnpair,
      expected,
      `状态 ${state.kind} 的 canUnpair 应为 ${expected}`,
    )
  }
})

// ===== 登录态（signed_in）：与绑定态正交，是「配对后免二次登录」的呈现依据 =====

test('signed_in=true 且带 user_label：展示「已登录为 X，无需再次登录」', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, online: true, device_id: 'dev-z', signed_in: true, user_label: '张三' },
  })
  assert.equal(state.signedIn, true)
  assert.equal(state.userLabel, '张三')

  const view = presentBond(state)
  assert.match(view.text, /已登录为 张三/)
  assert.match(view.text, /无需再次登录/)
  // 登录态不影响解绑权限：解绑仍是已配对即可。
  assert.equal(view.canUnpair, true)
})

test('signed_in=true 但 user_label 缺失：仍算已登录，只是不显示账号名', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, online: true, signed_in: true },
  })
  assert.equal(state.signedIn, true)
  assert.equal(state.userLabel, null)

  const view = presentBond(state)
  assert.match(view.text, /已登录/)
  assert.doesNotMatch(view.text, /为 |undefined|null/)
})

test('signed_in 缺失（旧服务端）：降级为未登录，提示仍需登录一次', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  // 这是兼容性核心断言：老壳/老服务端不会返回 signed_in，
  // 此时必须按「未登录」呈现（安全方向），而不是默默声称已登录。
  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, online: true, device_id: 'dev-old' },
  })
  assert.equal(state.signedIn, false)
  assert.equal(state.userLabel, null)

  const view = presentBond(state)
  assert.match(view.text, /尚未登录/)
  assert.match(view.text, /需要先登录一次/)
})

test('signed_in 非布尔（脏数据）：严格只认 true，一律按未登录处理', async () => {
  const { parseDeviceStatus } = await load()

  for (const bad of ['true', 1, {}, null, undefined]) {
    const state = parseDeviceStatus({
      ok: true,
      value: { paired: true, signed_in: bad },
    })
    assert.equal(state.signedIn, false, `signed_in=${JSON.stringify(bad)} 应视为未登录`)
  }
})

test('user_label 为空白串：归一成 null 而不是留空显示', async () => {
  const { parseDeviceStatus } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, signed_in: true, user_label: '   ' },
  })
  assert.equal(state.signedIn, true)
  assert.equal(state.userLabel, null)
})

/* ===== 登出（sign_out）：与解绑正交，额外要求已登录 ===== */

test('🔴 canSignOut 只在「已配对且已登录」时为 true', async () => {
  const { presentBond } = await load()

  // 已配对 + 已登录 → 可登出
  assert.equal(
    presentBond({ kind: 'paired', deviceId: 'd', online: true, signedIn: true, userLabel: 'a' })
      .canSignOut,
    true,
  )
  // 已配对 + 未登录 → 无从登出（旧服务端不签发会话时的常态）
  assert.equal(
    presentBond({ kind: 'paired', deviceId: 'd', online: true, signedIn: false, userLabel: null })
      .canSignOut,
    false,
  )
  // 未配对 / 读不出 → 一律不可
  assert.equal(presentBond({ kind: 'unpaired' }).canSignOut, false)
  assert.equal(presentBond({ kind: 'unknown', reason: 'x' }).canSignOut, false)
})

test('🔴 登出与解绑正交：已登录的已配对设备两者都可用', async () => {
  const { presentBond } = await load()

  const v = presentBond({
    kind: 'paired',
    deviceId: 'd',
    online: true,
    signedIn: true,
    userLabel: 'alice',
  })
  // 解绑只要求已配对；登出额外要求已登录。二者是**不同**的门禁，不能合并。
  assert.equal(v.canUnpair, true, '解绑只要求已配对')
  assert.equal(v.canSignOut, true, '登出额外要求已登录')
})

test('bondVisibility：showSignOut 由 signedIn 单独驱动，不能用 paired 推断', async () => {
  const { bondVisibility } = await load()

  // 已配对已登录 → 显示
  assert.equal(
    bondVisibility({ kind: 'paired', deviceId: 'd', online: true, signedIn: true, userLabel: null })
      .showSignOut,
    true,
  )
  // 已配对未登录 → 隐藏（若用 paired 推断就会错显一个永远点不动的按钮）
  assert.equal(
    bondVisibility({ kind: 'paired', deviceId: 'd', online: true, signedIn: false, userLabel: null })
      .showSignOut,
    false,
  )
  // 未配对 / 读不出 → 隐藏（fail-closed）
  assert.equal(bondVisibility({ kind: 'unpaired' }).showSignOut, false)
  assert.equal(bondVisibility({ kind: 'unknown', reason: 'x' }).showSignOut, false)
})

test('bondVisibility：配对表单与解绑互斥这条不变（登出不参与互斥）', async () => {
  const { bondVisibility } = await load()

  const paired = bondVisibility({
    kind: 'paired',
    deviceId: 'd',
    online: true,
    signedIn: true,
    userLabel: null,
  })
  // 已配对时：无配对表单、有解绑、有登出（三者共存是合法的 —— 登出与解绑正交）
  assert.equal(paired.showPairingForm, false)
  assert.equal(paired.showUnpair, true)
  assert.equal(paired.showSignOut, true)
})

/* ===== 会话失效（session_invalid）：设备令牌自续失败的呈现 ===== */

test('session_invalid 缺失（旧服务端 / 会话仍有效）：归一成 null', async () => {
  const { parseDeviceStatus } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, online: true, signed_in: true, user_label: '张三' },
  })
  assert.equal(state.sessionInvalid, null)
})

test('session_invalid 非字符串或空白：一律归一成 null（不把脏数据当原因）', async () => {
  const { parseDeviceStatus } = await load()

  for (const bad of [123, true, {}, null, undefined, '   ']) {
    const state = parseDeviceStatus({
      ok: true,
      value: { paired: true, session_invalid: bad },
    })
    assert.equal(state.sessionInvalid, null, `session_invalid=${JSON.stringify(bad)} 应为 null`)
  }
})

test('session_invalid 有效短串：原样带上（后端契约取值不得被改写）', async () => {
  const { parseDeviceStatus } = await load()

  for (const reason of ['expired', 'revoked', 'owner_unknown', 'network', 'unknown']) {
    const state = parseDeviceStatus({
      ok: true,
      value: { paired: true, signed_in: false, session_invalid: reason },
    })
    assert.equal(state.sessionInvalid, reason)
  }
})

test('🔴 已配对 + 未登录 + session_invalid=expired：文案说明「过期且续期未成功」', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, online: true, device_id: 'dev-e', signed_in: false, session_invalid: 'expired' },
  })
  const view = presentBond(state)
  assert.match(view.text, /过期/)
  assert.match(view.text, /续期/)
  // 过期可自愈 → 保持 ok 色，不吓用户
  assert.equal(view.tone, 'ok')
  // 绑定仍在：解绑入口必须依然可用（这正是「配对照旧有效」的语义）
  assert.equal(view.canUnpair, true)
  assert.equal(view.canSignOut, false)
})

test('🔴 session_invalid=revoked：文案指向「重新配对」，色调转 warn', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, signed_in: false, session_invalid: 'revoked' },
  })
  const view = presentBond(state)
  assert.match(view.text, /吊销/)
  assert.match(view.text, /重新/)
  assert.match(view.text, /配对/)
  assert.equal(view.tone, 'warn', '不可自愈的失效必须用 warn 色提醒用户动手')
})

test('🔴 session_invalid=owner_unknown：文案指向「重新配对绑定账号」', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, signed_in: false, session_invalid: 'owner_unknown' },
  })
  const view = presentBond(state)
  assert.match(view.text, /账号/)
  assert.match(view.text, /重新配对/)
  assert.equal(view.tone, 'warn')
})

test('session_invalid=network：文案说明「连不上、稍后重试」，不自愈也保持 ok 色', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, signed_in: false, session_invalid: 'network' },
  })
  const view = presentBond(state)
  assert.match(view.text, /连不上/)
  assert.equal(view.tone, 'ok')
})

test('未知的 session_invalid 取值：回落通用文案，绝不留空也绝不编造原因', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, signed_in: false, session_invalid: 'brand_new_reason_from_future' },
  })
  const view = presentBond(state)
  assert.equal(state.sessionInvalid, 'brand_new_reason_from_future')
  assert.match(view.text, /会话已失效/)
  // 通用文案必须是「可操作但不误导」：既提登录也提重新配对。
  assert.match(view.text, /登录/)
  assert.match(view.text, /配对/)
})

test('🔴 已登录时 session_invalid 不影响文案（会话好的，原因残留不该冒出来）', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: true, signed_in: true, user_label: '张三', session_invalid: 'expired' },
  })
  const view = presentBond(state)
  // 已登录就按已登录说，绝不能同时说「会话已过期」——那是自相矛盾的界面。
  assert.match(view.text, /已登录为 张三/)
  assert.doesNotMatch(view.text, /过期/)
  assert.equal(view.tone, 'ok')
})

test('🔴 三态语义不退化：session_invalid 存在也不能把 unknown 归成 unpaired', async () => {
  const { parseDeviceStatus } = await load()

  // 缺 paired 字段 + 带 session_invalid → 仍是 unknown（fail-closed），
  // 绝不能因为「有失效原因」就推断出「确定未配对」。
  const state = parseDeviceStatus({
    ok: true,
    value: { online: true, session_invalid: 'expired' },
  })
  assert.equal(state.kind, 'unknown')
})

test('🔴 三态语义不退化：paired=false 且带 session_invalid 仍是 unpaired', async () => {
  const { parseDeviceStatus, presentBond } = await load()

  const state = parseDeviceStatus({
    ok: true,
    value: { paired: false, session_invalid: 'revoked' },
  })
  // paired 是判别字段：明确未配对就是 unpaired，失效原因无从附着（也不该显示）。
  assert.equal(state.kind, 'unpaired')
  assert.equal(presentBond(state).canUnpair, false)
})

test('sessionInvalidHint 穷举：五个契约取值 + null 都有非空文案', async () => {
  const { sessionInvalidHint } = await load()

  for (const reason of ['expired', 'network', 'revoked', 'owner_unknown', 'unknown', null]) {
    const hint = sessionInvalidHint(reason)
    assert.equal(typeof hint, 'string')
    assert.ok(hint.length > 0, `${reason} 必须给出文案`)
  }
  // 两个"重试无用"的分支都必须明确提到重新配对。
  assert.match(sessionInvalidHint('revoked'), /重新/)
  assert.match(sessionInvalidHint('owner_unknown'), /重新配对/)
})
