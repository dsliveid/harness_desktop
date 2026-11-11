/**
 * pairingForm 单测：配对码归一/校验、服务端地址归一、设备名默认。
 *
 * ## 这份测试为哪个真实需求而写
 *
 * 基线界面长期**没有任何配对入口**，只提示「请先输入配对码完成设备绑定」却没有输入框；
 * 也**没有服务端地址输入**，导致服务端不跑在本机 5611 时完全无法配对。
 *
 * ## 为什么要把地址归一测这么细
 *
 * 后端 `PairingClient::new(base)` 只做字符串拼接。用户手填 `192.168.1.5:5611`
 * （无 scheme）时，若不补 `http://` 就会拼出非法 URL，而错误信息对普通用户毫无意义。
 * 归一逻辑一旦写错，表现是「配对永远失败且原因看不懂」—— 极难自查。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

const here = path.dirname(fileURLToPath(import.meta.url))
const MOD = pathToFileURL(path.join(here, '.build/pairingForm.mjs')).href

const load = () => import(MOD)

/* ============ 配对码归一 ============ */

test('配对码归一：小写转大写、去空白、剔连字符（用户手抄习惯）', async () => {
  const { normalizePairCode } = await load()

  assert.equal(normalizePairCode('ab12cd'), 'AB12CD')
  assert.equal(normalizePairCode('ab12-cd34'), 'AB12CD34')
  assert.equal(normalizePairCode('  AB12 CD34  '), 'AB12CD34')
})

/* ============ 服务端地址归一（🔴 跨机部署的关键） ============ */

test('地址归一：纯主机名补 http:// 与默认端口 5611', async () => {
  const { normalizeServerUrl, DEFAULT_SERVER_URL } = await load()

  // 留空 = 用默认（本机自用场景直接点「立即配对」即可）
  assert.deepEqual(normalizeServerUrl(''), { ok: true, url: DEFAULT_SERVER_URL })

  // 最常见的手填形态：只写 IP
  assert.deepEqual(normalizeServerUrl('192.168.1.5'), {
    ok: true,
    url: 'http://192.168.1.5:5611',
  })
})

test('地址归一：IP:端口 原样保留，不被重复补端口', async () => {
  const { normalizeServerUrl } = await load()

  assert.deepEqual(normalizeServerUrl('192.168.1.5:9000'), {
    ok: true,
    url: 'http://192.168.1.5:9000',
  })
  // 带 scheme 也应一致
  assert.deepEqual(normalizeServerUrl('http://192.168.1.5:9000'), {
    ok: true,
    url: 'http://192.168.1.5:9000',
  })
})

test('地址归一：去尾部斜杠（否则后端拼接会出双斜杠）', async () => {
  const { normalizeServerUrl } = await load()

  assert.deepEqual(normalizeServerUrl('http://192.168.1.5:5611/'), {
    ok: true,
    url: 'http://192.168.1.5:5611',
  })
  assert.deepEqual(normalizeServerUrl('http://192.168.1.5:5611///'), {
    ok: true,
    url: 'http://192.168.1.5:5611',
  })
})

test('地址归一：粘贴带路径时只保留 origin（路径由后端自己拼）', async () => {
  const { normalizeServerUrl } = await load()

  // 用户常整段粘贴 API 地址，带上路径会拼出错误 URL
  assert.deepEqual(normalizeServerUrl('http://10.0.0.7:5611/api/v1/devices/pair'), {
    ok: true,
    url: 'http://10.0.0.7:5611',
  })
})

test('地址归一：https 不擅自补 5611（几乎肯定是错的）', async () => {
  const { normalizeServerUrl } = await load()

  assert.deepEqual(normalizeServerUrl('https://example.com'), {
    ok: true,
    url: 'https://example.com',
  })
})

test('地址归一：非法输入给出可读原因而不是静默通过', async () => {
  const { normalizeServerUrl } = await load()

  const bad = normalizeServerUrl('http://')
  assert.equal(bad.ok, false)
  assert.match(bad.reason, /解析|主机名/)

  const proto = normalizeServerUrl('ftp://host')
  assert.equal(proto.ok, false)
  assert.match(proto.reason, /http/)
})

test('地址归一：localhost 与 127.0.0.1 都可用（不强制某一种）', async () => {
  const { normalizeServerUrl } = await load()

  assert.deepEqual(normalizeServerUrl('localhost:5611'), {
    ok: true,
    url: 'http://localhost:5611',
  })
})

/* ============ 整表单校验 ============ */

test('校验：合法输入返回归一后的三元组，可直接交给壳', async () => {
  const { validatePairing } = await load()

  const r = validatePairing({
    code: 'ab12-cd34',
    name: 'my-pc',
    serverUrl: '192.168.1.5:5611',
  })

  assert.equal(r.ok, true)
  // 配对码必须已归一，否则会带着连字符发给后端被拒
  assert.equal(r.code, 'AB12CD34')
  assert.equal(r.name, 'my-pc')
  assert.equal(r.serverUrl, 'http://192.168.1.5:5611')
})

test('校验：设备名留空时用默认值（后端会拒空名，前端兜住）', async () => {
  const { validatePairing, DEFAULT_DEVICE_NAME } = await load()

  const r = validatePairing({ code: 'ABC123', name: '   ', serverUrl: '' })

  assert.equal(r.ok, true)
  assert.equal(r.name, DEFAULT_DEVICE_NAME)
})

test('校验：配对码为空/过短/过长都拒，并指出是 code 字段', async () => {
  const { validatePairing } = await load()

  const empty = validatePairing({ code: '', name: 'x', serverUrl: '' })
  assert.equal(empty.ok, false)
  assert.equal(empty.field, 'code')
  assert.match(empty.reason, /请输入/)

  const tooShort = validatePairing({ code: 'AB1', name: 'x', serverUrl: '' })
  assert.equal(tooShort.ok, false)
  assert.equal(tooShort.field, 'code')
  assert.match(tooShort.reason, /6-12/)

  // 13 位（超过上限）
  const tooLong = validatePairing({ code: 'ABCDEFGHIJKLM', name: 'x', serverUrl: '' })
  assert.equal(tooLong.ok, false)
  assert.equal(tooLong.field, 'code')
})

test('校验：配对码含非法字符时拒绝（与 Rust 只允许大写字母数字同口径）', async () => {
  const { validatePairing } = await load()

  // 归一后仍含下划线 → 非法（说明手抄错了）
  const r = validatePairing({ code: 'AB_12CD', name: 'x', serverUrl: '' })
  assert.equal(r.ok, false)
  assert.equal(r.field, 'code')
  assert.match(r.reason, /大写字母与数字/)
})

test('校验：地址非法时**先**报地址错误（优先级高于配对码）', async () => {
  const { validatePairing } = await load()

  // 地址与配对码同时非法：应先说地址 —— 用户连目标服务端都没写对，
  // 报「配对码格式错」会把人引向错误方向。
  const r = validatePairing({ code: '!', name: 'x', serverUrl: 'http://' })
  assert.equal(r.ok, false)
  assert.equal(r.field, 'serverUrl')
})

test('校验：边界长度 6 与 12 都应通过（不要写成开区间）', async () => {
  const { validatePairing } = await load()

  assert.equal(validatePairing({ code: 'ABC123', name: 'x', serverUrl: '' }).ok, true)
  assert.equal(validatePairing({ code: 'ABCDEFGHIJKL', name: 'x', serverUrl: '' }).ok, true)
})

/* ============ 成功文案 ============ */

test('成功文案：signed_in 缺失（旧壳）时只用 message，不臆测登录态', async () => {
  const { describePairedSuccess } = await load()

  // 旧壳没有这个字段：既不能说「已登录」也不能说「需要登录」，否则都是误导
  const text = describePairedSuccess({ message: '配对成功，执行引擎已启动' })
  assert.equal(text, '配对成功，执行引擎已启动')
  assert.doesNotMatch(text, /登录/)
})

test('成功文案：signed_in=true 时明确告知已自动登录（免二次登录）', async () => {
  const { describePairedSuccess } = await load()

  const withLabel = describePairedSuccess({
    message: '配对成功，执行引擎已启动',
    signed_in: true,
    user_label: 'alice',
  })
  assert.match(withLabel, /配对成功/)
  assert.match(withLabel, /已自动登录为 alice/)

  // 服务端没回展示名也要说「已自动登录」，不能说「为 undefined」
  const noLabel = describePairedSuccess({ message: '配对成功', signed_in: true })
  assert.match(noLabel, /已自动登录/)
  assert.doesNotMatch(noLabel, /undefined|null/)
})

test('🔴 成功文案：signed_in=false 是合法降级，必须提示去登录（不是报错）', async () => {
  const { describePairedSuccess } = await load()

  // 后端注释明确要求：此时 UI 应提示「配对成功，请去 Web UI 登录」，而不是报错。
  // 若只说「配对成功」，用户进下一页撞上登录框却不知道为什么。
  const text = describePairedSuccess({
    message: '配对成功，执行引擎已启动',
    signed_in: false,
  })

  assert.match(text, /配对成功/, '仍是成功，不能表述成失败')
  assert.match(text, /登录/, '必须提前告知需要登录一次')
  assert.doesNotMatch(text, /失败|错误/)
})

test('成功文案：message 缺失时用兜底，但仍遵守 signed_in 分支', async () => {
  const { describePairedSuccess } = await load()

  assert.match(describePairedSuccess({}), /配对成功/)
  assert.match(describePairedSuccess(null), /配对成功/)
  // 空白 message 当缺失处理
  assert.match(describePairedSuccess({ message: '   ' }), /配对成功/)

  // 兜底文案 + 未登录提示
  const degraded = describePairedSuccess({ signed_in: false })
  assert.match(degraded, /配对成功/)
  assert.match(degraded, /登录/)
})
