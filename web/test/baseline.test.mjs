/**
 * 基线 UI 启动分支单测（node:test + 自建 DOM 桩）。
 *
 * 为什么必须测这块：§14.5 的核心要求不是「界面好看」，而是**服务端不可达时不得白屏**
 * 且**能力不足时按钮提前置灰**。这两条是兜底界面的存在意义，必须有回归护栏。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

import { assertHtmlCoverage, createDocument } from './fake-dom.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
// Windows 上动态 import 必须转成 file:// URL，否则 Node 会把 `D:` 当成协议报
// ERR_UNSUPPORTED_ESM_URL_SCHEME
const BASELINE = pathToFileURL(path.join(here, '.build/baseline.mjs')).href
const INDEX_HTML = path.join(here, '../index.html')

/** 等所有微任务/宏任务落地（bootstrap 内部有两级 await） */
async function flush(rounds = 6) {
  for (let i = 0; i < rounds; i += 1) {
    await new Promise((r) => setImmediate(r))
  }
}

/**
 * 在指定环境（document / location / fetch / __TAURI__）下加载一份**全新**的基线模块。
 * 用递增 query 破 ESM 模块缓存，否则第二次 import 会拿到上一用例的副作用。
 */
let caseSeq = 0
async function loadBaseline({ fetchImpl, tauri, confirmImpl }) {
  const { doc, buttons, server, capability, diag } = createDocument()
  globalThis.document = doc
  globalThis.location = { origin: 'http://127.0.0.1:7777', href: 'http://127.0.0.1:7777/' }
  globalThis.fetch = fetchImpl
  // 基线界面用 confirm 做不可逆操作的二次确认。Node 里没有它，
  // 不桩就会在点「解除配对」时抛 ReferenceError（与真实浏览器行为不符）。
  globalThis.confirm = confirmImpl ?? (() => true)
  if (tauri) globalThis.__TAURI__ = tauri
  else delete globalThis.__TAURI__

  caseSeq += 1
  await import(`${BASELINE}?case=${caseSeq}`)
  // readyState=loading → 走 DOMContentLoaded 分支（与真实浏览器一致）
  doc.fire('DOMContentLoaded')
  await flush()
  // 表单区块与输入框：供配对相关用例断言显隐与取值
  const pairingSection = doc.querySelector('#pairing')
  const bindingSection = doc.querySelector('#device-binding')
  const signInSection = doc.querySelector('#sign-in')
  const signOutRow = doc.querySelector('#sign-out-row')
  const pairServer = doc.querySelector('#pair-server')
  const pairCode = doc.querySelector('#pair-code')
  const pairName = doc.querySelector('#pair-name')
  const signUsername = doc.querySelector('#sign-username')
  const signPassword = doc.querySelector('#sign-password')
  return {
    doc,
    buttons,
    server,
    capability,
    diag,
    pairingSection,
    bindingSection,
    signInSection,
    signOutRow,
    pairServer,
    pairCode,
    pairName,
    signUsername,
    signPassword,
  }
}

/**
 * 造一个假壳：supported 决定能力清单，行为由各用例通过 extra 补充。
 *
 * ⚠️ `device_status` 必须返回**符合契约**的对象（含布尔 `paired`），不能落到默认的
 * `{ ok: true, cmd }`：那会被 `parseDeviceStatus` 判为「读不出」，从而把解除配对置灰，
 * 让「壳能力齐备 ⇒ 全部可点」这类用例意外失败（且失败原因与用例意图无关）。
 *
 * `signedIn` 与 `paired` **正交**：默认 false 表示「已配对但未自动登录」这个常态，
 * 与后端契约一致（旧服务端不签发会话）。
 */
function fakeTauri(
  supported,
  { paired = false, deviceId = null, online = false, signedIn = false, userLabel = null } = {},
) {
  return {
    core: {
      invoke: async (cmd) => {
        if (cmd === 'list_commands') return supported
        if (cmd === 'device_status') {
          return {
            paired,
            online,
            device_id: deviceId,
            app_version: '0.1.0',
            protocol_ok: true,
            signed_in: signedIn,
            user_label: userLabel,
          }
        }
        return { ok: true, cmd }
      },
    },
  }
}

const detail = (section) => section.querySelector('.line-detail')

/* ============ 项4：操作反馈三态（ok / warn / error） ============ */

/**
 * 三态判定的单测直接打 `desktop/actionFeedback.ts`（纯函数），不驱动 DOM。
 *
 * 为什么不做成「点按钮看文案」：三态里最关键的中间档（已保存但未下发）需要壳返回
 * `{ roots, pushed:false, warning }`，用 DOM 桩模拟也可以，但判定逻辑本身与 DOM 无关；
 * 单独测纯函数能让三条分支一一对应、失败时报错直指分支名。
 */
const ACTION_FEEDBACK_MOD = pathToFileURL(path.join(here, '.build/actionFeedback.mjs')).href

test('三态①：下发成功 → 文案「已保存并同步」，色调 ok（不是 warn/error）', async () => {
  const { describeActionResult, toneToReasonClass } = await import(ACTION_FEEDBACK_MOD)

  const fb = describeActionResult(
    'set_workspace_roots',
    { roots: ['C:\\ws'], pushed: true, warning: null },
    '已保存并同步到执行引擎',
  )
  assert.equal(fb.tone, 'ok')
  assert.match(fb.text, /已保存并同步/)
  assert.equal(toneToReasonClass(fb.tone), 'reason is-ok')
})

test('三态②：已保存但未下发 → warn 色 + 直接用后端 warning（绝不飘红）', async () => {
  const { describeActionResult, toneToReasonClass } = await import(ACTION_FEEDBACK_MOD)

  const warning = '工作区配置已保存，但未能同步到执行引擎：Runner 未运行。请重试或重启客户端'
  const fb = describeActionResult(
    'set_workspace_roots',
    { roots: ['C:\\ws'], pushed: false, warning },
    '已保存并同步到执行引擎',
  )
  // 🔴 核心断言：这一档**不是** error。红字只留给真故障。
  assert.equal(fb.tone, 'warn', '「已保存但未下发」不是故障，必须是 warn 而非 error')
  assert.equal(toneToReasonClass(fb.tone), 'reason is-warn')
  // 文案必须原样采用后端下发的 warning（后端才知道具体原因）
  assert.equal(fb.text, warning)
  // 且不能说成「未成功」——那是改造前的错误措辞
  assert.doesNotMatch(fb.text, /未成功/)
  assert.match(fb.text, /已保存/)
})

test('三态②兜底：pushed=false 但后端没给 warning → 用内置兜底文案且仍为 warn', async () => {
  const { describeActionResult, DEGRADED_PUSH_FALLBACK } = await import(ACTION_FEEDBACK_MOD)

  for (const warning of [null, '', '   ']) {
    const fb = describeActionResult(
      'set_workspace_roots',
      { roots: [], pushed: false, warning },
      '已保存并同步到执行引擎',
    )
    assert.equal(fb.tone, 'warn')
    assert.equal(fb.text, DEGRADED_PUSH_FALLBACK)
    // 兜底文案也必须说清「已保存」（否则与事实矛盾）
    assert.match(fb.text, /已保存/)
    assert.match(fb.text, /重试|重启/)
  }
})

test('三态③：null（真失败/无壳）→ error 色，沿用「未成功」文案', async () => {
  const { describeActionResult, toneToReasonClass } = await import(ACTION_FEEDBACK_MOD)

  const fb = describeActionResult('open_logs', null, '已请求打开日志')
  assert.equal(fb.tone, 'error')
  assert.equal(toneToReasonClass(fb.tone), 'reason is-error')
  assert.match(fb.text, /未成功/)
  assert.match(fb.text, /open_logs/)
})

test('非工作区结果（无 pushed 字段）按普通命令处理 → ok，不误判成 warn', async () => {
  const { describeActionResult } = await import(ACTION_FEEDBACK_MOD)

  // 壳若返回一个没有三态契约的对象（如 unpair 的空对象），不能因为「不是 null」
  // 就当成 pushed=false 去打黄字；它属于普通成功。
  const fb = describeActionResult('unpair_device', {}, '已解除配对')
  assert.equal(fb.tone, 'ok')
  assert.equal(fb.text, '已解除配对')
})

test('端到端：点按钮后发起的命令，reason 行带上对应的色调类', async () => {
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['check_update', 'open_settings', 'open_logs']
          throw new Error('壳内业务失败')
        },
      },
    },
  })

  buttons['open_logs'].btn.fire('click')
  await flush()
  // null → error：真失败才飘红
  assert.match(buttons['open_logs'].reason.className, /is-error/)

  const okCase = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'open_settings', 'open_logs']),
  })
  okCase.buttons['open_logs'].btn.fire('click')
  await flush()
  // 正常成功 → is-ok（不是默认的 warn）
  assert.match(okCase.buttons['open_logs'].reason.className, /is-ok/)
})

test('进入主界面：能力齐备时可点、点击发起 open_web_ui 并展示反馈文案', async () => {
  const { buttons, capability } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(
      ['check_update', 'open_settings', 'open_logs', 'open_web_ui', 'unpair_device', 'pair_device', 'sign_out', 'runner_status'],
      { paired: true, deviceId: 'dev-1', online: true, signedIn: true, userLabel: 'alice' },
    ),
  })

  // 未点击前：无 reason（门禁全过）
  assert.equal(buttons['open_web_ui'].btn.disabled, false)

  buttons['open_web_ui'].btn.fire('click')
  await flush()
  // 成功 → is-ok + 反馈文案（manual fallback 入口的存在性回归）
  assert.match(buttons['open_web_ui'].reason.className, /is-ok/)
  assert.match(buttons['open_web_ui'].reason.textContent, /主界面/)
  assert.ok(capability)
})

test('DOM 桩与真实 index.html 结构一致（防止桩脱节导致假绿）', async () => {
  const html = await readFile(INDEX_HTML, 'utf8')
  const built = createDocument()
  const stat = assertHtmlCoverage(html, built)
  // 至少要有 2 个状态卡、3 个按钮，否则下面的断言会失去意义
  assert.ok(stat.cmds >= 3, `按钮数异常：${stat.cmds}`)
  assert.ok(stat.ids >= 4, `id 数异常：${stat.ids}`)
})

test('服务端不可达：展示「服务端不可达，当前为内置基线，仅可查看本地信息」而非白屏', async () => {
  const { server, diag } = await loadBaseline({
    // 模拟网络错误（浏览器里 fetch 失败表现为 TypeError，这里等价模拟）
    fetchImpl: async () => {
      throw new TypeError('Failed to fetch')
    },
  })

  assert.equal(server.dataset['state'], 'error')
  const text = detail(server).textContent
  assert.match(text, /服务端不可达/)
  assert.match(text, /当前为内置基线/)
  assert.match(text, /仅可查看本地信息/)
  assert.match(text, /网络不可达/)
  // 「不白屏」的可观测代理指标：诊断行必须被填充
  assert.match(diag.textContent, /http:\/\/127\.0\.0\.1:7777/)
})

test('本地文件加载（origin=null）：给出可解释文案而非 "null/healthz" 报错', async () => {
  const { doc, server } = createDocument()
  globalThis.document = doc
  // file:// 场景下浏览器里 location.origin 就是字符串 "null"
  globalThis.location = { origin: 'null', href: 'file:///D:/baseline/index.html' }
  let fetched = false
  globalThis.fetch = async () => {
    fetched = true
    return { ok: true, json: async () => ({}) }
  }
  delete globalThis.__TAURI__

  caseSeq += 1
  await import(`${BASELINE}?case=${caseSeq}`)
  doc.fire('DOMContentLoaded')
  await flush()

  assert.equal(server.dataset['state'], 'error')
  assert.match(server.querySelector('.line-detail').textContent, /本地文件方式加载/)
  // 关键：连 fetch 都不该发出（否则控制台会出现 "null/healthz" 的费解报错）
  assert.equal(fetched, false)
})

test('服务端探测超时：文案标注 3s 超时且仍落在错误态', async () => {
  const { server } = await loadBaseline({
    fetchImpl: async () => {
      const err = new Error('aborted')
      err.name = 'AbortError'
      throw err
    },
  })

  assert.equal(server.dataset['state'], 'error')
  assert.match(detail(server).textContent, /3s 超时/)
})

test('服务端可达：展示版本与协议号', async () => {
  const { server, diag } = await loadBaseline({
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok', version: '1.2.3', protocol_version: '7' }),
    }),
  })

  assert.equal(server.dataset['state'], 'ok')
  assert.match(detail(server).textContent, /v1\.2\.3/)
  assert.match(detail(server).textContent, /协议 7/)
  assert.match(diag.textContent, /1\.2\.3/)
})

test('浏览器端（无 __TAURI__）：三个按钮全部置灰并写明「当前为浏览器端」', async () => {
  const { buttons, capability } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
  })

  for (const cmd of ['check_update', 'open_settings', 'open_logs']) {
    assert.equal(buttons[cmd].btn.disabled, true, `${cmd} 应置灰`)
    // 置灰必须同时给原因：只置灰不解释会让用户以为程序坏了
    assert.match(buttons[cmd].reason.textContent, /当前为浏览器端/)
    assert.match(buttons[cmd].btn.getAttribute('title') ?? '', /当前为浏览器端/)
  }
  // 浏览器端不是故障 → warn 而非 error
  assert.equal(capability.dataset['state'], 'warn')
})

test('壳缺命令：只有缺失项置灰且 reason 带命令名，其余可点', async () => {
  const { buttons, capability } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    // 故意只支持 2 个，缺 open_logs
    tauri: fakeTauri(['check_update', 'open_settings']),
  })

  assert.equal(buttons['check_update'].btn.disabled, false)
  assert.equal(buttons['open_settings'].btn.disabled, false)
  assert.equal(buttons['open_logs'].btn.disabled, true)
  assert.match(buttons['open_logs'].reason.textContent, /版本过低/)
  assert.match(buttons['open_logs'].reason.textContent, /open_logs/)
  assert.equal(capability.dataset['state'], 'warn')
})

test('壳能力齐备且已配对：全部可点且不显示任何 reason', async () => {
  const { buttons, capability } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    // 必须列出界面上的**全部** data-cmd，否则 `summarizeCapability` 会因
    // 「有按钮不可用」而降级为 warn —— 这是真实行为，不是测试放宽。
    // 注意含 pair_device / sign_out：它们也是界面按钮，漏列会让能力汇总降级。
    tauri: fakeTauri(
      [
        'check_update',
        'open_settings',
        'open_logs',
        'open_web_ui',
        'sign_in',
        'unpair_device',
        'pair_device',
        'sign_out',
        'runner_status',
      ],
      // 解除配对要可点，前置条件是**已配对**（业务门禁，见 deviceBond.ts）
      { paired: true, deviceId: 'dev-1', online: true, signedIn: true, userLabel: 'alice' },
    ),
  })

  for (const cmd of [
    'check_update',
    'open_settings',
    'open_logs',
    'open_web_ui',
    'unpair_device',
    'sign_out',
  ]) {
    assert.equal(buttons[cmd].btn.disabled, false, `${cmd} 应可点`)
    assert.equal(buttons[cmd].reason.textContent, '')
  }
  assert.equal(capability.dataset['state'], 'ok')
})

test('🔴 回归：壳能力齐备但**未配对**时，解除配对必须置灰并引导去配对', async () => {
  // 这就是「明明没配对，为什么就到取消配对界面了」的直接防线。
  // 修复前：只要壳支持 unpair_device 就放开点击，与是否配对毫无关系。
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'open_settings', 'open_logs', 'unpair_device'], {
      paired: false,
    }),
  })

  assert.equal(buttons['unpair_device'].btn.disabled, true, '未配对时解除配对不可点')
  assert.match(buttons['unpair_device'].reason.textContent, /未配对/)
  // 其他按钮不受业务门禁影响
  assert.equal(buttons['check_update'].btn.disabled, false)
})

test('壳能力齐备但 device_status 读不出：解除配对同样置灰（fail-closed）', async () => {
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') {
            return ['check_update', 'open_settings', 'open_logs', 'unpair_device']
          }
          // 形状不合契约（缺 paired）→ 归一成 unknown → 不放行
          return { something: 'else' }
        },
      },
    },
  })

  assert.equal(buttons['unpair_device'].btn.disabled, true, '读不出状态时不得放行解除配对')
  assert.match(buttons['unpair_device'].reason.textContent, /paired|未知|不可识别/)
})

test('点击可用按钮：调用成功后在 reason 行给出人话反馈', async () => {
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'open_settings', 'open_logs']),
  })

  buttons['open_settings'].btn.fire('click')
  await flush()
  assert.match(buttons['open_settings'].reason.textContent, /已请求打开设置页/)
})

/* ============ 配对界面（本次补齐的核心需求） ============ */

test('🔴 未配对时：配对表单可见、解除配对区块隐藏', async () => {
  // 需求：界面必须有配对入口，否则用户看到「请先输入配对码」却无处可输。
  const { pairingSection, bindingSection } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'pair_device', 'unpair_device'], { paired: false }),
  })

  assert.equal(pairingSection.hidden, false, '未配对时配对表单必须可见')
  assert.equal(bindingSection.hidden, true, '未配对时解除配对区块必须隐藏')
})

test('🔴 已配对时：解除配对区块可见、配对表单隐藏（两者互斥）', async () => {
  const { pairingSection, bindingSection } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'pair_device', 'unpair_device'], {
      paired: true,
      deviceId: 'dev-9',
      online: true,
    }),
  })

  assert.equal(pairingSection.hidden, true, '已配对时不该再显示配对表单')
  assert.equal(bindingSection.hidden, false)
})

/* ============ 原生登录（契约一，2026-11） ============ */

test('🔴 已配对未登录时：登录卡片可见、配对表单与登出隐藏', async () => {
  const { pairingSection, signInSection, bindingSection, signOutRow } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'sign_in', 'unpair_device', 'sign_out'], {
      paired: true,
      deviceId: 'dev-9',
      signedIn: false,
    }),
  })

  assert.equal(signInSection.hidden, false, '已配对未登录必须显示原生登录表单')
  assert.equal(pairingSection.hidden, true, '已配对时不再显示配对表单')
  assert.equal(bindingSection.hidden, false, '解除配对仍可见（配对态未变）')
  assert.equal(signOutRow.hidden, true, '未登录时没有「退出登录」可点')
})

test('🔴 已配对已登录时：登录卡片隐藏（没有可点的登录入口）', async () => {
  const { signInSection } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'sign_in', 'unpair_device', 'sign_out'], {
      paired: true,
      deviceId: 'dev-9',
      signedIn: true,
      userLabel: 'alice',
    }),
  })

  assert.equal(signInSection.hidden, true, '已登录不该再显示登录表单')
})

test('🔴 未配对时：登录卡片隐藏（先配对，配对码才是获取会话的入口）', async () => {
  const { signInSection, pairingSection } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'sign_in', 'unpair_device', 'sign_out'], {
      paired: false,
    }),
  })

  assert.equal(signInSection.hidden, true, '未配对时不该显示登录表单')
  assert.equal(pairingSection.hidden, false, '未配对时应显示配对表单')
})

test('🔴 登录提交：空输入被前端拦截（不发起 IPC）', async () => {
  let called = false
  const { buttons, signUsername } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['sign_in']
          if (cmd === 'device_status') {
            return { paired: true, online: true, device_id: 'dev-9', signed_in: false }
          }
          if (cmd === 'sign_in') {
            called = true
            return { signed_in: true, user_label: 'op' }
          }
          return null
        },
      },
    },
  })

  signUsername.value = 'op'
  signUsername.fire('input')
  await flush()
  buttons['sign_in'].btn.fire('click')
  await flush()

  assert.equal(called, false, '密码为空时不应发起登录请求')
  assert.match(buttons['sign_in'].reason.textContent, /请输入密码/)
})

test('🔴 登录提交：参数为 {username, password}，成功后文案带账号名', async () => {
  let captured = null
  let signedIn = false
  const { buttons, signUsername, signPassword } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd, args) => {
          if (cmd === 'list_commands') return ['sign_in', 'unpair_device']
          if (cmd === 'device_status') {
            return {
              paired: true,
              online: true,
              device_id: 'dev-9',
              signed_in: signedIn,
              user_label: signedIn ? 'op' : null,
            }
          }
          if (cmd === 'sign_in') {
            captured = args
            signedIn = true
            return { signed_in: true, user_label: '操作员' }
          }
          return null
        },
      },
    },
  })

  signUsername.value = 'op'
  signPassword.value = 'secret'
  signPassword.fire('input')
  await flush()
  buttons['sign_in'].btn.fire('click')
  await flush()

  assert.ok(captured, '应真的调用了 sign_in')
  assert.equal(captured.username, 'op')
  assert.equal(captured.password, 'secret')
  assert.match(buttons['sign_in'].reason.textContent, /操作员/)
})

test('🔴 登录失败：服务端拒绝原文上抛（保留错误码，色调 error）', async () => {
  const { buttons, signUsername, signPassword } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['sign_in']
          if (cmd === 'device_status') {
            return { paired: true, online: true, device_id: 'dev-9', signed_in: false }
          }
          if (cmd === 'sign_in') throw new Error('登录失败（auth.invalid_credentials）：用户名或密码错误')
          return null
        },
      },
    },
  })

  signUsername.value = 'op'
  signPassword.value = 'bad'
  signPassword.fire('input')
  await flush()
  buttons['sign_in'].btn.fire('click')
  await flush()

  const text = buttons['sign_in'].reason.textContent
  assert.match(text, /用户名或密码错误/)
})


test('服务端地址：默认值已预填（跨机部署才需要改）', async () => {
  const { pairServer } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['pair_device'], { paired: false }),
  })

  assert.equal(pairServer.value, 'http://127.0.0.1:5611')
})

test('配对按钮：未填配对码时置灰，并说明原因', async () => {
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['pair_device'], { paired: false }),
  })

  assert.equal(buttons['pair_device'].btn.disabled, true, '空配对码不得放行')
  assert.match(buttons['pair_device'].reason.textContent, /配对码/)
})

test('配对按钮：填入合法配对码后放开点击', async () => {
  const { buttons, pairCode } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['pair_device'], { paired: false }),
  })

  pairCode.value = 'ABC123'
  pairCode.fire('input')
  await flush()

  assert.equal(buttons['pair_device'].btn.disabled, false, '合法输入应放行')
})

test('配对码输入即时归一：小写与连字符自动处理', async () => {
  const { pairCode } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['pair_device'], { paired: false }),
  })

  pairCode.value = 'ab12-cd34'
  pairCode.fire('input')
  await flush()

  // 用户看到的就是将要提交的值，避免「看着输对了却被后端拒」
  assert.equal(pairCode.value, 'AB12CD34')
})

test('🔴 配对提交：参数名必须是 serverBaseUrl（Tauri 的 camelCase 映射）', async () => {
  // 传错名字的后果是参数被静默忽略 → 地址永远回落默认值，
  // 跨机部署静默失效且极难查。这里直接断言实际发出的参数。
  let captured = null
  let paired = false
  const { buttons, pairCode, pairServer, pairName } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd, args) => {
          if (cmd === 'list_commands') return ['pair_device', 'unpair_device']
          if (cmd === 'device_status') {
            return { paired, online: false, device_id: paired ? 'dev-new' : null }
          }
          if (cmd === 'pair_device') {
            captured = args
            paired = true
            return { accepted: true, message: '配对成功，执行引擎已启动' }
          }
          return null
        },
      },
    },
  })

  pairServer.value = '192.168.1.5:9000'
  pairCode.value = 'ABC123'
  pairName.value = 'my-pc'
  pairCode.fire('input')
  await flush()

  buttons['pair_device'].btn.fire('click')
  await flush()

  assert.ok(captured, '应真的调用了 pair_device')
  assert.equal(captured.code, 'ABC123')
  assert.equal(captured.name, 'my-pc')
  // 🔴 关键：参数名是 camelCase，且地址已归一
  assert.equal(captured.serverBaseUrl, 'http://192.168.1.5:9000')
})

test('配对成功后：界面切到已绑定（表单隐藏、解除配对可见）', async () => {
  let paired = false
  const { buttons, pairingSection, bindingSection, pairCode } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['pair_device', 'unpair_device']
          if (cmd === 'device_status') {
            return { paired, online: true, device_id: paired ? 'dev-new' : null }
          }
          if (cmd === 'pair_device') {
            paired = true
            return { accepted: true, message: '配对成功，执行引擎已启动' }
          }
          return null
        },
      },
    },
  })

  pairCode.value = 'ABC123'
  pairCode.fire('input')
  await flush()
  buttons['pair_device'].btn.fire('click')
  await flush()

  assert.equal(pairingSection.hidden, true, '配对成功后表单应隐藏')
  assert.equal(bindingSection.hidden, false, '配对成功后解除配对区块应出现')
})

test('配对失败：reason 行给出具体原因，且表单仍可见可重试', async () => {
  const { buttons, pairingSection, pairCode } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['pair_device']
          if (cmd === 'device_status') return { paired: false, online: false }
          if (cmd === 'pair_device') throw '配对码无效或已过期'
          return null
        },
      },
    },
  })

  pairCode.value = 'ABC123'
  pairCode.fire('input')
  await flush()
  buttons['pair_device'].btn.fire('click')
  await flush()

  assert.match(buttons['pair_device'].reason.textContent, /配对码无效|过期/)
  assert.equal(pairingSection.hidden, false, '失败后表单必须保留，供用户重试')
})

/* ============ 退出登录（sign_out，与解绑正交） ============ */

test('🔴 已配对且已登录：显示「退出登录」且可点；解绑也同时可用（两者正交）', async () => {
  // 登出只清会话、保留设备绑定，因此与解绑**必须同时存在**。
  // 若把登出做成「连设备一起解绑」，用户只想换账号却得重新找配对码
  // —— 这是移动端已踩过并修正的坑。
  const { buttons, signOutRow } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['unpair_device', 'sign_out'], {
      paired: true,
      deviceId: 'dev-1',
      online: true,
      signedIn: true,
      userLabel: 'alice',
    }),
  })

  assert.equal(signOutRow.hidden, false, '已登录时应显示退出登录')
  assert.equal(buttons['sign_out'].btn.disabled, false, '登出应可点')
  assert.equal(buttons['unpair_device'].btn.disabled, false, '解绑同样可用（正交，不互斥）')
})

test('🔴 已配对但未登录：隐藏「退出登录」（没登录就无从登出）', async () => {
  const { buttons, signOutRow } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['unpair_device', 'sign_out'], {
      paired: true,
      deviceId: 'dev-1',
      online: true,
      signedIn: false,
    }),
  })

  assert.equal(signOutRow.hidden, true, '未登录不得显示登出按钮')
  // 解绑不受登录态影响：它只要求已配对
  assert.equal(buttons['unpair_device'].btn.disabled, false)
})

test('未配对：隐藏「退出登录」', async () => {
  const { signOutRow } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['unpair_device', 'sign_out'], { paired: false }),
  })

  assert.equal(signOutRow.hidden, true)
})

test('🔴 登出成功后：设备仍绑定（解绑按钮仍在），但登出按钮消失', async () => {
  // 这是「登出 ≠ 解绑」最关键的行为断言：登出后设备仍是已配对状态。
  let signedIn = true
  const { buttons, signOutRow, bindingSection } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['unpair_device', 'sign_out']
          if (cmd === 'device_status') {
            return { paired: true, online: true, device_id: 'dev-1', signed_in: signedIn }
          }
          if (cmd === 'sign_out') {
            signedIn = false
            return null // Result<(), _> 成功返回 unit
          }
          return null
        },
      },
    },
  })

  assert.equal(signOutRow.hidden, false)
  buttons['sign_out'].btn.fire('click')
  await flush()

  // 关键断言：**没有**触发解绑，设备仍绑定
  assert.equal(bindingSection.hidden, false, '登出后设备绑定区块仍应可见')
  assert.equal(signOutRow.hidden, true, '登出后登出按钮应消失')
  assert.equal(buttons['unpair_device'].btn.disabled, false, '设备仍配对，解绑仍可用')
})

test('登出成功后 reason 行显示登出结果（不被刷新抹掉）', async () => {
  let signedIn = true
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['unpair_device', 'sign_out']
          if (cmd === 'device_status') {
            return { paired: true, online: true, device_id: 'dev-1', signed_in: signedIn }
          }
          if (cmd === 'sign_out') {
            signedIn = false
            return null
          }
          return null
        },
      },
    },
  })

  buttons['sign_out'].btn.fire('click')
  await flush()

  assert.match(buttons['sign_out'].reason.textContent, /已退出登录/)
})

test('旧壳无 sign_out：按钮置灰并说明需升级（不误报为可用）', async () => {
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    // 已登录但壳不支持 sign_out
    tauri: fakeTauri(['unpair_device'], {
      paired: true,
      deviceId: 'dev-1',
      online: true,
      signedIn: true,
    }),
  })

  assert.equal(buttons['sign_out'].btn.disabled, true)
  assert.match(buttons['sign_out'].reason.textContent, /sign_out|升级/)
})

test('点击可用按钮但壳内失败：反馈具体原因而不是把异常抛到界面', async () => {
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') return ['check_update', 'open_settings', 'open_logs']
          throw new Error('壳内业务失败')
        },
      },
    },
  })

  buttons['open_logs'].btn.fire('click')
  await flush()
  // 新语义：callResult 把异常转成 ok:false + reason，界面展示**具体原因**，
  // 比过去笼统的「未成功，请重试或升级客户端」更有助于排查。
  assert.match(buttons['open_logs'].reason.textContent, /壳内业务失败/)
  assert.match(buttons['open_logs'].reason.textContent, /失败/)
})

test('🔴 回归：命令成功但返回 unit（null）时，不得报「未成功」', async () => {
  // 事故现场：unpair_device 的 Rust 签名是 Result<(), String>，成功时返回 null。
  // 旧实现用 `raw === null` 判失败 → 后端日志「已解除配对」与界面「命令未成功」直接矛盾。
  let paired = true
  const { buttons } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: {
      core: {
        invoke: async (cmd) => {
          if (cmd === 'list_commands') {
            return ['check_update', 'open_settings', 'open_logs', 'unpair_device']
          }
          if (cmd === 'device_status') {
            return { paired, online: false, device_id: 'dev-1' }
          }
          // unpair_device 成功：返回 null（unit）。同时模拟真实副作用 —— 解绑后不再有令牌。
          paired = false
          return null
        },
      },
    },
  })

  assert.equal(buttons['unpair_device'].btn.disabled, false, '已配对时应可点')
  buttons['unpair_device'].btn.fire('click')
  await flush()

  const text = buttons['unpair_device'].reason.textContent
  assert.doesNotMatch(text, /未成功/, `成功返回 null 不得报失败，实际文案：${text}`)
  assert.match(text, /已解除配对/, '应给出解绑成功的明确反馈')
  // 解绑成功后状态卡会刷新：按钮随之置灰，且整个绑定区块应被隐藏（未配对了）
  assert.equal(buttons['unpair_device'].btn.disabled, true)
})
