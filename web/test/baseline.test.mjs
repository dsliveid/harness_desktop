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
async function loadBaseline({ fetchImpl, tauri }) {
  const { doc, buttons, server, capability, diag } = createDocument()
  globalThis.document = doc
  globalThis.location = { origin: 'http://127.0.0.1:7777', href: 'http://127.0.0.1:7777/' }
  globalThis.fetch = fetchImpl
  if (tauri) globalThis.__TAURI__ = tauri
  else delete globalThis.__TAURI__

  caseSeq += 1
  await import(`${BASELINE}?case=${caseSeq}`)
  // readyState=loading → 走 DOMContentLoaded 分支（与真实浏览器一致）
  doc.fire('DOMContentLoaded')
  await flush()
  return { doc, buttons, server, capability, diag }
}

/** 造一个假壳：supported 决定能力清单，行为由各用例通过 extra 补充 */
function fakeTauri(supported) {
  return {
    core: {
      invoke: async (cmd) => {
        if (cmd === 'list_commands') return supported
        return { ok: true, cmd }
      },
    },
  }
}

const detail = (section) => section.querySelector('.line-detail')

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

test('壳能力齐备：全部可点且不显示任何 reason', async () => {
  const { buttons, capability } = await loadBaseline({
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'ok' }) }),
    tauri: fakeTauri(['check_update', 'open_settings', 'open_logs']),
  })

  for (const cmd of ['check_update', 'open_settings', 'open_logs']) {
    assert.equal(buttons[cmd].btn.disabled, false, `${cmd} 应可点`)
    assert.equal(buttons[cmd].reason.textContent, '')
  }
  assert.equal(capability.dataset['state'], 'ok')
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

test('点击可用按钮但壳内失败：反馈「未成功」而不是把异常抛到界面', async () => {
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
  // call() 已把异常降级为 null，界面只看到「未成功」
  assert.match(buttons['open_logs'].reason.textContent, /未成功/)
})
