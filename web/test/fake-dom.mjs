/**
 * 极简 DOM 桩：只为测基线 UI 的**启动分支**（离线错误态 / 能力置灰）。
 *
 * 为什么不引 jsdom：
 *   1. 基线是零运行时依赖的兜底界面，为一个 260 行的 main.ts 拉进 jsdom（含大量
 *      传递依赖）不划算；
 *   2. 我们要验证的是「状态文案与按钮门禁的逻辑」，不是 DOM 引擎行为。
 *
 * 风险与对策：桩只支持本项目实际用到的少数选择器，一旦 main.ts 新增选择器这里会
 * 直接 throw（而不是静默返回 null 造成假绿）。另外 assertHtmlCoverage() 会拿真实
 * index.html 反查桩里的 id / data-cmd / data-reason-for，防止 HTML 改了桩没跟。
 */

/** 元素桩。classList 由 className 推导，避免维护两份状态 */
class FakeElement {
  constructor(tag, { id = '', className = '', dataset = {} } = {}) {
    this.tagName = tag.toUpperCase()
    this.id = id
    this.className = className
    this.dataset = { ...dataset }
    this.textContent = ''
    this.disabled = false
    this.attributes = new Map()
    this.children = []
    this.parent = null
    this.listeners = new Map()
  }

  get classList() {
    return this.className.split(/\s+/).filter(Boolean)
  }

  append(...kids) {
    for (const k of kids) {
      k.parent = this
      this.children.push(k)
    }
    return this
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value))
  }

  removeAttribute(name) {
    this.attributes.delete(name)
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null
  }

  addEventListener(type, fn) {
    const list = this.listeners.get(type) ?? []
    list.push(fn)
    this.listeners.set(type, list)
  }

  /** 测试用：手动触发事件 */
  fire(type) {
    for (const fn of this.listeners.get(type) ?? []) fn({ type, target: this })
  }

  /** 自身 + 全部后代（深度优先） */
  walk(out = []) {
    out.push(this)
    for (const c of this.children) c.walk(out)
    return out
  }

  querySelectorAll(selector) {
    return this.walk().slice(1).filter((el) => matches(el, selector))
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null
  }
}

/**
 * 选择器匹配：只实现本项目用到的四种写法。
 * 未知写法直接抛 —— 宁可测试红，也不要静默取不到元素。
 */
function matches(el, selector) {
  if (selector.startsWith('#')) return el.id === selector.slice(1)
  if (selector === '.line-detail') return el.classList.includes('line-detail')
  if (selector === 'button[data-cmd]') return el.tagName === 'BUTTON' && 'cmd' in el.dataset
  const reason = /^\[data-reason-for="(.+)"\]$/.exec(selector)
  if (reason) return el.dataset['reasonFor'] === reason[1]
  throw new Error(`[FakeDom] 不支持的 selector：${selector}（请同步更新 test/fake-dom.mjs）`)
}

/** 造一棵与 index.html 结构一致的镜像树 */
export function createDocument() {
  const app = new FakeElement('div', { id: 'app' })

  const mkStatus = (id) => {
    const sec = new FakeElement('section', { id, className: 'card status' })
    const detail = new FakeElement('p', { className: 'line-detail' })
    sec.append(detail)
    return sec
  }
  const server = mkStatus('server-status')
  // 执行引擎状态卡：与真实 index.html 的 #runner-status 对应。
  const runner = mkStatus('runner-status')
  const capability = mkStatus('capability-status')

  const actions = new FakeElement('section', { className: 'card actions' })
  const buttons = {}
  for (const cmd of ['check_update', 'open_settings', 'open_logs']) {
    const wrap = new FakeElement('div', { className: 'action' })
    const btn = new FakeElement('button', { dataset: { cmd } })
    const reason = new FakeElement('p', {
      className: 'reason',
      dataset: { reasonFor: cmd },
    })
    wrap.append(btn, reason)
    actions.append(wrap)
    buttons[cmd] = { btn, reason }
  }

  // 危险操作区块（解除配对）：结构同 actions，但独立成一块以匹配真实布局。
  const danger = new FakeElement('section', { className: 'card actions danger' })
  for (const cmd of ['unpair_device']) {
    const wrap = new FakeElement('div', { className: 'action' })
    const btn = new FakeElement('button', { dataset: { cmd } })
    const reason = new FakeElement('p', {
      className: 'reason',
      dataset: { reasonFor: cmd },
    })
    wrap.append(btn, reason)
    danger.append(wrap)
    buttons[cmd] = { btn, reason }
  }

  const diag = new FakeElement('p', { id: 'diag', className: 'diag' })
  const foot = new FakeElement('footer', { className: 'foot' })
  foot.append(diag)

  app.append(server, runner, capability, actions, danger, foot)

  const doc = {
    readyState: 'loading',
    listeners: new Map(),
    body: app,
    // document 级查询必须包含根节点自身（真实 document.querySelector('#app') 能命中）
    querySelector: (sel) => app.walk().find((el) => matches(el, sel)) ?? null,
    querySelectorAll: (sel) => app.walk().filter((el) => matches(el, sel)),
    addEventListener(type, fn) {
      const list = doc.listeners.get(type) ?? []
      list.push(fn)
      doc.listeners.set(type, list)
    },
    fire(type) {
      for (const fn of doc.listeners.get(type) ?? []) fn({ type })
    },
  }
  return { doc, buttons, server, capability, diag }
}

/**
 * 反查真实 index.html 与桩是否脱节：
 * 抽取 html 里的 id / data-cmd / data-reason-for，逐个确认桩里存在。
 * 这是「防止 HTML 改了、桩没改，测试假绿」的护栏。
 */
export function assertHtmlCoverage(html, built) {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1])
  for (const id of ids) {
    if (!built.doc.querySelector(`#${id}`)) {
      throw new Error(`[FakeDom] index.html 的 #${id} 未在测试桩中建模`)
    }
  }
  const cmds = [...html.matchAll(/data-cmd="([^"]+)"/g)].map((m) => m[1])
  for (const cmd of cmds) {
    if (!built.buttons[cmd]) throw new Error(`[FakeDom] index.html 的 data-cmd=${cmd} 未建模`)
  }
  const reasons = [...html.matchAll(/data-reason-for="([^"]+)"/g)].map((m) => m[1])
  for (const cmd of reasons) {
    if (!built.doc.querySelector(`[data-reason-for="${cmd}"]`)) {
      throw new Error(`[FakeDom] index.html 的 data-reason-for=${cmd} 未建模`)
    }
  }
  return { ids: ids.length, cmds: cmds.length, reasons: reasons.length }
}
