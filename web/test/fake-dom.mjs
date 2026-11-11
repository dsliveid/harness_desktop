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
  constructor(tag, { id = '', className = '', dataset = {}, value = '' } = {}) {
    this.tagName = tag.toUpperCase()
    this.id = id
    this.className = className
    this.dataset = { ...dataset }
    this.textContent = ''
    this.disabled = false
    /** `<input>` 的当前值（受控于测试，main.ts 会读写它） */
    this.value = value
    /**
     * `hidden` 属性：main.ts 用它做区块显隐（配对表单 / 解除配对互斥）。
     * 默认 false —— 与浏览器一致（没有 hidden 属性就是可见）。
     */
    this.hidden = false
    this.attributes = new Map()
    this.children = []
    this.parent = null
    this.listeners = new Map()
  }

  get classList() {
    // 返回一个「既是数组、又带 add/remove/contains」的对象：
    // main.ts 既用它做 `.includes()` 判断，也用 `.add()/.remove()` 改类名。
    // 真实浏览器里 classList 是 DOMTokenList（不是数组），但本项目只用到这三个
    // 方法 + 数组式遍历，用「数组挂方法」最省事且行为一致。
    const self = this
    const list = self.className.split(/\s+/).filter(Boolean)
    list.add = (...names) => {
      const set = new Set(self.className.split(/\s+/).filter(Boolean))
      for (const n of names) set.add(n)
      self.className = [...set].join(' ')
    }
    list.remove = (...names) => {
      const set = new Set(self.className.split(/\s+/).filter(Boolean))
      for (const n of names) set.delete(n)
      self.className = [...set].join(' ')
    }
    list.contains = (name) => self.className.split(/\s+/).filter(Boolean).includes(name)
    // main.ts 用 `classList.toggle(name, force)` 做登录输入框的校验高亮切换
    // （有 force 参数时行为同 add/remove）。
    list.toggle = (name, force) => {
      const set = new Set(self.className.split(/\s+/).filter(Boolean))
      const has = set.has(name)
      const want = force === undefined ? !has : Boolean(force)
      if (want) set.add(name)
      else set.delete(name)
      self.className = [...set].join(' ')
      return want
    }
    return list
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

  // 配对表单区块：id="pairing"，未配对时显示（与解除配对互斥）。
  // 三个输入框 + 一个「立即配对」按钮。桩必须与真实 index.html 的 id 完全一致，
  // 否则 main.ts 读不到 input.value 会静默走默认值（假绿）。
  const pairing = new FakeElement('section', { id: 'pairing', className: 'card actions' })
  const pairingTitle = new FakeElement('strong', { className: 'line-title' })
  const pairServer = new FakeElement('input', { id: 'pair-server', value: '' })
  const pairCode = new FakeElement('input', { id: 'pair-code', value: '' })
  const pairName = new FakeElement('input', { id: 'pair-name', value: 'harness-desktop' })
  pairing.append(pairingTitle)
  for (const input of [pairServer, pairCode, pairName]) {
    const field = new FakeElement('div', { className: 'field' })
    field.append(input)
    pairing.append(field)
  }
  {
    const wrap = new FakeElement('div', { className: 'action' })
    const btn = new FakeElement('button', { dataset: { cmd: 'pair_device' } })
    const reason = new FakeElement('p', {
      className: 'reason',
      dataset: { reasonFor: 'pair_device' },
    })
    wrap.append(btn, reason)
    pairing.append(wrap)
    buttons['pair_device'] = { btn, reason }
  }
  // 初始隐藏：真实 HTML 带 hidden，由 device_status 决定是否显示
  pairing.hidden = true

  // 原生登录表单（契约一，2026-11）：已配对未登录时显示，与配对表单互斥。
  // id="sign-in" 必须与真实 index.html 一致（assertHtmlCoverage 反查覆盖）。
  // 🔴 放在 danger 声明**之前**没问题 —— 它不引用 danger（只有 device-binding
  // 卡片内的桩要挂在 danger 下才受 TDZ 约束）。
  const signInSection = new FakeElement('section', { id: 'sign-in', className: 'card actions' })
  const signInTitle = new FakeElement('strong', { className: 'line-title' })
  const signUsername = new FakeElement('input', { id: 'sign-username', value: '' })
  const signPassword = new FakeElement('input', { id: 'sign-password', value: '' })
  signInSection.append(signInTitle)
  for (const input of [signUsername, signPassword]) {
    const field = new FakeElement('div', { className: 'field' })
    field.append(input)
    signInSection.append(field)
  }
  {
    const wrap = new FakeElement('div', { className: 'action' })
    const btn = new FakeElement('button', { dataset: { cmd: 'sign_in' } })
    const reason = new FakeElement('p', {
      className: 'reason',
      dataset: { reasonFor: 'sign_in' },
    })
    wrap.append(btn, reason)
    signInSection.append(wrap)
    buttons['sign_in'] = { btn, reason }
  }
  // 初始隐藏：与配对表单同款（device_status 决定显隐）
  signInSection.hidden = true

  // 危险操作区块（解除配对）：结构同 actions，但独立成一块以匹配真实布局。
  // id="device-binding" 必须与真实 index.html 一致 —— assertHtmlCoverage() 会反查，
  // 桩漏建这个 id 时 main.ts 的标题渲染会静默取不到元素（假绿）。
  const danger = new FakeElement('section', {
    id: 'device-binding',
    className: 'card actions danger',
  })
  // 卡片标题：main.ts 会按「是否已配对」动态改写（已绑定 / 未绑定 / 状态未知）
  const dangerTitle = new FakeElement('strong', { className: 'line-title' })
  danger.append(dangerTitle)

  // 「进入主界面」按钮（2026-11）：真实 HTML 里它在 device-binding 卡片首位。
  // 必须在 danger 声明之后建（TDZ），位置与 index.html 结构一致（反查覆盖）。
  {
    const wrap = new FakeElement('div', { className: 'action' })
    const btn = new FakeElement('button', { dataset: { cmd: 'open_web_ui' } })
    const reason = new FakeElement('p', {
      className: 'reason',
      dataset: { reasonFor: 'open_web_ui' },
    })
    wrap.append(btn, reason)
    danger.append(wrap)
    buttons['open_web_ui'] = { btn, reason }
  }

  // 「退出登录」行：仅已配对且已登录时显示（id 必须与真实 index.html 一致）。
  // 独立成一行而不与解绑混排 —— 两者语义正交，混在一起用户会误点解绑。
  const signOutRow = new FakeElement('div', { id: 'sign-out-row', className: 'action' })
  signOutRow.hidden = true
  {
    const btn = new FakeElement('button', { dataset: { cmd: 'sign_out' } })
    const reason = new FakeElement('p', {
      className: 'reason',
      dataset: { reasonFor: 'sign_out' },
    })
    signOutRow.append(btn, reason)
    danger.append(signOutRow)
    buttons['sign_out'] = { btn, reason }
  }

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

  app.append(server, runner, capability, actions, pairing, signInSection, danger, foot)

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
