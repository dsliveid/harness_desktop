/**
 * tauriBridge 单测（node:test，零额外依赖）。
 *
 * 覆盖的核心是 §14.6 的降级契约 —— 这三条一旦回退，远程 UI 就会在旧壳上「点了才报错」：
 *   ① 无 __TAURI__ → probe 返回不可用（浏览器端不是异常路径）；
 *   ② 有壳但清单缺命令 → 返回带命令名的降级 reason；
 *   ③ call 在 invoke 抛错时返回 null，绝不把异常漏给 UI。
 */

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  COMMANDS,
  NO_TAURI_REASON,
  call,
  callResult,
  hasTauriRuntime,
  normalizeSupported,
  probe,
  probeMany,
  resetCapabilityCache,
} from './.build/tauriBridge.mjs'

/** 记录本次用例里壳收到了哪些命令，用于验证「清单只问一次」 */
const invokeLog = []

/**
 * 注入一个假 __TAURI__（v2 形状）。
 * handler 收到的 (cmd, args) 由各用例决定返回什么或抛什么。
 */
function installFakeTauri(handler) {
  globalThis.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        invokeLog.push(cmd)
        return handler(cmd, args)
      },
    },
  }
}

beforeEach(() => {
  invokeLog.length = 0
  resetCapabilityCache()
  delete globalThis.__TAURI__
  delete globalThis.__TAURI_INTERNALS__
})

afterEach(() => {
  delete globalThis.__TAURI__
  delete globalThis.__TAURI_INTERNALS__
  resetCapabilityCache()
})

test('无 __TAURI__：probe 返回不可用且原因为「当前为浏览器端」', async () => {
  const state = await probe(COMMANDS.checkUpdate)
  assert.equal(state.ok, false)
  assert.equal(state.reason, NO_TAURI_REASON)
  // 浏览器端不应触发任何 IPC
  assert.deepEqual(invokeLog, [])
})

test('有 __TAURI__ 但清单不含该命令：返回含缺失命令名的降级 reason', async () => {
  installFakeTauri((cmd) => {
    if (cmd === COMMANDS.listCommands) return [COMMANDS.openSettings]
    throw new Error(`unexpected command ${cmd}`)
  })

  const state = await probe(COMMANDS.checkUpdate)
  assert.equal(state.ok, false)
  // 「缺 <命令>」是给用户/客服定位版本问题的关键信息，必须带上
  assert.match(state.reason, /版本过低/)
  assert.match(state.reason, new RegExp(COMMANDS.checkUpdate))
})

test('清单含该命令：probe 返回可用', async () => {
  installFakeTauri((cmd) => {
    if (cmd === COMMANDS.listCommands) {
      return { supported: [COMMANDS.checkUpdate, COMMANDS.openSettings, COMMANDS.openLogs] }
    }
    throw new Error(`unexpected command ${cmd}`)
  })

  const state = await probe(COMMANDS.checkUpdate)
  assert.deepEqual(state, { ok: true })
})

test('list_commands 本身失败：按「无法获取能力清单」降级而非抛错', async () => {
  installFakeTauri((cmd) => {
    if (cmd === COMMANDS.listCommands) throw new Error('command not found')
    throw new Error(`unexpected command ${cmd}`)
  })

  const state = await probe(COMMANDS.openLogs)
  assert.equal(state.ok, false)
  assert.match(state.reason, /无法获取客户端能力清单/)
})

test('call：invoke 抛错时返回 null 而不是抛出', async () => {
  installFakeTauri(() => {
    throw new Error('boom')
  })

  // 关键断言：这里的 await 不能抛
  const result = await call(COMMANDS.checkUpdate)
  assert.equal(result, null)
})

test('call：无 __TAURI__ 时返回 null 且不抛', async () => {
  const result = await call(COMMANDS.openSettings)
  assert.equal(result, null)
})

test('call：成功时原样返回壳的返回值', async () => {
  installFakeTauri((cmd, args) => ({ echo: cmd, args }))

  const result = await call(COMMANDS.openLogs, { level: 'warn' })
  assert.deepEqual(result, { echo: COMMANDS.openLogs, args: { level: 'warn' } })
})

test('能力清单只问壳一次（同会话缓存）', async () => {
  installFakeTauri((cmd) => {
    if (cmd === COMMANDS.listCommands) return [COMMANDS.checkUpdate]
    throw new Error(`unexpected command ${cmd}`)
  })

  await probe(COMMANDS.checkUpdate)
  await probe(COMMANDS.openSettings)
  const listCalls = invokeLog.filter((c) => c === COMMANDS.listCommands).length
  assert.equal(listCalls, 1)
})

test('probeMany：一次渲染批量拿到各命令状态', async () => {
  installFakeTauri((cmd) => {
    if (cmd === COMMANDS.listCommands) return [COMMANDS.checkUpdate, COMMANDS.openLogs]
    throw new Error(`unexpected command ${cmd}`)
  })

  const states = await probeMany([COMMANDS.checkUpdate, COMMANDS.openSettings, COMMANDS.openLogs])
  assert.equal(states.get(COMMANDS.checkUpdate).ok, true)
  assert.equal(states.get(COMMANDS.openSettings).ok, false)
  assert.equal(states.get(COMMANDS.openLogs).ok, true)
})

test('normalizeSupported：兼容数组与 {supported} / {commands} 三种形状', () => {
  assert.deepEqual(normalizeSupported(['a', 'b']), ['a', 'b'])
  assert.deepEqual(normalizeSupported({ supported: ['a'] }), ['a'])
  assert.deepEqual(normalizeSupported({ commands: ['b'] }), ['b'])
  // 脏数据过滤：非字符串元素不能进清单
  assert.deepEqual(normalizeSupported(['a', 1, null]), ['a'])
  // 无法识别一律返回 null（调用方据此全降级）
  assert.equal(normalizeSupported('nope'), null)
  assert.equal(normalizeSupported(null), null)
})

/* ============ 运行形态判定（🔴 回归：withGlobalTauri 缺失事故） ============ */

test('hasTauriRuntime：无任何壳全局对象时为 false（真浏览器端）', () => {
  assert.equal(hasTauriRuntime(), false)
})

test('hasTauriRuntime：__TAURI__.core.invoke 存在时为 true（v2 公开入口）', () => {
  installFakeTauri(() => null)
  assert.equal(hasTauriRuntime(), true)
})

test('hasTauriRuntime：仅 v1 形状 __TAURI__.tauri.invoke 也算壳内', () => {
  globalThis.__TAURI__ = { tauri: { invoke: async () => null } }
  assert.equal(hasTauriRuntime(), true)
})

test('hasTauriRuntime：__TAURI__ 存在但没有 invoke 时不算壳内（不能误判可用）', () => {
  // 空壳对象是最危险的形态：看着有 __TAURI__，实际调不通任何命令。
  // 若这里返回 true，按钮就会放开点击，点下去才失败 —— 正是要杜绝的体验。
  globalThis.__TAURI__ = {}
  assert.equal(hasTauriRuntime(), false)
})

test('🔴 回归：未开 withGlobalTauri 时仅靠 __TAURI_INTERNALS__ 也能用（本次事故根因）', async () => {
  // 事故现场：tauri.conf.json 缺 app.withGlobalTauri（Tauri 2 默认 false），
  // 于是 window.__TAURI__ 根本不存在，而 __TAURI_INTERNALS__ 由初始化脚本无条件注入。
  // 修复前这里会整体降级成「当前为浏览器端」，所有本机能力按钮一起置灰。
  assert.equal(globalThis.__TAURI__, undefined)
  globalThis.__TAURI_INTERNALS__ = {
    invoke: async (cmd) => {
      invokeLog.push(cmd)
      if (cmd === COMMANDS.listCommands) return [COMMANDS.runnerStatus]
      return { state: 'running' }
    },
  }

  assert.equal(hasTauriRuntime(), true)

  const state = await probe(COMMANDS.runnerStatus)
  assert.equal(state.ok, true)
  // 关键：不能再落到「浏览器端」那条降级分支上
  assert.notEqual(state.reason, NO_TAURI_REASON)

  const raw = await call(COMMANDS.runnerStatus)
  assert.deepEqual(raw, { state: 'running' })
})

test('__TAURI__ 与 __TAURI_INTERNALS__ 同时存在时优先用公开入口', async () => {
  // 公开入口才是稳定契约；内部 API 仅兜底。两者共存时必须先试公开的那个。
  installFakeTauri(() => 'from-public')
  globalThis.__TAURI_INTERNALS__ = { invoke: async () => 'from-internals' }

  assert.equal(await call(COMMANDS.checkUpdate), 'from-public')
})

test('__TAURI_INTERNALS__.invoke 的 this 被绑定（内部实现可依赖接收者）', async () => {
  // 内部实现若用 this 存状态，裸取函数再调用会静默丢接收者 → 报错。
  // 桥接层 bind 过，这里用依赖 this 的实现来验。
  globalThis.__TAURI_INTERNALS__ = {
    marker: 'bound-ok',
    async invoke() {
      return this.marker
    },
  }
  assert.equal(await call(COMMANDS.checkUpdate), 'bound-ok')
})

/* ============ callResult：分离「失败」与「成功返回 unit」 ============ */

test('🔴 回归：命令成功返回 null（Rust unit）必须判为 ok，不能报失败', async () => {
  // 事故现场：unpair_device 的 Rust 签名是 `Result<(), String>`，
  // 成功时序列化就是 null。旧 call() 用 null 同时表示「失败」和「成功返回 unit」，
  // 导致后端的「已解除配对」日志与前端「命令未成功」提示直接矛盾。
  installFakeTauri(() => null)

  const r = await callResult(COMMANDS.unpairDevice)

  assert.equal(r.ok, true, '成功返回 null 必须是 ok:true')
  assert.equal(r.value, null)
})

test('callResult：无壳时 ok:false 并带「浏览器端」原因（与 call 的 null 区分开）', async () => {
  const r = await callResult(COMMANDS.checkUpdate)

  assert.equal(r.ok, false)
  assert.equal(r.reason, NO_TAURI_REASON)
})

test('callResult：invoke 抛错时 ok:false 且 reason 可读，绝不 throw', async () => {
  installFakeTauri(() => {
    throw new Error('Command unpair_device not found')
  })

  const r = await callResult(COMMANDS.unpairDevice)

  assert.equal(r.ok, false)
  assert.match(r.reason, /unpair_device/)
})

test('callResult：字符串型 reject（Err(String) 命令）也能转成人话', async () => {
  installFakeTauri(() => {
    // Tauri 对 `Err(String)` 的 command，reject 值就是那个字符串
    throw '清除设备令牌失败：密钥链被锁定'
  })

  const r = await callResult(COMMANDS.unpairDevice)

  assert.equal(r.ok, false)
  assert.match(r.reason, /密钥链被锁定/)
})

test('callResult：成功返回对象时原样透传', async () => {
  installFakeTauri(() => ({ paired: true, online: true, device_id: 'dev-x' }))

  const r = await callResult(COMMANDS.deviceStatus)

  assert.equal(r.ok, true)
  assert.deepEqual(r.value, { paired: true, online: true, device_id: 'dev-x' })
})

test('call 仍保持旧契约：成功返回 null 时给 null（兼容既有调用方）', async () => {
  installFakeTauri(() => null)
  assert.equal(await call(COMMANDS.unpairDevice), null)
})
