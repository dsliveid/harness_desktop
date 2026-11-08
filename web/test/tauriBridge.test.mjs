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
})

afterEach(() => {
  delete globalThis.__TAURI__
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
