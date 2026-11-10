/**
 * `runnerPhase.ts` 的单测：钉死「后端相位 → UI 语义」的映射。
 *
 * ## 为什么这些断言值得写
 *
 * 这张映射表是本轮新增的唯一「解释层」：后端 `lifecycle.rs` 说 `backoff`，
 * 用户需要看到「重连中，正在自动恢复」而不是一个红叉。映射错了不会崩，
 * 但会让用户在系统正自愈时去点重启，反而打断恢复过程 —— 属于「不报错但有害」
 * 的一类缺陷，只能靠测试钉死。
 */
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  RUNNER_PHASES,
  describe,
  describeWithRestarts,
  isRunnerPhase,
} from './.build/runnerPhase.mjs'

test('RUNNER_PHASES 覆盖后端全部 8 个相位', () => {
  // 与 hd-host/src/lifecycle.rs 的 RunnerPhase 变体一一对应。
  // 后端新增变体而此处未跟进时，describe() 会走「状态未识别」兜底，
  // 因此这条断言是发现漂移的第一道防线。
  assert.equal(RUNNER_PHASES.length, 8)
  for (const p of [
    'idle',
    'needs_pairing',
    'running',
    'stopped',
    'backoff',
    'gave_up',
    'shutting_down',
    'externally_running',
  ]) {
    assert.ok(RUNNER_PHASES.includes(p), `缺少相位 ${p}`)
  }
})

test('isRunnerPhase 只接受已知相位', () => {
  assert.equal(isRunnerPhase('running'), true)
  assert.equal(isRunnerPhase('externally_running'), true)
  assert.equal(isRunnerPhase('nonsense'), false)
  assert.equal(isRunnerPhase(undefined), false)
  assert.equal(isRunnerPhase(42), false)
})

test('running 是唯一「健康且能干活」的相位', () => {
  const d = describe('running')
  assert.equal(d.tone, 'ok')
  assert.equal(d.canWork, true)
  assert.equal(d.transient, false)
})

test('backoff 是自愈中间态：warn 而非 error', () => {
  // 这是本文件最重要的一条：重连中用红色会让用户误以为要手动介入。
  const d = describe('backoff')
  assert.equal(d.tone, 'warn', '重连中不该报成故障')
  assert.equal(d.transient, true, '应提示「正在自动恢复」')
  assert.equal(d.canWork, false)
})

test('gave_up 才是真正需要人介入的故障', () => {
  const d = describe('gave_up')
  assert.equal(d.tone, 'error')
  assert.equal(d.transient, false, '放弃重试后不该再说「请稍候」')
})

test('idle（启动中）用中性色调，不吓人', () => {
  const d = describe('idle')
  assert.equal(d.tone, 'muted', '首帧的「启动中」不是故障')
  assert.equal(d.transient, true)
})

test('needs_pairing 不是故障，是可操作状态', () => {
  const d = describe('needs_pairing')
  assert.equal(d.tone, 'warn')
  assert.equal(d.canWork, false)
  assert.equal(d.transient, false, '需要用户操作，不能只说「请稍候」')
})

test('externally_running：能干活但不归本实例管', () => {
  // 这一条最容易被误解成「故障」。实际本机在正常执行任务，
  // 只是 config 要在另一个实例里改 —— 因此 canWork=true 但 tone=warn。
  const d = describe('externally_running')
  assert.equal(d.canWork, true, '本机确实在执行任务')
  assert.equal(d.tone, 'warn', '但本窗口改配置不生效，要提醒用户')
})

test('shutting_down 与 stopped 都是中性态', () => {
  for (const p of ['shutting_down', 'stopped']) {
    const d = describe(p)
    assert.equal(d.tone, 'muted', `${p} 不该用红/黄色`)
    assert.equal(d.canWork, false)
  }
})

test('未知相位必须显示「未识别」而不是伪装成健康', () => {
  // 核心不变量：后端将来新增相位而前端没跟随时，用户要能看出「状态没读明白」，
  // 而不是看到一片绿色以为一切正常。
  for (const bad of ['future_phase', '', undefined, null, 123]) {
    const d = describe(bad)
    assert.equal(d.label, '状态未识别')
    assert.equal(d.tone, 'error')
    assert.equal(d.canWork, false)
  }
})

test('describeWithRestarts 只在真发生过重启时附带次数', () => {
  // restarts=0 时显示「已重启 0 次」会让用户以为这是可调参数。
  assert.equal(describeWithRestarts('running', 0), '运行中')
  assert.equal(describeWithRestarts('running', 3), '运行中（已重启 3 次）')
  // 异常输入不该产生「已重启 NaN 次」这种文案。
  assert.equal(describeWithRestarts('running', Number.NaN), '运行中')
  assert.equal(describeWithRestarts('running', -1), '运行中')
})
