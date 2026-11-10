/**
 * 测试前置：把 tauriBridge.ts 打成 ESM 供 node:test 直接 import。
 *
 * 为什么不在测试里直接跑 TypeScript：
 *   - Node 22 的类型剥离仍需 --experimental-strip-types 开关，CI 里容易出现
 *     「本机绿、CI 红」的差异；
 *   - 项目本身零运行时依赖，也不想为测试再引入 tsx。
 * 复用已有 devDependency esbuild 最省事，且测的是**真实产物**而非另一条转译链。
 */

import { build } from 'esbuild'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const here = path.dirname(fileURLToPath(import.meta.url))

/**
 * 两个入口都要打：
 *  - tauriBridge：纯逻辑单测直接 import；
 *  - baseline/main：验证「启动即渲染 / 离线错误态 / 置灰」的真实分支
 *    （它 import 时会自动 bootstrap，因此测试里要在注入 DOM 桩后**动态** import）。
 */
const entries = [
  { src: '../src/desktop/tauriBridge.ts', out: '.build/tauriBridge.mjs' },
  { src: '../src/desktop/runnerPhase.ts', out: '.build/runnerPhase.mjs' },
  { src: '../src/baseline/main.ts', out: '.build/baseline.mjs' },
]

for (const { src, out } of entries) {
  await build({
    entryPoints: [path.join(here, src)],
    outfile: path.join(here, out),
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    target: ['es2020'],
    // 测试产物保留可读性，失败时栈里能看出是哪一行
    minify: false,
    sourcemap: false,
    logLevel: 'warning',
  })
}

console.log('[test] 已打包 test/.build/tauriBridge.mjs 与 test/.build/baseline.mjs')
