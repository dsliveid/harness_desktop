/**
 * 基线构建脚本（esbuild）。为什么用 esbuild 而不是 vite：
 *  - 基线只有一个入口 + 一份手写 CSS，不需要 dev server / HMR / 插件链；
 *  - esbuild 产物小、启动快，且**不会**引入 rollup 生态那堆传递依赖；
 *  - 关键：本脚本零 npm 逻辑分支，只做「打包 + 拷贝静态骨架」，便于 CI 里定位。
 *
 * 产物目录 dist-baseline/ 是 shell 内置资源的来源（后续由 hd-host 用
 * include_dir / rust-embed 打进去），因此**必须自包含**：index.html 里的相对路径
 * 要能在 dist-baseline 内闭环解析。
 */

import { build } from 'esbuild'
import { cp, mkdir, readdir, rm, stat } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const here = path.dirname(fileURLToPath(import.meta.url))
const outdir = path.join(here, 'dist-baseline')

/** §14.5 的体积预算：超了就是硬失败，不允许「先合进去后面再瘦身」 */
const SIZE_BUDGET_BYTES = 0.6 * 1024 * 1024

/** 递归统计目录字节数（产物是几十 KB 级，不必考虑大目录） */
async function dirSize(dir) {
  let total = 0
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      total += await dirSize(full)
    } else if (entry.isFile()) {
      total += (await stat(full)).size
    }
  }
  return total
}

function formatBytes(n) {
  // 四舍五入到整字节：预算值会出现小数（0.6*1024*1024=629145.6），显示 629146 才像人话
  return `${(n / 1024).toFixed(1)} KB (${Math.round(n)} 字节)`
}

async function main() {
  // 每次都清空：基线产物必须可复现，残留旧文件会让体积统计和 shell 内置资源失真
  await rm(outdir, { recursive: true, force: true })
  await mkdir(outdir, { recursive: true })

  await build({
    entryPoints: [path.join(here, 'src/baseline/main.ts')],
    outfile: path.join(outdir, 'main.js'),
    bundle: true,
    format: 'esm',
    // 桌面壳的 WebView2 / WKWebView 都支持 ES2020；不再往下降级，避免 polyfill 撑体积
    target: ['es2020'],
    minify: true,
    sourcemap: false,
    // 不注入任何 runtime helper 文件，产物保持「单文件 + 静态骨架」
    legalComments: 'none',
    logLevel: 'info',
  })

  // 静态骨架与样式直接拷贝（不参与打包，保持可读；两者合计不到 8KB）
  await cp(path.join(here, 'index.html'), path.join(outdir, 'index.html'))
  await cp(path.join(here, 'styles.css'), path.join(outdir, 'styles.css'))

  const total = await dirSize(outdir)
  const files = await readdir(outdir)
  console.log(`\n[baseline] 产物 ${files.length} 个文件：${files.join(', ')}`)
  console.log(`[baseline] dist-baseline 实测体积：${formatBytes(total)}`)

  if (total > SIZE_BUDGET_BYTES) {
    // 硬失败：体积预算是 §14.5 的约束，静默超限会让壳二进制无声膨胀
    console.error(
      `[baseline] 体积超预算：${formatBytes(total)} > ${formatBytes(SIZE_BUDGET_BYTES)}`,
    )
    process.exitCode = 1
    return
  }
  console.log(`[baseline] 体积预算 ${formatBytes(SIZE_BUDGET_BYTES)} ✅ 未超限`)
}

await main()
