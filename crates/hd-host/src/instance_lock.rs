//! 单实例锁：保证「本机只有一个宿主进程负责拉起 Runner」。
//!
//! ## 为什么需要它
//!
//! [`crate::bootstrap::Bootstrap::ensure_running`] 的幂等判断原先只看
//! `Daemon::is_running()` —— 那是**本进程手里的 `Child` 句柄**，不是「本机有没有
//! 执行引擎在跑」这个事实。用户双击两次图标、或用另一个快捷方式启动时，两个宿主
//! 各自 spawn 一个 Runner，同一设备令牌开出两条 WS 连接，服务端给旧连接发
//! `device.replaced` 并断开，用户看到的是「刚启动就掉线」。
//!
//! ## 为什么用 OS 独占文件锁，而不是「读 pid 再判断进程是否存活」
//!
//! pid 会被系统复用（Windows 上尤其快），用 pid 判活会出现两类误判：
//! 1. 锁文件里的 pid 恰好被别的进程占用 → 明明没人在跑却拒绝启动；
//! 2. 持锁进程已崩溃、pid 被回收 → 永远卡在「有人持有锁」。
//!
//! 操作系统提供的独占锁没有这两个问题：锁的持有者就是**打开该文件句柄的进程**，
//! 进程以任何方式死亡（含崩溃/被杀）时内核都会释放锁，天然不会留下 stale 锁。
//!
//! 不变量：**只要进程还活着且句柄未关闭，锁就不会被同一路径上的第二次
//! `try_acquire` 抢到**；反之句柄一关（含 drop）立即释放。

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;

/// 锁文件名（放在本地应用数据目录下，与配对档案同级层次）。
pub const LOCK_FILE_NAME: &str = "runner.lock";

/// 应用数据子目录名（与 `profile` 的档案目录保持同一命名空间）。
const APP_DIR_NAME: &str = "harness_desktop";

/// 本机唯一实例锁。
///
/// 持有它 == 「本机由我负责拉起 Runner」。**生命周期必须覆盖 Runner 的整个运行期**，
/// 提前 drop 会因为释放锁而让下一个宿主误判「没人在跑」并再 spawn 一份。
pub struct InstanceLock {
    /// 持有锁的句柄。锁本身与句柄同生共死，故这个字段**不允许**被优化掉或提前关闭。
    file: File,
    /// 锁文件路径（仅用于日志与排障，不参与判活）。
    path: PathBuf,
}

impl InstanceLock {
    /// 尝试抢占锁。
    ///
    /// - `Ok(Some(lock))`：抢到，本机当前没人在负责 Runner；
    /// - `Ok(None)`：已被其它进程持有 —— 调用方**不得**再 spawn；
    /// - `Err(e)`：目录不可写等真实 IO 故障（调用方应按启动失败处理）。
    pub fn try_acquire(path: impl AsRef<Path>) -> std::io::Result<Option<Self>> {
        let path = path.as_ref().to_path_buf();

        // 目录可能尚未创建（首次运行的新机器），先补建。
        // 不吞这个错误：目录建不出来说明数据目录权限异常，此时继续启动只会在
        // 后续写档案时以更难懂的形式失败。
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            // 显式 truncate(false)：锁文件的内容无意义（只靠 OS 锁语义），
            // 但 `create(true)` 而不声明 truncate 会让 clippy 认为意图不明。
            // 这里明确「不截断」——截断会改变别的进程已打开句柄的视图，毫无必要。
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;

        // 用 try_ 变体而非阻塞 lock：抢不到要立刻返回「外部已在运行」，
        // 卡在这里会让 GUI 首帧无限期等待。
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self { file, path })),
            Err(e) if is_lock_contended(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 默认锁文件路径：`<本地数据目录>/harness_desktop/runner.lock`。
    ///
    /// 不用 `current_dir()`：进程工作目录可能是用户随便点开的位置（甚至只读），
    /// 放在那里会导致不同启动方式算出不同锁文件，锁形同虚设。
    pub fn default_path() -> std::io::Result<PathBuf> {
        let base = dirs::data_local_dir().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "无法确定本地数据目录（dirs::data_local_dir 返回 None）",
            )
        })?;
        Ok(base.join(APP_DIR_NAME).join(LOCK_FILE_NAME))
    }

    /// 锁文件路径（日志/排障用）。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // 显式 unlock：虽然关闭句柄也会释放，但显式释放能让「何时释放」不依赖
        // 字段 drop 顺序（File 是最后一个被 drop 的字段还是中途？不留这种疑问）。
        // 失败只可能发生在句柄已失效时，属无害场景。
        //
        // 必须写成 `FileExt::unlock(&self.file)` 而非 `self.file.unlock()`：
        // 后者会解析到 std 的 `File::unlock`（Rust 1.89 才稳定），
        // 而本仓 MSRV 是 1.79，用完整路径显式指向 fs2 的实现。
        let _ = FileExt::unlock(&self.file);
        tracing::debug!(path = %self.path.display(), "实例锁已释放");
    }
}

/// 判断错误是否表示「锁被别的进程占着」。
///
/// 这里必须按平台区分，不能一律映射成 `Ok(None)`：真正的 IO 故障（磁盘只读、
/// 路径是目录等）被当成「外部在运行」会让启动静默跳过，比直接报错更难排查。
fn is_lock_contended(e: &std::io::Error) -> bool {
    // Unix: EWOULDBLOCK/EAGAIN；Windows: ERROR_LOCK_VIOLATION(33)。
    // 用原始错误码判断而不依赖 ErrorKind：Windows 上 fs2 返回的是 Other。
    matches!(e.kind(), std::io::ErrorKind::WouldBlock) || matches!(e.raw_os_error(), Some(33))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 核心不变量：同一路径上的第二把锁必须拿不到。
    ///
    /// 这正是「第二次双击图标不再开第二个 Runner」的底层保证；
    /// 若哪天有人把它改成「读 pid 判活」，本测试仍会通过而在真实机器上失灵，
    /// 因此断言里额外检查「第一把 drop 之后第二把能拿到」来钉住语义。
    #[test]
    fn second_acquire_returns_none_until_first_is_dropped() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let path = dir.path().join(LOCK_FILE_NAME);

        let first = InstanceLock::try_acquire(&path).expect("第一次抢占不应报错");
        let first = first.expect("第一把锁必须能拿到");
        assert_eq!(first.path(), path.as_path());

        let second = InstanceLock::try_acquire(&path).expect("第二次抢占不应报错");
        assert!(second.is_none(), "别人持有时必须返回 None，绝不能重复拉起");

        drop(first);
        let third = InstanceLock::try_acquire(&path).expect("释放后抢占不应报错");
        assert!(third.is_some(), "锁释放后必须能再次抢占");
    }

    /// 目录不存在时要自动补建：首次运行的机器上数据目录还是空的。
    #[test]
    fn creates_missing_parent_directory() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let nested = dir.path().join("a").join("b").join(LOCK_FILE_NAME);
        let lock = InstanceLock::try_acquire(&nested).expect("抢占不应报错");
        assert!(lock.is_some(), "父目录应被自动创建");
        assert!(nested.exists(), "锁文件应被创建：{}", nested.display());
    }

    #[test]
    fn default_path_ends_with_lock_file_name() {
        // data_local_dir 在极端环境下可能为 None，此时允许返回 Err ——
        // 但只要能拿到路径，文件名就必须是约定的那个。
        if let Ok(p) = InstanceLock::default_path() {
            assert_eq!(p.file_name().and_then(|s| s.to_str()), Some(LOCK_FILE_NAME));
            assert!(p.to_string_lossy().contains(APP_DIR_NAME));
        }
    }
}
