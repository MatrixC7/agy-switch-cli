use crate::domain::account::validate_account_id;
use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::store::fs_atomic::{
    ensure_no_symlink_components_under, ensure_private_dir, map_io_error,
};
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Read;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

thread_local! {
    /// Tracks whether the current synchronous stack frame holds `StoreWriteLock` (L3).
    /// Because L3 is ONLY accessible through synchronous `with_store_write_lock` (`FnOnce`),
    /// it is compile-time impossible to `.await` or yield to another async task while `true`!
    static HELD_L3_STORE_LOCK: Cell<bool> = const { Cell::new(false) };
}

tokio::task_local! {
    /// Tracks active `PendingAuthLock` scope depth (`L1 -> PendingAuthLock -> L2 -> L3`).
    static PENDING_AUTH_LOCK_DEPTH: usize;
    /// Tracks active L2 `AccountRefreshLock` scope depth for the current async task/future.
    /// Bound 1-to-1 with `with_account_refresh_lock` (the sole L2 entry point).
    static L2_REFRESH_DEPTH: usize;
}

fn assert_not_holding_l3(requested_tier: &str) -> CliResult<()> {
    if HELD_L3_STORE_LOCK.with(|c| c.get()) {
        return Err(CliError::conflict(
            "lock_order_violation",
            format!(
                "Lock hierarchy violation: attempted to acquire {requested_tier} while holding L3 StoreWriteLock (required order: L1 -> PendingAuthLock -> L2 -> L3)."
            ),
        ));
    }
    Ok(())
}

fn assert_not_holding_l2_or_l3(requested_tier: &str) -> CliResult<()> {
    assert_not_holding_l3(requested_tier)?;
    if L2_REFRESH_DEPTH.try_with(|d| *d > 0).unwrap_or(false) {
        return Err(CliError::conflict(
            "lock_order_violation",
            format!(
                "Lock hierarchy violation: attempted to acquire {requested_tier} while holding L2 AccountRefreshLock (required order: L1 -> PendingAuthLock -> L2 -> L3)."
            ),
        ));
    }
    Ok(())
}

fn assert_not_holding_pending_or_l2_or_l3(requested_tier: &str) -> CliResult<()> {
    assert_not_holding_l2_or_l3(requested_tier)?;
    if PENDING_AUTH_LOCK_DEPTH
        .try_with(|d| *d > 0)
        .unwrap_or(false)
    {
        return Err(CliError::conflict(
            "lock_order_violation",
            format!(
                "Lock hierarchy violation: attempted to acquire {requested_tier} while holding PendingAuthLock (required order: L1 -> PendingAuthLock -> L2 -> L3)."
            ),
        ));
    }
    Ok(())
}

fn open_lock_file_nofollow(base_dir: &Path, lock_path: &Path) -> CliResult<File> {
    ensure_no_symlink_components_under(base_dir, lock_path)?;
    let parent = lock_path.parent().ok_or_else(|| {
        CliError::data(format!(
            "Lock path '{}' has no parent directory.",
            lock_path.display()
        ))
    })?;
    ensure_private_dir(parent)?;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);

    let file = options.open(lock_path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            CliError::data(format!(
                "Refusing to open symlink lock file '{}'.",
                lock_path.display()
            ))
        } else {
            map_io_error(
                e,
                &format!("Cannot open lock file '{}'", lock_path.display()),
            )
        }
    })?;

    let meta = file.metadata().map_err(|e| {
        map_io_error(
            e,
            &format!("Cannot stat lock file '{}'", lock_path.display()),
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(CliError::data(format!(
            "Refusing to use non-regular lock file '{}'.",
            lock_path.display()
        )));
    }
    Ok(file)
}

fn try_flock_exclusive(file: &File) -> Result<bool, std::io::Error> {
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Ok(false);
        }
        return Err(err);
    }
}

fn unlock_flock(file: &File) {
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        if rc == 0 {
            return;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return;
        }
    }
}

fn acquire_flock_with_deadline(
    file: &File,
    lock_path: &Path,
    deadline: Instant,
    busy_message: &str,
    err_label: &str,
) -> CliResult<()> {
    loop {
        match try_flock_exclusive(file) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                if Instant::now() >= deadline {
                    return Err(CliError::lock_busy(busy_message.to_string()));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot lock {err_label} '{}'", lock_path.display()),
                ));
            }
        }
    }
}

/// **L1: `ActiveSlotLock`** (`~/.cache/agy-switch-cli/locks/slot-<sha256>.lock` [+ optional `keyring-<uid>.lock`])
/// Coordinates all writes to the active `agy` credential slot across arbitrary `--data-dir` instances
/// AND across both `file` and `secret-service` backends, while keeping `~/.gemini/antigravity-cli/` 100% clean.
pub struct ActiveSlotLock {
    slot_file: File,
    keyring_file: Option<File>,
    path: PathBuf,
}

impl ActiveSlotLock {
    pub fn try_acquire_for_slot_file(
        paths: &HeadlessPaths,
        slot_lock_path: PathBuf,
    ) -> CliResult<Self> {
        assert_not_holding_pending_or_l2_or_l3("L1 ActiveSlotLock")?;
        let slot_file = open_lock_file_nofollow(&paths.cache_dir, &slot_lock_path)?;
        match try_flock_exclusive(&slot_file) {
            Ok(true) => Ok(Self {
                slot_file,
                keyring_file: None,
                path: slot_lock_path,
            }),
            Ok(false) => Err(CliError::lock_busy(
                "Another process is currently modifying this external credential slot file. Retry shortly.",
            )),
            Err(e) => Err(map_io_error(
                e,
                &format!("Cannot lock external slot '{}'", slot_lock_path.display()),
            )),
        }
    }

    pub fn try_acquire(paths: &HeadlessPaths, include_keyring_scope: bool) -> CliResult<Self> {
        assert_not_holding_pending_or_l2_or_l3("L1 ActiveSlotLock")?;
        let slot_lock_path = paths.active_slot_lock_file();
        let slot_file = open_lock_file_nofollow(&paths.cache_dir, &slot_lock_path)?;
        match try_flock_exclusive(&slot_file) {
            Ok(true) => {}
            Ok(false) => {
                return Err(CliError::lock_busy(
                    "Another process is currently modifying the active agy credential slot. Retry shortly.",
                ));
            }
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot lock active slot '{}'", slot_lock_path.display()),
                ));
            }
        }

        let keyring_file = if include_keyring_scope {
            let kr_path = paths.keyring_lock_file();
            let kr_file = match open_lock_file_nofollow(&paths.cache_dir, &kr_path) {
                Ok(f) => f,
                Err(e) => {
                    unlock_flock(&slot_file);
                    return Err(e);
                }
            };
            match try_flock_exclusive(&kr_file) {
                Ok(true) => Some(kr_file),
                Ok(false) => {
                    unlock_flock(&slot_file);
                    return Err(CliError::lock_busy(
                        "Another process is currently modifying the Linux Secret Service credential slot. Retry shortly.",
                    ));
                }
                Err(e) => {
                    unlock_flock(&slot_file);
                    return Err(map_io_error(
                        e,
                        &format!("Cannot lock keyring scope '{}'", kr_path.display()),
                    ));
                }
            }
        } else {
            None
        };

        Ok(Self {
            slot_file,
            keyring_file,
            path: slot_lock_path,
        })
    }

    pub fn acquire(
        paths: &HeadlessPaths,
        include_keyring_scope: bool,
        timeout: Duration,
    ) -> CliResult<Self> {
        assert_not_holding_pending_or_l2_or_l3("L1 ActiveSlotLock")?;
        let deadline = Instant::now() + timeout;
        let slot_lock_path = paths.active_slot_lock_file();
        let slot_file = open_lock_file_nofollow(&paths.cache_dir, &slot_lock_path)?;
        acquire_flock_with_deadline(
            &slot_file,
            &slot_lock_path,
            deadline,
            "Another process is currently modifying the active agy credential slot. Retry shortly.",
            "active slot",
        )?;

        let keyring_file = if include_keyring_scope {
            let kr_path = paths.keyring_lock_file();
            let kr_file = match open_lock_file_nofollow(&paths.cache_dir, &kr_path) {
                Ok(f) => f,
                Err(e) => {
                    unlock_flock(&slot_file);
                    return Err(e);
                }
            };
            if let Err(e) = acquire_flock_with_deadline(
                &kr_file,
                &kr_path,
                deadline,
                "Another process is currently modifying the Linux Secret Service credential slot. Retry shortly.",
                "keyring scope",
            ) {
                unlock_flock(&slot_file);
                return Err(e);
            }
            Some(kr_file)
        } else {
            None
        };

        Ok(Self {
            slot_file,
            keyring_file,
            path: slot_lock_path,
        })
    }

    pub fn try_acquire_at(lock_path: &Path) -> CliResult<Self> {
        assert_not_holding_pending_or_l2_or_l3("L1 ActiveSlotLock")?;
        let base = lock_path.parent().unwrap_or(lock_path);
        let slot_file = open_lock_file_nofollow(base, lock_path)?;
        match try_flock_exclusive(&slot_file) {
            Ok(true) => Ok(Self {
                slot_file,
                keyring_file: None,
                path: lock_path.to_path_buf(),
            }),
            Ok(false) => Err(CliError::lock_busy(
                "Another process is currently modifying the active agy credential slot. Retry shortly.",
            )),
            Err(e) => Err(map_io_error(
                e,
                &format!("Cannot lock active slot '{}'", lock_path.display()),
            )),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn includes_keyring_scope(&self) -> bool {
        self.keyring_file.is_some()
    }
}

impl Drop for ActiveSlotLock {
    fn drop(&mut self) {
        if let Some(ref kr) = self.keyring_file {
            unlock_flock(kr);
        }
        unlock_flock(&self.slot_file);
    }
}

static PENDING_SHARD_MAP: LazyLock<Mutex<HashMap<PathBuf, Arc<AsyncMutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_inprocess_pending_mutex(lock_path: &Path) -> Arc<AsyncMutex<()>> {
    let mut guard = PENDING_SHARD_MAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .entry(lock_path.to_path_buf())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

/// Private RAII guard for **`PendingAuthLock`** (`<data_dir>/locks/pending-<pending_id>.lock` + `AsyncMutex`).
/// Sits strictly between `L1` and `L2` (`L1 -> PendingAuthLock -> L2 -> L3`) so pending OAuth lifecycles
/// (`re-read -> /token -> immediate save -> userinfo -> account bind & CAS delete`) serialize per pending record
/// without ever conflicting with per-account `L2` acquisition during account binding!
struct RawPendingAuthLock {
    file: File,
    _inproc_guard: OwnedMutexGuard<()>,
}

impl RawPendingAuthLock {
    async fn acquire(
        paths: &HeadlessPaths,
        pending_id: &str,
        timeout: Duration,
    ) -> CliResult<Self> {
        assert_not_holding_pending_or_l2_or_l3("PendingAuthLock")?;
        validate_account_id(pending_id).map_err(CliError::data)?;
        paths.ensure_not_legacy_store_dir()?;

        let lock_path = paths.pending_auth_lock_file(pending_id);
        let deadline = Instant::now() + timeout;

        let arc_mutex = get_inprocess_pending_mutex(&lock_path);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let inproc_guard = tokio::time::timeout(remaining, arc_mutex.lock_owned())
            .await
            .map_err(|_| {
                CliError::lock_busy(format!(
                    "Pending auth record '{pending_id}' is currently locked by another active auth operation. Retry shortly."
                ))
            })?;

        let file = open_lock_file_nofollow(&paths.data_dir, &lock_path)?;
        loop {
            match try_flock_exclusive(&file) {
                Ok(true) => {
                    return Ok(Self {
                        file,
                        _inproc_guard: inproc_guard,
                    });
                }
                Ok(false) => {
                    if Instant::now() >= deadline {
                        return Err(CliError::lock_busy(format!(
                            "Pending auth record '{pending_id}' is currently locked by another process. Retry shortly."
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
                Err(e) => {
                    return Err(map_io_error(
                        e,
                        &format!("Cannot acquire pending auth lock for '{pending_id}'"),
                    ));
                }
            }
        }
    }
}

impl Drop for RawPendingAuthLock {
    fn drop(&mut self) {
        unlock_flock(&self.file);
    }
}

/// Scoped per-pending-record async lock (`L1 -> PendingAuthLock -> L2 -> L3`).
pub async fn with_pending_auth_lock<F, Fut, T>(
    paths: &HeadlessPaths,
    pending_id: &str,
    timeout: Duration,
    f: F,
) -> CliResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = CliResult<T>>,
{
    let raw_lock = RawPendingAuthLock::acquire(paths, pending_id, timeout).await?;
    let next_depth = PENDING_AUTH_LOCK_DEPTH.try_with(|d| *d).unwrap_or(0) + 1;
    PENDING_AUTH_LOCK_DEPTH
        .scope(next_depth, async move {
            let _held = raw_lock;
            f().await
        })
        .await
}

/// Non-blocking RAII guard for `PendingAuthLock` used strictly inside synchronous cleanup paths (`purge`,
/// superseded duplicate cleanup) so the exclusive lock (`AsyncMutex` + `flock`) stays held across `remove_file`
/// with ZERO blocking wait (making deadlock structurally impossible).
pub struct NonBlockingPendingAuthLock {
    file: File,
    _inproc_guard: OwnedMutexGuard<()>,
}

impl Drop for NonBlockingPendingAuthLock {
    fn drop(&mut self) {
        unlock_flock(&self.file);
    }
}

/// Non-blocking attempt to acquire `PendingAuthLock` (`Ok(Some(guard))` when free, `Ok(None)` when actively held,
/// `Err(...)` if the lock path or an ancestor is a symlink, FIFO, or non-regular obstruction).
pub fn try_acquire_pending_auth_lock_nonblocking(
    paths: &HeadlessPaths,
    pending_id: &str,
) -> CliResult<Option<NonBlockingPendingAuthLock>> {
    validate_account_id(pending_id).map_err(CliError::data)?;
    paths.ensure_not_legacy_store_dir()?;
    let lock_path = paths.pending_auth_lock_file(pending_id);
    let arc_mutex = get_inprocess_pending_mutex(&lock_path);
    let Ok(inproc_guard) = arc_mutex.try_lock_owned() else {
        return Ok(None);
    };
    let file = open_lock_file_nofollow(&paths.data_dir, &lock_path)?;
    match try_flock_exclusive(&file) {
        Ok(true) => Ok(Some(NonBlockingPendingAuthLock {
            file,
            _inproc_guard: inproc_guard,
        })),
        Ok(false) => Ok(None),
        Err(e) => Err(map_io_error(
            e,
            &format!("Cannot probe pending auth lock '{}'", lock_path.display()),
        )),
    }
}

/// Side-effect-free probe checking whether `pending_id` is currently held by an active `PendingAuthLock`
/// (in-process `AsyncMutex` or cross-process `flock`) without creating any new lock file on disk.
pub fn is_pending_auth_lock_busy(paths: &HeadlessPaths, pending_id: &str) -> CliResult<bool> {
    if validate_account_id(pending_id).is_err() {
        return Ok(false);
    }
    let lock_path = paths.pending_auth_lock_file(pending_id);
    {
        let guard = PENDING_SHARD_MAP
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(m) = guard.get(&lock_path) {
            if m.try_lock().is_err() {
                return Ok(true);
            }
        }
    }
    ensure_no_symlink_components_under(&paths.data_dir, &lock_path)?;
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(CliError::data(format!(
                "Refusing to open symlink lock file '{}'.",
                lock_path.display()
            )));
        }
        Err(e) => {
            return Err(map_io_error(
                e,
                &format!("Cannot inspect pending auth lock '{}'", lock_path.display()),
            ))
        }
    };
    let meta = file.metadata().map_err(|e| {
        map_io_error(
            e,
            &format!("Cannot stat lock file '{}'", lock_path.display()),
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(CliError::data(format!(
            "Refusing to use non-regular lock file '{}'.",
            lock_path.display()
        )));
    }
    match try_flock_exclusive(&file) {
        Ok(true) => {
            unlock_flock(&file);
            Ok(false)
        }
        Ok(false) => Ok(true),
        Err(e) => Err(map_io_error(
            e,
            &format!("Cannot probe pending auth lock '{}'", lock_path.display()),
        )),
    }
}

static REFRESH_SHARD_MAP: LazyLock<Mutex<HashMap<PathBuf, Arc<AsyncMutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_inprocess_refresh_mutex(lock_path: &Path) -> Arc<AsyncMutex<()>> {
    let mut guard = REFRESH_SHARD_MAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .entry(lock_path.to_path_buf())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

/// Private RAII guard for **L2: `AccountRefreshLock`** (`<data_dir>/locks/refresh-<account_id>.lock` + `AsyncMutex`).
/// Unconstructible outside `with_account_refresh_lock`, making it impossible to hold L2 without activating `L2_REFRESH_DEPTH`.
struct RawAccountRefreshLock {
    file: File,
    _inproc_guard: OwnedMutexGuard<()>,
}

impl RawAccountRefreshLock {
    async fn acquire(
        paths: &HeadlessPaths,
        account_id: &str,
        timeout: Duration,
    ) -> CliResult<Self> {
        assert_not_holding_l2_or_l3("L2 AccountRefreshLock")?;
        validate_account_id(account_id).map_err(CliError::data)?;
        paths.ensure_not_legacy_store_dir()?;

        let lock_path = paths.account_refresh_lock_file(account_id);
        let deadline = Instant::now() + timeout;

        let arc_mutex = get_inprocess_refresh_mutex(&lock_path);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let inproc_guard = tokio::time::timeout(remaining, arc_mutex.lock_owned())
            .await
            .map_err(|_| {
                CliError::lock_busy(format!(
                    "Timed out waiting for in-process token refresh lock on account '{account_id}'."
                ))
            })?;

        let file = open_lock_file_nofollow(&paths.data_dir, &lock_path)?;
        loop {
            match try_flock_exclusive(&file) {
                Ok(true) => {
                    return Ok(Self {
                        file,
                        _inproc_guard: inproc_guard,
                    });
                }
                Ok(false) => {
                    if Instant::now() >= deadline {
                        return Err(CliError::lock_busy(format!(
                            "Timed out waiting for cross-process token refresh lock on account '{account_id}'."
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
                Err(e) => {
                    return Err(map_io_error(
                        e,
                        &format!("Cannot acquire refresh lock for account '{account_id}'"),
                    ));
                }
            }
        }
    }
}

impl Drop for RawAccountRefreshLock {
    fn drop(&mut self) {
        unlock_flock(&self.file);
    }
}

/// Scoped L2 per-account lock (`L1 -> L2 -> L3`).
/// Because `RawAccountRefreshLock` is private and bound inside `L2_REFRESH_DEPTH.scope(...)`,
/// any attempt to acquire L1 (`ActiveSlotLock`) or a nested L2 while holding L2 is deterministically rejected!
pub async fn with_account_refresh_lock<F, Fut, T>(
    paths: &HeadlessPaths,
    account_id: &str,
    timeout: Duration,
    f: F,
) -> CliResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = CliResult<T>>,
{
    let raw_lock = RawAccountRefreshLock::acquire(paths, account_id, timeout).await?;
    let next_depth = L2_REFRESH_DEPTH.try_with(|d| *d).unwrap_or(0) + 1;
    L2_REFRESH_DEPTH
        .scope(next_depth, async move {
            let _held = raw_lock;
            f().await
        })
        .await
}

/// Non-constructible proof token that the current synchronous stack frame holds **L3: `StoreWriteLock`**.
pub struct StoreWriteGuard<'a> {
    _not_send_or_sync: PhantomData<*const &'a ()>,
}

struct RawStoreWriteLock {
    file: File,
}

impl Drop for RawStoreWriteLock {
    fn drop(&mut self) {
        HELD_L3_STORE_LOCK.with(|c| c.set(false));
        unlock_flock(&self.file);
    }
}

/// Scoped synchronous L3 store write lock (`<data_dir>/locks/store.lock`).
/// Taking a synchronous `FnOnce(&StoreWriteGuard<'_>) -> CliResult<T>` makes holding L3 across `.await`
/// a **compile-time type error** on every Tokio runtime flavor (including `current_thread`), and guarantees
/// `HELD_L3_STORE_LOCK` can never leak across tasks on the same OS thread!
pub fn with_store_write_lock<F, T>(paths: &HeadlessPaths, timeout: Duration, f: F) -> CliResult<T>
where
    F: FnOnce(&StoreWriteGuard<'_>) -> CliResult<T>,
{
    assert_not_holding_l3("L3 StoreWriteLock")?;
    paths.ensure_not_legacy_store_dir()?;

    let lock_path = paths.store_lock_file();
    let file = open_lock_file_nofollow(&paths.data_dir, &lock_path)?;
    let deadline = Instant::now() + timeout;

    acquire_flock_with_deadline(
        &file,
        &lock_path,
        deadline,
        "Local account store is locked by another write operation. Retry shortly.",
        "store write lock",
    )?;

    HELD_L3_STORE_LOCK.with(|c| c.set(true));
    let _raw_guard = RawStoreWriteLock { file };
    let proof = StoreWriteGuard {
        _not_send_or_sync: PhantomData,
    };
    f(&proof)
}

/// Single-instance foreground daemon lock (`<data_dir>/locks/daemon.lock`).
pub struct DaemonInstanceLock {
    file: File,
}

impl DaemonInstanceLock {
    pub fn try_acquire(paths: &HeadlessPaths) -> CliResult<Self> {
        assert_not_holding_pending_or_l2_or_l3("DaemonInstanceLock")?;
        paths.ensure_not_legacy_store_dir()?;
        let lock_path = paths.daemon_lock_file();
        let file = open_lock_file_nofollow(&paths.data_dir, &lock_path)?;
        match try_flock_exclusive(&file) {
            Ok(true) => Ok(Self { file }),
            Ok(false) => Err(CliError::lock_busy(
                "Another agy-switch-cli daemon instance is already running for this data directory.",
            )),
            Err(e) => Err(map_io_error(
                e,
                &format!("Cannot acquire daemon lock '{}'", lock_path.display()),
            )),
        }
    }
}

impl Drop for DaemonInstanceLock {
    fn drop(&mut self) {
        unlock_flock(&self.file);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DaemonLockProbe {
    pub running: bool,
    pub pid: Option<u32>,
}

fn try_flock_shared(file: &File) -> Result<bool, std::io::Error> {
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Ok(false);
        }
        return Err(err);
    }
}

/// Parse `FLOCK ... WRITE <pid> <hex_major>:<hex_minor>:<dec_inode>` entries from `/proc/locks`.
fn parse_proc_locks_flock_write_entries(content: &str) -> Vec<(u32, u32, u32, u64)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let _idx = parts.next();
        let Some(kind) = parts.next() else { continue };
        let Some(_scope) = parts.next() else { continue };
        let Some(mode) = parts.next() else { continue };
        let Some(pid_str) = parts.next() else {
            continue;
        };
        let Some(dev_ino) = parts.next() else {
            continue;
        };
        if kind != "FLOCK" || mode != "WRITE" {
            continue;
        }
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let mut segs = dev_ino.split(':');
        let (Some(maj_s), Some(min_s), Some(ino_s), None) =
            (segs.next(), segs.next(), segs.next(), segs.next())
        else {
            continue;
        };
        let (Ok(maj), Ok(min), Ok(ino)) = (
            u32::from_str_radix(maj_s, 16),
            u32::from_str_radix(min_s, 16),
            ino_s.parse::<u64>(),
        ) else {
            continue;
        };
        out.push((pid, maj, min, ino));
    }
    out
}

fn pid_holds_file_dev_ino(proc_dir: &Path, pid: u32, target_dev: u64, target_ino: u64) -> bool {
    let fd_dir = proc_dir.join(pid.to_string()).join("fd");
    let Ok(entries) = std::fs::read_dir(&fd_dir) else {
        return false;
    };
    for entry in entries.flatten().take(512) {
        if let Ok(meta) = std::fs::metadata(entry.path()) {
            if meta.dev() == target_dev && meta.ino() == target_ino {
                return true;
            }
        }
    }
    false
}

/// Strictly read-only probe for whether another process currently holds `<data_dir>/locks/daemon.lock`.
/// Never creates `daemon.lock` or any parent directory. Prefers zero-lock `/proc/locks` inspection and
/// falls back to a non-blocking `LOCK_SH` check (immediately released) for filesystems such as `btrfs`
/// or containers where `/proc/locks` is unavailable or reports a different superblock device ID.
pub fn probe_daemon_lock_readonly(paths: &HeadlessPaths) -> DaemonLockProbe {
    const MAX_PROC_LOCKS_BYTES: u64 = 4 * 1024 * 1024;

    let lock_path = paths.daemon_lock_file();
    if ensure_no_symlink_components_under(&paths.data_dir, &lock_path).is_err() {
        return DaemonLockProbe::default();
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(_) => return DaemonLockProbe::default(),
    };
    let Ok(meta) = file.metadata() else {
        return DaemonLockProbe::default();
    };
    if !meta.file_type().is_file() {
        return DaemonLockProbe::default();
    }

    let target_dev = meta.dev();
    let target_ino = meta.ino();
    #[allow(clippy::unnecessary_cast)]
    let dev_major = libc::major(target_dev as libc::dev_t) as u32;
    #[allow(clippy::unnecessary_cast)]
    let dev_minor = libc::minor(target_dev as libc::dev_t) as u32;

    let proc_dir = crate::session::process::proc_root();
    let mut ino_candidates: Vec<u32> = Vec::new();
    if let Ok(f) = File::open(proc_dir.join("locks")) {
        let mut buf = String::new();
        if f.take(MAX_PROC_LOCKS_BYTES)
            .read_to_string(&mut buf)
            .is_ok()
        {
            for (pid, maj, min, ino) in parse_proc_locks_flock_write_entries(&buf) {
                if ino != target_ino {
                    continue;
                }
                if maj == dev_major && min == dev_minor {
                    return DaemonLockProbe {
                        running: true,
                        pid: Some(pid),
                    };
                }
                if !ino_candidates.contains(&pid) {
                    ino_candidates.push(pid);
                }
            }
        }
    }

    match try_flock_shared(&file) {
        Ok(true) => {
            unlock_flock(&file);
            DaemonLockProbe {
                running: false,
                pid: None,
            }
        }
        Ok(false) => {
            let pid = ino_candidates
                .into_iter()
                .find(|&p| pid_holds_file_dev_ino(&proc_dir, p, target_dev, target_ino));
            DaemonLockProbe { running: true, pid }
        }
        Err(_) => DaemonLockProbe::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_slot_lock_collides_across_data_dirs_and_mixed_backends_leaving_slot_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cache = tmp.path().join("cache");
        let slot_dir = home.join(".gemini").join("antigravity-cli");
        std::fs::create_dir_all(&slot_dir).unwrap();

        let paths_a =
            HeadlessPaths::with_explicit(home.clone(), tmp.path().join("data-a"), cache.clone());
        let paths_b =
            HeadlessPaths::with_explicit(home.clone(), tmp.path().join("data-b"), cache.clone());
        assert_eq!(
            paths_a.active_slot_lock_file(),
            paths_b.active_slot_lock_file()
        );

        let lock_a = ActiveSlotLock::try_acquire(&paths_a, false).unwrap();
        // Same backend (`false`) collides:
        let err_same = ActiveSlotLock::try_acquire(&paths_b, false).err().unwrap();
        assert_eq!(
            err_same.exit_code,
            crate::error::ExitCode::LockBusyOrConflict
        );
        // Mixed backend (`true` secret-service while `false` file lock is held) MUST ALSO collide!
        let err_mixed = ActiveSlotLock::try_acquire(&paths_b, true).err().unwrap();
        assert_eq!(
            err_mixed.exit_code,
            crate::error::ExitCode::LockBusyOrConflict
        );

        // Active slot directory remains 100% empty/clean!
        assert_eq!(std::fs::read_dir(&slot_dir).unwrap().count(), 0);
        // Lock file exists in cache_dir and is NOT unlinked on drop
        let lock_path = lock_a.path().to_path_buf();
        drop(lock_a);
        assert!(lock_path.exists());

        // Reverse mixed order (`true` held, `false` attempted) ALSO collides!
        let lock_kr = ActiveSlotLock::try_acquire(&paths_b, true).unwrap();
        let err_rev_mix = ActiveSlotLock::try_acquire(&paths_a, false).err().unwrap();
        assert_eq!(
            err_rev_mix.exit_code,
            crate::error::ExitCode::LockBusyOrConflict
        );
        drop(lock_kr);
    }

    #[test]
    fn enforces_l1_l2_l3_hierarchy_rejecting_reverse_order() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let reverse_err = with_store_write_lock(&paths, Duration::from_millis(100), |_| {
            Ok(ActiveSlotLock::try_acquire(&paths, false).err().unwrap())
        })
        .unwrap();
        assert_eq!(reverse_err.error_code, "lock_order_violation");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn l2_scope_deterministically_rejects_l1_and_nested_l2_without_manual_wrappers() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        let (l1_err, nested_l2_err, pending_after_l2_err) =
            with_account_refresh_lock(&paths, "acc-1", Duration::from_millis(200), || async {
                let e1 = ActiveSlotLock::try_acquire(&paths, false).err().unwrap();
                let e2 = with_account_refresh_lock(
                    &paths,
                    "acc-2",
                    Duration::from_millis(50),
                    || async { Ok(()) },
                )
                .await
                .err()
                .unwrap();
                let e3 =
                    with_pending_auth_lock(&paths, "pend-1", Duration::from_millis(50), || async {
                        Ok(())
                    })
                    .await
                    .err()
                    .unwrap();
                Ok((e1, e2, e3))
            })
            .await
            .unwrap();
        assert_eq!(l1_err.error_code, "lock_order_violation");
        assert_eq!(nested_l2_err.error_code, "lock_order_violation");
        assert_eq!(pending_after_l2_err.error_code, "lock_order_violation");

        // Forward order `PendingAuthLock -> L2 -> L3` MUST succeed while `PendingAuthLock -> L1` and nested `PendingAuthLock` fail!
        let (p_to_l1, nested_p, forward_ok) =
            with_pending_auth_lock(&paths, "pend-1", Duration::from_millis(200), || async {
                let e1 = ActiveSlotLock::try_acquire(&paths, false).err().unwrap();
                let e2 =
                    with_pending_auth_lock(&paths, "pend-2", Duration::from_millis(50), || async {
                        Ok(())
                    })
                    .await
                    .err()
                    .unwrap();
                let ok_val = with_account_refresh_lock(
                    &paths,
                    "acc-1",
                    Duration::from_millis(200),
                    || async {
                        with_store_write_lock(&paths, Duration::from_millis(200), |_| Ok(42))
                    },
                )
                .await
                .unwrap();
                Ok((e1, e2, ok_val))
            })
            .await
            .unwrap();
        assert_eq!(p_to_l1.error_code, "lock_order_violation");
        assert_eq!(nested_p.error_code, "lock_order_violation");
        assert_eq!(forward_ok, 42);
    }

    #[test]
    fn journal_keyring_scope_detection_covers_corrupt_legacy_and_explicit_journals() {
        use crate::session::journal::{
            journal_on_disk_may_need_keyring, write_journal, write_journal_with_replicas,
            JournalReplicaRecord, JournalReplicaSnapshot, SwitchJournal,
        };

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(&home).unwrap();
        let paths = HeadlessPaths::with_explicit(home, data, cache);
        std::fs::create_dir_all(paths.state_dir()).unwrap();

        // 1. Absent journal -> false
        assert!(!journal_on_disk_may_need_keyring(&paths));
        let l_file = ActiveSlotLock::try_acquire(&paths, false).unwrap();
        assert!(!l_file.includes_keyring_scope());
        drop(l_file);

        // 2. Explicit `file` journal -> false
        let j = SwitchJournal::new_prepared("op-1".into(), None, "acc-1".into(), None, 1_700_000);
        write_journal(&paths, &j).unwrap();
        assert!(!journal_on_disk_may_need_keyring(&paths));

        // 3. Explicit `keyring` journal -> true
        let kr_meta = JournalReplicaRecord {
            backend: "keyring".into(),
            uses_file: false,
            keyring: Some(JournalReplicaSnapshot {
                prev_present: false,
                prev_digest: None,
                prev_uniform: true,
                collections: Vec::new(),
            }),
            file: JournalReplicaSnapshot {
                prev_present: false,
                prev_digest: None,
                prev_uniform: true,
                collections: Vec::new(),
            },
        };
        write_journal_with_replicas(&paths, &j, Some(&kr_meta)).unwrap();
        assert!(journal_on_disk_may_need_keyring(&paths));
        let l_kr = ActiveSlotLock::try_acquire(&paths, true).unwrap();
        assert!(l_kr.includes_keyring_scope());
        drop(l_kr);

        // 4. Legacy journal (`replica_state == None`) -> true (unknown scope must lock keyring!)
        write_journal_with_replicas(&paths, &j, None).unwrap();
        assert!(journal_on_disk_may_need_keyring(&paths));

        // 5. Corrupt/truncated JSON journal -> true (unknown scope must lock keyring!)
        std::fs::write(paths.switch_journal_file(), b"{truncated-json").unwrap();
        assert!(journal_on_disk_may_need_keyring(&paths));
    }

    #[test]
    fn synthetic_probe_daemon_lock_readonly_tracks_live_lock_without_creating_files() {
        let parsed = parse_proc_locks_flock_write_entries(
            "1: POSIX  ADVISORY  WRITE 15517 103:0d:75130177 0 EOF\n\
             2: FLOCK  ADVISORY  READ  15518 103:0d:75130178 0 EOF\n\
             3: FLOCK  ADVISORY  WRITE 0     103:0d:75130179 0 EOF\n\
             4: FLOCK  ADVISORY  WRITE 42424 103:0d:75130180 0 EOF\n",
        );
        assert_eq!(parsed, vec![(42424, 0x103, 0x0d, 75130180)]);

        let tmp = tempfile::tempdir().unwrap();
        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );

        // Before any daemon runs: returns not running AND must NOT create `daemon.lock` or `locks/`.
        let before = probe_daemon_lock_readonly(&paths);
        assert_eq!(
            before,
            DaemonLockProbe {
                running: false,
                pid: None
            }
        );
        assert!(!paths.daemon_lock_file().exists());
        assert!(!paths.store_locks_dir().exists());

        // While lock is held: reports running (and PID on Linux `/proc/locks`).
        let held = DaemonInstanceLock::try_acquire(&paths).unwrap();
        let during = probe_daemon_lock_readonly(&paths);
        assert!(during.running);
        if let Some(pid) = during.pid {
            assert_eq!(pid, std::process::id());
        }

        // After lock release: reports not running.
        drop(held);
        let after = probe_daemon_lock_readonly(&paths);
        assert_eq!(
            after,
            DaemonLockProbe {
                running: false,
                pid: None
            }
        );
    }
}
