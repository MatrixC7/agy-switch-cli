use crate::store::fs_atomic::is_single_normal_filename;
use rusqlite::{ffi, Connection, OpenFlags};
use std::collections::{HashMap, HashSet};
use std::ffi::{c_char, c_int, c_void, CStr, CString, OsStr};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const VFS_NAME: &CStr = c"agy_pinned_ro";
const MAX_MEMORY_TEMP_BYTES: usize = 64 * 1024 * 1024;

const PENDING_BYTE: i64 = 0x4000_0000;
const RESERVED_BYTE: i64 = PENDING_BYTE + 1;
const SHARED_FIRST: i64 = PENDING_BYTE + 2;
const SHARED_SIZE: i64 = 510;

const UNIX_SHM_BASE: i64 = 120;
const UNIX_SHM_DMS: i64 = UNIX_SHM_BASE + 8;

/// SQLite `WAL_READ_LOCK(0..5)` maps to SHM lock slots `3..8` (`sqlite3.c:67170`).
const WAL_READ_LOCK_BITS: u32 = 0b1111_1000;

const MAIN_HEADER_PREFIX_BYTES: usize = 100;
const WAL_HEADER_PREFIX_BYTES: usize = 32;
const JOURNAL_HEADER_PREFIX_BYTES: usize = 28;

// Linux Open File Description (OFD) advisory lock commands (`<linux/fcntl.h>`):
// per-open-file-description locks interact with cross-process POSIX locks AND never
// strip locks held on other file descriptors in the same process upon `close()`.
const LINUX_F_OFD_GETLK: c_int = 36;
const LINUX_F_OFD_SETLK: c_int = 37;

#[cfg(test)]
type ShmUnreliableHook = Box<dyn FnOnce()>;

#[cfg(test)]
thread_local! {
    static TEST_OS_PAGE_SIZE_OVERRIDE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TEST_FORCE_OFD_EINVAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_AFTER_UNSHMED_LOCK_HOOK: std::cell::RefCell<Option<ShmUnreliableHook>> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn is_transient_sqlite_err(err: &rusqlite::Error) -> bool {
    matches!(
        err.sqlite_error_code(),
        Some(
            rusqlite::ErrorCode::DatabaseBusy
                | rusqlite::ErrorCode::DatabaseLocked
                | rusqlite::ErrorCode::CannotOpen
                | rusqlite::ErrorCode::FileLockingProtocolFailed
                | rusqlite::ErrorCode::SchemaChanged
        )
    ) || matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if matches!(
                e.extended_code,
                ffi::SQLITE_IOERR_SHORT_READ
                    | ffi::SQLITE_IOERR_SHMSIZE
                    | ffi::SQLITE_PROTOCOL
                    | ffi::SQLITE_READONLY_RECOVERY
                    | ffi::SQLITE_READONLY_CANTINIT
            )
    )
}

pub(crate) enum PinnedSqliteOpen {
    Absent,
    SkippedUnsafeOrDuplicate,
    TransientRetry,
    Unreadable,
    Opened(PinnedSqliteConnection),
}

pub(crate) struct PinnedSqliteConnection {
    conn: Option<Connection>,
    slot_id: u64,
    ctx: Arc<PinnedSlotContext>,
}

impl PinnedSqliteConnection {
    pub(crate) fn conn(&self) -> &Connection {
        self.conn.as_ref().expect("connection active before drop")
    }

    pub(crate) fn main_file_id(&self) -> (u64, u64) {
        (self.ctx.main_file.dev, self.ctx.main_file.ino)
    }

    pub(crate) fn saw_unsafe_companion(&self) -> bool {
        self.ctx.saw_unsafe_companion.load(Ordering::SeqCst)
    }

    pub(crate) fn saw_cohort_change(&self) -> bool {
        self.ctx.saw_cohort_change.load(Ordering::SeqCst)
    }

    /// Verify before committing aggregated stats (while the SQLite read transaction `tx` is STILL open!)
    /// that the database cohort in `dir_fd` remained bound to the exact verified inodes:
    /// - Only skips byte/mtime unchanged checks when this connection CURRENTLY holds a real OS `F_RDLCK`
    ///   on `WAL_READ_LOCK(0..5)` of the live pinned `<leaf>-shm` inode AND `<leaf>`, `<leaf>-wal`,
    ///   and `<leaf>-shm` still resolve to their exact pinned `(dev, ino)` in `dir_fd`.
    /// - In all unshmed / unlocked cases, verifies `<leaf>-shm` did not appear and `<leaf>`, `<leaf>-wal`,
    ///   and `<leaf>-journal` match exact `(dev, ino, size, mtime)` AND header bytes.
    pub(crate) fn verify_snapshot_consistent(&self) -> Result<(), rusqlite::Error> {
        self.ctx.verify_snapshot_consistent()
    }
}

impl Drop for PinnedSqliteConnection {
    fn drop(&mut self) {
        // Drop `Connection` FIRST so SQLite invokes `xClose`/`xShmUnmap` while `slot_id` is registered,
        // then remove the slot context so all FDs are deterministically released (`O(1)` FD footprint).
        let _ = self.conn.take();
        if let Ok(mut map) = pinned_slots().lock() {
            map.remove(&self.slot_id);
        }
    }
}

struct PinnedRegularFile {
    fd: OwnedFd,
    dev: u64,
    ino: u64,
    initial_size: i64,
    initial_mtime_sec: i64,
    initial_mtime_nsec: i64,
    initial_ctime_sec: i64,
    initial_ctime_nsec: i64,
    initial_header: Vec<u8>,
}

struct PinnedSlotContext {
    dir_fd: OwnedFd,
    leaf_bytes: Vec<u8>,
    main_file: PinnedRegularFile,
    main_opened_once: AtomicBool,
    wal_file: Option<PinnedRegularFile>,
    shm_file: Option<PinnedRegularFile>,
    journal_file: Option<PinnedRegularFile>,
    saw_unsafe_companion: AtomicBool,
    saw_cohort_change: AtomicBool,
    opened_virtual_empty_wal: AtomicBool,
    dms_initially_unlocked: AtomicBool,
    ofd_unavailable: AtomicBool,
    shm_reliable_dms_locked: AtomicBool,
    active_shm_lock_mask: AtomicU32,
}

impl PinnedSlotContext {
    /// Verify before committing aggregated stats (or on open/query error paths) that the database
    /// cohort in `dir_fd` remained bound to the exact verified inodes:
    /// - Only skips byte/mtime/ctime unchanged checks when this connection CURRENTLY holds a real
    ///   OS `F_RDLCK` on `WAL_READ_LOCK(0..5)` of the live pinned `<leaf>-shm` inode AND `<leaf>`,
    ///   `<leaf>-wal`, and `<leaf>-shm` are all present and resolve to their exact pinned `(dev, ino)`.
    /// - In all unshmed / unlocked / virtual-empty-WAL cases, verifies `<leaf>-shm` did not appear
    ///   and `<leaf>`, `<leaf>-wal`, `<leaf>-shm`, and `<leaf>-journal` match exact
    ///   `(dev, ino, size, mtime, ctime)` AND header bytes.
    fn verify_snapshot_consistent(&self) -> Result<(), rusqlite::Error> {
        let protocol_err = || {
            rusqlite::Error::SqliteFailure(
                ffi::Error {
                    code: ffi::ErrorCode::FileLockingProtocolFailed,
                    extended_code: ffi::SQLITE_PROTOCOL,
                },
                None,
            )
        };

        if verify_all_cohort_entries_in_dir(self).is_err() {
            return Err(protocol_err());
        }

        let holds_real_wal_read_lock = self.wal_file.is_some()
            && self.shm_file.is_some()
            && !self.opened_virtual_empty_wal.load(Ordering::SeqCst)
            && !self.ofd_unavailable.load(Ordering::SeqCst)
            && self.shm_reliable_dms_locked.load(Ordering::SeqCst)
            && (self.active_shm_lock_mask.load(Ordering::SeqCst) & WAL_READ_LOCK_BITS) != 0;

        if holds_real_wal_read_lock {
            return Ok(());
        }

        if let Some(ref pinned_shm) = self.shm_file {
            // If `<leaf>-shm` was initially unlocked (`dms_state == F_UNLCK`, `bShmUnreliable == 1`)
            // and a live writer attached to DMS while our heap WAL-index read ran, abort and retry!
            if self.dms_initially_unlocked.load(Ordering::SeqCst)
                && fcntl_get_lock(pinned_shm.fd.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_DMS, 1)
                    != Ok(libc::F_UNLCK)
            {
                self.saw_cohort_change.store(true, Ordering::SeqCst);
                return Err(protocol_err());
            }
            if !verify_pinned_file_unchanged(self, b"-shm", pinned_shm, 0) {
                self.saw_cohort_change.store(true, Ordering::SeqCst);
                return Err(protocol_err());
            }
        }

        for (suffix, member, hdr_cap) in [
            (
                b"".as_slice(),
                Some(&self.main_file),
                MAIN_HEADER_PREFIX_BYTES,
            ),
            (
                b"-wal".as_slice(),
                self.wal_file.as_ref(),
                WAL_HEADER_PREFIX_BYTES,
            ),
            (
                b"-journal".as_slice(),
                self.journal_file.as_ref(),
                JOURNAL_HEADER_PREFIX_BYTES,
            ),
        ] {
            if let Some(pinned_file) = member {
                if !verify_pinned_file_unchanged(self, suffix, pinned_file, hdr_cap) {
                    self.saw_cohort_change.store(true, Ordering::SeqCst);
                    return Err(protocol_err());
                }
            }
        }

        Ok(())
    }
}

static NEXT_SLOT_ID: AtomicU64 = AtomicU64::new(1);
static PINNED_SLOTS: OnceLock<Mutex<HashMap<u64, Arc<PinnedSlotContext>>>> = OnceLock::new();
static VFS_REGISTERED: OnceLock<Result<(), ()>> = OnceLock::new();

fn pinned_slots() -> &'static Mutex<HashMap<u64, Arc<PinnedSlotContext>>> {
    PINNED_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn effective_os_page_size() -> u64 {
    #[cfg(test)]
    {
        let ov = TEST_OS_PAGE_SIZE_OVERRIDE.with(std::cell::Cell::get);
        if ov >= 4096 && ov.is_power_of_two() {
            return ov;
        }
    }
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw >= 4096 {
        let val = raw as u64;
        if val.is_power_of_two() {
            return val;
        }
    }
    4096
}

fn ensure_vfs_registered() -> bool {
    VFS_REGISTERED
        .get_or_init(|| unsafe {
            if ffi::sqlite3_initialize() != ffi::SQLITE_OK {
                return Err(());
            }
            let base_unix = ffi::sqlite3_vfs_find(c"unix".as_ptr());
            if base_unix.is_null() {
                return Err(());
            }
            // Permanently transfer raw pointer provenance to SQLite via `Box::into_raw` so SQLite's
            // internal `pNext` link mutation never aliases an active Rust `Box` / `&mut` reference.
            let vfs_ptr = Box::into_raw(Box::new(ffi::sqlite3_vfs {
                iVersion: 2,
                szOsFile: std::mem::size_of::<PinnedVfsFile>() as c_int,
                mxPathname: 256,
                pNext: ptr::null_mut(),
                zName: VFS_NAME.as_ptr(),
                pAppData: base_unix.cast::<c_void>(),
                xOpen: Some(vfs_open),
                xDelete: Some(vfs_delete),
                xAccess: Some(vfs_access),
                xFullPathname: Some(vfs_full_pathname),
                xDlOpen: None,
                xDlError: None,
                xDlSym: None,
                xDlClose: None,
                xRandomness: (*base_unix).xRandomness,
                xSleep: (*base_unix).xSleep,
                xCurrentTime: (*base_unix).xCurrentTime,
                xGetLastError: Some(vfs_get_last_error),
                xCurrentTimeInt64: (*base_unix).xCurrentTimeInt64,
                xSetSystemCall: None,
                xGetSystemCall: None,
                xNextSystemCall: None,
            }));
            if ffi::sqlite3_vfs_register(vfs_ptr, 0) == ffi::SQLITE_OK {
                Ok(())
            } else {
                drop(Box::from_raw(vfs_ptr));
                Err(())
            }
        })
        .is_ok()
}

fn clear_nonblock(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 && (flags & libc::O_NONBLOCK) != 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
}

fn dup_fd_cloexec(fd: RawFd) -> Option<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

fn pread_header_prefix(fd: RawFd, max_len: usize) -> Result<Vec<u8>, ()> {
    if max_len == 0 {
        return Ok(Vec::new());
    }
    let mut uninit_buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); max_len];
    let mut total = 0usize;
    while total < max_len {
        let n = unsafe {
            libc::pread(
                fd,
                uninit_buf[total..].as_mut_ptr().cast::<c_void>(),
                max_len - total,
                total as libc::off_t,
            )
        };
        if n > 0 {
            total += n as usize;
        } else if n == 0 {
            break;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(());
        }
    }
    let mut out = Vec::with_capacity(total);
    for item in uninit_buf.into_iter().take(total) {
        out.push(unsafe { item.assume_init() });
    }
    Ok(out)
}

enum CohortMemberOpen {
    Absent,
    Unsafe,
    Unreadable,
    Present(PinnedRegularFile),
}

fn open_cohort_member_in_dir(
    dir_fd: RawFd,
    leaf_bytes: &[u8],
    suffix: &[u8],
    header_cap: usize,
) -> CohortMemberOpen {
    let Some(c_name) = build_companion_cstring(leaf_bytes, suffix) else {
        return CohortMemberOpen::Unsafe;
    };
    let raw_fd = unsafe {
        libc::openat(
            dir_fd,
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code == libc::ENOENT => CohortMemberOpen::Absent,
            Some(code) if code == libc::ELOOP || code == libc::ENXIO || code == libc::EISDIR => {
                CohortMemberOpen::Unsafe
            }
            _ => CohortMemberOpen::Unreadable,
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return CohortMemberOpen::Unreadable;
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return CohortMemberOpen::Unsafe;
    }
    clear_nonblock(fd.as_raw_fd());
    let Ok(initial_header) = pread_header_prefix(fd.as_raw_fd(), header_cap) else {
        return CohortMemberOpen::Unreadable;
    };
    #[allow(clippy::unnecessary_cast)]
    CohortMemberOpen::Present(PinnedRegularFile {
        fd,
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        initial_size: st.st_size as i64,
        initial_mtime_sec: st.st_mtime as i64,
        initial_mtime_nsec: st.st_mtime_nsec as i64,
        initial_ctime_sec: st.st_ctime as i64,
        initial_ctime_nsec: st.st_ctime_nsec as i64,
        initial_header,
    })
}

enum CohortVerify {
    Matches,
    Changed,
    Unsafe,
    Unreadable,
}

fn verify_cohort_entry_at_open(
    dir_fd: RawFd,
    leaf_bytes: &[u8],
    suffix: &[u8],
    expected: Option<(u64, u64)>,
) -> CohortVerify {
    let Some(c_name) = build_companion_cstring(leaf_bytes, suffix) else {
        return CohortVerify::Unsafe;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir_fd, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return CohortVerify::Unsafe;
        }
        #[allow(clippy::unnecessary_cast)]
        let actual = (st.st_dev as u64, st.st_ino as u64);
        if expected == Some(actual) {
            CohortVerify::Matches
        } else {
            CohortVerify::Changed
        }
    } else {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == libc::ENOENT => {
                if expected.is_none() {
                    CohortVerify::Matches
                } else {
                    CohortVerify::Changed
                }
            }
            Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => CohortVerify::Unsafe,
            _ => CohortVerify::Unreadable,
        }
    }
}

/// Open a SQLite database cohort strictly through an already-verified directory FD (`dir_fd`) using
/// the zero-write `"agy_pinned_ro"` VFS:
/// - Main DB, `-wal`, `-shm`, and `-journal` are opened and pinned together as a verified cohort via
///   `openat(dir_fd, ...)` with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and `S_IFREG` checks;
/// - Zero files are ever created, truncated, written, `PROT_WRITE`-mapped, or deleted on disk.
pub(crate) fn open_pinned_readonly_sqlite(
    dir_fd: &OwnedFd,
    leaf_name: &OsStr,
    seen_inodes: &HashSet<(u64, u64)>,
) -> PinnedSqliteOpen {
    if !ensure_vfs_registered() {
        return PinnedSqliteOpen::Unreadable;
    }

    let leaf_bytes = leaf_name.as_bytes();
    if !is_single_normal_filename(leaf_bytes) {
        return PinnedSqliteOpen::SkippedUnsafeOrDuplicate;
    }

    let main_file = match open_cohort_member_in_dir(
        dir_fd.as_raw_fd(),
        leaf_bytes,
        b"",
        MAIN_HEADER_PREFIX_BYTES,
    ) {
        CohortMemberOpen::Absent => return PinnedSqliteOpen::Absent,
        CohortMemberOpen::Unsafe => return PinnedSqliteOpen::SkippedUnsafeOrDuplicate,
        CohortMemberOpen::Unreadable => return PinnedSqliteOpen::Unreadable,
        CohortMemberOpen::Present(f) => f,
    };

    if seen_inodes.contains(&(main_file.dev, main_file.ino)) {
        return PinnedSqliteOpen::SkippedUnsafeOrDuplicate;
    }

    let wal_file = match open_cohort_member_in_dir(
        dir_fd.as_raw_fd(),
        leaf_bytes,
        b"-wal",
        WAL_HEADER_PREFIX_BYTES,
    ) {
        CohortMemberOpen::Absent => None,
        CohortMemberOpen::Unsafe => return PinnedSqliteOpen::SkippedUnsafeOrDuplicate,
        CohortMemberOpen::Unreadable => return PinnedSqliteOpen::Unreadable,
        CohortMemberOpen::Present(f) => Some(f),
    };

    let shm_file = match open_cohort_member_in_dir(dir_fd.as_raw_fd(), leaf_bytes, b"-shm", 0) {
        CohortMemberOpen::Absent => None,
        CohortMemberOpen::Unsafe => return PinnedSqliteOpen::SkippedUnsafeOrDuplicate,
        CohortMemberOpen::Unreadable => return PinnedSqliteOpen::Unreadable,
        CohortMemberOpen::Present(f) => Some(f),
    };

    let journal_file = match open_cohort_member_in_dir(
        dir_fd.as_raw_fd(),
        leaf_bytes,
        b"-journal",
        JOURNAL_HEADER_PREFIX_BYTES,
    ) {
        CohortMemberOpen::Absent => None,
        CohortMemberOpen::Unsafe => return PinnedSqliteOpen::SkippedUnsafeOrDuplicate,
        CohortMemberOpen::Unreadable => return PinnedSqliteOpen::Unreadable,
        CohortMemberOpen::Present(f) => Some(f),
    };

    // Verify the entire 4-member cohort simultaneously in `dir_fd` so any concurrent companion
    // creation, unlinking, or replacement during open triggers a clean bounded retry.
    for (suffix, exp) in [
        (b"".as_slice(), Some((main_file.dev, main_file.ino))),
        (
            b"-wal".as_slice(),
            wal_file.as_ref().map(|f| (f.dev, f.ino)),
        ),
        (
            b"-shm".as_slice(),
            shm_file.as_ref().map(|f| (f.dev, f.ino)),
        ),
        (
            b"-journal".as_slice(),
            journal_file.as_ref().map(|f| (f.dev, f.ino)),
        ),
    ] {
        match verify_cohort_entry_at_open(dir_fd.as_raw_fd(), leaf_bytes, suffix, exp) {
            CohortVerify::Matches => {}
            CohortVerify::Changed => return PinnedSqliteOpen::TransientRetry,
            CohortVerify::Unsafe => return PinnedSqliteOpen::SkippedUnsafeOrDuplicate,
            CohortVerify::Unreadable => return PinnedSqliteOpen::Unreadable,
        }
    }

    let Some(owned_dir_fd) = dup_fd_cloexec(dir_fd.as_raw_fd()) else {
        return PinnedSqliteOpen::Unreadable;
    };

    let slot_id = NEXT_SLOT_ID.fetch_add(1, Ordering::Relaxed);
    let ctx = Arc::new(PinnedSlotContext {
        dir_fd: owned_dir_fd,
        leaf_bytes: leaf_bytes.to_vec(),
        main_file,
        main_opened_once: AtomicBool::new(false),
        wal_file,
        shm_file,
        journal_file,
        saw_unsafe_companion: AtomicBool::new(false),
        saw_cohort_change: AtomicBool::new(false),
        opened_virtual_empty_wal: AtomicBool::new(false),
        dms_initially_unlocked: AtomicBool::new(false),
        ofd_unavailable: AtomicBool::new(false),
        shm_reliable_dms_locked: AtomicBool::new(false),
        active_shm_lock_mask: AtomicU32::new(0),
    });

    if let Ok(mut map) = pinned_slots().lock() {
        map.insert(slot_id, Arc::clone(&ctx));
    } else {
        return PinnedSqliteOpen::Unreadable;
    }

    let synthetic_path = format!("/{slot_id}/db");
    // Explicitly omit `SQLITE_OPEN_URI` and use a non-URI synthetic key `/<slot_id>/db`
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = match Connection::open_with_flags_and_vfs(&synthetic_path, flags, "agy_pinned_ro") {
        Ok(c) => c,
        Err(err) => {
            if let Ok(mut map) = pinned_slots().lock() {
                map.remove(&slot_id);
            }
            let _ = ctx.verify_snapshot_consistent();
            return if ctx.saw_unsafe_companion.load(Ordering::SeqCst) {
                PinnedSqliteOpen::SkippedUnsafeOrDuplicate
            } else if ctx.saw_cohort_change.load(Ordering::SeqCst) || is_transient_sqlite_err(&err)
            {
                PinnedSqliteOpen::TransientRetry
            } else {
                PinnedSqliteOpen::Unreadable
            };
        }
    };

    let mut guard = PinnedSqliteConnection {
        conn: Some(conn),
        slot_id,
        ctx,
    };

    let init_res: Result<i32, rusqlite::Error> = (|| {
        let c = guard.conn();
        c.busy_timeout(Duration::from_secs(2))?;
        c.pragma_update(None, "query_only", true)?;
        // Force SQLite temporary tables/indices to stay in memory (`MEMORY` = 2) and verify applied!
        c.pragma_update(None, "temp_store", 2_i32)?;
        c.pragma_query_value(None, "temp_store", |row| row.get::<_, i32>(0))
    })();
    if !matches!(init_res, Ok(2)) {
        let _ = guard.verify_snapshot_consistent();
        let transient_err = init_res.as_ref().err().is_some_and(is_transient_sqlite_err);
        return if guard.saw_unsafe_companion() {
            PinnedSqliteOpen::SkippedUnsafeOrDuplicate
        } else if guard.saw_cohort_change() || transient_err {
            PinnedSqliteOpen::TransientRetry
        } else {
            PinnedSqliteOpen::Unreadable
        };
    }

    let _ = &mut guard;
    PinnedSqliteOpen::Opened(guard)
}

// ==================== VFS Implementation Details ====================

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetRole {
    MainDb,
    Wal,
    Journal,
}

fn parse_synthetic_vfs_path(z_name: *const c_char) -> Option<(u64, TargetRole)> {
    if z_name.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(z_name) }.to_str().ok()?;
    let rest = s.strip_prefix('/')?;
    let (id_str, tail) = rest.split_once('/')?;
    let slot_id = id_str.parse::<u64>().ok()?;
    let role = match tail {
        "db" => TargetRole::MainDb,
        "db-wal" => TargetRole::Wal,
        "db-journal" => TargetRole::Journal,
        _ => return None,
    };
    Some((slot_id, role))
}

fn lookup_slot(slot_id: u64) -> Option<Arc<PinnedSlotContext>> {
    pinned_slots().lock().ok()?.get(&slot_id).cloned()
}

fn build_companion_cstring(leaf_bytes: &[u8], suffix: &[u8]) -> Option<CString> {
    let mut buf = Vec::with_capacity(leaf_bytes.len() + suffix.len());
    buf.extend_from_slice(leaf_bytes);
    buf.extend_from_slice(suffix);
    if !is_single_normal_filename(&buf) {
        return None;
    }
    CString::new(buf).ok()
}

fn verify_dir_entry_matches_cohort(
    ctx: &PinnedSlotContext,
    suffix: &[u8],
    expected: Option<(u64, u64)>,
) -> Result<(), c_int> {
    match verify_cohort_entry_at_open(ctx.dir_fd.as_raw_fd(), &ctx.leaf_bytes, suffix, expected) {
        CohortVerify::Matches => Ok(()),
        CohortVerify::Changed => {
            ctx.saw_cohort_change.store(true, Ordering::SeqCst);
            Err(ffi::SQLITE_PROTOCOL)
        }
        CohortVerify::Unsafe => {
            ctx.saw_unsafe_companion.store(true, Ordering::SeqCst);
            Err(ffi::SQLITE_CANTOPEN)
        }
        CohortVerify::Unreadable => Err(ffi::SQLITE_IOERR_ACCESS),
    }
}

fn verify_all_cohort_entries_in_dir(ctx: &PinnedSlotContext) -> Result<(), c_int> {
    for (suffix, expected) in [
        (b"".as_slice(), Some((ctx.main_file.dev, ctx.main_file.ino))),
        (
            b"-wal".as_slice(),
            ctx.wal_file.as_ref().map(|f| (f.dev, f.ino)),
        ),
        (
            b"-shm".as_slice(),
            ctx.shm_file.as_ref().map(|f| (f.dev, f.ino)),
        ),
        (
            b"-journal".as_slice(),
            ctx.journal_file.as_ref().map(|f| (f.dev, f.ino)),
        ),
    ] {
        verify_dir_entry_matches_cohort(ctx, suffix, expected)?;
    }
    Ok(())
}

fn verify_pinned_file_unchanged(
    ctx: &PinnedSlotContext,
    suffix: &[u8],
    pinned: &PinnedRegularFile,
    header_cap: usize,
) -> bool {
    let Some(c_name) = build_companion_cstring(&ctx.leaf_bytes, suffix) else {
        ctx.saw_unsafe_companion.store(true, Ordering::SeqCst);
        return false;
    };
    let mut cur_st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            ctx.dir_fd.as_raw_fd(),
            c_name.as_ptr(),
            &mut cur_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(c) if c == libc::ELOOP || c == libc::ENOTDIR) {
            ctx.saw_unsafe_companion.store(true, Ordering::SeqCst);
        }
        return false;
    };
    if (cur_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        ctx.saw_unsafe_companion.store(true, Ordering::SeqCst);
        return false;
    }
    #[allow(clippy::unnecessary_cast)]
    let stat_same = (cur_st.st_dev as u64) == pinned.dev
        && (cur_st.st_ino as u64) == pinned.ino
        && (cur_st.st_size as i64) == pinned.initial_size
        && (cur_st.st_mtime as i64) == pinned.initial_mtime_sec
        && (cur_st.st_mtime_nsec as i64) == pinned.initial_mtime_nsec
        && (cur_st.st_ctime as i64) == pinned.initial_ctime_sec
        && (cur_st.st_ctime_nsec as i64) == pinned.initial_ctime_nsec;
    if !stat_same {
        return false;
    }
    if header_cap > 0 {
        let Ok(cur_hdr) = pread_header_prefix(pinned.fd.as_raw_fd(), header_cap) else {
            return false;
        };
        if cur_hdr != pinned.initial_header {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
struct ShmRegionMapping {
    map_base: *mut c_void,
    map_len: usize,
    region_ptr: *mut c_void,
}

impl Default for ShmRegionMapping {
    fn default() -> Self {
        Self {
            map_base: ptr::null_mut(),
            map_len: 0,
            region_ptr: ptr::null_mut(),
        }
    }
}

#[repr(C)]
struct PinnedVfsFile {
    base: ffi::sqlite3_file,
    state: *mut VfsFileState,
}

enum VfsFileState {
    MainDb {
        ctx: Arc<PinnedSlotContext>,
        fd: OwnedFd,
        shared_locked: bool,
        shm_fd: Option<OwnedFd>,
        dms_shared_locked: bool,
        shm_unreliable: bool,
        shm_lock_mask: u32,
        shm_regions: Vec<ShmRegionMapping>,
    },
    ReadOnlyCompanion {
        fd: OwnedFd,
    },
    EmptyVirtualWal,
    MemoryTemp {
        buf: Vec<u8>,
    },
}

impl Drop for VfsFileState {
    fn drop(&mut self) {
        unsafe {
            cleanup_main_shm_and_locks(self);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockResult {
    OkOfd,
    OkPosixFallback,
    Busy,
    IoErr,
}

#[cfg(test)]
impl LockResult {
    fn is_ok(self) -> bool {
        matches!(self, Self::OkOfd | Self::OkPosixFallback)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfdOnlyLockResult {
    Ok,
    OfdUnsupported,
    Busy,
    IoErr,
}

fn force_ofd_einval_for_test() -> bool {
    #[cfg(test)]
    {
        TEST_FORCE_OFD_EINVAL.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Strictly acquire/release a real Linux OFD lock (`F_OFD_SETLK`) without EVER falling back to
/// process-scoped POSIX `F_SETLK` (which loses locks if any other FD to the same inode is closed).
fn ofd_set_lock_only(fd: RawFd, lock_type: c_int, start: i64, len: i64) -> OfdOnlyLockResult {
    if force_ofd_einval_for_test() {
        return OfdOnlyLockResult::OfdUnsupported;
    }
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = lock_type as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = start as _;
    fl.l_len = len as _;
    fl.l_pid = 0;

    loop {
        let rc = unsafe { libc::fcntl(fd, LINUX_F_OFD_SETLK, &fl) };
        if rc == 0 {
            return OfdOnlyLockResult::Ok;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return match err.raw_os_error() {
            Some(c) if c == libc::EINVAL => OfdOnlyLockResult::OfdUnsupported,
            Some(c) if c == libc::EACCES || c == libc::EAGAIN => OfdOnlyLockResult::Busy,
            _ => OfdOnlyLockResult::IoErr,
        };
    }
}

fn fcntl_set_lock(fd: RawFd, lock_type: c_int, start: i64, len: i64) -> LockResult {
    match ofd_set_lock_only(fd, lock_type, start, len) {
        OfdOnlyLockResult::Ok => return LockResult::OkOfd,
        OfdOnlyLockResult::Busy => return LockResult::Busy,
        OfdOnlyLockResult::IoErr => return LockResult::IoErr,
        OfdOnlyLockResult::OfdUnsupported => {}
    }

    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = lock_type as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = start as _;
    fl.l_len = len as _;
    fl.l_pid = 0;

    loop {
        let rc_posix = unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) };
        if rc_posix == 0 {
            return LockResult::OkPosixFallback;
        }
        let err_p = std::io::Error::last_os_error();
        if err_p.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return match err_p.raw_os_error() {
            Some(c) if c == libc::EACCES || c == libc::EAGAIN => LockResult::Busy,
            _ => LockResult::IoErr,
        };
    }
}

fn fcntl_get_lock(fd: RawFd, lock_type: c_int, start: i64, len: i64) -> Result<c_int, ()> {
    if let Some(state) = ofd_other_lock_state(fd, lock_type, start, len) {
        return Ok(state);
    }
    loop {
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = lock_type as _;
        fl.l_whence = libc::SEEK_SET as _;
        fl.l_start = start as _;
        fl.l_len = len as _;
        fl.l_pid = 0;
        if unsafe { libc::fcntl(fd, libc::F_GETLK, &mut fl) } == 0 {
            return Ok(c_int::from(fl.l_type));
        }
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(());
    }
}

/// Probe conflicting locks held by OTHER open file descriptions / processes via `LINUX_F_OFD_GETLK`
/// (which ignores OFD locks held on `fd` itself). Returns `None` if `LINUX_F_OFD_GETLK` is unavailable.
fn ofd_other_lock_state(fd: RawFd, lock_type: c_int, start: i64, len: i64) -> Option<c_int> {
    if force_ofd_einval_for_test() {
        return None;
    }
    loop {
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = lock_type as _;
        fl.l_whence = libc::SEEK_SET as _;
        fl.l_start = start as _;
        fl.l_len = len as _;
        fl.l_pid = 0;

        if unsafe { libc::fcntl(fd, LINUX_F_OFD_GETLK, &mut fl) } == 0 {
            return Some(c_int::from(fl.l_type));
        }
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return None;
    }
}

/// Read into an FFI output buffer (`&mut [MaybeUninit<u8>]`) WITHOUT assuming caller-initialized
/// memory, zero-filling the unread tail on short reads or I/O errors per SQLite `xRead` contract.
fn pread_exact_or_zero_tail_uninit(fd: RawFd, out: &mut [MaybeUninit<u8>], offset: i64) -> c_int {
    if offset < 0 {
        out.fill(MaybeUninit::new(0));
        return ffi::SQLITE_IOERR_READ;
    }
    let mut total = 0usize;
    while total < out.len() {
        let Some(cur_off) = offset.checked_add(total as i64) else {
            out[total..].fill(MaybeUninit::new(0));
            return ffi::SQLITE_IOERR_READ;
        };
        let n = unsafe {
            libc::pread(
                fd,
                out[total..].as_mut_ptr().cast::<c_void>(),
                out.len() - total,
                cur_off as libc::off_t,
            )
        };
        if n > 0 {
            total += n as usize;
        } else if n == 0 {
            out[total..].fill(MaybeUninit::new(0));
            return ffi::SQLITE_IOERR_SHORT_READ;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            out[total..].fill(MaybeUninit::new(0));
            return ffi::SQLITE_IOERR_READ;
        }
    }
    ffi::SQLITE_OK
}

static MAIN_IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write_readonly),
    xTruncate: Some(io_truncate_readonly),
    xSync: Some(io_sync_noop),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock),
    xUnlock: Some(io_unlock),
    xCheckReservedLock: Some(io_check_reserved_lock),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: Some(io_shm_map),
    xShmLock: Some(io_shm_lock),
    xShmBarrier: Some(io_shm_barrier),
    xShmUnmap: Some(io_shm_unmap),
    xFetch: None,
    xUnfetch: None,
};

static COMPANION_IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write_readonly),
    xTruncate: Some(io_truncate_readonly),
    xSync: Some(io_sync_noop),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock_noop),
    xUnlock: Some(io_unlock_noop),
    xCheckReservedLock: Some(io_check_reserved_noop),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

static TEMP_IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write_temp),
    xTruncate: Some(io_truncate_temp),
    xSync: Some(io_sync_noop),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock_noop),
    xUnlock: Some(io_unlock_noop),
    xCheckReservedLock: Some(io_check_reserved_noop),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

unsafe extern "C" fn vfs_open(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: ffi::sqlite3_filename,
    p_file: *mut ffi::sqlite3_file,
    flags: c_int,
    p_out_flags: *mut c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() {
            return ffi::SQLITE_CANTOPEN;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        (*pf).base.pMethods = ptr::null();
        (*pf).state = ptr::null_mut();

        let is_temp = z_name.is_null()
            || (flags
                & (ffi::SQLITE_OPEN_TEMP_DB
                    | ffi::SQLITE_OPEN_TEMP_JOURNAL
                    | ffi::SQLITE_OPEN_TRANSIENT_DB
                    | ffi::SQLITE_OPEN_SUBJOURNAL
                    | ffi::SQLITE_OPEN_SUPER_JOURNAL))
                != 0;
        if is_temp {
            let boxed = Box::new(VfsFileState::MemoryTemp { buf: Vec::new() });
            (*pf).state = Box::into_raw(boxed);
            (*pf).base.pMethods = &TEMP_IO_METHODS;
            if !p_out_flags.is_null() {
                *p_out_flags = flags;
            }
            return ffi::SQLITE_OK;
        }

        let Some((slot_id, role)) = parse_synthetic_vfs_path(z_name) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let Some(ctx) = lookup_slot(slot_id) else {
            return ffi::SQLITE_CANTOPEN;
        };

        match role {
            TargetRole::MainDb => {
                if (flags & ffi::SQLITE_OPEN_MAIN_DB) == 0 {
                    return ffi::SQLITE_CANTOPEN;
                }
                if ctx.main_opened_once.swap(true, Ordering::SeqCst) {
                    return ffi::SQLITE_CANTOPEN;
                }
                if verify_dir_entry_matches_cohort(
                    &ctx,
                    b"",
                    Some((ctx.main_file.dev, ctx.main_file.ino)),
                )
                .is_err()
                {
                    return ffi::SQLITE_CANTOPEN;
                }
                let Some(fd) = dup_fd_cloexec(ctx.main_file.fd.as_raw_fd()) else {
                    return ffi::SQLITE_CANTOPEN;
                };

                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
                    return ffi::SQLITE_CANTOPEN;
                }
                #[allow(clippy::unnecessary_cast)]
                let valid_inode = (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                    && (st.st_dev as u64) == ctx.main_file.dev
                    && (st.st_ino as u64) == ctx.main_file.ino;
                if !valid_inode {
                    ctx.saw_unsafe_companion.store(true, Ordering::SeqCst);
                    return ffi::SQLITE_CANTOPEN;
                }

                let boxed = Box::new(VfsFileState::MainDb {
                    ctx,
                    fd,
                    shared_locked: false,
                    shm_fd: None,
                    dms_shared_locked: false,
                    shm_unreliable: false,
                    shm_lock_mask: 0,
                    shm_regions: Vec::new(),
                });
                (*pf).state = Box::into_raw(boxed);
                (*pf).base.pMethods = &MAIN_IO_METHODS;
                if !p_out_flags.is_null() {
                    *p_out_flags = ffi::SQLITE_OPEN_READONLY;
                }
                ffi::SQLITE_OK
            }
            TargetRole::Wal => {
                if (flags & ffi::SQLITE_OPEN_WAL) == 0 {
                    return ffi::SQLITE_CANTOPEN;
                }
                let expected = ctx.wal_file.as_ref().map(|f| (f.dev, f.ino));
                if verify_dir_entry_matches_cohort(&ctx, b"-wal", expected).is_err() {
                    return ffi::SQLITE_CANTOPEN;
                }
                match ctx.wal_file.as_ref() {
                    Some(wf) => {
                        let Some(fd) = dup_fd_cloexec(wf.fd.as_raw_fd()) else {
                            return ffi::SQLITE_CANTOPEN;
                        };
                        ctx.opened_virtual_empty_wal.store(false, Ordering::SeqCst);
                        let boxed = Box::new(VfsFileState::ReadOnlyCompanion { fd });
                        (*pf).state = Box::into_raw(boxed);
                        (*pf).base.pMethods = &COMPANION_IO_METHODS;
                        if !p_out_flags.is_null() {
                            *p_out_flags = ffi::SQLITE_OPEN_READONLY;
                        }
                        ffi::SQLITE_OK
                    }
                    None => {
                        // Closed WAL database (`page1[19] == 2` without `-wal` on disk):
                        // serve a 0-byte read-only virtual WAL so SQLite reads `MAIN_DB` cleanly
                        // with ZERO companion file creation in the source directory!
                        ctx.opened_virtual_empty_wal.store(true, Ordering::SeqCst);
                        let boxed = Box::new(VfsFileState::EmptyVirtualWal);
                        (*pf).state = Box::into_raw(boxed);
                        (*pf).base.pMethods = &COMPANION_IO_METHODS;
                        if !p_out_flags.is_null() {
                            *p_out_flags = ffi::SQLITE_OPEN_READONLY;
                        }
                        ffi::SQLITE_OK
                    }
                }
            }
            TargetRole::Journal => {
                if (flags & ffi::SQLITE_OPEN_MAIN_JOURNAL) == 0 {
                    return ffi::SQLITE_CANTOPEN;
                }
                let expected = ctx.journal_file.as_ref().map(|f| (f.dev, f.ino));
                if verify_dir_entry_matches_cohort(&ctx, b"-journal", expected).is_err() {
                    return ffi::SQLITE_CANTOPEN;
                }
                match ctx.journal_file.as_ref() {
                    Some(jf) => {
                        let Some(fd) = dup_fd_cloexec(jf.fd.as_raw_fd()) else {
                            return ffi::SQLITE_CANTOPEN;
                        };
                        let boxed = Box::new(VfsFileState::ReadOnlyCompanion { fd });
                        (*pf).state = Box::into_raw(boxed);
                        (*pf).base.pMethods = &COMPANION_IO_METHODS;
                        if !p_out_flags.is_null() {
                            *p_out_flags = ffi::SQLITE_OPEN_READONLY;
                        }
                        ffi::SQLITE_OK
                    }
                    None => ffi::SQLITE_CANTOPEN,
                }
            }
        }
    }))
    .unwrap_or(ffi::SQLITE_CANTOPEN)
}

unsafe extern "C" fn vfs_delete(
    _vfs: *mut ffi::sqlite3_vfs,
    _z_name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn vfs_access(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    flags: c_int,
    p_res_out: *mut c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_res_out.is_null() {
            return ffi::SQLITE_IOERR_ACCESS;
        }
        *p_res_out = 0;

        if flags == ffi::SQLITE_ACCESS_READWRITE {
            return ffi::SQLITE_OK;
        }

        let Some((slot_id, role)) = parse_synthetic_vfs_path(z_name) else {
            return ffi::SQLITE_IOERR_ACCESS;
        };
        let Some(ctx) = lookup_slot(slot_id) else {
            return ffi::SQLITE_IOERR_ACCESS;
        };

        let (suffix, member): (&[u8], Option<&PinnedRegularFile>) = match role {
            TargetRole::MainDb => (b"", Some(&ctx.main_file)),
            TargetRole::Wal => (b"-wal", ctx.wal_file.as_ref()),
            TargetRole::Journal => (b"-journal", ctx.journal_file.as_ref()),
        };

        if verify_dir_entry_matches_cohort(&ctx, suffix, member.map(|f| (f.dev, f.ino))).is_err() {
            return ffi::SQLITE_IOERR_ACCESS;
        }

        match member {
            Some(pf) => {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(pf.fd.as_raw_fd(), &mut st) != 0 {
                    return ffi::SQLITE_IOERR_ACCESS;
                }
                *p_res_out = c_int::from(st.st_size > 0);
                ffi::SQLITE_OK
            }
            None => {
                *p_res_out = 0;
                ffi::SQLITE_OK
            }
        }
    }))
    .unwrap_or(ffi::SQLITE_IOERR_ACCESS)
}

unsafe extern "C" fn vfs_full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    n_out: c_int,
    z_out: *mut c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if z_name.is_null() || z_out.is_null() || n_out <= 1 {
            return ffi::SQLITE_CANTOPEN;
        }
        let Some((slot_id, TargetRole::MainDb)) = parse_synthetic_vfs_path(z_name) else {
            return ffi::SQLITE_CANTOPEN;
        };
        if lookup_slot(slot_id).is_none() {
            return ffi::SQLITE_CANTOPEN;
        }
        let canonical = format!("/{slot_id}/db");
        let bytes = canonical.as_bytes();
        if bytes.len() + 1 > (n_out as usize) {
            return ffi::SQLITE_CANTOPEN;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), z_out.cast::<u8>(), bytes.len());
        *z_out.add(bytes.len()) = 0;
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_CANTOPEN)
}

unsafe extern "C" fn vfs_get_last_error(
    _vfs: *mut ffi::sqlite3_vfs,
    _n_byte: c_int,
    _z_err_msg: *mut c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }))
    .unwrap_or(0)
}

unsafe fn unmap_all_shm_regions(shm_regions: &mut Vec<ShmRegionMapping>) {
    for entry in shm_regions.drain(..) {
        if !entry.map_base.is_null() && entry.map_len > 0 {
            let _ = libc::munmap(entry.map_base, entry.map_len);
        }
    }
}

unsafe fn release_shm_mappings_and_locks(
    ctx: &PinnedSlotContext,
    shm_fd: &mut Option<OwnedFd>,
    dms_shared_locked: &mut bool,
    shm_unreliable: &mut bool,
    shm_lock_mask: &mut u32,
    shm_regions: &mut Vec<ShmRegionMapping>,
) {
    unmap_all_shm_regions(shm_regions);
    // `shm_fd` is created via `dup_fd_cloexec(pinned_shm.fd)` and therefore shares the SAME kernel
    // Open File Description as `ctx.shm_file.fd`: closing `shm_fd` alone does NOT release Linux OFD
    // locks while `ctx.shm_file` remains open, so explicitly unlock SHM read slots and DMS first!
    if let Some(ref dup_shm) = *shm_fd {
        if !ctx.ofd_unavailable.load(Ordering::SeqCst) {
            // Unconditionally unlock all SHM slots plus `UNIX_SHM_DMS` (`UNIX_SHM_BASE ..= UNIX_SHM_DMS`,
            // `SQLITE_SHM_NLOCK + 1` bytes) via OFD-only unlock so zero OFD locks linger on the shared
            // `PinnedSlotContext` open file description without ever touching POSIX process locks.
            let _ = ofd_set_lock_only(
                dup_shm.as_raw_fd(),
                libc::F_UNLCK,
                UNIX_SHM_BASE,
                i64::from(ffi::SQLITE_SHM_NLOCK) + 1,
            );
        }
    }
    *shm_fd = None;
    *dms_shared_locked = false;
    *shm_unreliable = false;
    *shm_lock_mask = 0;
    ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
    ctx.active_shm_lock_mask.store(0, Ordering::SeqCst);
}

unsafe fn cleanup_main_shm_and_locks(state: &mut VfsFileState) {
    if let VfsFileState::MainDb {
        ctx,
        fd,
        shared_locked,
        shm_fd,
        dms_shared_locked,
        shm_unreliable,
        shm_lock_mask,
        shm_regions,
    } = state
    {
        release_shm_mappings_and_locks(
            ctx,
            shm_fd,
            dms_shared_locked,
            shm_unreliable,
            shm_lock_mask,
            shm_regions,
        );
        if *shared_locked {
            let _ = fcntl_set_lock(fd.as_raw_fd(), libc::F_UNLCK, PENDING_BYTE, 2 + SHARED_SIZE);
            *shared_locked = false;
        }
    }
}

unsafe extern "C" fn io_close(p_file: *mut ffi::sqlite3_file) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() {
            return ffi::SQLITE_OK;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if !(*pf).state.is_null() {
            let mut boxed = Box::from_raw((*pf).state);
            cleanup_main_shm_and_locks(&mut boxed);
            drop(boxed);
            (*pf).state = ptr::null_mut();
        }
        (*pf).base.pMethods = ptr::null();
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_IOERR_CLOSE)
}

unsafe extern "C" fn io_read(
    p_file: *mut ffi::sqlite3_file,
    z_buf: *mut c_void,
    i_amt: c_int,
    i_ofst: ffi::sqlite3_int64,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() || z_buf.is_null() || i_amt < 0 {
            return ffi::SQLITE_IOERR_READ;
        }
        let amt = i_amt as usize;
        if amt == 0 {
            return ffi::SQLITE_OK;
        }
        // Sound FFI boundary: SQLite passes uninitialized stack/heap buffers (`sqlite3.c:69826`, `69842`).
        // `MaybeUninit<u8>` imposes ZERO initialization precondition on `z_buf`.
        let out = std::slice::from_raw_parts_mut(z_buf.cast::<MaybeUninit<u8>>(), amt);
        if i_ofst < 0 {
            out.fill(MaybeUninit::new(0));
            return ffi::SQLITE_IOERR_READ;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            out.fill(MaybeUninit::new(0));
            return ffi::SQLITE_IOERR_READ;
        }
        match &*(*pf).state {
            VfsFileState::MainDb { fd, .. } | VfsFileState::ReadOnlyCompanion { fd } => {
                pread_exact_or_zero_tail_uninit(fd.as_raw_fd(), out, i_ofst)
            }
            VfsFileState::EmptyVirtualWal => {
                out.fill(MaybeUninit::new(0));
                ffi::SQLITE_IOERR_SHORT_READ
            }
            VfsFileState::MemoryTemp { buf } => {
                let start = usize::try_from(i_ofst).unwrap_or(usize::MAX);
                if start >= buf.len() {
                    out.fill(MaybeUninit::new(0));
                    return ffi::SQLITE_IOERR_SHORT_READ;
                }
                let avail = (buf.len() - start).min(amt);
                ptr::copy_nonoverlapping(
                    buf[start..start + avail].as_ptr(),
                    out.as_mut_ptr().cast::<u8>(),
                    avail,
                );
                if avail < amt {
                    out[avail..].fill(MaybeUninit::new(0));
                    return ffi::SQLITE_IOERR_SHORT_READ;
                }
                ffi::SQLITE_OK
            }
        }
    }))
    .unwrap_or(ffi::SQLITE_IOERR_READ)
}

unsafe extern "C" fn io_write_readonly(
    _p_file: *mut ffi::sqlite3_file,
    _z_buf: *const c_void,
    _i_amt: c_int,
    _i_ofst: ffi::sqlite3_int64,
) -> c_int {
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn io_truncate_readonly(
    _p_file: *mut ffi::sqlite3_file,
    _size: ffi::sqlite3_int64,
) -> c_int {
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn io_write_temp(
    p_file: *mut ffi::sqlite3_file,
    z_buf: *const c_void,
    i_amt: c_int,
    i_ofst: ffi::sqlite3_int64,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() || z_buf.is_null() || i_amt < 0 || i_ofst < 0 {
            return ffi::SQLITE_IOERR_WRITE;
        }
        let amt = i_amt as usize;
        let Ok(start) = usize::try_from(i_ofst) else {
            return ffi::SQLITE_FULL;
        };
        let Some(end) = start.checked_add(amt) else {
            return ffi::SQLITE_FULL;
        };
        if end > MAX_MEMORY_TEMP_BYTES {
            return ffi::SQLITE_FULL;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_WRITE;
        }
        let VfsFileState::MemoryTemp { buf } = &mut *(*pf).state else {
            return ffi::SQLITE_READONLY;
        };
        if end > buf.len() {
            if buf.try_reserve(end - buf.len()).is_err() {
                return ffi::SQLITE_NOMEM;
            }
            buf.resize(end, 0);
        }
        let src = std::slice::from_raw_parts(z_buf.cast::<u8>(), amt);
        buf[start..end].copy_from_slice(src);
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_IOERR_WRITE)
}

unsafe extern "C" fn io_truncate_temp(
    p_file: *mut ffi::sqlite3_file,
    size: ffi::sqlite3_int64,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() || size < 0 {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        let Ok(sz) = usize::try_from(size) else {
            return ffi::SQLITE_FULL;
        };
        if sz > MAX_MEMORY_TEMP_BYTES {
            return ffi::SQLITE_FULL;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        let VfsFileState::MemoryTemp { buf } = &mut *(*pf).state else {
            return ffi::SQLITE_READONLY;
        };
        buf.truncate(sz);
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_IOERR_TRUNCATE)
}

unsafe extern "C" fn io_sync_noop(_p_file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_file_size(
    p_file: *mut ffi::sqlite3_file,
    p_size: *mut ffi::sqlite3_int64,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() || p_size.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        match &*(*pf).state {
            VfsFileState::MainDb { fd, .. } | VfsFileState::ReadOnlyCompanion { fd } => {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
                    return ffi::SQLITE_IOERR_FSTAT;
                }
                *p_size = st.st_size as ffi::sqlite3_int64;
                ffi::SQLITE_OK
            }
            VfsFileState::EmptyVirtualWal => {
                *p_size = 0;
                ffi::SQLITE_OK
            }
            VfsFileState::MemoryTemp { buf } => {
                *p_size = buf.len() as ffi::sqlite3_int64;
                ffi::SQLITE_OK
            }
        }
    }))
    .unwrap_or(ffi::SQLITE_IOERR_FSTAT)
}

unsafe extern "C" fn io_lock(p_file: *mut ffi::sqlite3_file, e_lock: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if e_lock <= ffi::SQLITE_LOCK_NONE {
            return ffi::SQLITE_OK;
        }
        if e_lock > ffi::SQLITE_LOCK_SHARED {
            return ffi::SQLITE_READONLY;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_LOCK;
        }
        let VfsFileState::MainDb {
            fd, shared_locked, ..
        } = &mut *(*pf).state
        else {
            return ffi::SQLITE_OK;
        };
        if *shared_locked {
            return ffi::SQLITE_OK;
        }

        match fcntl_set_lock(fd.as_raw_fd(), libc::F_RDLCK, PENDING_BYTE, 1) {
            LockResult::OkOfd | LockResult::OkPosixFallback => {}
            LockResult::Busy => return ffi::SQLITE_BUSY,
            LockResult::IoErr => return ffi::SQLITE_IOERR_LOCK,
        }
        let shared_res = fcntl_set_lock(fd.as_raw_fd(), libc::F_RDLCK, SHARED_FIRST, SHARED_SIZE);
        let _ = fcntl_set_lock(fd.as_raw_fd(), libc::F_UNLCK, PENDING_BYTE, 1);

        match shared_res {
            LockResult::OkOfd | LockResult::OkPosixFallback => {
                *shared_locked = true;
                ffi::SQLITE_OK
            }
            LockResult::Busy => ffi::SQLITE_BUSY,
            LockResult::IoErr => ffi::SQLITE_IOERR_LOCK,
        }
    }))
    .unwrap_or(ffi::SQLITE_IOERR_LOCK)
}

unsafe extern "C" fn io_unlock(p_file: *mut ffi::sqlite3_file, e_lock: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if e_lock >= ffi::SQLITE_LOCK_SHARED {
            return ffi::SQLITE_OK;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_OK;
        }
        if let VfsFileState::MainDb {
            fd, shared_locked, ..
        } = &mut *(*pf).state
        {
            if *shared_locked {
                if fcntl_set_lock(fd.as_raw_fd(), libc::F_UNLCK, SHARED_FIRST, SHARED_SIZE)
                    == LockResult::IoErr
                {
                    return ffi::SQLITE_IOERR_UNLOCK;
                }
                *shared_locked = false;
            }
        }
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_IOERR_UNLOCK)
}

unsafe extern "C" fn io_check_reserved_lock(
    p_file: *mut ffi::sqlite3_file,
    p_res_out: *mut c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() || p_res_out.is_null() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        *p_res_out = 0;
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        if let VfsFileState::MainDb { fd, .. } = &*(*pf).state {
            let Ok(l_type) = fcntl_get_lock(fd.as_raw_fd(), libc::F_WRLCK, RESERVED_BYTE, 1) else {
                return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
            };
            *p_res_out = c_int::from(l_type != libc::F_UNLCK);
        }
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_IOERR_CHECKRESERVEDLOCK)
}

unsafe extern "C" fn io_lock_noop(_p_file: *mut ffi::sqlite3_file, _e_lock: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_unlock_noop(_p_file: *mut ffi::sqlite3_file, _e_lock: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_check_reserved_noop(
    _p_file: *mut ffi::sqlite3_file,
    p_res_out: *mut c_int,
) -> c_int {
    if !p_res_out.is_null() {
        *p_res_out = 0;
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_file_control(
    _p_file: *mut ffi::sqlite3_file,
    op: c_int,
    p_arg: *mut c_void,
) -> c_int {
    if op == ffi::SQLITE_FCNTL_HAS_MOVED && !p_arg.is_null() {
        *p_arg.cast::<c_int>() = 0;
        return ffi::SQLITE_OK;
    }
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn io_sector_size(_p_file: *mut ffi::sqlite3_file) -> c_int {
    4096
}

unsafe extern "C" fn io_device_characteristics(_p_file: *mut ffi::sqlite3_file) -> c_int {
    0
}

unsafe extern "C" fn io_shm_map(
    p_file: *mut ffi::sqlite3_file,
    i_pg: c_int,
    pgsz: c_int,
    _b_extend: c_int,
    pp: *mut *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if pp.is_null() {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        *pp = ptr::null_mut();
        if p_file.is_null() || i_pg < 0 || pgsz <= 0 {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        let VfsFileState::MainDb {
            ctx,
            shm_fd,
            dms_shared_locked,
            shm_unreliable,
            shm_regions,
            ..
        } = &mut *(*pf).state
        else {
            return ffi::SQLITE_IOERR_SHMMAP;
        };

        // Strictly verify `-shm` in `ctx.dir_fd` still matches the initial pinned cohort:
        // - If `-shm` was initially absent and STILL absent -> `SQLITE_READONLY_CANTINIT` (heap WAL-index).
        // - If `-shm` appeared, disappeared, or changed `(dev, ino)` -> mark `saw_cohort_change` and return
        //   `SQLITE_PROTOCOL` so the caller aborts immediately and reopens the entire cohort cleanly!
        let expected_shm = ctx.shm_file.as_ref().map(|f| (f.dev, f.ino));
        if let Err(rc) = verify_dir_entry_matches_cohort(ctx, b"-shm", expected_shm) {
            return rc;
        }

        let Some(ref pinned_shm) = ctx.shm_file else {
            return ffi::SQLITE_READONLY_CANTINIT;
        };

        if shm_fd.is_none() {
            let Some(dup) = dup_fd_cloexec(pinned_shm.fd.as_raw_fd()) else {
                return ffi::SQLITE_IOERR_SHMMAP;
            };
            *shm_fd = Some(dup);
        }
        let fd_raw = shm_fd.as_ref().unwrap().as_raw_fd();

        let logical_offset = match u64::try_from(i_pg)
            .ok()
            .and_then(|pg| u64::try_from(pgsz).ok().and_then(|sz| pg.checked_mul(sz)))
        {
            Some(v) => v,
            None => return ffi::SQLITE_IOERR_SHMSIZE,
        };
        let Some(req_end) = logical_offset.checked_add(pgsz as u64) else {
            return ffi::SQLITE_IOERR_SHMSIZE;
        };

        // When `<leaf>-wal` was absent at open (`EmptyVirtualWal`), first verify the full 4-member
        // cohort so any newly created `<leaf>-wal` triggers immediate reopen (`SQLITE_PROTOCOL`);
        // if `<leaf>-wal` is still absent, never mmap `<leaf>-shm` (use heap WAL-index via
        // `SQLITE_READONLY_CANTINIT` and enforce full end-of-tx snapshot checks).
        if ctx.opened_virtual_empty_wal.load(Ordering::SeqCst) {
            if let Err(rc) = verify_all_cohort_entries_in_dir(ctx) {
                if *dms_shared_locked {
                    let _ = ofd_set_lock_only(fd_raw, libc::F_UNLCK, UNIX_SHM_DMS, 1);
                    *dms_shared_locked = false;
                }
                ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                return rc;
            }
            let Ok(dms_state) = fcntl_get_lock(fd_raw, libc::F_WRLCK, UNIX_SHM_DMS, 1) else {
                return ffi::SQLITE_IOERR_SHMLOCK;
            };
            if dms_state == libc::F_WRLCK {
                return ffi::SQLITE_BUSY;
            }
            if dms_state == libc::F_UNLCK {
                ctx.dms_initially_unlocked.store(true, Ordering::SeqCst);
            }
            if *dms_shared_locked {
                let _ = ofd_set_lock_only(fd_raw, libc::F_UNLCK, UNIX_SHM_DMS, 1);
                *dms_shared_locked = false;
            }
            *shm_unreliable = true;
            ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
            return ffi::SQLITE_READONLY_CANTINIT;
        }

        // If an earlier `io_shm_map` on this connection entered unreliable heap WAL-index mode
        // (`dms_initially_unlocked` or `< 1`-page `-shm`), do not re-acquire DMS on re-entry:
        // abort with `SQLITE_PROTOCOL` if cohort/DMS state changed or `< 1`-page `-shm` grew to
        // `>= req_end`, otherwise stay in `SQLITE_READONLY_CANTINIT` without bliping DMS.
        if *shm_unreliable {
            if let Err(rc) = verify_all_cohort_entries_in_dir(ctx) {
                return rc;
            }
            if ctx.ofd_unavailable.load(Ordering::SeqCst) {
                return ffi::SQLITE_READONLY_CANTINIT;
            }
            let Ok(dms_state) = fcntl_get_lock(fd_raw, libc::F_WRLCK, UNIX_SHM_DMS, 1) else {
                return ffi::SQLITE_IOERR_SHMLOCK;
            };
            if dms_state == libc::F_WRLCK {
                return ffi::SQLITE_BUSY;
            }
            let was_unlocked = ctx.dms_initially_unlocked.load(Ordering::SeqCst);
            if was_unlocked != (dms_state == libc::F_UNLCK) {
                ctx.saw_cohort_change.store(true, Ordering::SeqCst);
                return ffi::SQLITE_PROTOCOL;
            }
            let mut st_unrel: libc::stat = std::mem::zeroed();
            if libc::fstat(fd_raw, &mut st_unrel) != 0 {
                return ffi::SQLITE_IOERR_SHMSIZE;
            }
            #[allow(clippy::unnecessary_cast)]
            let cur_unrel_size = (st_unrel.st_size as i64).max(0) as u64;
            if !was_unlocked && cur_unrel_size >= req_end {
                ctx.saw_cohort_change.store(true, Ordering::SeqCst);
                return ffi::SQLITE_PROTOCOL;
            }
            return ffi::SQLITE_READONLY_CANTINIT;
        }

        if !*dms_shared_locked {
            let Some(dms_state) = ofd_other_lock_state(fd_raw, libc::F_WRLCK, UNIX_SHM_DMS, 1)
            else {
                // Kernel lacks OFD locks (`EINVAL`): NEVER fall back to POSIX process locks or
                // enter reliable mmap SHM mode — stay in heap WAL-index mode so
                // `verify_snapshot_consistent` always runs full cohort byte/metadata checks!
                ctx.ofd_unavailable.store(true, Ordering::SeqCst);
                *shm_unreliable = true;
                ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                return ffi::SQLITE_READONLY_CANTINIT;
            };
            if dms_state == libc::F_WRLCK {
                return ffi::SQLITE_BUSY;
            }
            if dms_state == libc::F_UNLCK {
                ctx.dms_initially_unlocked.store(true, Ordering::SeqCst);
                *shm_unreliable = true;
                ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                return ffi::SQLITE_READONLY_CANTINIT;
            }
            if ctx.dms_initially_unlocked.load(Ordering::SeqCst) {
                ctx.saw_cohort_change.store(true, Ordering::SeqCst);
                return ffi::SQLITE_PROTOCOL;
            }
            match ofd_set_lock_only(fd_raw, libc::F_RDLCK, UNIX_SHM_DMS, 1) {
                OfdOnlyLockResult::Ok => {
                    if let Err(rc) = verify_all_cohort_entries_in_dir(ctx) {
                        let _ = ofd_set_lock_only(fd_raw, libc::F_UNLCK, UNIX_SHM_DMS, 1);
                        return rc;
                    }
                    // Catch the microsecond window where the last writer released `UNIX_SHM_DMS`
                    // right between `ofd_other_lock_state` and `ofd_set_lock_only(F_RDLCK)`,
                    // AND fail closed to unreliable mode if OFD status cannot be confirmed!
                    match ofd_other_lock_state(fd_raw, libc::F_WRLCK, UNIX_SHM_DMS, 1) {
                        Some(state) if state != libc::F_UNLCK => {}
                        Some(_) => {
                            let _ = ofd_set_lock_only(fd_raw, libc::F_UNLCK, UNIX_SHM_DMS, 1);
                            if let Err(rc) = verify_all_cohort_entries_in_dir(ctx) {
                                return rc;
                            }
                            ctx.dms_initially_unlocked.store(true, Ordering::SeqCst);
                            *shm_unreliable = true;
                            ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                            return ffi::SQLITE_READONLY_CANTINIT;
                        }
                        None => {
                            let _ = ofd_set_lock_only(fd_raw, libc::F_UNLCK, UNIX_SHM_DMS, 1);
                            ctx.ofd_unavailable.store(true, Ordering::SeqCst);
                            *shm_unreliable = true;
                            ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                            return ffi::SQLITE_READONLY_CANTINIT;
                        }
                    }
                    *dms_shared_locked = true;
                    ctx.shm_reliable_dms_locked.store(true, Ordering::SeqCst);
                }
                OfdOnlyLockResult::OfdUnsupported => {
                    ctx.ofd_unavailable.store(true, Ordering::SeqCst);
                    *shm_unreliable = true;
                    ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                    return ffi::SQLITE_READONLY_CANTINIT;
                }
                OfdOnlyLockResult::Busy => return ffi::SQLITE_BUSY,
                OfdOnlyLockResult::IoErr => return ffi::SQLITE_IOERR_SHMLOCK,
            }
        }

        let idx = i_pg as usize;
        if let Some(existing) = shm_regions.get(idx) {
            if !existing.region_ptr.is_null() {
                *pp = existing.region_ptr;
                return ffi::SQLITE_READONLY;
            }
        }

        let no_mapped_regions = shm_regions.iter().all(|r| r.region_ptr.is_null());
        let release_unmapped_dms = |dms_locked: &mut bool| {
            if no_mapped_regions && *dms_locked {
                let _ = ofd_set_lock_only(fd_raw, libc::F_UNLCK, UNIX_SHM_DMS, 1);
                *dms_locked = false;
                ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
            }
        };

        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd_raw, &mut st) != 0 {
            release_unmapped_dms(dms_shared_locked);
            return ffi::SQLITE_IOERR_SHMSIZE;
        }
        #[allow(clippy::unnecessary_cast)]
        let cur_shm_size = (st.st_size as i64).max(0) as u64;
        if cur_shm_size < req_end {
            // When `i_pg == 0` and `-shm` is smaller than 1 SHM page (e.g. 0-byte `-shm` mid-init
            // or held by a read-only peer), return `SQLITE_READONLY_CANTINIT` so SQLite 3.54 enters
            // `walBeginShmUnreliable` heap WAL-index mode instead of failing with `SQLITE_READONLY_RECOVERY`,
            // while releasing DMS and clearing `shm_reliable_dms_locked` so `verify_snapshot_consistent`
            // enforces full byte/size/mtime checks; for `i_pg > 0`, return `SQLITE_BUSY` so transient growth retries cleanly.
            if i_pg == 0 {
                release_unmapped_dms(dms_shared_locked);
                *shm_unreliable = true;
                ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                return ffi::SQLITE_READONLY_CANTINIT;
            }
            return ffi::SQLITE_BUSY;
        }

        if shm_regions.len() <= idx {
            let extra = idx + 1 - shm_regions.len();
            if shm_regions.try_reserve(extra).is_err() {
                release_unmapped_dms(dms_shared_locked);
                return ffi::SQLITE_NOMEM;
            }
            shm_regions.resize(idx + 1, ShmRegionMapping::default());
        }

        // Align `mmap` file offset downward to the actual OS base page size (e.g. 64 KiB on Linux arm64 64k kernels),
        // track `(map_base, map_len)` for `munmap`, and return the intra-mapping region pointer!
        let os_pgsz = effective_os_page_size();
        let aligned_base_offset = (logical_offset / os_pgsz) * os_pgsz;
        let Ok(in_map_delta) = usize::try_from(logical_offset - aligned_base_offset) else {
            release_unmapped_dms(dms_shared_locked);
            return ffi::SQLITE_IOERR_SHMMAP;
        };
        let Some(map_len) = in_map_delta.checked_add(pgsz as usize) else {
            release_unmapped_dms(dms_shared_locked);
            return ffi::SQLITE_IOERR_SHMMAP;
        };
        let Ok(mmap_off) = libc::off_t::try_from(aligned_base_offset) else {
            release_unmapped_dms(dms_shared_locked);
            return ffi::SQLITE_IOERR_SHMMAP;
        };

        let mapped = libc::mmap(
            ptr::null_mut(),
            map_len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd_raw,
            mmap_off,
        );
        if mapped == libc::MAP_FAILED {
            release_unmapped_dms(dms_shared_locked);
            return ffi::SQLITE_IOERR_SHMMAP;
        }

        let region_ptr = mapped.cast::<u8>().add(in_map_delta).cast::<c_void>();
        shm_regions[idx] = ShmRegionMapping {
            map_base: mapped,
            map_len,
            region_ptr,
        };
        *pp = region_ptr;
        ffi::SQLITE_READONLY
    }))
    .unwrap_or(ffi::SQLITE_IOERR_SHMMAP)
}

unsafe extern "C" fn io_shm_lock(
    p_file: *mut ffi::sqlite3_file,
    offset: c_int,
    n: c_int,
    flags: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() || offset < 0 || n <= 0 || offset + n > ffi::SQLITE_SHM_NLOCK {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        let VfsFileState::MainDb {
            ctx,
            shm_fd,
            shm_unreliable,
            shm_lock_mask,
            ..
        } = &mut *(*pf).state
        else {
            return ffi::SQLITE_IOERR_SHMLOCK;
        };

        let is_unlock = (flags & ffi::SQLITE_SHM_UNLOCK) != 0;
        let is_exclusive = (flags & ffi::SQLITE_SHM_EXCLUSIVE) != 0;

        if is_exclusive && !is_unlock {
            return ffi::SQLITE_BUSY;
        }

        let expected_shm = ctx.shm_file.as_ref().map(|f| (f.dev, f.ino));
        let bits = (((1_u32) << (n as u32)) - 1) << (offset as u32);

        if is_unlock {
            let had_bits = (*shm_lock_mask & bits) != 0;
            *shm_lock_mask &= !bits;
            ctx.active_shm_lock_mask
                .store(*shm_lock_mask, Ordering::SeqCst);
            let _ = verify_dir_entry_matches_cohort(ctx, b"-shm", expected_shm);
            if !had_bits || ctx.ofd_unavailable.load(Ordering::SeqCst) {
                return ffi::SQLITE_OK;
            }
            let Some(ref dup_shm) = *shm_fd else {
                return ffi::SQLITE_OK;
            };
            return match ofd_set_lock_only(
                dup_shm.as_raw_fd(),
                libc::F_UNLCK,
                UNIX_SHM_BASE + i64::from(offset),
                i64::from(n),
            ) {
                OfdOnlyLockResult::Ok | OfdOnlyLockResult::OfdUnsupported => ffi::SQLITE_OK,
                OfdOnlyLockResult::Busy => ffi::SQLITE_BUSY,
                OfdOnlyLockResult::IoErr => ffi::SQLITE_IOERR_SHMLOCK,
            };
        }

        if let Err(rc) = verify_dir_entry_matches_cohort(ctx, b"-shm", expected_shm) {
            return rc;
        }

        let Some(ref pinned_shm) = ctx.shm_file else {
            #[cfg(test)]
            if offset == 3 {
                let hook_opt = TEST_AFTER_UNSHMED_LOCK_HOOK.with(|slot| slot.borrow_mut().take());
                if let Some(hook) = hook_opt {
                    hook();
                }
            }
            return ffi::SQLITE_OK;
        };

        if ctx.ofd_unavailable.load(Ordering::SeqCst) {
            // Kernel does not support Linux OFD locks: never set POSIX process locks or
            // `active_shm_lock_mask` so `verify_snapshot_consistent` ALWAYS runs full cohort checks!
            return ffi::SQLITE_OK;
        }

        if shm_fd.is_none() {
            let Some(dup) = dup_fd_cloexec(pinned_shm.fd.as_raw_fd()) else {
                return ffi::SQLITE_IOERR_SHMLOCK;
            };
            *shm_fd = Some(dup);
        }
        let fd_raw = shm_fd.as_ref().unwrap().as_raw_fd();

        match ofd_set_lock_only(
            fd_raw,
            libc::F_RDLCK,
            UNIX_SHM_BASE + i64::from(offset),
            i64::from(n),
        ) {
            OfdOnlyLockResult::Ok => {
                if let Err(rc) = verify_dir_entry_matches_cohort(ctx, b"-shm", expected_shm) {
                    let _ = ofd_set_lock_only(
                        fd_raw,
                        libc::F_UNLCK,
                        UNIX_SHM_BASE + i64::from(offset),
                        i64::from(n),
                    );
                    return rc;
                }
                *shm_lock_mask |= bits;
                ctx.active_shm_lock_mask
                    .store(*shm_lock_mask, Ordering::SeqCst);
                ffi::SQLITE_OK
            }
            OfdOnlyLockResult::OfdUnsupported => {
                // Kernel does not support OFD locks: refuse to mark `active_shm_lock_mask` and
                // force unreliable mode so `verify_snapshot_consistent` verifies every cohort file!
                ctx.ofd_unavailable.store(true, Ordering::SeqCst);
                *shm_unreliable = true;
                ctx.shm_reliable_dms_locked.store(false, Ordering::SeqCst);
                ffi::SQLITE_OK
            }
            OfdOnlyLockResult::Busy => ffi::SQLITE_BUSY,
            OfdOnlyLockResult::IoErr => ffi::SQLITE_IOERR_SHMLOCK,
        }
    }))
    .unwrap_or(ffi::SQLITE_IOERR_SHMLOCK)
}

unsafe extern "C" fn io_shm_barrier(_p_file: *mut ffi::sqlite3_file) {
    std::sync::atomic::fence(Ordering::SeqCst);
}

unsafe extern "C" fn io_shm_unmap(p_file: *mut ffi::sqlite3_file, _delete_flag: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if p_file.is_null() {
            return ffi::SQLITE_OK;
        }
        let pf = p_file.cast::<PinnedVfsFile>();
        if (*pf).state.is_null() {
            return ffi::SQLITE_OK;
        }
        if let VfsFileState::MainDb {
            ctx,
            shm_fd,
            dms_shared_locked,
            shm_unreliable,
            shm_lock_mask,
            shm_regions,
            ..
        } = &mut *(*pf).state
        {
            release_shm_mappings_and_locks(
                ctx,
                shm_fd,
                dms_shared_locked,
                shm_unreliable,
                shm_lock_mask,
                shm_regions,
            );
        }
        ffi::SQLITE_OK
    }))
    .unwrap_or(ffi::SQLITE_OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fs_atomic::open_existing_dir_nofollow;
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn xread_handles_uninitialized_buffers_and_zero_fills_short_reads_across_all_file_kinds() {
        let tmp = tempfile::tempdir().unwrap();
        let main_path = tmp.path().join("main.bin");
        let wal_path = tmp.path().join("wal.bin");
        fs::write(&main_path, b"0123456789abcdef").unwrap();
        fs::write(&wal_path, b"WALHDR").unwrap();

        let main_fd: OwnedFd = fs::File::open(&main_path).unwrap().into();
        let wal_fd: OwnedFd = fs::File::open(&wal_path).unwrap().into();
        let dir_fd = open_existing_dir_nofollow(tmp.path()).unwrap().unwrap();
        let dummy_ctx = Arc::new(PinnedSlotContext {
            dir_fd,
            leaf_bytes: b"main.bin".to_vec(),
            main_file: PinnedRegularFile {
                fd: dup_fd_cloexec(main_fd.as_raw_fd()).unwrap(),
                dev: 1,
                ino: 1,
                initial_size: 16,
                initial_mtime_sec: 0,
                initial_mtime_nsec: 0,
                initial_ctime_sec: 0,
                initial_ctime_nsec: 0,
                initial_header: Vec::new(),
            },
            main_opened_once: AtomicBool::new(true),
            wal_file: None,
            shm_file: None,
            journal_file: None,
            saw_unsafe_companion: AtomicBool::new(false),
            saw_cohort_change: AtomicBool::new(false),
            opened_virtual_empty_wal: AtomicBool::new(false),
            dms_initially_unlocked: AtomicBool::new(false),
            ofd_unavailable: AtomicBool::new(false),
            shm_reliable_dms_locked: AtomicBool::new(false),
            active_shm_lock_mask: AtomicU32::new(0),
        });

        // 1. MainDb: exact read + short read tail zeroing on uninitialized output buffer
        let mut main_vfs = PinnedVfsFile {
            base: ffi::sqlite3_file {
                pMethods: &MAIN_IO_METHODS,
            },
            state: Box::into_raw(Box::new(VfsFileState::MainDb {
                ctx: dummy_ctx,
                fd: main_fd,
                shared_locked: false,
                shm_fd: None,
                dms_shared_locked: false,
                shm_unreliable: false,
                shm_lock_mask: 0,
                shm_regions: Vec::new(),
            })),
        };
        let mut buf_exact: [MaybeUninit<u8>; 16] = [MaybeUninit::uninit(); 16];
        let rc1 = unsafe {
            io_read(
                (&raw mut main_vfs).cast(),
                buf_exact.as_mut_ptr().cast(),
                16,
                0,
            )
        };
        assert_eq!(rc1, ffi::SQLITE_OK);
        let init_exact: [u8; 16] = unsafe { std::mem::transmute(buf_exact) };
        assert_eq!(&init_exact, b"0123456789abcdef");

        let mut buf_short: [MaybeUninit<u8>; 16] = [MaybeUninit::new(0xAA); 16];
        let rc2 = unsafe {
            io_read(
                (&raw mut main_vfs).cast(),
                buf_short.as_mut_ptr().cast(),
                16,
                10,
            )
        };
        assert_eq!(rc2, ffi::SQLITE_IOERR_SHORT_READ);
        let init_short: [u8; 16] = unsafe { std::mem::transmute(buf_short) };
        assert_eq!(&init_short[..6], b"abcdef");
        assert_eq!(&init_short[6..], &[0u8; 10]);
        unsafe {
            assert_eq!(io_close((&raw mut main_vfs).cast()), ffi::SQLITE_OK);
        }

        // 2. ReadOnlyCompanion (`-wal`): short read + past-EOF read zero-filling
        let mut wal_vfs = PinnedVfsFile {
            base: ffi::sqlite3_file {
                pMethods: &COMPANION_IO_METHODS,
            },
            state: Box::into_raw(Box::new(VfsFileState::ReadOnlyCompanion { fd: wal_fd })),
        };
        let mut buf_wal: [MaybeUninit<u8>; 12] = [MaybeUninit::uninit(); 12];
        let rc_w = unsafe {
            io_read(
                (&raw mut wal_vfs).cast(),
                buf_wal.as_mut_ptr().cast(),
                12,
                0,
            )
        };
        assert_eq!(rc_w, ffi::SQLITE_IOERR_SHORT_READ);
        let init_wal: [u8; 12] = unsafe { std::mem::transmute(buf_wal) };
        assert_eq!(&init_wal[..6], b"WALHDR");
        assert_eq!(&init_wal[6..], &[0u8; 6]);
        unsafe {
            assert_eq!(io_close((&raw mut wal_vfs).cast()), ffi::SQLITE_OK);
        }

        // 3. EmptyVirtualWal: zero-fills entire uninitialized buffer and returns SHORT_READ
        let mut vwal_vfs = PinnedVfsFile {
            base: ffi::sqlite3_file {
                pMethods: &COMPANION_IO_METHODS,
            },
            state: Box::into_raw(Box::new(VfsFileState::EmptyVirtualWal)),
        };
        let mut buf_vwal: [MaybeUninit<u8>; 32] = [MaybeUninit::uninit(); 32];
        let rc_vw = unsafe {
            io_read(
                (&raw mut vwal_vfs).cast(),
                buf_vwal.as_mut_ptr().cast(),
                32,
                0,
            )
        };
        assert_eq!(rc_vw, ffi::SQLITE_IOERR_SHORT_READ);
        let init_vwal: [u8; 32] = unsafe { std::mem::transmute(buf_vwal) };
        assert_eq!(init_vwal, [0u8; 32]);
        unsafe {
            assert_eq!(io_close((&raw mut vwal_vfs).cast()), ffi::SQLITE_OK);
        }

        // 4. MemoryTemp: write, full read, partial read tail-zeroing, and past-EOF zeroing
        let mut tmp_vfs = PinnedVfsFile {
            base: ffi::sqlite3_file {
                pMethods: &TEMP_IO_METHODS,
            },
            state: Box::into_raw(Box::new(VfsFileState::MemoryTemp { buf: Vec::new() })),
        };
        let payload = b"TEMP_DATA_99";
        let rc_tw = unsafe {
            io_write_temp(
                (&raw mut tmp_vfs).cast(),
                payload.as_ptr().cast(),
                payload.len() as c_int,
                0,
            )
        };
        assert_eq!(rc_tw, ffi::SQLITE_OK);

        let mut buf_tfull: [MaybeUninit<u8>; 12] = [MaybeUninit::uninit(); 12];
        let rc_tf = unsafe {
            io_read(
                (&raw mut tmp_vfs).cast(),
                buf_tfull.as_mut_ptr().cast(),
                12,
                0,
            )
        };
        assert_eq!(rc_tf, ffi::SQLITE_OK);
        let init_tf: [u8; 12] = unsafe { std::mem::transmute(buf_tfull) };
        assert_eq!(&init_tf, payload);

        let mut buf_tshort: [MaybeUninit<u8>; 10] = [MaybeUninit::new(0xFF); 10];
        let rc_ts = unsafe {
            io_read(
                (&raw mut tmp_vfs).cast(),
                buf_tshort.as_mut_ptr().cast(),
                10,
                8,
            )
        };
        assert_eq!(rc_ts, ffi::SQLITE_IOERR_SHORT_READ);
        let init_ts: [u8; 10] = unsafe { std::mem::transmute(buf_tshort) };
        assert_eq!(&init_ts[..4], b"A_99");
        assert_eq!(&init_ts[4..], &[0u8; 6]);

        let mut buf_teof: [MaybeUninit<u8>; 8] = [MaybeUninit::new(0xCC); 8];
        let rc_te = unsafe {
            io_read(
                (&raw mut tmp_vfs).cast(),
                buf_teof.as_mut_ptr().cast(),
                8,
                64,
            )
        };
        assert_eq!(rc_te, ffi::SQLITE_IOERR_SHORT_READ);
        let init_te: [u8; 8] = unsafe { std::mem::transmute(buf_teof) };
        assert_eq!(init_te, [0u8; 8]);
        unsafe {
            assert_eq!(io_close((&raw mut tmp_vfs).cast()), ffi::SQLITE_OK);
        }
    }

    #[test]
    fn shm_map_aligns_offsets_for_64k_os_pages_and_returns_exact_region_pointers() {
        struct ResetPageSize;
        impl Drop for ResetPageSize {
            fn drop(&mut self) {
                TEST_OS_PAGE_SIZE_OVERRIDE.with(|c| c.set(0));
            }
        }
        let _reset = ResetPageSize;
        TEST_OS_PAGE_SIZE_OVERRIDE.with(|c| c.set(65_536));

        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("sixtyfour_k.db");
        let wconn = Connection::open(&db_path).unwrap();
        wconn
            .execute_batch(
                "PRAGMA page_size = 512;
                 PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE filler (id INTEGER PRIMARY KEY, pad BLOB);
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);",
            )
            .unwrap();
        wconn.execute_batch("BEGIN;").unwrap();
        let pad = vec![0x5A_u8; 480];
        for i in 1..=12_800_i64 {
            wconn
                .execute(
                    "INSERT INTO filler VALUES (?1, ?2)",
                    rusqlite::params![i, &pad],
                )
                .unwrap();
        }
        wconn
            .execute("INSERT INTO items VALUES (1, 777)", [])
            .unwrap();
        wconn.execute_batch("COMMIT;").unwrap();

        // Verify our 64 KiB page-aligned `io_shm_map` maps across 4 SHM regions (`i_pg = 0, 1, 2, 3`,
        // >= 128 KiB, covering both `aligned_base_offset = 0` and `aligned_base_offset = 65536` with
        // `in_map_delta = 0` and `in_map_delta = 32768`) cleanly!
        let shm_len = fs::metadata(tmp.path().join("sixtyfour_k.db-shm"))
            .unwrap()
            .len();
        assert!(
            shm_len >= 131_072,
            "expected >= 128 KiB (4 regions) shm, got {shm_len}"
        );

        let dir_fd = open_existing_dir_nofollow(tmp.path()).unwrap().unwrap();
        let seen = HashSet::new();
        let PinnedSqliteOpen::Opened(pinned) =
            open_pinned_readonly_sqlite(&dir_fd, OsStr::new("sixtyfour_k.db"), &seen)
        else {
            panic!("expected Opened under simulated 64 KiB OS page size");
        };
        let tx = pinned.conn().unchecked_transaction().unwrap();
        let v: i64 = tx
            .query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 777);
        pinned.verify_snapshot_consistent().unwrap();
        drop(tx);
        drop(pinned);
        drop(wconn);

        // Orphaned/unlocked `-shm` (`dms_state == F_UNLCK`, `bShmUnreliable == 1`) MUST NOT skip
        // `verify_snapshot_consistent` even though `WAL_READ_LOCK(0)` is held on `-shm`!
        let orph_src = tmp.path().join("orph_src");
        let orph_dst = tmp.path().join("orph_dst");
        fs::create_dir_all(&orph_src).unwrap();
        fs::create_dir_all(&orph_dst).unwrap();
        let o_db = orph_src.join("orph.db");
        let oconn = Connection::open(&o_db).unwrap();
        oconn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);",
            )
            .unwrap();
        oconn
            .execute("INSERT INTO items VALUES (1, 42)", [])
            .unwrap();
        // Copy `.db`, `-wal`, AND `-shm` while writer is open, then drop writer so `orph_dst/orph.db-shm`
        // exists on disk with `DMS == F_UNLCK` (orphaned `-shm`)!
        fs::copy(&o_db, orph_dst.join("orph.db")).unwrap();
        fs::copy(orph_src.join("orph.db-wal"), orph_dst.join("orph.db-wal")).unwrap();
        fs::copy(orph_src.join("orph.db-shm"), orph_dst.join("orph.db-shm")).unwrap();
        drop(oconn);

        let o_dir_fd = open_existing_dir_nofollow(&orph_dst).unwrap().unwrap();
        let o_seen = HashSet::new();
        let PinnedSqliteOpen::Opened(o_pinned) =
            open_pinned_readonly_sqlite(&o_dir_fd, OsStr::new("orph.db"), &o_seen)
        else {
            panic!("expected Opened on orphaned -shm cohort");
        };
        let o_tx = o_pinned.conn().unchecked_transaction().unwrap();
        let ov: i64 = o_tx
            .query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ov, 42);
        // Unchanged orphaned `-shm` cohort passes consistency check
        o_pinned.verify_snapshot_consistent().unwrap();
        // Mutating `-wal` header salt in place while `o_tx` holds `WAL_READ_LOCK(0)` on unlocked `-shm`
        // MUST be caught by `verify_snapshot_consistent` (`saw_cohort_change == true`)!
        let mut wal_bytes = fs::read(orph_dst.join("orph.db-wal")).unwrap();
        wal_bytes[16] ^= 0xFF;
        fs::write(orph_dst.join("orph.db-wal"), &wal_bytes).unwrap();
        assert!(
            o_pinned.verify_snapshot_consistent().is_err(),
            "Orphaned unlocked -shm MUST NOT skip WAL header/mtime verification!"
        );
        assert!(o_pinned.saw_cohort_change());
        drop(o_tx);
        drop(o_pinned);
    }

    #[test]
    fn cross_process_shm_appearance_mid_unshmed_wal_scan_aborts_and_retries_cleanly() {
        use std::time::Instant;

        // Child helper mode: opens WAL DB, inserts a second row, and runs RESTART checkpoint while holding DMS
        if let Ok(db_env) = std::env::var("AGY_TEST_CHILD_WAL_WRITER_DB") {
            let ready_file = std::env::var("AGY_TEST_CHILD_WAL_READY").unwrap();
            let done_wait_file = std::env::var("AGY_TEST_CHILD_WAL_HOLD").unwrap();
            let done_path = Path::new(&done_wait_file);
            let wconn = Connection::open(&db_env).unwrap();
            wconn.busy_timeout(Duration::from_secs(2)).unwrap();
            wconn
                .execute("INSERT INTO items VALUES (2, 200)", [])
                .unwrap();
            let _ = wconn.execute_batch("PRAGMA wal_checkpoint(RESTART);");
            let mut f = fs::File::create(&ready_file).unwrap();
            f.write_all(b"ready").unwrap();
            drop(f);
            let hold_deadline = Instant::now() + Duration::from_secs(30);
            while !done_path.exists()
                && done_path.parent().is_some_and(Path::exists)
                && Instant::now() < hold_deadline
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            drop(wconn);
            return;
        }

        struct ResetUnshmedHook;
        impl Drop for ResetUnshmedHook {
            fn drop(&mut self) {
                TEST_AFTER_UNSHMED_LOCK_HOOK.with(|slot| {
                    let _ = slot.borrow_mut().take();
                });
            }
        }

        struct KillChildOnDrop(Arc<Mutex<Option<std::process::Child>>>);
        impl Drop for KillChildOnDrop {
            fn drop(&mut self) {
                if let Ok(mut guard) = self.0.lock() {
                    if let Some(mut ch) = guard.take() {
                        let _ = ch.kill();
                        let _ = ch.wait();
                    }
                }
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let child_handle: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(None));
        let _child_guard = KillChildOnDrop(Arc::clone(&child_handle));
        let _hook_guard = ResetUnshmedHook;

        let src_dir = tmp.path().join("src");
        let dst_dir = tmp.path().join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();

        let src_db = src_dir.join("sync.db");
        let init_conn = Connection::open(&src_db).unwrap();
        init_conn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);",
            )
            .unwrap();
        init_conn
            .execute("INSERT INTO items VALUES (1, 100)", [])
            .unwrap();

        // Copy `sync.db` + `sync.db-wal` WITHOUT `sync.db-shm` into `dst_dir`
        let target_db = dst_dir.join("sync.db");
        fs::copy(&src_db, &target_db).unwrap();
        fs::copy(src_dir.join("sync.db-wal"), dst_dir.join("sync.db-wal")).unwrap();
        drop(init_conn);
        assert!(!dst_dir.join("sync.db-shm").exists());

        let ready_file = tmp.path().join("writer.ready");
        let hold_file = tmp.path().join("writer.release");

        // Install thread-local one-shot synchronization hook right inside `io_shm_lock(WAL_READ_LOCK(0))`
        // when `-shm` was initially absent! At that exact point (`walBeginShmUnreliable` between
        // `walLockShared(0)` and `sqlite3OsShmMap`), spawn a REAL separate OS child writer process
        // that creates `sync.db-shm`, commits row 2, and checkpoints!
        let target_db_c = target_db.clone();
        let ready_c = ready_file.clone();
        let hold_c = hold_file.clone();
        let child_slot = Arc::clone(&child_handle);
        let child_tmpdir = tmp.path().to_path_buf();

        TEST_AFTER_UNSHMED_LOCK_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("TMPDIR", &child_tmpdir)
                    .env("AGY_TEST_CHILD_WAL_WRITER_DB", &target_db_c)
                    .env("AGY_TEST_CHILD_WAL_READY", &ready_c)
                    .env("AGY_TEST_CHILD_WAL_HOLD", &hold_c)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .args([
                        "--test-threads=1",
                        "--exact",
                        "stats::readonly_vfs::tests::cross_process_shm_appearance_mid_unshmed_wal_scan_aborts_and_retries_cleanly",
                    ])
                    .spawn()
                    .unwrap();
                *child_slot.lock().unwrap() = Some(child);
                let deadline = Instant::now() + Duration::from_secs(15);
                while !ready_c.exists() {
                    if let Some(status) = child_slot
                        .lock()
                        .unwrap()
                        .as_mut()
                        .and_then(|c| c.try_wait().unwrap())
                    {
                        if !ready_c.exists() {
                            panic!(
                                "Child WAL writer exited prematurely ({status}) before creating ready marker"
                            );
                        }
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "Timed out waiting for child WAL writer ready marker"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }));
        });

        let dir_fd = open_existing_dir_nofollow(&dst_dir).unwrap().unwrap();

        // Attempt 1 MUST detect `-shm` appearance (`saw_cohort_change() == true`) and abort with `SQLITE_PROTOCOL`!
        let seen1 = HashSet::new();
        let PinnedSqliteOpen::Opened(pinned1) =
            open_pinned_readonly_sqlite(&dir_fd, OsStr::new("sync.db"), &seen1)
        else {
            panic!("expected initial Opened");
        };
        let err1 = pinned1
            .conn()
            .query_row("SELECT SUM(val) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap_err();
        assert!(
            pinned1.saw_cohort_change(),
            "expected saw_cohort_change=true on SHM appearance, err={err1:?}"
        );
        drop(pinned1);

        // Attempt 2 (while separate OS writer STILL holds live `-shm` DMS lock!) reopens the fresh cohort,
        // acquires real cross-process DMS + `WAL_READ_LOCK` on `sync.db-shm`, and reads exact consistent sum `300`!
        let seen2 = HashSet::new();
        let PinnedSqliteOpen::Opened(pinned2) =
            open_pinned_readonly_sqlite(&dir_fd, OsStr::new("sync.db"), &seen2)
        else {
            panic!("expected retry Opened with live -shm");
        };
        let tx2 = pinned2.conn().unchecked_transaction().unwrap();
        let sum: i64 = tx2
            .query_row("SELECT SUM(val) FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sum, 300);
        pinned2.verify_snapshot_consistent().unwrap();
        drop(tx2);
        drop(pinned2);

        fs::write(&hold_file, b"done").unwrap();
        let taken_child = child_handle.lock().unwrap().take();
        if let Some(mut ch) = taken_child {
            let st = ch.wait().unwrap();
            assert!(st.success());
        }
    }

    #[test]
    fn parallel_unshmed_wal_scans_and_thread_local_vfs_hooks_never_interfere_or_hang() {
        let tmp = tempfile::tempdir().unwrap();
        let closed_dir = tmp.path().join("closed");
        let hook_src_dir = tmp.path().join("hook_src");
        fs::create_dir_all(&closed_dir).unwrap();
        fs::create_dir_all(&hook_src_dir).unwrap();

        let closed_db = closed_dir.join("closed_wal.db");
        {
            let conn = Connection::open(&closed_db).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);
                 INSERT INTO items VALUES (1, 42);",
            )
            .unwrap();
        }
        assert!(!closed_dir.join("closed_wal.db-wal").exists());
        assert!(!closed_dir.join("closed_wal.db-shm").exists());

        let hook_src_db = hook_src_dir.join("unshmed.db");
        let keep_writer = Connection::open(&hook_src_db).unwrap();
        keep_writer
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);
                 INSERT INTO items VALUES (1, 99);",
            )
            .unwrap();

        let host_page_size = {
            let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if raw >= 4096 && (raw as u64).is_power_of_two() {
                raw as u64
            } else {
                4096
            }
        };

        let barrier = Arc::new(std::sync::Barrier::new(12));
        let mut handles = Vec::new();

        // 8 threads hammering `closed_wal.db` (which enters `io_shm_lock(offset = 3)` with `shm_file == None`)
        for _ in 0..8 {
            let b = Arc::clone(&barrier);
            let cdir = closed_dir.clone();
            handles.push(std::thread::spawn(move || {
                b.wait();
                let dir_fd = open_existing_dir_nofollow(&cdir).unwrap().unwrap();
                for _ in 0..40 {
                    assert_eq!(effective_os_page_size(), host_page_size);
                    let seen = HashSet::new();
                    let PinnedSqliteOpen::Opened(pinned) =
                        open_pinned_readonly_sqlite(&dir_fd, OsStr::new("closed_wal.db"), &seen)
                    else {
                        panic!("expected Opened on closed_wal.db");
                    };
                    let v: i64 = pinned
                        .conn()
                        .query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))
                        .unwrap();
                    assert_eq!(v, 42);
                    assert!(!pinned.saw_cohort_change());
                }
            }));
        }

        // 4 threads concurrently installing thread-local `TEST_AFTER_UNSHMED_LOCK_HOOK` and `TEST_OS_PAGE_SIZE_OVERRIDE`
        for worker_idx in 0..4usize {
            let b = Arc::clone(&barrier);
            let wdir = tmp.path().join(format!("hook_worker_{worker_idx}"));
            fs::create_dir_all(&wdir).unwrap();
            fs::copy(&hook_src_db, wdir.join("unshmed.db")).unwrap();
            fs::copy(
                hook_src_dir.join("unshmed.db-wal"),
                wdir.join("unshmed.db-wal"),
            )
            .unwrap();

            handles.push(std::thread::spawn(move || {
                struct ResetTls;
                impl Drop for ResetTls {
                    fn drop(&mut self) {
                        TEST_OS_PAGE_SIZE_OVERRIDE.with(|c| c.set(0));
                        TEST_AFTER_UNSHMED_LOCK_HOOK.with(|s| {
                            let _ = s.borrow_mut().take();
                        });
                    }
                }
                let _reset = ResetTls;
                TEST_OS_PAGE_SIZE_OVERRIDE.with(|c| c.set(65_536));
                let my_tid = std::thread::current().id();
                b.wait();

                let dir_fd = open_existing_dir_nofollow(&wdir).unwrap().unwrap();
                for _ in 0..25 {
                    assert_eq!(effective_os_page_size(), 65_536);
                    let fired_tid = Arc::new(Mutex::new(None));
                    let fired_c = Arc::clone(&fired_tid);
                    TEST_AFTER_UNSHMED_LOCK_HOOK.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move || {
                            *fired_c.lock().unwrap() = Some(std::thread::current().id());
                        }));
                    });

                    let seen = HashSet::new();
                    let PinnedSqliteOpen::Opened(pinned) =
                        open_pinned_readonly_sqlite(&dir_fd, OsStr::new("unshmed.db"), &seen)
                    else {
                        panic!("expected Opened on unshmed.db");
                    };
                    let v: i64 = pinned
                        .conn()
                        .query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))
                        .unwrap();
                    assert_eq!(v, 99);
                    assert_eq!(
                        *fired_tid.lock().unwrap(),
                        Some(my_tid),
                        "Hook MUST fire exclusively on the installing thread and NEVER be stolen by parallel threads!"
                    );
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        drop(keep_writer);
    }

    #[test]
    fn zero_byte_dms_locked_shm_enforces_snapshot_checks_and_shm_unlock_releases_fd_after_unlink() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("src");
        let dst_dir = tmp.path().join("dst");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&dst_dir).unwrap();

        let src_db = src_dir.join("zero_shm.db");
        let wconn = Connection::open(&src_db).unwrap();
        wconn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);
                 INSERT INTO items VALUES (1, 314);",
            )
            .unwrap();
        fs::copy(&src_db, dst_dir.join("zero_shm.db")).unwrap();
        fs::copy(
            src_dir.join("zero_shm.db-wal"),
            dst_dir.join("zero_shm.db-wal"),
        )
        .unwrap();
        drop(wconn);

        // Create a 0-byte `-shm` in `dst_dir` with a live `F_RDLCK` on `UNIX_SHM_DMS`
        // (simulating a concurrent process mid-SHM-initialization or read-only attach on 0-byte `-shm`)
        let dst_shm = dst_dir.join("zero_shm.db-shm");
        let holder_file = TestOfdLockGuard::lock_shared(
            fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&dst_shm)
                .unwrap(),
            UNIX_SHM_DMS,
            1,
        );

        let dir_fd = open_existing_dir_nofollow(&dst_dir).unwrap().unwrap();
        let seen = HashSet::new();
        let PinnedSqliteOpen::Opened(pinned) =
            open_pinned_readonly_sqlite(&dir_fd, OsStr::new("zero_shm.db"), &seen)
        else {
            panic!("expected Opened on 0-byte DMS-locked -shm");
        };
        let tx = pinned.conn().unchecked_transaction().unwrap();
        let val: i64 = tx
            .query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(val, 314);
        assert!(
            !pinned.ctx.shm_reliable_dms_locked.load(Ordering::SeqCst),
            "0-byte -shm fallback (`*pp == NULL`) MUST clear shm_reliable_dms_locked!"
        );
        pinned.verify_snapshot_consistent().unwrap();

        // Extending `-shm` (simulating a writer finishing SHM initialization mid-scan) MUST be caught!
        holder_file.file.set_len(32_768).unwrap();
        assert!(pinned.verify_snapshot_consistent().is_err());
        assert!(pinned.saw_cohort_change());
        drop(tx);
        drop(pinned);
        drop(holder_file);

        // Verify `io_shm_lock(SQLITE_SHM_UNLOCK)` releases the OS `F_RDLCK` even if `-shm` was unlinked in `dir_fd`
        let ul_dir = tmp.path().join("ul");
        fs::create_dir_all(&ul_dir).unwrap();
        let ul_main = ul_dir.join("u.db");
        let ul_shm = ul_dir.join("u.db-shm");
        fs::write(&ul_main, b"0123456789abcdef").unwrap();
        fs::write(&ul_shm, vec![0_u8; 4096]).unwrap();

        let ul_dir_fd = open_existing_dir_nofollow(&ul_dir).unwrap().unwrap();
        let CohortMemberOpen::Present(m_pf) =
            open_cohort_member_in_dir(ul_dir_fd.as_raw_fd(), b"u.db", b"", 16)
        else {
            panic!("expected main present");
        };
        let CohortMemberOpen::Present(s_pf) =
            open_cohort_member_in_dir(ul_dir_fd.as_raw_fd(), b"u.db", b"-shm", 0)
        else {
            panic!("expected shm present");
        };
        let probe_fd: OwnedFd = fs::File::open(&ul_shm).unwrap().into();
        let main_dup = dup_fd_cloexec(m_pf.fd.as_raw_fd()).unwrap();
        let ul_ctx = Arc::new(PinnedSlotContext {
            dir_fd: ul_dir_fd,
            leaf_bytes: b"u.db".to_vec(),
            main_file: m_pf,
            main_opened_once: AtomicBool::new(true),
            wal_file: None,
            shm_file: Some(s_pf),
            journal_file: None,
            saw_unsafe_companion: AtomicBool::new(false),
            saw_cohort_change: AtomicBool::new(false),
            opened_virtual_empty_wal: AtomicBool::new(false),
            dms_initially_unlocked: AtomicBool::new(false),
            ofd_unavailable: AtomicBool::new(false),
            shm_reliable_dms_locked: AtomicBool::new(false),
            active_shm_lock_mask: AtomicU32::new(0),
        });
        let mut vfile = PinnedVfsFile {
            base: ffi::sqlite3_file {
                pMethods: &MAIN_IO_METHODS,
            },
            state: Box::into_raw(Box::new(VfsFileState::MainDb {
                ctx: Arc::clone(&ul_ctx),
                fd: main_dup,
                shared_locked: false,
                shm_fd: None,
                dms_shared_locked: false,
                shm_unreliable: false,
                shm_lock_mask: 0,
                shm_regions: Vec::new(),
            })),
        };
        unsafe {
            assert_eq!(
                io_shm_lock(
                    (&raw mut vfile).cast(),
                    3,
                    1,
                    ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_SHARED
                ),
                ffi::SQLITE_OK
            );
        }
        assert_eq!(
            ofd_other_lock_state(probe_fd.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_BASE + 3, 1),
            Some(libc::F_RDLCK)
        );
        // Unlink `u.db-shm` BEFORE unlocking slot 3: `io_shm_lock(UNLOCK)` MUST still release the OS lock AND record cohort change!
        fs::remove_file(&ul_shm).unwrap();
        unsafe {
            assert_eq!(
                io_shm_lock(
                    (&raw mut vfile).cast(),
                    3,
                    1,
                    ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_SHARED
                ),
                ffi::SQLITE_OK
            );
        }
        assert!(ul_ctx.saw_cohort_change.load(Ordering::SeqCst));
        assert_eq!(
            ofd_other_lock_state(probe_fd.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_BASE + 3, 1),
            Some(libc::F_UNLCK)
        );
        unsafe {
            assert_eq!(io_close((&raw mut vfile).cast()), ffi::SQLITE_OK);
        }
    }

    struct TestOfdLockGuard {
        file: fs::File,
        start: i64,
        len: i64,
    }

    impl TestOfdLockGuard {
        fn lock_shared(file: fs::File, start: i64, len: i64) -> Self {
            assert!(fcntl_set_lock(file.as_raw_fd(), libc::F_RDLCK, start, len).is_ok());
            Self { file, start, len }
        }
    }

    impl Drop for TestOfdLockGuard {
        fn drop(&mut self) {
            // Explicitly `F_UNLCK` before closing `self.file`: Linux OFD locks (`F_OFD_SETLK`) attach
            // to the kernel `struct file` (`locks_remove_file` in `__fput`), so relying on `close()`
            // alone races with concurrent `fork()`/`Command::spawn()` in parallel threads that briefly
            // hold a duplicated fdtable reference (`f_count > 1`) before `execve` (`do_close_on_exec`).
            let _ = fcntl_set_lock(self.file.as_raw_fd(), libc::F_UNLCK, self.start, self.len);
        }
    }

    #[test]
    fn absent_wal_with_dms_locked_shm_and_shm_unmap_close_ofd_lock_release() {
        let tmp = tempfile::tempdir().unwrap();
        let wal_dir = tmp.path().join("nowal_shm");
        fs::create_dir_all(&wal_dir).unwrap();
        let db_path = wal_dir.join("checkpointed.db");
        {
            let wconn = Connection::open(&db_path).unwrap();
            wconn
                .execute_batch(
                    "PRAGMA journal_mode = WAL;
                     CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);
                     INSERT INTO items VALUES (1, 2718);",
                )
                .unwrap();
        }
        assert!(!wal_dir.join("checkpointed.db-wal").exists());

        // Another process holds `F_RDLCK` on `UNIX_SHM_DMS` of `checkpointed.db-shm` while `-wal` is absent:
        let shm_path = wal_dir.join("checkpointed.db-shm");
        let shm_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&shm_path)
            .unwrap();
        shm_file.set_len(32_768).unwrap();
        let shm_holder = TestOfdLockGuard::lock_shared(shm_file, UNIX_SHM_DMS, 1);

        let dir_fd = open_existing_dir_nofollow(&wal_dir).unwrap().unwrap();
        let seen = HashSet::new();
        let PinnedSqliteOpen::Opened(pinned) =
            open_pinned_readonly_sqlite(&dir_fd, OsStr::new("checkpointed.db"), &seen)
        else {
            panic!("expected Opened on WAL DB with absent -wal and DMS-locked -shm");
        };
        let tx = pinned.conn().unchecked_transaction().unwrap();
        let v: i64 = tx
            .query_row("SELECT val FROM items WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2718);
        assert!(pinned.ctx.opened_virtual_empty_wal.load(Ordering::SeqCst));
        assert!(!pinned.ctx.shm_reliable_dms_locked.load(Ordering::SeqCst));
        assert!(!pinned.saw_cohort_change());
        pinned.verify_snapshot_consistent().unwrap();

        // If `<leaf>-wal` appears mid-transaction, `verify_snapshot_consistent()` MUST reject with `saw_cohort_change`!
        fs::write(wal_dir.join("checkpointed.db-wal"), b"").unwrap();
        assert!(pinned.verify_snapshot_consistent().is_err());
        assert!(pinned.saw_cohort_change());
        drop(tx);
        drop(pinned);
        drop(shm_holder);

        // Verify `io_shm_unmap` AND `io_close` explicitly release OFD locks (`UNIX_SHM_DMS` + `WAL_READ_LOCK`)
        // on `shm_fd` even while `Arc<PinnedSlotContext>` (`ctx.shm_file.fd`) remains alive AND while
        // concurrent threads spawn child processes (`fork()`..`execve()` inheriting open FDs pre-`CLOEXEC`)!
        let lk_dir = tmp.path().join("lk");
        fs::create_dir_all(&lk_dir).unwrap();
        let lk_main = lk_dir.join("m.db");
        let lk_wal = lk_dir.join("m.db-wal");
        let lk_shm = lk_dir.join("m.db-shm");
        fs::write(&lk_main, b"0123456789abcdef").unwrap();
        fs::write(&lk_wal, b"0123456789abcdef0123456789abcdef").unwrap();
        fs::write(&lk_shm, vec![0_u8; 32_768]).unwrap();

        let stop_spawner = Arc::new(AtomicBool::new(false));
        struct StopSpawnerOnDrop(Arc<AtomicBool>);
        impl Drop for StopSpawnerOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _stop_guard = StopSpawnerOnDrop(Arc::clone(&stop_spawner));
        let stop_spawner_bg = Arc::clone(&stop_spawner);
        let spawner_thread = std::thread::spawn(move || {
            let true_bin = if Path::new("/usr/bin/true").is_file() {
                "/usr/bin/true"
            } else {
                "/bin/true"
            };
            while !stop_spawner_bg.load(Ordering::Relaxed) {
                if let Ok(mut ch) = std::process::Command::new(true_bin).env_clear().spawn() {
                    let _ = ch.wait();
                }
            }
        });

        for _ in 0..8 {
            let peer_shm = TestOfdLockGuard::lock_shared(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lk_shm)
                    .unwrap(),
                UNIX_SHM_DMS,
                1,
            );
            let probe_shm: OwnedFd = fs::File::open(&lk_shm).unwrap().into();

            let lk_dir_fd = open_existing_dir_nofollow(&lk_dir).unwrap().unwrap();
            let CohortMemberOpen::Present(m_pf) =
                open_cohort_member_in_dir(lk_dir_fd.as_raw_fd(), b"m.db", b"", 16)
            else {
                panic!("expected main");
            };
            let CohortMemberOpen::Present(w_pf) =
                open_cohort_member_in_dir(lk_dir_fd.as_raw_fd(), b"m.db", b"-wal", 32)
            else {
                panic!("expected wal");
            };
            let CohortMemberOpen::Present(s_pf) =
                open_cohort_member_in_dir(lk_dir_fd.as_raw_fd(), b"m.db", b"-shm", 0)
            else {
                panic!("expected shm");
            };
            let main_dup = dup_fd_cloexec(m_pf.fd.as_raw_fd()).unwrap();
            let lk_ctx = Arc::new(PinnedSlotContext {
                dir_fd: lk_dir_fd,
                leaf_bytes: b"m.db".to_vec(),
                main_file: m_pf,
                main_opened_once: AtomicBool::new(true),
                wal_file: Some(w_pf),
                shm_file: Some(s_pf),
                journal_file: None,
                saw_unsafe_companion: AtomicBool::new(false),
                saw_cohort_change: AtomicBool::new(false),
                opened_virtual_empty_wal: AtomicBool::new(false),
                dms_initially_unlocked: AtomicBool::new(false),
                ofd_unavailable: AtomicBool::new(false),
                shm_reliable_dms_locked: AtomicBool::new(false),
                active_shm_lock_mask: AtomicU32::new(0),
            });
            let mut vfile = PinnedVfsFile {
                base: ffi::sqlite3_file {
                    pMethods: &MAIN_IO_METHODS,
                },
                state: Box::into_raw(Box::new(VfsFileState::MainDb {
                    ctx: Arc::clone(&lk_ctx),
                    fd: main_dup,
                    shared_locked: false,
                    shm_fd: None,
                    dms_shared_locked: false,
                    shm_unreliable: false,
                    shm_lock_mask: 0,
                    shm_regions: Vec::new(),
                })),
            };

            let mut region_ptr: *mut c_void = ptr::null_mut();
            unsafe {
                assert_eq!(
                    io_shm_map((&raw mut vfile).cast(), 0, 32_768, 0, &raw mut region_ptr),
                    ffi::SQLITE_READONLY
                );
                assert!(!region_ptr.is_null());
                assert_eq!(
                    io_shm_lock(
                        (&raw mut vfile).cast(),
                        3,
                        1,
                        ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_SHARED
                    ),
                    ffi::SQLITE_OK
                );
            }
            // Release `peer_shm`'s DMS lock so ONLY `vfile` holds `UNIX_SHM_DMS` + `WAL_READ_LOCK(0)`
            drop(peer_shm);
            assert_eq!(
                ofd_other_lock_state(probe_shm.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_DMS, 1),
                Some(libc::F_RDLCK)
            );
            assert_eq!(
                ofd_other_lock_state(probe_shm.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_BASE + 3, 1),
                Some(libc::F_RDLCK)
            );

            // `io_shm_unmap` MUST release BOTH `UNIX_SHM_DMS` and `WAL_READ_LOCK(0)` immediately while `lk_ctx` is still alive!
            unsafe {
                assert_eq!(io_shm_unmap((&raw mut vfile).cast(), 0), ffi::SQLITE_OK);
            }
            assert_eq!(
                ofd_other_lock_state(probe_shm.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_DMS, 1),
                Some(libc::F_UNLCK),
                "io_shm_unmap leaked UNIX_SHM_DMS OFD lock on shared PinnedSlotContext FD!"
            );
            assert_eq!(
                ofd_other_lock_state(probe_shm.as_raw_fd(), libc::F_WRLCK, UNIX_SHM_BASE + 3, 1),
                Some(libc::F_UNLCK),
                "io_shm_unmap leaked WAL_READ_LOCK OFD lock on shared PinnedSlotContext FD!"
            );
            unsafe {
                assert_eq!(io_close((&raw mut vfile).cast()), ffi::SQLITE_OK);
            }
            drop(lk_ctx);
        }

        stop_spawner.store(true, Ordering::SeqCst);
        spawner_thread.join().unwrap();
    }

    #[test]
    fn r3_06_ofd_einval_fallback_never_marks_reliable_shm_and_enforces_snapshot_check() {
        struct ForceOfdEinvalGuard;
        impl Drop for ForceOfdEinvalGuard {
            fn drop(&mut self) {
                TEST_FORCE_OFD_EINVAL.with(|c| c.set(false));
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let wal_dir = tmp.path().join("ofd_einval_wal");
        fs::create_dir_all(&wal_dir).unwrap();
        let db_path = wal_dir.join("active.db");

        // Keep an active WAL writer open with uncommitted checkpoint so `-wal` AND `-shm` exist
        // AND the writer holds `UNIX_SHM_DMS` shared lock!
        let wconn = Connection::open(&db_path).unwrap();
        wconn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER);
                 INSERT INTO items VALUES (1, 100);
                 INSERT INTO items VALUES (2, 200);",
            )
            .unwrap();
        assert!(wal_dir.join("active.db-wal").exists());
        assert!(wal_dir.join("active.db-shm").exists());

        TEST_FORCE_OFD_EINVAL.with(|c| c.set(true));
        let _guard = ForceOfdEinvalGuard;

        let dir_fd = open_existing_dir_nofollow(&wal_dir).unwrap().unwrap();
        let seen = HashSet::new();
        let PinnedSqliteOpen::Opened(pinned) =
            open_pinned_readonly_sqlite(&dir_fd, OsStr::new("active.db"), &seen)
        else {
            panic!("Expected active WAL DB to open cleanly under simulated OFD EINVAL");
        };

        let tx = pinned.conn().unchecked_transaction().unwrap();
        let sum: i64 = tx
            .query_row("SELECT SUM(val) FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sum, 300);

        // Under simulated OFD `EINVAL`:
        // 1. `ofd_unavailable` MUST be true;
        // 2. `shm_reliable_dms_locked` MUST remain false (NEVER promoted via POSIX fallback);
        // 3. `active_shm_lock_mask` MUST remain 0 (NO POSIX WAL_READ_LOCK acquired on `-shm`).
        assert!(pinned.ctx.ofd_unavailable.load(Ordering::SeqCst));
        assert!(!pinned.ctx.shm_reliable_dms_locked.load(Ordering::SeqCst));
        assert_eq!(pinned.ctx.active_shm_lock_mask.load(Ordering::SeqCst), 0);

        // Clean read with no concurrent writer modification passes snapshot check!
        pinned.verify_snapshot_consistent().unwrap();

        // Now the live writer appends to `-wal` during the reader transaction:
        // because `shm_reliable_dms_locked == false`, `verify_snapshot_consistent()` MUST NOT skip
        // cohort validation and MUST reject the modified `-wal` snapshot!
        wconn
            .execute("INSERT INTO items VALUES (3, 300)", [])
            .unwrap();
        assert!(
            pinned.verify_snapshot_consistent().is_err(),
            "Under OFD EINVAL fallback, concurrent WAL append MUST fail verify_snapshot_consistent!"
        );
        assert!(pinned.saw_cohort_change());
        drop(tx);
        drop(pinned);
        drop(wconn);
    }
}
