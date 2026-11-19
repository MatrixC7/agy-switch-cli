use crate::error::{CliError, CliResult};
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const MAX_STORE_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Exact ownership marker embedded in temporary files created by `agy-switch-cli`.
pub const OWNED_TMP_MARKER: &str = ".tmp.agy-switch-cli.";

#[cfg(feature = "stats")]
#[derive(Debug)]
pub(crate) enum ChildDirOpen {
    Opened(OwnedFd),
    Absent,
    Unsafe,
    IoError,
}

pub(crate) fn is_single_normal_filename(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

/// Open a single child directory inside an already-verified `parent_fd` strictly via
/// `openat(..., (O_RDONLY | O_PATH) | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`.
#[cfg(feature = "stats")]
pub(crate) fn open_child_dir_nofollow(
    parent_fd: &OwnedFd,
    child_name: &str,
    readable: bool,
) -> ChildDirOpen {
    if !is_single_normal_filename(child_name.as_bytes()) {
        return ChildDirOpen::Unsafe;
    }
    let Ok(c_name) = CString::new(child_name.as_bytes()) else {
        return ChildDirOpen::Unsafe;
    };
    let access_mode = if readable {
        libc::O_RDONLY
    } else {
        libc::O_PATH
    };
    let raw_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_name.as_ptr(),
            access_mode | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code == libc::ENOENT => ChildDirOpen::Absent,
            Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => ChildDirOpen::Unsafe,
            _ => ChildDirOpen::IoError,
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return ChildDirOpen::IoError;
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return ChildDirOpen::Unsafe;
    }
    ChildDirOpen::Opened(fd)
}

/// Walk every existing ancestor component of `dir_path` top-down using chained `openat` handles
/// (`O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`), returning the verified handle to `dir_path`:
/// - Eliminates TOCTOU between ancestor verification and directory opening;
/// - Opens the first top-level component `/<first>` directly rather than literal `"/"` so user-mode
///   QEMU `-L <sysroot>` emulation never redirects `"/"` to `/usr/aarch64-linux-gnu`;
/// - Deterministically rejects ANY symlink or non-directory component at ANY depth;
/// - Returns `Ok(None)` when a component does not exist yet (`ENOENT`), AFTER proving all existing higher ancestors are real directories.
pub(crate) fn open_existing_dir_nofollow(dir_path: &Path) -> CliResult<Option<OwnedFd>> {
    let effective = if dir_path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir_path
    };

    let resolved = if effective.is_absolute() {
        crate::paths::normalize_components(effective)
    } else {
        let cwd = std::env::current_dir()
            .map_err(|e| map_io_error(e, "Cannot resolve current working directory"))?;
        crate::paths::normalize_components(&cwd.join(effective))
    };

    let mut walked = PathBuf::new();
    let mut cur_fd: Option<OwnedFd> = None;

    for comp in resolved.components() {
        match comp {
            Component::RootDir => {
                walked.push("/");
                continue;
            }
            Component::CurDir => continue,
            Component::Prefix(p) => {
                walked.push(p.as_os_str());
                continue;
            }
            Component::ParentDir => {
                walked.push("..");
                return Err(CliError::data(format!(
                    "Directory path '{}' must not traverse '..' or symlinked ancestors.",
                    walked.display()
                )));
            }
            Component::Normal(part) => {
                if !is_single_normal_filename(part.as_bytes()) {
                    return Err(CliError::data(format!(
                        "Directory path '{}' contains an invalid component.",
                        resolved.display()
                    )));
                }
                walked.push(part);
                let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                let raw_fd = if let Some(ref parent) = cur_fd {
                    let c_part = CString::new(part.as_bytes()).map_err(|_| {
                        CliError::data(format!(
                            "Path '{}' contains an invalid NUL byte.",
                            walked.display()
                        ))
                    })?;
                    unsafe { libc::openat(parent.as_raw_fd(), c_part.as_ptr(), flags) }
                } else {
                    let c_first = CString::new(walked.as_os_str().as_bytes()).map_err(|_| {
                        CliError::data(format!(
                            "Path '{}' contains an invalid NUL byte.",
                            walked.display()
                        ))
                    })?;
                    unsafe { libc::open(c_first.as_ptr(), flags) }
                };

                if raw_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    return match err.raw_os_error() {
                        Some(code) if code == libc::ENOENT => Ok(None),
                        Some(code) if code == libc::ENOTDIR || code == libc::ELOOP => {
                            Err(CliError::data(format!(
                                "Directory path '{}' must be a real directory, not a symlink or file.",
                                walked.display()
                            )))
                        }
                        _ => Err(map_io_error(
                            err,
                            &format!("Cannot open directory component '{}'", walked.display()),
                        )),
                    };
                }

                let next_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(next_fd.as_raw_fd(), &mut st) } != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(map_io_error(
                        err,
                        &format!("Cannot stat directory '{}'", walked.display()),
                    ));
                }
                if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                    return Err(CliError::data(format!(
                        "Directory path '{}' must be a real directory, not a symlink or file.",
                        walked.display()
                    )));
                }
                cur_fd = Some(next_fd);
            }
        }
    }

    if let Some(fd) = cur_fd {
        return Ok(Some(fd));
    }

    let c_root = CString::new("/").unwrap();
    let root_raw = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        let err = std::io::Error::last_os_error();
        return Err(map_io_error(err, "Cannot open root directory '/'"));
    }
    Ok(Some(unsafe { OwnedFd::from_raw_fd(root_raw) }))
}

/// Verify that every existing directory component of `dir_path` from `/` (or `.`) down is a real directory
/// (never a symlink or non-directory). Missing trailing components are allowed (e.g. before initialization).
pub fn ensure_no_symlink_ancestors(dir_path: &Path) -> CliResult<()> {
    let _ = open_existing_dir_nofollow(dir_path)?;
    Ok(())
}

/// Pin an already-opened regular file's `(dev, ino)` against `fstatat(AT_SYMLINK_NOFOLLOW)` inside an
/// `O_PATH | O_DIRECTORY | O_NOFOLLOW` handle of its parent directory (rejecting any ancestor symlink or inode swap).
pub(crate) fn verify_opened_regular_file_pinned(
    path: &Path,
    meta: &fs::Metadata,
    label: &str,
) -> CliResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(parent_fd) = open_existing_dir_nofollow(parent)? else {
        return Err(map_io_error(
            std::io::Error::from(std::io::ErrorKind::NotFound),
            &format!(
                "Parent directory of {label} '{}' disappeared",
                path.display()
            ),
        ));
    };
    let Some(leaf_name) = path.file_name() else {
        return Err(CliError::data(format!(
            "{label} '{}' has no regular file name.",
            path.display()
        )));
    };
    let c_leaf = CString::new(leaf_name.as_bytes()).map_err(|_| {
        CliError::data(format!(
            "{label} '{}' contains an invalid NUL byte.",
            path.display()
        ))
    })?;
    let mut pinned_st: libc::stat = unsafe { std::mem::zeroed() };
    let fstatat_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut pinned_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if fstatat_rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(map_io_error(
            err,
            &format!(
                "Cannot verify directory entry for {label} '{}'",
                path.display()
            ),
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    let same_inode = (pinned_st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && (pinned_st.st_dev as u64) == meta.dev()
        && (pinned_st.st_ino as u64) == meta.ino();
    if !same_inode {
        return Err(CliError::data(format!(
            "{label} '{}' changed inode or resolved through a replaced ancestor during open.",
            path.display()
        )));
    }
    Ok(())
}

/// Verify that all existing ancestors above `base`, `base` itself (if it exists), and every relative
/// component from `base` down to `target` (inclusive of intermediate directories and leaf) are free of symlinks.
pub fn ensure_no_symlink_components_under(base: &Path, target: &Path) -> CliResult<()> {
    ensure_no_symlink_ancestors(base)?;
    check_not_symlink_if_exists(base)?;
    let Ok(rel) = target.strip_prefix(base) else {
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                ensure_no_symlink_ancestors(parent)?;
            }
        }
        check_not_symlink_if_exists(target)?;
        return Ok(());
    };
    let mut cur = base.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    for (idx, comp) in comps.iter().enumerate() {
        if let Component::Normal(part) = comp {
            cur.push(part);
            let is_last = idx + 1 == comps.len();
            if !is_last {
                check_not_symlink_dir_if_exists(&cur)?;
            } else {
                check_not_symlink_if_exists(&cur)?;
            }
        }
    }
    Ok(())
}

fn check_not_symlink_if_exists(path: &Path) -> CliResult<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CliError::data(format!(
            "Refusing to traverse symlink path '{}'.",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(map_io_error(
            e,
            &format!("Cannot inspect path '{}'", path.display()),
        )),
    }
}

fn check_not_symlink_dir_if_exists(path: &Path) -> CliResult<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                Err(CliError::data(format!(
                    "Directory path '{}' must be a real directory, not a symlink or file.",
                    path.display()
                )))
            } else {
                Ok(())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(map_io_error(
            e,
            &format!("Cannot inspect directory '{}'", path.display()),
        )),
    }
}

/// Create directory recursively with `0700` permissions, rejecting symlinks on the target
/// AND on EVERY existing ancestor directory from `/` (or `.`) downward.
pub fn ensure_private_dir(dir: &Path) -> CliResult<()> {
    ensure_no_symlink_ancestors(dir)?;

    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(CliError::data(format!(
                    "Directory path '{}' must be a real directory, not a symlink or file.",
                    dir.display()
                )));
            }
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(map_io_error(
                e,
                &format!("Cannot inspect directory '{}'", dir.display()),
            ))
        }
    }

    let mut missing_stack: Vec<&Path> = Vec::new();
    let mut probe = dir;
    loop {
        match fs::symlink_metadata(probe) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                    return Err(CliError::data(format!(
                        "Ancestor path '{}' must be a real directory, not a symlink or file.",
                        probe.display()
                    )));
                }
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing_stack.push(probe);
                match probe.parent() {
                    Some(p) if !p.as_os_str().is_empty() => probe = p,
                    _ => break,
                }
            }
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot inspect ancestor directory '{}'", probe.display()),
                ));
            }
        }
    }

    for to_create in missing_stack.into_iter().rev() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(to_create) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot create directory '{}'", to_create.display()),
                ));
            }
        }
        let created_meta = fs::symlink_metadata(to_create).map_err(|e| {
            map_io_error(
                e,
                &format!("Cannot verify created directory '{}'", to_create.display()),
            )
        })?;
        if created_meta.file_type().is_symlink() || !created_meta.file_type().is_dir() {
            return Err(CliError::data(format!(
                "Directory path '{}' resolved to a symlink or non-directory during creation.",
                to_create.display()
            )));
        }
        let _ = fs::set_permissions(to_create, fs::Permissions::from_mode(0o700));
    }

    // Re-verify full ancestor chain via `openat(O_PATH | O_DIRECTORY | O_NOFOLLOW)` after creation.
    ensure_no_symlink_ancestors(dir)?;
    Ok(())
}

/// Safe non-blocking regular-file reader (`O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` + `fstat` `S_ISREG` + bounded read).
/// Deterministically rejects symlinks, FIFOs (without ever blocking in `open()`!), sockets, devices, directories,
/// symlinked ancestor directories at ANY depth, and oversized files (`> max_bytes`).
pub fn read_regular_file_opt_bounded(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> CliResult<Option<Vec<u8>>> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(parent_fd) = open_existing_dir_nofollow(parent)? else {
        return Ok(None);
    };
    let Some(leaf_name) = path.file_name() else {
        return Err(CliError::data(format!(
            "{label} '{}' has no regular file name.",
            path.display()
        )));
    };
    let c_leaf = CString::new(leaf_name.as_bytes()).map_err(|_| {
        CliError::data(format!(
            "{label} '{}' contains an invalid NUL byte.",
            path.display()
        ))
    })?;

    let raw_file_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let file = if raw_file_fd >= 0 {
        unsafe { fs::File::from_raw_fd(raw_file_fd) }
    } else {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        if e.raw_os_error() == Some(libc::ELOOP) {
            return Err(CliError::data(format!(
                "{label} '{}' must be a regular file, not a symlink.",
                path.display()
            )));
        }
        if e.raw_os_error() == Some(libc::ENXIO) || e.raw_os_error() == Some(libc::EISDIR) {
            return Err(CliError::data(format!(
                "{label} '{}' must be a regular file, not a special file or directory.",
                path.display()
            )));
        }
        return Err(map_io_error(
            e,
            &format!("Cannot open {label} '{}'", path.display()),
        ));
    };

    let meta = file.metadata().map_err(|e| {
        map_io_error(
            e,
            &format!("Cannot stat opened {label} '{}'", path.display()),
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(CliError::data(format!(
            "{label} '{}' must be a regular file (found FIFO, socket, device, or directory).",
            path.display()
        )));
    }

    // Confirm the opened fd matches the exact regular-file inode inside the `openat`-verified real `parent_fd`.
    let mut pinned_st: libc::stat = unsafe { std::mem::zeroed() };
    let fstatat_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut pinned_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if fstatat_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(map_io_error(
            err,
            &format!(
                "Cannot verify directory entry for {label} '{}'",
                path.display()
            ),
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    let same_inode = (pinned_st.st_mode & libc::S_IFMT) == libc::S_IFREG
        && (pinned_st.st_dev as u64) == meta.dev()
        && (pinned_st.st_ino as u64) == meta.ino();
    if !same_inode {
        return Err(CliError::data(format!(
            "{label} '{}' changed inode or resolved through a replaced ancestor during open.",
            path.display()
        )));
    }

    if meta.len() > max_bytes as u64 {
        return Err(CliError::data(format!(
            "{label} '{}' exceeds maximum allowed size ({max_bytes} bytes).",
            path.display()
        )));
    }

    // Clear O_NONBLOCK now that `fstat` proved the fd is an ordinary regular file.
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 && (flags & libc::O_NONBLOCK) != 0 {
            let _ = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }

    let cap = (meta.len() as usize).min(max_bytes);
    let mut buf = Vec::with_capacity(cap);
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| map_io_error(e, &format!("Cannot read {label} '{}'", path.display())))?;
    if buf.len() > max_bytes {
        return Err(CliError::data(format!(
            "{label} '{}' exceeds maximum allowed size ({max_bytes} bytes).",
            path.display()
        )));
    }
    Ok(Some(buf))
}

pub fn read_regular_file_bounded(path: &Path, max_bytes: usize, label: &str) -> CliResult<Vec<u8>> {
    match read_regular_file_opt_bounded(path, max_bytes, label)? {
        Some(bytes) => Ok(bytes),
        None => Err(map_io_error(
            std::io::Error::from(std::io::ErrorKind::NotFound),
            &format!("Cannot find {label} '{}'", path.display()),
        )),
    }
}

/// Fault-injection hook used strictly in automated fault-injection tests via `AGY_SWITCH_CLI_FAULT_SPEC`.
/// Format: `<stage>:<filename_substr>:<action>` where action is `enospc`, `erofs`, `io`, `corrupt_after_rename`, or `abort`.
pub fn check_fault_injection(stage: &str, target: &Path) -> CliResult<()> {
    let Ok(spec) = std::env::var("AGY_SWITCH_CLI_FAULT_SPEC") else {
        return Ok(());
    };
    for rule in spec.split(';') {
        let parts: Vec<&str> = rule.trim().split(':').collect();
        if parts.len() != 3 {
            continue;
        }
        let (rule_stage, name_match, action) = (parts[0], parts[1], parts[2]);
        let target_str = target.to_string_lossy();
        if rule_stage == stage && (name_match == "*" || target_str.contains(name_match)) {
            match action {
                "enospc" => {
                    return Err(map_io_error(
                        std::io::Error::from_raw_os_error(libc::ENOSPC),
                        &format!("Injected ENOSPC at {stage} for '{}'", target.display()),
                    ));
                }
                "erofs" => {
                    return Err(map_io_error(
                        std::io::Error::from_raw_os_error(libc::EROFS),
                        &format!("Injected EROFS at {stage} for '{}'", target.display()),
                    ));
                }
                "io" => {
                    return Err(CliError::io(
                        "io_error",
                        format!("Injected I/O error at {stage} for '{}'", target.display()),
                    ));
                }
                "corrupt_after_rename" if stage == "after_rename" => {
                    let _ = fs::write(target, b"corrupted-by-fault-injector");
                }
                "corrupt_once" if stage == "after_rename" => {
                    use std::sync::atomic::{AtomicBool, Ordering};
                    static FIRED_ONCE: AtomicBool = AtomicBool::new(false);
                    if !FIRED_ONCE.swap(true, Ordering::SeqCst) {
                        let _ = fs::write(target, b"corrupted-once-by-fault-injector");
                    }
                }
                "abort" => {
                    std::process::exit(137);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn map_io_error(err: std::io::Error, context: &str) -> CliError {
    match err.raw_os_error() {
        Some(code) if code == libc::ENOSPC => CliError::io(
            "disk_full_enospc",
            format!("{context}: No space left on device (ENOSPC)."),
        ),
        Some(code) if code == libc::EROFS => CliError::io(
            "read_only_fs_erofs",
            format!("{context}: Read-only file system (EROFS)."),
        ),
        Some(code) if code == libc::EACCES || code == libc::EPERM => CliError::io(
            "permission_denied",
            format!("{context}: Permission denied ({err})."),
        ),
        _ => CliError::io("io_error", format!("{context}: {err}")),
    }
}

/// Durable single-file atomic write per Blueprint §3.2:
/// 1. `symlink_metadata` check on both parent directory and target rejecting symlinks, directories, FIFOs, etc.
/// 2. Same-directory unique `.tmp.<uuid>` created with `0600` + `O_NOFOLLOW` + `create_new(true)`.
/// 3. `write_all` -> `file.sync_all()` -> `drop(file)` -> `fs::rename` -> `parent_dir.sync_all()`.
/// 4. Safe non-blocking regular-file readback verification checking exact byte equality.
pub fn write_atomic_durable(target: &Path, content: &[u8]) -> CliResult<()> {
    let raw_parent = target.parent().ok_or_else(|| {
        CliError::data(format!(
            "Target path '{}' has no parent directory.",
            target.display()
        ))
    })?;
    let parent_dir = if raw_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        raw_parent
    };
    ensure_no_symlink_ancestors(parent_dir)?;
    let parent_meta = fs::symlink_metadata(parent_dir).map_err(|e| {
        map_io_error(
            e,
            &format!(
                "Parent directory '{}' is not accessible",
                parent_dir.display()
            ),
        )
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
        return Err(CliError::data(format!(
            "Parent path '{}' must be a real directory, not a symlink or file.",
            parent_dir.display()
        )));
    }

    match fs::symlink_metadata(target) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(CliError::data(format!(
                "Refusing to write '{}': target exists and is not a regular file (symlink, FIFO, or directory).",
                target.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(map_io_error(
                e,
                &format!("Cannot inspect target file '{}'", target.display()),
            ))
        }
    }

    check_fault_injection("before_write", target)?;

    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CliError::data("Invalid target file name."))?;
    let temp_path: PathBuf =
        parent_dir.join(format!("{file_name}{OWNED_TMP_MARKER}{}", Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);

    let mut file = options.open(&temp_path).map_err(|e| {
        map_io_error(
            e,
            &format!("Failed to create temporary file '{}'", temp_path.display()),
        )
    })?;

    if let Err(e) = file.write_all(content) {
        let _ = fs::remove_file(&temp_path);
        return Err(map_io_error(
            e,
            &format!("Failed to write temporary file '{}'", temp_path.display()),
        ));
    }

    if let Err(e) = check_fault_injection("before_fsync", target) {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    if let Err(e) = file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(map_io_error(
            e,
            &format!("Failed to fsync temporary file '{}'", temp_path.display()),
        ));
    }

    drop(file);

    if let Err(e) = check_fault_injection("before_rename", target) {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&temp_path, target) {
        let _ = fs::remove_file(&temp_path);
        return Err(map_io_error(
            e,
            &format!("Failed to atomically replace '{}'", target.display()),
        ));
    }

    check_fault_injection("sync_parent_dir", target)?;

    // Parent directory fsync (`O_DIRECTORY | O_NOFOLLOW`) to guarantee directory entry durability.
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent_dir)
        .map_err(|e| {
            map_io_error(
                e,
                &format!(
                    "Failed to open parent directory '{}' for fsync",
                    parent_dir.display()
                ),
            )
        })?;
    dir_file.sync_all().map_err(|e| {
        map_io_error(
            e,
            &format!(
                "Failed to fsync parent directory '{}'",
                parent_dir.display()
            ),
        )
    })?;

    check_fault_injection("after_rename", target)?;

    // Non-blocking regular-file readback verification
    let max_rb = content.len().max(MAX_STORE_FILE_BYTES);
    let actual = match read_regular_file_opt_bounded(target, max_rb, "Readback file") {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(CliError::io(
                "readback_missing",
                format!(
                    "Readback verification failed for '{}': file missing immediately after rename.",
                    target.display()
                ),
            ));
        }
        Err(e) if e.error_code == "data_error" => {
            return Err(CliError::io("readback_not_regular_file", e.message));
        }
        Err(e) => return Err(e),
    };
    if actual != content {
        return Err(CliError::io(
            "readback_mismatch",
            format!(
                "Readback verification mismatch for '{}' (expected {} bytes, got {} bytes).",
                target.display(),
                content.len(),
                actual.len()
            ),
        ));
    }

    Ok(())
}

pub(crate) fn stat_dir_fd(dir_fd: &OwnedFd, dir_path: &Path) -> CliResult<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir_fd.as_raw_fd(), &mut st) } != 0 {
        return Err(map_io_error(
            std::io::Error::last_os_error(),
            &format!("Cannot stat directory '{}'", dir_path.display()),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(CliError::data(format!(
            "Directory path '{}' must be a real directory.",
            dir_path.display()
        )));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok((st.st_dev as u64, st.st_ino as u64))
}

pub(crate) fn fsync_pinned_dir_fd(dir_fd: &OwnedFd, dir_path: &Path) -> CliResult<()> {
    let raw_rd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_rd < 0 {
        return Err(map_io_error(
            std::io::Error::last_os_error(),
            &format!(
                "Failed to open directory '{}' for fsync",
                dir_path.display()
            ),
        ));
    }
    let rd_file = unsafe { fs::File::from_raw_fd(raw_rd) };
    rd_file.sync_all().map_err(|e| {
        map_io_error(
            e,
            &format!("Failed to fsync directory '{}'", dir_path.display()),
        )
    })
}

pub(crate) fn verify_dir_still_pinned(
    dir_path: &Path,
    expected_dev: u64,
    expected_ino: u64,
) -> CliResult<()> {
    let Some(reopened) = open_existing_dir_nofollow(dir_path)? else {
        return Err(CliError::data(format!(
            "Directory '{}' disappeared during operation.",
            dir_path.display()
        )));
    };
    let (cur_dev, cur_ino) = stat_dir_fd(&reopened, dir_path)?;
    if (cur_dev, cur_ino) != (expected_dev, expected_ino) {
        return Err(CliError::data(format!(
            "Directory '{}' changed inode or resolved through a replaced ancestor.",
            dir_path.display()
        )));
    }
    Ok(())
}

/// Remove a regular file strictly through an `openat`-pinned parent directory handle,
/// propagating parent directory `fsync` errors (even when the target was already unlinked in dcache!)
/// so post-removal absence is durably confirmed on stable storage.
pub fn remove_regular_file_durable_under(
    base_dir: &Path,
    target: &Path,
    label: &str,
) -> CliResult<bool> {
    ensure_no_symlink_components_under(base_dir, target)?;
    let raw_parent = target.parent().ok_or_else(|| {
        CliError::data(format!(
            "{label} '{}' has no parent directory.",
            target.display()
        ))
    })?;
    let parent_dir = if raw_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        raw_parent
    };
    let leaf = target.file_name().ok_or_else(|| {
        CliError::data(format!("{label} '{}' has no file name.", target.display()))
    })?;
    if !is_single_normal_filename(leaf.as_bytes()) {
        return Err(CliError::data(format!(
            "{label} '{}' has an invalid file name.",
            target.display()
        )));
    }
    let c_leaf = CString::new(leaf.as_bytes()).map_err(|_| {
        CliError::data(format!(
            "{label} '{}' contains an invalid NUL byte.",
            target.display()
        ))
    })?;

    let Some(parent_fd) = open_existing_dir_nofollow(parent_dir)? else {
        return Ok(false);
    };
    let (dir_dev, dir_ino) = stat_dir_fd(&parent_fd, parent_dir)?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let mut removed = false;
    if stat_rc == 0 {
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(CliError::data(format!(
                "Refusing to remove non-regular {label} '{}'.",
                target.display()
            )));
        }
        verify_dir_still_pinned(parent_dir, dir_dev, dir_ino)?;
        let unlink_rc = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), c_leaf.as_ptr(), 0) };
        if unlink_rc == 0 {
            removed = true;
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(map_io_error(
                    err,
                    &format!("Failed to remove {label} '{}'", target.display()),
                ));
            }
        }
    } else {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(c) if c == libc::ENOENT => {}
            Some(c) if c == libc::ELOOP || c == libc::ENOTDIR => {
                return Err(CliError::data(format!(
                    "Refusing to remove non-regular {label} '{}'.",
                    target.display()
                )));
            }
            _ => {
                return Err(map_io_error(
                    err,
                    &format!("Cannot inspect {label} '{}'", target.display()),
                ));
            }
        }
    }

    verify_dir_still_pinned(parent_dir, dir_dev, dir_ino)?;
    check_fault_injection("sync_parent_dir", target)?;
    fsync_pinned_dir_fd(&parent_fd, parent_dir)?;

    let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
    let post_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut post_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if post_rc == 0 {
        return Err(CliError::io(
            "remove_readback_present",
            format!("{label} '{}' still exists after removal.", target.display()),
        ));
    }
    let post_err = std::io::Error::last_os_error();
    if post_err.raw_os_error() != Some(libc::ENOENT) {
        return Err(map_io_error(
            post_err,
            &format!("Cannot verify removal of {label} '{}'", target.display()),
        ));
    }

    Ok(removed)
}

/// Confirm that already-updated entries inside `parent_dir` (and each target path) pass symlink
/// safety checks and `sync_parent_dir` durability confirmation via a pinned directory handle.
pub fn confirm_dir_entries_durable_under(
    base_dir: &Path,
    parent_dir: &Path,
    targets: &[&Path],
) -> CliResult<()> {
    ensure_no_symlink_components_under(base_dir, parent_dir)?;
    for target in targets {
        ensure_no_symlink_components_under(base_dir, target)?;
    }
    let Some(parent_fd) = open_existing_dir_nofollow(parent_dir)? else {
        return Err(CliError::io(
            "io_error",
            format!(
                "Parent directory '{}' does not exist while confirming durability.",
                parent_dir.display()
            ),
        ));
    };
    let (dir_dev, dir_ino) = stat_dir_fd(&parent_fd, parent_dir)?;
    for target in targets {
        check_fault_injection("sync_parent_dir", target)?;
    }
    verify_dir_still_pinned(parent_dir, dir_dev, dir_ino)?;
    fsync_pinned_dir_fd(&parent_fd, parent_dir)?;
    Ok(())
}

/// Confirm via pinned `openat`/`fstatat(AT_SYMLINK_NOFOLLOW)` and parent directory `fsync` that
/// `target` is absent without unlinking any newly appeared file.
pub fn confirm_file_absent_and_parent_durable_under(
    base_dir: &Path,
    target: &Path,
    label: &str,
) -> CliResult<()> {
    ensure_no_symlink_components_under(base_dir, target)?;
    let raw_parent = target.parent().ok_or_else(|| {
        CliError::data(format!(
            "{label} '{}' has no parent directory.",
            target.display()
        ))
    })?;
    let parent_dir = if raw_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        raw_parent
    };
    let leaf = target.file_name().ok_or_else(|| {
        CliError::data(format!("{label} '{}' has no file name.", target.display()))
    })?;
    if !is_single_normal_filename(leaf.as_bytes()) {
        return Err(CliError::data(format!(
            "{label} '{}' has an invalid file name.",
            target.display()
        )));
    }
    let c_leaf = CString::new(leaf.as_bytes()).map_err(|_| {
        CliError::data(format!(
            "{label} '{}' contains an invalid NUL byte.",
            target.display()
        ))
    })?;

    let Some(parent_fd) = open_existing_dir_nofollow(parent_dir)? else {
        return Ok(());
    };
    let (dir_dev, dir_ino) = stat_dir_fd(&parent_fd, parent_dir)?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_rc == 0 {
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            format!(
                "{label} '{}' is present on disk while confirming absence durability; journal preserved.",
                target.display()
            ),
        ));
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(c) if c == libc::ENOENT => {}
        Some(c) if c == libc::ELOOP || c == libc::ENOTDIR => {
            return Err(CliError::data(format!(
                "Refusing to traverse non-regular {label} '{}'.",
                target.display()
            )));
        }
        _ => {
            return Err(map_io_error(
                err,
                &format!("Cannot inspect {label} '{}'", target.display()),
            ));
        }
    }

    verify_dir_still_pinned(parent_dir, dir_dev, dir_ino)?;
    check_fault_injection("sync_parent_dir", target)?;
    fsync_pinned_dir_fd(&parent_fd, parent_dir)?;

    let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
    let post_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut post_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if post_rc == 0 {
        return Err(CliError::partial_commit(
            "recovery_incomplete",
            format!(
                "{label} '{}' appeared concurrently during parent directory sync; journal preserved.",
                target.display()
            ),
        ));
    }
    let post_err = std::io::Error::last_os_error();
    if post_err.raw_os_error() != Some(libc::ENOENT) {
        return Err(map_io_error(
            post_err,
            &format!("Cannot verify absence of {label} '{}'", target.display()),
        ));
    }

    Ok(())
}

/// Create/open a real non-symlink directory hierarchy from `/` down to `target_dir` (`0700` on newly
/// created components under `root_dir`), returning the pinned `OwnedFd` and `(dev, ino)` of `target_dir`.
pub(crate) fn ensure_dir_chain_pinned_under(
    root_dir: &Path,
    target_dir: &Path,
) -> CliResult<(OwnedFd, u64, u64)> {
    ensure_no_symlink_ancestors(root_dir)?;
    if !root_dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root_dir)
            .map_err(|e| {
                map_io_error(
                    e,
                    &format!("Failed to create directory '{}'", root_dir.display()),
                )
            })?;
    }
    let Some(mut cur_fd) = open_existing_dir_nofollow(root_dir)? else {
        return Err(CliError::data(format!(
            "Directory '{}' could not be opened after creation.",
            root_dir.display()
        )));
    };
    let rel = target_dir.strip_prefix(root_dir).map_err(|_| {
        CliError::data(format!(
            "Target directory '{}' is not inside '{}'.",
            target_dir.display(),
            root_dir.display()
        ))
    })?;
    let mut cur_path = root_dir.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::CurDir => continue,
            Component::Normal(part) => {
                if !is_single_normal_filename(part.as_bytes()) {
                    return Err(CliError::data(format!(
                        "Invalid directory component in '{}'.",
                        target_dir.display()
                    )));
                }
                cur_path.push(part);
                let c_part = CString::new(part.as_bytes()).map_err(|_| {
                    CliError::data(format!(
                        "Path '{}' contains an invalid NUL byte.",
                        cur_path.display()
                    ))
                })?;
                let mk_rc = unsafe { libc::mkdirat(cur_fd.as_raw_fd(), c_part.as_ptr(), 0o700) };
                if mk_rc != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(map_io_error(
                            err,
                            &format!("Failed to create directory '{}'", cur_path.display()),
                        ));
                    }
                }
                let next_raw = unsafe {
                    libc::openat(
                        cur_fd.as_raw_fd(),
                        c_part.as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_raw < 0 {
                    let err = std::io::Error::last_os_error();
                    return if matches!(err.raw_os_error(), Some(c) if c == libc::ELOOP || c == libc::ENOTDIR)
                    {
                        Err(CliError::data(format!(
                            "Refusing to use '{}' because it is a symlink or non-directory.",
                            cur_path.display()
                        )))
                    } else {
                        Err(map_io_error(
                            err,
                            &format!("Cannot open directory '{}'", cur_path.display()),
                        ))
                    };
                }
                let next_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
                let _ = stat_dir_fd(&next_fd, &cur_path)?;
                cur_fd = next_fd;
            }
            _ => {
                return Err(CliError::data(format!(
                    "Directory '{}' must not contain '..' components.",
                    target_dir.display()
                )));
            }
        }
    }

    let (dev, ino) = stat_dir_fd(&cur_fd, target_dir)?;
    verify_dir_still_pinned(target_dir, dev, ino)?;
    Ok((cur_fd, dev, ino))
}

/// Atomically write and durably replace `leaf_name` strictly inside an `openat`-pinned `dir_fd`,
/// re-verifying that `dir_path` still resolves to `(dir_dev, dir_ino)` and that `leaf_name` was
/// not replaced with a symlink before `renameat`, and keeping the readback FD open (`OwnedFd`)
/// so the kernel cannot reclaim/reuse the inode while the caller verifies follow-up waits!
pub(crate) fn write_atomic_durable_in_pinned_dir(
    dir_fd: &OwnedFd,
    dir_dev: u64,
    dir_ino: u64,
    dir_path: &Path,
    leaf_name: &str,
    content: &[u8],
) -> CliResult<(OwnedFd, u64, u64)> {
    if !is_single_normal_filename(leaf_name.as_bytes()) {
        return Err(CliError::data("Invalid target file name."));
    }
    let c_leaf = CString::new(leaf_name.as_bytes())
        .map_err(|_| CliError::data("Invalid NUL in target file name."))?;
    let target_full = dir_path.join(leaf_name);

    verify_dir_still_pinned(dir_path, dir_dev, dir_ino)?;

    let mut pre_st: libc::stat = unsafe { std::mem::zeroed() };
    let pre_rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut pre_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let pre_existing_id: Option<(u64, u64)> = if pre_rc == 0 {
        if (pre_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(CliError::data(format!(
                "Refusing to overwrite non-regular service target '{}'.",
                target_full.display()
            )));
        }
        #[allow(clippy::unnecessary_cast)]
        Some((pre_st.st_dev as u64, pre_st.st_ino as u64))
    } else {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(c) if c == libc::ENOENT => None,
            Some(c) if c == libc::ELOOP || c == libc::ENOTDIR => {
                return Err(CliError::data(format!(
                    "Refusing to overwrite non-regular service target '{}'.",
                    target_full.display()
                )));
            }
            _ => {
                return Err(map_io_error(
                    err,
                    &format!("Cannot inspect target '{}'", target_full.display()),
                ));
            }
        }
    };

    check_fault_injection("before_write", &target_full)?;

    let tmp_name = format!("{leaf_name}{OWNED_TMP_MARKER}{}", Uuid::new_v4());
    let c_tmp = CString::new(tmp_name.as_bytes())
        .map_err(|_| CliError::data("Invalid temporary file name."))?;
    let raw_tmp = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c_tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw_tmp < 0 {
        return Err(map_io_error(
            std::io::Error::last_os_error(),
            &format!(
                "Failed to create temporary file in '{}'",
                dir_path.display()
            ),
        ));
    }
    let mut tmp_file = unsafe { fs::File::from_raw_fd(raw_tmp) };
    let cleanup_tmp = || unsafe {
        let _ = libc::unlinkat(dir_fd.as_raw_fd(), c_tmp.as_ptr(), 0);
    };

    if let Err(e) = tmp_file.write_all(content) {
        drop(tmp_file);
        cleanup_tmp();
        return Err(map_io_error(
            e,
            &format!(
                "Failed to write temporary file for '{}'",
                target_full.display()
            ),
        ));
    }
    if let Err(e) = check_fault_injection("before_fsync", &target_full) {
        drop(tmp_file);
        cleanup_tmp();
        return Err(e);
    }
    if let Err(e) = tmp_file.sync_all() {
        drop(tmp_file);
        cleanup_tmp();
        return Err(map_io_error(
            e,
            &format!(
                "Failed to fsync temporary file for '{}'",
                target_full.display()
            ),
        ));
    }
    drop(tmp_file);

    if let Err(e) = verify_dir_still_pinned(dir_path, dir_dev, dir_ino) {
        cleanup_tmp();
        return Err(e);
    }

    let mut mid_st: libc::stat = unsafe { std::mem::zeroed() };
    let mid_rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut mid_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let still_same_target = match (mid_rc == 0, pre_existing_id) {
        (true, Some((ed, ei))) => {
            #[allow(clippy::unnecessary_cast)]
            {
                (mid_st.st_mode & libc::S_IFMT) == libc::S_IFREG
                    && (mid_st.st_dev as u64) == ed
                    && (mid_st.st_ino as u64) == ei
            }
        }
        (false, None) => std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        _ => false,
    };
    if !still_same_target {
        cleanup_tmp();
        return Err(CliError::data(format!(
            "Refusing to replace '{}' because target changed concurrently during install.",
            target_full.display()
        )));
    }

    if let Err(e) = check_fault_injection("before_rename", &target_full) {
        cleanup_tmp();
        return Err(e);
    }

    let ren_rc = unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            c_tmp.as_ptr(),
            dir_fd.as_raw_fd(),
            c_leaf.as_ptr(),
        )
    };
    if ren_rc != 0 {
        let err = std::io::Error::last_os_error();
        cleanup_tmp();
        return Err(map_io_error(
            err,
            &format!("Failed to atomically replace '{}'", target_full.display()),
        ));
    }

    check_fault_injection("sync_parent_dir", &target_full)?;
    fsync_pinned_dir_fd(dir_fd, dir_path)?;
    check_fault_injection("after_rename", &target_full)?;

    let raw_rb = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_rb < 0 {
        return Err(map_io_error(
            std::io::Error::last_os_error(),
            &format!("Readback open failed for '{}'", target_full.display()),
        ));
    }
    let mut rb_file = unsafe { fs::File::from_raw_fd(raw_rb) };
    let rb_meta = rb_file.metadata().map_err(|e| {
        map_io_error(
            e,
            &format!("Readback stat failed for '{}'", target_full.display()),
        )
    })?;
    if !rb_meta.file_type().is_file() {
        return Err(CliError::io(
            "readback_not_regular_file",
            format!(
                "Readback target '{}' is not a regular file.",
                target_full.display()
            ),
        ));
    }
    unsafe {
        let fl = libc::fcntl(rb_file.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 && (fl & libc::O_NONBLOCK) != 0 {
            let _ = libc::fcntl(rb_file.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    let mut actual = Vec::with_capacity(content.len());
    rb_file.read_to_end(&mut actual).map_err(|e| {
        map_io_error(
            e,
            &format!("Readback failed for '{}'", target_full.display()),
        )
    })?;
    if actual != content {
        return Err(CliError::io(
            "readback_mismatch",
            format!("Readback mismatch for '{}'.", target_full.display()),
        ));
    }
    Ok((OwnedFd::from(rb_file), rb_meta.dev(), rb_meta.ino()))
}

/// Re-verify after waiting for an external command (`systemctl --user disable --now`) that
/// `dir_path` still resolves without symlinks to the exact pinned `(dir_dev, dir_ino)` AND
/// `leaf_name` inside `dir_fd` is still the exact regular-file `(expected_target_dev, expected_target_ino)`,
/// then unlink via `unlinkat(dir_fd, ...)` and durably `fsync(dir_fd)`.
pub(crate) fn unlink_pinned_regular_target_after_wait(
    dir_fd: &OwnedFd,
    dir_dev: u64,
    dir_ino: u64,
    dir_path: &Path,
    leaf_name: &str,
    expected_target_dev: u64,
    expected_target_ino: u64,
) -> CliResult<bool> {
    verify_dir_still_pinned(dir_path, dir_dev, dir_ino)?;

    let c_leaf = CString::new(leaf_name.as_bytes())
        .map_err(|_| CliError::data("Invalid NUL in target file name."))?;
    let target_full = dir_path.join(leaf_name);

    let mut cur_st: libc::stat = unsafe { std::mem::zeroed() };
    let st_rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            c_leaf.as_ptr(),
            &mut cur_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if st_rc != 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(c) if c == libc::ENOENT => {
                fsync_pinned_dir_fd(dir_fd, dir_path)?;
                Ok(false)
            }
            Some(c) if c == libc::ELOOP || c == libc::ENOTDIR => Err(CliError::data(format!(
                "Refusing to remove non-regular service file '{}' after stop.",
                target_full.display()
            ))),
            _ => Err(map_io_error(
                err,
                &format!("Cannot inspect service unit '{}'", target_full.display()),
            )),
        };
    }
    if (cur_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(CliError::data(format!(
            "Refusing to remove non-regular service file '{}' (symlink or directory).",
            target_full.display()
        )));
    }
    #[allow(clippy::unnecessary_cast)]
    let same_target = (cur_st.st_dev as u64) == expected_target_dev
        && (cur_st.st_ino as u64) == expected_target_ino;
    if !same_target {
        return Err(CliError::data(format!(
            "Refusing to remove service file '{}' because target inode changed concurrently.",
            target_full.display()
        )));
    }

    let u_rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_leaf.as_ptr(), 0) };
    if u_rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(map_io_error(
            err,
            &format!("Failed to remove service unit '{}'", target_full.display()),
        ));
    }

    check_fault_injection("sync_parent_dir", &target_full)?;
    fsync_pinned_dir_fd(dir_fd, dir_path)?;
    Ok(true)
}

/// Returns `true` strictly for temporary filenames owned by `agy-switch-cli`
/// (`<target_prefix>.tmp.agy-switch-cli.<uuid>`).
pub fn is_owned_temp_filename(name: &str, allowed_target_prefix: Option<&str>) -> bool {
    let Some((prefix, uuid_part)) = name.split_once(OWNED_TMP_MARKER) else {
        return false;
    };
    if prefix.is_empty() {
        return false;
    }
    if let Some(expected_prefix) = allowed_target_prefix {
        if prefix != expected_prefix {
            return false;
        }
    }
    Uuid::parse_str(uuid_part).is_ok()
}

/// Full durability preflight for a pinned directory matching the real persistence protocol:
/// create (`O_CREAT | O_EXCL | O_NOFOLLOW`) -> write -> file `sync_all` -> atomic `renameat`
/// -> parent dir `fsync` -> `unlinkat` (error-propagating) -> parent dir `fsync`.
pub(crate) fn verify_dir_writable_and_durable_nofollow(dir: &Path) -> CliResult<()> {
    let Some(dir_fd) = open_existing_dir_nofollow(dir)? else {
        return Err(CliError::io(
            "io_error",
            format!("Store directory '{}' does not exist.", dir.display()),
        ));
    };
    let (dir_dev, dir_ino) = stat_dir_fd(&dir_fd, dir)?;

    let probe_a_name = format!(".write-probe-a{OWNED_TMP_MARKER}{}", Uuid::new_v4());
    let probe_b_name = format!(".write-probe-b{OWNED_TMP_MARKER}{}", Uuid::new_v4());
    let probe_b_path = dir.join(&probe_b_name);
    let c_a = CString::new(probe_a_name.as_bytes())
        .map_err(|_| CliError::data("Invalid write probe filename."))?;
    let c_b = CString::new(probe_b_name.as_bytes())
        .map_err(|_| CliError::data("Invalid write probe filename."))?;

    let raw_a = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c_a.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw_a < 0 {
        return Err(map_io_error(
            std::io::Error::last_os_error(),
            &format!("Store directory '{}' is not writable", dir.display()),
        ));
    }
    let mut file_a = unsafe { fs::File::from_raw_fd(raw_a) };
    let write_res = file_a.write_all(b"ok").and_then(|()| file_a.sync_all());
    drop(file_a);
    if let Err(e) = write_res {
        unsafe {
            let _ = libc::unlinkat(dir_fd.as_raw_fd(), c_a.as_ptr(), 0);
        }
        return Err(map_io_error(
            e,
            &format!(
                "Store directory '{}' failed durability probe",
                dir.display()
            ),
        ));
    }

    verify_dir_still_pinned(dir, dir_dev, dir_ino)?;
    let ren_rc = unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            c_a.as_ptr(),
            dir_fd.as_raw_fd(),
            c_b.as_ptr(),
        )
    };
    if ren_rc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            let _ = libc::unlinkat(dir_fd.as_raw_fd(), c_a.as_ptr(), 0);
        }
        return Err(map_io_error(
            err,
            &format!(
                "Store directory '{}' failed atomic rename probe",
                dir.display()
            ),
        ));
    }

    let sync_after_rename = check_fault_injection("sync_parent_dir", &probe_b_path)
        .and_then(|()| fsync_pinned_dir_fd(&dir_fd, dir));
    let unlink_rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_b.as_ptr(), 0) };
    let unlink_err = (unlink_rc != 0).then(std::io::Error::last_os_error);

    sync_after_rename?;
    if let Some(err) = unlink_err {
        return Err(map_io_error(
            err,
            &format!(
                "Store directory '{}' failed probe cleanup unlink",
                dir.display()
            ),
        ));
    }

    verify_dir_still_pinned(dir, dir_dev, dir_ino)?;
    fsync_pinned_dir_fd(&dir_fd, dir)?;
    Ok(())
}

/// Clean ONLY expired temporary files demonstrably owned by `agy-switch-cli`
/// (`<target_prefix>.tmp.agy-switch-cli.<uuid>`) strictly through an `openat`-pinned directory FD,
/// propagating unlink and parent directory `fsync` errors instead of swallowing them.
/// MUST ONLY be called while holding the corresponding write lock (`ActiveSlotLock` or `StoreWriteLock`).
pub fn cleanup_owned_orphan_temp_files_pinned(
    dir: &Path,
    allowed_target_prefix: Option<&str>,
    max_age: Duration,
) -> CliResult<usize> {
    let Some(dir_fd) = open_existing_dir_nofollow(dir)? else {
        return Ok(0);
    };
    let (dir_dev, dir_ino) = stat_dir_fd(&dir_fd, dir)?;

    let rd_raw = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if rd_raw < 0 {
        return Err(map_io_error(
            std::io::Error::last_os_error(),
            &format!("Cannot open directory '{}' for reading", dir.display()),
        ));
    }
    let dir_ptr = unsafe { libc::fdopendir(rd_raw) };
    if dir_ptr.is_null() {
        let err = std::io::Error::last_os_error();
        unsafe {
            let _ = libc::close(rd_raw);
        }
        return Err(map_io_error(
            err,
            &format!("Cannot iterate directory '{}'", dir.display()),
        ));
    }
    struct DirGuard(*mut libc::DIR);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = libc::closedir(self.0);
            }
        }
    }
    let _dir_guard = DirGuard(dir_ptr);

    let mut owned_names: Vec<CString> = Vec::new();
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let ent = unsafe { libc::readdir(dir_ptr) };
        if ent.is_null() {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error().unwrap_or(0) != 0 {
                return Err(map_io_error(
                    err,
                    &format!("Failed reading directory '{}'", dir.display()),
                ));
            }
            break;
        }
        let raw_name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if raw_name == b"." || raw_name == b".." || !is_single_normal_filename(raw_name) {
            continue;
        }
        let Ok(name_str) = std::str::from_utf8(raw_name) else {
            continue;
        };
        if !is_owned_temp_filename(name_str, allowed_target_prefix) {
            continue;
        }
        if let Ok(cname) = CString::new(raw_name) {
            owned_names.push(cname);
        }
    }
    drop(_dir_guard);

    let now = SystemTime::now();
    let mut removed = 0usize;
    for c_name in owned_names {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                c_name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return Err(map_io_error(
                err,
                &format!("Cannot inspect temporary file in '{}'", dir.display()),
            ));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            continue;
        }
        #[allow(clippy::unnecessary_cast)]
        let mtime_opt = if st.st_mtime >= 0 {
            let nanos = (st.st_mtime_nsec as i64).clamp(0, 999_999_999) as u32;
            UNIX_EPOCH.checked_add(Duration::new(st.st_mtime as u64, nanos))
        } else {
            None
        };
        let is_expired = if max_age.is_zero() {
            true
        } else {
            mtime_opt
                .and_then(|mt| now.duration_since(mt).ok())
                .is_some_and(|age| age >= max_age)
        };
        if !is_expired {
            continue;
        }
        verify_dir_still_pinned(dir, dir_dev, dir_ino)?;
        let unlink_rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), 0) };
        if unlink_rc == 0 {
            removed += 1;
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(map_io_error(
                    err,
                    &format!(
                        "Failed to remove orphan temporary file in '{}'",
                        dir.display()
                    ),
                ));
            }
        }
    }

    if removed > 0 {
        verify_dir_still_pinned(dir, dir_dev, dir_ino)?;
        check_fault_injection("sync_parent_dir", &dir.join(OWNED_TMP_MARKER))?;
        fsync_pinned_dir_fd(&dir_fd, dir)?;
    }

    Ok(removed)
}

/// Best-effort wrapper for internal private store maintenance (still restricted strictly to
/// expired `agy-switch-cli`-owned temporary files via pinned directory FD).
pub fn cleanup_orphan_temp_files(dir: &Path, max_age: Duration) -> usize {
    cleanup_owned_orphan_temp_files_pinned(dir, None, max_age).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_symlink_fifo_and_symlink_parent_without_modifying_or_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let original = tmp.path().join("real.txt");
        fs::write(&original, b"keep-me").unwrap();

        let link = tmp.path().join("link.txt");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        let err = write_atomic_durable(&link, b"overwrite").unwrap_err();
        assert!(err.message.contains("not a regular file"));
        assert_eq!(fs::read(&original).unwrap(), b"keep-me");
        assert!(link.is_symlink());

        let subdir = tmp.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        let err2 = write_atomic_durable(&subdir, b"overwrite").unwrap_err();
        assert!(err2.message.contains("not a regular file"));
        assert!(subdir.is_dir());

        // Symlinked parent directory MUST be rejected on both write and read!
        let real_dir = tmp.path().join("real_dir");
        fs::create_dir(&real_dir).unwrap();
        let symlink_parent = tmp.path().join("symlink_parent");
        std::os::unix::fs::symlink(&real_dir, &symlink_parent).unwrap();
        assert!(write_atomic_durable(&symlink_parent.join("victim.json"), b"{}").is_err());
        assert!(!real_dir.join("victim.json").exists());
        assert!(ensure_private_dir(&symlink_parent.join("nested")).is_err());

        // FIFO MUST be rejected immediately without blocking even with zero writers!
        let fifo_path = tmp.path().join("pipe.json");
        let c_fifo = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        let fifo_read_err =
            read_regular_file_bounded(&fifo_path, MAX_STORE_FILE_BYTES, "Test file").unwrap_err();
        assert!(fifo_read_err.message.contains("regular file"));
        let fifo_write_err = write_atomic_durable(&fifo_path, b"{}").unwrap_err();
        assert!(fifo_write_err.message.contains("not a regular file"));
    }

    #[test]
    fn enforces_0600_permissions_and_leaves_zero_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("secret.json");
        write_atomic_durable(&target, b"{\"v\":1}").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic_durable(&target, b"{\"v\":2}").unwrap();
        let mode2 = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode2, 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"{\"v\":2}");
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
    }
}
