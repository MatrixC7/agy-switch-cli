use crate::error::{CliError, CliResult};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

pub const MAX_STORE_FILE_BYTES: usize = 8 * 1024 * 1024;

/// Verify every existing ancestor component of `dir_path` from `/` (or `.` for relative paths) downward
/// is a real directory (`!is_symlink() && is_dir()`), and open the final directory handle with
/// `O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`:
/// - Deterministically rejects ANY symlink or non-directory component at ANY depth in the ancestor chain;
/// - Uses prefix `symlink_metadata` (`lstat`) rather than `open("/")` + relative `openat` from `/` so user-mode
///   QEMU `-L <sysroot>` emulation never redirects `"/"` to `/usr/aarch64-linux-gnu`;
/// - Returns `Ok(Some(dir_fd))` when `dir_path` exists and every component is a real directory;
/// - Returns `Ok(None)` when a component does not exist yet (`NotFound`), AFTER proving all existing higher ancestors are real directories.
fn open_existing_dir_nofollow(dir_path: &Path) -> CliResult<Option<OwnedFd>> {
    let effective = if dir_path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir_path
    };

    let mut walked = PathBuf::new();
    for comp in effective.components() {
        match comp {
            Component::RootDir => {
                walked.push("/");
                continue;
            }
            Component::CurDir => {
                if walked.as_os_str().is_empty() {
                    walked.push(".");
                }
                continue;
            }
            Component::ParentDir => {
                walked.push("..");
            }
            Component::Normal(part) => {
                walked.push(part);
            }
            Component::Prefix(p) => {
                walked.push(p.as_os_str());
                continue;
            }
        }

        match fs::symlink_metadata(&walked) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                    return Err(CliError::data(format!(
                        "Directory path '{}' must be a real directory, not a symlink or file.",
                        walked.display()
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(map_io_error(
                    e,
                    &format!("Cannot inspect directory component '{}'", walked.display()),
                ));
            }
        }
    }

    let c_dir = CString::new(effective.as_os_str().as_bytes()).map_err(|_| {
        CliError::data(format!(
            "Path '{}' contains an invalid NUL byte.",
            effective.display()
        ))
    })?;
    let raw_fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code == libc::ENOENT => Ok(None),
            Some(code) if code == libc::ENOTDIR || code == libc::ELOOP => {
                Err(CliError::data(format!(
                    "Directory path '{}' must be a real directory, not a symlink or file.",
                    effective.display()
                )))
            }
            _ => Err(map_io_error(
                err,
                &format!("Cannot open directory '{}'", effective.display()),
            )),
        };
    }

    let dir_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir_fd.as_raw_fd(), &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(map_io_error(
            err,
            &format!("Cannot stat directory '{}'", effective.display()),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(CliError::data(format!(
            "Directory path '{}' must be a real directory, not a symlink or file.",
            effective.display()
        )));
    }

    Ok(Some(dir_fd))
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

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(CliError::data(format!(
                "{label} '{}' must be a regular file, not a symlink.",
                path.display()
            )));
        }
        Err(e)
            if e.raw_os_error() == Some(libc::ENXIO) || e.raw_os_error() == Some(libc::EISDIR) =>
        {
            return Err(CliError::data(format!(
                "{label} '{}' must be a regular file, not a special file or directory.",
                path.display()
            )));
        }
        Err(e) => {
            return Err(map_io_error(
                e,
                &format!("Cannot open {label} '{}'", path.display()),
            ));
        }
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
    let temp_path: PathBuf = parent_dir.join(format!("{file_name}.tmp.{}", Uuid::new_v4()));

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

/// Clean orphan `*.tmp.*` files older than `max_age` (use `Duration::ZERO` under exclusive `doctor --fix` L1/L3 lock).
/// MUST ONLY be called while holding the corresponding write lock (`ActiveSlotLock` or `StoreWriteLock`).
pub fn cleanup_orphan_temp_files(dir: &Path, max_age: Duration) -> usize {
    if ensure_no_symlink_ancestors(dir).is_err() || check_not_symlink_dir_if_exists(dir).is_err() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };
        if !name_str.contains(".tmp.") {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let is_old = max_age.is_zero()
            || meta
                .modified()
                .ok()
                .and_then(|mtime| now.duration_since(mtime).ok())
                .is_some_and(|age| age >= max_age);
        if is_old && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        if let Ok(dir_file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir)
        {
            let _ = dir_file.sync_all();
        }
    }
    removed
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
