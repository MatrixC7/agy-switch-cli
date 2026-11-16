use crate::domain::account::{RuntimeState, STORE_SCHEMA_VERSION};
use crate::error::{CliError, CliResult};
use crate::paths::HeadlessPaths;
use crate::store::fs_atomic::{
    ensure_no_symlink_components_under, ensure_private_dir, read_regular_file_opt_bounded,
    write_atomic_durable,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_LEASE_BYTES: usize = 64 * 1024;

/// Two-factor managed process lease (`<data_dir>/state/leases/<pid>.json`) per Blueprint §7.1.
/// Binds both `pid` and `/proc/<pid>/stat` field 22 `starttime` (`proc_starttime_ticks`)
/// so OS PID recycling after `SIGKILL` / power loss can NEVER masquerade as an active lease!
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLease {
    pub schema_version: u32,
    pub pid: u32,
    pub proc_starttime_ticks: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_basename: Option<String>,
    pub account_id: String,
    pub started_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcIdentity {
    pub pid: u32,
    pub starttime_ticks: u64,
    pub exe_basename: Option<String>,
    pub exe_path: Option<PathBuf>,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedProcStat {
    Alive {
        pid: u32,
        comm: String,
        starttime_ticks: u64,
    },
    TerminatedZombieOrDead,
    Malformed,
}

fn parse_proc_stat_detailed(stat_content: &str) -> ParsedProcStat {
    let trimmed = stat_content.trim();
    let Some(open_paren) = trimmed.find('(') else {
        return ParsedProcStat::Malformed;
    };
    let Ok(pid) = trimmed[..open_paren].trim().parse::<u32>() else {
        return ParsedProcStat::Malformed;
    };
    let Some(close_paren) = trimmed.rfind(')') else {
        return ParsedProcStat::Malformed;
    };
    if close_paren <= open_paren {
        return ParsedProcStat::Malformed;
    }
    let comm = trimmed[open_paren + 1..close_paren].trim().to_string();
    let after_comm = &trimmed[close_paren + 1..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let Some(state_char) = fields.first().and_then(|s| s.chars().next()) else {
        return ParsedProcStat::Malformed;
    };
    if matches!(state_char, 'Z' | 'X' | 'x') {
        return ParsedProcStat::TerminatedZombieOrDead;
    }
    let Some(starttime_ticks) = fields.get(19).and_then(|s| s.parse::<u64>().ok()) else {
        return ParsedProcStat::Malformed;
    };
    ParsedProcStat::Alive {
        pid,
        comm,
        starttime_ticks,
    }
}

/// Parse `/proc/<pid>/stat` safely by slicing AFTER the last `')'` first, defending against
/// executable names containing spaces, parentheses, or newlines!
/// Zombie (`Z`) and dead (`X`/`x`) processes are treated as terminated (`None`).
pub fn parse_proc_stat_starttime(stat_content: &str) -> Option<(u32, u64)> {
    match parse_proc_stat_detailed(stat_content) {
        ParsedProcStat::Alive {
            pid,
            starttime_ticks,
            ..
        } => Some((pid, starttime_ticks)),
        ParsedProcStat::TerminatedZombieOrDead | ParsedProcStat::Malformed => None,
    }
}

pub fn proc_root() -> PathBuf {
    std::env::var_os("AGY_SWITCH_CLI_PROC_ROOT")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/proc"))
}

fn is_proc_vanished_io(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
        || err.raw_os_error() == Some(libc::ESRCH)
        || err.raw_os_error() == Some(libc::ENOENT)
}

#[derive(Debug)]
enum StrictProcOutcome {
    Alive(ProcIdentity),
    VanishedOrZombie,
    Unverified(String),
}

fn inspect_proc_pid_strict(proc_dir: &Path, pid: u32) -> StrictProcOutcome {
    let entry_dir = proc_dir.join(pid.to_string());
    let meta = match fs::metadata(&entry_dir) {
        Ok(m) => m,
        Err(e) if is_proc_vanished_io(&e) => return StrictProcOutcome::VanishedOrZombie,
        Err(e) => {
            return StrictProcOutcome::Unverified(format!(
                "Cannot inspect process entry '{}': {e}",
                entry_dir.display()
            ))
        }
    };

    let stat_text = match fs::read_to_string(entry_dir.join("stat")) {
        Ok(s) => s,
        Err(e) if is_proc_vanished_io(&e) => return StrictProcOutcome::VanishedOrZombie,
        Err(e) => {
            return StrictProcOutcome::Unverified(format!(
                "Cannot read '{}' for process {pid}: {e}",
                entry_dir.join("stat").display()
            ))
        }
    };

    let (parsed_pid, stat_comm, starttime_ticks) = match parse_proc_stat_detailed(&stat_text) {
        ParsedProcStat::Alive {
            pid: p,
            comm,
            starttime_ticks: st,
        } => (p, comm, st),
        ParsedProcStat::TerminatedZombieOrDead => return StrictProcOutcome::VanishedOrZombie,
        ParsedProcStat::Malformed => {
            return StrictProcOutcome::Unverified(format!(
                "Malformed proc stat record for process {pid}."
            ))
        }
    };
    if parsed_pid != pid {
        return StrictProcOutcome::Unverified(format!(
            "Process {pid} stat PID mismatch ({parsed_pid})."
        ));
    }

    let exe_path = match fs::read_link(entry_dir.join("exe")) {
        Ok(p) => Some(p),
        Err(e) if is_proc_vanished_io(&e) => None,
        Err(_) => None,
    };

    let comm_file = match fs::read_to_string(entry_dir.join("comm")) {
        Ok(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Err(e) if is_proc_vanished_io(&e) => None,
        Err(e) => {
            if exe_path.is_none() && stat_comm.is_empty() {
                return StrictProcOutcome::Unverified(format!(
                    "Cannot determine executable name for process {pid}: {e}"
                ));
            }
            None
        }
    };

    let exe_basename = exe_path
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.strip_suffix(" (deleted)").unwrap_or(s).to_string())
        .or(comm_file)
        .or_else(|| (!stat_comm.is_empty()).then_some(stat_comm));

    StrictProcOutcome::Alive(ProcIdentity {
        pid,
        starttime_ticks,
        exe_basename,
        exe_path,
        uid: meta.uid(),
    })
}

pub fn inspect_proc_pid(proc_dir: &Path, pid: u32) -> Option<ProcIdentity> {
    match inspect_proc_pid_strict(proc_dir, pid) {
        StrictProcOutcome::Alive(info) => Some(info),
        StrictProcOutcome::VanishedOrZombie | StrictProcOutcome::Unverified(_) => None,
    }
}

pub fn write_process_lease(
    paths: &HeadlessPaths,
    pid: u32,
    account_id: &str,
    now_unix: i64,
) -> CliResult<ProcessLease> {
    let proc_dir = proc_root();
    let proc_info = inspect_proc_pid(&proc_dir, pid).ok_or_else(|| {
        CliError::io(
            "lease_proc_missing",
            format!("Child process {pid} disappeared before lease registration."),
        )
    })?;
    let lease = ProcessLease {
        schema_version: STORE_SCHEMA_VERSION,
        pid,
        proc_starttime_ticks: proc_info.starttime_ticks,
        exe_basename: proc_info.exe_basename,
        account_id: account_id.to_string(),
        started_at: now_unix,
    };
    ensure_no_symlink_components_under(&paths.data_dir, &paths.leases_dir())?;
    ensure_private_dir(&paths.leases_dir())?;
    let lease_path = paths.leases_dir().join(format!("{pid}.json"));
    ensure_no_symlink_components_under(&paths.data_dir, &lease_path)?;
    let bytes = serde_json::to_vec_pretty(&lease)
        .map_err(|_| CliError::data("Failed to serialize process lease."))?;
    write_atomic_durable(&lease_path, &bytes)?;
    Ok(lease)
}

pub fn remove_process_lease(paths: &HeadlessPaths, pid: u32) {
    let lease_path = paths.leases_dir().join(format!("{pid}.json"));
    if ensure_no_symlink_components_under(&paths.data_dir, &lease_path).is_ok() {
        let _ = fs::remove_file(lease_path);
    }
}

/// Sweep stale dead leases ONLY when caller holds `StoreWriteLock`.
/// Read-only commands (`status`) NEVER call this function; only removes leases confirmed dead/recycled
/// (never deletes leases when `/proc` is unreadable!).
pub fn cleanup_stale_leases_under_write_lock(paths: &HeadlessPaths) {
    let proc_dir = proc_root();
    if fs::read_dir(&proc_dir).is_err() {
        return;
    }
    let Ok(entries) = fs::read_dir(paths.leases_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(Some(bytes)) =
            read_regular_file_opt_bounded(&path, MAX_LEASE_BYTES, "Process lease")
        else {
            continue;
        };
        let Ok(lease) = serde_json::from_slice::<ProcessLease>(&bytes) else {
            let _ = fs::remove_file(path);
            continue;
        };
        match inspect_proc_pid_strict(&proc_dir, lease.pid) {
            StrictProcOutcome::Alive(live)
                if live.starttime_ticks == lease.proc_starttime_ticks => {}
            StrictProcOutcome::Alive(_) | StrictProcOutcome::VanishedOrZombie => {
                let _ = fs::remove_file(path);
            }
            StrictProcOutcome::Unverified(_) => {}
        }
    }
}

pub fn is_lease_alive(proc_dir: &Path, lease: &ProcessLease) -> bool {
    inspect_proc_pid(proc_dir, lease.pid)
        .is_some_and(|live| live.starttime_ticks == lease.proc_starttime_ticks)
}

/// Fail-closed read-only runtime process observation (`Idle`, `ManagedRunning`, `UnmanagedRunning`, `Unverified`) per Blueprint §2.2 & §7.1.
/// Any inability to enumerate `proc_dir`, inspect `leases_dir`, or read a live same-UID candidate returns `RuntimeState::Unverified`
/// (NEVER silently falling back to `Idle`)!
pub fn observe_runtime_state(paths: &HeadlessPaths) -> RuntimeState {
    let proc_dir = proc_root();
    match fs::metadata(&proc_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return RuntimeState::Unverified {
                detail: format!("Process table '{}' is not a directory.", proc_dir.display()),
            };
        }
        Err(e) => {
            return RuntimeState::Unverified {
                detail: format!("Process table '{}' is unavailable: {e}", proc_dir.display()),
            };
        }
    }

    // Fail-closed: verify `proc_dir` is genuinely readable BEFORE trusting lease/process absence!
    let proc_entries = match fs::read_dir(&proc_dir) {
        Ok(it) => it,
        Err(e) => {
            return RuntimeState::Unverified {
                detail: format!(
                    "Cannot enumerate process table '{}' ({e}).",
                    proc_dir.display()
                ),
            };
        }
    };

    // 1. Read active two-factor managed leases (fail-closed on unreadable/corrupt lease store)
    let mut managed_by_pid: HashMap<u32, String> = HashMap::new();
    if let Err(e) = ensure_no_symlink_components_under(&paths.data_dir, &paths.leases_dir()) {
        return RuntimeState::Unverified { detail: e.message };
    }
    match fs::read_dir(paths.leases_dir()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return RuntimeState::Unverified {
                detail: format!(
                    "Cannot read managed leases directory '{}': {e}",
                    paths.leases_dir().display()
                ),
            };
        }
        Ok(entries) => {
            for entry_res in entries {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(e) => {
                        return RuntimeState::Unverified {
                            detail: format!("Error reading leases directory entry: {e}"),
                        };
                    }
                };
                let path = entry.path();
                let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !fname.ends_with(".json") || fname.contains(".tmp.") {
                    continue;
                }
                let bytes =
                    match read_regular_file_opt_bounded(&path, MAX_LEASE_BYTES, "Process lease") {
                        Ok(Some(b)) => b,
                        Ok(None) => continue,
                        Err(e) => {
                            return RuntimeState::Unverified { detail: e.message };
                        }
                    };
                let lease: ProcessLease = match serde_json::from_slice::<ProcessLease>(&bytes) {
                    Ok(l) if l.schema_version == STORE_SCHEMA_VERSION => l,
                    _ => {
                        return RuntimeState::Unverified {
                            detail: format!("Corrupt process lease file '{}'.", path.display()),
                        };
                    }
                };
                match inspect_proc_pid_strict(&proc_dir, lease.pid) {
                    StrictProcOutcome::Alive(live) => {
                        if live.starttime_ticks == lease.proc_starttime_ticks {
                            managed_by_pid.insert(lease.pid, lease.account_id);
                        }
                    }
                    StrictProcOutcome::VanishedOrZombie => {}
                    StrictProcOutcome::Unverified(detail) => {
                        return RuntimeState::Unverified { detail };
                    }
                }
            }
        }
    }

    // 2. Conservative fail-closed same-UID scan for official `agy` processes
    let own_pid = std::process::id();
    let current_uid = unsafe { libc::geteuid() };
    let explicit_agy_bin = std::env::var_os("AGY_SWITCH_CLI_AGY_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let canonical_agy_bin = explicit_agy_bin
        .as_ref()
        .and_then(|p| fs::canonicalize(p).ok().or_else(|| Some(p.clone())));
    let target_bin_basename = canonical_agy_bin
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("agy");

    let mut unmanaged_pids: BTreeSet<u32> = BTreeSet::new();

    for entry_res in proc_entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(e) => {
                return RuntimeState::Unverified {
                    detail: format!("Process table iteration failed: {e}"),
                };
            }
        };
        let Some(name_str) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        if pid == own_pid || managed_by_pid.contains_key(&pid) {
            continue;
        }

        // Check process ownership via `/proc/<pid>` stat BEFORE reading `/proc/<pid>/stat`
        let pid_dir = proc_dir.join(&name_str);
        let pid_meta = match fs::metadata(&pid_dir) {
            Ok(m) => m,
            Err(e) if is_proc_vanished_io(&e) => continue,
            Err(e) => {
                return RuntimeState::Unverified {
                    detail: format!("Cannot stat process directory '{}': {e}", pid_dir.display()),
                };
            }
        };
        if pid_meta.uid() != current_uid {
            continue;
        }

        let info = match inspect_proc_pid_strict(&proc_dir, pid) {
            StrictProcOutcome::Alive(i) => i,
            StrictProcOutcome::VanishedOrZombie => continue,
            StrictProcOutcome::Unverified(detail) => {
                return RuntimeState::Unverified { detail };
            }
        };

        let matches_agy = if let Some(ref target_bin) = canonical_agy_bin {
            if let Some(ref exe_p) = info.exe_path {
                let clean_exe = exe_p
                    .to_str()
                    .and_then(|s| s.strip_suffix(" (deleted)"))
                    .map(PathBuf::from)
                    .unwrap_or_else(|| exe_p.clone());
                let norm = fs::canonicalize(&clean_exe).unwrap_or(clean_exe);
                &norm == target_bin
            } else if info.exe_basename.as_deref().is_some_and(|b| {
                b == "agy"
                    || b == target_bin_basename
                    || (b.len() >= 15 && target_bin_basename.starts_with(b))
            }) {
                return RuntimeState::Unverified {
                    detail: format!(
                        "Cannot verify executable symlink for same-UID candidate process {pid}."
                    ),
                };
            } else {
                false
            }
        } else {
            match info.exe_basename.as_deref() {
                Some(base) => base == "agy",
                None => {
                    return RuntimeState::Unverified {
                        detail: format!(
                            "Cannot verify executable basename for same-UID process {pid}."
                        ),
                    };
                }
            }
        };
        if matches_agy {
            unmanaged_pids.insert(pid);
        }
    }

    if !unmanaged_pids.is_empty() {
        let mut managed_accounts: Vec<String> = managed_by_pid.into_values().collect();
        managed_accounts.sort();
        managed_accounts.dedup();
        return RuntimeState::UnmanagedRunning {
            pids: unmanaged_pids.into_iter().collect(),
            identity: "unknown".into(),
            managed_account_ids: managed_accounts,
        };
    }

    if !managed_by_pid.is_empty() {
        let mut pids: Vec<u32> = managed_by_pid.keys().copied().collect();
        pids.sort_unstable();
        let mut account_ids: Vec<String> = managed_by_pid.into_values().collect();
        account_ids.sort();
        account_ids.dedup();
        return RuntimeState::ManagedRunning {
            count: pids.len(),
            account_ids,
            pids,
        };
    }

    RuntimeState::Idle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_stat_starttime_even_with_evil_comm_names() {
        // Standard comm
        let stat1 = "12345 (agy) S 1000 12345 12345 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 4 0 987654321 1234567 100";
        assert_eq!(parse_proc_stat_starttime(stat1), Some((12345, 987654321)));

        // Evil comm containing spaces and nested closing parentheses `)`!
        let stat_evil = "4242 (weird ) name (agy) v2) R 1 4242 4242 0 -1 0 0 0 0 0 1 2 3 4 20 0 1 0 555666777 99999 10";
        assert_eq!(
            parse_proc_stat_starttime(stat_evil),
            Some((4242, 555666777))
        );

        // Zombie (`Z`) and dead (`X`) processes MUST be rejected as terminated!
        let stat_zombie = "5001 (agy) Z 1 5001 5001 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555666777 0 0";
        assert_eq!(parse_proc_stat_starttime(stat_zombie), None);
        let stat_dead = "5002 (agy) X 1 5002 5002 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555666777 0 0";
        assert_eq!(parse_proc_stat_starttime(stat_dead), None);
    }

    #[test]
    fn stale_lease_with_recycled_pid_and_different_starttime_is_ignored_without_deleting_in_readonly(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let fake_proc = tmp.path().join("proc");
        fs::create_dir_all(fake_proc.join("777")).unwrap();
        // Recycled PID 777 now has starttime 999999 instead of 111111!
        fs::write(
            fake_proc.join("777/stat"),
            "777 (bash) S 1 777 777 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 999999 1000 10",
        )
        .unwrap();

        let paths = HeadlessPaths::with_explicit(
            tmp.path().join("home"),
            tmp.path().join("data"),
            tmp.path().join("cache"),
        );
        ensure_private_dir(&paths.leases_dir()).unwrap();
        let stale = ProcessLease {
            schema_version: 1,
            pid: 777,
            proc_starttime_ticks: 111111,
            exe_basename: Some("agy".into()),
            account_id: "acc-1".into(),
            started_at: 100,
        };
        let lease_file = paths.leases_dir().join("777.json");
        fs::write(&lease_file, serde_json::to_vec(&stale).unwrap()).unwrap();

        assert!(!is_lease_alive(&fake_proc, &stale));
        // Matching starttime IS alive
        let live_lease = ProcessLease {
            proc_starttime_ticks: 999999,
            ..stale
        };
        assert!(is_lease_alive(&fake_proc, &live_lease));
        assert!(lease_file.exists());
    }
}
