mod common;

use common::IsolatedEnv;
#[cfg(feature = "stats")]
use std::fs;
#[cfg(feature = "stats")]
use std::os::unix::fs::PermissionsExt;
#[cfg(feature = "stats")]
use std::process::Stdio;

#[test]
fn synthetic_stats_cli_contract_covering_sources_dates_json_fifo_symlink_and_readonly() {
    let env = IsolatedEnv::new();

    // 1. Bare `stats` (no subcommand), mutually exclusive window flags, `--to` without `--from`, & invalid `<N>d` / `--recent` bounds MUST fail with exit code 2 across all feature tiers
    for bad_args in [
        vec!["stats"],
        vec![
            "stats",
            "summary",
            "--range",
            "today",
            "--date",
            "2026-11-17",
        ],
        vec!["stats", "summary", "--range", "7d", "--from", "2026-11-01"],
        vec![
            "stats",
            "summary",
            "--date",
            "2026-11-17",
            "--from",
            "2026-11-01",
        ],
        vec!["stats", "summary", "--range", "today", "--recent", "10"],
        vec!["stats", "list", "--date", "2026-11-17", "--recent", "10"],
        vec!["stats", "summary", "--to", "2026-11-17"],
        vec!["stats", "summary", "--range", "0d"],
        vec!["stats", "summary", "--range", "03d"],
        vec!["stats", "summary", "--range", "36501d"],
        vec!["stats", "list", "--recent", "0"],
        vec!["stats", "list", "--recent", "501"],
    ] {
        let out = env.cli_cmd().args(&bad_args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "Expected exit code 2 for {bad_args:?}"
        );
    }

    #[cfg(not(feature = "stats"))]
    {
        for sub in ["summary", "list"] {
            let out = env
                .cli_cmd()
                .args(["--json", "stats", sub])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2));
            let err_json: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
            assert_eq!(err_json["ok"], false);
            assert_eq!(err_json["exit_code"], 2);
            assert!(!env.data_dir.exists(), "`stats` must never create data_dir");
        }
    }

    #[cfg(feature = "stats")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let vi = |mut v: u64| -> Vec<u8> {
            let mut b = Vec::new();
            loop {
                let n = (v & 0x7f) as u8;
                v >>= 7;
                b.push(if v == 0 { n } else { n | 0x80 });
                if v == 0 {
                    return b;
                }
            }
        };
        let pb_v = |num: u32, v: u64| -> Vec<u8> { [vi(u64::from(num << 3)), vi(v)].concat() };
        let pb_b = |num: u32, v: &[u8]| -> Vec<u8> {
            [vi(u64::from(num << 3 | 2)), vi(v.len() as u64), v.to_vec()].concat()
        };

        // Empty fresh sandbox (`~/.gemini` absent): pure read-only, exit 0, zero files created
        let empty_out = env
            .cli_cmd()
            .args(["--json", "stats", "summary"])
            .output()
            .unwrap();
        assert_eq!(empty_out.status.code(), Some(0));
        assert!(
            !env.data_dir.exists() && !env.home.join(".gemini").exists(),
            "Read-only `stats` must NEVER create `data_dir` or `~/.gemini`"
        );
        let empty_json: serde_json::Value = serde_json::from_slice(&empty_out.stdout).unwrap();
        assert_eq!(empty_json["schema_version"], 1);
        assert_eq!(empty_json["ok"], true);
        assert_eq!(empty_json["source"], "all");
        assert_eq!(empty_json["databases_scanned"], 0);
        assert_eq!(empty_json["summary"]["request_count"], 0);
        assert!(empty_json["summary"]["cache_hit_ratio"].is_null());
        assert!(empty_json["performance"].is_null());

        // Empty fresh sandbox with `--range all` (JSON + human)
        let empty_all_out = env
            .cli_cmd()
            .args(["--json", "stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(empty_all_out.status.code(), Some(0));
        let empty_all_json: serde_json::Value =
            serde_json::from_slice(&empty_all_out.stdout).unwrap();
        assert_eq!(empty_all_json["range"]["kind"], "preset");
        assert_eq!(empty_all_json["range"]["preset"], "all");
        assert!(empty_all_json["range"]["from"].is_null());
        assert!(empty_all_json["range"]["to"].is_null());

        let empty_all_human = env
            .cli_cmd()
            .args(["stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(empty_all_human.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&empty_all_human.stdout).contains("\nRange  : all\n"));

        // Populate synthetic SQLite databases under isolated `$HOME/.gemini`
        let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
        let app_conv = env.home.join(".gemini/antigravity/conversations");
        fs::create_dir_all(&cli_conv).unwrap();
        fs::create_dir_all(&app_conv).unwrap();

        // Fixed UTC date `2026-11-15T10:00:00Z` via `TZ=UTC0` on child command
        let ts_nov15 = "2026-11-15T10:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;
        let ts_nov10 = "2026-11-10T08:30:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second() as u64;

        let cli_db = cli_conv.join("session_a.db");
        let conn = rusqlite::Connection::open(&cli_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();

        let step_done_text = pb_b(
            20,
            &[pb_b(1, b"synthetic completed text"), pb_v(12, 2)].concat(),
        );

        let make_blob = |sys_in: u64,
                         usr_in: u64,
                         out_t: u64,
                         cache_t: u64,
                         ts: u64,
                         model_id: &str,
                         label: &str|
         -> Vec<u8> {
            let usage = [
                pb_v(1, sys_in),
                pb_v(2, usr_in),
                pb_v(3, out_t),
                pb_v(5, cache_t),
                pb_v(10, out_t),
            ]
            .concat();
            let timing = pb_b(4, &pb_v(1, ts));
            let ttft_dur = [pb_v(1, 2), pb_v(2, 500_000_000)].concat(); // 2.5s
            let stream_dur = pb_v(1, 10); // 10.0s
            let wrapped = [
                pb_b(4, &usage),
                pb_b(9, &timing),
                pb_b(11, &ttft_dur),
                pb_b(12, &stream_dur),
                pb_b(19, model_id.as_bytes()),
                pb_b(21, label.as_bytes()),
            ]
            .concat();
            pb_b(1, &wrapped)
        };

        conn.execute(
            "INSERT INTO steps VALUES (1, 15, ?1, 3, ?2)",
            rusqlite::params![pb_b(1, &pb_v(1, ts_nov15)), &step_done_text],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![make_blob(
                1_000,
                9_000,
                500,
                40_000,
                ts_nov15,
                "gemini-4-carbon",
                "Gemini 4 Carbon (High)"
            )],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO steps VALUES (2, 15, ?1, 3, ?2)",
            rusqlite::params![pb_b(1, &pb_v(1, ts_nov10)), &step_done_text],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (2, ?1)",
            rusqlite::params![make_blob(
                500,
                1_500,
                200,
                8_000,
                ts_nov10,
                "gemini-4-hydrogen-xhigh",
                "Gemini 4 Hydrogen (XHigh)"
            )],
        )
        .unwrap();
        drop(conn);

        // Adversarial FIFO `.db` AND regular `.db` with FIFO `-wal` companion: MUST NOT hang!
        let fifo_db = cli_conv.join("trap_fifo.db");
        let c_fifo_db = CString::new(fifo_db.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo_db.as_ptr(), 0o600) }, 0);

        let wal_trap_db = cli_conv.join("wal_trap.db");
        let wconn = rusqlite::Connection::open(&wal_trap_db).unwrap();
        wconn
            .execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
            .unwrap();
        drop(wconn);
        let wal_fifo = cli_conv.join("wal_trap.db-wal");
        let c_wal_fifo = CString::new(wal_fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_wal_fifo.as_ptr(), 0o600) }, 0);

        // App DB on `2026-11-15`
        let app_db = app_conv.join("app_session.db");
        let aconn = rusqlite::Connection::open(&app_db).unwrap();
        aconn
            .execute_batch(
                "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        aconn
            .execute(
                "INSERT INTO steps VALUES (1, 15, ?1, 3, NULL)",
                rusqlite::params![pb_b(1, &pb_v(1, ts_nov15 + 60))],
            )
            .unwrap();
        aconn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(
                    2_000,
                    3_000,
                    600,
                    15_000,
                    ts_nov15 + 60,
                    "claude-opus-4-6",
                    "Claude Opus 4.6"
                )],
            )
            .unwrap();
        drop(aconn);

        // Query default `stats summary --date 2026-11-15` (defaults to `--source all`: scans both CLI + App!)
        let default_d_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["stats", "summary", "--date", "2026-11-15"])
            .output()
            .unwrap();
        assert_eq!(default_d_out.status.code(), Some(0));
        let default_d_txt = String::from_utf8_lossy(&default_d_out.stdout);
        assert!(
            default_d_txt.contains(
                "Source : all (~/.gemini/antigravity-cli + ~/.gemini/antigravity) · 2 db(s) · latest 2026-11-15 10:01"
            ),
            "{default_d_txt}"
        );
        assert!(
            default_d_txt.contains("Gemini 4 Carbon (High)"),
            "{default_d_txt}"
        );
        assert!(default_d_txt.contains("Claude Opus 4.6"), "{default_d_txt}");

        // Query explicit `--source cli --date 2026-11-15`
        let d_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args([
                "stats",
                "summary",
                "--source",
                "cli",
                "--date",
                "2026-11-15",
            ])
            .output()
            .unwrap();
        assert_eq!(d_out.status.code(), Some(0));
        let d_txt = String::from_utf8_lossy(&d_out.stdout);
        assert!(
            d_txt.contains(
                "Source : cli (~/.gemini/antigravity-cli) · 1 db(s) · latest 2026-11-15 10:00"
            ),
            "{d_txt}"
        );
        assert!(d_txt.contains("Range  : 2026-11-15"), "{d_txt}");
        assert!(
            d_txt.contains("Total input        : 50.0K (50,000)"),
            "{d_txt}"
        );
        assert!(d_txt.contains("Cache hit          : 80.0%"), "{d_txt}");
        assert!(
            d_txt.contains("TTFT (P10/P50/P90) : 2.5 / 2.5 / 2.5 s"),
            "{d_txt}"
        );
        assert!(
            d_txt.contains("TPS (P10/P50/P90) : 50.0 / 50.0 / 50.0 t/s"),
            "{d_txt}"
        );
        assert!(!d_txt.contains("Duration"), "{d_txt}");
        assert!(!d_txt.contains("In TPS"), "{d_txt}");
        assert!(d_txt.contains("Gemini 4 Carbon (High)"), "{d_txt}");
        assert!(!d_txt.contains("Gemini 4 Hydrogen"), "{d_txt}");

        // Query `--source all --from 2026-11-10 --to 2026-11-15 --json`
        let all_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args([
                "--json",
                "stats",
                "summary",
                "--source",
                "all",
                "--from",
                "2026-11-10",
                "--to",
                "2026-11-15",
            ])
            .output()
            .unwrap();
        assert_eq!(all_out.status.code(), Some(0));
        let all_json: serde_json::Value = serde_json::from_slice(&all_out.stdout).unwrap();
        assert_eq!(all_json["source"], "all");
        assert_eq!(all_json["databases_scanned"], 2);
        assert_eq!(all_json["summary"]["request_count"], 3);
        assert_eq!(all_json["summary"]["uncached_input_tokens"], 17_000);
        assert_eq!(all_json["summary"]["cached_input_tokens"], 63_000);
        assert_eq!(all_json["summary"]["total_input_tokens"], 80_000);
        assert_eq!(all_json["summary"]["total_output_tokens"], 1_300);
        assert_eq!(all_json["performance"]["sample_count"], 3);
        assert_eq!(all_json["performance"]["model_count"], 3);
        assert_eq!(all_json["performance"]["source_count"], 2);
        assert_eq!(all_json["performance"]["ttft_seconds"]["p50"], 2.5);
        assert_eq!(all_json["performance"]["output_tps"]["p10"], 26.0);
        assert_eq!(all_json["performance"]["output_tps"]["p50"], 50.0);
        assert_eq!(all_json["performance"]["output_tps"]["p90"], 58.0);

        // Inverted `--from > --to` and secret `--date` redaction
        let inv_out = env
            .cli_cmd()
            .args([
                "--json",
                "stats",
                "summary",
                "--from",
                "2026-11-16",
                "--to",
                "2026-11-15",
            ])
            .output()
            .unwrap();
        assert_eq!(inv_out.status.code(), Some(2));

        let sec_out = env
            .cli_cmd()
            .args([
                "--json",
                "stats",
                "summary",
                "--date",
                "1//0gSECRET_DATE_LEAK_12345",
            ])
            .output()
            .unwrap();
        assert_eq!(sec_out.status.code(), Some(2));
        let sec_err = String::from_utf8_lossy(&sec_out.stderr);
        assert!(!sec_err.contains("SECRET_DATE_LEAK_12345"), "{sec_err}");

        // Arbitrary `<N>d` preset (`--range 14d` & `--range 1d`) and `--range` secret redaction
        let nd_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--range", "14d"])
            .output()
            .unwrap();
        assert_eq!(nd_out.status.code(), Some(0));
        let nd_json: serde_json::Value = serde_json::from_slice(&nd_out.stdout).unwrap();
        assert_eq!(nd_json["range"]["kind"], "preset");
        assert_eq!(nd_json["range"]["preset"], "14d");

        let d1_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--range", "1d"])
            .output()
            .unwrap();
        assert_eq!(d1_out.status.code(), Some(0));
        let d1_json: serde_json::Value = serde_json::from_slice(&d1_out.stdout).unwrap();
        assert_eq!(d1_json["range"]["preset"], "1d");
        assert_eq!(d1_json["range"]["from"], d1_json["range"]["to"]);

        // `--range all` across historical DBs (`2026-11-10 .. 2026-11-15` observed span)
        let r_all_json_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(r_all_json_out.status.code(), Some(0));
        let r_all_j: serde_json::Value = serde_json::from_slice(&r_all_json_out.stdout).unwrap();
        assert_eq!(r_all_j["range"]["kind"], "preset");
        assert_eq!(r_all_j["range"]["preset"], "all");
        assert_eq!(r_all_j["range"]["from"], "2026-11-10");
        assert_eq!(r_all_j["range"]["to"], "2026-11-15");
        assert_eq!(r_all_j["summary"]["request_count"], 3);
        assert_eq!(r_all_j["performance"]["sample_count"], 3);

        let r_all_human_out = env
            .cli_cmd()
            .env("TZ", "UTC0")
            .args(["stats", "summary", "--range", "all"])
            .output()
            .unwrap();
        assert_eq!(r_all_human_out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&r_all_human_out.stdout)
            .contains("Range  : all (2026-11-10 .. 2026-11-15)"));

        let rng_sec_out = env
            .cli_cmd()
            .args([
                "--json",
                "stats",
                "summary",
                "--range",
                "1//0gSECRET_RANGE_LEAK_54321",
            ])
            .output()
            .unwrap();
        assert_eq!(rng_sec_out.status.code(), Some(2));
        let rng_sec_err = String::from_utf8_lossy(&rng_sec_out.stderr);
        assert!(
            !rng_sec_err.contains("SECRET_RANGE_LEAK_54321"),
            "{rng_sec_err}"
        );
        assert!(!env.data_dir.exists(), "`stats` must remain 100% read-only");

        // Concurrent active SQLite WAL writer holding an open uncheckpointed transaction +
        // 150 live `.db`s under tight `RLIMIT_NOFILE = 256` (`O(1)` FD scan regression lock!)
        let scale_env = IsolatedEnv::new();
        let scale_conv = scale_env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&scale_conv).unwrap();

        for i in 0..149_u64 {
            let p = scale_conv.join(format!("conv_{i:03}.db"));
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);")
                .unwrap();
            c.execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(
                    10,
                    90,
                    20,
                    0,
                    ts_nov15,
                    "gemini-4-carbon",
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();
        }

        // 150th DB held open by an active in-process WAL writer with `wal_autocheckpoint = 0`!
        let active_wal_path = scale_conv.join("conv_149_wal.db");
        let active_wal_conn = rusqlite::Connection::open(&active_wal_path).unwrap();
        active_wal_conn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
            )
            .unwrap();
        active_wal_conn
            .execute(
                "INSERT INTO gen_metadata VALUES (1, ?1)",
                rusqlite::params![make_blob(
                    10,
                    90,
                    20,
                    0,
                    ts_nov15,
                    "gemini-4-carbon",
                    "Gemini 4 Carbon (High)"
                )],
            )
            .unwrap();

        // Also place a corrupt `.db` (and if non-root, an unreadable `0000` `.db`) to verify `unreadable_databases` accounting
        let corrupt_db = scale_conv.join("corrupt_header.db");
        fs::write(&corrupt_db, b"not-a-valid-sqlite-header-at-all").unwrap();
        let expected_unreadable = if unsafe { libc::geteuid() } != 0 {
            let locked_db = scale_conv.join("no_perm.db");
            fs::write(&locked_db, b"").unwrap();
            fs::set_permissions(&locked_db, fs::Permissions::from_mode(0o000)).unwrap();
            2_u64
        } else {
            1_u64
        };

        use std::os::unix::process::CommandExt;
        let mut scale_cmd = scale_env.cli_cmd();
        scale_cmd
            .env("TZ", "UTC0")
            .args(["--json", "stats", "summary", "--date", "2026-11-15"]);
        unsafe {
            scale_cmd.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 256,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let scale_out = scale_cmd.output().unwrap();
        if unsafe { libc::geteuid() } != 0 {
            let _ = fs::set_permissions(
                scale_conv.join("no_perm.db"),
                fs::Permissions::from_mode(0o600),
            );
        }
        drop(active_wal_conn);

        assert_eq!(scale_out.status.code(), Some(0));
        let scale_json: serde_json::Value = serde_json::from_slice(&scale_out.stdout).unwrap();
        assert_eq!(scale_json["databases_scanned"], 150);
        assert_eq!(scale_json["unreadable_databases"], expected_unreadable);
        assert_eq!(scale_json["summary"]["request_count"], 150);
    }
}

#[test]
fn stats_watch_cli_validation_and_live_pty_lifecycle() {
    let env = IsolatedEnv::new();

    // 1. Invalid `--watch` values are rejected with exit code 2 across all feature tiers
    for bad in ["0", "3601", "notanumber"] {
        let out = env
            .cli_cmd()
            .args(["stats", "summary", "--watch", bad])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for --watch {bad}, got {:?}",
            out.status.code()
        );
    }

    // 2. `--watch` combined with `--json` is rejected with exit code 2
    let json_out = env
        .cli_cmd()
        .args(["--json", "stats", "summary", "--watch"])
        .output()
        .unwrap();
    assert_eq!(json_out.status.code(), Some(2));

    // 3. Non-TTY stdin/stdout is rejected cleanly with exit code 2
    let non_tty_out = env
        .cli_cmd()
        .args(["stats", "list", "--watch", "3"])
        .output()
        .unwrap();
    assert_eq!(non_tty_out.status.code(), Some(2));

    #[cfg(feature = "stats")]
    {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::time::Duration;

        let env = IsolatedEnv::new();
        let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
        fs::create_dir_all(&cli_conv).unwrap();

        let win = libc::winsize {
            ws_row: 24,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &win as *const libc::winsize as *mut libc::winsize,
                )
            },
            0
        );
        let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { fs::File::from_raw_fd(slave_fd) };
        let inspect_slave = slave.try_clone().unwrap();
        unsafe {
            let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }

        let mut child = env
            .cli_cmd()
            .args(["stats", "summary", "--watch", "1"])
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();

        let drain = |m: &mut fs::File, buf: &mut Vec<u8>| {
            let mut chunk = [0u8; 4096];
            loop {
                match m.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        };

        // 4. Initial live render shows Summary view & `Live [summary]: every 1s`
        let mut screen = Vec::new();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            let txt = String::from_utf8_lossy(&screen);
            if txt.contains("Live [summary]: every 1s") && txt.contains("Summary") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let initial_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            initial_txt.contains("Live [summary]: every 1s"),
            "initial screen missing summary live bar:\n{initial_txt}"
        );

        // 5. Write a live synthetic SQLite DB while `--watch 1` is open -> auto-refreshes without restart!
        let enc_v = |mut n: u64| -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let mut b = (n & 0x7f) as u8;
                n >>= 7;
                if n != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if n == 0 {
                    break;
                }
            }
            out
        };
        let pb_v = |field: u64, val: u64| -> Vec<u8> {
            let mut out = enc_v(field << 3);
            out.extend_from_slice(&enc_v(val));
            out
        };
        let pb_b = |field: u64, bytes: &[u8]| -> Vec<u8> {
            let mut out = enc_v((field << 3) | 2);
            out.extend_from_slice(&enc_v(bytes.len() as u64));
            out.extend_from_slice(bytes);
            out
        };
        let now_ts = jiff::Timestamp::now().as_second() as u64;
        let usage = [
            pb_v(1, 500),
            pb_v(2, 1_500),
            pb_v(3, 400),
            pb_v(5, 8_000),
            pb_v(10, 400),
        ]
        .concat();
        let timing = pb_b(4, &pb_v(1, now_ts));
        let wrapped = [
            pb_b(4, &usage),
            pb_b(9, &timing),
            pb_b(19, b"gemini-4-carbon"),
            pb_b(21, b"Gemini 4 Carbon"),
        ]
        .concat();
        let blob = pb_b(1, &wrapped);

        let live_db = cli_conv.join("live_watch.db");
        let conn = rusqlite::Connection::open(&live_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO steps VALUES (1, 15, ?1, 3, NULL)",
            rusqlite::params![pb_b(1, &pb_v(1, now_ts))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (1, ?1)",
            rusqlite::params![blob],
        )
        .unwrap();
        drop(conn);

        screen.clear();
        for _ in 0..120 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Gemini 4 Carbon") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Gemini 4 Carbon"),
            "watch mode did not detect live SQLite write:\n{}",
            String::from_utf8_lossy(&screen)
        );

        // 6. Press Tab -> switches live to `List` view (`Live [list]:`)
        screen.clear();
        master.write_all(b"\t").unwrap();
        master.flush().unwrap();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            let txt = String::from_utf8_lossy(&screen);
            if txt.contains("Live [list]: every 1s") && txt.contains("Requests (newest first") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let list_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            list_txt.contains("Live [list]: every 1s")
                && list_txt.contains("Requests (newest first"),
            "Tab did not toggle to list view:\n{list_txt}"
        );

        // 7. Arrow key CSI sequence (`\x1b[A`) alone must NOT quit watch mode,
        //    and `\x1b[A\t` sent together must still dispatch `Tab` back to `summary`.
        master.write_all(b"\x1b[A").unwrap();
        master.flush().unwrap();
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            child.try_wait().unwrap().is_none(),
            "Escape sequence accidentally exited `stats --watch`"
        );
        screen.clear();
        master.write_all(b"\x1b[A\t").unwrap();
        master.flush().unwrap();
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            let txt = String::from_utf8_lossy(&screen);
            if txt.contains("Live [summary]: every 1s") && txt.contains("Summary") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let back_to_summary = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            back_to_summary.contains("Live [summary]: every 1s")
                && back_to_summary.contains("Summary"),
            "Arrow key followed by Tab swallowed Tab:\n{back_to_summary}"
        );

        // 7b. Resizing PTY to `5x0` (valid non-zero rows, zero cols) must NOT fall back to 120x24
        //     or emit body text; restoring to `24x100` redraws cleanly.
        screen.clear();
        let zero_col_win = libc::winsize {
            ws_row: 5,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &zero_col_win) },
            0
        );
        std::thread::sleep(Duration::from_millis(150));
        drain(&mut master, &mut screen);
        let zero_col_txt = String::from_utf8_lossy(&screen).into_owned();
        assert!(
            !zero_col_txt.contains("Live [") && !zero_col_txt.contains("Summary"),
            "5x0 zero-col resize unexpectedly rendered body/footer:\n{zero_col_txt}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "5x0 resize unexpectedly exited watch mode"
        );
        screen.clear();
        assert_eq!(
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &win) },
            0
        );
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            if String::from_utf8_lossy(&screen).contains("Live [summary]: every 1s") {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            String::from_utf8_lossy(&screen).contains("Live [summary]: every 1s"),
            "restoring PTY from 5x0 to 24x100 did not redraw frame"
        );

        // 8. Press `q` -> clean exit 0, alt screen exited, and ECHO/ICANON restored
        screen.clear();
        master.write_all(b"q").unwrap();
        master.flush().unwrap();
        let mut status_opt = None;
        for _ in 0..80 {
            drain(&mut master, &mut screen);
            if let Some(st) = child.try_wait().unwrap() {
                status_opt = Some(st);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        drain(&mut master, &mut screen);
        let status = status_opt.expect("stats --watch did not exit after pressing q");
        assert_eq!(status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&screen).contains("\x1b[?1049l"),
            "alt-screen restore sequence missing on exit"
        );
        let mut final_tio: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(inspect_slave.as_raw_fd(), &mut final_tio) },
            0
        );
        assert_ne!(
            final_tio.c_lflag & libc::ECHO,
            0,
            "ECHO was not restored after stats --watch exit"
        );
        assert_ne!(
            final_tio.c_lflag & libc::ICANON,
            0,
            "ICANON was not restored after stats --watch exit"
        );
    }
}

#[cfg(feature = "stats")]
#[test]
fn synthetic_v125_stats_cleared_canceled_interrupted_cli_contract() {
    use common::stats_fixture::{open_live_conv_db, pb_b, pb_v};

    let env = IsolatedEnv::new();
    let cli_conv = env.home.join(".gemini/antigravity-cli/conversations");
    fs::create_dir_all(&cli_conv).unwrap();

    let make_blob =
        |out_tok: u64, ttft_s: u64, stream_s: u64, ts: u64, err: Option<&[u8]>| -> Vec<u8> {
            let usage = [pb_v(1, 300), pb_v(2, 200), pb_v(3, out_tok), pb_v(5, 1_500)].concat();
            let timing = pb_b(4, &pb_v(1, ts));
            let wrapped = [
                pb_b(4, &usage),
                pb_b(9, &timing),
                pb_b(11, &pb_v(1, ttft_s)),
                pb_b(12, &pb_v(1, stream_s)),
                pb_b(19, b"gemini-3.1-pro"),
                pb_b(21, b"Gemini 3.1 Pro (High)"),
            ]
            .concat();
            let mut outer = pb_b(1, &wrapped);
            if let Some(e) = err {
                outer.extend(pb_b(5, e));
            }
            outer
        };

    let t0 = "2026-11-21T09:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second() as u64;
    let valid_payload = pb_b(20, &pb_b(1, b"done"));
    let db_path = cli_conv.join("status_split.db");
    let conn = open_live_conv_db(&db_path);
    for (idx, status, out_tok, err) in [
        (1i64, 12i64, 400u64, None),
        (2, 6, 400, None),
        (3, 5, 400, Some(&b"upstream_failed"[..])),
        (4, 5, 480, None),
        (5, 3, 240, None),
    ] {
        conn.execute(
            "INSERT INTO steps VALUES (?1, 15, NULL, ?2, ?3)",
            rusqlite::params![idx, status, &valid_payload],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gen_metadata VALUES (?1, ?2)",
            rusqlite::params![idx, make_blob(out_tok, 2, 4, t0 + (idx as u64) * 10, err)],
        )
        .unwrap();
    }
    drop(conn);

    // 1. `stats list --range all --json`
    let list_json = env
        .cli_cmd()
        .args(["--json", "stats", "list", "--range", "all"])
        .output()
        .unwrap();
    assert_eq!(
        list_json.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&list_json.stderr)
    );
    let lj: serde_json::Value = serde_json::from_slice(&list_json.stdout).unwrap();
    let items = lj["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    assert_eq!(items[0]["status"], "ok");
    assert_eq!(items[0]["output_tps"].as_f64().unwrap().round() as u64, 60);
    assert_eq!(items[1]["status"], "cleared");
    assert_eq!(items[1]["output_tps"].as_f64().unwrap().round() as u64, 120);
    assert_eq!(items[2]["status"], "error");
    assert!(items[2]["output_tps"].is_null());
    assert_eq!(items[3]["status"], "canceled");
    assert!(items[3]["output_tps"].is_null());
    assert_eq!(items[4]["status"], "interrupted");
    assert!(items[4]["output_tps"].is_null());

    // 2. `stats summary --range all --json` shares the exact 2 eligible TPS samples (`3` and clean `5`)
    let sum_json = env
        .cli_cmd()
        .args(["--json", "stats", "summary", "--range", "all"])
        .output()
        .unwrap();
    assert_eq!(sum_json.status.code(), Some(0));
    let sj: serde_json::Value = serde_json::from_slice(&sum_json.stdout).unwrap();
    assert_eq!(sj["performance"]["sample_count"], 2);
    assert_eq!(
        sj["performance"]["output_tps"]["p50"]
            .as_f64()
            .unwrap()
            .round() as u64,
        90
    );

    // 3. Human `stats list --range all` shows `ok`, `clr`, `err`, `canc`, `intr`
    let list_text = env
        .cli_cmd()
        .args(["stats", "list", "--range", "all"])
        .output()
        .unwrap();
    assert_eq!(list_text.status.code(), Some(0));
    let txt = String::from_utf8_lossy(&list_text.stdout);
    for tok in [" ok", " clr", " err", " canc", " intr", " 120 ", " 60 "] {
        assert!(txt.contains(tok), "missing `{tok}` in stats list:\n{txt}");
    }
}
