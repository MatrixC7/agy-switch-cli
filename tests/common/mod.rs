#![allow(dead_code)]

use agy_switch_cli::domain::account::AccountRecord;
use agy_switch_cli::domain::quota::{
    ModelQuota, QuotaBucket, QuotaGroup, QuotaObservation, QuotaSourceEnv,
};
use agy_switch_cli::domain::token::TokenRecord;
use agy_switch_cli::oauth::refresh::OAuthEndpoints;
use agy_switch_cli::paths::HeadlessPaths;
use agy_switch_cli::quota::official_cli::{
    OfficialCliQuotaError, OfficialCliQuotaRunner, OfficialCliUsageOutcome,
};
use agy_switch_cli::store::repository::StoreRepository;
use agy_switch_cli::transport::client::BoxFuture;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// Re-executes the current integration test binary targeting a single `--exact` test
/// inside a single-threaded child process with clean, explicit environment variables,
/// completely avoiding `std::env::set_var` in multi-threaded parent test processes.
pub fn run_isolated_subtest(test_name: &str, flag_env: &str, extra_envs: &[(&str, &OsStr)]) {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(flag_env, "1")
        .args(["--exact", test_name, "--test-threads=1", "--nocapture"]);
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        cmd.env("TMPDIR", tmp);
    }
    for (k, v) in extra_envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "Isolated subtest `{test_name}` ({flag_env}) failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Ensures spawned child processes are always killed and reaped on drop/panic.
pub struct KillChildOnDrop(Option<Child>);

impl KillChildOnDrop {
    pub fn new(child: Child) -> Self {
        Self(Some(child))
    }

    pub fn as_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child active")
    }

    pub fn take(&mut self) -> Child {
        self.0.take().expect("child active")
    }
}

impl Drop for KillChildOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Fully isolated temporary home/XDG/data/cache/runtime/proc sandbox that never touches
/// host credentials, D-Bus session bus, host `agy`, or Antigravity desktop app files.
pub struct IsolatedEnv {
    pub _tmp: TempDir,
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub proc_dir: PathBuf,
}

impl IsolatedEnv {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data_dir = tmp.path().join("data");
        let cache_dir = tmp.path().join("cache");
        let runtime_dir = tmp.path().join("run");
        let proc_dir = tmp.path().join("empty_proc");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::create_dir_all(&proc_dir).unwrap();
        Self {
            _tmp: tmp,
            home,
            data_dir,
            cache_dir,
            runtime_dir,
            proc_dir,
        }
    }

    pub fn tmp_path(&self) -> &Path {
        self._tmp.path()
    }

    pub fn init_agy_slot_dir(&self) -> PathBuf {
        let slot_dir = self.home.join(".gemini").join("antigravity-cli");
        fs::create_dir_all(&slot_dir).unwrap();
        fs::set_permissions(&slot_dir, fs::Permissions::from_mode(0o700)).unwrap();
        slot_dir
    }

    pub fn paths(&self) -> HeadlessPaths {
        HeadlessPaths::with_explicit(
            self.home.clone(),
            self.data_dir.clone(),
            self.cache_dir.join("agy-switch-cli"),
        )
    }

    pub fn repo(&self) -> StoreRepository {
        StoreRepository::new(self.paths())
    }

    pub fn cli_cmd(&self) -> Command {
        self.cli_cmd_with_data_dir(&self.data_dir)
    }

    pub fn cli_cmd_with_data_dir(&self, data_dir: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agy-switch-cli"));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self._tmp.path().join("xdg_data"))
            .env("XDG_CACHE_HOME", &self.cache_dir)
            .env("XDG_CONFIG_HOME", self._tmp.path().join("xdg_cfg"))
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/no-dbus", self.runtime_dir.display()),
            )
            .env("AGY_SWITCH_CLI_PROC_ROOT", &self.proc_dir)
            .env(
                "AGY_SWITCH_CLI_AGY_BIN",
                self._tmp.path().join("no-host-agy"),
            )
            .env(
                "AGY_SWITCH_CLI_ANTIGRAVITY_APP_DIR",
                self._tmp.path().join("no-host-antigravity-app"),
            )
            .env("NO_PROXY", "*")
            .env("AGY_SWITCH_CLI_PROXY", "direct")
            .args(["--data-dir", data_dir.to_str().unwrap()]);
        cmd
    }
}

pub fn make_synthetic_account(
    id: &str,
    email: &str,
    refresh_token: &str,
    expiry: i64,
    now: i64,
) -> AccountRecord {
    let tok = TokenRecord {
        access_token: format!("ya29.{id}"),
        refresh_token: refresh_token.into(),
        expires_in: 3600,
        expiry_timestamp: expiry,
        token_type: "Bearer".into(),
        id_token: None,
        oauth_client_key: Some("antigravity_enterprise".into()),
        granted_scopes: Some(vec![
            "openid".into(),
            "https://www.googleapis.com/auth/cloud-platform".into(),
        ]),
        project_id: None,
        is_gcp_tos: true,
    };
    AccountRecord::new(id.into(), email.into(), tok, now)
}

pub fn make_rich_sample_account(id: &str, email: &str, now: i64) -> AccountRecord {
    let token = TokenRecord {
        access_token: format!("SECRET_ACCESS_TOKEN_{id}"),
        refresh_token: format!("SECRET_REFRESH_TOKEN_{id}"),
        expires_in: 7200,
        expiry_timestamp: now + 7200,
        token_type: "Bearer".into(),
        id_token: Some(format!("SECRET_ID_TOKEN_{id}")),
        oauth_client_key: Some("antigravity_enterprise".into()),
        granted_scopes: Some(vec![
            "openid".into(),
            "https://www.googleapis.com/auth/cloud-platform".into(),
        ]),
        project_id: Some("proj-synth".into()),
        is_gcp_tos: true,
    };
    let mut rec = AccountRecord::new(id.into(), email.into(), token, now);
    rec.custom_label = Some("label-\x1b[31mANSI\x1b[0m".into());
    rec.disabled_detail = Some(format!("SECRET_DISABLED_DETAIL_{id}"));
    rec.validation_url = Some(format!(
        "https://example.invalid/SECRET_VALIDATION_URL_{id}"
    ));
    let mut q = QuotaObservation::new(now, QuotaSourceEnv::Production);
    q.forbidden_reason = Some(format!("SECRET_FORBIDDEN_REASON_{id}"));
    q.models.push(ModelQuota {
        name: "gemini-3.8-flash".into(),
        percentage: 75,
        percentage_known: Some(true),
        observed_remaining_fraction: Some(0.75),
        primary_quota: None,
        quota_bucket_id: Some("gemini-5h".into()),
        reset_time: "2099-01-01T00:00:00Z".into(),
        display_name: Some("Gemini 3.8 Flash".into()),
        supports_images: None,
        supports_thinking: None,
        thinking_budget: None,
        recommended: None,
        max_tokens: None,
        max_output_tokens: None,
        supported_mime_types: None,
    });
    q.quota_groups = Some(vec![QuotaGroup {
        display_name: "Gemini Models".into(),
        description: Some("Models within this group: Gemini 3.8 Flash".into()),
        buckets: vec![
            QuotaBucket {
                bucket_id: "gemini-5h".into(),
                window: "5h".into(),
                remaining_fraction: 0.75,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-01T00:00:00Z".into(),
                display_name: None,
                description: None,
            },
            QuotaBucket {
                bucket_id: "gemini-weekly".into(),
                window: "weekly".into(),
                remaining_fraction: 0.80,
                remaining_fraction_known: Some(true),
                reset_time: "2099-01-07T00:00:00Z".into(),
                display_name: None,
                description: None,
            },
        ],
    }]);
    rec.quota = Some(q);
    rec
}

pub fn fast_oauth_endpoints() -> OAuthEndpoints {
    OAuthEndpoints {
        base_backoff: Duration::from_millis(5),
        ..OAuthEndpoints::default()
    }
}

pub fn write_fake_agy_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

pub type SlotUsageHandler = dyn Fn(&HeadlessPaths, bool, &str) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError>
    + Send
    + Sync;

pub struct SlotQuotaRunner {
    handler: Arc<SlotUsageHandler>,
    probed_slots: Arc<Mutex<Vec<String>>>,
}

impl SlotQuotaRunner {
    pub fn from_handler<F>(f: F) -> Self
    where
        F: Fn(&HeadlessPaths, bool, &str) -> Result<OfficialCliUsageOutcome, OfficialCliQuotaError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            handler: Arc::new(f),
            probed_slots: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn constant_pct(pct: f64) -> Self {
        Self::from_handler(move |_, _, _| Ok(make_usage_outcome(pct, pct, "2099-01-01T00:00:00Z")))
    }

    pub fn probed_slots(&self) -> Vec<String> {
        self.probed_slots.lock().unwrap().clone()
    }
}

impl OfficialCliQuotaRunner for SlotQuotaRunner {
    fn query_active_usage<'a>(
        &'a self,
        paths: &'a HeadlessPaths,
        explicit_file_backend: bool,
    ) -> BoxFuture<'a, Result<OfficialCliUsageOutcome, OfficialCliQuotaError>> {
        Box::pin(async move {
            let slot_text = fs::read_to_string(&paths.active_slot_file).unwrap_or_default();
            self.probed_slots.lock().unwrap().push(slot_text.clone());
            (self.handler)(paths, explicit_file_backend, &slot_text)
        })
    }
}

pub fn make_usage_outcome(short_5h: f64, weekly: f64, reset_str: &str) -> OfficialCliUsageOutcome {
    OfficialCliUsageOutcome::Quota {
        description: None,
        groups: vec![QuotaGroup {
            display_name: "Gemini Models".into(),
            description: Some("Models within this group: gemini-3.1-pro".into()),
            buckets: vec![
                QuotaBucket {
                    bucket_id: "gemini-5h".into(),
                    window: "5h".into(),
                    remaining_fraction: short_5h,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_str.into(),
                    display_name: None,
                    description: None,
                },
                QuotaBucket {
                    bucket_id: "gemini-weekly".into(),
                    window: "weekly".into(),
                    remaining_fraction: weekly,
                    remaining_fraction_known: Some(true),
                    reset_time: reset_str.into(),
                    display_name: None,
                    description: None,
                },
            ],
        }],
    }
}

#[cfg(feature = "secret-service-backend")]
pub mod secret_service {
    use super::IsolatedEnv;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Clone, Copy, Debug)]
    pub enum SecretServiceLayout {
        /// Single `/org/freedesktop/secrets/collection/login`; aliases `default` and `login` both point there.
        SingleLogin,
        /// `/org/freedesktop/secrets/collection/login` + `/org/freedesktop/secrets/collection/default`;
        /// `ReadAlias("default")` -> `default`, `ReadAlias("login")` -> `/`.
        LoginAndDefault,
        /// `/org/freedesktop/secrets/collection/login` + `/org/freedesktop/secrets/collection/custom_default`;
        /// `ReadAlias("default")` -> `custom_default`, `ReadAlias("login")` -> `login`.
        LoginAndCustomDefault,
    }

    impl SecretServiceLayout {
        fn as_arg(self) -> &'static str {
            match self {
                Self::SingleLogin => "login_only",
                Self::LoginAndDefault => "login_and_default",
                Self::LoginAndCustomDefault => "login_and_custom_default",
            }
        }
    }

    const MOCK_SECRET_SERVICE_PY: &str = r#"
import json, os, sys
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LAYOUT, CTRL_PATH, STATS_PATH, READY_PATH = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)

LOGIN_PATH = "/org/freedesktop/secrets/collection/login"
if LAYOUT == "login_only":
    DEFAULT_PATH = None
    DEFAULT_LABEL = None
elif LAYOUT == "login_and_default":
    DEFAULT_PATH = "/org/freedesktop/secrets/collection/default"
    DEFAULT_LABEL = "default"
else:
    DEFAULT_PATH = "/org/freedesktop/secrets/collection/custom_default"
    DEFAULT_LABEL = "custom_default"

state = {
    "sessions": {},
    "items": {},
    "next_id": 1,
    "unlock_calls": 0,
    "create_calls": 0,
    "delete_calls": 0,
    "last_reseed_seq": -1,
    "login_locked": False,
    "default_locked": False,
}

def dump_stats():
    login_secrets = []
    default_secrets = []
    all_secrets = []
    for p, it in state["items"].items():
        s = it["secret"].decode("utf-8", "replace")
        all_secrets.append(s)
        if it["col"] == LOGIN_PATH:
            login_secrets.append(s)
        else:
            default_secrets.append(s)
    payload = {
        "unlock_calls": state["unlock_calls"],
        "create_calls": state["create_calls"],
        "delete_calls": state["delete_calls"],
        "login_count": len(login_secrets),
        "default_count": len(default_secrets),
        "login": login_secrets,
        "default": default_secrets,
        "login_secrets": login_secrets,
        "default_secrets": default_secrets,
        "secrets": all_secrets,
    }
    tmp = STATS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, STATS_PATH)

def load_ctrl():
    with open(CTRL_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "login_locked" in cfg and cfg["login_locked"] is not None:
        state["login_locked"] = bool(cfg["login_locked"])
    if "default_locked" in cfg and cfg["default_locked"] is not None:
        state["default_locked"] = bool(cfg["default_locked"])
    if "item_locked" in cfg and cfg["item_locked"] is not None:
        locked = bool(cfg["item_locked"])
        for it in state["items"].values():
            it["locked"] = locked

    reseed_seq = cfg.get("_reseed_seq", 0)
    if cfg.get("reseed") and reseed_seq != state["last_reseed_seq"]:
        state["last_reseed_seq"] = reseed_seq
        state["delete_calls"] = 0
        state["create_calls"] = 0
        for p, it in list(state["items"].items()):
            it["obj"].remove_from_connection()
            state["items"].pop(p, None)
        attrs = {"service": "gemini", "username": "antigravity"}
        pairs = [("login", LOGIN_PATH)]
        if DEFAULT_PATH is not None:
            pairs.append(("default", DEFAULT_PATH))
        for key, cpath in pairs:
            val = cfg.get(key)
            if val is not None:
                iid = state["next_id"]
                state["next_id"] += 1
                ipath = f"{cpath}/i{iid}"
                obj = ItemObj(bus, ipath)
                state["items"][ipath] = {
                    "obj": obj,
                    "col": cpath,
                    "attrs": dict(attrs),
                    "secret": val.encode("utf-8"),
                    "locked": False,
                }
        dump_stats()

    if DEFAULT_PATH is not None and (cfg.get("inject_conflict") or cfg.get("inject_conflict_secret")):
        conflict_path = f"{DEFAULT_PATH}/iconflict"
        secret_str = cfg.get("inject_conflict_secret") or '{"conflicting":true}'
        if conflict_path not in state["items"]:
            obj = ItemObj(bus, conflict_path)
            state["items"][conflict_path] = {
                "obj": obj,
                "col": DEFAULT_PATH,
                "attrs": {"service": "gemini", "username": "antigravity"},
                "secret": secret_str.encode("utf-8"),
                "locked": False,
            }
            dump_stats()
    if DEFAULT_PATH is not None and (cfg.get("clear_conflict") or cfg.get("clear_conflict_secret")):
        conflict_path = f"{DEFAULT_PATH}/iconflict"
        if conflict_path in state["items"]:
            state["items"][conflict_path]["obj"].remove_from_connection()
            state["items"].pop(conflict_path, None)
            dump_stats()

    return cfg

def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()

def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

class SessionObj(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Secret.Session", in_signature="", out_signature="")
    def Close(self):
        pass

class ItemObj(dbus.service.Object):
    def __init__(self, conn, path):
        super().__init__(conn, path)
        self.path = path
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        load_ctrl()
        it = state["items"][self.path]
        if prop == "Locked":
            return dbus.Boolean(it["locked"], variant_level=1)
        if prop == "Attributes":
            return dbus.Dictionary(it["attrs"], signature="ss", variant_level=1)
        return dbus.String("item", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        load_ctrl()
        it = state["items"][self.path]
        return dbus.Dictionary({
            "Locked": dbus.Boolean(it["locked"], variant_level=1),
            "Attributes": dbus.Dictionary(it["attrs"], signature="ss", variant_level=1),
            "Label": dbus.String("Antigravity", variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session_path):
        load_ctrl()
        key = state["sessions"][str(session_path)]
        iv, ct = aes_encrypt(key, state["items"][self.path]["secret"])
        return (session_path, dbus.ByteArray(iv), dbus.ByteArray(ct), "text/plain")
    @dbus.service.method("org.freedesktop.Secret.Item", in_signature="", out_signature="o")
    def Delete(self):
        cfg = load_ctrl()
        state["delete_calls"] += 1
        fail_del = int(cfg.get("fail_delete_from_call", -1))
        if fail_del >= 0 and state["delete_calls"] >= fail_del:
            dump_stats()
            raise dbus.DBusException("simulated Delete failure on second collection")
        state["items"].pop(self.path, None)
        self.remove_from_connection()
        dump_stats()
        return dbus.ObjectPath("/")

class CollectionObj(dbus.service.Object):
    def __init__(self, conn, path, label, is_login):
        self.path = path
        self.label = label
        self.is_login = is_login
        super().__init__(conn, self.path)
    def is_locked(self):
        return state["login_locked"] if self.is_login else state["default_locked"]
    def my_items(self):
        return [p for p, it in state["items"].items() if it["col"] == self.path]
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        load_ctrl()
        if prop == "Locked":
            return dbus.Boolean(self.is_locked(), variant_level=1)
        if prop == "Items":
            return dbus.Array([dbus.ObjectPath(p) for p in self.my_items()], signature="o", variant_level=1)
        return dbus.String(self.label, variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        load_ctrl()
        return dbus.Dictionary({
            "Locked": dbus.Boolean(self.is_locked(), variant_level=1),
            "Items": dbus.Array([dbus.ObjectPath(p) for p in self.my_items()], signature="o", variant_level=1),
            "Label": dbus.String(self.label, variant_level=1),
            "Created": dbus.UInt64(0, variant_level=1),
            "Modified": dbus.UInt64(0, variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        load_ctrl()
        req = {str(k): str(v) for k, v in attrs.items()}
        return [
            dbus.ObjectPath(p)
            for p, it in state["items"].items()
            if it["col"] == self.path and all(it["attrs"].get(k) == v for k, v in req.items())
        ]
    @dbus.service.method("org.freedesktop.Secret.Collection", in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        cfg = load_ctrl()
        state["create_calls"] += 1
        if cfg.get("exit_provider_on_create"):
            os._exit(1)
        kill_pid = int(cfg.get("kill_dbus_on_create_pid", 0))
        if kill_pid > 0:
            os.kill(kill_pid, 9)
            os._exit(1)
        if cfg.get("fail_create"):
            dump_stats()
            raise dbus.DBusException(cfg.get("fail_msg", "err"))
        fail_from = int(cfg.get("fail_create_from_call", -1))
        if fail_from >= 0 and state["create_calls"] >= fail_from:
            dump_stats()
            raise dbus.DBusException("simulated keyring CreateItem failure")
        sess_path, iv, ct, _ = secret
        key = state["sessions"][str(sess_path)]
        raw = aes_decrypt(key, bytes(iv), bytes(ct))
        attrs = {str(k): str(v) for k, v in props.get("org.freedesktop.Secret.Item.Attributes", {}).items()}
        if bool(replace):
            for p, it in list(state["items"].items()):
                if it["col"] == self.path and it["attrs"] == attrs:
                    it["secret"] = raw
                    dump_stats()
                    return (dbus.ObjectPath(p), dbus.ObjectPath("/"))
        iid = state["next_id"]
        state["next_id"] += 1
        ipath = f"{self.path}/i{iid}"
        obj = ItemObj(bus, ipath)
        state["items"][ipath] = {
            "obj": obj,
            "col": self.path,
            "attrs": attrs,
            "secret": raw,
            "locked": False,
        }
        dump_stats()
        return (dbus.ObjectPath(ipath), dbus.ObjectPath("/"))

class ServiceObj(dbus.service.Object):
    def __init__(self, conn):
        super().__init__(conn, "/org/freedesktop/secrets")
    def visible_cols(self):
        cfg = load_ctrl()
        if DEFAULT_PATH is None or cfg.get("hide_default"):
            return [dbus.ObjectPath(LOGIN_PATH)]
        return [dbus.ObjectPath(LOGIN_PATH), dbus.ObjectPath(DEFAULT_PATH)]
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        if prop == "Collections":
            return dbus.Array(self.visible_cols(), signature="o", variant_level=1)
        return dbus.Array([], signature="o", variant_level=1)
    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return dbus.Dictionary({
            "Collections": dbus.Array(self.visible_cols(), signature="o", variant_level=1),
        }, signature="sv")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algo, inp):
        load_ctrl()
        sid = len(state["sessions"]) + 1
        spath = f"/org/freedesktop/secrets/session/s{sid}"
        SessionObj(bus, spath)
        peer_pub = int.from_bytes(bytes(inp), "big")
        priv = int.from_bytes(os.urandom(32), "big") | 1
        pub = pow(2, priv, DH_PRIME)
        shared = pow(peer_pub, priv, DH_PRIME)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"").derive(
            shared.to_bytes(128, "big")
        )
        state["sessions"][spath] = aes_key
        srv_bytes = pub.to_bytes(max(1, (pub.bit_length() + 7) // 8), "big")
        return (dbus.ByteArray(srv_bytes, variant_level=1), dbus.ObjectPath(spath))
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        cfg = load_ctrl()
        name = str(name)
        if name == "default" and cfg.get("fail_read_alias"):
            raise dbus.DBusException("simulated ReadAlias D-Bus failure")
        if LAYOUT == "login_only":
            if name in ("default", "login"):
                return dbus.ObjectPath(LOGIN_PATH)
            return dbus.ObjectPath("/")
        if LAYOUT == "login_and_default":
            if name == "default":
                return dbus.ObjectPath(DEFAULT_PATH)
            return dbus.ObjectPath("/")
        if name == "default" and cfg.get("hide_default"):
            return dbus.ObjectPath("/")
        if name == "login":
            return dbus.ObjectPath(LOGIN_PATH)
        if name == "default":
            return dbus.ObjectPath(DEFAULT_PATH)
        return dbus.ObjectPath("/")
    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        state["unlock_calls"] += 1
        for o in objects:
            s = str(o)
            if s == LOGIN_PATH:
                state["login_locked"] = False
            elif DEFAULT_PATH is not None and s == DEFAULT_PATH:
                state["default_locked"] = False
            elif s in state["items"]:
                state["items"][s]["locked"] = False
        with open(CTRL_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "login_locked" in cfg:
            cfg["login_locked"] = state["login_locked"]
        if "default_locked" in cfg:
            cfg["default_locked"] = state["default_locked"]
        if "item_locked" in cfg:
            cfg["item_locked"] = False
        tmp = CTRL_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        os.replace(tmp, CTRL_PATH)
        dump_stats()
        return (objects, dbus.ObjectPath("/"))

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus_name = dbus.service.BusName("org.freedesktop.secrets", bus)
svc = ServiceObj(bus)
col_login = CollectionObj(bus, LOGIN_PATH, "login", True)
if DEFAULT_PATH is not None:
    col_default = CollectionObj(bus, DEFAULT_PATH, DEFAULT_LABEL, False)
load_ctrl()
dump_stats()
with open(READY_PATH, "w", encoding="utf-8") as rf:
    rf.write("ready")
GLib.MainLoop().run()
"#;

    /// Isolated private `/usr/bin/dbus-daemon` + Python Secret Service mock fixture (`A13-a`).
    /// Both child processes are wrapped in `KillChildOnDrop` immediately upon `spawn()` so
    /// readiness timeouts or assertion panics never leave orphaned background processes.
    pub struct PrivateSecretServiceFixture {
        py_proc: Option<super::KillChildOnDrop>,
        _dbus_proc: super::KillChildOnDrop,
        dbus_pid: u32,
        bus_addr: String,
        layout: SecretServiceLayout,
        mock_py: PathBuf,
        ctrl_file: PathBuf,
        stats_file: PathBuf,
        ready_file: PathBuf,
        reseed_seq: AtomicU64,
    }

    impl PrivateSecretServiceFixture {
        /// Starts ONLY the isolated `/usr/bin/dbus-daemon` (without registering `org.freedesktop.secrets`),
        /// allowing callers to test `auto -> file` fallback against a live session bus before calling
        /// `start_provider()`.
        pub fn start_bus_only(
            env: &IsolatedEnv,
            prefix: &str,
            layout: SecretServiceLayout,
            initial_ctrl: serde_json::Value,
        ) -> Option<Self> {
            let allow_skip = std::env::var("AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let has_bins = Path::new("/usr/bin/dbus-daemon").is_file()
                && Path::new("/usr/bin/python3").is_file();
            let has_py_deps = has_bins
                && Command::new("/usr/bin/python3")
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .args([
                        "-c",
                        "import dbus, dbus.service, dbus.mainloop.glib; from gi.repository import GLib; from cryptography.hazmat.primitives.kdf.hkdf import HKDF",
                    ])
                    .status()
                    .is_ok_and(|s| s.success());
            if !has_py_deps {
                if allow_skip {
                    eprintln!(
                        "[SKIPPED] PrivateSecretServiceFixture ({prefix}): missing dbus-daemon or Python Secret Service deps (AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST=1)"
                    );
                    return None;
                }
                panic!(
                    "Live isolated D-Bus test requires `/usr/bin/dbus-daemon` and Python `dbus` + `gi` + `cryptography` (set AGY_SWITCH_CLI_ALLOW_SKIP_DBUS_TEST=1 to explicitly skip)."
                );
            }

            let bus_sock = env.runtime_dir.join(format!("{prefix}-secrets.sock"));
            let bus_addr = format!("unix:path={}", bus_sock.display());
            let dbus_child = Command::new("/usr/bin/dbus-daemon")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args([
                    "--session",
                    &format!("--address={bus_addr}"),
                    "--nofork",
                    "--nopidfile",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let dbus_pid = dbus_child.id();
            let dbus_guard = super::KillChildOnDrop::new(dbus_child);

            for _ in 0..80 {
                if bus_sock.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(
                bus_sock.exists(),
                "Isolated dbus-daemon socket did not appear: {}",
                bus_sock.display()
            );

            let ctrl_file = env.tmp_path().join(format!("{prefix}_ctrl.json"));
            let stats_file = env.tmp_path().join(format!("{prefix}_stats.json"));
            let ready_file = env.tmp_path().join(format!("{prefix}_ready"));
            let mock_py = env.tmp_path().join(format!("{prefix}_mock_ss.py"));
            fs::write(&mock_py, MOCK_SECRET_SERVICE_PY).unwrap();

            let mut init_obj = initial_ctrl;
            if let Some(map) = init_obj.as_object_mut() {
                map.insert("_reseed_seq".into(), serde_json::json!(1));
            }
            fs::write(&ctrl_file, serde_json::to_vec(&init_obj).unwrap()).unwrap();

            Some(Self {
                py_proc: None,
                _dbus_proc: dbus_guard,
                dbus_pid,
                bus_addr,
                layout,
                mock_py,
                ctrl_file,
                stats_file,
                ready_file,
                reseed_seq: AtomicU64::new(1),
            })
        }

        pub fn start(
            env: &IsolatedEnv,
            prefix: &str,
            layout: SecretServiceLayout,
            initial_ctrl: serde_json::Value,
        ) -> Option<Self> {
            let mut fixture = Self::start_bus_only(env, prefix, layout, initial_ctrl)?;
            fixture.start_provider();
            Some(fixture)
        }

        pub fn start_provider(&mut self) {
            self.py_proc = None;
            let guard = Self::spawn_provider(
                &self.bus_addr,
                self.layout,
                &self.mock_py,
                &self.ctrl_file,
                &self.stats_file,
                &self.ready_file,
            );
            self.py_proc = Some(guard);
        }

        fn spawn_provider(
            bus_addr: &str,
            layout: SecretServiceLayout,
            mock_py: &Path,
            ctrl_file: &Path,
            stats_file: &Path,
            ready_file: &Path,
        ) -> super::KillChildOnDrop {
            let _ = fs::remove_file(ready_file);
            let proc = Command::new("/usr/bin/python3")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("DBUS_SESSION_BUS_ADDRESS", bus_addr)
                .args([
                    mock_py.to_str().unwrap(),
                    layout.as_arg(),
                    ctrl_file.to_str().unwrap(),
                    stats_file.to_str().unwrap(),
                    ready_file.to_str().unwrap(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let guard = super::KillChildOnDrop::new(proc);
            for _ in 0..100 {
                if ready_file.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            assert!(
                ready_file.exists(),
                "Isolated Python Secret Service provider did not become ready"
            );
            guard
        }

        pub fn bus_addr(&self) -> &str {
            &self.bus_addr
        }

        pub fn dbus_pid(&self) -> u32 {
            self.dbus_pid
        }

        pub fn set_ctrl(&self, mut ctrl: serde_json::Value) {
            let seq = self.reseed_seq.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(map) = ctrl.as_object_mut() {
                map.insert("_reseed_seq".into(), serde_json::json!(seq));
            }
            let tmp = self.ctrl_file.with_extension("json.tmp");
            fs::write(&tmp, serde_json::to_vec(&ctrl).unwrap()).unwrap();
            fs::rename(&tmp, &self.ctrl_file).unwrap();
        }

        pub fn stats(&self) -> serde_json::Value {
            serde_json::from_slice(&fs::read(&self.stats_file).unwrap()).unwrap()
        }

        pub fn restart_provider(&mut self, ctrl: serde_json::Value) {
            self.py_proc = None;
            self.set_ctrl(ctrl);
            self.start_provider();
        }
    }
}

/// Real Linux PTY test harness (`openpty` + non-blocking master + `setsid`/`TIOCSCTTY` + ECHO inspection).
/// Kills and reaps any still-running child on drop so assertion panics never leak orphan PTY processes.
pub struct PtyChild {
    pub master: fs::File,
    pub inspect_slave: fs::File,
    pub child: Child,
}

impl Drop for PtyChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl PtyChild {
    pub fn spawn(mut cmd: Command, cols: u16, rows: u16, setsid: bool) -> Self {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;

        let win = libc::winsize {
            ws_row: rows,
            ws_col: cols,
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
                    &win,
                )
            },
            0,
            "openpty failed"
        );
        let slave_out_fd = unsafe { libc::dup(slave_fd) };
        let inspect_fd = unsafe { libc::dup(slave_fd) };
        let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
        let slave_out = unsafe { fs::File::from_raw_fd(slave_out_fd) };
        let inspect_slave = unsafe { fs::File::from_raw_fd(inspect_fd) };
        let master = unsafe { fs::File::from_raw_fd(master_fd) };
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            let _ = libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        cmd.stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::piped());
        if setsid {
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    let _ = libc::ioctl(0, libc::TIOCSCTTY, 0);
                    Ok(())
                });
            }
        }
        let child = cmd.spawn().unwrap();
        Self {
            master,
            inspect_slave,
            child,
        }
    }

    pub fn drain(&mut self, buf: &mut Vec<u8>) {
        use std::io::Read;
        let mut chunk = [0u8; 4096];
        while let Ok(n) = self.master.read(&mut chunk) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        use std::io::Write;
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
    }

    pub fn wait_for_text(&mut self, buf: &mut Vec<u8>, needle: &str, max_polls: usize) -> String {
        for _ in 0..max_polls {
            self.drain(buf);
            if String::from_utf8_lossy(buf).contains(needle) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        String::from_utf8_lossy(buf).into_owned()
    }

    pub fn echo_enabled(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.inspect_slave.as_raw_fd(), &mut t) },
            0
        );
        (t.c_lflag & libc::ECHO) != 0
    }
}

#[cfg(feature = "stats")]
pub mod stats_fixture {
    use std::path::Path;

    pub fn pb_varint(mut v: u64) -> Vec<u8> {
        let mut b = Vec::new();
        loop {
            let n = (v & 0x7f) as u8;
            v >>= 7;
            b.push(if v == 0 { n } else { n | 0x80 });
            if v == 0 {
                return b;
            }
        }
    }

    pub fn pb_v(field: u32, v: u64) -> Vec<u8> {
        [pb_varint(u64::from(field) << 3), pb_varint(v)].concat()
    }

    pub fn pb_b(field: u32, v: &[u8]) -> Vec<u8> {
        [
            pb_varint((u64::from(field) << 3) | 2),
            pb_varint(v.len() as u64),
            v.to_vec(),
        ]
        .concat()
    }

    pub fn open_live_conv_db(path: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS steps (idx INTEGER PRIMARY KEY, step_type INTEGER, metadata BLOB, status INTEGER, step_payload BLOB);
             CREATE TABLE IF NOT EXISTS gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        conn
    }

    pub fn open_archive_db(path: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS archived_generations (
                source_key TEXT, generation_idx INTEGER, ordinal INTEGER,
                model TEXT, input_tokens TEXT, output_tokens TEXT, cached_tokens TEXT,
                total_tokens TEXT, timestamp_seconds INTEGER, valid INTEGER, oversized INTEGER
             );",
        )
        .unwrap();
        conn
    }

    #[allow(clippy::too_many_arguments)]
    pub fn make_gen_blob(
        in_t: u64,
        cache_t: u64,
        out_t: u64,
        ts: u64,
        ttft_s: u64,
        stream_s: u64,
        model_id: &[u8],
        display_name: &[u8],
    ) -> Vec<u8> {
        let usage = [
            pb_v(1, in_t),
            pb_v(3, out_t),
            pb_v(5, cache_t),
            pb_v(10, out_t),
        ]
        .concat();
        let timing = pb_b(4, &pb_v(1, ts));
        let wrapped = [
            pb_b(4, &usage),
            pb_b(9, &timing),
            pb_b(11, &pb_v(1, ttft_s)),
            pb_b(12, &pb_v(1, stream_s)),
            pb_b(19, model_id),
            pb_b(21, display_name),
        ]
        .concat();
        pb_b(1, &wrapped)
    }
}
