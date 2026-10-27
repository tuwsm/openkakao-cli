//! Signed send-request verification (msgcap fork of openkakao-cli).
//!
//! Replaces macOS device-owner authentication (`human_auth::require_device_owner_auth`)
//! at the two AX-send commit points. A real AX send is allowed only for a request
//! that carries a valid HMAC-SHA256 signature made by the sender host with a shared
//! key (read from the macOS login keychain), is inside its 600-second window, and has
//! not been delivered before.
//!
//! Threat model: this is an integrity / accident-prevention gate, not a security
//! boundary against a caller that already holds the key or a uid-equal attacker.
//!
//! Wire format (stdin, one JSON object, unknown fields rejected):
//! `{"v":1,"platform":"kakaotalk","room":"..","body":"..","id":"..","iat":<unix>,
//!   "exp":<unix>,"confirm":"<64 hex>","sig":"<64 hex>"}`
//!
//! Signed bytes: `msgcap-send-v1` followed, for each of platform, room, body, id, iat,
//! exp, confirm (in that order), by `\n<byte length>:<utf-8 bytes>`. `iat`/`exp` are
//! rendered as decimal. Length prefixes make the encoding injective.
//!
//! Order guarantee: parsing, key read, signature, time window and replay checks all
//! happen in [`process`] before the sender closure (the only AX contact) is called.

use std::cell::RefCell;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Request validity window: `exp == iat + TTL_SECS` and `now <= exp`.
pub const TTL_SECS: i64 = 600;
/// How far `iat` may lie ahead of this machine's clock (clock difference between
/// the two hosts; measured offset 2026-10-27 was ~0.1 s, so 60 s is generous).
pub const FUTURE_SKEW_SECS: i64 = 60;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const SUPPORTED_PLATFORM: &str = "kakaotalk";
pub const KEYCHAIN_SERVICE: &str = "msgcap-send-hmac";
pub const KEYCHAIN_ACCOUNT: &str = "openkakao-signed-send";

const DOMAIN: &str = "msgcap-send-v1";
const ID_HASH_DOMAIN: &str = "msgcap-send-id-v1\n";
const MIN_KEY_BYTES: usize = 16;
const MAX_ROOM_BYTES: usize = 512;
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Result codes. The name is the only text the CLI prints (never a message, room
/// name or error chain); the number is the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Sent,
    ProbeOk,
    AxTrusted,
    ReqMalformed,
    PlatformUnsupported,
    SigMissing,
    SigMismatch,
    SigExpired,
    SigNotYetValid,
    SigReplay,
    KeyNotFound,
    KeyAccessDenied,
    KeyUnavailable,
    LedgerError,
    NoVerifiedRequest,
    RequestMismatch,
    PhotoUnsupported,
    AllowlistDenied,
    SendUncertain,
    ChatNotFound,
    ChatAmbiguous,
    KakaoNotRunning,
    AxNotTrusted,
    AxFailed,
    KakaoIdentityRejected,
    MainWindowMinimized,
    MainWindowMissing,
    ChatListMissing,
    AxSnapshotBudget,
    ChatOpenFailed,
    ComposerNotReady,
    ComposerUnreadable,
    ComposerHasDraft,
    FocusFailed,
    ComposerWriteFailed,
    ComposerVerifyFailed,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Sent => "SENT",
            Code::ProbeOk => "PROBE_OK",
            Code::AxTrusted => "AX_TRUSTED",
            Code::ReqMalformed => "REQ_MALFORMED",
            Code::PlatformUnsupported => "PLATFORM_UNSUPPORTED",
            Code::SigMissing => "SIG_MISSING",
            Code::SigMismatch => "SIG_MISMATCH",
            Code::SigExpired => "SIG_EXPIRED",
            Code::SigNotYetValid => "SIG_NOT_YET_VALID",
            Code::SigReplay => "SIG_REPLAY",
            Code::KeyNotFound => "KEY_NOT_FOUND",
            Code::KeyAccessDenied => "KEY_ACCESS_DENIED",
            Code::KeyUnavailable => "KEY_UNAVAILABLE",
            Code::LedgerError => "LEDGER_ERROR",
            Code::NoVerifiedRequest => "NO_VERIFIED_REQUEST",
            Code::RequestMismatch => "REQUEST_MISMATCH",
            Code::PhotoUnsupported => "PHOTO_UNSUPPORTED",
            Code::AllowlistDenied => "ALLOWLIST_DENIED",
            Code::SendUncertain => "SEND_UNCERTAIN",
            Code::ChatNotFound => "CHAT_NOT_FOUND",
            Code::ChatAmbiguous => "CHAT_AMBIGUOUS",
            Code::KakaoNotRunning => "KAKAO_NOT_RUNNING",
            Code::AxNotTrusted => "AX_NOT_TRUSTED",
            Code::AxFailed => "AX_FAILED",
            Code::KakaoIdentityRejected => "KAKAO_IDENTITY_REJECTED",
            Code::MainWindowMinimized => "MAIN_WINDOW_MINIMIZED",
            Code::MainWindowMissing => "MAIN_WINDOW_MISSING",
            Code::ChatListMissing => "CHAT_LIST_MISSING",
            Code::AxSnapshotBudget => "AX_SNAPSHOT_BUDGET",
            Code::ChatOpenFailed => "CHAT_OPEN_FAILED",
            Code::ComposerNotReady => "COMPOSER_NOT_READY",
            Code::ComposerUnreadable => "COMPOSER_UNREADABLE",
            Code::ComposerHasDraft => "COMPOSER_HAS_DRAFT",
            Code::FocusFailed => "FOCUS_FAILED",
            Code::ComposerWriteFailed => "COMPOSER_WRITE_FAILED",
            Code::ComposerVerifyFailed => "COMPOSER_VERIFY_FAILED",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Code::Sent | Code::ProbeOk | Code::AxTrusted => 0,
            Code::ReqMalformed => 20,
            Code::PlatformUnsupported => 21,
            Code::SigMissing => 22,
            Code::SigMismatch => 23,
            Code::SigExpired => 24,
            Code::SigNotYetValid => 25,
            Code::SigReplay => 26,
            Code::KeyNotFound => 27,
            Code::KeyAccessDenied => 28,
            Code::KeyUnavailable => 29,
            Code::LedgerError => 30,
            Code::NoVerifiedRequest => 31,
            Code::RequestMismatch => 32,
            Code::PhotoUnsupported => 33,
            Code::AllowlistDenied => 34,
            Code::SendUncertain => 40,
            Code::ChatNotFound => 41,
            Code::ChatAmbiguous => 42,
            Code::KakaoNotRunning => 43,
            Code::AxNotTrusted => 44,
            Code::AxFailed => 45,
            Code::KakaoIdentityRejected => 46,
            Code::MainWindowMinimized => 47,
            Code::MainWindowMissing => 48,
            Code::ChatListMissing => 49,
            Code::AxSnapshotBudget => 50,
            Code::ChatOpenFailed => 51,
            Code::ComposerNotReady => 52,
            Code::ComposerUnreadable => 53,
            Code::ComposerHasDraft => 54,
            Code::FocusFailed => 55,
            Code::ComposerWriteFailed => 56,
            Code::ComposerVerifyFailed => 57,
        }
    }
}

/// Error carrying only a [`Code`] (so it can travel through `anyhow` from the
/// commit-point guards without any message text).
#[derive(Debug)]
pub struct SignedError(pub Code);

impl fmt::Display for SignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl std::error::Error for SignedError {}

/// Outcome of the AX send as reported by the sender closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Verified,
    Uncertain,
}

/// A parsed request. `Debug` deliberately omits room and body.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub platform: String,
    pub room: String,
    pub body: String,
    pub id: String,
    pub iat: i64,
    pub exp: i64,
    pub confirm: String,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("platform", &self.platform)
            .field("id", &self.id)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    v: Option<i64>,
    platform: Option<String>,
    room: Option<String>,
    body: Option<String>,
    id: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    confirm: Option<String>,
    sig: Option<String>,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse and shape-check a request. Returns the request and its signature.
fn parse(raw: &[u8]) -> Result<(Request, String), SignedError> {
    let bad = || SignedError(Code::ReqMalformed);
    if raw.is_empty() || raw.len() > MAX_REQUEST_BYTES {
        return Err(bad());
    }
    let parsed: Raw = serde_json::from_slice(raw).map_err(|_| bad())?;
    let sig = match parsed.sig {
        Some(s) if !s.is_empty() => s,
        _ => return Err(SignedError(Code::SigMissing)),
    };
    if parsed.v != Some(1) {
        return Err(bad());
    }
    let (platform, room, body, id, iat, exp, confirm) = match (
        parsed.platform,
        parsed.room,
        parsed.body,
        parsed.id,
        parsed.iat,
        parsed.exp,
        parsed.confirm,
    ) {
        (Some(p), Some(r), Some(b), Some(i), Some(t), Some(e), Some(c)) => (p, r, b, i, t, e, c),
        _ => return Err(bad()),
    };
    if platform.is_empty()
        || room.is_empty()
        || room.len() > MAX_ROOM_BYTES
        || body.trim().is_empty()
        || body.len() > MAX_BODY_BYTES
        || !(8..=64).contains(&id.len())
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || !is_lower_hex(&confirm, 64)
        || exp != iat.checked_add(TTL_SECS).ok_or_else(bad)?
    {
        return Err(bad());
    }
    if platform != SUPPORTED_PLATFORM {
        return Err(SignedError(Code::PlatformUnsupported));
    }
    Ok((
        Request {
            platform,
            room,
            body,
            id,
            iat,
            exp,
            confirm,
        },
        sig,
    ))
}

/// Bytes covered by the signature (see module docs).
pub fn canonical(r: &Request) -> Vec<u8> {
    let mut out = DOMAIN.as_bytes().to_vec();
    let iat = r.iat.to_string();
    let exp = r.exp.to_string();
    for field in [
        r.platform.as_str(),
        r.room.as_str(),
        r.body.as_str(),
        r.id.as_str(),
        iat.as_str(),
        exp.as_str(),
        r.confirm.as_str(),
    ] {
        out.push(b'\n');
        out.extend_from_slice(field.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// Check signature (constant-time) and then the time window.
fn verify(req: &Request, sig_hex: &str, key: &[u8], now: i64) -> Result<(), SignedError> {
    if key.len() < MIN_KEY_BYTES {
        return Err(SignedError(Code::KeyUnavailable));
    }
    let sig = hex::decode(sig_hex).map_err(|_| SignedError(Code::SigMismatch))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| SignedError(Code::KeyUnavailable))?;
    mac.update(&canonical(req));
    mac.verify_slice(&sig)
        .map_err(|_| SignedError(Code::SigMismatch))?;
    if now > req.exp {
        return Err(SignedError(Code::SigExpired));
    }
    if req.iat > now.saturating_add(FUTURE_SKEW_SECS) {
        return Err(SignedError(Code::SigNotYetValid));
    }
    Ok(())
}

fn id_hash(id: &str) -> String {
    let mut h = Sha256::new();
    h.update(ID_HASH_DOMAIN.as_bytes());
    h.update(id.as_bytes());
    hex::encode(h.finalize())
}

/// Replay ledger: remembers `sha256(request id)` and `iat` (nothing else) until the
/// request can no longer pass the time window, in `<dir>/seen`, mode 0600, guarded by
/// an exclusive `flock` on `<dir>/lock`. Survives fork processes and agent restarts.
/// Returns `SigReplay` if the id was already consumed.
pub fn consume_request_id(dir: &Path, id: &str, iat: i64, now: i64) -> Result<(), SignedError> {
    let err = || SignedError(Code::LedgerError);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| err())?;
    let lock: File = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("lock"))
        .map_err(|_| err())?;
    // SAFETY: valid open fd for the duration of the call; the lock is released when
    // `lock` is dropped at the end of this function.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(err());
    }
    let seen_path = dir.join("seen");
    let existing = match fs::read_to_string(&seen_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(err()),
    };
    let hash = id_hash(id);
    let mut kept: Vec<String> = Vec::new();
    for line in existing.lines() {
        let mut parts = line.split(' ');
        let (Some(h), Some(t), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Ok(t) = t.parse::<i64>() else { continue };
        if !is_lower_hex(h, 64) {
            continue;
        }
        if now > t.saturating_add(TTL_SECS + FUTURE_SKEW_SECS) {
            continue; // can no longer pass the window; safe to forget
        }
        if h == hash {
            return Err(SignedError(Code::SigReplay));
        }
        kept.push(line.to_string());
    }
    kept.push(format!("{hash} {iat}"));
    let tmp_path = dir.join("seen.tmp");
    let mut tmp = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|_| err())?;
    tmp.write_all((kept.join("\n") + "\n").as_bytes())
        .map_err(|_| err())?;
    tmp.sync_all().map_err(|_| err())?;
    drop(tmp);
    fs::rename(&tmp_path, &seen_path).map_err(|_| err())?;
    Ok(())
}

thread_local! {
    static VERIFIED: RefCell<Option<Request>> = const { RefCell::new(None) };
}

struct ContextGuard;

impl ContextGuard {
    fn install(req: &Request) -> Self {
        VERIFIED.with(|v| *v.borrow_mut() = Some(req.clone()));
        ContextGuard
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        VERIFIED.with(|v| *v.borrow_mut() = None);
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn require_verified_send_at(room: &str, body: &str, now: i64) -> anyhow::Result<()> {
    VERIFIED.with(|v| match v.borrow().as_ref() {
        None => Err(anyhow::Error::new(SignedError(Code::NoVerifiedRequest))),
        Some(r) if r.room != room || r.body != body => {
            Err(anyhow::Error::new(SignedError(Code::RequestMismatch)))
        }
        Some(r) if now > r.exp => Err(anyhow::Error::new(SignedError(Code::SigExpired))),
        Some(_) => Ok(()),
    })
}

/// Replacement for `require_device_owner_auth` at the message commit point. Passes only
/// while [`process`] has a verified request installed for this thread, the room and
/// body about to be typed are byte-identical to it, and its window has not closed.
pub fn require_verified_send(room: &str, body: &str) -> anyhow::Result<()> {
    require_verified_send_at(room, body, now_unix())
}

/// Replacement for `require_device_owner_auth` at the photo commit point: signed
/// requests carry text only, so a photo send is never authorised.
pub fn require_verified_photo() -> anyhow::Result<()> {
    Err(anyhow::Error::new(SignedError(Code::PhotoUnsupported)))
}

/// Map a sender-side error to a [`Code`] without exposing its text (upstream messages
/// embed the room name).
pub fn classify_send_error(err: &anyhow::Error) -> Code {
    if let Some(s) = err.downcast_ref::<SignedError>() {
        return s.0;
    }
    let text = format!("{err:#}");
    // Fixed substrings of the upstream English messages (src/ax_send.rs); the first
    // match wins, so the more specific patterns come first. Several upstream messages
    // embed the room name: only the code is ever printed, never this text.
    const RULES: &[(&[&str], Code)] = &[
        (&["KakaoTalk is not running"], Code::KakaoNotRunning),
        (
            &["Accessibility permission is not granted"],
            Code::AxNotTrusted,
        ),
        (
            &[
                "signing identity is not",
                "multiple authentic KakaoTalk processes",
            ],
            Code::KakaoIdentityRejected,
        ),
        (
            &["main chat-list window is minimized"],
            Code::MainWindowMinimized,
        ),
        (
            &["could not find KakaoTalk's main chat-list window"],
            Code::MainWindowMissing,
        ),
        (&["could not find chat list table"], Code::ChatListMissing),
        (
            &["AX snapshot exceeded its safety budget"],
            Code::AxSnapshotBudget,
        ),
        (
            &["not found in visible/loaded chat list"],
            Code::ChatNotFound,
        ),
        (&["ambiguous, refusing to guess"], Code::ChatAmbiguous),
        (
            &["did not open with a readable composer in time"],
            Code::ComposerNotReady,
        ),
        (
            &["could not read the exact target's composer"],
            Code::ComposerUnreadable,
        ),
        (
            &["composer already contains a draft"],
            Code::ComposerHasDraft,
        ),
        (
            &[
                "is not AX-focusable",
                "focus support",
                "could not focus ",
                "could not verify focus on",
                "could not make KakaoTalk frontmost",
                "could not raise exact target window",
                "could not verify exact KakaoTalk target window focus",
            ],
            Code::FocusFailed,
        ),
        (
            &["could not set the exact target composer"],
            Code::ComposerWriteFailed,
        ),
        (
            &[
                "could not verify the exact message in the target composer",
                "the exact target composer changed before commit",
            ],
            Code::ComposerVerifyFailed,
        ),
        (
            &[
                "did not become AX-visible",
                "failed to select chat row",
                "failed to verify selected chat row",
                "selected chat row could not be read back",
                "selected chat row did not match",
                "failed to open exact chat row",
                "failed to confirm the exact selected chat row",
                "double-click fallback failed",
                "could not bring KakaoTalk to the front",
                "KakaoTalk did not become frontmost",
            ],
            Code::ChatOpenFailed,
        ),
    ];
    for (needles, code) in RULES {
        if needles.iter().any(|n| text.contains(n)) {
            return *code;
        }
    }
    Code::AxFailed
}

/// Verify a request and, only if every check passes, run `send` (the sole AX contact).
///
/// * `key`: reads the verification key (called only after the request parsed and
///   carries a signature).
/// * `gate`: fills the per-request allowlist (`allowed_send_chats` = this request's
///   room) and runs the original gates; failing it burns the request id.
/// * `send`: performs the AX send; it runs with the verified request installed so the
///   commit-point guard [`require_verified_send`] can pass.
pub fn process<K, G, S>(raw: &[u8], now: i64, ledger_dir: &Path, key: K, gate: G, send: S) -> Code
where
    K: FnOnce() -> Result<Zeroizing<Vec<u8>>, Code>,
    G: FnOnce(&Request) -> anyhow::Result<()>,
    S: FnOnce(&Request) -> anyhow::Result<Delivery>,
{
    let (req, sig) = match parse(raw) {
        Ok(v) => v,
        Err(e) => return e.0,
    };
    let key = match key() {
        Ok(k) => k,
        Err(c) => return c,
    };
    if let Err(e) = verify(&req, &sig, &key, now) {
        return e.0;
    }
    if let Err(e) = consume_request_id(ledger_dir, &req.id, req.iat, now) {
        return e.0;
    }
    if gate(&req).is_err() {
        return Code::AllowlistDenied;
    }
    let _ctx = ContextGuard::install(&req);
    match send(&req) {
        Ok(Delivery::Verified) => Code::Sent,
        Ok(Delivery::Uncertain) => Code::SendUncertain,
        Err(e) => classify_send_error(&e),
    }
}

/// Cap for the title list `ax-match` accepts on stdin.
pub const MAX_MATCH_TITLES: usize = 5000;

/// Counts only; never a title. See [`count_matches`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchCounts {
    /// Distinct non-empty titles that were given.
    pub given: usize,
    /// Given titles that match exactly one chat-list row.
    pub exact: usize,
    /// Given titles that match two or more chat-list rows.
    pub dup: usize,
    /// Given titles that match no chat-list row.
    pub missing: usize,
    /// Chat-list rows that were read (loaded rows only).
    pub app_rows: usize,
    /// Distinct chat-list names that are not among the given titles.
    pub app_only: usize,
}

/// Parse the stdin of `ax-match`: one JSON string per line (blank lines ignored),
/// de-duplicated, at most [`MAX_MATCH_TITLES`] and [`MAX_REQUEST_BYTES`] * 16 bytes.
/// Any problem is `ReqMalformed`; no input text ever reaches an error.
pub fn parse_titles(raw: &[u8]) -> Result<Vec<String>, Code> {
    if raw.is_empty() || raw.len() > MAX_REQUEST_BYTES * 16 {
        return Err(Code::ReqMalformed);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Code::ReqMalformed)?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let title: String = serde_json::from_str(line).map_err(|_| Code::ReqMalformed)?;
        if title.is_empty() || !seen.insert(title.clone()) {
            continue;
        }
        out.push(title);
        if out.len() > MAX_MATCH_TITLES {
            return Err(Code::ReqMalformed);
        }
    }
    if out.is_empty() {
        return Err(Code::ReqMalformed);
    }
    Ok(out)
}

/// Exact (byte-for-byte) comparison of given titles with the chat-list names.
pub fn count_matches(app_names: &[String], given: &[String]) -> MatchCounts {
    let mut app: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for n in app_names {
        *app.entry(n.as_str()).or_insert(0) += 1;
    }
    let given_set: std::collections::HashSet<&str> = given.iter().map(String::as_str).collect();
    let (mut exact, mut dup, mut missing) = (0, 0, 0);
    for t in &given_set {
        match app.get(t).copied().unwrap_or(0) {
            0 => missing += 1,
            1 => exact += 1,
            _ => dup += 1,
        }
    }
    let app_only = app.keys().filter(|k| !given_set.contains(*k)).count();
    MatchCounts {
        given: given_set.len(),
        exact,
        dup,
        missing,
        app_rows: app_names.len(),
        app_only,
    }
}

/// The single stdout line of a successful `ax-match`: digits and fixed words only.
pub fn format_counts(c: &MatchCounts) -> String {
    format!(
        "MATCH_COUNTS given={} exact={} dup={} missing={} app_rows={} app_only={}",
        c.given, c.exact, c.dup, c.missing, c.app_rows, c.app_only
    )
}

/// Read the HMAC key (64 hex chars stored as the generic-password data) from the
/// login keychain via the native helper. Never prompts: `Code::KeyAccessDenied` if
/// the item would need user interaction.
#[cfg(target_os = "macos")]
pub fn read_hmac_key() -> Result<Zeroizing<Vec<u8>>, Code> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    unsafe extern "C" {
        fn openkakao_read_keychain_secret(
            service_utf8: *const c_char,
            account_utf8: *const c_char,
            out: *mut u8,
            cap: usize,
            out_len: *mut usize,
        ) -> c_int;
    }

    let service = CString::new(KEYCHAIN_SERVICE).map_err(|_| Code::KeyUnavailable)?;
    let account = CString::new(KEYCHAIN_ACCOUNT).map_err(|_| Code::KeyUnavailable)?;
    let mut buf = Zeroizing::new(vec![0u8; 256]);
    let mut len: usize = 0;
    let status = unsafe {
        openkakao_read_keychain_secret(
            service.as_ptr(),
            account.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut len,
        )
    };
    match status {
        0 => {}
        1 => return Err(Code::KeyNotFound),
        2 => return Err(Code::KeyAccessDenied),
        _ => return Err(Code::KeyUnavailable),
    }
    if len > buf.len() {
        return Err(Code::KeyUnavailable);
    }
    let text = std::str::from_utf8(&buf[..len]).map_err(|_| Code::KeyUnavailable)?;
    let decoded = hex::decode(text.trim()).map_err(|_| Code::KeyUnavailable)?;
    if decoded.len() < MIN_KEY_BYTES {
        return Err(Code::KeyUnavailable);
    }
    Ok(Zeroizing::new(decoded))
}

#[cfg(not(target_os = "macos"))]
pub fn read_hmac_key() -> Result<Zeroizing<Vec<u8>>, Code> {
    Err(Code::KeyUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    const NOW: i64 = 1_793_119_000;
    const KEY: [u8; 32] = [7u8; 32];
    const CANARY_ROOM: &str = "room-canary-\u{00e9}";
    const CANARY_BODY: &str = "msgcap-test-canary body";

    fn request(iat: i64) -> Request {
        Request {
            platform: "kakaotalk".into(),
            room: CANARY_ROOM.into(),
            body: CANARY_BODY.into(),
            id: "req-0001-abcd".into(),
            iat,
            exp: iat + TTL_SECS,
            confirm: "ab".repeat(32),
        }
    }

    fn sign(r: &Request, key: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(&canonical(r));
        hex::encode(mac.finalize().into_bytes())
    }

    fn wire(r: &Request, sig: Option<&str>) -> Vec<u8> {
        let mut v = serde_json::json!({
            "v": 1, "platform": r.platform, "room": r.room, "body": r.body, "id": r.id,
            "iat": r.iat, "exp": r.exp, "confirm": r.confirm,
        });
        if let Some(s) = sig {
            v["sig"] = serde_json::Value::String(s.to_string());
        }
        serde_json::to_vec(&v).unwrap()
    }

    fn signed(r: &Request) -> Vec<u8> {
        wire(r, Some(&sign(r, &KEY)))
    }

    #[derive(Default)]
    struct Counters {
        key: Cell<u32>,
        gate: Cell<u32>,
        send: Cell<u32>,
    }

    fn run(raw: &[u8], now: i64, dir: &Path, c: &Counters) -> Code {
        process(
            raw,
            now,
            dir,
            || {
                c.key.set(c.key.get() + 1);
                Ok(Zeroizing::new(KEY.to_vec()))
            },
            |_| {
                c.gate.set(c.gate.get() + 1);
                Ok(())
            },
            |r| {
                c.send.set(c.send.get() + 1);
                // Propagate a guard failure exactly like the real commit point would.
                require_verified_send_at(&r.room, &r.body, now)?;
                Ok(Delivery::Verified)
            },
        )
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn python_interop_vector() {
        // Independently computed with Python hmac/hashlib (see tasks 1.3 notes).
        let key: Vec<u8> = (0..32u8)
            .map(|i| {
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                ][i as usize]
            })
            .collect();
        let r = Request {
            platform: "kakaotalk".into(),
            room: "room-\u{00e9}\u{3131}".into(),
            body: "msgcap-test-123\nline2".into(),
            id: "req-0001-abcd".into(),
            iat: 1_793_119_000,
            exp: 1_793_119_600,
            confirm: "ab".repeat(32),
        };
        assert_eq!(
            sign(&r, &key),
            "25ce2471a520fc6064419be4ce7d07b0890a668e98bff5455ae3176bdcac5a2c"
        );
    }

    #[test]
    fn canonical_encoding_is_injective() {
        let mut a = request(NOW);
        let mut b = request(NOW);
        a.room = "ab".into();
        a.body = "c".into();
        b.room = "a".into();
        b.body = "bc".into();
        assert_ne!(canonical(&a), canonical(&b));
    }

    #[test]
    fn valid_request_sends_once_with_context_then_clears_it() {
        let dir = tmp();
        let c = Counters::default();
        let r = request(NOW);
        assert_eq!(run(&signed(&r), NOW, dir.path(), &c), Code::Sent);
        assert_eq!((c.key.get(), c.gate.get(), c.send.get()), (1, 1, 1));
        // After process returns, the commit-point guard no longer passes.
        let after = require_verified_send_at(&r.room, &r.body, NOW).unwrap_err();
        assert_eq!(
            classify_send_error(&after),
            Code::NoVerifiedRequest,
            "context must not outlive process()"
        );
    }

    #[test]
    fn uncertain_delivery_maps_to_its_own_code() {
        let dir = tmp();
        let code = process(
            &signed(&request(NOW)),
            NOW,
            dir.path(),
            || Ok(Zeroizing::new(KEY.to_vec())),
            |_| Ok(()),
            |_| Ok(Delivery::Uncertain),
        );
        assert_eq!(code, Code::SendUncertain);
    }

    fn assert_rejected(raw: &[u8], now: i64, expect: Code, key_calls: u32) {
        let dir = tmp();
        let c = Counters::default();
        assert_eq!(run(raw, now, dir.path(), &c), expect);
        assert_eq!(c.send.get(), 0, "AX sender must not be reached");
        assert_eq!(c.gate.get(), 0, "gate must not be reached");
        assert_eq!(c.key.get(), key_calls);
    }

    #[test]
    fn missing_signature_is_rejected_before_key_and_ax() {
        assert_rejected(&wire(&request(NOW), None), NOW, Code::SigMissing, 0);
        assert_rejected(&wire(&request(NOW), Some("")), NOW, Code::SigMissing, 0);
    }

    #[test]
    fn wrong_key_signature_is_a_mismatch() {
        let r = request(NOW);
        let sig = sign(&r, &[9u8; 32]);
        assert_rejected(&wire(&r, Some(&sig)), NOW, Code::SigMismatch, 1);
        assert_rejected(&wire(&r, Some("zz")), NOW, Code::SigMismatch, 1);
        assert_rejected(&wire(&r, Some(&"0".repeat(64))), NOW, Code::SigMismatch, 1);
    }

    #[test]
    fn one_byte_tamper_of_any_signed_field_is_a_mismatch() {
        let r = request(NOW);
        let sig = sign(&r, &KEY);
        let mut t = r.clone();
        t.body = "msgcap-test-canary bodz".into();
        assert_rejected(&wire(&t, Some(&sig)), NOW, Code::SigMismatch, 1);
        let mut t = r.clone();
        t.room = "room-canary-f".into();
        assert_rejected(&wire(&t, Some(&sig)), NOW, Code::SigMismatch, 1);
        let mut t = r.clone();
        t.id = "req-0002-abcd".into();
        assert_rejected(&wire(&t, Some(&sig)), NOW, Code::SigMismatch, 1);
        let mut t = r.clone();
        t.confirm = format!("{}ac", "ab".repeat(31));
        assert_rejected(&wire(&t, Some(&sig)), NOW, Code::SigMismatch, 1);
        let mut t = r.clone();
        t.iat += 1;
        t.exp += 1;
        assert_rejected(&wire(&t, Some(&sig)), NOW, Code::SigMismatch, 1);
    }

    #[test]
    fn window_boundaries() {
        // Issued exactly 600 s ago: still valid. 601 s ago: expired.
        let dir = tmp();
        let c = Counters::default();
        let ok = request(NOW - 600);
        assert_eq!(run(&signed(&ok), NOW, dir.path(), &c), Code::Sent);
        assert_rejected(&signed(&request(NOW - 601)), NOW, Code::SigExpired, 1);
        // iat up to 60 s ahead of this clock is tolerated, 61 s is not.
        let dir = tmp();
        let c = Counters::default();
        assert_eq!(
            run(&signed(&request(NOW + 60)), NOW, dir.path(), &c),
            Code::Sent
        );
        assert_rejected(&signed(&request(NOW + 61)), NOW, Code::SigNotYetValid, 1);
    }

    #[test]
    fn replay_is_rejected_and_remembered_across_processes() {
        let dir = tmp();
        let r = request(NOW);
        let raw = signed(&r);
        let c1 = Counters::default();
        assert_eq!(run(&raw, NOW, dir.path(), &c1), Code::Sent);
        // "New process": fresh counters, same ledger directory.
        let c2 = Counters::default();
        assert_eq!(run(&raw, NOW + 1, dir.path(), &c2), Code::SigReplay);
        assert_eq!(c2.send.get(), 0);
        assert_eq!(c2.gate.get(), 0);
        // A different request id is independent.
        let mut other = request(NOW);
        other.id = "req-0002-abcd".into();
        assert_eq!(run(&signed(&other), NOW, dir.path(), &c2), Code::Sent);
    }

    #[test]
    fn ledger_holds_hashes_and_times_only() {
        let base = tmp();
        // A directory that does not exist yet, so the code under test creates it.
        let ledger = base.path().join("state").join("signed-requests");
        let c = Counters::default();
        assert_eq!(run(&signed(&request(NOW)), NOW, &ledger, &c), Code::Sent);
        let seen = fs::read_to_string(ledger.join("seen")).unwrap();
        for needle in [CANARY_ROOM, CANARY_BODY, "req-0001-abcd", &"ab".repeat(32)] {
            assert!(!seen.contains(needle), "ledger leaked plaintext");
        }
        let line = seen.trim_end();
        let (h, t) = line.split_once(' ').unwrap();
        assert!(is_lower_hex(h, 64));
        assert_eq!(t, NOW.to_string());
        for f in ["seen", "lock"] {
            let mode = fs::metadata(ledger.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
        for d in [&ledger, ledger.parent().unwrap()] {
            let mode = fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "dirs created by the ledger must be 0700");
        }
        assert!(
            !ledger.join("seen.tmp").exists(),
            "no temp file left behind"
        );
    }

    #[test]
    fn ledger_forgets_entries_after_they_can_no_longer_pass() {
        let dir = tmp();
        consume_request_id(dir.path(), "old-id-0001", NOW, NOW).unwrap();
        let later = NOW + TTL_SECS + FUTURE_SKEW_SECS + 1;
        consume_request_id(dir.path(), "new-id-0001", later, later).unwrap();
        let seen = fs::read_to_string(dir.path().join("seen")).unwrap();
        assert_eq!(seen.lines().count(), 1, "old entry should have been pruned");
        assert!(seen.contains(&id_hash("new-id-0001")));
    }

    #[test]
    fn replay_inside_window_still_rejected_at_the_edge() {
        let dir = tmp();
        consume_request_id(dir.path(), "edge-id-0001", NOW, NOW).unwrap();
        let edge = NOW + TTL_SECS + FUTURE_SKEW_SECS;
        assert_eq!(
            consume_request_id(dir.path(), "edge-id-0001", NOW, edge)
                .unwrap_err()
                .0,
            Code::SigReplay
        );
    }

    #[test]
    fn malformed_requests() {
        for raw in [
            &b""[..],
            b"not json",
            b"{}",
            br#"{"v":1,"sig":"aa","extra":1}"#,
        ] {
            let dir = tmp();
            let c = Counters::default();
            let code = run(raw, NOW, dir.path(), &c);
            assert!(
                matches!(code, Code::ReqMalformed | Code::SigMissing),
                "{code:?}"
            );
            assert_eq!(c.send.get(), 0);
            assert_eq!(c.key.get(), 0);
        }
        // Unknown extra field is rejected even if otherwise valid and signed.
        let r = request(NOW);
        let mut v: serde_json::Value = serde_json::from_slice(&signed(&r)).unwrap();
        v["extra"] = serde_json::json!(1);
        assert_rejected(&serde_json::to_vec(&v).unwrap(), NOW, Code::ReqMalformed, 0);
        // exp must equal iat + 600; whitespace-only body; bad id; bad confirm.
        let mut t = request(NOW);
        t.exp += 1;
        assert_rejected(&signed(&t), NOW, Code::ReqMalformed, 0);
        let mut t = request(NOW);
        t.body = "  \n".into();
        assert_rejected(&signed(&t), NOW, Code::ReqMalformed, 0);
        let mut t = request(NOW);
        t.id = "a b".into();
        assert_rejected(&signed(&t), NOW, Code::ReqMalformed, 0);
        let mut t = request(NOW);
        t.confirm = "AB".repeat(32);
        assert_rejected(&signed(&t), NOW, Code::ReqMalformed, 0);
        assert_rejected(
            &vec![b'x'; MAX_REQUEST_BYTES + 1],
            NOW,
            Code::ReqMalformed,
            0,
        );
    }

    #[test]
    fn other_platforms_are_not_sent_even_when_signed() {
        let mut t = request(NOW);
        t.platform = "instagram".into();
        assert_rejected(&signed(&t), NOW, Code::PlatformUnsupported, 0);
    }

    #[test]
    fn key_provider_failures_are_distinct_codes_and_block_the_send() {
        for (provided, expect) in [
            (Code::KeyNotFound, Code::KeyNotFound),
            (Code::KeyAccessDenied, Code::KeyAccessDenied),
            (Code::KeyUnavailable, Code::KeyUnavailable),
        ] {
            let dir = tmp();
            let sent = Cell::new(0);
            let code = process(
                &signed(&request(NOW)),
                NOW,
                dir.path(),
                || Err(provided),
                |_| Ok(()),
                |_| {
                    sent.set(1);
                    Ok(Delivery::Verified)
                },
            );
            assert_eq!(code, expect);
            assert_eq!(sent.get(), 0);
        }
        // A too-short key is refused.
        let dir = tmp();
        let code = process(
            &signed(&request(NOW)),
            NOW,
            dir.path(),
            || Ok(Zeroizing::new(vec![1u8; 8])),
            |_| Ok(()),
            |_| Ok(Delivery::Verified),
        );
        assert_eq!(code, Code::KeyUnavailable);
    }

    #[test]
    fn gate_denial_blocks_the_send_and_burns_the_id() {
        let dir = tmp();
        let sent = Cell::new(0);
        let raw = signed(&request(NOW));
        let code = process(
            &raw,
            NOW,
            dir.path(),
            || Ok(Zeroizing::new(KEY.to_vec())),
            |_| Err(anyhow::anyhow!("denied")),
            |_| {
                sent.set(1);
                Ok(Delivery::Verified)
            },
        );
        assert_eq!(code, Code::AllowlistDenied);
        assert_eq!(sent.get(), 0);
        let c = Counters::default();
        assert_eq!(run(&raw, NOW, dir.path(), &c), Code::SigReplay);
    }

    #[test]
    fn commit_point_guard_requires_context_and_exact_match() {
        let none = require_verified_send_at("r", "b", NOW).unwrap_err();
        assert_eq!(classify_send_error(&none), Code::NoVerifiedRequest);
        let r = request(NOW);
        let _g = ContextGuard::install(&r);
        assert!(require_verified_send_at(&r.room, &r.body, NOW).is_ok());
        let mismatch = require_verified_send_at(&r.room, "other body", NOW).unwrap_err();
        assert_eq!(classify_send_error(&mismatch), Code::RequestMismatch);
        let mismatch = require_verified_send_at("other room", &r.body, NOW).unwrap_err();
        assert_eq!(classify_send_error(&mismatch), Code::RequestMismatch);
        let late = require_verified_send_at(&r.room, &r.body, r.exp + 1).unwrap_err();
        assert_eq!(classify_send_error(&late), Code::SigExpired);
    }

    #[test]
    fn photo_commit_point_is_never_authorised() {
        let r = request(NOW);
        let _g = ContextGuard::install(&r);
        let e = require_verified_photo().unwrap_err();
        assert_eq!(classify_send_error(&e), Code::PhotoUnsupported);
    }

    #[test]
    fn send_errors_are_classified_without_exposing_text() {
        let cases = [
            (
                "KakaoTalk is not running (or `x` not found) — open it",
                Code::KakaoNotRunning,
            ),
            (
                "Accessibility permission is not granted to this terminal app.",
                Code::AxNotTrusted,
            ),
            (
                "chat 'X' not found in visible/loaded chat list",
                Code::ChatNotFound,
            ),
            (
                "chat name 'X' matches 2 chats in the visible list — ambiguous, refusing to guess",
                Code::ChatAmbiguous,
            ),
            ("something else entirely", Code::AxFailed),
            (
                "a process named KakaoTalk is running, but its bundle signing identity is not com.x/Y; refusing AX access",
                Code::KakaoIdentityRejected,
            ),
            (
                "multiple authentic KakaoTalk processes are running; refusing to choose an AX target",
                Code::KakaoIdentityRejected,
            ),
            (
                "KakaoTalk's main chat-list window is minimized. Restoring it automatically risks stealing your foreground focus",
                Code::MainWindowMinimized,
            ),
            (
                "could not find KakaoTalk's main chat-list window. Make sure it's open, not minimized",
                Code::MainWindowMissing,
            ),
            (
                "could not find chat list table in KakaoTalk's AX tree",
                Code::ChatListMissing,
            ),
            (
                "KakaoTalk AX snapshot exceeded its safety budget (1 nodes in 1.0s; limits: depth 128, nodes 20000, time 30s); refusing incomplete UI data.",
                Code::AxSnapshotBudget,
            ),
            (
                "chat name 'X' matches 2 open windows exactly — ambiguous, refusing to guess",
                Code::ChatAmbiguous,
            ),
            (
                "exact chat window 'X' did not open with a readable composer in time",
                Code::ComposerNotReady,
            ),
            (
                "could not read the exact target's composer before commit; refusing to type blindly",
                Code::ComposerUnreadable,
            ),
            (
                "the exact target's composer already contains a draft; refusing to overwrite or append to it",
                Code::ComposerHasDraft,
            ),
            (
                "exact target composer is not AX-focusable; refusing synthetic key delivery",
                Code::FocusFailed,
            ),
            (
                "could not focus exact target composer: AXError",
                Code::FocusFailed,
            ),
            (
                "could not verify focus on exact target composer immediately before commit; refusing synthetic key delivery",
                Code::FocusFailed,
            ),
            (
                "could not focus exact target window before composer write: could not make KakaoTalk frontmost: AXError",
                Code::FocusFailed,
            ),
            (
                "could not raise exact target window: AXError",
                Code::FocusFailed,
            ),
            (
                "could not verify exact KakaoTalk target window focus",
                Code::FocusFailed,
            ),
            (
                "could not set the exact target composer: AXError",
                Code::ComposerWriteFailed,
            ),
            (
                "could not verify the exact message in the target composer; Return was not pressed",
                Code::ComposerVerifyFailed,
            ),
            (
                "the exact target composer changed before commit; Return was not pressed",
                Code::ComposerVerifyFailed,
            ),
            (
                "exact chat selected from KakaoTalk's Window menu did not become AX-visible",
                Code::ChatOpenFailed,
            ),
            (
                "failed to open exact chat row with AXPress: AXError",
                Code::ChatOpenFailed,
            ),
            (
                "the exact selected KakaoTalk chat row exposes no element-scoped open action, and the hit-tested double-click fallback failed: x",
                Code::ChatOpenFailed,
            ),
        ];
        for (text, expect) in cases {
            assert_eq!(
                classify_send_error(&anyhow::anyhow!(text.to_string())),
                expect
            );
        }
    }

    #[test]
    fn match_counts_classify_exact_duplicate_and_missing_without_titles() {
        let app: Vec<String> = [
            "room-canary-A",
            "room-canary-B",
            "room-canary-B",
            "only-in-app",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let given: Vec<String> = ["room-canary-A", "room-canary-B", "room-canary-C"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let c = count_matches(&app, &given);
        assert_eq!(
            c,
            MatchCounts {
                given: 3,
                exact: 1,
                dup: 1,
                missing: 1,
                app_rows: 4,
                app_only: 1
            }
        );
        let line = format_counts(&c);
        assert_eq!(
            line,
            "MATCH_COUNTS given=3 exact=1 dup=1 missing=1 app_rows=4 app_only=1"
        );
        assert!(
            !line.contains("canary"),
            "title text leaked into the output line"
        );
        // Exact bytes only: no trimming or case folding.
        let c2 = count_matches(
            &["Room".to_string()],
            &["room".to_string(), "Room ".to_string()],
        );
        assert_eq!((c2.exact, c2.missing, c2.app_only), (0, 2, 1));
    }

    #[test]
    fn parse_titles_accepts_json_lines_dedupes_and_rejects_bad_input_without_text() {
        let ok = parse_titles("\"a\"\n\n\"b\"\n\"a\"\n\"\"\n".as_bytes()).unwrap();
        assert_eq!(ok, vec!["a".to_string(), "b".to_string()]);
        let unicode = parse_titles("\"\\uac00\\ub098\"\n".as_bytes()).unwrap();
        assert_eq!(unicode, vec!["\u{ac00}\u{b098}".to_string()]);
        for bad in [
            &b""[..],
            b"not json\n",
            b"1\n",
            b"[\"a\"]\n",
            b"\"\"\n",
            &[0xff, 0xfe][..],
        ] {
            assert_eq!(parse_titles(bad).unwrap_err(), Code::ReqMalformed);
        }
        let many: String = (0..=MAX_MATCH_TITLES)
            .map(|i| format!("\"t{i}\"\n"))
            .collect();
        assert_eq!(
            parse_titles(many.as_bytes()).unwrap_err(),
            Code::ReqMalformed
        );
        let at_cap: String = (0..MAX_MATCH_TITLES)
            .map(|i| format!("\"t{i}\"\n"))
            .collect();
        assert_eq!(
            parse_titles(at_cap.as_bytes()).unwrap().len(),
            MAX_MATCH_TITLES
        );
    }

    #[test]
    fn code_names_are_unique_upper_snake_and_exit_codes_distinct() {
        let all = [
            Code::Sent,
            Code::ProbeOk,
            Code::AxTrusted,
            Code::ReqMalformed,
            Code::PlatformUnsupported,
            Code::SigMissing,
            Code::SigMismatch,
            Code::SigExpired,
            Code::SigNotYetValid,
            Code::SigReplay,
            Code::KeyNotFound,
            Code::KeyAccessDenied,
            Code::KeyUnavailable,
            Code::LedgerError,
            Code::NoVerifiedRequest,
            Code::RequestMismatch,
            Code::PhotoUnsupported,
            Code::AllowlistDenied,
            Code::SendUncertain,
            Code::ChatNotFound,
            Code::ChatAmbiguous,
            Code::KakaoNotRunning,
            Code::AxNotTrusted,
            Code::AxFailed,
            Code::KakaoIdentityRejected,
            Code::MainWindowMinimized,
            Code::MainWindowMissing,
            Code::ChatListMissing,
            Code::AxSnapshotBudget,
            Code::ChatOpenFailed,
            Code::ComposerNotReady,
            Code::ComposerUnreadable,
            Code::ComposerHasDraft,
            Code::FocusFailed,
            Code::ComposerWriteFailed,
            Code::ComposerVerifyFailed,
        ];
        let mut names = std::collections::HashSet::new();
        let mut exits = std::collections::HashSet::new();
        for c in all {
            assert!(c
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'_'));
            assert!(names.insert(c.as_str()));
            // Success-like codes share exit status 0; every failure has its own.
            if c.exit_code() != 0 {
                assert!(exits.insert(c.exit_code()));
            }
        }
        for ok in [Code::Sent, Code::ProbeOk, Code::AxTrusted] {
            assert_eq!(ok.exit_code(), 0);
        }
    }
}
