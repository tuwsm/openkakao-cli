//! `signed-send`: the only send entry point of the msgcap fork.
//!
//! Reads one signed request from stdin (never argv), verifies it before any AX
//! contact, and prints a single result code line (no room, body or error text).
//!
//! Also two read-only diagnostics used to prove the AX origin of a launchd-started
//! process (`ax-trust`) and that the AX path reaches a chat (`ax-probe`); both print
//! a result code only.

use std::io::Read;

use openkakao_cli::signed_request::{self, Code, Delivery};

use crate::ax_send::{self, AxDeliveryOutcome};

/// `gate` receives the verified request's room and must fill the per-request
/// allowlist (`allowed_send_chats = [room]`, in memory only) and run the original
/// config gates. Returns the process exit code.
pub fn run<G>(gate: G) -> i32
where
    G: FnOnce(&str) -> anyhow::Result<()>,
{
    let code = run_inner(gate);
    println!("{}", code.as_str());
    code.exit_code()
}

fn run_inner<G>(gate: G) -> Code
where
    G: FnOnce(&str) -> anyhow::Result<()>,
{
    let mut raw = Vec::new();
    if std::io::stdin()
        .take(signed_request::MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .is_err()
    {
        return Code::ReqMalformed;
    }
    let Some(home) = dirs::home_dir() else {
        return Code::LedgerError;
    };
    let ledger = home
        .join(".config")
        .join("openkakao")
        .join("signed-requests");
    signed_request::process(
        &raw,
        signed_request::now_unix(),
        &ledger,
        signed_request::read_hmac_key,
        |req| gate(&req.room),
        |req| match ax_send::send_via_ax_classified(&req.room, &req.body)? {
            AxDeliveryOutcome::Verified => Ok(Delivery::Verified),
            AxDeliveryOutcome::Uncertain { .. } => Ok(Delivery::Uncertain),
        },
    )
}

/// `ax-trust`: whether *this process* is Accessibility-trusted. Never prompts and
/// never touches KakaoTalk (`AXIsProcessTrusted` only).
pub fn ax_trust() -> i32 {
    #[cfg(target_os = "macos")]
    let trusted = unsafe { accessibility_sys::AXIsProcessTrusted() };
    #[cfg(not(target_os = "macos"))]
    let trusted = false;
    let code = if trusted {
        Code::AxTrusted
    } else {
        Code::AxNotTrusted
    };
    println!("{}", code.as_str());
    code.exit_code()
}

/// `ax-probe <room-file>`: open the chat named in a file (mode 600, first line) and read
/// at most one visible message in memory, then print a result code only. The message and
/// the room name are never printed.
pub fn ax_probe(room_file: &str) -> i32 {
    let code = probe_inner(room_file);
    println!("{}", code.as_str());
    code.exit_code()
}

fn probe_inner(room_file: &str) -> Code {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(room_file) else {
        return Code::ReqMalformed;
    };
    if meta.permissions().mode() & 0o077 != 0 {
        return Code::ReqMalformed;
    }
    let Ok(text) = std::fs::read_to_string(room_file) else {
        return Code::ReqMalformed;
    };
    let room = text.lines().next().unwrap_or("").trim_end();
    if room.is_empty() {
        return Code::ReqMalformed;
    }
    match ax_send::read_via_ax(room, 1) {
        Ok(_) => Code::ProbeOk,
        Err(e) => signed_request::classify_send_error(&e),
    }
}

/// `ax-match`: read-only chat-list comparison. stdin = one JSON string per line (the
/// titles to look for); stdout = one `MATCH_COUNTS …` line of counts, or a result code.
/// The chat list is read without opening any chat (no unread/read state changes).
/// Titles and chat names are never printed, logged or put into an error.
pub fn ax_match() -> i32 {
    match match_inner() {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(code) => {
            println!("{}", code.as_str());
            code.exit_code()
        }
    }
}

fn match_inner() -> Result<String, Code> {
    let mut raw = Vec::new();
    std::io::stdin()
        .take(signed_request::MAX_REQUEST_BYTES as u64 * 16 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Code::ReqMalformed)?;
    let titles = signed_request::parse_titles(&raw)?;
    let rows = ax_send::scrape_chat_list().map_err(|e| signed_request::classify_send_error(&e))?;
    let names: Vec<String> = rows.into_iter().map(|row| row.name).collect();
    Ok(signed_request::format_counts(
        &signed_request::count_matches(&names, &titles),
    ))
}
