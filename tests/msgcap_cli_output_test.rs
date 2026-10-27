//! The msgcap commands print one result code and never echo their input.
//! Only inputs rejected before any AX contact are used here (no KakaoTalk access).

use assert_cmd::Command;

const CANARY: &str = "room-canary-\u{ac00}\u{b098}";

fn run(subcommand: &str, stdin: &[u8]) -> (String, String, Option<i32>) {
    let out = Command::cargo_bin("openkakao-cli")
        .unwrap()
        .arg(subcommand)
        .write_stdin(stdin.to_vec())
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

#[test]
fn ax_match_rejects_bad_input_with_only_a_code() {
    let not_json = format!("{CANARY}\n");
    let empty_title = "\"\"\n".to_string();
    for input in [not_json.as_bytes(), b"", empty_title.as_bytes()] {
        let (stdout, stderr, code) = run("ax-match", input);
        assert_eq!(stdout, "REQ_MALFORMED\n");
        assert_eq!(stderr, "");
        assert_eq!(code, Some(20));
    }
}

#[test]
fn signed_send_rejects_unsigned_or_bad_input_with_only_a_code_and_never_echoes_it() {
    let (stdout, stderr, code) = run("signed-send", format!("{CANARY}\n").as_bytes());
    assert_eq!(
        (stdout.as_str(), stderr.as_str(), code),
        ("REQ_MALFORMED\n", "", Some(20))
    );

    let unsigned = format!(
        "{{\"v\":1,\"platform\":\"kakaotalk\",\"room\":\"{CANARY}\",\"body\":\"{CANARY}\",\
         \"id\":\"req-canary-0001\",\"iat\":1,\"exp\":601,\"confirm\":\"{}\"}}",
        "ab".repeat(32)
    );
    let (stdout, stderr, code) = run("signed-send", unsigned.as_bytes());
    assert_eq!(
        (stdout.as_str(), stderr.as_str(), code),
        ("SIG_MISSING\n", "", Some(22))
    );
    assert!(!stdout.contains("canary") && !stderr.contains("canary"));
}
