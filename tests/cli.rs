use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const JWT_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
    mFiqJLxnKmlH9RNt-xVzKeZeIIHsxbsMf4Gveo1FV7w";
const SECRET_KEY: &str = "hello_world,hello,rust!";

#[test]
fn binary_cracks_with_file_inputs() {
    let temp_dir = TempDir::new("file_inputs");
    let token_path = temp_dir.path().join("tokens.txt");
    let key_path = temp_dir.path().join("keys.txt");
    fs::write(&token_path, format!("{JWT_TOKEN}\n")).expect("token fixture should be written");
    fs::write(&key_path, format!("wrong\n{SECRET_KEY}\n")).expect("key fixture should be written");

    let output = Command::new(binary_path())
        .args([
            "-t",
            token_path
                .to_str()
                .expect("token path should be valid UTF-8"),
            "-k",
            key_path.to_str().expect("key path should be valid UTF-8"),
            "-w",
            "2",
        ])
        .output()
        .expect("binary should run");

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains(&format!("MATCH token=\x1b[33m{JWT_TOKEN}\x1b[0m")));
    assert!(stdout.contains(&format!("key=\x1b[32m{SECRET_KEY}\x1b[0m")));
    assert!(stderr.contains("Loaded 1 token(s) from file and 2 key(s) from file."));
    assert!(stderr.contains(" total attempt(s) across 2 worker(s) in "));
}

#[test]
fn binary_cracks_with_secret_keys_from_stdin() {
    let mut child = Command::new(binary_path())
        .args(["-t", JWT_TOKEN, "-k", "-", "-w", "4"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(format!("wrong\n{SECRET_KEY}\n").as_bytes())
        .expect("stdin fixture should be written");

    let output = child.wait_with_output().expect("binary should finish");

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains(&format!("MATCH token=\x1b[33m{JWT_TOKEN}\x1b[0m")));
    assert!(stdout.contains(&format!("key=\x1b[32m{SECRET_KEY}\x1b[0m")));
    assert!(stderr.contains("Loaded 1 token(s) from direct input and 2 key(s) from stdin."));
    assert!(stderr.contains(" total attempt(s) across 2 worker(s) in "));
}

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_jwt_cracker")
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jwt_cracker_{name}_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir(&path).expect("temp dir should be created");
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
