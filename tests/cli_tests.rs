use std::fs;
use std::io::Write;
use std::process::Command;

use tempfile::NamedTempFile;

/// Strip ANSI escape codes from string for test comparison.
fn strip_ansi(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until 'm'
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc == 'm' {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[test]
fn test_cli_with_prefix() {
    let result = Command::new("./target/debug/kitak")
        .args(["--btc", "-p", "tst"])
        .output()
        .expect("Failed to execute CLI command");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&result.stdout));
    assert!(
        stdout.to_ascii_lowercase().contains("1tst"),
        "Missing prefix in output: {}",
        stdout
    );
}

#[test]
fn test_cli_with_regex() {
    let result = Command::new("./target/debug/kitak")
        .args(["--btc", "-r", "^1E.*T$"])
        .output()
        .expect("Failed to execute CLI command");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&result.stdout));
    assert!(
        stdout.contains("1E"),
        "Missing regex match in output: {}",
        stdout
    );
}

#[test]
fn test_cli_with_output_file() {
    let output_file = "test_output.txt";

    let result = Command::new("./target/debug/kitak")
        .args(["--btc", "-o", output_file, "tst"])
        .output()
        .expect("Failed to execute CLI command");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let output = fs::read_to_string(output_file).expect("Failed to read output file");
    let clean = strip_ansi(&output);
    assert!(
        clean.to_ascii_lowercase().contains("1tst"),
        "Missing prefix in output file: {}",
        clean
    );

    fs::remove_file(output_file).expect("Failed to delete output file");
}

#[test]
fn test_cli_with_case_sensitivity() {
    let result = Command::new("./target/debug/kitak")
        .args(["--btc", "-c", "-a", "TST"])
        .output()
        .expect("Failed to execute CLI command");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&result.stdout));
    assert!(
        stdout.contains("TST"),
        "Missing case-sensitive match: {}",
        stdout
    );
}

#[test]
fn test_cli_missing_required_arguments() {
    let result = Command::new("./target/debug/kitak")
        .output()
        .expect("Failed to execute CLI command");

    assert!(!result.status.success(), "CLI succeeded unexpectedly");

    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("the following required arguments were not provided"),
        "Wrong error message: {}",
        stderr
    );
}

#[test]
fn test_cli_with_input_file_tempfile() {
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "t1 -p --btc\nT2 -c -p --btc").expect("Failed to write temp file");

    let input_file_path = temp_file.path().to_str().expect("Bad path");

    let result = Command::new("./target/debug/kitak")
        .args(["--btc", "-i", input_file_path])
        .output()
        .expect("Failed to execute CLI command");

    assert!(
        result.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let stdout = strip_ansi(&String::from_utf8_lossy(&result.stdout));
    assert!(
        stdout.to_lowercase().contains("1t1") && stdout.contains("1T2"),
        "Missing results: {}",
        stdout
    );
}
