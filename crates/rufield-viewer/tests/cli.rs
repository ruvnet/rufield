//! Process-level checks for fail-closed CLI configuration.
use std::process::Command;

#[test]
fn help_exits_without_starting_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_rufield-viewer"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--sensor-key"));
}

#[test]
fn invalid_configuration_exits_with_usage_error() {
    for args in [
        vec!["--sorce", "live"],
        vec!["--source"],
        vec!["--port", "70000"],
        vec!["--tick-ms", "invalid"],
        vec!["--source", "live"],
        vec!["--source", "live", "--upstream", "http://127.0.0.1:9"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rufield-viewer"))
            .env_clear()
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "arguments: {args:?}");
    }
}

#[test]
fn invalid_numeric_environment_is_not_silently_defaulted() {
    let output = Command::new(env!("CARGO_BIN_EXE_rufield-viewer"))
        .env_clear()
        .env("RUFIELD_VIEWER_SEED", "invalid")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
