//! Integration tests using `smbclient` to verify real SMB2 protocol interactions.
//!
//! These tests require:
//! 1. The SMB server binary built with `--features server`
//! 2. `smbclient` installed and available on `$PATH`
//!
//! The test harness spawns the server on a random port, runs smbclient commands
//! against it, and asserts on the output / exit codes.
//!
//! Run with: `cargo test --test smbclient --features server`
//!
//! These tests are `#[ignore]`d by default so they don't run in normal CI
//! without the server binary. Use `cargo test --test smbclient --features server -- --ignored`
//! to run them explicitly.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Find a free TCP port by binding to port 0.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to free port");
    listener.local_addr().unwrap().port()
}

/// Spawn the SMB server on the given port and return the child process.
/// Waits briefly for the server to start listening.
fn spawn_server(port: u16) -> Child {
    let server_bin = env!("CARGO_BIN_EXE_spin_server_up");
    let child = Command::new(server_bin)
        .env("SMB_PORT", port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn SMB server binary");

    // Give the server time to bind
    std::thread::sleep(Duration::from_millis(500));
    child
}

/// Run an smbclient command and return (exit_status, stdout, stderr).
fn run_smbclient(args: &[&str]) -> (bool, String, String) {
    let output = Command::new("smbclient")
        .args(args)
        .output()
        .expect("Failed to run smbclient — is it installed?");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

// ---------------------------------------------------------------------------
// Negotiate / Connection Tests
// ---------------------------------------------------------------------------

/// Verify that smbclient can connect and perform SMB2 negotiation.
///
/// Expected: The server responds to the negotiate request. smbclient may
/// fail at a later stage (session setup, auth) but the negotiate itself
/// should succeed — indicated by smbclient progressing past the initial
/// connection phase.
#[test]
#[ignore]
fn negotiate_completes() {
    let port = free_port();
    let mut server = spawn_server(port);

    let (success, stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1:{}/share", port),
        "-N",  // no password
        "-m", "SMB2",
        "-c", "exit",
    ]);

    // smbclient may fail auth but should get past negotiate.
    // If negotiate itself fails, stderr typically contains "NT_STATUS_CONNECTION_REFUSED"
    // or "Connection to ... failed".
    let negotiate_failed = stderr.contains("Connection to") && stderr.contains("failed");
    assert!(
        !negotiate_failed,
        "smbclient should connect and negotiate. stderr: {}",
        stderr
    );

    server.kill().ok();
}

/// Verify that the server rejects connections with an unsupported dialect
/// gracefully (no crash).
#[test]
#[ignore]
fn server_does_not_crash_on_smb1_only() {
    let port = free_port();
    let mut server = spawn_server(port);

    // Force SMB1 only — server should handle gracefully
    let (_success, _stdout, _stderr) = run_smbclient(&[
        &format!("//127.0.0.1:{}/share", port),
        "-N",
        "-m", "NT1",
        "-c", "exit",
    ]);

    // Server should still be running (not crashed)
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after SMB1 connection attempt, but exited with: {:?}",
        status
    );

    server.kill().ok();
}

// ---------------------------------------------------------------------------
// Session Setup Tests
// ---------------------------------------------------------------------------

/// Verify that smbclient can attempt session setup with credentials.
///
/// Expected: The server processes the session setup request. Whether it
/// succeeds depends on the auth configuration, but the server should not
/// crash.
#[test]
#[ignore]
fn session_setup_with_credentials() {
    let port = free_port();
    let mut server = spawn_server(port);

    let (_success, _stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1:{}/share", port),
        "-U", "testuser%testpass",
        "-m", "SMB2",
        "-c", "exit",
    ]);

    // Server should not crash
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after session setup attempt. stderr: {}",
        stderr
    );

    server.kill().ok();
}

/// Verify that anonymous (no-auth) session setup is handled.
#[test]
#[ignore]
fn session_setup_anonymous() {
    let port = free_port();
    let mut server = spawn_server(port);

    let (_success, _stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1:{}/share", port),
        "-N",
        "-m", "SMB2",
        "-c", "exit",
    ]);

    // Server should not crash
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after anonymous session. stderr: {}",
        stderr
    );

    server.kill().ok();
}

// ---------------------------------------------------------------------------
// Tree Connect Tests
// ---------------------------------------------------------------------------

/// Verify that tree connect to a valid share name is attempted.
///
/// Expected: smbclient reaches the tree connect phase. The server may
/// reject it (e.g. due to signing issues) but should respond with a
/// proper NT status, not crash.
#[test]
#[ignore]
fn tree_connect_to_share() {
    let port = free_port();
    let mut server = spawn_server(port);

    let (_success, _stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1:{}/share", port),
        "-U", "testuser%testpass",
        "-m", "SMB2",
        "-c", "ls",
    ]);

    // Server should not crash
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after tree connect. stderr: {}",
        stderr
    );

    server.kill().ok();
}

/// Verify that tree connect to a nonexistent share returns an error.
#[test]
#[ignore]
fn tree_connect_nonexistent_share() {
    let port = free_port();
    let mut server = spawn_server(port);

    let (success, _stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1:{}/nonexistent_share_xyz", port),
        "-U", "testuser%testpass",
        "-m", "SMB2",
        "-c", "ls",
    ]);

    // Should fail (share doesn't exist)
    assert!(
        !success || stderr.contains("NT_STATUS_"),
        "Connecting to nonexistent share should fail. stderr: {}",
        stderr
    );

    server.kill().ok();
}

// ---------------------------------------------------------------------------
// Echo Tests
// ---------------------------------------------------------------------------

/// Verify that the server responds to an echo request without crashing.
///
/// Note: smbclient doesn't have a direct "echo" command, but we can
/// verify the server stays alive through multiple operations.
#[test]
#[ignore]
fn server_survives_multiple_connections() {
    let port = free_port();
    let mut server = spawn_server(port);

    // Make several connections in sequence
    for _ in 0..3 {
        let (_success, _stdout, _stderr) = run_smbclient(&[
            &format!("//127.0.0.1:{}/share", port),
            "-N",
            "-m", "SMB2",
            "-c", "exit",
        ]);
    }

    // Server should still be running
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should survive multiple sequential connections"
    );

    server.kill().ok();
}
