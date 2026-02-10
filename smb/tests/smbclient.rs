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

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Find a free TCP port by binding to port 0.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to free port");
    listener.local_addr().unwrap().port()
}

/// Spawn the SMB server on the given port and return the child process.
/// Polls the port until the server is accepting connections (up to 5 s).
fn spawn_server(port: u16) -> Child {
    let server_bin = env!("CARGO_BIN_EXE_spin_server_up");
    let child = Command::new(server_bin)
        .env("SMB_PORT", port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn SMB server binary");

    // Wait until the server is accepting TCP connections
    let addr = format!("127.0.0.1:{}", port);
    for _ in 0..50 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("Server did not start listening on {} within 5 seconds", addr);
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

    let port_str = port.to_string();
    let (_success, _stdout, stderr) = run_smbclient(&[
        "//127.0.0.1/share",
        "-p", &port_str,
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
    let port_str = port.to_string();
    let (_success, _stdout, _stderr) = run_smbclient(&[
        "//127.0.0.1/share",
        "-p", &port_str,
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

    let port_str = port.to_string();
    let (_success, _stdout, stderr) = run_smbclient(&[
        "//127.0.0.1/share",
        "-p", &port_str,
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

    let port_str = port.to_string();
    let (_success, _stdout, stderr) = run_smbclient(&[
        "//127.0.0.1/share",
        "-p", &port_str,
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

    let port_str = port.to_string();
    let (_success, _stdout, stderr) = run_smbclient(&[
        "//127.0.0.1/share",
        "-p", &port_str,
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

    let port_str = port.to_string();
    let (success, _stdout, stderr) = run_smbclient(&[
        "//127.0.0.1/nonexistent_share_xyz",
        "-p", &port_str,
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
// File Read Tests
// ---------------------------------------------------------------------------

/// Verify that smbclient can read a file from the share.
///
/// Expected: The server handles Create, Read, QueryInfo, and Close
/// without crashing. smbclient should be able to retrieve file contents.
#[test]
#[ignore]
fn file_read_does_not_crash_server() {
    use std::io::Write;

    let port = free_port();

    // Create a temp file in the server's working directory for the share to serve
    let tmp_dir = std::env::temp_dir().join(format!("smb_test_{}", port));
    std::fs::create_dir_all(&tmp_dir).expect("Failed to create temp dir");
    let test_file = tmp_dir.join("testfile.txt");
    {
        let mut f = std::fs::File::create(&test_file).expect("Failed to create test file");
        f.write_all(b"hello from smb server").expect("Failed to write test file");
    }

    // Start server with the share path pointing to our temp dir
    let server_bin = env!("CARGO_BIN_EXE_spin_server_up");
    let mut server = std::process::Command::new(server_bin)
        .env("SMB_PORT", port.to_string())
        .env("SMB_SHARE_PATH", tmp_dir.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn SMB server binary");

    // Wait for server to start
    let addr = format!("127.0.0.1:{}", port);
    for _ in 0..50 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let download_path = tmp_dir.join("downloaded.txt");
    let port_str = port.to_string();
    let download_str = download_path.to_str().unwrap().to_string();
    let get_cmd = format!("get testfile.txt {}", download_str);
    let (success, stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1/test"),
        "-p", &port_str,
        "-U", "tejasmehta%password",
        "-m", "SMB2",
        "-c", &get_cmd,
    ]);

    // Server should not crash
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after file read. stdout: {} stderr: {}",
        stdout, stderr
    );

    // Verify the file was downloaded and contents match
    assert!(success, "smbclient get should succeed. stdout: {} stderr: {}", stdout, stderr);
    let downloaded = std::fs::read(&download_path)
        .expect("Downloaded file should exist");
    assert_eq!(
        downloaded,
        b"hello from smb server",
        "Downloaded file contents should match the original"
    );

    server.kill().ok();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Verify that smbclient can list files (which triggers QueryInfo).
#[test]
#[ignore]
fn directory_listing_does_not_crash_server() {
    use std::io::Write;

    let port = free_port();

    let tmp_dir = std::env::temp_dir().join(format!("smb_test_ls_{}", port));
    std::fs::create_dir_all(&tmp_dir).expect("Failed to create temp dir");
    let test_file = tmp_dir.join("listing_test.txt");
    {
        let mut f = std::fs::File::create(&test_file).expect("Failed to create test file");
        f.write_all(b"test content").expect("Failed to write test file");
    }

    let server_bin = env!("CARGO_BIN_EXE_spin_server_up");
    let mut server = std::process::Command::new(server_bin)
        .env("SMB_PORT", port.to_string())
        .env("SMB_SHARE_PATH", tmp_dir.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn SMB server binary");

    let addr = format!("127.0.0.1:{}", port);
    for _ in 0..50 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let port_str = port.to_string();
    let (_success, _stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1/test"),
        "-p", &port_str,
        "-U", "tejasmehta%password",
        "-m", "SMB2",
        "-c", "ls",
    ]);

    // Server should not crash
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after directory listing. stderr: {}",
        stderr
    );

    server.kill().ok();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Verify that reading a nonexistent file returns an error without crashing.
#[test]
#[ignore]
fn read_nonexistent_file_returns_error() {
    let port = free_port();

    let tmp_dir = std::env::temp_dir().join(format!("smb_test_nofile_{}", port));
    std::fs::create_dir_all(&tmp_dir).expect("Failed to create temp dir");

    let server_bin = env!("CARGO_BIN_EXE_spin_server_up");
    let mut server = std::process::Command::new(server_bin)
        .env("SMB_PORT", port.to_string())
        .env("SMB_SHARE_PATH", tmp_dir.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn SMB server binary");

    let addr = format!("127.0.0.1:{}", port);
    for _ in 0..50 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let port_str = port.to_string();
    let (success, stdout, stderr) = run_smbclient(&[
        &format!("//127.0.0.1/test"),
        "-p", &port_str,
        "-U", "tejasmehta%password",
        "-m", "SMB2",
        "-c", "get nonexistent_file.txt /dev/null",
    ]);

    // Should fail (file doesn't exist)
    assert!(
        !success || stdout.contains("NT_STATUS_") || stderr.contains("NT_STATUS_"),
        "Reading nonexistent file should fail. stdout: {} stderr: {}",
        stdout, stderr
    );

    // Server should not crash
    std::thread::sleep(Duration::from_millis(200));
    let status = server.try_wait().expect("Failed to check server status");
    assert!(
        status.is_none(),
        "Server should still be running after failed file read. stderr: {}",
        stderr
    );

    server.kill().ok();
    let _ = std::fs::remove_dir_all(&tmp_dir);
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
        let port_str = port.to_string();
        let (_success, _stdout, _stderr) = run_smbclient(&[
            "//127.0.0.1/share",
            "-p", &port_str,
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
