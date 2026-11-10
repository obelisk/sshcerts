// Check that lines written by AllowedSigner::to_line() mean the same thing to OpenSSH's ssh-keygen.
// Skipped when ssh-keygen isn't installed.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sshcerts::ssh::AllowedSigner;
use sshcerts::PublicKey;

// Removed even when the test fails
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Run ssh-keygen in `dir`, with the message on stdin for -Y verify
fn ssh_keygen(dir: &Path, args: &[&str]) -> bool {
    Command::new("ssh-keygen")
        .args(args)
        .current_dir(dir)
        .stdin(File::open(dir.join("message")).unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn ssh_keygen_reads_allowed_signer_lines() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("ssh-keygen not found, skipping");
        return;
    }

    let temp_dir = TempDir(std::env::temp_dir().join(format!("sshcerts-allowed-signer-{}", std::process::id())));
    let dir = temp_dir.0.as_path();
    let _ = fs::remove_dir_all(dir);
    fs::create_dir(dir).unwrap();
    fs::write(dir.join("message"), "message").unwrap();

    // A key that signs in two namespaces, and a certificate for it signed by a CA
    for name in ["key", "ca"] {
        assert!(ssh_keygen(dir, &["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", name]));
    }
    assert!(ssh_keygen(dir, &["-q", "-s", "ca", "-I", "id", "-n", "alice", "key.pub"]));
    for (key, namespace, signature) in [("key", "git", "git.sig"), ("key", "file", "file.sig"), ("key-cert.pub", "git", "cert.sig")] {
        assert!(ssh_keygen(dir, &["-Y", "sign", "-q", "-f", key, "-n", namespace, "message"]));
        fs::rename(dir.join("message.sig"), dir.join(signature)).unwrap();
    }
    let key_line = fs::read_to_string(dir.join("key.pub")).unwrap();
    let key = PublicKey::from_string(&key_line).unwrap();
    let ca = PublicKey::from_string(&fs::read_to_string(dir.join("ca.pub")).unwrap()).unwrap();

    let signer = |principals: &[&str]| AllowedSigner {
        principals: principals.iter().map(|p| p.to_string()).collect(),
        cert_authority: false,
        namespaces: None,
        valid_after: None,
        valid_before: None,
        key: key.clone(),
    };
    let namespaces = Some(vec!["file".to_string(), "a\"b".to_string(), "c\\".to_string()]);

    // (entry, principal, namespace, signature, whether ssh-keygen should accept the signature)
    for (allowed_signer, principal, namespace, signature, expected) in [
        (signer(&["alice", "bob"]), "bob", "git", "git.sig", true),
        // Each character that needs the principals quoted
        (signer(&["alice smith"]), "alice smith", "git", "git.sig", true),
        (signer(&["alice\tsmith"]), "alice\tsmith", "git", "git.sig", true),
        (signer(&["alice\rsmith"]), "alice\rsmith", "git", "git.sig", true),
        (signer(&["#alice"]), "#alice", "git", "git.sig", true),
        // An escaped quote and a trailing backslash in namespaces
        (AllowedSigner { namespaces: namespaces.clone(), ..signer(&["alice"]) }, "alice", "file", "file.sig", true),
        (AllowedSigner { namespaces, ..signer(&["alice"]) }, "alice", "git", "git.sig", false),
        // Validity windows
        (AllowedSigner { valid_after: Some(946684800), valid_before: Some(253402300799), ..signer(&["alice"]) }, "alice", "git", "git.sig", true),
        (AllowedSigner { valid_before: Some(946684800), ..signer(&["alice"]) }, "alice", "git", "git.sig", false),
        // A line break in the key comment must not add an entry
        (
            AllowedSigner {
                key: PublicKey { comment: Some(format!("comment\nmallory {}", key_line.trim())), ..key.clone() },
                ..signer(&["alice"])
            },
            "mallory", "git", "git.sig", false,
        ),
        // The CA vouches for alice's certificate only with cert-authority
        (AllowedSigner { cert_authority: true, key: ca.clone(), ..signer(&["alice"]) }, "alice", "git", "cert.sig", true),
        (AllowedSigner { key: ca.clone(), ..signer(&["alice"]) }, "alice", "git", "cert.sig", false),
    ] {
        let line = allowed_signer.to_line().unwrap();
        fs::write(dir.join("allowed_signers"), format!("{line}\n")).unwrap();
        let actual = ssh_keygen(dir, &[
            "-Y", "verify", "-f", "allowed_signers", "-I", principal, "-n", namespace, "-s", signature,
        ]);
        assert_eq!(actual, expected, "{:?} {:?} {}", line, principal, namespace);
    }
}
