// Check that lines written by AllowedSigner mean the same thing to OpenSSH's ssh-keygen. Skipped
// when ssh-keygen isn't installed.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use sshcerts::ssh::AllowedSigner;
use sshcerts::PublicKey;

fn ssh_keygen(dir: &Path, args: &[&str]) -> bool {
    let mut child = Command::new("ssh-keygen")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"message").unwrap();
    child.wait().unwrap().success()
}

#[test]
fn ssh_keygen_reads_allowed_signer_lines() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("ssh-keygen not found, skipping");
        return;
    }

    let dir = std::env::temp_dir().join(format!("sshcerts-allowed-signer-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();

    assert!(ssh_keygen(&dir, &["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", "key"]));
    fs::write(dir.join("message"), "message").unwrap();
    for namespace in ["git", "file"] {
        assert!(ssh_keygen(&dir, &["-Y", "sign", "-q", "-f", "key", "-n", namespace, "message"]));
        fs::rename(dir.join("message.sig"), dir.join(format!("{namespace}.sig"))).unwrap();
    }
    let key_line = fs::read_to_string(dir.join("key.pub")).unwrap();
    let key = PublicKey::from_string(&key_line).unwrap();

    let signer = |principals: &[&str]| AllowedSigner {
        principals: principals.iter().map(|p| p.to_string()).collect(),
        cert_authority: false,
        namespaces: None,
        valid_after: None,
        valid_before: None,
        key: key.clone(),
    };

    // (entry, principal, namespace, whether ssh-keygen should accept the signature)
    let mut cases = vec![
        (signer(&["alice"]), "alice", "git", true),
        (signer(&["alice"]), "bob", "git", false),
        (signer(&["alice smith", "#bob", "a\rb"]), "alice smith", "git", true),
        (signer(&["alice smith", "#bob", "a\rb"]), "#bob", "git", true),
        (signer(&["alice smith", "#bob", "a\rb"]), "a\rb", "git", true),
    ];

    for (namespace, expected) in [("file", true), ("git", false)] {
        let mut namespaces = signer(&["alice"]);
        namespaces.namespaces = Some(vec!["file".to_string(), "a\"b".to_string()]);
        cases.push((namespaces, "alice", namespace, expected));
    }

    let mut valid = signer(&["alice"]);
    valid.valid_after = Some(946684800);
    valid.valid_before = Some(253402300799);
    cases.push((valid, "alice", "git", true));

    let mut expired = signer(&["alice"]);
    expired.valid_before = Some(946684800);
    cases.push((expired, "alice", "git", false));

    // A line break in the key comment must not add an entry
    let mut comment = signer(&["alice"]);
    comment.key.comment = Some(format!("comment\nmallory {}", key_line.trim()));
    cases.push((comment, "mallory", "git", false));

    for (allowed_signer, principal, namespace, expected) in cases {
        let line = allowed_signer.to_line().unwrap();
        fs::write(dir.join("allowed_signers"), format!("{line}\n")).unwrap();
        let actual = ssh_keygen(&dir, &[
            "-Y", "verify", "-f", "allowed_signers", "-I", principal, "-n", namespace, "-s", &format!("{namespace}.sig"),
        ]);
        assert_eq!(actual, expected, "{:?} {} {}", line, principal, namespace);
    }

    fs::remove_dir_all(&dir).unwrap();
}
