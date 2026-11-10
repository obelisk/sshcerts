use sshcerts::error::Error;
use sshcerts::ssh::{AllowedSigner, AllowedSignerParsingError};
use sshcerts::PublicKey;

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDO0VQD9TIdICZLWFWwtf7s8/aENve8twGTEmNV0myh5";

fn signer(principals: &[&str]) -> AllowedSigner {
    AllowedSigner {
        principals: principals.iter().map(|p| p.to_string()).collect(),
        cert_authority: false,
        namespaces: None,
        valid_after: None,
        valid_before: None,
        key: PublicKey::from_string(KEY).unwrap(),
    }
}

fn namespaces(namespaces: &[&str]) -> Option<Vec<String>> {
    Some(namespaces.iter().map(|n| n.to_string()).collect())
}

// Lines that parse, and the entries they parse to
fn good_allowed_signers() -> Vec<(String, AllowedSigner)> {
    vec![
        (format!("mitchell@confurious.io {KEY}"), signer(&["mitchell@confurious.io"])),
        (format!("\"mitchell@confurious.io,mitchell\" {KEY}"), signer(&["mitchell@confurious.io", "mitchell"])),
        (
            format!("mitchell@confurious.io cert-authority,namespaces=\"git,file\",valid-after=\"20240101Z\",valid-before=\"20240505123045Z\" {KEY}"),
            AllowedSigner {
                cert_authority: true,
                namespaces: namespaces(&["git", "file"]),
                valid_after: Some(1704067200),
                valid_before: Some(1714912245),
                ..signer(&["mitchell@confurious.io"])
            },
        ),
        // regress/sshsig.sh lines
        (
            format!("user@example.com namespaces=\"test,whatever\" {KEY}"),
            AllowedSigner { namespaces: namespaces(&["test", "whatever"]), ..signer(&["user@example.com"]) },
        ),
        (format!("*@example.com cert-authority {KEY}"), AllowedSigner { cert_authority: true, ..signer(&["*@example.com"]) }),
        // strdelimw(): a quote inside the principals field starts a quoted section
        (format!("\"mitchell confurious\" {KEY}"), signer(&["mitchell confurious"])),
        (format!("a\"b c\" {KEY}"), signer(&["ab c"])),
        // Option names are case-insensitive, and empty options between commas are skipped
        (
            format!("mitchell@confurious.io ,,CERT-AUTHORITY,,Namespaces=\"git\" {KEY}"),
            AllowedSigner { cert_authority: true, namespaces: namespaces(&["git"]), ..signer(&["mitchell@confurious.io"]) },
        ),
        // Inside a quoted value: '#', spaces, an escaped quote, and empty items, which are skipped
        (
            format!("mitchell@confurious.io namespaces=\"#git,,a   b,c\\\"d\" {KEY}"),
            AllowedSigner { namespaces: namespaces(&["#git", "a   b", "c\"d"]), ..signer(&["mitchell@confurious.io"]) },
        ),
        // Fields can be separated by any run of spaces and tabs
        (
            format!("mitchell@confurious.io \t cert-authority\t{}  ", KEY.replace(' ', "\t")),
            AllowedSigner { cert_authority: true, ..signer(&["mitchell@confurious.io"]) },
        ),
        // sshkey_read() ignores anything after the key data, quotes included
        (format!("mitchell@confurious.io {KEY} comment"), signer(&["mitchell@confurious.io"])),
        (format!("\"mitchell confurious\" {KEY} # \"quoted comment"), signer(&["mitchell confurious"])),
    ]
}

#[test]
fn parse_good_allowed_signer() {
    for (line, expected) in good_allowed_signers() {
        assert_eq!(AllowedSigner::from_string(&line).unwrap(), expected, "{}", line);
    }
}

#[test]
fn parse_bad_allowed_signer() {
    use AllowedSignerParsingError::*;

    let key_data = KEY.strip_prefix("ssh-ed25519 ").unwrap();
    for (line, expected) in [
        // Blank lines and comments
        (String::new(), MissingPrincipals),
        (format!("# mitchell@confurious.io {KEY}"), MissingPrincipals),
        // Principals
        (format!("\"a b {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io,,thanh@timweri.me {KEY}"), InvalidPrincipals),
        // The principals field ends at whitespace or at the closing quote, and the rest is read as options
        (format!("mitchell@confurious.io ,thanh@timweri.me {KEY}"), InvalidOption("thanh@timweri.me".into())),
        (format!("a\"b c\"d {KEY}"), InvalidOption("d".into())),

        // Options: unknown names, and flags given a value
        (format!("mitchell@confurious.io option=test {KEY}"), InvalidOption("option".into())),
        (format!("mitchell@confurious.io octopus {KEY}"), InvalidOption("octopus".into())), // regress/sshsig.sh
        (format!("mitchell@confurious.io namespace=\"git\" {KEY}"), InvalidOption("namespace".into())),
        (format!("mitchell@confurious.io cert-authorityx {KEY}"), InvalidOption("cert-authorityx".into())),
        (format!("mitchell@confurious.io cert-authority=\"x\" {KEY}"), InvalidOption("cert-authority".into())),
        // A multibyte character where an option name ends
        (format!("mitchell@confurious.io namespaceé=\"git\" {KEY}"), InvalidOption("namespaceé".into())),
        // A trailing comma
        (format!("mitchell@confurious.io cert-authority, {KEY}"), InvalidOption("cert-authority".into())),
        // Options: values must be double-quoted, with nothing after the closing quote
        (format!("mitchell@confurious.io namespaces=thanh,mitchell {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=a\"test\" {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=\"a {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=\"tester,thanh\"\" {KEY}"), InvalidQuotes),
        (format!("mitchell@confurious.io namespaces=\"\"a\"\" {KEY}"), InvalidOption("namespaces".into())),
        (format!("mitchell@confurious.io namespaces=\"a\"b {KEY}"), InvalidOption("namespaces".into())),
        // Options: duplicates, and timestamps out of order
        (format!("mitchell@confurious.io namespaces=\"thanh\",namespaces=\"mitchell\" {KEY}"), DuplicateOptions("namespaces".into())),
        (format!("mitchell@confurious.io valid-after=\"20240101Z\",VALID-AFTER=\"20240102Z\" {KEY}"), DuplicateOptions("valid-after".into())),
        (format!("mitchell@confurious.io valid-before=\"20240101Z\",valid-before=\"20240102Z\" {KEY}"), DuplicateOptions("valid-before".into())),
        (format!("mitchell@confurious.io valid-before=\"20240505\",valid-after=\"20240505\" {KEY}"), InvalidTimestamps),
        // Options: the field ends at whitespace, so the next option is read as the key type
        (format!("mitchell@confurious.io cert-authority namespaces=\"thanh\" {KEY}"), InvalidKey),

        // Key
        (format!("mitchell@confurious.io ecdsa-sha2-nistp384 {key_data}"), InvalidKey),
        (format!("mitchell@confurious.io \"ssh-ed25519\" {key_data}"), InvalidKey),
        (format!("mitchell@confurious.io ssh-ed25519 \"{key_data}\""), InvalidKey),
        // A quoted key is read as an options field with no key after it
        (format!("mitchell@confurious.io \"{KEY}\""), MissingKey),
        (String::from("mitchell@confurious.io cert-authority"), MissingKey),
    ] {
        let actual = AllowedSigner::from_string(&line).unwrap_err();
        assert_eq!(format!("{:?}", actual), format!("{:?}", Error::InvalidAllowedSigner(expected)), "{}", line);
    }
}

// Cases from OpenSSH's regress/unittests/misc/test_convtime.c, plus case-insensitive suffixes and the epoch
#[test]
fn parse_allowed_signer_timestamps_like_openssh() {
    let parse = |timestamp: &str| {
        AllowedSigner::from_string(&format!("mitchell@confurious.io valid-after=\"{timestamp}\" {KEY}"))
            .map(|allowed_signer| allowed_signer.valid_after.unwrap())
    };

    // Local time, so the value depends on TZ
    for timestamp in ["20000101", "200001011223", "20000101122345"] {
        assert!(parse(timestamp).is_ok(), "{}", timestamp);
    }

    for (timestamp, expected) in [
        ("20000101Z", 946684800),
        ("200001011223Z", 946729380),
        ("20000101122345Z", 946729425),
        ("20000101UTC", 946684800),
        ("200001011223UTC", 946729380),
        ("20000101122345UTC", 946729425),
        ("20000101z", 946684800),
        ("20000101utc", 946684800),
    ] {
        assert_eq!(parse(timestamp).unwrap(), expected, "{}", timestamp);
    }

    for timestamp in [
        // Bad month
        "20001301", "20000001",
        // Incomplete
        "2", "2000", "20000", "200001", "2000010", "200001010", "2000010UTC",
        // Bad day, hour, minute, second
        "20000199", "200001019900", "200001010099", "20000101000099",
        // Invalid TZ specifier
        "20000101ZZ", "20000101PDT", "20000101U", "20000101UTCUTC", "20000101UTCZ",
        // OpenSSH 10.2 rejects the epoch and anything before it
        "0", "19700101Z", "19691231Z",
        // An escaped quote is part of the value
        "\\\"20000101Z\\\"",
    ] {
        assert!(
            matches!(
                parse(timestamp),
                Err(Error::InvalidAllowedSigner(AllowedSignerParsingError::InvalidOption(ref v))) if v == "valid-after",
            ),
            "{}", timestamp,
        );
    }
}
