use sshcerts::ssh::Writer;

use std::collections::HashMap;

#[test]
fn bad_data_one() {
    let test_vector = [0, 0, 3];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 1, 3]);
}

#[test]
fn difficult_data_one() {
    let test_vector = [255];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 2, 0, 255]);
}

#[test]
fn edge_case_with_127() {
    let test_vector = [127];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 1, 127]);
}

#[test]
fn edge_case_with_128() {
    let test_vector = [128];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 2, 0, 128]);
}

#[test]
fn filled_u32_mpint() {
    let test_vector = [255, 255, 255, 255];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 5, 0, 255, 255, 255, 255]);
}

#[test]
fn all_zeroes() {
    let test_vector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 0]);
}

#[test]
fn one_zero() {
    let test_vector = [0];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 0]);
}

#[test]
fn empty() {
    let test_vector = [];
    let mut writer = Writer::new();
    writer.write_mpint(&test_vector);
    let result = writer.as_bytes();
    assert_eq!(result, &vec![0, 0, 0, 0]);
}

#[test]
fn string_map_is_sorted() {
    let mut map = HashMap::new();
    for key in ["permit-pty", "permit-X11-forwarding", "permit-user-rc", "permit-agent-forwarding"] {
        map.insert(String::from(key), String::new());
    }
    map.insert(String::from("force-command"), String::from("/bin/true"));

    let mut writer = Writer::new();
    writer.write_string_map(&map);

    let mut expected = Writer::new();
    let mut inner = Writer::new();
    inner.write_string("force-command");
    inner.write_u32(13);
    inner.write_string("/bin/true");
    for key in ["permit-X11-forwarding", "permit-agent-forwarding", "permit-pty", "permit-user-rc"] {
        inner.write_string(key);
        inner.write_u32(0);
    }
    expected.write_bytes(inner.as_bytes());

    assert_eq!(writer.as_bytes(), expected.as_bytes());
}
