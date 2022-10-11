use sshcerts::ssh::Writer;

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