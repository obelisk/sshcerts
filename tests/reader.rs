use sshcerts::error::Error;
use sshcerts::ssh::Reader;

#[test]
fn rfc4251_mpint_test_vector_one() {
    let test_vector = [0, 0, 0, 0];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_positive_mpint();
    assert_eq!(num.unwrap().len(), 0);
}

#[test]
fn rfc4251_mpint_test_vector_two() {
    let test_vector = [
        0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7,
    ];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_positive_mpint();
    assert_eq!(
        num.unwrap(),
        vec![0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
    );
}

#[test]
fn rfc4251_mpint_test_vector_three() {
    let test_vector = [0x00, 0x00, 0x00, 0x02, 0x00, 0x80];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_positive_mpint();
    assert_eq!(num.unwrap(), vec![0x80]);
}

#[test]
fn rfc4251_mpint_test_vector_four() {
    let test_vector = [0x00, 0x00, 0x00, 0x02, 0xed, 0xcc];
    let mut reader = Reader::new(&test_vector);
    match reader.read_positive_mpint() {
        Err(Error::InvalidFormat) => (),
        Ok(n) => panic!(
            "This should have failed to parse as it's a negative mpint but instead got {:?}",
            n
        ),
        Err(other) => panic!("Got {other}, when expected InvalidFormat"),
    }
}

#[test]
fn rfc4251_mpint_test_vector_five() {
    let test_vector = [0x00, 0x00, 0x00, 0x05, 0xff, 0x21, 0x52, 0x41, 0x11];
    let mut reader = Reader::new(&test_vector);
    match reader.read_positive_mpint() {
        Err(Error::InvalidFormat) => (),
        Ok(n) => panic!(
            "This should have failed to parse as it's a negative mpint but instead got {:?}",
            n
        ),
        Err(other) => panic!("Got {other}, when expected InvalidFormat"),
    }
}

#[test]
fn malicious_mpint_wrong_zero() {
    let test_vector = [0x00, 0x00, 0x00, 0x01, 0x00];
    let mut reader = Reader::new(&test_vector);
    match reader.read_positive_mpint() {
        Err(Error::InvalidFormat) => (),
        Ok(n) => panic!(
            "This should have failed to parse as it's a negative mpint but instead got {:?}",
            n
        ),
        Err(other) => panic!("Got {other}, when expected InvalidFormat"),
    }
}

#[test]
fn malicious_mpint_unneeded_zero() {
    let test_vector = [0x00, 0x00, 0x00, 0x02, 0x00, 0x01];
    let mut reader = Reader::new(&test_vector);
    match reader.read_positive_mpint() {
        Err(Error::InvalidFormat) => (),
        Ok(n) => panic!(
            "This should have failed to parse as it's a negative mpint but instead got {:?}",
            n
        ),
        Err(other) => panic!("Got {other}, when expected InvalidFormat"),
    }
}

#[test]
fn malicious_mpint_too_many_zeros() {
    let test_vector = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF];
    let mut reader = Reader::new(&test_vector);
    match reader.read_positive_mpint() {
        Err(Error::InvalidFormat) => (),
        Ok(n) => panic!(
            "This should have failed to parse as it's a negative mpint but instead got {:?}",
            n
        ),
        Err(other) => panic!("Got {other}, when expected InvalidFormat"),
    }
}

#[test]
fn extra_good_check() {
    let test_vector = [0x00, 0x00, 0x00, 0x01, 0x7F];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_positive_mpint();
    assert_eq!(num.unwrap(), vec![0x7F]);
}

#[test]
fn extra_good_check_two() {
    let test_vector = [0x00, 0x00, 0x00, 0x02, 0x00, 0x80];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_positive_mpint();
    assert_eq!(num.unwrap(), vec![0x80]);
}

#[test]
fn read_raw_bytes() {
    let test_vector = [
        0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11,
        0xff, 0x21, 0x52, 0x41, 0x11,
    ];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_raw_bytes(10);
    assert_eq!(
        num.unwrap(),
        vec![0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11,]
    );
}

#[test]
fn read_raw_too_many() {
    let test_vector = [
        0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11,
        0xff, 0x21, 0x52, 0x41, 0x11,
    ];
    let mut reader = Reader::new(&test_vector);
    let num = reader.read_raw_bytes(40);
    assert_eq!(num.is_err(), true);
}

#[test]
fn read_raw_wrap() {
    let test_vector = [
        0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11, 0xff, 0x21, 0x52, 0x41, 0x11,
        0xff, 0x21, 0x52, 0x41, 0x11,
    ];
    let mut reader = Reader::new(&test_vector);
    reader.read_raw_bytes(4).unwrap();
    let num = reader.read_raw_bytes(2 ^ 64 - 1);
    assert_eq!(num.is_err(), true);
}
