/// Takes an ASN1 encode ECDSA signature and attempts to
/// parse it into it's R and S constituent parts
pub fn asn_der_to_r_s(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 ||  buf[0] != 0x30 {
        println!("Bad formatting at the start");
        return None;
    }
    let buf = &buf[3..];
    let r_length = buf[0] as usize;
    if buf.len() < r_length + 2 {
        println!("Bad r len");
        return None;
    }
    let buf = &buf[1..];
    let r = &buf[..r_length];
    let buf = &buf[r_length..];
    if buf[0] != 0x2 {
        println!("Bad Marker after r, found: {:x}", buf[0]);
        return None
    }
    let s_length = buf[1] as usize;
    let s = &buf[2..];

    if s.len() != s_length {
        println!("Bad s len");
        return None
    }

    Some((r, s))
}