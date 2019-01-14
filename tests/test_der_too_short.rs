extern crate certificate_carver;

use std::io::Cursor;

use certificate_carver::Carver;

const BYTES: [u8; 14] = [
    0x30, 0x82, 0xff, 0xff, 0x30, 0x82, 0xff, 0xf0, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
];

#[test]
fn test_der_too_short() {
    let mut stream = Cursor::new(&BYTES);
    let carver = Carver::new(Vec::new());
    let certs = carver.carve_stream(&mut stream);
    assert!(certs.is_empty());
}
