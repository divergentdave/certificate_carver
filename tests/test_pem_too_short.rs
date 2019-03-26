extern crate certificate_carver;

use std::io::Cursor;

use certificate_carver::Carver;

const BYTES: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIC";

#[test]
fn test_pem_too_short() {
    let mut stream = Cursor::new(&BYTES);
    let carver = Carver::new(Vec::new());
    let certs = carver.carve_stream(&mut stream);
    assert!(certs.is_empty());
}
