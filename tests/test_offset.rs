extern crate certificate_carver;

use std::io::Cursor;

use certificate_carver::Carver;

const MAX_PADDING: usize = 10 * 1024 * 1024;
const PADDINGS: [usize; 8] = [
    0,
    1,
    512,
    1024,
    1024 * 1024,
    5 * 1024 * 1024,
    10 * 1024 * 1024 - 1,
    10 * 1024 * 1024,
];

#[test]
fn test_offset_pem_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut padded = vec![0; MAX_PADDING];
    padded.extend_from_slice(bytes);
    let padded = padded;
    let carver = Carver::new(Vec::new());
    for padding in PADDINGS.iter() {
        let offset: usize = MAX_PADDING - *padding;
        let mut stream = Cursor::new(&padded[offset..]);
        let certs = carver.carve_file(&mut stream);
        assert_eq!(certs.len(), 2, "padding is {}", padding);
    }
}

#[test]
fn test_offset_der_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let mut padded = vec![0; MAX_PADDING];
    padded.extend_from_slice(bytes);
    let padded = padded;
    let carver = Carver::new(Vec::new());
    for padding in PADDINGS.iter() {
        let offset: usize = MAX_PADDING - *padding;
        let mut stream = Cursor::new(&padded[offset..]);
        let certs = carver.carve_file(&mut stream);
        assert_eq!(certs.len(), 1, "padding is {}", padding);
    }
}
