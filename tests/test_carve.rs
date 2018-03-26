extern crate certificate_carver;

use certificate_carver::Carver;

use std::io::Cursor;

#[test]
fn test_load_pem_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new();
    let certs = carver.carve_file(&mut stream);
    assert!(certs.len() == 2);
}

#[test]
fn test_load_zip_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.zip");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new();
    let certs = carver.carve_file(&mut stream);
    assert!(certs.len() == 2);
}
