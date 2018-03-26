extern crate certificate_carver;

use certificate_carver::Carver;

use std::io::Cursor;

#[test]
fn test_load_pem_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut stream = Cursor::new(&bytes[..]);
    let mut carver = Carver::new();
    carver.scan_file(&mut stream, "fullchain.pem");
    assert!(carver.map.len() == 2);
}

#[test]
fn test_load_zip_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.zip");
    let mut stream = Cursor::new(&bytes[..]);
    let mut carver = Carver::new();
    carver.scan_file(&mut stream, "fullchain.zip");
    assert!(carver.map.len() == 2);
}
