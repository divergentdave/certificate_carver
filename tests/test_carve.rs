extern crate certificate_carver;

mod mock_crtsh;
mod mock_log;

use std::io::Cursor;

use certificate_carver::Carver;

use mock_crtsh::MockCrtShServer;
use mock_log::MockLogServers;

#[test]
fn test_load_pem_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new(), Box::new(MockCrtShServer()), Box::new(MockLogServers()));
    let certs = carver.carve_file(&mut stream);
    assert!(certs.len() == 2);
}

#[test]
fn test_load_zip_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.zip");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new(), Box::new(MockCrtShServer()), Box::new(MockLogServers()));
    let certs = carver.carve_file(&mut stream);
    assert!(certs.len() == 2);
}

#[test]
fn test_load_der_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new(), Box::new(MockCrtShServer()), Box::new(MockLogServers()));
    let certs = carver.carve_file(&mut stream);
    assert!(certs.len() == 1);
}
