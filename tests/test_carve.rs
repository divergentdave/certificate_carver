use std::io::Cursor;

use certificate_carver::x509::Certificate;
use certificate_carver::Carver;

#[test]
fn test_load_pem_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new());
    let certs = carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 2);
}

#[test]
fn test_load_zip_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.zip");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new());
    let certs = carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 2);
}

#[test]
fn test_load_der_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new());
    let certs = carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 1);
}

#[test]
fn test_overlapping_pem_header() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"-----BEGIN CERTIFICATE");
    bytes.extend_from_slice(include_bytes!("files/bespoke/rootca.crt"));
    let mut stream = Cursor::new(bytes);
    let carver = Carver::new(Vec::new());
    let mut certs = carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 1);
    let cert = certs.pop().unwrap();
    let cert = Certificate::parse(cert).unwrap();
    let fp = cert.fingerprint();
    assert_eq!(&fp.0, b"\x34\x47\x5A\x72\x1C\xF4\x8D\x2F\x90\x79\x31\x6E\x7E\x32\xC4\xBE\x83\x35\x8D\xD7\xD4\x42\xD9\x31\x12\x6D\x02\x16\x26\xC7\x12\x3D");
}

#[test]
fn test_xmldsig() {
    let bytes = include_bytes!("files/collected/OJ_L_2014_189_FULL.xml");
    let mut stream = Cursor::new(&bytes[..]);
    let carver = Carver::new(Vec::new());
    let certs = carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 9);
}
