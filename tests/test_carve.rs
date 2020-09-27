use std::io::Cursor;

use certificate_carver::x509::Certificate;
use certificate_carver::{CertificatePool, FileCarver};

#[test]
fn test_load_pem_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.pem");
    let mut stream = Cursor::new(&bytes[..]);
    let mut file_carver = FileCarver::new();
    let certs = file_carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 2);
}

#[test]
fn test_load_zip_chain() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/fullchain.zip");
    let mut stream = Cursor::new(&bytes[..]);
    let mut file_carver = FileCarver::new();
    let certs = file_carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 2);
}

#[test]
fn test_load_der_cert() {
    let bytes = include_bytes!("files/davidsherenowitsa.party/cert.der");
    let mut stream = Cursor::new(&bytes[..]);
    let mut file_carver = FileCarver::new();
    let certs = file_carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 1);
}

#[test]
fn test_overlapping_pem_header() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"-----BEGIN CERTIFICATE");
    bytes.extend_from_slice(include_bytes!("files/bespoke/rootca.crt"));
    let mut stream = Cursor::new(bytes);
    let mut file_carver = FileCarver::new();
    let mut certs = file_carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 1);
    let cert = certs.pop().unwrap().unwrap();
    let cert = Certificate::parse(cert).unwrap();
    let fp = cert.fingerprint();
    assert_eq!(&fp.0, b"\x34\x47\x5A\x72\x1C\xF4\x8D\x2F\x90\x79\x31\x6E\x7E\x32\xC4\xBE\x83\x35\x8D\xD7\xD4\x42\xD9\x31\x12\x6D\x02\x16\x26\xC7\x12\x3D");
}

#[test]
fn test_xmldsig() {
    let bytes = include_bytes!("files/collected/OJ_L_2014_189_FULL.xml");
    let mut stream = Cursor::new(&bytes[..]);
    let mut file_carver = FileCarver::new();
    let mut pool = CertificatePool::new();
    let certs = file_carver.carve_file(&mut stream);
    assert_eq!(certs.len(), 9);
    let root_fp = b"\xa1\xb2\xdb\xeb\x64\xe7\x06\xc6\x16\x9e\x3c\x41\x18\xb2\x3b\xaa\x09\x01\x8a\x84\x27\x66\x6d\x8b\xf0\xe2\x88\x91\xec\x05\x19\x50";
    assert!(certs.iter().any(|res| if let Ok(cert) = res {
        Certificate::parse(cert.clone())
            .unwrap()
            .fingerprint()
            .as_ref()
            == root_fp
    } else {
        false
    }));
    for res in certs.into_iter() {
        if let Ok(certbytes) = res {
            if let Ok(cert) = Certificate::parse(certbytes) {
                pool.add_cert(cert, "files/collected/OJ_L_2014_189_FULL.xml".to_string());
            }
        }
    }
    assert!(pool.fp_map.iter().any(|(fp, _)| fp.as_ref() == root_fp));
    assert_eq!(pool.fp_map.len(), 2);
}
