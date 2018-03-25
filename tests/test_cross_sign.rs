extern crate certificate_carver;
extern crate openssl;

use std::io::Cursor;
use openssl::x509::{X509, X509VerifyResult};

use certificate_carver::{Carver, CertificateFingerprint, LogInfo};

#[test]
fn test_fixture_bespoke_certs() {
    let cert3 = X509::from_pem(include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt")).unwrap();
    let cert4 = X509::from_pem(include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt")).unwrap();
    assert!(cert3.issued(&cert4) == X509VerifyResult::OK);
    assert!(cert4.issued(&cert3) == X509VerifyResult::OK);
}

#[test]
fn test_cross_signatures() {
    let mut carver = Carver::new();
    let root_fp = CertificateFingerprint([0x34, 0x47, 0x5A, 0x72, 0x1C, 0xF4, 0x8D, 0x2F,
                                          0x90, 0x79, 0x31, 0x6E, 0x7E, 0x32, 0xC4, 0xBE,
                                          0x83, 0x35, 0x8D, 0xD7, 0xD4, 0x42, 0xD9, 0x31,
                                          0x12, 0x6D, 0x02, 0x16, 0x26, 0xC7, 0x12, 0x3D]);
    let cert4_fp = CertificateFingerprint([0x8B, 0x6A, 0x74, 0x55, 0x60, 0x59, 0x93, 0x9E,
                                           0x85, 0xEA, 0x2A, 0x44, 0x6D, 0xCE, 0x16, 0x87,
                                           0x14, 0x79, 0xD4, 0xBA, 0xAF, 0x0F, 0xE1, 0xDE,
                                           0x0C, 0x70, 0xD9, 0xED, 0x28, 0xC6, 0x4C, 0x93]);
    let mut root = Cursor::new(include_bytes!("files/bespoke/rootca.crt").to_vec());
    let mut cert1 = Cursor::new(include_bytes!("files/bespoke/intermediate_a_signed_by_rootca.crt").to_vec());
    let mut cert2 = Cursor::new(include_bytes!("files/bespoke/intermediate_b_signed_by_rootca.crt").to_vec());
    let mut cert3 = Cursor::new(include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt").to_vec());
    let mut cert4 = Cursor::new(include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt").to_vec());
    carver.carve_stream(&mut root, "root");
    carver.carve_stream(&mut cert1, "cert1");
    carver.carve_stream(&mut cert2, "cert2");
    carver.carve_stream(&mut cert3, "cert3");
    carver.carve_stream(&mut cert4, "cert4");
    assert!(carver.map.len() == 5);
    let issuer_lookup = carver.build_issuer_lookup();

    let mut log = LogInfo::new("http://127.0.0.0/");
    log.root_fps_sorted.push(root_fp);

    let chains = carver.build_chains(&cert4_fp, &issuer_lookup, &log.root_fps_sorted);
    assert!(chains.len() == 2);
}
