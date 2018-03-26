extern crate certificate_carver;
extern crate openssl;

use std::io::Cursor;
use openssl::x509::{X509, X509VerifyResult};

use certificate_carver::{Carver, CertificateBytes, LogInfo};

#[test]
fn test_fixture_bespoke_certs() {
    let cert3 = X509::from_pem(include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt")).unwrap();
    let cert4 = X509::from_pem(include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt")).unwrap();
    assert!(cert3.issued(&cert4) == X509VerifyResult::OK);
    assert!(cert4.issued(&cert3) == X509VerifyResult::OK);
}

fn pem_to_der(pem: &[u8]) -> Vec<u8> {
    X509::from_pem(pem).unwrap().to_der().unwrap()
}

#[test]
fn test_cross_signatures() {
    let mut carver = Carver::new();
    let root_pem = include_bytes!("files/bespoke/rootca.crt");
    let cert1_pem = include_bytes!("files/bespoke/intermediate_a_signed_by_rootca.crt");
    let cert2_pem = include_bytes!("files/bespoke/intermediate_b_signed_by_rootca.crt");
    let cert3_pem = include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt");
    let cert4_pem = include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt");
    let cert4_fp = CertificateBytes(pem_to_der(cert4_pem)).fingerprint();
    let mut root = Cursor::new(root_pem.to_vec());
    let mut cert1 = Cursor::new(cert1_pem.to_vec());
    let mut cert2 = Cursor::new(cert2_pem.to_vec());
    let mut cert3 = Cursor::new(cert3_pem.to_vec());
    let mut cert4 = Cursor::new(cert4_pem.to_vec());
    carver.scan_file(&mut root, "root");
    carver.scan_file(&mut cert1, "cert1");
    carver.scan_file(&mut cert2, "cert2");
    carver.scan_file(&mut cert3, "cert3");
    carver.scan_file(&mut cert4, "cert4");
    assert!(carver.map.len() == 5);
    let issuer_lookup = carver.build_issuer_lookup();

    let mut log = LogInfo::new("http://127.0.0.0/");
    log.trust_roots.add_roots(&[CertificateBytes(pem_to_der(root_pem))]);

    let chains = carver.build_chains(&cert4_fp, &issuer_lookup, &log.trust_roots);
    assert!(chains.len() == 2);
}
