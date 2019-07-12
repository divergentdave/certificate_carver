mod utils;

use std::io::Cursor;

use certificate_carver::ctlog::{LogInfo, LogShard};
use certificate_carver::x509::Certificate;
use certificate_carver::{CertificatePool, FileCarver};

use crate::utils::decode_pem;

#[test]
fn test_fixture_bespoke_certs() {
    let cert3 = Certificate::parse(decode_pem(include_bytes!(
        "files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt"
    )))
    .unwrap();
    let cert4 = Certificate::parse(decode_pem(include_bytes!(
        "files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt"
    )))
    .unwrap();
    assert!(cert3.issued(&cert4));
    assert!(cert4.issued(&cert3));
}

#[test]
fn test_cross_signatures() {
    let mut file_carver = FileCarver::new();
    let mut pool = CertificatePool::new();
    let root_pem = include_bytes!("files/bespoke/rootca.crt");
    let cert1_pem = include_bytes!("files/bespoke/intermediate_a_signed_by_rootca.crt");
    let cert2_pem = include_bytes!("files/bespoke/intermediate_b_signed_by_rootca.crt");
    let cert3_pem =
        include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt");
    let cert4_pem =
        include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt");
    let cert4_parsed = Certificate::parse(decode_pem(cert4_pem)).unwrap();
    let mut root = Cursor::new(root_pem.to_vec());
    let mut cert1 = Cursor::new(cert1_pem.to_vec());
    let mut cert2 = Cursor::new(cert2_pem.to_vec());
    let mut cert3 = Cursor::new(cert3_pem.to_vec());
    let mut cert4 = Cursor::new(cert4_pem.to_vec());
    file_carver.scan_file_object(&mut root, "root", &mut pool);
    file_carver.scan_file_object(&mut cert1, "cert1", &mut pool);
    file_carver.scan_file_object(&mut cert2, "cert2", &mut pool);
    file_carver.scan_file_object(&mut cert3, "cert3", &mut pool);
    file_carver.scan_file_object(&mut cert4, "cert4", &mut pool);
    assert_eq!(pool.fp_map.len(), 5);

    let mut log = LogInfo::new("http://127.0.0.0/", LogShard::Any, "{\"certificates\":[]}");
    log.trust_roots
        .add_roots(&[Certificate::parse(decode_pem(root_pem)).unwrap()]);

    let chains = pool.build_chains(&cert4_parsed, &log.trust_roots);
    assert_eq!(chains.len(), 2);
}
