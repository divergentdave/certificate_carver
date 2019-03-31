extern crate certificate_carver;

mod utils;

use std::io::Cursor;

use certificate_carver::ctlog::{LogInfo, LogShard};
use certificate_carver::x509::Certificate;
use certificate_carver::Carver;

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
    let mut carver = Carver::new(Vec::new());
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
    carver.scan_file_object(&mut root, "root");
    carver.scan_file_object(&mut cert1, "cert1");
    carver.scan_file_object(&mut cert2, "cert2");
    carver.scan_file_object(&mut cert3, "cert3");
    carver.scan_file_object(&mut cert4, "cert4");
    assert_eq!(carver.fp_map.len(), 5);

    let mut log = LogInfo::new("http://127.0.0.0/", LogShard::Any);
    log.trust_roots
        .add_roots(&[Certificate::parse(decode_pem(root_pem)).unwrap()]);

    let chains = carver.build_chains(&cert4_parsed, &log.trust_roots);
    assert_eq!(chains.len(), 2);
}
