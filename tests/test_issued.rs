extern crate certificate_carver;

mod utils;

use certificate_carver::x509::Certificate;

use utils::decode_pem;

#[test]
fn test_issued_bespoke() {
    let root_cert =
        Certificate::new(decode_pem(include_bytes!("files/bespoke/rootca.crt"))).unwrap();
    let root_to_a = Certificate::new(decode_pem(include_bytes!(
        "files/bespoke/intermediate_a_signed_by_rootca.crt"
    )))
    .unwrap();
    let root_to_b = Certificate::new(decode_pem(include_bytes!(
        "files/bespoke/intermediate_b_signed_by_rootca.crt"
    )))
    .unwrap();
    let a_to_b = Certificate::new(decode_pem(include_bytes!(
        "files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt"
    )))
    .unwrap();
    let b_to_a = Certificate::new(decode_pem(include_bytes!(
        "files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt"
    )))
    .unwrap();

    assert!(root_cert.issued(&root_cert));
    assert!(root_cert.issued(&root_to_a));
    assert!(root_cert.issued(&root_to_b));
    assert!(!root_cert.issued(&a_to_b));
    assert!(!root_cert.issued(&b_to_a));

    assert!(!root_to_a.issued(&root_cert));
    assert!(!root_to_a.issued(&root_to_a));
    assert!(!root_to_a.issued(&root_to_b));
    assert!(root_to_a.issued(&a_to_b));
    assert!(!root_to_a.issued(&b_to_a));

    assert!(!root_to_b.issued(&root_cert));
    assert!(!root_to_b.issued(&root_to_a));
    assert!(!root_to_b.issued(&root_to_b));
    assert!(!root_to_b.issued(&a_to_b));
    assert!(root_to_b.issued(&b_to_a));

    assert!(!a_to_b.issued(&root_cert));
    assert!(!a_to_b.issued(&root_to_a));
    assert!(!a_to_b.issued(&root_to_b));
    assert!(!a_to_b.issued(&a_to_b));
    assert!(a_to_b.issued(&b_to_a));

    assert!(!b_to_a.issued(&root_cert));
    assert!(!b_to_a.issued(&root_to_a));
    assert!(!b_to_a.issued(&root_to_b));
    assert!(b_to_a.issued(&a_to_b));
    assert!(!b_to_a.issued(&b_to_a));
}

#[test]
fn test_issued_ignore_case() {
    let cert1 = Certificate::new(decode_pem(include_bytes!(
        "files/collected/test_end_entity.pem"
    )))
    .unwrap();
    let cert2 = Certificate::new(decode_pem(include_bytes!(
        "files/collected/issued_by_ee.pem"
    )))
    .unwrap();

    assert!(cert1.issued(&cert2));
}
