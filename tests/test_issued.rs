extern crate openssl;

extern crate certificate_carver;

use openssl::x509::{X509, X509VerifyResult};

#[test]
fn test_issued_bespoke() {
    let root_cert = X509::from_pem(include_bytes!("files/bespoke/rootca.crt")).unwrap();
    let root_to_a = X509::from_pem(include_bytes!("files/bespoke/intermediate_a_signed_by_rootca.crt")).unwrap();
    let root_to_b = X509::from_pem(include_bytes!("files/bespoke/intermediate_b_signed_by_rootca.crt")).unwrap();
    let a_to_b = X509::from_pem(include_bytes!("files/bespoke/intermediate_a/intermediate_b_signed_by_intermediate_a.crt")).unwrap();
    let b_to_a = X509::from_pem(include_bytes!("files/bespoke/intermediate_b/intermediate_a_signed_by_intermediate_b.crt")).unwrap();
    assert!(root_cert.issued(&root_cert) == X509VerifyResult::OK);
    assert!(root_cert.issued(&root_to_a) == X509VerifyResult::OK);
    assert!(root_cert.issued(&root_to_b) == X509VerifyResult::OK);
    assert!(root_cert.issued(&a_to_b) != X509VerifyResult::OK);
    assert!(root_cert.issued(&b_to_a) != X509VerifyResult::OK);

    assert!(root_to_a.issued(&root_cert) != X509VerifyResult::OK);
    assert!(root_to_a.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(root_to_a.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(root_to_a.issued(&a_to_b) == X509VerifyResult::OK);
    assert!(root_to_a.issued(&b_to_a) != X509VerifyResult::OK);

    assert!(root_to_b.issued(&root_cert) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&a_to_b) != X509VerifyResult::OK);
    assert!(root_to_b.issued(&b_to_a) == X509VerifyResult::OK);

    assert!(a_to_b.issued(&root_cert) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&a_to_b) != X509VerifyResult::OK);
    assert!(a_to_b.issued(&b_to_a) == X509VerifyResult::OK);

    assert!(b_to_a.issued(&root_cert) != X509VerifyResult::OK);
    assert!(b_to_a.issued(&root_to_a) != X509VerifyResult::OK);
    assert!(b_to_a.issued(&root_to_b) != X509VerifyResult::OK);
    assert!(b_to_a.issued(&a_to_b) == X509VerifyResult::OK);
    assert!(b_to_a.issued(&b_to_a) != X509VerifyResult::OK);
}
