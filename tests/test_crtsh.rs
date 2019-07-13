use std::time::{Duration, Instant};

use certificate_carver::crtsh::{CachedCrtShServer, CrtShServer, RetryDelayCrtShServer};
use certificate_carver::mocks::MockCrtShServer;
use certificate_carver::CertificateFingerprint;

#[test]
fn test_cache() {
    let crtsh = MockCrtShServer::always_true();
    let crtsh = CachedCrtShServer::new_temporary(crtsh).unwrap();
    let fp = CertificateFingerprint([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    crtsh.check_crtsh(&fp).unwrap();
    crtsh.check_crtsh(&fp).unwrap();
}

#[test]
fn test_delay() {
    let crtsh = MockCrtShServer::default();
    let crtsh = RetryDelayCrtShServer::new(crtsh, Duration::new(1, 0));
    let fp = CertificateFingerprint([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let start = Instant::now();
    crtsh.check_crtsh(&fp).unwrap();
    crtsh.check_crtsh(&fp).unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() >= 1);
}
