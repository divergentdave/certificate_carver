#![feature(test)]
extern crate test;

use certificate_carver::mocks::{MockCrtShServer, MockLogServers};
use certificate_carver::{run, CertificatePool};
use std::path::PathBuf;
use test::Bencher;

#[bench]
fn bench_run(b: &mut Bencher) {
    let mut args = Vec::new();
    args.push(PathBuf::from(format!(
        "{}/tests/files",
        env!("CARGO_MANIFEST_DIR")
    )));
    let crtsh = MockCrtShServer::default();
    let log_comms = MockLogServers::new();
    b.iter(|| {
        let mut pool = CertificatePool::new();
        run(
            &mut pool,
            vec![],
            args.clone().into_iter(),
            &crtsh,
            &log_comms,
        );
    });
}
