extern crate certificate_carver;

mod mocks;

use certificate_carver::Carver;
use mocks::{MockCrtShServer, MockLogServers};

#[test]
fn test_run() {
    let mut logs = Vec::new();
    logs.push(String::from("https://ct.googleapis.com/pilot/"));
    let mut carver = Carver::new(logs);
    let mut args = Vec::new();
    args.push(String::from(format!(
        "{}/tests/files",
        env!("CARGO_MANIFEST_DIR")
    )));
    let crtsh = MockCrtShServer();
    let log_comms = MockLogServers::new();
    carver.run(args, &crtsh, &log_comms);
    assert!(*log_comms.add_chain_count.borrow() > 0);
}
