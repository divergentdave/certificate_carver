extern crate certificate_carver;

mod mocks;

use crate::mocks::{MockCrtShServer, MockLogServers};
use certificate_carver::Carver;

#[test]
fn test_run() {
    let mut logs = Vec::new();
    logs.push(String::from("https://ct.googleapis.com/pilot/"));
    let mut carver = Carver::new(logs);
    let mut args = Vec::new();
    args.push(format!("{}/tests/files", env!("CARGO_MANIFEST_DIR")));
    let crtsh = MockCrtShServer();
    let log_comms = MockLogServers::new();
    carver.run(&args, &crtsh, &log_comms);
    let chains = log_comms.submitted_chains.borrow();
    assert!(chains.len() > 0);
}
