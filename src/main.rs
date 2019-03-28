extern crate certificate_carver;

use std::env::args;

use certificate_carver::ctlog::RealLogServers;
use certificate_carver::{Carver, RealCrtShServer};

const LOG_URLS: [&str; 8] = [
    "https://ct.googleapis.com/pilot/",
    "https://ct.googleapis.com/daedalus/",
    "https://ct.googleapis.com/icarus/",
    "https://ct1.digicert-ct.com/log/",
    "https://dodo.ct.comodo.com/",
    "https://sabre.ct.comodo.com/",
    "https://mammoth.ct.comodo.com/",
    "https://plausible.ct.nordu.net/",
];

fn main() {
    let mut iter = args();
    iter.next(); // skip argv[0]
    let args = iter.collect::<Vec<String>>();
    if args.is_empty() {
        panic!("pass at least one directory as a command line argument");
    }
    let logs = LOG_URLS
        .iter()
        .map(|s| String::from(*s))
        .collect::<Vec<String>>();
    let mut carver = Carver::new(logs);
    let crtsh = RealCrtShServer();
    let log_comms = RealLogServers();
    carver.run(&args, &crtsh, &log_comms);
}
