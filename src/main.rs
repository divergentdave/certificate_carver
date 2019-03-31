extern crate certificate_carver;

use std::env::args;

use certificate_carver::ctlog::{LogInfo, LogShard, RealLogServers};
use certificate_carver::{Carver, RealCrtShServer};

fn main() {
    let mut iter = args();
    iter.next(); // skip argv[0]
    let args = iter.collect::<Vec<String>>();
    if args.is_empty() {
        panic!("pass at least one directory as a command line argument");
    }
    let logs = vec![
        LogInfo::new("https://ct.googleapis.com/pilot/", LogShard::Any),
        LogInfo::new("https://ct.googleapis.com/daedalus/", LogShard::Any),
        LogInfo::new("https://ct.googleapis.com/icarus/", LogShard::Any),
        LogInfo::new("https://ct1.digicert-ct.com/log/", LogShard::Any),
        LogInfo::new("https://dodo.ct.comodo.com/", LogShard::Any),
        LogInfo::new("https://sabre.ct.comodo.com/", LogShard::Any),
        LogInfo::new("https://mammoth.ct.comodo.com/", LogShard::Any),
        LogInfo::new("https://plausible.ct.nordu.net/", LogShard::Any),
    ];
    let mut carver = Carver::new(logs);
    let crtsh = RealCrtShServer();
    let log_comms = RealLogServers();
    carver.run(&args, &crtsh, &log_comms);
}
