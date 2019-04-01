extern crate certificate_carver;

use std::env::args;

use certificate_carver::ctlog::{LogInfo, LogShard, RealLogServers};
use certificate_carver::{Carver, RealCrtShServer};

const PILOT_DAEDALUS_ROOTS: &str = include_str!("../roots/pilot-daedalus.json");
const ICARUS_ROOTS: &str = include_str!("../roots/icarus.json");
const DIGICERT_CT1_ROOTS: &str = include_str!("../roots/digicert-ct1.json");
const DODO_ROOTS: &str = include_str!("../roots/dodo.json");
const MAMMOTH_SABRE_ROOTS: &str = include_str!("../roots/mammoth-sabre.json");
const PLAUSIBLE_ROOTS: &str = include_str!("../roots/plausible.json");
const ARGON_XENON_ROOTS: &str = include_str!("../roots/argon-xenon.json");
const NIMBUS_ROOTS: &str = include_str!("../roots/nimbus.json");
const NESSIE_YETI_ROOTS: &str = include_str!("../roots/nessie-yeti.json");

fn main() {
    let mut iter = args();
    iter.next(); // skip argv[0]
    let args = iter.collect::<Vec<String>>();
    if args.is_empty() {
        panic!("pass at least one directory as a command line argument");
    }
    let logs = vec![
        LogInfo::new(
            "https://ct.googleapis.com/pilot/",
            LogShard::Any,
            PILOT_DAEDALUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/daedalus/",
            LogShard::Any,
            PILOT_DAEDALUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/icarus/",
            LogShard::Any,
            ICARUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct1.digicert-ct.com/log/",
            LogShard::Any,
            DIGICERT_CT1_ROOTS,
        ),
        LogInfo::new("https://dodo.ct.comodo.com/", LogShard::Any, DODO_ROOTS),
        LogInfo::new(
            "https://sabre.ct.comodo.com/",
            LogShard::Any,
            MAMMOTH_SABRE_ROOTS,
        ),
        LogInfo::new(
            "https://mammoth.ct.comodo.com/",
            LogShard::Any,
            MAMMOTH_SABRE_ROOTS,
        ),
        LogInfo::new(
            "https://plausible.ct.nordu.net/",
            LogShard::Any,
            PLAUSIBLE_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/argon2017/",
            LogShard::ExpiryYear(2017),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/argon2018/",
            LogShard::ExpiryYear(2018),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/argon2019/",
            LogShard::ExpiryYear(2019),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/argon2020/",
            LogShard::ExpiryYear(2020),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/argon2021/",
            LogShard::ExpiryYear(2021),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/argon2022/",
            LogShard::ExpiryYear(2022),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/xenon2018/",
            LogShard::ExpiryYear(2018),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/xenon2019/",
            LogShard::ExpiryYear(2019),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/xenon2020/",
            LogShard::ExpiryYear(2020),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/xenon2021/",
            LogShard::ExpiryYear(2021),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/logs/xenon2022/",
            LogShard::ExpiryYear(2022),
            ARGON_XENON_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2017/",
            LogShard::ExpiryYear(2017),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2018/",
            LogShard::ExpiryYear(2018),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2019/",
            LogShard::ExpiryYear(2019),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2020/",
            LogShard::ExpiryYear(2020),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2021/",
            LogShard::ExpiryYear(2021),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2022/",
            LogShard::ExpiryYear(2022),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.cloudflare.com/logs/nimbus2023/",
            LogShard::ExpiryYear(2023),
            NIMBUS_ROOTS,
        ),
        LogInfo::new(
            "https://nessie2018.ct.digicert.com/log/",
            LogShard::ExpiryYear(2018),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://nessie2019.ct.digicert.com/log/",
            LogShard::ExpiryYear(2019),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://nessie2020.ct.digicert.com/log/",
            LogShard::ExpiryYear(2020),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://nessie2021.ct.digicert.com/log/",
            LogShard::ExpiryYear(2021),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://nessie2022.ct.digicert.com/log/",
            LogShard::ExpiryYear(2022),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://yeti2018.ct.digicert.com/log/",
            LogShard::ExpiryYear(2018),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://yeti2019.ct.digicert.com/log/",
            LogShard::ExpiryYear(2019),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://yeti2020.ct.digicert.com/log/",
            LogShard::ExpiryYear(2020),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://yeti2021.ct.digicert.com/log/",
            LogShard::ExpiryYear(2021),
            NESSIE_YETI_ROOTS,
        ),
        LogInfo::new(
            "https://yeti2022.ct.digicert.com/log/",
            LogShard::ExpiryYear(2022),
            NESSIE_YETI_ROOTS,
        ),
    ];
    let mut carver = Carver::new(logs);
    let crtsh = RealCrtShServer();
    let log_comms = RealLogServers();
    carver.run(&args, &crtsh, &log_comms);
}
