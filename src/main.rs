#![forbid(unsafe_code)]

use clap::{App, Arg};
use futures_core::future::BoxFuture;
use std::{
    convert::TryInto,
    ffi::OsStr,
    path::{Path, PathBuf},
    process,
    time::Duration,
};

use certificate_carver::{
    crtsh::{CachedCrtShServer, RealCrtShServer, RetryDelayCrtShServer},
    ctlog::{LogInfo, LogShard, RealLogServers},
    run, CarveConfig,
};

const PILOT_DAEDALUS_ROOTS: &str = include_str!("../roots/pilot-daedalus.json");
const ICARUS_ROOTS: &str = include_str!("../roots/icarus.json");
const DIGICERT_CT1_ROOTS: &str = include_str!("../roots/digicert-ct1.json");
const DODO_ROOTS: &str = include_str!("../roots/dodo.json");
const MAMMOTH_SABRE_ROOTS: &str = include_str!("../roots/mammoth-sabre.json");
const ARGON_XENON_ROOTS: &str = include_str!("../roots/argon-xenon.json");
const NIMBUS_ROOTS: &str = include_str!("../roots/nimbus.json");
const NESSIE_YETI_ROOTS: &str = include_str!("../roots/nessie-yeti.json");

fn make_log_list() -> Vec<LogInfo> {
    vec![
        LogInfo::new(
            "https://ct.googleapis.com/pilot/",
            LogShard::Any,
            PILOT_DAEDALUS_ROOTS,
        ),
        LogInfo::new(
            "https://ct.googleapis.com/daedalus/",
            LogShard::AlreadyExpired,
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
    ]
}

fn add_user_agent_header(
    mut req: surf::Request,
    client: surf::Client,
    next: surf::middleware::Next<'_>,
) -> BoxFuture<'_, Result<surf::Response, surf::Error>> {
    Box::pin(async move {
        req.insert_header(
            surf::http::headers::USER_AGENT,
            surf::http::headers::HeaderValue::from_bytes(
                b"certificate_carver (https://github.com/divergentdave/certificate_carver)"
                    .to_vec(),
            )
            .unwrap(),
        );
        next.run(req, client).await
    })
}

fn build_surf_client() -> surf::Client {
    surf::Client::new().with(add_user_agent_header)
}

fn main() {
    let matches = App::new("Certificate Carver")
        .version("0.1.7-alpha")
        .author("David Cook <divergentdave@gmail.com>")
        .about(
            "Certificate Carver searches files for X.509 certificates and \
             uploads them to Certificate Transparency logs.",
        )
        .arg(
            Arg::with_name("paths")
                .takes_value(true)
                .multiple(true)
                .required(true)
                .min_values(1)
                .allow_hyphen_values(true)
                .help("File or directory paths"),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the verbosity level"),
        )
        .arg(
            Arg::with_name("jobs")
                .short("j")
                .default_value("4")
                .help("Sets the number of carving threads"),
        )
        .get_matches();
    let paths = matches
        .values_of_os("paths")
        .unwrap()
        .map(|osstr: &OsStr| -> PathBuf { From::from(osstr) });

    let verbosity = matches.occurrences_of("v");
    stderrlog::new()
        .module(module_path!())
        .verbosity(verbosity.try_into().unwrap())
        .init()
        .unwrap();

    let carve_config = match matches.value_of("jobs").unwrap().parse() {
        Err(_) | Ok(0) => {
            eprintln!("Invalid number of threads");
            process::exit(1);
        }
        Ok(threads) => CarveConfig::new(threads),
    };

    let client = build_surf_client();

    let crtsh = RealCrtShServer::new(&client);
    let crtsh = RetryDelayCrtShServer::new(crtsh, Duration::new(5, 0));
    let cache_dir = Path::new("certificate_carver_cache");
    let db = sled::open(cache_dir).expect("Couldn't create or open cache");
    let crtsh = CachedCrtShServer::new(crtsh, db).expect("Couldn't open cache");

    let log_comms = RealLogServers::new(&client);

    let logs = make_log_list();

    run(logs, paths, &crtsh, &log_comms, carve_config);
}
