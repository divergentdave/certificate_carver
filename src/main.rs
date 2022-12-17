#![forbid(unsafe_code)]

use clap::{builder::ValueParser, value_parser, Arg, ArgAction, Command};
use std::{
    path::{Path, PathBuf},
    process,
    time::Duration,
};
use surf::http::headers::{HeaderValue, USER_AGENT};

use certificate_carver::{
    crtsh::{CachedCrtShServer, RealCrtShServer, RetryDelayCrtShServer},
    ctlog::{LogInfo, LogShard, RealLogServers},
    run, CarveConfig,
};

const DAEDALUS_ROOTS: &str = include_str!("../roots/daedalus.json");
const DODO_ROOTS: &str = include_str!("../roots/dodo.json");
const MAMMOTH_SABRE_ROOTS: &str = include_str!("../roots/mammoth-sabre.json");
const ARGON_XENON_ROOTS: &str = include_str!("../roots/argon-xenon.json");
const NIMBUS_ROOTS: &str = include_str!("../roots/nimbus.json");
const NESSIE_YETI_ROOTS: &str = include_str!("../roots/nessie-yeti.json");
const GORGON_ROOTS: &str = include_str!("../roots/gorgon.json");

fn make_log_list() -> Vec<LogInfo> {
    vec![
        LogInfo::new(
            "https://ct.googleapis.com/daedalus/",
            LogShard::AlreadyExpired,
            DAEDALUS_ROOTS,
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
        LogInfo::new(
            "https://gorgon.ct.digicert.com/log/",
            LogShard::Any,
            GORGON_ROOTS,
        ),
    ]
}

fn build_surf_client() -> surf::Client {
    surf::Config::new()
        .add_header(
            USER_AGENT,
            HeaderValue::from_bytes(
                b"certificate_carver (https://github.com/divergentdave/certificate_carver)"
                    .to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap()
}

fn app() -> Command {
    Command::new("Certificate Carver")
        .version("0.1.7-alpha")
        .author("David Cook <divergentdave@gmail.com>")
        .about(
            "Certificate Carver searches files for X.509 certificates and \
             uploads them to Certificate Transparency logs.",
        )
        .arg(
            Arg::new("paths")
                .num_args(1..)
                .required(true)
                .allow_hyphen_values(true)
                .value_parser(ValueParser::path_buf())
                .help("File or directory paths"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the verbosity level"),
        )
        .arg(
            Arg::new("jobs")
                .short('j')
                .default_value("4")
                .value_parser(value_parser!(usize))
                .help("Sets the number of carving threads"),
        )
}

fn main() {
    let matches = app().get_matches();
    let paths = matches.get_many::<PathBuf>("paths").unwrap().cloned();

    let verbosity = *matches.get_one::<u8>("verbose").unwrap();
    stderrlog::new()
        .module(module_path!())
        .verbosity(usize::from(verbosity))
        .init()
        .unwrap();

    let carve_config = match matches.get_one::<usize>("jobs").unwrap() {
        0 => {
            eprintln!("Invalid number of threads");
            process::exit(1);
        }
        threads => CarveConfig::new(*threads),
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

#[test]
fn verify_app() {
    app().debug_assert();
}
