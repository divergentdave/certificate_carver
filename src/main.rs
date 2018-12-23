extern crate certificate_carver;

extern crate regex;
extern crate reqwest;

use std::env::args;
use std::io::stdout;

use certificate_carver::{Carver, CertificateFingerprint, LogInfo, TrustRoots, CrtShServer, RealCrtShServer, LogServers, RealLogServers, format_issuer_subject};

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
    let mut carver = Carver::new();
    let crtsh: Box<CrtShServer> = Box::new(RealCrtShServer());
    let mut empty_args = true;
    let mut iter = args();
    iter.next();  // skip argv[0]
    for arg in iter {
        carver.scan_directory(&arg);
        empty_args = false;
    }
    if empty_args {
        panic!("pass at least one directory as a command line argument");
    }

    let log_comms: Box<LogServers> = Box::new(RealLogServers());
    let mut logs = Vec::new();
    let mut all_roots = TrustRoots::new();
    for log_url in LOG_URLS.iter() {
        let mut log = LogInfo::new(log_url);
        match log.fetch_roots(log_comms.as_ref()) {
            Ok(roots) => {
                log.roots = roots;
                for root_der in &log.roots[..] {
                    carver.add_cert(root_der, "log roots");
                }
                all_roots.add_roots(&log.roots);
                log.trust_roots.add_roots(&log.roots);
                logs.push(log);
            },
            Err(e) => {
                println!("Warning: couldn't connect to {}, {:?}", log_url, e);
            },
        }
    }

    let issuer_lookup = carver.build_issuer_lookup();

    let mut total_found = 0;
    let mut total_not_found = 0;
    let mut count_no_chain = 0;
    let mut new_fps: Vec<CertificateFingerprint> = Vec::new();
    for (fp, info) in carver.map.iter() {
        if all_roots.test_fingerprint(fp).is_ok() {
            // skip root CAs
            continue;
        }
        let found = crtsh.check_crtsh(fp).unwrap();
        format_issuer_subject(&info.cert, &mut stdout()).unwrap();
        println!();
        println!("{}, crtsh seen = {}, {} file paths", fp, found, info.paths.len());
        for path in info.paths.iter() {
            println!("{}", path);
        }
        println!();
        if !carver.build_chains(fp, &issuer_lookup, &all_roots).is_empty() {
            if found {
                total_found += 1;
            } else {
                total_not_found += 1;
                 new_fps.push(fp.clone());
            }
        } else {
            count_no_chain += 1;
        }
    }
    let total = total_found + total_not_found;
    println!("{}/{} in crt.sh already, {}/{} not yet in crt.sh ({} did not chain to roots)",
             total_found, total, total_not_found, total, count_no_chain);
    println!();

    let mut new_submission_count = 0;
    for fp in new_fps.iter() {
        let mut any_chain = false;
        let mut any_submission_success = false;
        let mut all_submission_errors = true;
        let mut last_submission_error: Option<Box<std::error::Error>> = None;
        for log in logs.iter() {
            if log.trust_roots.test_fingerprint(fp).is_ok() {
                // skip root CAs
                continue;
            }
            let chains = carver.build_chains(fp, &issuer_lookup, &log.trust_roots);
            for chain in chains.iter() {
                any_chain = true;
                match log_comms.submit_chain(&log, &chain) {
                    Ok(Ok(_)) => {
                        if !any_submission_success {
                            new_submission_count += 1;
                        }
                        any_submission_success = true;
                        all_submission_errors = false;

                        print!("submitted to {}: {}, ", log.get_url(), fp);
                        format_issuer_subject(&carver.map[fp].cert, &mut stdout()).unwrap();
                        println!();
                        println!();
                        // only submit one chain
                        break;
                    },
                    Ok(Err(status)) => {
                        all_submission_errors = false;  // don't want to panic on this

                        print!("submission was rejected by {} with reason {}: {}, ", log.get_url(), status, fp);
                        format_issuer_subject(&carver.map[fp].cert, &mut stdout()).unwrap();
                        println!();
                        println!();
                    },
                    Err(e) => {
                        println!("submission error: {} {:?}", e, e);
                        last_submission_error = Some(e);
                    },
                }
            }
        }
        if any_chain && all_submission_errors {
            let error = last_submission_error.unwrap();
            let error_desc = String::from(error.description());
            panic!(error_desc);
        }
    }
    println!("Successfully submitted {}/{} new certificates", new_submission_count, new_fps.len());
}
