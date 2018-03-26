extern crate certificate_carver;

extern crate regex;

use std::env::args;
use std::io::stdout;

use certificate_carver::{Carver, CertificateFingerprint, LogInfo, TrustRoots, check_crtsh, format_subject_issuer};

const LOG_URLS: [&str; 1] = ["https://ct.googleapis.com/pilot/"];

fn main() {
    let mut carver = Carver::new();
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

    let mut logs = Vec::new();
    let mut all_roots = TrustRoots::new();
    for log_url in LOG_URLS.iter() {
        let mut log = LogInfo::new(log_url);
        log.roots = log.fetch_roots();
        for root_der in &log.roots[..] {
            carver.add_cert(root_der, "pilot roots");
        }
        all_roots.add_roots(&log.roots);
        log.trust_roots.add_roots(&log.roots);
        logs.push(log);
    }

    let issuer_lookup = carver.build_issuer_lookup();

    let mut total_found = 0;
    let mut total_not_found = 0;
    let mut new_fps: Vec<CertificateFingerprint> = Vec::new();
    for (fp, info) in carver.map.iter() {
        if let Ok(_) = all_roots.test_fingerprint(fp) {
            // skip root CAs
            continue;
        }
        let found = check_crtsh(fp).unwrap();
        format_subject_issuer(&info.cert, &mut stdout()).unwrap();
        println!("");
        println!("{}, crtsh seen = {}, {} paths", fp, found, info.paths.len());
        println!("");
        if found {
            total_found += 1;
        } else {
            total_not_found += 1;
            new_fps.push(fp.clone());
        }
    }
    let total = total_found + total_not_found;
    println!("{}/{} in crt.sh already, {}/{} not yet in crt.sh", total_found, total, total_not_found, total);

    for fp in new_fps.iter() {
        for log in logs.iter() {
            if let Ok(_) = log.trust_roots.test_fingerprint(fp) {
                // skip root CAs
                continue;
            }
            let chains = carver.build_chains(fp, &issuer_lookup, &log.trust_roots);
            for chain in chains.iter() {
                log.submit_chain(&chain).unwrap();
                print!("submitted {}, ", fp);
                format_subject_issuer(&carver.map.get(fp).unwrap().cert, &mut stdout()).unwrap();
                println!("");
                // only submit one chain
                break;
            }
        }
    }
}
