extern crate certificate_carver;

extern crate regex;

use certificate_carver::{Carver, LogInfo, CertificateFingerprint, check_crtsh};

const LOG_URLS: [&str; 1] = ["https://ct.googleapis.com/pilot/"];

fn main() {
    println!("Hello, world!");

    let mut carver = Carver::new();
    //carver.scan_directory("/etc/ssl/certs");
    //carver.scan_directory("/home/david/certificate_carver/javacerts");
    carver.scan_directory("/home/david/certificate-carver/tests/files/davidsherenowitsa.party");
    //carver.scan_directory("/home/david/Downloads");

    if false {
        return;
    }

    let mut logs = Vec::new();
    for log_url in LOG_URLS.iter() {
        let mut log = LogInfo::new(log_url);
        log.roots = log.fetch_roots();
        for root_der in &log.roots[..] {
            carver.add_cert(root_der, "pilot roots");
        }
        log.trust_roots.add_roots(&log.roots);
        logs.push(log);
    }

    let issuer_lookup = carver.build_issuer_lookup();

    if true {
        return;
    }

    let total = carver.map.len();
    let mut total_found = 0;
    let mut total_not_found = 0;
    let mut new_fps: Vec<CertificateFingerprint> = Vec::new();
    for (fp, info) in carver.map.iter() {
        let found = check_crtsh(fp).unwrap();
        println!("{}, crtsh seen = {}, {} paths", fp, found, info.paths.len());
        if found {
            total_found += 1;
        } else {
            total_not_found += 1;
        }
        new_fps.push(fp.clone());
    }
    println!("{}/{} in crt.sh already, {}/{} not yet in crt.sh", total_found, total, total_not_found, total);

    for fp in new_fps.iter() {
        for log in logs.iter() {
            if let Ok(_) = log.trust_roots.test_fingerprint(fp) {
                continue;
            }
            let chains = carver.build_chains(fp, &issuer_lookup, &log.trust_roots);
            for chain in chains.iter() {
                log.submit_chain(&chain).unwrap();
                println!("submitted");
            }
        }
    }
}
