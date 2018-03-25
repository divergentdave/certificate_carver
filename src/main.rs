extern crate certificate_carver;

extern crate regex;

use certificate_carver::{Carver, LogInfo, CertificateFingerprint, check_crtsh};

const LOG_URLS: [&str; 1] = ["https://ct.googleapis.com/pilot/"];

fn main() {
    println!("Hello, world!");

    let mut carver = Carver::new();
    //carver.scan_directory("/home/david/Rockwell-Automation-firmware");
    //carver.scan_directory("/etc/ssl/certs");
    //carver.scan_directory("/home/david/certificate-carver/javacerts");
    carver.scan_directory("/home/david/certificate-carver/src/tests");
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
            log.root_fps_sorted.push(root_der.fingerprint());
        }
        log.root_fps_sorted.sort();
        logs.push(log);
    }

    let issuer_lookup = carver.build_issuer_lookup();

    /*
    for log in logs.iter() {
        for (fp, info) in carver.map.iter() {
            if let Ok(_) = log.root_fps_sorted.binary_search(fp) {
                continue;
            }
            let chains = carver.build_chains(fp, &issuer_lookup, &log.root_fps_sorted);
            println!("Built {} chains", chains.len());
        }
    }
    */

    if false {
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
            //new_fps.push(fp.clone());
        }
        new_fps.push(fp.clone());
    }
    println!("{}/{} in crt.sh already, {}/{} not yet in crt.sh", total_found, total, total_not_found, total);

    for fp in new_fps.iter() {
        for log in logs.iter() {
            if let Ok(_) = log.root_fps_sorted.binary_search(fp) {
                continue;
            }
            let chains = carver.build_chains(fp, &issuer_lookup, &log.root_fps_sorted);
            for chain_fps in chains.iter() {
                let chain_ders = chain_fps.iter().map(|fp| carver.map.get(fp).unwrap().der.clone()).collect();
                log.submit_chain(&chain_ders).unwrap();
                println!("submitted");
            }
        }
    }
}

// could use a hashmap over name der bytes to avoid calling issued() O(n^2) times

// TODO: test that chain building works in the presence of mutually cross-signing certs
