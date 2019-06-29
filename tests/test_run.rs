extern crate reqwest;
extern crate sha2;

extern crate certificate_carver;

mod mocks;

use reqwest::Url;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::mocks::{MockCrtShServer, MockLogServers};
use certificate_carver::ctlog::{LogInfo, LogShard};
use certificate_carver::Carver;

#[test]
fn test_run() {
    let log_url_str = "https://ct.googleapis.com/pilot/";
    let logs = vec![LogInfo::new(
        log_url_str,
        LogShard::Any,
        include_str!("../roots/pilot-daedalus.json"),
    )];
    let mut carver = Carver::new(logs);
    let mut args = Vec::new();
    args.push(PathBuf::from(format!(
        "{}/tests/files/davidsherenowitsa.party",
        env!("CARGO_MANIFEST_DIR")
    )));
    let crtsh = MockCrtShServer::default();
    let log_comms = MockLogServers::new();
    carver.run(args.into_iter(), &crtsh, &log_comms);

    let mut chains = log_comms.submitted_chains.borrow_mut();
    chains.sort_by_key(|(url, chain)| -> (Url, Vec<Vec<u8>>) {
        (
            url.clone(),
            chain
                .0
                .iter()
                .map(|certbytes| certbytes.0.clone())
                .collect(),
        )
    });

    assert!(chains.len() == 2);

    let davidsherenowitsa_party_fp = [
        0x9C, 0x1E, 0xE5, 0x12, 0x8A, 0x1E, 0xDF, 0x87, 0xD7, 0x4F, 0x4D, 0x5E, 0x5C, 0x0D, 0x90,
        0xBA, 0xDA, 0xE4, 0xB5, 0xEB, 0x52, 0x6F, 0x77, 0xAF, 0x15, 0xB8, 0x37, 0x25, 0xAD, 0x53,
        0x49, 0xB8,
    ];
    let lets_encrypt_authority_x3_fp = [
        0x25, 0x84, 0x7D, 0x66, 0x8E, 0xB4, 0xF0, 0x4F, 0xDD, 0x40, 0xB1, 0x2B, 0x6B, 0x07, 0x40,
        0xC5, 0x67, 0xDA, 0x7D, 0x02, 0x43, 0x08, 0xEB, 0x6C, 0x2C, 0x96, 0xFE, 0x41, 0xD9, 0xDE,
        0x21, 0x8D,
    ];

    let first_chain = &chains[0].1;
    assert_eq!(first_chain.0.len(), 1);
    let first_chain_only_cert = &first_chain.0[0];
    let first_chain_only_cert_fp = Sha256::digest(&first_chain_only_cert.0);
    assert_eq!(
        first_chain_only_cert_fp.as_slice(),
        &lets_encrypt_authority_x3_fp
    );

    let second_chain = &chains[1].1;
    assert_eq!(second_chain.0.len(), 2);
    let second_chain_first_cert = &second_chain.0[0];
    let second_chain_second_cert = &second_chain.0[1];
    let second_chain_first_cert_fp = Sha256::digest(&second_chain_first_cert.0);
    let second_chain_second_cert_fp = Sha256::digest(&second_chain_second_cert.0);
    assert_eq!(
        second_chain_first_cert_fp.as_slice(),
        &davidsherenowitsa_party_fp
    );
    assert_eq!(
        second_chain_second_cert_fp.as_slice(),
        &lets_encrypt_authority_x3_fp
    );
}
