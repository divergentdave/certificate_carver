extern crate base64;
extern crate copy_in_place;
extern crate encoding;
extern crate hex;
extern crate regex;
extern crate reqwest;
extern crate sha2;
extern crate stringprep;
extern crate unicode_normalization;
extern crate untrusted;
extern crate walkdir;
extern crate zip;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

pub mod ctlog;
pub mod ldapprep;
pub mod x509;

use copy_in_place::copy_in_place;
use regex::bytes::Regex;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io::{stdout, Read, Seek, SeekFrom};
use std::path::Path;
use std::str;
use walkdir::WalkDir;
use zip::read::ZipArchive;

use crate::ctlog::{LogInfo, LogServers, TrustRoots};
use crate::x509::Certificate;

const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 3, 4];

fn pem_base64_config() -> base64::Config {
    base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        true,
        base64::LineWrap::Wrap(64, base64::LineEnding::CRLF),
    )
}

fn pem_base64_encode(input: &[u8]) -> String {
    base64::encode_config(input, pem_base64_config())
}

fn pem_base64_decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(input, pem_base64_config())
}

// should make separate types for fingerprints and cert der instead of using Vec<u8>
#[derive(Hash, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct CertificateFingerprint(pub [u8; 32]);

impl AsRef<[u8]> for CertificateFingerprint {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Display for CertificateFingerprint {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        <String as Display>::fmt(&hex::encode(self), f)
    }
}

impl Debug for CertificateFingerprint {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "CertificateFingerprint({})", self)
    }
}

#[derive(Clone)]
pub struct CertificateBytes(pub Vec<u8>);

impl CertificateBytes {
    pub fn fingerprint(&self) -> CertificateFingerprint {
        let mut digest = Sha256::new();
        digest.input(self.as_ref());
        let mut arr: [u8; 32] = Default::default();
        arr.copy_from_slice(&digest.result());
        CertificateFingerprint(arr)
    }
}

impl AsRef<[u8]> for CertificateBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct CertificateChain(pub Vec<CertificateBytes>);

pub struct CertificateRecord {
    pub paths: Vec<String>,
    pub der: CertificateBytes,
    pub cert: Certificate,
}

impl CertificateRecord {
    fn new(der: &CertificateBytes, cert: Certificate) -> CertificateRecord {
        CertificateRecord {
            paths: Vec::new(),
            der: der.clone(),
            cert,
        }
    }
}

struct BufReaderOverlap<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl<R: Read> BufReaderOverlap<R> {
    fn with_capacity(cap: usize, inner: R) -> BufReaderOverlap<R> {
        BufReaderOverlap {
            inner,
            buf: vec![0; cap].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    fn fill_buf(&mut self, min_size: usize) -> std::io::Result<(&[u8], bool)> {
        // like BufRead::fill_buf, but reads if there is min_size or less left in the buffer,
        // not just when it is empty. Returns a buffer and a boolean to indicate end of file,
        // or an error.
        let remaining = self.cap - self.pos;
        let mut eof = false;
        if remaining <= min_size {
            if self.pos > 0 {
                copy_in_place(&mut self.buf, self.pos..self.cap, 0);
                self.cap = remaining;
                self.pos = 0;
            }
            while self.cap < self.buf.len() && self.cap <= min_size {
                let n = self.inner.read(&mut self.buf[self.cap..])?;
                self.cap += n;
                if n == 0 {
                    eof = true;
                    break;
                }
            }
        }
        Ok((&self.buf[self.pos..self.cap], eof))
    }

    fn consume(&mut self, amt: usize) {
        debug_assert!(self.pos + amt <= self.cap);
        self.pos = std::cmp::min(self.pos + amt, self.cap);
    }
}

pub struct Carver {
    pub log_urls: Vec<String>,
    pub map: HashMap<CertificateFingerprint, CertificateRecord>,
}

impl Carver {
    pub fn new(log_urls: Vec<String>) -> Carver {
        Carver {
            log_urls,
            map: HashMap::new(),
        }
    }

    pub fn add_cert(&mut self, der: &CertificateBytes, path: &str) {
        if let Ok(cert) = Certificate::parse(der.0.clone()) {
            let digest = der.fingerprint();
            let entry = self.map.entry(digest);
            let info = entry.or_insert_with(|| CertificateRecord::new(&der, cert));
            info.paths.push(String::from(path));
        }
    }

    pub fn carve_stream<R: Read>(&self, stream: &mut R) -> Vec<CertificateBytes> {
        lazy_static! {
            static ref HEADER_RE: Regex = Regex::new(
                r"(?P<DER>(?-u:\x30\x82(?P<length>..)\x30\x82..(?:\xa0\x03\x02\x01.)?\x02))|(?P<PEM>-----BEGIN CERTIFICATE-----)"
            ).unwrap();
            static ref PEM_END_RE: Regex = Regex::new("-----END CERTIFICATE-----").unwrap();
        }

        let mut results = Vec::new();

        const MAX_CERTIFICATE_SIZE: usize = 16 * 1024;
        const BUFFER_SIZE: usize = 32 * 1024;
        const OVERLAP: usize = 27; // enough to capture the PEM header (and the DER prefix)
        let mut stream = BufReaderOverlap::with_capacity(BUFFER_SIZE, stream);
        let mut min_size = OVERLAP;
        loop {
            let (buf, eof) = match stream.fill_buf(min_size) {
                Ok((buf, eof)) => (buf, eof),
                Err(_) => return results,
            };
            min_size = OVERLAP;
            let consume_amount: usize = match HEADER_RE.captures(&buf) {
                Some(caps) => {
                    if let Some(m) = caps.name("DER") {
                        let length_bytes = &caps["length"];
                        let length = ((length_bytes[0] as usize) << 8) | length_bytes[1] as usize;
                        let start = m.start();
                        let end = start + length + 4;
                        if end <= buf.len() {
                            results.push(CertificateBytes(buf[start..end].to_vec()));
                            end
                        } else {
                            // The end of this certificate isn't in the buffer yet, try reading
                            // more if the buffer is too small
                            if buf.len() - start < MAX_CERTIFICATE_SIZE && !eof {
                                min_size = MAX_CERTIFICATE_SIZE;
                                start
                            } else {
                                // The DER sequence is too long, this was probably a false
                                // positive. Discard the first byte of the match, and keep
                                // searching from there.
                                1
                            }
                        }
                    } else if let Some(m) = caps.name("PEM") {
                        let header_start = m.start();
                        let b64_start = header_start + 27;
                        match PEM_END_RE.find(&buf[b64_start..]) {
                            Some(m2) => {
                                let b64_end = b64_start + m2.start();
                                let encoded = &buf[b64_start..b64_end];
                                if let Ok(bytes) = pem_base64_decode(&encoded) {
                                    results.push(CertificateBytes(bytes));
                                }
                                m.end() - 5
                            }
                            None => {
                                // The footer isn't in the buffer yet, try reading more if the
                                // buffer is too small
                                if buf.len() - header_start < MAX_CERTIFICATE_SIZE && !eof {
                                    min_size = MAX_CERTIFICATE_SIZE;
                                    header_start
                                } else {
                                    // Couldn't find a footer, this was probably a false positive.
                                    // Keep searching from after the header.
                                    m.end() - 5
                                }
                            }
                        }
                    } else {
                        panic!("Impossible else branch, if this regex matches, one of its two capturing groups must match");
                    }
                }
                None => {
                    if eof {
                        return results;
                    }
                    if buf.len() > OVERLAP {
                        buf.len() - OVERLAP
                    } else {
                        0
                    }
                }
            };
            stream.consume(consume_amount);
        }
    }

    pub fn carve_file<RS: Read + Seek>(&self, mut file: &mut RS) -> Vec<CertificateBytes> {
        let mut results = Vec::new();
        let mut magic: [u8; 4] = [0; 4];
        match file.read(&mut magic) {
            Ok(_) => (),
            Err(_) => return results,
        }
        match file.seek(SeekFrom::Start(0)) {
            Ok(_) => (),
            Err(_) => return results,
        }
        if magic == ZIP_MAGIC {
            if let Ok(mut archive) = ZipArchive::new(&mut file) {
                for i in 0..archive.len() {
                    if let Ok(mut entry) = archive.by_index(i) {
                        results.append(&mut self.carve_stream(&mut entry));
                    }
                }
            }
            match file.seek(SeekFrom::Start(0)) {
                Ok(_) => (),
                Err(_) => return results,
            }
        }
        results.append(&mut self.carve_stream(&mut file));
        results
    }

    pub fn scan_file_object<RS: Read + Seek>(&mut self, mut file: &mut RS, path: &str) {
        for certbytes in self.carve_file(&mut file).iter() {
            self.add_cert(&certbytes, path);
        }
    }

    fn scan_file_path(&mut self, path: &Path) {
        if let Ok(mut file) = File::open(path) {
            self.scan_file_object(&mut file, path.to_str().unwrap_or("(unprintable path)"));
        }
    }

    fn scan_directory(&mut self, root: &str) {
        // TODO: parallelize? WalkDir doesn't have parallel iterator support yet
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            self.scan_file_path(entry.path());
        }
    }

    pub fn scan_directory_or_file(&mut self, path_str: &str) {
        let path = Path::new(path_str);
        if path.is_dir() {
            self.scan_directory(path_str);
        } else {
            self.scan_file_path(path);
        }
    }

    pub fn build_issuer_lookup(
        &self,
    ) -> HashMap<CertificateFingerprint, Vec<CertificateFingerprint>> {
        // TODO: could use a hashmap over name der bytes to avoid calling issued() O(n^2) times
        let mut lookup: HashMap<CertificateFingerprint, Vec<CertificateFingerprint>> =
            HashMap::new();
        for (issuer_fp, issuer_info) in self.map.iter() {
            let issuer = &issuer_info.cert;
            for (subject_fp, subject_info) in self.map.iter() {
                if issuer_fp == subject_fp {
                    continue;
                }
                let subject = &subject_info.cert;
                if issuer.issued(subject) {
                    let issuer_fps = lookup.entry(subject_fp.clone()).or_insert_with(Vec::new);
                    issuer_fps.push(issuer_fp.clone());
                }
            }
        }
        lookup
    }

    pub fn build_chains(
        &self,
        leaf_fp: &CertificateFingerprint,
        issuer_lookup: &HashMap<CertificateFingerprint, Vec<CertificateFingerprint>>,
        trust_roots: &TrustRoots,
    ) -> Vec<CertificateChain> {
        fn recurse<'a>(
            fp: &'a CertificateFingerprint,
            history: &[CertificateFingerprint],
            issuer_lookup: &'a HashMap<CertificateFingerprint, Vec<CertificateFingerprint>>,
            trust_roots: &TrustRoots,
        ) -> Vec<Vec<CertificateFingerprint>> {
            if let Some(issuer_fps) = issuer_lookup.get(fp) {
                let mut partial_chains: Vec<Vec<CertificateFingerprint>> = Vec::new();
                for issuer_fp in issuer_fps.iter() {
                    let mut in_history = false;
                    for history_fp in history.iter() {
                        if issuer_fp == history_fp {
                            in_history = true;
                            break;
                        }
                    }
                    if in_history {
                        continue;
                    }
                    let mut new = history.to_owned();
                    new.push(fp.clone());
                    match trust_roots.test_fingerprint(&issuer_fp) {
                        Ok(_) => {
                            partial_chains.push(new);
                            break;
                            // only want this chain once, even if we have multiple equivalent roots
                        }
                        Err(_) => {
                            let mut result = recurse(issuer_fp, &new, issuer_lookup, trust_roots);
                            partial_chains.append(&mut result);
                        }
                    }
                }
                partial_chains
            } else {
                Vec::new()
            }
        }
        let fp_chains = recurse(leaf_fp, &Vec::new(), issuer_lookup, trust_roots);
        fp_chains
            .iter()
            .map(|fp_chain| {
                CertificateChain(fp_chain.iter().map(|fp| self.map[fp].der.clone()).collect())
            })
            .collect()
    }

    pub fn run(&mut self, args: &[String], crtsh: &CrtShServer, log_comms: &LogServers) {
        for arg in args.iter() {
            self.scan_directory_or_file(&arg);
        }
        let mut logs = Vec::new();
        let mut all_roots = TrustRoots::new();
        for log_url in self.log_urls.clone().iter() {
            let mut log = LogInfo::new(log_url);
            match log.fetch_roots(log_comms) {
                Ok(roots) => {
                    log.roots = roots;
                    for root_der in &log.roots[..] {
                        self.add_cert(root_der, "log roots");
                    }
                    all_roots.add_roots(&log.roots);
                    log.trust_roots.add_roots(&log.roots);
                    logs.push(log);
                }
                Err(e) => {
                    println!("Warning: couldn't connect to {}, {:?}", log_url, e);
                }
            }
        }

        let issuer_lookup = self.build_issuer_lookup();

        let mut total_found = 0;
        let mut total_not_found = 0;
        let mut count_no_chain = 0;
        let mut new_fps: Vec<CertificateFingerprint> = Vec::new();
        for (fp, info) in self.map.iter() {
            if all_roots.test_fingerprint(fp).is_ok() {
                // skip root CAs
                continue;
            }
            let found = crtsh.check_crtsh(fp).unwrap();
            info.cert.format_issuer_subject(&mut stdout()).unwrap();
            println!();
            println!(
                "{}, crtsh seen = {}, {} file paths",
                fp,
                found,
                info.paths.len()
            );
            for path in info.paths.iter() {
                println!("{}", path);
            }
            println!();
            if !self.build_chains(fp, &issuer_lookup, &all_roots).is_empty() {
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
        println!(
            "{}/{} in crt.sh already, {}/{} not yet in crt.sh ({} did not chain to roots)",
            total_found, total, total_not_found, total, count_no_chain
        );
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
                let chains = self.build_chains(fp, &issuer_lookup, &log.trust_roots);
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
                            self.map[fp]
                                .cert
                                .format_issuer_subject(&mut stdout())
                                .unwrap();
                            println!();
                            println!();
                            // only submit one chain
                            break;
                        }
                        Ok(Err(status)) => {
                            all_submission_errors = false; // don't want to panic on this

                            print!(
                                "submission was rejected by {} with reason {}: {}, ",
                                log.get_url(),
                                status,
                                fp
                            );
                            self.map[fp]
                                .cert
                                .format_issuer_subject(&mut stdout())
                                .unwrap();
                            println!();
                            println!();
                        }
                        Err(e) => {
                            println!("submission error: {} {:?}", e, e);
                            last_submission_error = Some(e);
                        }
                    }
                }
            }
            if any_chain && all_submission_errors {
                let error = last_submission_error.unwrap();
                let error_desc = String::from(error.description());
                panic!(error_desc);
            }
        }
        println!(
            "Successfully submitted {}/{} new certificates",
            new_submission_count,
            new_fps.len()
        );
    }
}

pub trait CrtShServer {
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, Box<std::error::Error>>;
}

pub struct RealCrtShServer();

impl CrtShServer for RealCrtShServer {
    // true: certificate has already been indexed
    // false: certificate has not been indexed
    fn check_crtsh(&self, fp: &CertificateFingerprint) -> Result<bool, Box<std::error::Error>> {
        let url_str = format!("https://crt.sh/?q={}", fp);
        let url = Url::parse(&url_str).unwrap();
        let mut resp = reqwest::get(url)?;
        assert!(resp.status().is_success());
        let body = resp.text()?;
        match body.find("Certificate not found") {
            None => Ok(true),
            Some(_) => Ok(false),
        }
    }
}
