extern crate base64;
extern crate hex;
extern crate openssl;
extern crate regex;
extern crate reqwest;
extern crate ring;
extern crate serde;
extern crate walkdir;
extern crate zip;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Cursor};
use std::str;
use openssl::x509::{X509, X509VerifyResult};
use regex::bytes::Regex;
use reqwest::Url;
use ring::digest::{digest, SHA256};
use walkdir::WalkDir;
use zip::read::ZipArchive;

const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 3, 4];
const LOG_URLS: [&str; 1] = ["https://ct.googleapis.com/pilot/"];

fn pem_base64_config() -> base64::Config {
    /*
    lazy_static! {
        static ref BASE64_CONFIG: base64::Config = base64::Config::new(base64::CharacterSet::Standard, true, true, base64::LineWrap::Wrap(64, base64::LineEnding::CRLF));
    }
    BASE64_CONFIG
    */
    base64::Config::new(base64::CharacterSet::Standard, true, true, base64::LineWrap::Wrap(64, base64::LineEnding::CRLF))
}

#[derive(Deserialize)]
struct GetRootsResponse {
    certificates: Vec<String>,
}

#[derive(Serialize)]
struct AddChainRequest {
    chain: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct AddChainResponse {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

// should make separate types for fingerprints and cert der instead of using Vec<u8>
#[derive(Hash, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
struct CertificateFingerprint (
    [u8; 32]
);

impl AsRef<[u8]> for CertificateFingerprint {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Display for CertificateFingerprint {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        hex::encode(self).fmt(f)
    }
}

#[derive(Clone)]
struct CertificateBytes (
    Vec<u8>
);

impl AsRef<[u8]> for CertificateBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// make a class to hold certificate infos, and counts of certs, unchainable, submitted, etc.
struct CertificateInfo {
    paths: Vec<String>,
    der: CertificateBytes,
    cert: X509,
}

impl CertificateInfo {
    fn new(der: CertificateBytes, cert: X509) -> CertificateInfo {
        CertificateInfo {
            paths: Vec::new(),
            der: der.clone(),
            cert,
        }
    }
}

struct LogInfo {
    url: Url,
    roots: Vec<CertificateBytes>,
    root_fps_sorted: Vec<CertificateFingerprint>,
}

impl LogInfo {
    fn new(url: &str) -> LogInfo {
        LogInfo {
            url: Url::parse(url).unwrap(),
            roots: Vec::new(),
            root_fps_sorted: Vec::new(),
        }
    }

    fn fetch_roots(&self) -> Vec<CertificateBytes> {
        let mut vec = Vec::new();
        let url = self.url.join("ct/v1/get-roots").unwrap();
        let mut resp = reqwest::get(url).unwrap();
        let body: GetRootsResponse = resp.json().unwrap();
        for encoded in body.certificates {
            let bytes = base64::decode_config(&encoded, pem_base64_config()).unwrap();
            vec.push(CertificateBytes(bytes));
        }
        vec
    }

    fn submit_chain(&self, chain: &Vec<CertificateBytes>) -> Result<AddChainResponse, reqwest::Error> {
        // TODO: which order? should have leaf first, i think we're okay
        let url = self.url.join("ct/v1/add-chain").unwrap();
        let encoded = chain.iter().map(|c| base64::encode_config(c.as_ref(), pem_base64_config())).collect();
        let request_body = AddChainRequest{
            chain: encoded,
        };
        let client = reqwest::Client::new();
        let mut response = client.post(url)
            .json(&request_body)
            .send()?;
        let response_body: AddChainResponse = response.json().unwrap();
        Ok((response_body))
    }
}

struct Carver {
    map: HashMap<CertificateFingerprint, CertificateInfo>,
}

// make another class for each cert, holds der data, parsed cert, list of file paths, flags for
// submitted/not

impl Carver {
    fn new() -> Carver {
        Carver {
            map: HashMap::new(),
        }
    }

    fn add_cert(&mut self, der: &CertificateBytes, path: &str) {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            let digest = fingerprint(der);
            let mut entry = self.map.entry(digest);
            let mut info = entry.or_insert(CertificateInfo::new(der.clone(), cert));
            info.paths.push(String::from(path));
        }
    }

    fn carve_stream<R: Read>(&mut self, stream: &mut R, path: &str) {
        lazy_static! {
            static ref HEADER_RE: Regex = Regex::new(
                r"(?P<DER>(?-u:\x30\x82(?P<length>..)\x30\x82..(?:\xa0\x03\x02\x01.)?\x02))|(?P<PEM>-----BEGIN CERTIFICATE-----)"
            ).unwrap();
            static ref PEM_END_RE: Regex = Regex::new("-----END CERTIFICATE-----").unwrap();
        }

        // TODO: stream through a buffer and keep searching that
        let mut data = Vec::new();
        match stream.read_to_end(&mut data) {
            Ok(_) => (),
            Err(_) => return
        }
        for caps in HEADER_RE.captures_iter(&data) {
            if let Some(m) = caps.name("DER") {
                let length_bytes = &caps["length"];
                let length = ((length_bytes[0] as usize) << 8) | length_bytes[1] as usize;
                let start = m.start();
                //println!("DER match, {} to {} out of {}", start, start + length + 4, data.len());
                self.add_cert(&CertificateBytes(data[start..start + length + 4].to_vec()), path);
            }
            if let Some(m) = caps.name("PEM") {
                let start = m.start() + 27;
                if let Some(m2) = PEM_END_RE.find(&data[start..]) {
                    let end = start + m2.start();
                    let encoded = &data[start..end];
                    if let Ok(bytes) = base64::decode_config(&encoded, pem_base64_config()) {
                        self.add_cert(&CertificateBytes(bytes), path);
                    }
                }
            }
        }
    }

    fn carve_file<RS: Read + Seek>(&mut self, mut file: &mut RS, path: &str) {
        let mut magic: [u8; 4] = [0; 4];
        match file.read(&mut magic) {
            Ok(_) => (),
            Err(_) => return
        }
        match file.seek(SeekFrom::Start(0)) {
            Ok(_) => (),
            Err(_) => return
        }
        if magic == ZIP_MAGIC {
            if let Ok(mut archive) = ZipArchive::new(&mut file) {
                for i in 0..archive.len() {
                    if let Ok(mut entry) = archive.by_index(i) {
                        let path = format!("{}:{}", path, entry.name());
                        self.carve_stream(&mut entry, &path);
                    }
                }
            }
            match file.seek(SeekFrom::Start(0)) {
                Ok(_) => (),
                Err(_) => return
            }
        }
        self.carve_stream(&mut file, path);
    }

    fn scan_directory(&mut self, root: &str) {
        // TODO: does this work when passed a path to a file instead?
        // TODO: parallelize
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if let Ok(mut file) = File::open(entry.path()) {
                self.carve_file(&mut file, entry.path().to_str().unwrap_or("TODO"));
            }
        }
    }

    fn build_issuer_lookup(&self) -> HashMap<CertificateFingerprint, Vec<CertificateFingerprint>> {
        let mut lookup: HashMap<CertificateFingerprint, Vec<CertificateFingerprint>> = HashMap::new();
        for (issuer_fp, issuer_info) in self.map.iter() {
            let issuer = &issuer_info.cert;
            for (subject_fp, subject_info) in self.map.iter() {
                if issuer_fp == subject_fp {
                    continue;
                }
                let subject = &subject_info.cert;
                if issuer.issued(subject) == X509VerifyResult::OK {
                    let mut issuer_fps = lookup.entry(subject_fp.clone()).or_insert(Vec::new());
                    issuer_fps.push(issuer_fp.clone());
                }
            }
        }
        lookup
    }

    fn build_chains(&self, leaf_fp: &CertificateFingerprint, issuer_lookup: &HashMap<CertificateFingerprint, Vec<CertificateFingerprint>>, root_fps_sorted: &Vec<CertificateFingerprint>) -> Vec<Vec<CertificateFingerprint>> {
        fn recurse<'a, 'b>(fp: &'a CertificateFingerprint, history: Vec<CertificateFingerprint>, issuer_lookup: &'a HashMap<CertificateFingerprint, Vec<CertificateFingerprint>>, root_fps_sorted: &'b Vec<CertificateFingerprint>) -> Vec<Vec<CertificateFingerprint>> {
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
                    let mut new = history.clone();
                    new.push(fp.clone());
                    match root_fps_sorted.binary_search(&issuer_fp) {
                        Ok(_) => {
                            partial_chains.push(new);
                            break;
                            // only want one chain even if we have multiple equivalent roots
                        },
                        Err(_) => {
                            let mut result = recurse(issuer_fp, new, issuer_lookup, root_fps_sorted);
                            partial_chains.append(&mut result);
                        },
                    }
                }
                partial_chains
            } else {
                Vec::new()
            }
        }
        recurse(leaf_fp, Vec::new(), issuer_lookup, root_fps_sorted)
    }
}

/*
fn parse_certificate(der: &[u8]) -> X509 {
    X509::from_der(der).unwrap()
    // no api to der encode name... also not comparable
    // TODO: write a function to parse enough of a certificate to get name blobs
    // use lookup by name blobs to speed up checking issuers
}
*/

fn fingerprint(der: &CertificateBytes) -> CertificateFingerprint {
    let digest = digest(&SHA256, der.as_ref());
    let mut arr: [u8; 32] = Default::default();
    arr.copy_from_slice(digest.as_ref());
    CertificateFingerprint(arr)
}

fn check_crtsh_fingerprint(fp: &CertificateFingerprint) -> Result<bool, reqwest::Error> {
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
            log.root_fps_sorted.push(fingerprint(root_der));
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
        let found = check_crtsh_fingerprint(fp).unwrap();
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

#[test]
fn byte_regex() {
    let re = Regex::new(r"(?-u:\x30\x82)").unwrap();
    let haystack: [u8; 9] = [0x30, 0x82, 0, 100, 0x30, 0x82, 0, 50, 2];
    assert!(re.find(&haystack).is_some());
}

// TODO: test that chain building works in the presence of mutually cross-signing certs

#[test]
fn test_load_pem_chain() {
    let bytes = include_bytes!("tests/fullchain.pem");
    let mut stream = Cursor::new(&bytes[..]);
    let mut carver = Carver::new();
    carver.carve_stream(&mut stream, "fullchain.pem");
    // TODO: check data structures, fingerprints
}

#[test]
fn test_load_zip_chain() {
    let bytes = include_bytes!("tests/fullchain.zip");
    let mut stream = Cursor::new(&bytes[..]);
    let mut carver = Carver::new();
    carver.carve_file(&mut stream, "fullchain.zip");
    // TODO: check data structures, fingerprints
}
