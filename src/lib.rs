extern crate base64;
extern crate hex;
extern crate openssl;
extern crate regex;
extern crate reqwest;
extern crate ring;
extern crate zip;
extern crate walkdir;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::fs::{File, read_dir};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::str;
use openssl::nid::Nid;
use openssl::x509::{X509, X509NameRef, X509VerifyResult};
use regex::bytes::Regex;
use reqwest::Url;
use ring::digest::{digest, SHA256};
use walkdir::WalkDir;
use zip::read::ZipArchive;

const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 3, 4];

fn pem_base64_config() -> base64::Config {
    base64::Config::new(base64::CharacterSet::Standard, true, true, base64::LineWrap::Wrap(64, base64::LineEnding::CRLF))
}

fn pem_base64_encode(input: &[u8]) -> String {
    base64::encode_config(input, pem_base64_config())
}

fn pem_base64_decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(input, pem_base64_config())
}

#[derive(Deserialize)]
pub struct GetRootsResponse {
    certificates: Vec<String>,
}

#[derive(Serialize)]
pub struct AddChainRequest {
    chain: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct AddChainResponse {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

// should make separate types for fingerprints and cert der instead of using Vec<u8>
#[derive(Hash, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct CertificateFingerprint (
    pub [u8; 32]
);

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
pub struct CertificateBytes (
    pub Vec<u8>
);

impl CertificateBytes {
    pub fn fingerprint(&self) -> CertificateFingerprint {
        let digest = digest(&SHA256, self.as_ref());
        let mut arr: [u8; 32] = Default::default();
        arr.copy_from_slice(digest.as_ref());
        CertificateFingerprint(arr)
    }
}

impl AsRef<[u8]> for CertificateBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct CertificateChain (
    pub Vec<CertificateBytes>
);

// make a class to hold certificate infos, and counts of certs, unchainable, submitted, etc.
pub struct CertificateInfo {
    pub paths: Vec<String>,
    pub der: CertificateBytes,
    pub cert: X509,
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

pub struct LogInfo {
    url: Url,
    pub roots: Vec<CertificateBytes>,
    pub trust_roots: TrustRoots,
}

impl LogInfo {
    pub fn new(url: &str) -> LogInfo {
        LogInfo {
            url: Url::parse(url).unwrap(),
            roots: Vec::new(),
            trust_roots: TrustRoots::new(),
        }
    }

    pub fn fetch_roots(&self) -> Result<Vec<CertificateBytes>, reqwest::Error> {
        let mut vec = Vec::new();
        let url = self.url.join("ct/v1/get-roots").unwrap();
        let mut resp = reqwest::get(url)?;
        let body: GetRootsResponse = resp.json().unwrap();
        for encoded in body.certificates {
            let bytes = pem_base64_decode(&encoded).unwrap();
            vec.push(CertificateBytes(bytes));
        }
        Ok(vec)
    }

    pub fn submit_chain(&self, chain: &CertificateChain) -> Result<Result<AddChainResponse, reqwest::StatusCode>, reqwest::Error> {
        // TODO: which order? should have leaf first, i think we're okay
        let url = self.url.join("ct/v1/add-chain").unwrap();
        let encoded = chain.0.iter().map(|c| pem_base64_encode(c.as_ref())).collect();
        let request_body = AddChainRequest{
            chain: encoded,
        };
        let client = reqwest::Client::new();
        let mut response = client.post(url)
            .json(&request_body)
            .send()?;
        if !response.status().is_success() {
            return Ok(Err(response.status()));
        }
        let response_body: AddChainResponse = response.json()?;
        Ok(Ok(response_body))
    }

    pub fn get_url(&self) -> &Url {
            &self.url
    }
}

pub struct TrustRoots {
    root_fps: HashSet<CertificateFingerprint>,
}

impl TrustRoots {
    pub fn new() -> TrustRoots {
        TrustRoots {
            root_fps: HashSet::new(),
        }
    }

    pub fn add_roots(&mut self, roots: &[CertificateBytes]) {
        for root in roots.iter() {
            let fp = root.fingerprint();
            self.root_fps.insert(fp);
        }
    }

    pub fn test_fingerprint(&self, fp: &CertificateFingerprint) -> Result<(), ()> {
        if self.root_fps.contains(fp) {
            Ok(())
        } else {
            Err(())
        }
    }
}

pub struct Carver {
    pub map: HashMap<CertificateFingerprint, CertificateInfo>,
}

impl Carver {
    pub fn new() -> Carver {
        Carver {
            map: HashMap::new(),
        }
    }

    pub fn add_cert(&mut self, der: &CertificateBytes, path: &str) {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            let digest = der.fingerprint();
            let mut entry = self.map.entry(digest);
            let mut info = entry.or_insert(CertificateInfo::new(der.clone(), cert));
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

        // TODO: stream through a buffer and keep searching that
        let mut data = Vec::new();
        match stream.read_to_end(&mut data) {
            Ok(_) => (),
            Err(_) => return results,
        }
        for caps in HEADER_RE.captures_iter(&data) {
            if let Some(m) = caps.name("DER") {
                let length_bytes = &caps["length"];
                let length = ((length_bytes[0] as usize) << 8) | length_bytes[1] as usize;
                let start = m.start();
                let end = start + length + 4;
                if end <= data.len() {
                    results.push(CertificateBytes(data[start..end].to_vec()));
                }
            }
            if let Some(m) = caps.name("PEM") {
                let start = m.start() + 27;
                if let Some(m2) = PEM_END_RE.find(&data[start..]) {
                    let end = start + m2.start();
                    let encoded = &data[start..end];
                    if let Ok(bytes) = pem_base64_decode(&encoded) {
                        results.push(CertificateBytes(bytes));
                    }
                }
            }
        }
        results
    }

    pub fn carve_file<RS: Read + Seek>(&self, mut file: &mut RS) -> Vec<CertificateBytes> {
        let mut results = Vec::new();
        let mut magic: [u8; 4] = [0; 4];
        match file.read(&mut magic) {
            Ok(_) => (),
            Err(_) => return results
        }
        match file.seek(SeekFrom::Start(0)) {
            Ok(_) => (),
            Err(_) => return results
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
                Err(_) => return results
            }
        }
        results.append(&mut self.carve_stream(&mut file));
        results
    }

    pub fn scan_file<RS: Read + Seek>(&mut self, mut file: &mut RS, path: &str) {
        for certbytes in self.carve_file(&mut file).iter() {
            self.add_cert(&certbytes, path);
        }
    }

    pub fn scan_directory(&mut self, root: &str) {
        read_dir(Path::new(root)).unwrap();
        // TODO: parallelize? WalkDir doesn't have parallel iterator support yet
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if let Ok(mut file) = File::open(entry.path()) {
                self.scan_file(&mut file, entry.path().to_str().unwrap_or("(unprintable_path)"));
            }
        }
    }

    pub fn build_issuer_lookup(&self) -> HashMap<CertificateFingerprint, Vec<CertificateFingerprint>> {
        // TODO: could use a hashmap over name der bytes to avoid calling issued() O(n^2) times
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

    pub fn build_chains(&self,
                        leaf_fp: &CertificateFingerprint,
                        issuer_lookup: &HashMap<CertificateFingerprint, Vec<CertificateFingerprint>>,
                        trust_roots: &TrustRoots) -> Vec<CertificateChain> {
        fn recurse<'a, 'b>(fp: &'a CertificateFingerprint,
                           history: Vec<CertificateFingerprint>,
                           issuer_lookup: &'a HashMap<CertificateFingerprint, Vec<CertificateFingerprint>>,
                           trust_roots: &TrustRoots) -> Vec<Vec<CertificateFingerprint>> {
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
                    match trust_roots.test_fingerprint(&issuer_fp) {
                        Ok(_) => {
                            partial_chains.push(new);
                            break;
                            // only want this chain once, even if we have multiple equivalent roots
                        },
                        Err(_) => {
                            let mut result = recurse(issuer_fp, new, issuer_lookup, trust_roots);
                            partial_chains.append(&mut result);
                        },
                    }
                }
                partial_chains
            } else {
                Vec::new()
            }
        }
        let fp_chains = recurse(leaf_fp, Vec::new(), issuer_lookup, trust_roots);
        fp_chains.iter().map(
            |fp_chain| CertificateChain(fp_chain.iter().map(
                |fp| self.map.get(fp).unwrap().der.clone()
            ).collect())
        ).collect()
    }
}

pub fn check_crtsh(fp: &CertificateFingerprint) -> Result<bool, reqwest::Error> {
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

pub fn format_name(name: &X509NameRef, f: &mut Write) -> std::io::Result<()> {
    let mut space = false;
    for (n, descr) in (&[
            Nid::COUNTRYNAME,
            Nid::ORGANIZATIONNAME,
            Nid::ORGANIZATIONALUNITNAME,
            Nid::DNQUALIFIER,
            Nid::STATEORPROVINCENAME,
            Nid::COMMONNAME,
            Nid::SERIALNUMBER,
            Nid::LOCALITYNAME,
            Nid::TITLE,
            Nid::SURNAME,
            Nid::GIVENNAME,
            Nid::INITIALS,
            Nid::PSEUDONYM,
            Nid::GENERATIONQUALIFIER]).into_iter().zip((&["C", "O", "OU",
            "Distinguished Name Qualifier", "ST", "CN", "SN", "L", "T", "S", "G", "I",
            "Pseudonym", "Generation Qualifier"]).into_iter()) {
        for entry in name.entries_by_nid(*n) {
            if space {
                write!(f, " {}=", descr)?;
            } else {
                write!(f, "{}=", descr)?;
            }
            match entry.data().as_utf8() {
                Ok(string) => write!(f, "{}", &string)?,
                Err(_) => write!(f, "(undecodable string)")?,
            }
            space = true;
        }
    }
    Ok(())
}

pub fn format_subject_issuer(cert: &X509, f: &mut Write) -> std::io::Result<()> {
    write!(f, "issuer=")?;
    format_name(cert.issuer_name(), f)?;
    write!(f, ", subject=")?;
    format_name(cert.subject_name(), f)
}
