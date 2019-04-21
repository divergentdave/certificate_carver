extern crate base64;
extern crate chrono;
extern crate copy_in_place;
extern crate encoding;
extern crate hex;
extern crate lopdf;
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

pub mod crtsh;
pub mod ctlog;
pub mod ldapprep;
pub mod x509;

use copy_in_place::copy_in_place;
use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io::{stdout, Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::str;
use walkdir::WalkDir;
use zip::read::ZipArchive;

use crate::crtsh::CrtShServer;
use crate::ctlog::{LogInfo, LogServers, TrustRoots};
use crate::x509::{Certificate, NameInfo};

const PDF_MAGIC: [u8; 4] = [0x25, 0x50, 0x44, 0x46];
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

impl AsRef<[u8]> for CertificateBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone)]
pub struct CertificateChain(pub Vec<CertificateBytes>);

pub struct CertificateRecord {
    pub paths: Vec<String>,
    pub cert: Certificate,
}

impl CertificateRecord {
    fn new(cert: Certificate) -> CertificateRecord {
        CertificateRecord {
            paths: Vec::new(),
            cert,
        }
    }
}

#[derive(Debug)]
pub enum APIError {
    Network(reqwest::Error),
    Status(reqwest::StatusCode),
}

impl Display for APIError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            APIError::Network(err) => Display::fmt(err, f),
            APIError::Status(code) => match code.canonical_reason() {
                Some(reason) => write!(f, "{} {}", code.as_u16(), reason),
                None => write!(f, "{}", code.as_u16()),
            },
        }
    }
}

impl std::error::Error for APIError {}

impl From<reqwest::Error> for APIError {
    fn from(e: reqwest::Error) -> APIError {
        APIError::Network(e)
    }
}

impl From<reqwest::StatusCode> for APIError {
    fn from(e: reqwest::StatusCode) -> APIError {
        APIError::Status(e)
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
    pub logs: Vec<LogInfo>,
    pub fp_map: HashMap<CertificateFingerprint, CertificateRecord>,
    pub subject_map: HashMap<NameInfo, HashSet<CertificateFingerprint>>,
}

impl Carver {
    pub fn new(logs: Vec<LogInfo>) -> Carver {
        Carver {
            logs,
            fp_map: HashMap::new(),
            subject_map: HashMap::new(),
        }
    }

    pub fn add_cert(&mut self, der: CertificateBytes, path: &str) {
        if let Ok(cert) = Certificate::parse(der) {
            let digest = cert.fingerprint();
            let subject = cert.get_subject().clone();

            let entry = self.fp_map.entry(digest);
            let info = entry.or_insert_with(|| CertificateRecord::new(cert));
            info.paths.push(String::from(path));

            let entry = self.subject_map.entry(subject);
            let fp_vec = entry.or_insert_with(HashSet::new);
            fp_vec.insert(digest);
        }
    }

    pub fn carve_stream<R: Read>(&self, stream: R) -> Vec<CertificateBytes> {
        lazy_static! {
            static ref HEADER_RE: Regex = Regex::new(
                "(?P<DER>(?-u:\\x30\\x82(?P<length>..)\\x30\\x82..(?:\\xa0\\x03\\x02\\x01.)?\\x02))|\
                (?P<PEM>-----BEGIN CERTIFICATE-----)|\
                (?P<XMLDSig><(?:[A-Z_a-z][A-Z_a-z-.0-9]*:)?(X509Certificate|EncapsulatedTimeStamp|CertifiedRole|EncapsulatedX509Certificate|EncapsulatedCRLValue|EncapsulatedOCSPValue)[> ])"
            ).unwrap();
            static ref PEM_END_RE: Regex = Regex::new("-----END CERTIFICATE-----").unwrap();
            static ref XMLDSIG_END_RE: Regex = Regex::new(
                "</(?:[A-Z_a-z][A-Z_a-z-.0-9]*:)?(X509Certificate|EncapsulatedTimeStamp|CertifiedRole|EncapsulatedX509Certificate|EncapsulatedCRLValue|EncapsulatedOCSPValue)>"
            ).unwrap();
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
                        let length = u16::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
                        let start = m.start();
                        let end = start + length + 4;
                        if end <= buf.len() {
                            results.push(CertificateBytes(buf[start..end].to_vec()));
                            start + 2
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
                        let b64_start = m.end();
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
                    } else if let Some(m) = caps.name("XMLDSig") {
                        let tag_start = m.start();
                        let temp_start = m.end() - 1;
                        match buf[temp_start..].iter().position(|&b| b == '>' as u8) {
                            None => {
                                // The buffer has the beginning of an opening tag, but not its
                                // closing angle bracket, try reading more if the buffer is too
                                // small
                                if buf.len() - tag_start < MAX_CERTIFICATE_SIZE && !eof {
                                    min_size = MAX_CERTIFICATE_SIZE;
                                    tag_start
                                } else {
                                    // Couldn't find the end of the opening tag, this was probably
                                    // a false positive. Skip the opening angle bracket and keep
                                    // searching.
                                    1
                                }
                            }
                            Some(bracket_off) => {
                                let b64_start = temp_start + bracket_off + 1;
                                match XMLDSIG_END_RE.find(&buf[b64_start..]) {
                                    Some(m2) => {
                                        let b64_end = b64_start + m2.start();
                                        let encoded = &buf[b64_start..b64_end];
                                        if let Ok(bytes) = pem_base64_decode(&encoded) {
                                            let mut cursor = Cursor::new(bytes);
                                            results.append(&mut self.carve_stream(&mut cursor));
                                        }
                                        m.end()
                                    }
                                    None => {
                                        // The closing tag isn't in the buffer yet, try reading
                                        // more if the buffer is too small
                                        if buf.len() - tag_start < MAX_CERTIFICATE_SIZE && !eof {
                                            min_size = MAX_CERTIFICATE_SIZE;
                                            tag_start
                                        } else {
                                            // Couldn't find a closing tag, this was probably a
                                            // false positive. Keep searching from after the
                                            // opening tag.
                                            m.end()
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        panic!("Impossible else branch, if this regex matches, one of its three capturing groups must match");
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
        let mut magic: [u8; 4] = [0; 4];
        match file.read(&mut magic) {
            Ok(_) => (),
            Err(_) => return Vec::new(),
        }
        match file.seek(SeekFrom::Start(0)) {
            Ok(_) => (),
            Err(_) => return Vec::new(),
        }
        if magic == ZIP_MAGIC {
            let mut results = Vec::new();
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
            results.append(&mut self.carve_stream(&mut file));
            results
        } else if magic == PDF_MAGIC {
            if let Some(mut results) = self.carve_pdf(&mut file) {
                match file.seek(SeekFrom::Start(0)) {
                    Ok(_) => (),
                    Err(_) => return results,
                }
                results.append(&mut self.carve_stream(&mut file));
                results
            } else {
                match file.seek(SeekFrom::Start(0)) {
                    Ok(_) => (),
                    Err(_) => return Vec::new(),
                }
                self.carve_stream(&mut file)
            }
        } else {
            self.carve_stream(&mut file)
        }
    }

    fn carve_pdf(&self, file: &mut Read) -> Option<Vec<CertificateBytes>> {
        let doc = lopdf::Document::load_from(file).ok()?;
        let catalog = doc.catalog()?;
        let acroform_ref = catalog
            .get(b"AcroForm")
            .and_then(|obj| obj.as_reference())?;
        let acroform = doc.get_object(acroform_ref).and_then(|obj| obj.as_dict())?;
        let sigflags = acroform.get(b"SigFlags").and_then(|obj| obj.as_i64())?;
        if sigflags & 1 == 0 {
            // The first bit position is "SignaturesExist"
            return None;
        }
        let fields = acroform.get(b"Fields").and_then(|obj| obj.as_array())?;
        let mut results = Vec::new();
        for field_ref in fields.into_iter().filter_map(|obj| obj.as_reference()) {
            if let Some(field) = doc.get_object(field_ref).and_then(|obj| obj.as_dict()) {
                if field.get(b"FT").and_then(|obj| obj.as_name()) == Some(b"Sig") {
                    if let Some(value_ref) = field.get(b"V").and_then(|obj| obj.as_reference()) {
                        if let Some(value) = doc.get_object(value_ref).and_then(|obj| obj.as_dict())
                        {
                            if let Some(lopdf::Object::String(bytes, _)) = value.get(b"Contents") {
                                results.append(&mut self.carve_stream(&bytes[..]));
                            }
                            if let Some(lopdf::Object::String(bytes, _)) = value.get(b"Cert") {
                                results.append(&mut self.carve_stream(&bytes[..]));
                            }
                        }
                    }
                }
            }
        }
        Some(results)
    }

    pub fn scan_file_object<RS: Read + Seek>(&mut self, mut file: &mut RS, path: &str) {
        for certbytes in self.carve_file(&mut file).into_iter() {
            self.add_cert(certbytes, path);
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

    pub fn build_chains(
        &self,
        leaf: &Certificate,
        trust_roots: &TrustRoots,
    ) -> Vec<CertificateChain> {
        fn recurse<'a>(
            cert: &'a Certificate,
            history: &[CertificateFingerprint],
            fp_map: &'a HashMap<CertificateFingerprint, CertificateRecord>,
            subject_map: &'a HashMap<NameInfo, HashSet<CertificateFingerprint>>,
            trust_roots: &TrustRoots,
        ) -> Vec<Vec<CertificateFingerprint>> {
            if let Some(issuer_fps) = subject_map.get(cert.get_issuer()) {
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

                    let issuer_cert = &fp_map[issuer_fp].cert;
                    if issuer_cert.get_subject() == cert.get_subject() {
                        // Don't follow self-signed certificates with the same name as this one
                        continue;
                    }

                    let mut new = history.to_owned();
                    new.push(cert.fingerprint());
                    if trust_roots.test_fingerprint(&issuer_fp) {
                        partial_chains.push(new);
                        // only want this chain once, even if we have multiple equivalent roots
                        break;
                    } else {
                        let mut result =
                            recurse(issuer_cert, &new, fp_map, subject_map, trust_roots);
                        partial_chains.append(&mut result);
                    }
                }
                partial_chains
            } else {
                Vec::new()
            }
        }
        let fp_chains = recurse(
            leaf,
            &Vec::new(),
            &self.fp_map,
            &self.subject_map,
            trust_roots,
        );
        fp_chains
            .into_iter()
            .map(|fp_chain| {
                CertificateChain(
                    fp_chain
                        .into_iter()
                        .map(|fp| self.fp_map[&fp].cert.get_bytes().clone())
                        .collect(),
                )
            })
            .collect()
    }

    pub fn run(&mut self, args: &[String], crtsh: &CrtShServer, log_comms: &LogServers) {
        for arg in args.iter() {
            self.scan_directory_or_file(&arg);
        }
        let mut all_roots_vec = Vec::new();
        for log in self.logs.iter_mut() {
            for root_cert in log.roots.iter() {
                all_roots_vec.push(root_cert.clone());
            }
        }
        for root_cert in all_roots_vec.iter() {
            self.add_cert(root_cert.get_bytes().clone(), "log roots");
        }
        let mut all_roots = TrustRoots::new();
        all_roots.add_roots(&all_roots_vec[..]);

        let mut total_found = 0;
        let mut total_not_found = 0;
        let mut count_no_chain = 0;
        let mut new_certs: Vec<&Certificate> = Vec::new();
        for (fp, info) in self.fp_map.iter() {
            if all_roots.test_fingerprint(fp) {
                // skip root CAs
                continue;
            }
            info.cert.format_issuer_subject(&mut stdout()).unwrap();
            println!();
            if !self.build_chains(&info.cert, &all_roots).is_empty() {
                let found = crtsh.check_crtsh(fp).unwrap();
                if found {
                    total_found += 1;
                } else {
                    total_not_found += 1;
                    new_certs.push(&info.cert);
                }

                println!(
                    "{}, crtsh seen = {}, {} file paths",
                    fp,
                    found,
                    info.paths.len()
                );
            } else {
                count_no_chain += 1;

                println!("{}, doesn't chain, {} file paths", fp, info.paths.len());
            }
            for path in info.paths.iter() {
                println!("{}", path);
            }
            println!();
        }
        let total = total_found + total_not_found;
        println!(
            "{}/{} in crt.sh already, {}/{} not yet in crt.sh ({} did not chain to roots)",
            total_found, total, total_not_found, total, count_no_chain
        );
        println!();

        let mut new_submission_count = 0;
        let new_certs_len = new_certs.len();
        for cert in new_certs.into_iter() {
            let mut any_chain = false;
            let mut any_submission_success = false;
            let mut all_submission_errors = true;
            let mut last_submission_error: Option<APIError> = None;
            for log in self.logs.iter() {
                if log.trust_roots.test_fingerprint(&cert.fingerprint()) {
                    // skip root CAs
                    continue;
                }
                if !log.will_accept_year(cert.get_not_after_year()) {
                    continue;
                }
                let chains = self.build_chains(cert, &log.trust_roots);
                for chain in chains.into_iter() {
                    any_chain = true;
                    match log_comms.submit_chain(&log, &chain) {
                        Ok(_) => {
                            if !any_submission_success {
                                new_submission_count += 1;
                            }
                            any_submission_success = true;
                            all_submission_errors = false;

                            print!("submitted to {}: {}, ", log.get_url(), cert.fingerprint());
                            cert.format_issuer_subject(&mut stdout()).unwrap();
                            println!();
                            println!();
                            // only submit one chain
                            break;
                        }
                        Err(APIError::Status(status)) => {
                            all_submission_errors = false; // don't want to panic on this

                            print!(
                                "submission was rejected by {} with reason {}: {}, ",
                                log.get_url(),
                                status,
                                cert.fingerprint()
                            );
                            cert.format_issuer_subject(&mut stdout()).unwrap();
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
                let error_desc = error.to_string();
                panic!(error_desc);
            }
        }
        println!(
            "Successfully submitted {}/{} new certificates",
            new_submission_count, new_certs_len
        );
    }
}

#[cfg(test)]
mod tests {
    use super::Carver;
    use std::io::Cursor;

    #[test]
    fn test_der_too_short() {
        const BYTES: [u8; 14] = [
            0x30, 0x82, 0xff, 0xff, 0x30, 0x82, 0xff, 0xf0, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        ];

        let mut stream = Cursor::new(&BYTES);
        let carver = Carver::new(Vec::new());
        let certs = carver.carve_stream(&mut stream);
        assert!(certs.is_empty());
    }

    #[test]
    fn test_pem_too_short() {
        const BYTES: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIC";

        let mut stream = Cursor::new(&BYTES);
        let carver = Carver::new(Vec::new());
        let certs = carver.carve_stream(&mut stream);
        assert!(certs.is_empty());
    }

}
