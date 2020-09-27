#![forbid(unsafe_code)]
pub mod crtsh;
pub mod ctlog;
pub mod ldapprep;
pub mod mocks;
pub mod x509;

use futures_core::future::BoxFuture;
use jwalk::WalkDir;
use lazy_static::lazy_static;
use log::{error, info, trace};
use rayon::iter::{ParallelBridge, ParallelIterator};
use regex::bytes::{CaptureLocations, Regex};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use zip::read::read_zipfile_from_stream;

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use crate::crtsh::CrtShServer;
use crate::ctlog::{LogInfo, LogServers, TrustRoots};
use crate::x509::{Certificate, NameInfo};

const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 3, 4];

// This was removed from base64 in version 0.10.0
fn copy_without_whitespace(input: &[u8]) -> Vec<u8> {
    let mut input_copy = Vec::<u8>::with_capacity(input.len());
    input_copy.extend(input.iter().filter(|b| !b" \n\t\r\x0b\x0c".contains(b)));

    input_copy
}

fn pem_base64_config() -> base64::Config {
    base64::Config::new(base64::CharacterSet::Standard, true)
}

fn pem_base64_encode(input: &[u8]) -> String {
    base64::encode_config(input, pem_base64_config())
}

fn pem_base64_decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, base64::DecodeError> {
    let stripped = copy_without_whitespace(input.as_ref());
    base64::decode_config(&stripped, pem_base64_config())
}

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
pub enum ApiError {
    Io(io::Error),
    Surf(surf::Exception),
    Status(surf::http::status::StatusCode),
    Json(json::Error),
    InvalidResponse(&'static str),
}

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            ApiError::Io(err) => Display::fmt(err, f),
            ApiError::Surf(err) => Display::fmt(err, f),
            ApiError::Status(code) => match code.canonical_reason() {
                Some(reason) => write!(f, "{} {}", code.as_u16(), reason),
                None => write!(f, "{}", code.as_u16()),
            },
            ApiError::Json(err) => Display::fmt(err, f),
            ApiError::InvalidResponse(details) => write!(f, "Invalid response, {}", details),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<io::Error> for ApiError {
    fn from(e: io::Error) -> ApiError {
        ApiError::Io(e)
    }
}

impl From<surf::Exception> for ApiError {
    fn from(e: surf::Exception) -> ApiError {
        ApiError::Surf(e)
    }
}

impl From<surf::http::status::StatusCode> for ApiError {
    fn from(e: surf::http::status::StatusCode) -> ApiError {
        ApiError::Status(e)
    }
}

impl From<json::Error> for ApiError {
    fn from(e: json::Error) -> ApiError {
        ApiError::Json(e)
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

    fn fill_buf(&mut self, min_size: usize) -> io::Result<(&[u8], bool)> {
        // like BufRead::fill_buf, but reads if there is min_size or less left in the buffer,
        // not just when it is empty. Returns a buffer and a boolean to indicate end of file,
        // or an error.
        let remaining = self.cap - self.pos;
        let mut eof = false;
        if remaining <= min_size {
            if self.pos > 0 {
                self.buf.copy_within(self.pos..self.cap, 0);
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

#[derive(Default)]
pub struct CertificatePool {
    pub fp_map: HashMap<CertificateFingerprint, CertificateRecord>,
    pub subject_map: HashMap<NameInfo, HashSet<CertificateFingerprint>>,
}

impl CertificatePool {
    pub fn new() -> CertificatePool {
        CertificatePool::default()
    }

    pub fn add_cert(&mut self, cert: Certificate, path: String) {
        if cert.looks_like_ca() || cert.looks_like_server() {
            let digest = cert.fingerprint();
            let subject = cert.get_subject().clone();

            let entry = self.fp_map.entry(digest);
            let info = entry.or_insert_with(|| CertificateRecord::new(cert));
            info.paths.push(path);

            let entry = self.subject_map.entry(subject);
            let fp_vec = entry.or_insert_with(HashSet::new);
            fp_vec.insert(digest);
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
}

lazy_static! {
    static ref HEADER_RE: Regex = Regex::new(
        "((?-u:\\x30\\x82(..)\\x30\\x82..(?:\\xa0\\x03\\x02\\x01.)?\\x02))|\
        (-----BEGIN CERTIFICATE-----)|\
        (<(?:[A-Z_a-z][A-Z_a-z-.0-9]*:)?(?:X509Certificate|EncapsulatedTimeStamp|CertifiedRole|EncapsulatedX509Certificate|EncapsulatedCRLValue|EncapsulatedOCSPValue)[> ])"
    ).unwrap();
    static ref PEM_END_RE: Regex = Regex::new("-----END CERTIFICATE-----").unwrap();
    static ref XMLDSIG_END_RE: Regex = Regex::new(
        "</(?:[A-Z_a-z][A-Z_a-z-.0-9]*:)?(?:X509Certificate|EncapsulatedTimeStamp|CertifiedRole|EncapsulatedX509Certificate|EncapsulatedCRLValue|EncapsulatedOCSPValue)>"
    ).unwrap();
}

#[derive(Debug)]
pub enum CarveError {
    IO(io::Error),
    X509(x509::Error),
    Zip(zip::result::ZipError),
}

impl fmt::Display for CarveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CarveError::IO(e) => Display::fmt(e, f),
            CarveError::X509(e) => Display::fmt(e, f),
            CarveError::Zip(e) => Display::fmt(e, f),
        }
    }
}

impl From<io::Error> for CarveError {
    fn from(e: io::Error) -> Self {
        CarveError::IO(e)
    }
}

impl From<x509::Error> for CarveError {
    fn from(e: x509::Error) -> Self {
        CarveError::X509(e)
    }
}

impl From<zip::result::ZipError> for CarveError {
    fn from(e: zip::result::ZipError) -> Self {
        CarveError::Zip(e)
    }
}

pub struct CarveBytesResult {
    pub res: Result<CertificateBytes, CarveError>,
    pub path: String,
}

struct CarveCertResult {
    pub res: Result<Certificate, CarveError>,
    pub path: String,
}

pub struct FileCarver {
    caps: CaptureLocations,
}

impl Default for FileCarver {
    fn default() -> Self {
        Self::new()
    }
}

impl FileCarver {
    pub fn new() -> FileCarver {
        FileCarver {
            caps: HEADER_RE.capture_locations(),
        }
    }

    fn carve_stream<R: Read>(
        &mut self,
        stream: &mut R,
    ) -> Vec<Result<CertificateBytes, CarveError>> {
        let mut results = Vec::new();

        const MAX_CERTIFICATE_SIZE: usize = 16 * 1024;
        const BUFFER_SIZE: usize = 32 * 1024;
        const OVERLAP: usize = 40; // enough to capture a XMLDSig opening tag (or PEM header or DER prefix)
        let mut stream = BufReaderOverlap::with_capacity(BUFFER_SIZE, stream);
        let mut min_size = OVERLAP;
        loop {
            let (buf, eof) = match stream.fill_buf(min_size) {
                Ok((buf, eof)) => (buf, eof),
                Err(e) => {
                    results.push(Err(e.into()));
                    return results;
                }
            };
            min_size = OVERLAP;
            let consume_amount: usize = match HEADER_RE.captures_read(&mut self.caps, &buf) {
                Some(_) => {
                    if let Some((start, _end)) = self.caps.get(1) {
                        let (length_start, _length_end) = self.caps.get(2).unwrap();
                        let length_bytes = [buf[length_start], buf[length_start + 1]];
                        let length = u16::from_be_bytes(length_bytes) as usize;
                        let end = start + length + 4;
                        if end <= buf.len() {
                            results.push(Ok(CertificateBytes(buf[start..end].to_vec())));
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
                    } else if let Some((header_start, b64_start)) = self.caps.get(3) {
                        match PEM_END_RE.find(&buf[b64_start..]) {
                            Some(m2) => {
                                let b64_end = b64_start + m2.start();
                                let encoded = &buf[b64_start..b64_end];
                                match pem_base64_decode(&encoded) {
                                    Ok(bytes) => results.push(Ok(CertificateBytes(bytes))),
                                    Err(e) => trace!(
                                        "Skipping PEM certificate with invalid contents, {}",
                                        e,
                                    ),
                                }
                                b64_start - 5
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
                                    b64_start - 5
                                }
                            }
                        }
                    } else if let Some((tag_start, match_end)) = self.caps.get(4) {
                        let temp_start = match_end - 1;
                        match buf[temp_start..].iter().position(|&b| b == b'>') {
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
                                        match pem_base64_decode(&encoded) {
                                            Ok(bytes) => {
                                                let mut cursor = Cursor::new(bytes);
                                                results.append(&mut self.carve_stream(&mut cursor));
                                            }
                                            Err(e) => trace!(
                                                "Skipping XMLDsig tag with invalid base64 contents, {}",
                                                e,
                                            ),
                                        }
                                        match_end
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
                                            match_end
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

    pub fn carve_file<RS: Read + Seek>(
        &mut self,
        mut file: &mut RS,
    ) -> Vec<Result<CertificateBytes, CarveError>> {
        let mut magic: [u8; 4] = [0; 4];
        match file.read(&mut magic) {
            Ok(_) => (),
            Err(e) => return vec![Err(e.into())],
        }
        match file.seek(SeekFrom::Start(0)) {
            Ok(_) => (),
            Err(e) => return vec![Err(e.into())],
        }
        if magic == ZIP_MAGIC {
            let mut results = Vec::new();
            loop {
                match read_zipfile_from_stream(&mut file) {
                    Ok(Some(mut zip_file)) => {
                        results.append(&mut self.carve_stream(&mut zip_file));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        results.push(Err(e.into()));
                        break;
                    }
                }
            }
            match file.seek(SeekFrom::Start(0)) {
                Ok(_) => (),
                Err(e) => {
                    results.push(Err(e.into()));
                    return results;
                }
            }
            results.append(&mut self.carve_stream(&mut file));
            results
        } else {
            self.carve_stream(&mut file)
        }
    }

    pub fn scan_file_object<RS: Read + Seek>(
        &mut self,
        mut file: &mut RS,
        path_buf: PathBuf,
    ) -> Vec<CarveBytesResult> {
        self.carve_file(&mut file)
            .into_iter()
            .map(|res| CarveBytesResult {
                res,
                path: path_buf.to_str().unwrap_or("(unprintable path)").to_owned(),
            })
            .collect()
    }
}

#[cfg(not(unix))]
fn filter_file_metadata(metadata: &std::fs::Metadata) -> bool {
    metadata.len() > 0 && !metadata.file_type().is_dir() && !metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn filter_file_metadata(metadata: &std::fs::Metadata) -> bool {
    if metadata.len() == 0 {
        return false;
    }
    let file_type = metadata.file_type();
    !file_type.is_dir()
        && !file_type.is_symlink()
        && !file_type.is_block_device()
        && !file_type.is_char_device()
        && !file_type.is_fifo()
        && !file_type.is_socket()
}

pub fn run<I: Iterator<Item = PathBuf> + Send, C: CrtShServer, L: LogServers>(
    logs: Vec<LogInfo>,
    paths: I,
    crtsh: &C,
    log_comms: &L,
) {
    let (sender, receiver): (
        mpsc::Sender<CarveCertResult>,
        mpsc::Receiver<CarveCertResult>,
    ) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut pool = CertificatePool::new();
        for match_cert in receiver {
            match match_cert.res {
                Ok(cert) => pool.add_cert(cert, match_cert.path),
                Err(e) => info!("Certificate parsing error in {}: {}", match_cert.path, e),
            }
        }
        pool
    });
    let threadpool = Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap(),
    );
    paths
        .par_bridge()
        .flat_map(|path| {
            WalkDir::new(path)
                .parallelism(jwalk::Parallelism::RayonExistingPool(threadpool.clone()))
                .into_iter()
                .par_bridge()
                .filter_map(Result::ok)
                .filter(|entry| match entry.metadata() {
                    Ok(ref metadata) => filter_file_metadata(metadata),
                    Err(e) => {
                        error!("Failed to read metadata of {:?}, {:?}", entry.path(), e);
                        false
                    }
                })
                .map(|entry| entry.path())
        })
        .map_init(FileCarver::new, |file_carver, path| {
            trace!("Carving {:?}", &path);
            match File::open(&path) {
                Ok(mut file) => file_carver.scan_file_object(&mut file, path),
                Err(e) => {
                    error!("Failed to open {:?}, {:?}", path, e);
                    vec![]
                }
            }
        })
        .flatten()
        .map(|match_bytes| {
            let res = match match_bytes.res {
                Ok(bytes) => Certificate::parse(bytes).map_err(|e| e.into()),
                Err(e) => Err(e),
            };
            CarveCertResult {
                res,
                path: match_bytes.path,
            }
        })
        .filter(|match_cert| {
            if let Ok(cert) = &match_cert.res {
                cert.looks_like_ca() || cert.looks_like_server()
            } else {
                true
            }
        })
        .for_each_with(sender, |sender, match_cert| {
            sender.send(match_cert).unwrap()
        });
    let mut pool = thread.join().unwrap();

    let mut all_roots_vec = Vec::new();
    for log in logs.iter() {
        for root_cert in log.roots.iter() {
            all_roots_vec.push(root_cert.clone());
        }
    }
    for root_cert in all_roots_vec.iter() {
        pool.add_cert(root_cert.clone(), "log roots".to_string());
    }
    let mut all_roots = TrustRoots::new();
    all_roots.add_roots(&all_roots_vec[..]);

    let mut total_found = 0;
    let mut total_not_found = 0;
    let mut count_no_chain = 0;
    let mut new_certs: Vec<&Certificate> = Vec::new();
    for (fp, info) in pool.fp_map.iter() {
        if all_roots.test_fingerprint(fp) {
            // skip root CAs
            continue;
        }
        println!("{}", info.cert.format_issuer_subject());
        if !pool.build_chains(&info.cert, &all_roots).is_empty() {
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
        let path_limit = 10;
        for path in info.paths.iter().take(path_limit) {
            println!("{}", path);
        }
        if info.paths.len() > path_limit {
            println!("...");
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
        let mut last_submission_error: Option<ApiError> = None;
        for log in logs.iter() {
            if log.trust_roots.test_fingerprint(&cert.fingerprint()) {
                // skip root CAs
                continue;
            }
            if !log.will_accept_year(cert.get_not_after_year()) {
                continue;
            }
            let chains = pool.build_chains(cert, &log.trust_roots);
            for chain in chains.into_iter() {
                any_chain = true;
                match log_comms.submit_chain(&log, &chain) {
                    Ok(_) => {
                        if !any_submission_success {
                            new_submission_count += 1;
                        }
                        any_submission_success = true;
                        all_submission_errors = false;

                        println!(
                            "submitted to {}: {}, {}",
                            log.get_url(),
                            cert.fingerprint(),
                            cert.format_issuer_subject()
                        );
                        println!();
                        // only submit one chain
                        break;
                    }
                    Err(ApiError::Status(status)) => {
                        all_submission_errors = false; // don't want to panic on this

                        println!(
                            "submission was rejected by {} with reason {}: {}, {}",
                            log.get_url(),
                            status,
                            cert.fingerprint(),
                            cert.format_issuer_subject(),
                        );
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

fn add_user_agent_header<C: surf::middleware::HttpClient>(
    mut req: surf::middleware::Request,
    client: C,
    next: surf::middleware::Next<'_, C>,
) -> BoxFuture<'_, Result<surf::middleware::Response, surf::Exception>> {
    Box::pin(async move {
        req.headers_mut().insert(
            surf::http::header::USER_AGENT,
            surf::http::header::HeaderValue::from_static(
                "certificate_carver (https://github.com/divergentdave/certificate_carver)",
            ),
        );
        next.run(req, client).await
    })
}

#[cfg(test)]
mod tests {
    use super::FileCarver;
    use std::io::Cursor;

    #[test]
    fn test_der_too_short() {
        const BYTES: [u8; 14] = [
            0x30, 0x82, 0xff, 0xff, 0x30, 0x82, 0xff, 0xf0, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        ];

        let mut stream = Cursor::new(&BYTES);
        let mut file_carver = FileCarver::new();
        let certs = file_carver.carve_stream(&mut stream);
        assert!(certs.is_empty());
    }

    #[test]
    fn test_pem_too_short() {
        const BYTES: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIC";

        let mut stream = Cursor::new(&BYTES);
        let mut file_carver = FileCarver::new();
        let certs = file_carver.carve_stream(&mut stream);
        assert!(certs.is_empty());
    }
}
