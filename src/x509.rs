use encoding::all::ISO_8859_1;
use encoding::{DecoderTrap, Encoding};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::io::Write;
use untrusted;

use crate::{CertificateBytes, CertificateFingerprint};

use crate::ldapprep::ldapprep_case_insensitive;

const CONSTRUCTED: u8 = 1 << 5;
const CONTEXT_SPECIFIC: u8 = 2 << 6;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum Tag {
    // Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    // OctetString = 0x04,
    // Null = 0x05,
    OID = 0x06,
    Utf8String = 0x0C,
    PrintableString = 0x13,
    TeletexString = 0x14,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    Sequence = CONSTRUCTED | 0x10, // 0x30
    Set = CONSTRUCTED | 0x11,      // 0x31
    // UTCTime = 0x17,
    // GeneralizedTime = 0x18,
    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED | 0,
    // ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
}

const NAME_ATTRIBUTES_DESCRIPTIONS: [(NameType, &str); 14] = [
    (NameType::CountryName, "C"),
    (NameType::OrganizationName, "O"),
    (NameType::OrganizationalUnitName, "OU"),
    (
        NameType::DistinguishedNameQualifier,
        "Distinguished Name Qualifier",
    ),
    (NameType::StateOrProvinceName, "ST"),
    (NameType::CommonName, "CN"),
    (NameType::SerialNumber, "SN"),
    (NameType::LocalityName, "L"),
    (NameType::Title, "T"),
    (NameType::Surname, "S"),
    (NameType::GivenName, "G"),
    (NameType::Initials, "I"),
    (NameType::Pseudonym, "Pseudonym"),
    (NameType::GenerationQualifier, "Generation Qualifier"),
];

#[derive(Clone)]
pub struct Certificate {
    bytes: CertificateBytes,
    fp: CertificateFingerprint,
    not_after_year: Year,
    issuer: NameInfo,
    subject: NameInfo,
}

impl Certificate {
    pub fn parse(bytes: CertificateBytes) -> Result<Certificate, Error> {
        let (issuer, subject, not_after_year) = Certificate::parse_cert_contents(bytes.as_ref())?;
        let mut arr: [u8; 32] = Default::default();
        arr.copy_from_slice(&Sha256::digest(bytes.as_ref()));
        let fp = CertificateFingerprint(arr);
        Ok(Certificate {
            bytes,
            fp,
            not_after_year,
            issuer,
            subject,
        })
    }

    fn parse_cert_contents(bytes: &[u8]) -> Result<(NameInfo, NameInfo, Year), Error> {
        let cert_der = untrusted::Input::from(bytes);
        let tbs_der = cert_der.read_all(Error::BadDERCertificateExtraData, |cert_der| {
            nested(
                cert_der,
                Tag::Sequence,
                Error::BadDERCertificate,
                Error::BadDERCertificateExtraData,
                parse_signed_data,
            )
        })?;
        let (issuer, subject, not_after_year) =
            tbs_der.read_all(Error::BadDERCertificate, |tbs_der| {
                let (first_tag, _first_value) =
                    read_tag_and_get_value(tbs_der, Error::BadDERSerialNumber)?;
                let next_tag =
                    if (first_tag as usize) == (Tag::ContextSpecificConstructed0 as usize) {
                        // skip version number, if present
                        let (next_tag, _next_value) =
                            read_tag_and_get_value(tbs_der, Error::BadDERSerialNumber)?;
                        next_tag
                    } else {
                        first_tag
                    };

                // skip serial number, either the first or second tag
                if (next_tag as usize) != (Tag::Integer as usize) {
                    return Err(Error::SerialNumberNotInteger);
                }

                skip(tbs_der, Tag::Sequence, Error::BadDERSignatureInTBS)?;

                let issuer = expect_tag_and_get_value(tbs_der, Tag::Sequence, Error::BadDERIssuer)?;
                let issuer = copy_input(&issuer);

                let not_after_year = nested(
                    tbs_der,
                    Tag::Sequence,
                    Error::BadDERValidity,
                    Error::BadDERValidityExtraData,
                    parse_validity,
                )?;

                let subject =
                    expect_tag_and_get_value(tbs_der, Tag::Sequence, Error::BadDERSubject)?;
                let subject = copy_input(&subject);

                skip(tbs_der, Tag::Sequence, Error::BadDERSPKI)?;

                if !tbs_der.at_end() {
                    skip(
                        tbs_der,
                        Tag::ContextSpecificConstructed3,
                        Error::BadDERExtensions,
                    )?;
                }

                Ok((issuer, subject, not_after_year))
            })?;
        Ok((
            NameInfo::new(issuer),
            NameInfo::new(subject),
            not_after_year,
        ))
    }

    pub fn fingerprint(&self) -> CertificateFingerprint {
        self.fp
    }

    pub fn format_issuer_subject(&self, f: &mut Write) -> std::io::Result<()> {
        write!(f, "issuer=")?;
        self.issuer.format(f)?;
        write!(f, ", subject=")?;
        self.subject.format(f)
    }

    pub fn issued(&self, other: &Certificate) -> bool {
        self.subject == other.issuer
    }

    pub fn get_issuer(&self) -> &NameInfo {
        &self.issuer
    }

    pub fn get_subject(&self) -> &NameInfo {
        &self.subject
    }

    pub fn get_bytes(&self) -> &CertificateBytes {
        &self.bytes
    }

    pub fn get_not_after_year(&self) -> u64 {
        self.not_after_year.0
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
pub enum NameType {
    CountryName,
    OrganizationName,
    OrganizationalUnitName,
    DistinguishedNameQualifier,
    StateOrProvinceName,
    CommonName,
    SerialNumber,
    LocalityName,
    Title,
    Surname,
    GivenName,
    Initials,
    Pseudonym,
    GenerationQualifier,
    UnrecognizedType,
}

pub enum MatchingRule {
    CaseIgnoreMatch,
    Unknown,
}

impl NameType {
    fn matching_rule(&self) -> MatchingRule {
        // See ITU-T Rec. X.520 § 6
        match self {
            NameType::CountryName => MatchingRule::CaseIgnoreMatch,
            NameType::OrganizationName => MatchingRule::CaseIgnoreMatch,
            NameType::OrganizationalUnitName => MatchingRule::CaseIgnoreMatch,
            NameType::DistinguishedNameQualifier => MatchingRule::CaseIgnoreMatch,
            NameType::StateOrProvinceName => MatchingRule::CaseIgnoreMatch,
            NameType::CommonName => MatchingRule::CaseIgnoreMatch,
            NameType::SerialNumber => MatchingRule::CaseIgnoreMatch,
            NameType::LocalityName => MatchingRule::CaseIgnoreMatch,
            NameType::Title => MatchingRule::CaseIgnoreMatch,
            NameType::Surname => MatchingRule::CaseIgnoreMatch,
            NameType::GivenName => MatchingRule::CaseIgnoreMatch,
            NameType::Initials => MatchingRule::CaseIgnoreMatch,
            NameType::Pseudonym => MatchingRule::CaseIgnoreMatch,
            NameType::GenerationQualifier => MatchingRule::CaseIgnoreMatch,
            NameType::UnrecognizedType => MatchingRule::Unknown,
        }
    }
}

impl From<&[u8]> for NameType {
    fn from(type_oid: &[u8]) -> NameType {
        if type_oid.len() != 3 || type_oid[0] != 0x55 || type_oid[1] != 0x04 {
            NameType::UnrecognizedType
        } else {
            match type_oid[2] {
                0x06 => NameType::CountryName,
                0x0A => NameType::OrganizationName,
                0x0B => NameType::OrganizationalUnitName,
                0x2E => NameType::DistinguishedNameQualifier,
                0x08 => NameType::StateOrProvinceName,
                0x03 => NameType::CommonName,
                0x05 => NameType::SerialNumber,
                0x07 => NameType::LocalityName,
                0x0C => NameType::Title,
                0x04 => NameType::Surname,
                0x2A => NameType::GivenName,
                0x2B => NameType::Initials,
                0x41 => NameType::Pseudonym,
                0x2C => NameType::GenerationQualifier,
                _ => NameType::UnrecognizedType,
            }
        }
    }
}

#[derive(Clone, Eq, Debug)]
pub struct NameTypeValue {
    pub bytes: Vec<u8>,
    pub name_type: NameType,
    pub value: Option<String>,
}

impl PartialEq for NameTypeValue {
    fn eq(&self, other: &NameTypeValue) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Ord for NameTypeValue {
    fn cmp(&self, other: &NameTypeValue) -> Ordering {
        match self.name_type.cmp(&other.name_type) {
            Ordering::Equal => {
                if self.name_type == NameType::UnrecognizedType {
                    self.bytes.cmp(&other.bytes)
                } else {
                    match (&self.value, &other.value) {
                        (Some(self_value), Some(other_value)) => {
                            match self.name_type.matching_rule() {
                                MatchingRule::CaseIgnoreMatch => {
                                    match (
                                        ldapprep_case_insensitive(&self_value),
                                        ldapprep_case_insensitive(&other_value),
                                    ) {
                                        (Ok(self_prepped), Ok(other_prepped)) => {
                                            self_prepped.cmp(&other_prepped)
                                        }
                                        _ => self.bytes.cmp(&other.bytes),
                                    }
                                }
                                MatchingRule::Unknown => self.bytes.cmp(&other.bytes),
                            }
                        }
                        (Some(_), None) => Ordering::Greater,
                        (None, Some(_)) => Ordering::Less,
                        (None, None) => Ordering::Equal,
                    }
                }
            }
            result => result,
        }
    }
}

impl PartialOrd for NameTypeValue {
    fn partial_cmp(&self, other: &NameTypeValue) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for NameTypeValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name_type.hash(state);
        match self.name_type {
            NameType::UnrecognizedType => self.bytes.hash(state),
            _ => match &self.value {
                Some(value) => match self.name_type.matching_rule() {
                    MatchingRule::CaseIgnoreMatch => match ldapprep_case_insensitive(&value) {
                        Ok(prepped) => prepped.hash(state),
                        Err(_) => self.bytes.hash(state),
                    },
                    MatchingRule::Unknown => self.bytes.hash(state),
                },
                None => self.bytes.hash(state),
            },
        }
    }
}

fn parse_directory_string(raw: &[u8]) -> Option<String> {
    let input = untrusted::Input::from(raw);
    if let Ok((tag, inner)) = input.read_all(Error::BadDERString, |value_der| {
        read_tag_and_get_value(value_der, Error::BadDERString)
    }) {
        let tag_usize: usize = tag as usize;
        let slice = inner.as_slice_less_safe();
        if tag_usize == (Tag::Utf8String as usize) || tag_usize == (Tag::PrintableString as usize) {
            String::from_utf8(slice.to_vec()).ok()
        } else if tag_usize == (Tag::TeletexString as usize) {
            let mut decoded = String::new();
            match ISO_8859_1.decode_to(slice, DecoderTrap::Replace, &mut decoded) {
                Ok(()) => Some(decoded),
                Err(_) => None,
            }
        } else {
            return None;
        }
    } else {
        None
    }
}

#[derive(Clone, Eq, Debug)]
pub struct RelativeDistinguishedName {
    pub attribs: Vec<NameTypeValue>,
}

impl PartialEq for RelativeDistinguishedName {
    fn eq(&self, other: &RelativeDistinguishedName) -> bool {
        if self.attribs.len() != other.attribs.len() {
            return false;
        }
        for a1 in self.attribs.iter() {
            let mut any_match = false;
            for a2 in other.attribs.iter() {
                if a1 == a2 {
                    any_match = true;
                    break;
                }
            }
            if !any_match {
                return false;
            }
        }
        true
    }
}

impl Hash for RelativeDistinguishedName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.attribs.len().hash(state);
        if self.attribs.len() == 1 {
            self.attribs[0].hash(state);
        } else if self.attribs.len() > 1 {
            let mut sorted = self.attribs.clone();
            sorted.sort();
            for attrib in sorted.iter() {
                attrib.hash(state);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct NameInfo {
    bytes: Vec<u8>,
    rdns: Result<Vec<RelativeDistinguishedName>, Error>,
}

impl NameInfo {
    pub fn new(bytes: Vec<u8>) -> NameInfo {
        let rdns = NameInfo::parse_rdns(&bytes);
        NameInfo { bytes, rdns }
    }

    fn parse_rdns(bytes: &[u8]) -> Result<Vec<RelativeDistinguishedName>, Error> {
        let mut results: Vec<RelativeDistinguishedName> = Vec::new();
        let name_der = untrusted::Input::from(bytes);
        name_der.read_all(Error::BadDERDistinguishedNameExtraData, |name_der| {
            while !name_der.at_end() {
                let mut attribs: Vec<NameTypeValue> = Vec::new();
                nested(
                    name_der,
                    Tag::Set,
                    Error::BadDERRelativeDistinguishedName,
                    Error::BadDERRelativeDistinguishedNameExtraData,
                    |rdn_der| {
                        loop {
                            nested(
                                rdn_der,
                                Tag::Sequence,
                                Error::BadDERRDNAttribute,
                                Error::BadDERRDNAttributeExtraData,
                                |attrib_der| {
                                    let mark_type_value_1 = attrib_der.mark();
                                    let attrib_type = expect_tag_and_get_value(
                                        attrib_der,
                                        Tag::OID,
                                        Error::BadDERRDNType,
                                    )?;
                                    let attrib_type = copy_input(&attrib_type);
                                    let mark_value_1 = attrib_der.mark();
                                    let (_value_tag, _value) =
                                        read_tag_and_get_value(attrib_der, Error::BadDERRDNValue)?;
                                    let mark_value_2 = attrib_der.mark();
                                    let mark_type_value_2 = attrib_der.mark();
                                    let value_data = attrib_der
                                        .get_input_between_marks(mark_value_1, mark_value_2)
                                        .unwrap();
                                    let value_data = copy_input(&value_data);
                                    let type_and_value_data = attrib_der
                                        .get_input_between_marks(
                                            mark_type_value_1,
                                            mark_type_value_2,
                                        )
                                        .unwrap();
                                    let type_and_value_data = copy_input(&type_and_value_data);
                                    attribs.push(NameTypeValue {
                                        bytes: type_and_value_data,
                                        name_type: NameType::from(attrib_type.as_ref()),
                                        value: parse_directory_string(&value_data),
                                    });
                                    Ok(())
                                },
                            )?;
                            if rdn_der.at_end() {
                                break;
                            }
                        }
                        Ok(())
                    },
                )?;
                results.push(RelativeDistinguishedName { attribs });
            }
            Ok(())
        })?;
        Ok(results)
    }

    pub fn format(&self, f: &mut Write) -> std::io::Result<()> {
        let mut space = false;
        match self.rdns {
            Ok(ref rdns) => {
                for (name_type, type_description) in NAME_ATTRIBUTES_DESCRIPTIONS.iter() {
                    for rdn in rdns.iter() {
                        for type_value in rdn.attribs.iter() {
                            if type_value.name_type == *name_type {
                                if space {
                                    write!(f, " {}=", type_description)?;
                                } else {
                                    write!(f, "{}=", type_description)?;
                                }
                                match &type_value.value {
                                    Some(string) => write!(f, "{}", string)?,
                                    None => write!(f, "(unparseable value)")?,
                                }
                                space = true;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                write!(f, "(unparseable name)")?;
            }
        }
        Ok(())
    }
}

impl AsRef<[u8]> for NameInfo {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl PartialEq for NameInfo {
    fn eq(&self, other: &NameInfo) -> bool {
        match (&self.rdns, &other.rdns) {
            (Ok(self_rdns), Ok(other_rdns)) => self_rdns == other_rdns,
            _ => self.bytes == other.bytes,
        }
    }
}

impl Hash for NameInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.rdns {
            Ok(rdns) => rdns.hash(state),
            Err(_) => self.bytes.hash(state),
        }
    }
}

impl Eq for NameInfo {}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    SerialNumberNotInteger,
    BadDERCertificate,
    BadDERCertificateExtraData,
    BadDERTBSCertificateWrongTag,
    BadDERTBSCertificateExtraData,
    BadDERSerialNumber,
    BadDERSignatureInTBS,
    BadDERIssuer,
    BadDERValidity,
    BadDERValidityExtraData,
    BadDERTime,
    BadDERTimeValue,
    BadDERSubject,
    BadDERSPKI,
    BadDERExtensions,
    BadDERDistinguishedNameExtraData,
    BadDERRelativeDistinguishedName,
    BadDERRelativeDistinguishedNameExtraData,
    BadDERRDNAttribute,
    BadDERRDNAttributeExtraData,
    BadDERRDNType,
    BadDERString,
    BadDERRDNValue,
    BadDERAlgorithm,
    BadDERSignature2,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Error::SerialNumberNotInteger => write!(f, "Certificate serial number is not an integer"),
            Error::BadDERCertificate => write!(f, "DER error encountered while parsing Certificate"),
            Error::BadDERCertificateExtraData => write!(f, "DER error encountered while parsing Certificate due to extra data"),
            Error::BadDERTBSCertificateWrongTag => write!(f, "DER error encountered while parsing TBSCertificate due to an incorrect tag"),
            Error::BadDERTBSCertificateExtraData => write!(f, "DER error encountered while parsing TBSCertificate due to extra data"),
            Error::BadDERSerialNumber => write!(f, "DER error encountered while parsing serial number"),
            Error::BadDERSignatureInTBS => write!(f, "DER error encountered while parsing signature informatin in TBSCertificate"),
            Error::BadDERIssuer => write!(f, "DER error encountered while parsing issuer"),
            Error::BadDERValidity => write!(f, "DER error encountered while parsing validity"),
            Error::BadDERValidityExtraData => write!(f, "DER error encountered while parsing validity due to extra data"),
            Error::BadDERTime => write!(f, "DER error encountered while parsing a time object"),
            Error::BadDERTimeValue => write!(f, "DER error encountered while parsing a time value"),
            Error::BadDERSubject => write!(f, "DER error encountered while parsing subject"),
            Error::BadDERSPKI => write!(f, "DER error encountered while parsing SubjectPublicKeyIdentifier"),
            Error::BadDERExtensions => write!(f, "DER error encountered while parsing extensions"),
            Error::BadDERDistinguishedNameExtraData => write!(f, "DER error encountered while parsing DistinguishedName due to extra data"),
            Error::BadDERRelativeDistinguishedName => write!(f, "DER error encountered while parsing RelativeDistinguishedName"),
            Error::BadDERRelativeDistinguishedNameExtraData => write!(f, "DER error encountered while parsing RelativeDistinguishedName due to extra data"),
            Error::BadDERRDNAttribute => write!(f, "DER error encountered while parsing RelativeDistinguishedName Attribute"),
            Error::BadDERRDNAttributeExtraData => write!(f, "DER error encountered while parsing RelativeDistinguishedName Attribute due to extra data"),
            Error::BadDERRDNType => write!(f, "DER error encountered while parsing RelativeDistinguishedName Type"),
            Error::BadDERString => write!(f, "DER error encountered while parsing a string"),
            Error::BadDERRDNValue => write!(f, "DER error encountered while parsing RelativeDistinguishedName Value"),
            Error::BadDERAlgorithm => write!(f, "DER error encountered while parsing outer signature algorithm"),
            Error::BadDERSignature2 => write!(f, "DER error encountered while parsing signature value"),
        }
    }
}

impl std::error::Error for Error {}

#[inline(always)]
fn expect_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
    error: Error,
) -> Result<untrusted::Input<'a>, Error> {
    let (actual_tag, inner) = read_tag_and_get_value(input, error)?;
    if (tag as usize) != (actual_tag as usize) {
        return Err(error);
    }
    Ok(inner)
}

fn read_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
    error: Error,
) -> Result<(u8, untrusted::Input<'a>), Error> {
    // based on ring::io::der::read_tag_and_get_value
    let tag = input.read_byte().map_err(|_| error)?;
    if (tag & 0x1F) == 0x1F {
        return Err(error); // High tag number form is not allowed.
    }

    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length.
    let length = match input.read_byte().map_err(|_| error)? {
        n if (n & 0x80) == 0 => n as usize,
        0x81 => {
            let second_byte = input.read_byte().map_err(|_| error)?;
            if second_byte < 128 {
                return Err(error); // Not the canonical encoding.
            }
            second_byte as usize
        }
        0x82 => {
            let second_byte = input.read_byte().map_err(|_| error)?;
            let third_byte = input.read_byte().map_err(|_| error)?;
            let combined = u16::from_be_bytes([second_byte, third_byte]) as usize;
            if combined < 256 {
                return Err(error); // Not the canonical encoding.
            }
            combined
        }
        _ => {
            return Err(error); // We don't support longer lengths.
        }
    };

    let inner = input.skip_and_get_input(length).map_err(|_| error)?;
    Ok((tag, inner))
}

fn skip(input: &mut untrusted::Reader, tag: Tag, error: Error) -> Result<(), Error> {
    expect_tag_and_get_value(input, tag, error).map(|_| ())
}

fn nested<'a, F, R>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
    error_wrong_tag: Error,
    error_incomplete_read: Error,
    decoder: F,
) -> Result<R, Error>
where
    F: FnOnce(&mut untrusted::Reader<'a>) -> Result<R, Error>,
{
    let inner = expect_tag_and_get_value(input, tag, error_wrong_tag)?;
    inner.read_all(error_incomplete_read, decoder)
}

fn copy_input(input: &untrusted::Input) -> Vec<u8> {
    let slice = input.as_slice_less_safe();
    Vec::from(slice)
}

fn parse_signed_data<'a>(der: &mut untrusted::Reader<'a>) -> Result<untrusted::Input<'a>, Error> {
    let mark1 = der.mark();
    let tbs = expect_tag_and_get_value(der, Tag::Sequence, Error::BadDERCertificate)?;
    let mark2 = der.mark();
    let _data = der.get_input_between_marks(mark1, mark2).unwrap();
    let _algorithm = expect_tag_and_get_value(der, Tag::Sequence, Error::BadDERAlgorithm)?;
    let _signature = bit_string_with_no_unused_bits(der, Error::BadDERSignature2)?;
    Ok(tbs)
}

fn bit_string_with_no_unused_bits<'a>(
    input: &mut untrusted::Reader<'a>,
    error: Error,
) -> Result<untrusted::Input<'a>, Error> {
    nested(input, Tag::BitString, error, error, |value| {
        let unused_bits_at_end = value.read_byte().map_err(|_| error)?;
        if unused_bits_at_end != 0 {
            return Err(error);
        }
        Ok(value.skip_to_end())
    })
}

fn parse_validity(input: &mut untrusted::Reader) -> Result<Year, Error> {
    parse_time(input)?;
    parse_time(input)
}

fn parse_time(input: &mut untrusted::Reader) -> Result<Year, Error> {
    let (tag, value) = read_tag_and_get_value(input, Error::BadDERTime)?;

    fn read_digit(inner: &mut untrusted::Reader) -> Result<u64, Error> {
        let b = inner.read_byte().map_err(|_| Error::BadDERTimeValue)?;
        if b >= 0x30 && b <= 0x39 {
            Ok((b - 0x30) as u64)
        } else {
            Err(Error::BadDERTimeValue)
        }
    }

    fn read_two_digits(inner: &mut untrusted::Reader) -> Result<u64, Error> {
        let high = read_digit(inner)?;
        let low = read_digit(inner)?;
        let value = high * 10 + low;
        Ok(value)
    }

    let mut input = untrusted::Reader::new(value);
    let year = if (tag as usize) == (Tag::UTCTime as usize) {
        let yy = read_two_digits(&mut input)?;
        if yy >= 50 {
            1900 + yy
        } else {
            2000 + yy
        }
    } else if (tag as usize) == (Tag::GeneralizedTime as usize) {
        let high = read_two_digits(&mut input)?;
        let low = read_two_digits(&mut input)?;
        high * 100 + low
    } else {
        return Err(Error::BadDERTime);
    };
    // Ignore the rest of the time
    Ok(Year(year))
}
#[derive(Clone)]
pub struct Year(u64);
