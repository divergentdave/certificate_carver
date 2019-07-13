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

const DER_OID_EXTENSION_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1D, 0x13];
const DER_OID_EXTENSION_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];
const DER_OID_EXTENSION_EXTENDED_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x25];
const DER_OID_EKU_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const DER_OID_EKU_ANY_EKU: [u8; 4] = [0x55, 0x1D, 0x25, 0x00];

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
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
    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED,
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
    issuer: NameInfo,
    subject: NameInfo,
    not_after_year: Year,
    basic_constraints_ca: bool,
    has_ku: bool,
    ku_tls_handshake: bool,
    has_eku: bool,
    eku_server_auth: bool,
}

struct CertificateInternal {
    issuer: NameInfo,
    subject: NameInfo,
    not_after_year: Year,
    basic_constraints_ca: bool,
    has_ku: bool,
    ku_tls_handshake: bool,
    has_eku: bool,
    eku_server_auth: bool,
}

impl Certificate {
    pub fn parse(bytes: CertificateBytes) -> Result<Certificate, Error> {
        let cert_internal = Certificate::parse_cert_contents(bytes.as_ref())?;
        let mut arr: [u8; 32] = Default::default();
        arr.copy_from_slice(&Sha256::digest(bytes.as_ref()));
        let fp = CertificateFingerprint(arr);
        Ok(Certificate {
            bytes,
            fp,
            issuer: cert_internal.issuer,
            subject: cert_internal.subject,
            not_after_year: cert_internal.not_after_year,
            basic_constraints_ca: cert_internal.basic_constraints_ca,
            has_ku: cert_internal.has_ku,
            ku_tls_handshake: cert_internal.ku_tls_handshake,
            has_eku: cert_internal.has_eku,
            eku_server_auth: cert_internal.eku_server_auth,
        })
    }

    fn parse_cert_contents(bytes: &[u8]) -> Result<CertificateInternal, Error> {
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
        tbs_der.read_all(Error::BadDERCertificate, |tbs_der| {
            let (first_tag, _first_value) =
                read_tag_and_get_value(tbs_der, Error::BadDERSerialNumber)?;
            let next_tag = if (first_tag as usize) == (Tag::ContextSpecificConstructed0 as usize) {
                // Version is present, skip it and read the serial number
                let (next_tag, _next_value) =
                    read_tag_and_get_value(tbs_der, Error::BadDERSerialNumber)?;
                next_tag
            } else {
                // Version is not present, the first TLV should be for the serial number
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

            let subject = expect_tag_and_get_value(tbs_der, Tag::Sequence, Error::BadDERSubject)?;
            let subject = copy_input(&subject);

            skip(tbs_der, Tag::Sequence, Error::BadDERSPKI)?;

            let extension_flags = if tbs_der.at_end() {
                Default::default()
            } else {
                nested(
                    tbs_der,
                    Tag::ContextSpecificConstructed3,
                    Error::BadDERExtensions,
                    Error::BadDERExtensionsExtraData,
                    |der| {
                        nested(
                            der,
                            Tag::Sequence,
                            Error::BadDERExtensions,
                            Error::BadDERExtensionsExtraData,
                            parse_extensions,
                        )
                    },
                )?
            };

            Ok(CertificateInternal {
                issuer: NameInfo::new(issuer),
                subject: NameInfo::new(subject),
                not_after_year,
                basic_constraints_ca: extension_flags.basic_constraints_ca,
                has_ku: extension_flags.has_ku,
                ku_tls_handshake: extension_flags.ku_tls_handshake,
                has_eku: extension_flags.has_eku,
                eku_server_auth: extension_flags.eku_server_auth,
            })
        })
    }

    pub fn fingerprint(&self) -> CertificateFingerprint {
        self.fp
    }

    pub fn format_issuer_subject(&self, f: &mut dyn Write) -> std::io::Result<()> {
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

    pub fn looks_like_ca(&self) -> bool {
        self.basic_constraints_ca
    }

    pub fn looks_like_server(&self) -> bool {
        (!self.has_ku || self.ku_tls_handshake) && (!self.has_eku || self.eku_server_auth)
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
pub enum NameTypeValue {
    CaseInsensitive(NameType, String, String, Vec<u8>),
    Unknown(NameType, Option<String>, Vec<u8>),
}

impl NameTypeValue {
    fn parse(name_type_bytes: &[u8], value_bytes: &[u8], der_bytes: Vec<u8>) -> NameTypeValue {
        let name_type = NameType::from(name_type_bytes);
        match name_type {
            NameType::UnrecognizedType => {
                NameTypeValue::Unknown(name_type, parse_directory_string(&value_bytes), der_bytes)
            }
            name_type => match name_type.matching_rule() {
                MatchingRule::Unknown => NameTypeValue::Unknown(
                    name_type,
                    parse_directory_string(&value_bytes),
                    der_bytes,
                ),
                MatchingRule::CaseIgnoreMatch => match parse_directory_string(&value_bytes) {
                    None => NameTypeValue::Unknown(name_type, None, der_bytes),
                    Some(value) => match ldapprep_case_insensitive(&value) {
                        Err(_) => NameTypeValue::Unknown(name_type, Some(value), der_bytes),
                        Ok(prepped) => NameTypeValue::CaseInsensitive(
                            name_type,
                            value.clone(),
                            prepped.to_string(),
                            der_bytes,
                        ),
                    },
                },
            },
        }
    }

    pub fn get_name_type(&self) -> &NameType {
        match self {
            NameTypeValue::CaseInsensitive(name_type, _, _, _) => name_type,
            NameTypeValue::Unknown(name_type, _, _) => name_type,
        }
    }
}

impl PartialEq for NameTypeValue {
    fn eq(&self, other: &NameTypeValue) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Ord for NameTypeValue {
    fn cmp(&self, other: &NameTypeValue) -> Ordering {
        match self.get_name_type().cmp(&other.get_name_type()) {
            Ordering::Equal => match (self, other) {
                (
                    NameTypeValue::CaseInsensitive(_, _, self_prepped, _),
                    NameTypeValue::CaseInsensitive(_, _, other_prepped, _),
                ) => self_prepped.cmp(&other_prepped),
                (
                    NameTypeValue::Unknown(_, _, self_bytes),
                    NameTypeValue::Unknown(_, _, other_bytes),
                ) => self_bytes.cmp(&other_bytes),
                (
                    NameTypeValue::CaseInsensitive(_, _, _, self_bytes),
                    NameTypeValue::Unknown(_, _, other_bytes),
                ) => self_bytes.cmp(&other_bytes),
                (
                    NameTypeValue::Unknown(_, _, self_bytes),
                    NameTypeValue::CaseInsensitive(_, _, _, other_bytes),
                ) => self_bytes.cmp(&other_bytes),
            },
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
        match self {
            NameTypeValue::CaseInsensitive(name_type, _, prepped, _) => {
                1.hash(state);
                name_type.hash(state);
                prepped.hash(state);
            }
            NameTypeValue::Unknown(_, _, der) => {
                2.hash(state);
                der.hash(state);
            }
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
                                    attribs.push(NameTypeValue::parse(
                                        attrib_type.as_ref(),
                                        &value_data,
                                        type_and_value_data,
                                    ));
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

    pub fn format(&self, f: &mut dyn Write) -> std::io::Result<()> {
        let mut space = false;
        match self.rdns {
            Ok(ref rdns) => {
                for (name_type, type_description) in NAME_ATTRIBUTES_DESCRIPTIONS.iter() {
                    for rdn in rdns.iter() {
                        for type_value in rdn.attribs.iter() {
                            let (cur_name_type, cur_value) = match type_value {
                                NameTypeValue::CaseInsensitive(name_type, value, _, _) => {
                                    (name_type, Some(value))
                                }
                                NameTypeValue::Unknown(name_type, value, _) => {
                                    (name_type, value.as_ref())
                                }
                            };
                            if cur_name_type == name_type {
                                if space {
                                    write!(f, " {}=", type_description)?;
                                } else {
                                    write!(f, "{}=", type_description)?;
                                }
                                match cur_value {
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
    BadDERExtensionsExtraData,
    BadDERExtension,
    BadDERExtensionExtraData,
    BadDERExtensionID,
    BadDERBasicConstraints,
    BadDERBasicConstraintsExtraData,
    BadDERKeyUsage,
    BadDERKeyUsageExtraData,
    BadDERExtendedKeyUsage,
    BadDERExtendedKeyUsageExtraData,
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
            Error::BadDERExtensionsExtraData => write!(f, "DER error encountered while parsing extensions due to extra data"),
            Error::BadDERExtension => write!(f, "DER error encountered while parsing an extension"),
            Error::BadDERExtensionExtraData => write!(f, "DER error encountered while parsing an extension due to extra data"),
            Error::BadDERExtensionID => write!(f, "DER error encountered while parsing an extension ID"),
            Error::BadDERBasicConstraints => write!(f, "DER error encountered while parsing a basicConstraints extension"),
            Error::BadDERBasicConstraintsExtraData => write!(f, "DER error encountered while parsing a basicConstraints extension due to extra data"),
            Error::BadDERKeyUsage => write!(f, "DER error encountered while parsing an keyUsage extension"),
            Error::BadDERKeyUsageExtraData => write!(f, "DER error encountered while parsing an keyUsage extension due to extra data"),
            Error::BadDERExtendedKeyUsage => write!(f, "DER error encountered while parsing an extKeyUsage extension"),
            Error::BadDERExtendedKeyUsageExtraData => write!(f, "DER error encountered while parsing an extKeyUsage extension due to extra data"),
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

struct ExtensionFlags {
    basic_constraints_ca: bool,
    has_ku: bool,
    ku_tls_handshake: bool,
    has_eku: bool,
    eku_server_auth: bool,
}

impl Default for ExtensionFlags {
    fn default() -> ExtensionFlags {
        ExtensionFlags {
            basic_constraints_ca: true,
            has_ku: true,
            ku_tls_handshake: true,
            has_eku: true,
            eku_server_auth: true,
        }
    }
}

fn parse_extensions(der: &mut untrusted::Reader) -> Result<ExtensionFlags, Error> {
    let mut basic_constraints_ca = false;
    let mut has_ku = false;
    let mut ku_tls_handshake = false;
    let mut has_eku = false;
    let mut eku_server_auth = false;
    while !der.at_end() {
        nested(
            der,
            Tag::Sequence,
            Error::BadDERExtension,
            Error::BadDERExtensionExtraData,
            |der| {
                let id = expect_tag_and_get_value(der, Tag::OID, Error::BadDERExtensionID)?;
                let (next_tag, next_value) = read_tag_and_get_value(der, Error::BadDERExtension)?;
                let value = if next_tag == Tag::Boolean as u8 {
                    expect_tag_and_get_value(der, Tag::OctetString, Error::BadDERExtension)?
                } else if next_tag == Tag::OctetString as u8 {
                    next_value
                } else {
                    return Err(Error::BadDERExtension);
                };

                let id = copy_input(&id);
                let mut value = untrusted::Reader::new(value);
                if id == DER_OID_EXTENSION_BASIC_CONSTRAINTS {
                    let result = nested(
                        &mut value,
                        Tag::Sequence,
                        Error::BadDERBasicConstraints,
                        Error::BadDERBasicConstraintsExtraData,
                        |der| {
                            if der.at_end() {
                                Ok(false)
                            } else {
                                let (tag, value) =
                                    read_tag_and_get_value(der, Error::BadDERBasicConstraints)?;
                                let value = copy_input(&value);
                                if tag == Tag::Boolean as u8 {
                                    let result = value.into_iter().any(|b| b != 0);
                                    if !der.at_end() {
                                        expect_tag_and_get_value(
                                            der,
                                            Tag::Integer,
                                            Error::BadDERBasicConstraints,
                                        )?;
                                    }
                                    Ok(result)
                                } else if tag == Tag::Integer as u8 {
                                    Ok(false)
                                } else {
                                    Err(Error::BadDERBasicConstraints)
                                }
                            }
                        },
                    );
                    if let Ok(ca) = result {
                        basic_constraints_ca = ca;
                    }
                } else if id == DER_OID_EXTENSION_KEY_USAGE {
                    let result = nested(
                        &mut value,
                        Tag::BitString,
                        Error::BadDERKeyUsage,
                        Error::BadDERKeyUsageExtraData,
                        |der| {
                            let _unused_bits_at_end =
                                der.read_byte().map_err(|_| Error::BadDERKeyUsage)?;
                            let byte = der.read_byte().unwrap_or(0);
                            Ok(byte)
                        },
                    );
                    if let Ok(byte) = result {
                        has_ku = true;
                        // Check if the digitalSignature(0), keyEncipherment(2),
                        // or keyAgreement(4) bits are set
                        ku_tls_handshake = byte & 0xA8 != 0;
                    }
                } else if id == DER_OID_EXTENSION_EXTENDED_KEY_USAGE {
                    let result = nested(
                        &mut value,
                        Tag::Sequence,
                        Error::BadDERExtendedKeyUsage,
                        Error::BadDERExtendedKeyUsageExtraData,
                        |der| {
                            let mut server_auth = false;
                            while !der.at_end() {
                                let oid = expect_tag_and_get_value(
                                    der,
                                    Tag::OID,
                                    Error::BadDERExtendedKeyUsage,
                                )?;
                                let oid = copy_input(&oid);
                                if oid == DER_OID_EKU_SERVER_AUTH || oid == DER_OID_EKU_ANY_EKU {
                                    server_auth = true;
                                }
                            }
                            Ok(server_auth)
                        },
                    );
                    if let Ok(server_auth) = result {
                        has_eku = true;
                        eku_server_auth = server_auth;
                    }
                }
                Ok(())
            },
        )?;
    }
    Ok(ExtensionFlags {
        basic_constraints_ca,
        has_ku,
        ku_tls_handshake,
        has_eku,
        eku_server_auth,
    })
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
            Ok(u64::from(b - 0x30))
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
