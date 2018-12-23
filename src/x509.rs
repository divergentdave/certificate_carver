use ring;
use untrusted;

use std::io::Write;
use ring::digest::{digest, SHA256};

use encoding::{Encoding, DecoderTrap};
use encoding::all::ISO_8859_1;

use CertificateFingerprint;

const CONSTRUCTED: u8 = 1 << 5;
const CONTEXT_SPECIFIC: u8 = 2 << 6;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    OID = 0x06,
    Utf8String = 0x0C,
    PrintableString = 0x13,
    TeletexString = 0x14,
    Sequence = CONSTRUCTED | 0x10, // 0x30
    Set = CONSTRUCTED | 0x11, // 0x31
    UTCTime = 0x17,
    GeneralizedTime = 0x18,

    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED | 0,
    ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
}

const OID_COUNTRY_NAME: [u8; 3] = [0x55, 0x04, 0x06];
const OID_ORGANIZATION_NAME: [u8; 3] = [0x55, 0x04, 0x0A];
const OID_ORGANIZATIONAL_UNIT_NAME: [u8; 3] = [0x55, 0x04, 0x0B];
const OID_DISTINGUISHED_NAME_QUALIFIER: [u8; 3] = [0x55, 0x04, 0x2E];
const OID_STATE_OR_PROVINCE_NAME: [u8; 3] = [0x55, 0x04, 0x08];
const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
const OID_SERIAL_NUMBER: [u8; 3] = [0x55, 0x04, 0x05];
const OID_LOCALITY_NAME: [u8; 3] = [0x55, 0x04, 0x07];
const OID_TITLE: [u8; 3] = [0x55, 0x04, 0x0C];
const OID_SURNAME: [u8; 3] = [0x55, 0x04, 0x04];
const OID_GIVEN_NAME: [u8; 3] = [0x55, 0x04, 0x2A];
const OID_INITIALS: [u8; 3] = [0x55, 0x04, 0x2B];
const OID_PSEUDONYM: [u8; 3] = [0x55, 0x04, 0x41];
const OID_GENERATION_QUALIFIER: [u8; 3] = [0x55, 0x04, 0x2C];

const NAME_ATTRIBUTES_DESCRIPTIONS: [(&[u8], &str); 14] = [
    (&OID_COUNTRY_NAME, "C"),
    (&OID_ORGANIZATION_NAME, "O"),
    (&OID_ORGANIZATIONAL_UNIT_NAME, "OU"),
    (&OID_DISTINGUISHED_NAME_QUALIFIER, "Distinguished Name Qualifier"),
    (&OID_STATE_OR_PROVINCE_NAME, "ST"),
    (&OID_COMMON_NAME, "CN"),
    (&OID_SERIAL_NUMBER, "SN"),
    (&OID_LOCALITY_NAME, "L"),
    (&OID_TITLE, "T"),
    (&OID_SURNAME, "S"),
    (&OID_GIVEN_NAME, "G"),
    (&OID_INITIALS, "I"),
    (&OID_PSEUDONYM, "Pseudonym"),
    (&OID_GENERATION_QUALIFIER, "Generation Qualifier")
];

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

    pub fn parse_cert_names(&self) -> Result<(NameBytes, NameBytes), Error> {
        let cert_der = untrusted::Input::from(self.as_ref());
        let tbs_der = cert_der.read_all(Error::BadDERCertificateExtraData, |cert_der| {
            nested(cert_der, Tag::Sequence, Error::BadDERCertificate, Error::BadDERCertificateExtraData, parse_signed_data)
        })?;
        let (issuer, subject) = tbs_der.read_all(Error::BadDERCertificate, |tbs_der| {
            let (first_tag, _first_value) = read_tag_and_get_value(tbs_der, Error::BadDERSerialNumber)?;
            let next_tag = if (first_tag as usize) == (Tag::ContextSpecificConstructed0 as usize) {
                // skip version number, if present
                let (next_tag, _next_value) = read_tag_and_get_value(tbs_der, Error::BadDERSerialNumber)?;
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

            skip(tbs_der, Tag::Sequence, Error::BadDERValidity)?;

            let subject = expect_tag_and_get_value(tbs_der, Tag::Sequence, Error::BadDERSubject)?;
            let subject = copy_input(&subject);

            skip(tbs_der, Tag::Sequence, Error::BadDERSPKI)?;

            if !tbs_der.at_end() {
                skip(tbs_der, Tag::ContextSpecificConstructed3, Error::BadDERExtensions)?;
            }

            Ok((issuer, subject))
        })?;
        Ok((NameBytes(issuer), NameBytes(subject)))
    }

    pub fn format_issuer_subject(&self, issuer: NameBytes, subject: NameBytes, f: &mut Write) -> std::io::Result<()> {
        write!(f, "issuer=")?;
        issuer.format(f)?;
        write!(f, ", subject=")?;
        subject.format(f)
    }
}

impl AsRef<[u8]> for CertificateBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct NameTypeValue {
    pub type_oid: Vec<u8>,
    pub value: Vec<u8>
}

#[derive(PartialEq, Eq)]
pub struct NameBytes (
    pub Vec<u8>
);

fn format_directory_string(f: &mut Write, value: &Vec<u8>) -> std::io::Result<()> {
    let input = untrusted::Input::from(value.as_ref());
    let (tag, inner) = input.read_all(Error::BadDERString, |value_der| {
        read_tag_and_get_value(value_der, Error::BadDERString)
    }).unwrap();
    let tag_usize: usize = tag as usize;
    if tag_usize == (Tag::Utf8String as usize) {
        f.write(inner.as_slice_less_safe())
    } else if tag_usize == (Tag::PrintableString as usize) {
        f.write(inner.as_slice_less_safe())
    } else if tag_usize == (Tag::TeletexString as usize) {
        let mut decoded = String::new();
        ISO_8859_1.decode_to(inner.as_slice_less_safe(), DecoderTrap::Replace, &mut decoded).unwrap();
        f.write(decoded.as_ref())
    } else {
        f.write(b"(unsupported string type)")
    }.map(|_| ())
}

impl NameBytes {
    pub fn parse_rdns(&self) -> Result<Vec<NameTypeValue>, Error> {
        let mut results: Vec<NameTypeValue> = Vec::new();
        let name_der = untrusted::Input::from(self.as_ref());
        name_der.read_all(Error::BadDERDistinguishedNameExtraData, |name_der| {
            loop {
                nested(name_der, Tag::Set, Error::BadDERRelativeDistinguishedName, Error::BadDERRelativeDistinguishedNameExtraData, |rdn_der| {
                    loop {
                        nested(rdn_der, Tag::Sequence, Error::BadDERRDNAttribute, Error::BadDERRDNAttributeExtraData, |attrib_der| {
                            let attrib_type = expect_tag_and_get_value(attrib_der, Tag::OID, Error::BadDERRDNType)?;
                            let attrib_type = copy_input(&attrib_type);
                            let mark1 = attrib_der.mark();
                            let (_value_tag, _value) = read_tag_and_get_value(attrib_der, Error::BadDERRDNValue)?;
                            let mark2 = attrib_der.mark();
                            let value_data = attrib_der.get_input_between_marks(mark1, mark2).unwrap();
                            let value_data = copy_input(&value_data);
                            results.push(NameTypeValue {
                                type_oid: attrib_type,
                                value: value_data
                            });
                            Ok(())
                        })?;
                        if rdn_der.at_end() {
                            break;
                        }
                    }
                    Ok(())
                })?;
                if name_der.at_end() {
                    break;
                }
            }
            Ok(())
        })?;
        Ok(results)
    }

    pub fn format(&self, f: &mut Write) -> std::io::Result<()> {
        let mut space = false;
        let rdns = match self.parse_rdns() {
            Ok(rdns) => rdns,
            Err(_) => {
                return write!(f, "DER error parsing name");
            }
        };
        for (oid_bytes, type_description) in NAME_ATTRIBUTES_DESCRIPTIONS.iter() {
            for type_value in rdns.iter() {
                if type_value.type_oid == *oid_bytes {
                    if space {
                        write!(f, " {}=", type_description)?;
                    } else {
                        write!(f, "{}=", type_description)?;
                    }
                    format_directory_string(f, &type_value.value)?;
                    space = true;
                }
            }
        }
        Ok(())
    }
}

impl AsRef<[u8]> for NameBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

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
    BadDERSubject,
    BadDERSPKI,
    BadDERExtensions,
    BadDERSignatureAlgorithm,
    BadDERSignature,
    BadDERDistinguishedNameExtraData,
    BadDERRelativeDistinguishedName,
    BadDERRelativeDistinguishedNameExtraData,
    BadDERRDNAttribute,
    BadDERRDNAttributeExtraData,
    BadDERRDNType,
    BadDERString,
    BadDERRDNValue,
    BadDERAlgorithm,
    BadDERSignature2
}

#[inline(always)]
fn expect_tag_and_get_value<'a>(input: &mut untrusted::Reader<'a>, tag: Tag, error: Error) -> Result<untrusted::Input<'a>, Error> {
    let (actual_tag, inner) = read_tag_and_get_value(input, error)?;
    if (tag as usize) != (actual_tag as usize) {
        return Err(error);
    }
    Ok(inner)
}

#[inline(always)]
fn read_tag_and_get_value<'a>(input: &mut untrusted::Reader<'a>, error: Error) -> Result<(u8, untrusted::Input<'a>), Error> {
    ring::der::read_tag_and_get_value(input).map_err(|_| error)
}

fn skip(input: &mut untrusted::Reader, tag: Tag, error: Error) -> Result<(), Error> {
    expect_tag_and_get_value(input, tag, error).map(|_| ())
}

fn nested<'a, F, R>(input: &mut untrusted::Reader<'a>, tag: Tag, error_wrong_tag: Error, error_incomplete_read: Error, decoder: F) -> Result<R, Error> where F : FnOnce(&mut untrusted::Reader<'a>) -> Result<R, Error> {
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
    let data = der.get_input_between_marks(mark1, mark2).unwrap();
    let algorithm = expect_tag_and_get_value(der, Tag::Sequence, Error::BadDERAlgorithm)?;
    let signature = bit_string_with_no_unused_bits(der, Error::BadDERSignature2)?;
    Ok(tbs)
}

fn bit_string_with_no_unused_bits<'a>(input: &mut untrusted::Reader<'a>, error: Error) -> Result<untrusted::Input<'a>, Error> {
    nested(input, Tag::BitString, error, error, |value| {
        let unused_bits_at_end = value.read_byte().map_err(|_| error)?;
        if unused_bits_at_end != 0 {
            return Err(error);
        }
        Ok(value.skip_to_end())
    })
}
