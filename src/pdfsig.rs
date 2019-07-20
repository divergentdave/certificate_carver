use error_chain::bail;
use pdf;
use pdf::backend::Backend;
use pdf::object::{Object, Resolve};
use pdf::primitive::{Dictionary, PdfString, Primitive};
use pdf::Result;
use pdf_derive::Object;

#[derive(Object)]
struct Trailer {
    #[pdf(key = "Root")]
    pub root: Catalog,
}

#[derive(Object)]
struct Catalog {
    #[pdf(key = "AcroForm")]
    pub forms: Option<AcroForm>,
}

#[derive(Object)]
struct AcroForm {
    #[pdf(key = "Fields")]
    pub fields: Vec<Annot>,
}

#[derive(Object)]
struct Annot {
    #[pdf(key = "FT")]
    pub field_type: String,

    #[pdf(key = "V")]
    pub value: Option<Value>,
}

#[derive(Object)]
struct Value {
    #[pdf(key = "Contents")]
    pub contents: Option<PdfString>,

    #[pdf(key = "Cert")]
    pub cert: Option<PdfString>,
}

pub fn find_signature_certificates(data: &Vec<u8>) -> Option<Vec<Vec<u8>>> {
    let mut results = Vec::new();
    let (refs, trailer) = data.read_xref_table_and_trailer().ok()?;
    let trailer =
        Trailer::from_primitive(Primitive::Dictionary(trailer), &|r| data.resolve(&refs, r))
            .ok()?;
    for field in trailer.root.forms?.fields.into_iter() {
        if field.field_type == "Sig" {
            if let Some(value) = field.value {
                if let Some(contents) = value.contents {
                    results.push(contents.into_bytes());
                }
                if let Some(cert) = value.cert {
                    results.push(cert.into_bytes());
                }
            }
        }
    }
    Some(results)
}
