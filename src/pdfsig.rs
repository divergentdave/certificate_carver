use log::trace;
use pdf::{
    self,
    backend::Backend,
    error::PdfError,
    file::Storage,
    object::Object,
    primitive::{PdfString, Primitive},
};
use pdf_derive::Object;

#[derive(Debug, Object)]
struct Trailer {
    #[pdf(key = "Root")]
    pub root: Catalog,
}

#[derive(Debug, Object)]
struct Catalog {
    #[pdf(key = "AcroForm")]
    pub forms: Option<AcroForm>,
}

#[derive(Debug, Object)]
struct AcroForm {
    #[pdf(key = "Fields")]
    pub fields: Vec<Annot>,
}

#[derive(Debug, Object)]
struct Annot {
    #[pdf(key = "FT")]
    pub field_type: String,

    #[pdf(key = "V")]
    pub value: Option<Value>,
}

#[derive(Debug, Object)]
struct Value {
    #[pdf(key = "Contents")]
    pub contents: Option<PdfString>,

    #[pdf(key = "Cert")]
    pub cert: Option<PdfString>,
}

pub fn find_signature_blobs(data: Vec<u8>) -> Result<Vec<Vec<u8>>, PdfError> {
    let start_offset = data.locate_start_offset()?;
    let (refs, trailer) = data.read_xref_table_and_trailer(start_offset)?;
    let storage = Storage::new(data, refs, start_offset);
    let trailer = Trailer::from_primitive(Primitive::Dictionary(trailer), &storage)?;

    let mut results = Vec::new();
    if let Some(forms) = trailer.root.forms {
        trace!("PDF XForms are present");
        for field in forms.fields.into_iter() {
            if field.field_type == "Sig" {
                trace!("PDF signature field is present");
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
    }
    Ok(results)
}
