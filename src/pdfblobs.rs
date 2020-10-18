use log::{trace, warn};
use pdf::{
    self,
    error::PdfError,
    file::Storage,
    object::{Object, Ref, Resolve, Stream},
    primitive::{Dictionary, Primitive},
};
use pdf_derive::Object;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

#[derive(Debug, Object)]
struct Trailer {
    #[pdf(key = "Root")]
    root: Catalog,
}

#[derive(Debug, Object)]
struct Catalog {
    #[pdf(key = "AcroForm")]
    forms: Option<AcroForm>,

    #[pdf(key = "Pages")]
    pages: PagesNode,
}

#[derive(Debug, Object)]
struct AcroForm {
    #[pdf(key = "Fields")]
    fields: Vec<Ref<Annot>>,

    #[pdf(key = "SigFlags")]
    sig_flags: Option<i32>,
}

#[derive(Debug, Object)]
struct Annot {
    #[pdf(key = "FT")]
    field_type: Option<String>,

    #[pdf(key = "V")]
    value: Option<Primitive>,

    #[pdf(key = "Kids")]
    kids: Vec<Ref<Annot>>,
}

#[derive(Debug)]
enum PagesNode {
    Tree(Rc<PageTree>),
    Leaf(Rc<Page>),
}

impl Object for PagesNode {
    fn serialize<W: io::Write>(&self, out: &mut W) -> Result<(), PdfError> {
        match *self {
            PagesNode::Tree(ref t) => t.serialize(out),
            PagesNode::Leaf(ref l) => l.serialize(out),
        }
    }

    fn from_primitive(p: Primitive, r: &impl Resolve) -> Result<PagesNode, PdfError> {
        let dict = Dictionary::from_primitive(p, r)?;
        match dict["Type"].as_name()? {
            "Page" => Ok(PagesNode::Leaf(Object::from_primitive(
                Primitive::Dictionary(dict),
                r,
            )?)),
            "Pages" => Ok(PagesNode::Tree(Object::from_primitive(
                Primitive::Dictionary(dict),
                r,
            )?)),
            other => Err(PdfError::WrongDictionaryType {
                expected: "Page or Pages".into(),
                found: other.into(),
            }),
        }
    }
}

#[derive(Debug, Object)]
struct PageTree {
    #[pdf(key = "Kids")]
    kids: Vec<Ref<PagesNode>>,

    #[pdf(key = "Resources")]
    resources: Option<Rc<Resources>>,
}

#[derive(Debug, Object)]
struct Page {
    #[pdf(key = "Resources")]
    resources: Option<Rc<Resources>>,
}

#[derive(Debug, Object)]
struct Resources {
    #[pdf(key = "Font")]
    fonts: HashMap<String, Rc<Font>>,
}

#[derive(Debug, Object)]
struct Font {
    #[pdf(key = "FontDescriptor")]
    font_descriptor: Option<FontDescriptor>,
}

#[derive(Debug, Object)]
struct FontDescriptor {
    #[pdf(key = "FontFile2")]
    font_file_2: Option<Stream>,

    #[pdf(key = "FontFile3")]
    font_file_3: Option<Stream>,
}

trait FormFieldVisitor {
    fn visit_field(&mut self, field: &Annot);
    fn visit_field_end(&mut self);

    fn walk_fields<R: Resolve>(
        &mut self,
        fields: &[Ref<Annot>],
        resolve: &R,
    ) -> Result<(), PdfError> {
        for field in fields {
            let field = resolve.get(*field)?;
            self.visit_field(&*field);
            if !field.kids.is_empty() {
                self.walk_fields(&*field.kids, resolve)?;
            }
            self.visit_field_end();
        }
        Ok(())
    }
}

struct SignatureFormFieldVisitor<'a, R: Resolve> {
    blobs: Vec<Vec<u8>>,
    resolve: &'a R,
}

impl<'a, R: Resolve> SignatureFormFieldVisitor<'a, R> {
    fn new(resolve: &'a R) -> SignatureFormFieldVisitor<'a, R> {
        SignatureFormFieldVisitor {
            blobs: Vec::new(),
            resolve,
        }
    }

    fn into_blobs(self) -> Vec<Vec<u8>> {
        self.blobs
    }
}

impl<'a, R: Resolve> FormFieldVisitor for SignatureFormFieldVisitor<'a, R> {
    fn visit_field(&mut self, field: &Annot) {
        if let Some(field_type) = &field.field_type {
            if field_type == "Sig" {
                trace!("PDF signature field is present");
                if let Some(value) = &field.value {
                    if let Ok(dict) = value.clone().into_dictionary(self.resolve) {
                        for key in &["Contents", "Cert"] {
                            if let Some(obj) = dict.get(key) {
                                if let Ok(string) = obj.as_string() {
                                    self.blobs.push(string.as_bytes().to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn visit_field_end(&mut self) {}
}

fn find_signature_blobs<R: Resolve>(
    trailer: &Trailer,
    resolve: &R,
) -> Result<Vec<Vec<u8>>, PdfError> {
    if let Some(forms) = &trailer.root.forms {
        let signatures_exist = match forms.sig_flags {
            Some(flags) if flags & 1 == 1 => {
                trace!("PDF XForms are present, and the SignaturesExist flag is set");
                true
            }
            _ => {
                trace!("PDF XForms are present (no signatures)");
                false
            }
        };

        let mut visitor = SignatureFormFieldVisitor::new(resolve);
        visitor.walk_fields(&forms.fields, resolve)?;
        let results = visitor.into_blobs();

        if signatures_exist && results.is_empty() {
            warn!("PDF SignaturesExist flag was set, but no signature blobs were extracted");
        }
        Ok(results)
    } else {
        Ok(vec![])
    }
}

trait PageVisitor {
    fn visit_page(&mut self, page: &Page);
    fn visit_tree(&mut self, tree: &PageTree);

    fn walk_pages<R: Resolve>(&mut self, node: &PagesNode, resolve: &R) -> Result<(), PdfError> {
        match node {
            PagesNode::Tree(tree) => {
                self.visit_tree(tree);
                for node in tree.kids.iter() {
                    self.walk_pages(&*resolve.get(*node)?, resolve)?;
                }
            }
            PagesNode::Leaf(page) => self.visit_page(page),
        }
        Ok(())
    }
}

struct FontPageVisitor {
    font_map: HashMap<usize, Rc<Font>>,
}

impl FontPageVisitor {
    fn new() -> FontPageVisitor {
        FontPageVisitor {
            font_map: HashMap::new(),
        }
    }

    fn visit_resources(&mut self, resources: &Rc<Resources>) {
        for font in resources.fonts.values() {
            let key = Rc::as_ptr(font) as usize;
            self.font_map.entry(key).or_insert_with(|| font.clone());
        }
    }

    fn into_fonts(self) -> impl Iterator<Item = Rc<Font>> {
        self.font_map.into_iter().map(|(_, font)| font)
    }
}

impl PageVisitor for FontPageVisitor {
    fn visit_page(&mut self, page: &Page) {
        if let Some(resources) = &page.resources {
            self.visit_resources(resources);
        }
    }

    fn visit_tree(&mut self, tree: &PageTree) {
        if let Some(resources) = &tree.resources {
            self.visit_resources(resources);
        }
    }
}

fn find_font_blobs<R: Resolve>(trailer: &Trailer, resolve: &R) -> Result<Vec<Vec<u8>>, PdfError> {
    let mut visitor = FontPageVisitor::new();
    visitor.walk_pages(&trailer.root.pages, resolve)?;
    let mut results = Vec::new();
    for font in visitor.into_fonts() {
        if let Some(descr) = &font.font_descriptor {
            // TrueType/OpenType fonts may have digital signatures
            if let Some(stream) = &descr.font_file_2 {
                results.push(stream.data()?.to_vec());
            }
            if let Some(stream) = &descr.font_file_3 {
                results.push(stream.data()?.to_vec());
            }
        }
    }
    Ok(results)
}

fn load_pdf_data(data: Vec<u8>) -> Result<(Storage<Vec<u8>>, Trailer), PdfError> {
    let (storage, trailer) = pdf::file::load_storage_and_trailer(data)?;
    let trailer = Trailer::from_primitive(Primitive::Dictionary(trailer), &storage)?;
    Ok((storage, trailer))
}

pub fn find_blobs(data: Vec<u8>) -> Result<Vec<Vec<u8>>, PdfError> {
    let (storage, trailer) = load_pdf_data(data)?;
    let mut results = find_signature_blobs(&trailer, &storage)?;
    results.append(&mut find_font_blobs(&trailer, &storage)?);
    Ok(results)
}
