use std::collections::HashSet;

use lopdf::{Dictionary, Document, Error, Object, Result};

trait GetInDict {
    fn get_in_dict<'a>(&'a self, dict: &'a Dictionary, key: &[u8]) -> Result<&'a Object>;
    fn deref<'a>(&'a self, obj: &'a Object) -> Result<&'a Object>;
}

impl GetInDict for Document {
    fn get_in_dict<'a>(&'a self, dict: &'a Dictionary, key: &[u8]) -> Result<&'a Object> {
        let obj = dict.get(key)?;

        self.deref(obj)
    }

    fn deref<'a>(&'a self, obj: &'a Object) -> Result<&'a Object> {
        match obj {
            Object::Reference(id) => {
                let obj = self.get_object(*id)?;
                if let Object::Reference(_) = obj {
                    // ChatGPT says a reference to another reference is invalid
                    return Err(Error::Type);
                }
                Ok(obj)
            },
            _ => Ok(obj),
        }
    }
}

pub fn extract_valid_signatures(pdf_bytes: &[u8]) -> Result<()>
{
    let doc = Document::load_mem(pdf_bytes)?;

    // Access the AcroForm dictionary
    if let Object::Dictionary(acro_form) = doc.catalog()?.get(b"AcroForm")? {
        // Early skip if the form does not have any signatures
        if let Object::Integer(sig_flags) = doc.get_in_dict(acro_form, b"SigFlags")? {
            if sig_flags & 1 == 0 {
                return Err(lopdf::Error::Invalid("No signatures found".to_string()));
            }
        }

        // Get the form fields array
        for field in doc.get_in_dict(acro_form, b"Fields")?.as_array()?.iter().map(|f| doc.deref(f)) {
            let field = field?.as_dict()?;

            // Check if the field is a signature
            if is_signature(field) {
                println!("Field: {:#?}", field);
                // TODO: verify the signature
            }
        }
    }

    Ok(())
}

fn is_signature(annot_dict: &Dictionary) -> bool {
    // Check if /Subtype is /Widget
    if let Ok(Object::Name(subtype)) = annot_dict.get(b"Subtype") {
        if subtype == b"Widget" {
            // Check for /FT (Field Type) being /Sig
            if let Ok(Object::Name(ft)) = annot_dict.get(b"FT") {
                if ft == b"Sig" {
                    return true;
                }
            }
        }
    }
    false
}
