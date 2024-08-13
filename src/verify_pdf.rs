use lopdf::{Dictionary, Document, Object};
use thiserror::Error;

use crate::validate_signature::{CaBundle, SignerInfo};

#[derive(Error, Debug)]
pub enum Error {
    #[error("PDF parsing error")]
    ParsingError(#[from] lopdf::Error),
    #[error("signature verification error")]
    SignatureVerificationError(#[from] crate::validate_signature::Error),
    #[error("file is not signed from the beginning")]
    WrongRangeStart,
    #[error("invalid signature range")]
    InvalidRange,
}

type Result<T> = std::result::Result<T, Error>;

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
                    return Err(Error::ParsingError(lopdf::Error::Type));
                }
                Ok(obj)
            }
            _ => Ok(obj),
        }
    }
}

struct ExactArrayOrNone<T, const N: usize>(Option<[T; N]>);

impl<T, const N: usize> FromIterator<T> for ExactArrayOrNone<T, N> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut iter = iter.into_iter();
        let result = array_init::from_iter(&mut iter);
        let result = if iter.next().is_none() { result } else { None };
        ExactArrayOrNone(result)
    }
}

pub fn verify_and_get_signers(pdf_bytes: &[u8], ca_bundle: &CaBundle) -> Result<Vec<SignerInfo>> {
    let doc = Document::load_mem(pdf_bytes)?;

    let mut result = Vec::new();

    // Access the AcroForm dictionary
    let acro_form = doc.get_dict_in_dict(doc.catalog()?, b"AcroForm")?;

    // Early skip if the form does not have any signatures
    let sig_flags = doc.get_in_dict(acro_form, b"SigFlags")?.as_i64()?;
    if sig_flags & 1 == 0 {
        return Ok(result);
    }

    // Get the form fields array
    for field in doc
        .get_in_dict(acro_form, b"Fields")?
        .as_array()?
        .iter()
        .map(|f| doc.deref(f))
    {
        let field = field?.as_dict()?;

        // Check if the field is a signature
        if !is_signature(field) {
            continue;
        }
        let _rect = doc
            .get_in_dict(field, b"Rect")?
            .as_array()?
            .iter()
            .map(|r| doc.deref(r).and_then(|r| Ok(r.as_float()?)))
            .collect::<Result<ExactArrayOrNone<f32, 4>>>()?
            .0
            .ok_or(lopdf::Error::Type)?;

        // TODO: check if the signature box is inside the allowed area

        let signature = doc.get_dict_in_dict(field, b"V")?;

        let signed_range = doc
            .get_in_dict(signature, b"ByteRange")?
            .as_array()?
            .iter()
            .map(|r| doc.deref(r).and_then(|r| Ok(r.as_i64()?)))
            .collect::<Result<ExactArrayOrNone<i64, 4>>>()?
            .0
            .ok_or(lopdf::Error::Type)?;

        // For soundness, we must ensure the only range that is not signed is the signature contents itself.
        if signed_range[0] != 0 {
            return Err(Error::WrongRangeStart);
        }
        if signed_range[1] > signed_range[2] {
            return Err(Error::InvalidRange);
        }
        let skipped_range = signed_range[2] - signed_range[1];
        let contents = doc.get_in_dict(signature, b"Contents")?.as_str()?;
        // TODO: figure out whether if it is safe to carefully limit what is not veritied.
        /*if skipped_range != contents.len() as i64 {
            return Err(Error::InvalidRange);
        }*/
        // TODO: support multiple signatures. The following test will only work
        // for single signature documents.
        let signed_range_end = signed_range[2] + signed_range[3];
        if signed_range_end != pdf_bytes.len() as i64 {
            return Err(Error::InvalidRange);
        }

        // TODO: ensure the original document is the prefix of the signed
        // document (but this can probably be done in the caller function).

        // TODO: ensure that each signature covers an incrementally larger range
        // of the document, and the last signature covers the whole document.

        // TODO: ensure that each signature covers its own dictionaries (Widget
        // anc V).

        // TODO: for soundness, check that no visual elements were
        // incrementally added to the original document before it was
        // signed. Otherwise the user could have added visual elements to
        // the document changing its meaning, but fooled us into thinking
        // what was signed was the original document. Of course, legally
        // this could be seen as some kind of fraud, and we would have the
        // signed proof the user did it.

        // Unfortunatelly openssl requires a continuous array of bytes to
        // verify the signature, so we must concatenate the ranges.
        let mut signed_data = Vec::with_capacity((signed_range[1] + signed_range[3]) as usize);
        signed_data.extend_from_slice(&pdf_bytes[0..signed_range[1] as usize]);
        signed_data
            .extend_from_slice(&pdf_bytes[signed_range[2] as usize..signed_range_end as usize]);

        eprintln!("Signature field found: {:?}", field);
        let signature = crate::validate_signature::Signature::new(contents)?;

        result.extend(signature.get_signers_info()?);

        // Verify the signature
        signature.verify(&signed_data, ca_bundle)?;
    }

    Ok(result)
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
