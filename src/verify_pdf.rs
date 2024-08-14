use std::ops::Range;

use lopdf::{Dictionary, Document, Object};
use regex::bytes::Regex;
use thiserror::Error;

use crate::validate_signature::{CaBundle, SignerInfo};

#[derive(Error, Debug)]
pub enum Error {
    #[error("PDF parsing error")]
    ParsingError(#[from] lopdf::Error),
    #[error("reference document does not end like a PDF file")]
    InvalidReferenceDocument,
    #[error("end of the reference increment is bigger than the signed document")]
    ReferenceIncrementOutOfBounds,
    #[error("can not guarantee the contents of the signed document match the original")]
    PossibleContentChange,
    #[error("signature verification error")]
    SignatureVerificationError(#[from] crate::validate_signature::Error),
    #[error("file is not signed from the beginning")]
    WrongRangeStart,
    #[error("signature range does not end at the end of a PDF file")]
    WrongRangeEnd,
    #[error("invalid signature range")]
    InvalidRange,
    #[error("signature coverage skips over wrong sections of the document")]
    InvalidCoverage,
    #[error("last signature does not cover the whole document")]
    IncompleteCoverage,
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
                    // in PDF specification.
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

/// Verifies the signatures in a PDF document, assembled by concatenating an
/// incremental update to the reference document. Ensures that the contents of
/// the final document matches the reference.
pub fn verify_incremental_update(
    reference_pdf_bytes: impl AsRef<[u8]>,
    incremental_update_bytes: impl AsRef<[u8]>,
    ca_bundle: &CaBundle,
) -> Result<Vec<SignerInfo>> {
    let reference = reference_pdf_bytes.as_ref();
    let incremental_update = incremental_update_bytes.as_ref();

    let full_pdf = [reference, incremental_update].concat();
    let end_of_reference_pdf = reference.len();

    drop(reference_pdf_bytes);
    drop(incremental_update_bytes);

    verify(&full_pdf, end_of_reference_pdf, ca_bundle)
}

/// Verifies the signatures in a PDF document, ensuring that the contents of the
/// document matches the reference document.
pub fn verify_from_reference(
    reference_pdf_bytes: impl AsRef<[u8]>,
    signed_pdf_bytes: impl AsRef<[u8]>,
    ca_bundle: &CaBundle,
) -> Result<Vec<SignerInfo>> {
    let signed = signed_pdf_bytes.as_ref();
    let reference = reference_pdf_bytes.as_ref();

    if !signed.starts_with(reference) {
        return Err(Error::PossibleContentChange);
    }
    let end_of_reference_pdf = reference.len();
    drop(reference_pdf_bytes);

    verify(&signed, end_of_reference_pdf, ca_bundle)
}

/// Verifies the signatures in a PDF document, ensuring that the contents of the
/// document matches a previous version of the same document.
pub fn verify(
    pdf_bytes: &[u8],
    end_of_reference_pdf: usize,
    ca_bundle: &CaBundle,
) -> Result<Vec<SignerInfo>> {
    if end_of_reference_pdf > pdf_bytes.len() {
        return Err(Error::ReferenceIncrementOutOfBounds);
    }
    if !pdf_ends_with_eof(&pdf_bytes[..end_of_reference_pdf]) {
        return Err(Error::InvalidReferenceDocument);
    }

    let doc = Document::load_mem(pdf_bytes)?;

    let mut result = Vec::new();

    // Access the AcroForm dictionary
    let acro_form = match doc.get_dict_in_dict(doc.catalog()?, b"AcroForm") {
        Ok(val) => val,
        Err(lopdf::Error::DictKey) => return Ok(result),
        Err(e) => return Err(e.into()),
    };

    // Early skip if the form does not have any signatures
    let sig_flags = doc.get_in_dict(acro_form, b"SigFlags")?.as_i64()?;
    if sig_flags & 1 == 0 {
        return Ok(result);
    }

    struct Signature<'a> {
        coverage_end: usize,
        skipped_range: Range<usize>,
        rect: [f32; 4],
        pkcs7_signature: &'a [u8],
    }

    let mut signatures = Vec::new();

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

        let signature = doc.get_dict_in_dict(field, b"V")?;

        let signed_range = doc
            .get_in_dict(signature, b"ByteRange")?
            .as_array()?
            .iter()
            .map(|r| doc.deref(r).and_then(|r| Ok(r.as_i64()?)))
            .collect::<Result<ExactArrayOrNone<i64, 4>>>()?
            .0
            .ok_or(lopdf::Error::Type)?;

        // For soundness, we must ensure the signature covers the file since the
        // beginning.
        if signed_range[0] != 0 {
            return Err(Error::WrongRangeStart);
        }

        // Sanity check that the range is well formed and inside the document.
        for &range in &signed_range[1..] {
            if range < 0 {
                return Err(Error::InvalidRange);
            }
        }
        let signed_range_end = signed_range[2] + signed_range[3];
        if signed_range[1] > signed_range[2] || signed_range_end > pdf_bytes.len() as i64 {
            return Err(Error::InvalidRange);
        }

        // The /Contents field must match the bytes skipped in the signed range, which must be hex encoded.
        let skipped_bytes =
            decode_pdf_hex_string(&pdf_bytes[signed_range[1] as usize..signed_range[2] as usize])
                .ok_or(Error::InvalidCoverage)?;
        let pkcs7_signature = doc.get_in_dict(signature, b"Contents")?.as_str()?;
        if pkcs7_signature != skipped_bytes {
            return Err(Error::InvalidCoverage);
        }

        // Tests if the signature range ends with the PDF end marker (%%EOF).
        if !pdf_ends_with_eof(&pdf_bytes[..signed_range_end as usize]) {
            return Err(Error::WrongRangeEnd);
        }

        let rect = doc
            .get_in_dict(field, b"Rect")?
            .as_array()?
            .iter()
            .map(|r| doc.deref(r).and_then(|r| Ok(r.as_float()?)))
            .collect::<Result<ExactArrayOrNone<f32, 4>>>()?
            .0
            .ok_or(lopdf::Error::Type)?;

        // Store the signature for later verification.
        signatures.push(Signature {
            coverage_end: signed_range_end as usize,
            skipped_range: signed_range[1] as usize..signed_range[2] as usize,
            rect,
            pkcs7_signature,
        });
    }

    // Sort the signatures by increasing coverage of the document.
    signatures.sort_by_key(|s| s.coverage_end);

    // The last signature must cover the whole document.
    match signatures.last() {
        Some(last) => {
            if last.coverage_end != pdf_bytes.len() {
                return Err(Error::InvalidCoverage);
            }
        }
        None => return Ok(result),
    }

    for signature in signatures {
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

        /*let mut signed_data = Vec::with_capacity((signed_range[1] + signed_range[3]) as usize);
        signed_data.extend_from_slice(&pdf_bytes[0..signed_range[1] as usize]);
        signed_data
            .extend_from_slice(&pdf_bytes[signed_range[2] as usize..signed_range_end as usize]);

        eprintln!("Signature field found: {:?}", field);
        let signature = crate::validate_signature::Signature::new(pkcs7_signature)?;

        result.extend(signature.get_signers_info()?);

        // Verify the signature
        signature.verify(&signed_data, ca_bundle)?;*/
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

/// Decodes a PDF hex string, skipping whitespace.
/// Returns None if any character is not a valid hex digit.
fn decode_pdf_hex_string(hex_input: &[u8]) -> Option<Vec<u8>> {
    // First and last characters must be the delimiters '<' and '>'.
    if hex_input.first() != Some(&b'<') || hex_input.last() != Some(&b'>') {
        return None;
    }
    let hex_input = &hex_input[1..hex_input.len() - 1];

    let mut bytes = Vec::new();
    let mut hex_iter = hex_input.iter().filter_map(|&b| {
        let c = b as char;
        if c.is_whitespace() {
            None
        } else {
            Some(c.to_digit(16))
        }
    });

    while let Some(first) = hex_iter.next() {
        let first = first? as u8;
        let second = hex_iter.next().unwrap_or(Some(0))? as u8;
        bytes.push(first << 4 | second);
    }

    Some(bytes)
}

lazy_static::lazy_static! {
    static ref EOF_REGEX: Regex = Regex::new(r"(?:\r\n|\r|\n)%%EOF[ \t]*(?:\r\n|\r|\n)?$").unwrap();
}

/// Tests if the PDF ends with the %%EOF marker.
fn pdf_ends_with_eof(pdf_bytes: &[u8]) -> bool {
    EOF_REGEX.is_match(pdf_bytes)
}
