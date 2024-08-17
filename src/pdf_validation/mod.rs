mod increment_validation;

use std::ops::Range;

use lopdf::{xref::XrefEntry, Dictionary, Document, Object};
use regex::bytes::Regex;
use thiserror::Error;

use crate::signature_validation::{CaBundle, SignerInfo};

#[derive(Error, Debug)]
pub enum Error {
    #[error("PDF parsing error")]
    Parsing(#[from] lopdf::Error),
    #[error("reference document does not end like a PDF file")]
    InvalidReferenceDocument,
    #[error("end of the reference increment is bigger than the signed document")]
    ReferenceIncrementOutOfBounds,
    #[error("can not guarantee the contents of the signed document match the original")]
    PossibleContentChange,
    #[error("signature verification error")]
    SignatureVerification(#[from] crate::signature_validation::Error),
    #[error("invalid signature object")]
    InvalidSignatureObject,
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
    #[error("can not ensure that the incremental update didn't change the document")]
    PossibleIncrementalChange(#[from] increment_validation::Error),
    #[error("we encountered an internal consistency error, this is a bug that should be reported")]
    InternalConsistency,
}

type Result<T> = std::result::Result<T, Error>;

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

    verify(signed, end_of_reference_pdf, ca_bundle)
}

struct Signature<'a> {
    coverage_end: i64,
    skipped_range: Range<usize>,
    rect: [f32; 4],
    pkcs7_der: &'a [u8],
}

/// Verifies the signatures in a PDF document, ensuring that the contents of the
/// document matches a previous increment of the same document.
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
    let sig_flags = acro_form.get_deref(b"SigFlags", &doc)?.as_i64()?;
    if sig_flags & 1 == 0 {
        return Ok(result);
    }

    let mut signatures = get_signature_objects(pdf_bytes, &doc, acro_form)?;

    // Sort the signatures by decreasing coverage of the document.
    signatures.sort_by_key(|s| -s.coverage_end);

    // The biggest signature must cover the whole document.
    match signatures.first() {
        Some(last) => {
            if last.coverage_end as usize != pdf_bytes.len() {
                return Err(Error::IncompleteCoverage);
            }
        }
        None => {
            if end_of_reference_pdf == pdf_bytes.len() {
                // If there are no signatures, the document must be the same as the reference.
                return Ok(result);
            } else {
                // There document is bigger than the reference, but there are no signatures.
                return Err(Error::PossibleContentChange);
            }
        }
    }

    // Signatures validating ranges inside the reference document won't be
    // subject to scrutiny on how they were added, so we filter them out for the
    // next step.
    let added_signatures = &signatures
        [..signatures.partition_point(|s| s.coverage_end as usize > end_of_reference_pdf)];

    // An iterator in decreasing order over the incremental updates we are comparing against.
    let incremental_updates = added_signatures[1..]
        .iter()
        .map(|s| s.coverage_end as usize)
        .chain([end_of_reference_pdf]);

    // Ensures that the incremental updates were added correctly.
    {
        let mut tmp_storage;
        let mut curr_doc = &doc;
        for (sig, previous_doc) in added_signatures.iter().zip(incremental_updates) {
            let previous_doc = Box::new(Document::load_mem(&pdf_bytes[..previous_doc])?);
            increment_validation::verify_increment(sig, curr_doc, &previous_doc)?;

            tmp_storage = previous_doc;
            curr_doc = &tmp_storage;
        }
    }

    // Finally, we verify the signatures.
    for sig in signatures {
        // Openssl requires a continuous array of bytes to verify the signature,
        // so we must concatenate the ranges.
        let data_size = sig.coverage_end as usize - sig.skipped_range.len();
        let mut signed_data = Vec::with_capacity(data_size);
        signed_data.extend_from_slice(&pdf_bytes[0..sig.skipped_range.start]);
        signed_data.extend_from_slice(&pdf_bytes[sig.skipped_range.end..sig.coverage_end as usize]);
        assert!(signed_data.len() == data_size);

        let signature = crate::signature_validation::Signature::new(sig.pkcs7_der)?;

        result.extend(signature.get_signers_info()?);

        // Verify the signature
        signature.verify(&signed_data, ca_bundle)?;
    }

    Ok(result)
}

fn get_signature_objects<'a>(
    pdf_bytes: &[u8],
    doc: &'a Document,
    acro_form: &'a Dictionary,
) -> Result<Vec<Signature<'a>>> {
    let mut signatures = Vec::new();

    for field in acro_form
        .get_deref(b"Fields", doc)?
        .as_array()?
        .iter()
        .map(|f| doc.dereference(f))
    {
        let field = field?.1.as_dict()?;

        // Check if the field is a signature
        if !is_signature(field) {
            continue;
        }

        signatures.push(process_signature(pdf_bytes, doc, field)?);
    }

    Ok(signatures)
}

fn process_signature<'a>(
    pdf_bytes: &[u8],
    doc: &'a Document,
    field: &'a Dictionary,
) -> Result<Signature<'a>> {
    let (Some(signature_obj_id), Object::Dictionary(signature)) =
        doc.dereference(field.get(b"V")?)?
    else {
        // Signature object must be an indirect dictionary.
        return Err(Error::InvalidSignatureObject);
    };

    let signed_range = signature
        .get_deref(b"ByteRange", doc)?
        .as_array()?
        .iter()
        .map(|r| doc.dereference(r).and_then(|(_, r)| r.as_i64()))
        .collect::<lopdf::Result<ExactArrayOrNone<i64, 4>>>()?
        .0
        .ok_or(lopdf::Error::Type)?;

    // For soundness, we must ensure the signature covers the file since the
    // beginning.
    if signed_range[0] != 0 {
        return Err(Error::WrongRangeStart);
    }

    // The signature object must be inside the signed range.
    if let XrefEntry::Normal { offset, generation } =
        doc.reference_table.get(signature_obj_id.0).ok_or(
            // This entry must exist, as it was dereferenced above. But to be
            // resilient, we won't panic.
            Error::InternalConsistency,
        )?
    {
        if *generation != signature_obj_id.1 {
            // The generation is known, so it must match the entry in the xref table.
            return Err(Error::InternalConsistency);
        }
        if *offset as i64 >= signed_range[1] {
            return Err(Error::InvalidCoverage);
        }
    } else {
        return Err(Error::InvalidSignatureObject);
    };

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
    let pkcs7_signature = signature.get_deref(b"Contents", doc)?.as_str()?;
    if pkcs7_signature != skipped_bytes {
        return Err(Error::InvalidCoverage);
    }

    // Tests if the signature range ends with the PDF end marker (%%EOF).
    if !pdf_ends_with_eof(&pdf_bytes[..signed_range_end as usize]) {
        return Err(Error::WrongRangeEnd);
    }

    let rect = field
        .get_deref(b"Rect", doc)?
        .as_array()?
        .iter()
        .map(|r| doc.dereference(r).and_then(|(_, r)| r.as_float()))
        .collect::<lopdf::Result<ExactArrayOrNone<f32, 4>>>()?
        .0
        .ok_or(lopdf::Error::Type)?;

    Ok(Signature {
        coverage_end: signed_range_end,
        skipped_range: signed_range[1] as usize..signed_range[2] as usize,
        rect,
        pkcs7_der: pkcs7_signature,
    })
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