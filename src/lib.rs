#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

#[cfg(feature = "openssl")]
pub mod openssl;

mod increment_validation;

use std::ops::Range;

use anyhow::Result;
pub use increment_validation::Annotation;
use lopdf::{xref::XrefEntry, Dictionary, Document, Object, ObjectId};
use regex::bytes::Regex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("reference document does not end like a PDF file")]
    InvalidReferenceDocument,
    #[error("end of the reference increment is bigger than the signed document")]
    ReferenceIncrementOutOfBounds,
    #[error("can not guarantee the contents of the signed document match the original")]
    PossibleContentChange,
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
    InternalConsistency,
}

/// Information about a signature found in the PDF document.
///
/// The signatures have not been verified yet. You can use the optional
/// [`openssl`] module to verify them.
#[derive(Debug)]
pub struct SignatureInfo {
    /// If the signature corresponds to a visible annotation, this field holds
    /// the details about it.
    pub annotation: Option<Annotation>,

    /// The byte ranges of the document that were signed. The skipped range
    /// contains the signature itself, as an hexadecimal encoded PDF ByteStream.
    pub signed_byte_ranges: [Range<usize>; 2],

    /// The signature itself, as decoded from the PDF ByteStream. It is a BER
    /// encoded PKCS #7.
    pub pkcs7_ber: Vec<u8>,
}

/// Verifies if the contents of a signed PDF matches a reference document.
///
/// The `reference_pdf_bytes` parameter is the reference document, and the
/// `signed_pdf_bytes` parameter is the signed document.
pub fn verify_from_reference(
    reference_pdf_bytes: impl AsRef<[u8]>,
    signed_pdf_bytes: impl AsRef<[u8]>,
) -> Result<Vec<SignatureInfo>> {
    let signed = signed_pdf_bytes.as_ref();
    let reference = reference_pdf_bytes.as_ref();

    if !signed.starts_with(reference) {
        return Err(Error::PossibleContentChange.into());
    }
    let end_of_reference_pdf = reference.len();
    drop(reference_pdf_bytes);

    Verifier::parse(signed)?.verify(end_of_reference_pdf)
}

/// State machine for parsing and then verifying.
pub struct Verifier<'a> {
    doc: Document,
    pdf_bytes: &'a [u8],
}

impl<'a> Verifier<'a> {
    /// Parse a PDF document and creates the verification structure.
    ///
    /// Parameter `pdf_bytes` is the byte array of the PDF document.
    pub fn parse(pdf_bytes: &'a [u8]) -> Result<Self> {
        let doc = Document::load_mem(pdf_bytes)?;
        Ok(Self { doc, pdf_bytes })
    }

    /// Verifies if the contents of a signed PDF file matches an earlier
    /// version.
    ///
    /// The `end_of_reference_pdf` is the byte offset that limits the original
    /// PDF document inside the full signed document, to be compared against.
    /// The contents of the original document must match the contents of the
    /// signed document.
    pub fn verify(&self, end_of_reference_pdf: usize) -> Result<Vec<SignatureInfo>> {
        let doc = &self.doc;
        let pdf_bytes = self.pdf_bytes;

        basic_file_buff_checks(pdf_bytes, end_of_reference_pdf)?;

        if end_of_reference_pdf == pdf_bytes.len() {
            return Ok(Vec::new());
        }

        // Access the AcroForm dictionary
        let acro_form = match doc.get_dict_in_dict(doc.catalog()?, b"AcroForm") {
            Ok(val) => val,
            Err(e) => return Err(e.into()),
        };

        let mut signatures = get_signature_objects(pdf_bytes, doc, acro_form)?;

        // Sort the signatures by decreasing coverage of the document.
        signatures.sort_by_key(|s| -s.coverage_end);

        // The biggest signature must cover the whole document.
        match signatures.first() {
            Some(last) => {
                if last.coverage_end as usize != pdf_bytes.len() {
                    return Err(Error::IncompleteCoverage.into());
                }
            }
            None => {
                // There document is bigger than the reference, but there are no signatures.
                return Err(Error::PossibleContentChange.into());
            }
        }

        // Signatures validating ranges inside the reference document won't be
        // subject to scrutiny on how they were added, so we filter them out for the
        // next step.
        let partition_point =
            signatures.partition_point(|s| s.coverage_end as usize > end_of_reference_pdf);
        let added_signatures = &signatures[..partition_point];

        // An iterator in decreasing order over the incremental updates we are comparing against.
        let incremental_updates = added_signatures[1..]
            .iter()
            .map(|s| s.coverage_end as usize)
            .chain([end_of_reference_pdf]);

        // Ensures that the incremental updates were added correctly.
        let mut annotations = Vec::new();
        {
            let mut tmp_storage;
            let mut curr_doc = doc;
            for (sig, previous_doc) in added_signatures.iter().zip(incremental_updates) {
                // Signature offset must be after the previous document.
                if (sig.offset as usize) < previous_doc {
                    return Err(Error::InvalidSignatureObject.into());
                }

                let previous_doc = Document::load_mem(&pdf_bytes[..previous_doc])?;
                let annot = increment_validation::verify_increment(sig, curr_doc, &previous_doc)?;
                annotations.push(annot);

                tmp_storage = previous_doc;
                curr_doc = &tmp_storage;
            }
        }

        // Join annotations with the signatures in a single vector.
        //
        // Since annotations may be smaller than the signatures, we must pad the
        // the beginning of the vector with None.
        let extra_none_count = signatures.len() - annotations.len();
        let padded_annotations = std::iter::repeat_with(|| None)
            .take(extra_none_count)
            .chain(annotations);
        padded_annotations
            .zip(signatures)
            .map(|(annotation, signature)| {
                let signed_byte_ranges = [
                    0..signature.skipped_range.start,
                    signature.skipped_range.end..signature.coverage_end as usize,
                ];
                Ok(SignatureInfo {
                    annotation,
                    signed_byte_ranges,
                    pkcs7_ber: signature.pkcs7_ber,
                })
            })
            .collect()
    }
}

fn basic_file_buff_checks(pdf_bytes: &[u8], end_of_reference_pdf: usize) -> Result<()> {
    if end_of_reference_pdf > pdf_bytes.len() {
        return Err(Error::ReferenceIncrementOutOfBounds.into());
    }

    if !pdf_ends_with_eof(&pdf_bytes[..end_of_reference_pdf]) {
        return Err(Error::InvalidReferenceDocument.into());
    }

    Ok(())
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

struct Signature {
    obj_id: ObjectId,
    offset: u32,
    coverage_end: i64,
    skipped_range: Range<usize>,
    pkcs7_ber: Vec<u8>,
}

fn get_signature_objects(
    pdf_bytes: &[u8],
    doc: &Document,
    acro_form: &Dictionary,
) -> Result<Vec<Signature>> {
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

        signatures.push(process_signature(pdf_bytes, doc, field.get(b"V")?)?);
    }

    Ok(signatures)
}

fn process_signature(
    pdf_bytes: &[u8],
    doc: &Document,
    sig_reference: &Object,
) -> Result<Signature> {
    let (Some(obj_id), Object::Dictionary(signature)) = doc.dereference(sig_reference)? else {
        // Signature object must be an indirect dictionary.
        return Err(Error::InvalidSignatureObject.into());
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
        return Err(Error::WrongRangeStart.into());
    }

    // The signature object must be inside the signed range.
    let offset = if let XrefEntry::Normal { offset, generation } =
        doc.reference_table.get(obj_id.0).ok_or(
            // This entry must exist, as it was dereferenced above. But to be
            // resilient, we won't panic.
            Error::InternalConsistency,
        )? {
        if *generation != obj_id.1 {
            // The generation is known, so it must match the entry in the xref table.
            return Err(Error::InternalConsistency.into());
        }
        if *offset as i64 >= signed_range[1] {
            return Err(Error::InvalidCoverage.into());
        }
        *offset
    } else {
        return Err(Error::InvalidSignatureObject.into());
    };

    // Sanity check that the range is well formed and inside the document.
    for &range in &signed_range[1..] {
        if range < 0 {
            return Err(Error::InvalidRange.into());
        }
    }
    let signed_range_end = signed_range[2] + signed_range[3];
    if signed_range[1] > signed_range[2] || signed_range_end > pdf_bytes.len() as i64 {
        return Err(Error::InvalidRange.into());
    }

    // The /Contents field must match the bytes skipped in the signed range, which must be hex encoded.
    let skipped_bytes =
        decode_pdf_hex_string(&pdf_bytes[signed_range[1] as usize..signed_range[2] as usize])
            .ok_or(Error::InvalidCoverage)?;
    let pkcs7_signature = signature.get_deref(b"Contents", doc)?.as_str()?;
    if pkcs7_signature != skipped_bytes {
        return Err(Error::InvalidCoverage.into());
    }

    // Tests if the signature range ends with the PDF end marker (%%EOF).
    if !pdf_ends_with_eof(&pdf_bytes[..signed_range_end as usize]) {
        return Err(Error::WrongRangeEnd.into());
    }

    Ok(Signature {
        obj_id,
        offset,
        coverage_end: signed_range_end,
        skipped_range: signed_range[1] as usize..signed_range[2] as usize,
        pkcs7_ber: skipped_bytes,
    })
}

fn is_signature(annot_dict: &Dictionary) -> bool {
    // Check for /FT (Field Type) being /Sig
    if let Ok(Object::Name(ft)) = annot_dict.get(b"FT") {
        if ft == b"Sig" {
            return true;
        }
    }
    false
}

/// Decodes a PDF hex string, including the delimiters '<' and '>'.
///
/// Returns None if the string doesn't match the pattern "^<[0-9A-Fa-f]*>$".
fn decode_pdf_hex_string(hex_input: &[u8]) -> Option<Vec<u8>> {
    // First and last characters must be the delimiters '<' and '>'.
    if hex_input.first() != Some(&b'<') || hex_input.last() != Some(&b'>') {
        return None;
    }
    let hex_input = &hex_input[1..hex_input.len() - 1];

    let mut bytes = Vec::new();
    let mut hex_iter = hex_input.iter().map(|&b| {
        let c = b as char;
        c.to_digit(16)
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
