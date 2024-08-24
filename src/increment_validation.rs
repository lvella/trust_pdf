use crate::ExactArrayOrNone;

use super::Signature;
use anyhow::Result;
use lopdf::{xref::XrefEntry, Dictionary, Document, Object, ObjectId};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    vec::IntoIter,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("mismatch between /Catalog dictionaries")]
    CatalogMismatch,
    #[error("mismatch between /AcroForm dictionaries")]
    AcroFormMismatch,
    #[error("array has more than one extra reference")]
    NotSingleArrayIncrement,
    #[error("multiple pages changed in the increment")]
    MultiplePagesChanged,
    #[error("mismatch between /Page dictionaries")]
    PageMismatch,
    #[error("invalid annotation")]
    InvalidAnnotation,
    #[error("invalid form")]
    InvalidForm,
    #[error("signature dictionary was modified")]
    SignatureModified,
    #[error("wrong SigFlags value")]
    WrongSigFlags,
    #[error("mismatch between xref tables")]
    XrefMismatch,
}

struct DocTracker<'a> {
    traversed: RefCell<HashMap<u32, u16>>,
    doc: &'a Document,
}

impl<'a> DocTracker<'a> {
    fn new(doc: &'a Document) -> Self {
        DocTracker {
            traversed: RefCell::new(HashMap::new()),
            doc,
        }
    }

    fn catalog(&self) -> Result<DictTracker> {
        DictTracker {
            tracker: self,
            dict: &self.doc.trailer,
        }
        .get_dict_deref(b"Root")
    }

    fn get(&self, id: ObjectId) -> Result<&Object> {
        if let Some(gen) = self.traversed.borrow_mut().insert(id.0, id.1) {
            if gen != id.1 {
                return Err(lopdf::Error::ObjectIdMismatch.into());
            }
        }
        Ok(self.doc.get_object(id)?)
    }

    fn deref(&self, obj: &'a Object) -> Result<&Object> {
        // It is reasonable to only track the first reference in a chain of
        // references, because that is the only one that needs to change. I.e.,
        // we don't allow an increment update to introduce a silly chain of
        // references.
        match obj {
            Object::Reference(id) => self.get(*id),
            _ => Ok(obj),
        }
    }

    fn deref_dict(&self, obj: &'a Object) -> Result<DictTracker> {
        Ok(DictTracker {
            tracker: self,
            dict: self.deref(obj)?.as_dict()?,
        })
    }

    fn verify_all_changes_are_allowed(self, other: &Document) -> Result<()> {
        let traversed = self.traversed.into_inner();

        for (id, entry) in self.doc.reference_table.entries.iter() {
            if traversed.get(id).is_some() {
                // This entry is allowed to be different.
                continue;
            }

            let Some(other_entry) = other.reference_table.entries.get(id) else {
                return Err(Error::XrefMismatch.into());
            };

            if XrefEntryComparer(entry) != XrefEntryComparer(other_entry) {
                return Err(Error::XrefMismatch.into());
            }
        }

        Ok(())
    }
}

struct DictTracker<'a> {
    tracker: &'a DocTracker<'a>,
    dict: &'a Dictionary,
}

impl<'a> DictTracker<'a> {
    fn get_dict_deref(&self, key: &[u8]) -> Result<DictTracker<'a>> {
        self.tracker.deref_dict(self.dict.get(key)?)
    }
}

/// Unfortunatelly, XrefEntry does not implement PartialEq, so we have to implement ourselves.
struct XrefEntryComparer<'a>(&'a XrefEntry);

impl PartialEq for XrefEntryComparer<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self.0, other.0) {
            (
                XrefEntry::Normal { offset, generation },
                XrefEntry::Normal {
                    offset: other_offset,
                    generation: other_generation,
                },
            ) => offset == other_offset && generation == other_generation,
            (
                XrefEntry::Compressed { container, index },
                XrefEntry::Compressed {
                    container: other_container,
                    index: other_index,
                },
            ) => container == other_container && index == other_index,
            (XrefEntry::Free, XrefEntry::Free)
            | (XrefEntry::UnusableFree, XrefEntry::UnusableFree) => true,
            _ => {
                assert!(
                    std::mem::discriminant(self.0) != std::mem::discriminant(other.0),
                    "Bug: unhandled XrefEntry variant in comparison"
                );
                false
            }
        }
    }
}

#[derive(Debug)]
pub struct Annotation {
    pub page_idx: usize,
    pub rect: [f32; 4],
}

/// For soundness, check that no visual elements were incrementally added to the
/// original document before it was signed. Otherwise the user could have added
/// visual elements to the document changing its meaning, but fooled us into
/// thinking what was signed was the original document. Of course, legally this
/// could be seen as some kind of fraud, and we would have the signed proof the
/// user did it.
pub fn verify_increment(
    curr_sig: &Signature,
    curr_doc: &Document,
    previous_doc: &Document,
) -> Result<Option<Annotation>> {
    // check the reference signature id has the expected offset in the xref table
    let xref_entry = curr_doc
        .reference_table
        .entries
        .get(&curr_sig.obj_id.0)
        .ok_or(Error::SignatureModified)?;
    if XrefEntryComparer(xref_entry)
        != XrefEntryComparer(&XrefEntry::Normal {
            offset: curr_sig.offset,
            generation: curr_sig.obj_id.1,
        })
    {
        return Err(Error::SignatureModified.into());
    }

    let prev_doc_tracker = DocTracker::new(previous_doc);

    let anotation = verify_catalogs(curr_sig.obj_id, curr_doc, &prev_doc_tracker)?;

    // All the indirect objects in the tracked list are allowed to be
    // different from the corresponding object in the current document.
    // All others must match.
    prev_doc_tracker.verify_all_changes_are_allowed(curr_doc)?;

    Ok(anotation)
}

fn verify_catalogs(
    curr_sig_id: ObjectId,
    curr_doc: &Document,
    previous_doc: &DocTracker,
) -> Result<Option<Annotation>> {
    let curr_catalog = curr_doc.catalog()?;
    let prev_catalog = previous_doc.catalog()?;

    let mut prev_acro_form = None;
    let mut size_diff = 1;

    let mut pages = None;

    for (key, obj) in prev_catalog.dict.iter() {
        if key == b"AcroForm" {
            prev_acro_form = Some(previous_doc.deref_dict(obj)?);
            size_diff = 0;

            // AcroForm is handled separately.
            continue;
        }

        if key == b"Pages" {
            // The /Type /Pages dictionary must be a reference to a dictionary
            // and remain the same, but we still need to check the individual
            // pages, so we store it for later use.
            pages = Some(curr_doc.get_dictionary(obj.as_reference()?)?);
        }

        let curr_obj = curr_catalog.get(key)?;
        if curr_obj != obj {
            return Err(Error::CatalogMismatch.into());
        }
    }

    // All the elements from both catalogs must have matched.
    if prev_catalog.dict.len() + size_diff != curr_catalog.len() {
        return Err(Error::CatalogMismatch.into());
    }

    // Current catalog must have an AcroForm dictionary.
    verify_acro_forms(
        curr_doc,
        curr_doc.get_dict_in_dict(curr_catalog, b"AcroForm")?,
        prev_acro_form,
        curr_sig_id,
    )?;

    // One page individually can be different (by one annotation, at most), but
    // the /Type /Pages dictionary must remain the same.
    verify_pages(curr_doc, previous_doc, pages.ok_or(lopdf::Error::DictKey)?)
}

fn verify_acro_forms(
    curr_doc: &Document,
    curr_acro_form: &Dictionary,
    prev_acro_form: Option<DictTracker>,
    signature: ObjectId,
) -> Result<()> {
    let mut prev_has_da = false;
    let mut prev_has_dr = false;

    let mut prev_fields = None;

    let mut expected_len = if let Some(prev_acro_form) = prev_acro_form {
        let mut extra_fields = 1;
        for (key, obj) in prev_acro_form.dict.iter() {
            if key == b"Fields" {
                // Fields are handled separately.
                prev_fields = Some(prev_acro_form.tracker.deref(obj)?.as_array()?);
                continue;
            }

            if key == b"DA" {
                prev_has_da = true;
            } else if key == b"DR" {
                prev_has_dr = true;
            } else if key == b"SigFlags" {
                // We required SigFlags for the incremental update, but the
                // original document may not have it. If it does, we don't need
                // to count it as an extra field.
                extra_fields = 0;
            }

            let curr_obj = curr_acro_form.get(key)?;
            if curr_obj != obj {
                return Err(Error::AcroFormMismatch.into());
            }
        }
        prev_acro_form.dict.len() + extra_fields
    } else {
        // /Fields and /SigFlags are required in the increment.
        2
    };

    let mut handle_extra_field = |key| {
        if curr_acro_form.has(key) {
            expected_len += 1;
        }
    };

    if !prev_has_da {
        handle_extra_field(b"DA");
    }

    if !prev_has_dr {
        handle_extra_field(b"DR");
    }

    if curr_acro_form.len() != expected_len {
        return Err(Error::AcroFormMismatch.into());
    }

    // Test /SigFlags expected value.
    if curr_acro_form.get(b"SigFlags")?.as_i64()? != 3 {
        return Err(Error::WrongSigFlags.into());
    }

    // Handle the fields
    let curr_fields = curr_acro_form.get_deref(b"Fields", curr_doc)?.as_array()?;
    let extra_form = has_array_one_extra_ref(curr_fields, prev_fields)?;

    verify_form(curr_doc, extra_form, signature)
}

/// Verifies the form field which contains the signature.
fn verify_form(doc: &Document, form_id: ObjectId, reference_sig: ObjectId) -> Result<()> {
    let form = doc.get_dictionary(form_id)?;

    // check /FT is /Sig
    if form.get_deref(b"FT", doc)?.as_name()? != b"Sig" {
        return Err(Error::InvalidForm.into());
    }

    // check /V is the reference signature id
    if form.get(b"V")?.as_reference()? != reference_sig {
        return Err(Error::InvalidForm.into());
    }

    Ok(())
}

/// Why peekable is not a trait? Let's do our own trait.
trait Peekable {
    type Item;
    fn peek(&self) -> Option<&Self::Item>;
}

impl<I> Peekable for IntoIter<I> {
    type Item = I;

    fn peek(&self) -> Option<&Self::Item> {
        self.as_slice().first()
    }
}

/// If curr_refs elements matches all the prev_refs elements, except for one
/// single exta element, and all elements in both arrays are references, returns
/// the extra element.
///
/// Allows for reordering.
///
/// Returns or Err in any other case.
fn has_array_one_extra_ref(
    curr_refs: &[Object],
    prev_refs: Option<&Vec<Object>>,
) -> Result<ObjectId> {
    fn sort_array(array: &[Object]) -> Result<IntoIter<ObjectId>> {
        let mut array = array
            .iter()
            .map(|obj| obj.as_reference())
            .collect::<lopdf::Result<Vec<ObjectId>>>()?;
        array.sort();
        Ok(array.into_iter())
    }

    let prev_refs = prev_refs.map_or([].as_slice(), |prev_refs| prev_refs);
    let mut prev_iter = sort_array(prev_refs)?;
    let mut curr_iter = sort_array(curr_refs)?;

    while let (Some(prev), Some(curr)) = (prev_iter.peek(), curr_iter.peek()) {
        if prev != curr {
            break;
        }
        prev_iter.next();
        curr_iter.next();
    }

    let odd_one_out = curr_iter.next().ok_or(Error::NotSingleArrayIncrement)?;
    if !curr_iter.eq(prev_iter) {
        return Err(Error::NotSingleArrayIncrement.into());
    }

    Ok(odd_one_out)
}

fn verify_pages(
    curr_doc: &Document,
    prev_doc: &DocTracker,
    pages: &Dictionary,
) -> Result<Option<Annotation>> {
    let mut extra_annotation = None;

    let kids = pages.get_deref(b"Kids", curr_doc)?.as_array()?;
    for (page_idx, page) in kids.iter().enumerate() {
        if let Some(page_id) = object_has_changed(curr_doc, prev_doc.doc, page.as_reference()?)? {
            // Found our candidate page to contain the signature annotation.
            if extra_annotation.is_some() {
                return Err(Error::MultiplePagesChanged.into());
            }

            let curr_page = curr_doc.get_dictionary(page_id)?;
            let prev_page = prev_doc.deref_dict(page)?;

            extra_annotation = Some(Annotation {
                page_idx,
                // We need to check the page contents for the signature annotation.
                rect: verify_page(curr_doc, page_id, curr_page, prev_page)?,
            });
        }
    }

    // The only way this is None is if no page was changed.
    Ok(extra_annotation)
}

/// Returns the first different object id in the reference chain, if any.
fn object_has_changed(
    curr_doc: &Document,
    prev_doc: &Document,
    mut id: ObjectId,
) -> Result<Option<ObjectId>> {
    let mut seen = HashSet::from([id.0]);

    while let (Some(curr_entry), Some(prev_entry)) = (
        curr_doc.reference_table.entries.get(&id.0),
        prev_doc.reference_table.entries.get(&id.0),
    ) {
        if XrefEntryComparer(curr_entry) != XrefEntryComparer(prev_entry) {
            return Ok(Some(id));
        }

        if let Object::Reference(next_id) = curr_doc.get_object(id)? {
            if seen.insert(next_id.0) {
                id = *next_id;
            } else {
                // We have a cycle in the reference chain.
                return Err(lopdf::Error::ReferenceLimit.into());
            }
        } else {
            // The original object id points to the exact same object in the new document.
            return Ok(None);
        }
    }

    Err(lopdf::Error::ObjectNotFound.into())
}

fn verify_page(
    curr_doc: &Document,
    curr_page_id: ObjectId,
    curr_page: &Dictionary,
    prev_page: DictTracker,
) -> Result<[f32; 4]> {
    let mut prev_annots = None;
    let mut extra_len = 1;

    for (key, obj) in prev_page.dict.iter() {
        if key == b"Annots" {
            prev_annots = Some(prev_page.tracker.deref(obj)?.as_array()?);
            extra_len = 0;

            // Annotations are handled separately.
            continue;
        }

        let curr_obj = curr_page.get(key)?;
        if curr_obj != obj {
            return Err(Error::PageMismatch.into());
        }
    }

    if curr_page.len() != prev_page.dict.len() + extra_len {
        return Err(Error::PageMismatch.into());
    }

    let curr_annots = curr_page.get_deref(b"Annots", curr_doc)?.as_array()?;
    let extra_annotation = has_array_one_extra_ref(curr_annots, prev_annots)?;

    verify_annotation(curr_doc, curr_page_id, extra_annotation)
}

/// Some signing software creates an annotation /Widget with the "visuals" of
/// the signature. There is not much we can do to verify this doesn't not try to
/// mess with the original appearance of the page, but we can at least extract
/// the rectangle where the annotation is contained, and return it.
fn verify_annotation(doc: &Document, page_id: ObjectId, annot_id: ObjectId) -> Result<[f32; 4]> {
    let dict = doc.get_dictionary(annot_id)?;

    // /Type is optional, but if present, it must be /Annot.
    match dict.get_deref(b"Type", doc) {
        Ok(obj) => {
            if obj.as_name()? != b"Annot".as_slice() {
                return Err(Error::InvalidAnnotation.into());
            }
        }
        Err(lopdf::Error::DictKey) => (),
        Err(e) => return Err(e.into()),
    };

    // /P is optional, but if present, it must point to the page where the
    // annotation is.
    if let Ok(p) = dict.get(b"P") {
        if p.as_reference()? != page_id {
            return Err(Error::InvalidAnnotation.into());
        }
    }

    // /Subtype /Widget is mandatory.
    if dict.get_deref(b"Subtype", doc)?.as_name()? != b"Widget".as_slice() {
        return Err(Error::InvalidAnnotation.into());
    }

    // /Rect is also mandatory.
    Ok(dict
        .get_deref(b"Rect", doc)?
        .as_array()?
        .iter()
        .map(|r| doc.dereference(r).and_then(|(_, r)| r.as_float()))
        .collect::<lopdf::Result<ExactArrayOrNone<f32, 4>>>()?
        .0
        .ok_or(lopdf::Error::Type)?)
}
