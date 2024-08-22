use super::Signature;
use lopdf::{xref::XrefEntry, Dictionary, Document, Object, ObjectId};
use std::{cell::RefCell, collections::HashMap};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("PDF parsing error")]
    Parsing(#[from] lopdf::Error),
    #[error("mismatch between /Catalog dictionaries")]
    CatalogMismatch,
    #[error("mismatch between /AcroForm dictionaries")]
    AcroFormMismatch,
    #[error("array has more than one extra reference")]
    NotSingleArrayIncrement,
    #[error("two different signature annotations found in the increment")]
    TwoDifferentSignatureInIncrement,
    #[error("multiple pages changed in the increment")]
    MultiplePagesChanged,
    #[error("mismatch between /Page dictionaries")]
    PageMismatch,
    #[error("mismatch between xref tables")]
    XrefMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;

struct DocTracker<'a> {
    traversed: RefCell<HashMap<u32, u16>>,
    doc: &'a Document,
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

    fn deref(&self, obj: &'a Object) -> Result<&Object> {
        // It is reasonable to only track the first reference in a chain of
        // references, because that is the only one that needs to change.
        match obj {
            Object::Reference(id) => {
                if let Some(gen) = self.traversed.borrow_mut().insert(id.0, id.1) {
                    if gen != id.1 {
                        return Err(Error::Parsing(lopdf::Error::ObjectIdMismatch));
                    }
                }
                Ok(self.doc.get_object(*id)?)
            }
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
                return Err(Error::XrefMismatch);
            };

            // Unfortunatelly, XrefEntry does not implement PartialEq, so we have to compare manually.
            match (entry, other_entry) {
                (
                    XrefEntry::Normal { offset, generation },
                    XrefEntry::Normal {
                        offset: other_offset,
                        generation: other_generation,
                    },
                ) => {
                    if offset != other_offset || generation != other_generation {
                        return Err(Error::XrefMismatch);
                    }
                }
                (
                    XrefEntry::Compressed { container, index },
                    XrefEntry::Compressed {
                        container: other_container,
                        index: other_index,
                    },
                ) => {
                    if container != other_container || index != other_index {
                        return Err(Error::XrefMismatch);
                    }
                }
                (XrefEntry::Free, XrefEntry::Free) => {}
                (XrefEntry::UnusableFree, XrefEntry::UnusableFree) => {}
                _ => {
                    assert!(
                        std::mem::discriminant(entry) != std::mem::discriminant(other_entry),
                        "Bug: unhandled XrefEntry variant in match"
                    );
                    return Err(Error::XrefMismatch);
                }
            }
        }

        Ok(())
    }
}

pub fn verify_increment(
    curr_sig: &Signature,
    curr_doc: &Document,
    previous_doc: &Document,
) -> Result<()> {
    // TODO: for soundness, check that no visual elements were
    // incrementally added to the original document before it was
    // signed. Otherwise the user could have added visual elements to
    // the document changing its meaning, but fooled us into thinking
    // what was signed was the original document. Of course, legally
    // this could be seen as some kind of fraud, and we would have the
    // signed proof the user did it.

    let prev_doc_tracker = DocTracker::new(previous_doc);

    verify_catalogs(curr_sig, curr_doc, &prev_doc_tracker)?;

    // All the indirect objects in the tracked list are allowed to be
    // different from the corresponding object in the current document.
    // All others must match.
    prev_doc_tracker.verify_all_changes_are_allowed(curr_doc)?;

    Ok(())
}

fn verify_catalogs(
    curr_sig: &Signature,
    curr_doc: &Document,
    previous_doc: &DocTracker,
) -> Result<()> {
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
            return Err(Error::CatalogMismatch);
        }
    }

    // All the elements from both catalogs must have matched.
    if prev_catalog.dict.len() + size_diff != curr_catalog.len() {
        return Err(Error::CatalogMismatch);
    }

    // Current catalog must have an AcroForm dictionary.
    let new_signature_id_f = verify_acro_forms(
        curr_doc,
        curr_doc.get_dict_in_dict(curr_catalog, b"AcroForm")?,
        prev_acro_form,
    )?;

    // Each page individually can be different (by one annotation, at most), but
    // the /Type /Pages dictionary must remain the same.
    let new_signature_id_p = verify_pages(
        curr_doc,
        previous_doc,
        pages.ok_or(Error::Parsing(lopdf::Error::DictKey))?,
    )?;

    if let Some(new_signature_id_p) = new_signature_id_p {
        if new_signature_id_f != new_signature_id_p {
            return Err(Error::TwoDifferentSignatureInIncrement);
        }
    }

    verify_sig_annotation(curr_sig, curr_doc, new_signature_id_f)?;

    Ok(())
}

fn verify_acro_forms(
    curr_doc: &Document,
    curr_acro_form: &Dictionary,
    prev_acro_form: Option<DictTracker>,
) -> Result<ObjectId> {
    let mut prev_has_da = false;
    let mut prev_has_dr = false;

    let mut prev_fields = None;

    let mut allowed_len = if let Some(prev_acro_form) = prev_acro_form {
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
            }

            let curr_obj = curr_acro_form.get(key)?;
            if curr_obj != obj {
                return Err(Error::AcroFormMismatch);
            }
        }
        prev_acro_form.dict.len()
    } else {
        1
    };

    let mut handle_extra_field = |key| {
        if curr_acro_form.has(key) {
            allowed_len += 1;
        }
    };

    if !prev_has_da {
        handle_extra_field(b"DA");
    }

    if !prev_has_dr {
        handle_extra_field(b"DR");
    }

    if curr_acro_form.len() != allowed_len {
        return Err(Error::AcroFormMismatch);
    }

    // Handle the fields
    let curr_fields = curr_acro_form.get_deref(b"Fields", curr_doc)?.as_array()?;
    let extra_signature_annotation = has_array_one_extra_ref(curr_fields, prev_fields)?;

    extra_signature_annotation.ok_or(Error::NotSingleArrayIncrement)
}

/// Gets the single extra ObjectId curr array has compared to the prev array, if any.
/// Allows for reordering.
///
/// Return Ok(None) if the arrays are equial.
///
/// Returns or Err in case of any other difference.
fn has_array_one_extra_ref(
    curr_refs: &[Object],
    prev_refs: Option<&Vec<Object>>,
) -> Result<Option<ObjectId>> {
    fn sort_array(array: &[Object]) -> Result<Vec<ObjectId>> {
        let mut array = array
            .iter()
            .map(|obj| obj.as_reference())
            .collect::<lopdf::Result<Vec<ObjectId>>>()?;
        array.sort();
        Ok(array)
    }

    let prev_refs = prev_refs.map_or([].as_slice(), |prev_refs| prev_refs);
    let prev_refs = sort_array(prev_refs)?;
    let curr_refs = sort_array(curr_refs)?;

    let mut prev_iter = prev_refs.into_iter().peekable();
    let mut curr_iter = curr_refs.into_iter().peekable();

    while let (Some(prev), Some(curr)) = (prev_iter.peek(), curr_iter.peek()) {
        if prev != curr {
            break;
        }
        prev_iter.next();
        curr_iter.next();
    }

    let odd_one_out = match (prev_iter.peek(), curr_iter.next()) {
        (None, None) => None,
        (_, odd_one_out) => odd_one_out,
    };

    if curr_iter.eq(prev_iter) {
        return Err(Error::NotSingleArrayIncrement);
    }

    Ok(odd_one_out)
}

fn verify_pages(
    curr_doc: &Document,
    prev_doc: &DocTracker,
    pages: &Dictionary,
) -> Result<Option<ObjectId>> {
    let mut extra_annotation = None;

    let kids = pages.get_deref(b"Kids", curr_doc)?.as_array()?;
    for page in kids {
        // Ensure the page is a reference.
        page.as_reference()?;

        if let Some(extra) = verify_page(
            curr_doc,
            curr_doc.dereference(page)?.1.as_dict()?,
            prev_doc.deref_dict(page)?,
        )? {
            if extra_annotation.is_some() {
                return Err(Error::MultiplePagesChanged);
            }
            extra_annotation = Some(extra);
        }
    }

    Ok(extra_annotation)
}

fn verify_page(
    curr_doc: &Document,
    curr_page: &Dictionary,
    prev_page: DictTracker,
) -> Result<Option<ObjectId>> {
    let mut extra_annotation = None;

    for (key, obj) in prev_page.dict.iter() {
        if key == b"Annots" {
            let curr_annots = curr_page.get_deref(b"Annots", curr_doc)?.as_array()?;
            let prev_annots = prev_page.tracker.deref(obj)?.as_array()?;

            if let Some(annot) = has_array_one_extra_ref(curr_annots, Some(prev_annots))? {
                if extra_annotation.is_some() {
                    return Err(Error::PageMismatch);
                }
                extra_annotation = Some(annot);
            }
        }

        let curr_obj = curr_page.get(key)?;
        if curr_obj != obj {
            return Err(Error::PageMismatch);
        }
    }

    if curr_page.len() != prev_page.dict.len() {
        return Err(Error::PageMismatch);
    }

    Ok(extra_annotation)
}

fn verify_sig_annotation(
    curr_sig: &Signature,
    curr_doc: &Document,
    sig_id: ObjectId,
) -> Result<()> {
    todo!()
}
