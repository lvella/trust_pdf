use super::Signature;
use lopdf::{xref::XrefEntry, Dictionary, Document, Object, ObjectId};
use openssl::{stack, x509::verify};
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, BTreeMap, HashMap},
    vec,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("PDF parsing error")]
    Parsing(#[from] lopdf::Error),
    #[error("mismatch between /Catalog dictionaries")]
    CatalogMismatch,
    #[error("mismatch between /AcroForm dictionaries")]
    AcroFormMismatch,
    #[error("only uncompressed xref entries are supported")]
    UnsupportedXrefEntry,
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

    fn deref(&self, mut obj: &'a Object) -> Result<&Object> {
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
            if let Some(gen) = traversed.get(id) {
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

    verify_catalogs(&curr_doc, &prev_doc_tracker)?;

    // All the indirect objects in the tracked list are allowed to be
    // different from the corresponding object in the current document.
    // All others must match.
    prev_doc_tracker.verify_all_changes_are_allowed(&curr_doc)?;

    Ok(())
}

fn verify_catalogs<'a, 'b>(curr_doc: &'a Document, previous_doc: &'b DocTracker<'b>) -> Result<()> {
    let curr_catalog = curr_doc.catalog()?;
    let prev_catalog = previous_doc.catalog()?;

    let mut prev_acro_form = None;
    let mut size_diff = 1;

    for (key, obj) in prev_catalog.dict.iter() {
        if key == b"AcroForm" {
            prev_acro_form = Some(previous_doc.deref_dict(obj)?);
            size_diff = 0;

            // AcroForm is handled separately.
            continue;
        }

        if key == b"Pages" {
            // Pages object is also handled separately.
            continue;
        }

        let curr_obj = curr_catalog.dict.get(key)?;
        if curr_obj != obj {
            return Err(Error::CatalogMismatch);
        }
    }

    // All the elements from both catalogs must have matched.
    if prev_catalog.dict.len() + size_diff != curr_catalog.dict.len() {
        return Err(Error::CatalogMismatch);
    }

    // Current catalog must have an AcroForm dictionary.
    verify_acro_forms(curr_catalog.get_dict_deref(b"AcroForm")?, prev_acro_form)?;

    // Pages object must exist in both, catalogs, too.
    verify_pages(
        curr_catalog.get_dict_deref(b"Pages")?,
        prev_catalog.get_dict_deref(b"Pages")?,
    );

    Ok(())
}

fn verify_acro_forms(
    curr_acro_form: DictTracker,
    prev_acro_form: Option<DictTracker>,
) -> Result<()> {
    let mut prev_has_da = false;
    let mut prev_has_dr = false;

    let mut prev_fields = None;

    let mut allowed_len = if let Some(prev_acro_form) = prev_acro_form {
        for (key, obj) in prev_acro_form.dict.iter() {
            if key == b"Fields" {
                // Fields are handled separately.
                prev_fields = Some(prev_acro_form.tracker.deref_array(obj)?);
                continue;
            }

            if key == b"DA" {
                prev_has_da = true;
            } else if key == b"DR" {
                prev_has_dr = true;
            }

            let curr_obj = curr_acro_form.dict.get(key)?;
            if curr_obj != obj {
                return Err(Error::AcroFormMismatch);
            }
        }
        prev_acro_form.dict.len()
    } else {
        1
    };

    let handle_extra_field = |key| {
        if let Ok(obj) = curr_acro_form.dict.get(key) {
            curr_acro_form.tracker.deep_track(obj)?;
            allowed_len += 1;
        }
    };

    if !prev_has_da {
        handle_extra_field(b"DA");
    }

    if !prev_has_dr {
        handle_extra_field(b"DR");
    }

    if curr_acro_form.dict.len() != allowed_len {
        return Err(Error::AcroFormMismatch);
    }

    // Handle the fields
    let curr_fields = curr_acro_form.get_array_deref(b"Fields")?;
    verify_fields(curr_fields, prev_fields)?;

    Ok(())
}

fn verify_pages(curr_pages: DictTracker, prev_pages: DictTracker) {
    todo!()
}
