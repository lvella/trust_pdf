use super::{Error, Result, Signature};
use lopdf::{Dictionary, Document, Object, ObjectId};
use std::{cell::RefCell, collections::HashSet};

struct DocTracker<'a> {
    traversed: RefCell<HashSet<ObjectId>>,
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
            traversed: RefCell::new(HashSet::new()),
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
        let mut seen = HashSet::new();

        while let Object::Reference(id) = obj {
            if !seen.insert(*id) {
                return Err(Error::Parsing(lopdf::Error::ReferenceLimit));
            }
            obj = self.doc.get_object(*id)?;
        }

        self.traversed.borrow_mut().extend(seen);
        Ok(obj)
    }

    fn deref_dict(&self, obj: &'a Object) -> Result<DictTracker> {
        Ok(DictTracker {
            tracker: self,
            dict: self.deref(obj)?.as_dict()?,
        })
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

    let curr_doc = DocTracker::new(curr_doc);
    let previous_doc = DocTracker::new(previous_doc);

    // Everything must match in the catalog, except for the AcroForm.
    let (curr_acro_form, prev_acro_form) = verify_catalogs(&curr_doc, &previous_doc)?;

    // The AcroForm is only allowed to add a new signature in the /Fields array, and DA and DR if missing.
    // TODO: to be continued...

    Ok(())
}

fn verify_catalogs<'a, 'b>(
    curr_doc: &'a DocTracker<'a>,
    previous_doc: &'b DocTracker<'b>,
) -> Result<(DictTracker<'a>, Option<DictTracker<'b>>)> {
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

        let curr_obj = curr_catalog.dict.get(key)?;
        if curr_obj != obj {
            return Err(Error::PossibleContentChange);
        }
    }

    // Current catalog must have an AcroForm dictionary.
    let curr_acro_form = curr_catalog.get_dict_deref(b"AcroForm")?;

    // All the elements from both catalogs must have matched.
    if prev_catalog.dict.len() + size_diff != curr_catalog.dict.len() {
        return Err(Error::PossibleContentChange);
    }

    Ok((curr_acro_form, prev_acro_form))
}
