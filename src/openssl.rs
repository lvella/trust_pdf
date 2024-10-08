//! Optional OpenSSL module for signature verification.
//!
//! This module provides an OpneSSL-based implementation of the signature
//! verifier. See [`OpenSslVerifier`]. It is enabled by the `openssl` feature.

use std::path::Path;

use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::{
    store::{X509Store, X509StoreBuilder},
    X509,
};

/// OpenSSL implementation of the signature verifier.
pub struct OpenSslVerifier {
    ca_store: X509Store,
    intermediaries: Stack<X509>,
}

impl OpenSslVerifier {
    /// Creates a new verifier with the given CA store and a set of untrusted
    /// intermediary certificates that might be needed in the verification.
    pub fn new(ca_store: X509Store, intermediaries: Stack<X509>) -> Self {
        Self {
            ca_store,
            intermediaries,
        }
    }
}

impl OpenSslVerifier {
    /// Verifies a PKCS #7 signature using OpenSSL.
    ///
    /// Returns the parsed PKCS #7 structure if the signature is valid, which
    /// contains the signers certificates and other information that might be
    /// of interest.
    pub fn verify(&self, pkcs7_ber: &[u8], signed_data: [&[u8]; 2]) -> anyhow::Result<Pkcs7> {
        // Unfortunately OpenSSL requires a contiguous array of bytes to verify
        // the signature, so we must allocate and copy the slices.
        let mut contiguous = Vec::with_capacity(signed_data[0].len() + signed_data[1].len());
        contiguous.extend_from_slice(signed_data[0]);
        contiguous.extend_from_slice(signed_data[1]);

        let pkcs7 = Pkcs7::from_der(pkcs7_ber)?;
        pkcs7.verify(
            &self.intermediaries,
            &self.ca_store,
            Some(&contiguous),
            None,
            Pkcs7Flags::empty(),
        )?;

        Ok(pkcs7)
    }

    /// Verifies multiple signatures from a validated PDF file.
    pub fn verify_many(
        &self,
        full_pdf: &[u8],
        signatures: &[crate::SignatureInfo],
    ) -> anyhow::Result<Vec<Pkcs7>> {
        signatures
            .iter()
            .map(|sig| {
                let signed_slices = sig.signed_byte_ranges.clone().map(|r| &full_pdf[r]);
                self.verify(&sig.pkcs7_ber, signed_slices)
            })
            .collect()
    }
}

/// Loads CA certificates from a directory containing PEM files.
pub fn load_ca_bundle_from_dir<P: AsRef<Path>>(dir: P) -> Result<X509StoreBuilder, anyhow::Error> {
    let mut builder = X509StoreBuilder::new()?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let cert = X509::from_pem(&std::fs::read(&path)?)?;
        builder.add_cert(cert)?;
    }

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use crate::SignatureInfo;

    use super::OpenSslVerifier;

    use openssl::stack::Stack;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    fn create_signature_verifier() -> OpenSslVerifier {
        let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data/trusted_CAs");

        // Stop verification at the first trusted certificate
        let mut builder = super::load_ca_bundle_from_dir(certs_dir).unwrap();
        builder
            .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
            .unwrap();
        let ca_store = builder.build();

        let intermediaries = Stack::new().unwrap();
        OpenSslVerifier::new(ca_store, intermediaries)
    }

    fn verify(
        verifier: &OpenSslVerifier,
        reference: &[u8],
        pdf_file_name: PathBuf,
    ) -> Vec<SignatureInfo> {
        let signed = fs::read(pdf_file_name).unwrap();
        let result = crate::verify_from_reference(reference, &signed).unwrap();
        verifier.verify_many(&signed, &result).unwrap();
        for res in &result {
            if let Some(annot) = res.annotation.as_ref() {
                assert_eq!(annot.page_idx, 0);
                println!("Signature box {:?}", annot.rect);
            }
        }
        result
    }

    #[test]
    fn test_valid_pdfs() {
        let verifier = create_signature_verifier();
        let pdfs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data/valid_modification");
        let unsigned = fs::read(pdfs_dir.join("unsigned.pdf")).unwrap();

        let result = verify(&verifier, &unsigned, pdfs_dir.join("signed-visible.pdf"));
        assert_eq!(result.len(), 1);
        assert!(result[0].annotation.is_some());

        let result = verify(
            &verifier,
            &unsigned,
            pdfs_dir.join("signed-visible-twice.pdf"),
        );
        assert_eq!(result.len(), 2);
        for res in &result {
            assert!(res.annotation.is_some());
        }

        let result = verify(&verifier, &unsigned, pdfs_dir.join("signed-invisible.pdf"));
        assert_eq!(result.len(), 1);
        assert!(result[0].annotation.is_none());
    }

    #[test]
    fn test_poppler_signature() {
        let verifier = create_signature_verifier();
        let pdfs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data/poppler");
        let unsigned = fs::read(pdfs_dir.join("unsigned.pdf")).unwrap();

        let result = verify(&verifier, &unsigned, pdfs_dir.join("signed.pdf"));
        assert_eq!(result.len(), 9);
    }

    #[test]
    fn test_invalid_pdfs() {
        let verifier = create_signature_verifier();
        let pdfs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data/invalid_modification");
        let unsigned = fs::read(pdfs_dir.join("unsigned.pdf")).unwrap();

        let result = verify(&verifier, &unsigned, pdfs_dir.join("valid_signed.pdf"));
        assert_eq!(result.len(), 1);
        assert!(result[0].annotation.is_some());

        let invalid = fs::read(pdfs_dir.join("invalid_signed.pdf")).unwrap();
        let err = crate::verify_from_reference(unsigned, invalid)
            .err()
            .unwrap();
        println!("Difference detected: {err}");
    }
}
