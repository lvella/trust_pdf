use std::path::Path;

use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::{
    store::{X509Store, X509StoreBuilder},
    X509,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("openssl error")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("unexpected distinguished name format")]
    WrongDistinguished,
}

/// Verifies the signatures using OpenSSL.
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

impl super::Pkcs7Verifier for &OpenSslVerifier {
    type Return = Pkcs7;

    fn verify(&self, pkcs7_der: &[u8], signed_data: [&[u8]; 2]) -> anyhow::Result<Self::Return> {
        // Unfortunately OpenSSL requires a contiguous array of bytes to verify
        // the signature, so we must allocate and copy the slices.
        let mut contiguous = Vec::with_capacity(signed_data[0].len() + signed_data[1].len());
        contiguous.extend_from_slice(signed_data[0]);
        contiguous.extend_from_slice(signed_data[1]);

        let pkcs7 = Pkcs7::from_der(pkcs7_der)?;
        pkcs7.verify(
            &self.intermediaries,
            &self.ca_store,
            Some(&contiguous),
            None,
            Pkcs7Flags::empty(),
        )?;

        Ok(pkcs7)
    }
}

/// Loads a CA bundle from a directory containing PEM files.
pub fn load_ca_bundle_from_dir(dir: &Path) -> Result<X509Store, anyhow::Error> {
    let mut builder = X509StoreBuilder::new()?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let cert = X509::from_pem(&std::fs::read(&path)?)?;
        builder.add_cert(cert)?;
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use openssl::stack::Stack;

    use super::OpenSslVerifier;

    fn create_signature_verifier() -> OpenSslVerifier {
        let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data/trusted_CAs");

        let ca_store = super::load_ca_bundle_from_dir(&certs_dir).unwrap();
        let intermediaries = Stack::new().unwrap();
        OpenSslVerifier::new(ca_store, intermediaries)
    }

    #[test]
    fn test_valid_pdfs() {
        let verifier = create_signature_verifier();
        let pdfs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data/valid_modification");

        let unsigned = fs::read(pdfs_dir.join("unsigned.pdf")).unwrap();

        // Test visible signature
        {
            let signed_visible = fs::read(pdfs_dir.join("signed-visible.pdf")).unwrap();
            let result = crate::verify_from_reference(unsigned, signed_visible, &verifier).unwrap();
            assert_eq!(result.len(), 1);
            let annot = result[0].annotation.as_ref().unwrap();
            assert_eq!(annot.page_idx, 0);
            println!("Annotation box {:?}", annot.rect);
        }
    }

    #[test]
    fn test_invalid_pdfs() {
        todo!()
    }
}
