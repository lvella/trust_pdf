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

impl super::Pkcs7Verifier for OpenSslVerifier {
    type Return = Pkcs7;

    fn verify(&self, pkcs7_der: &[u8], signed_data: Vec<u8>) -> anyhow::Result<Self::Return> {
        let pkcs7 = Pkcs7::from_der(pkcs7_der)?;
        pkcs7.verify(
            &self.intermediaries,
            &self.ca_store,
            Some(&signed_data),
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
    use super::OpenSslVerifier;

    fn create_validator() -> OpenSslVerifier {
        todo!()
    }

    #[test]
    fn test_valid_pdfs() {
        todo!()
    }

    #[test]
    fn test_invalid_pdfs() {
        todo!()
    }
}

pub struct CaBundle(X509Store);

impl CaBundle {
    pub fn load() -> Self {
        // TODO: somehow configure where the trusted CAs are stored
        let certs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("trusted-CAs");
        let mut builder = X509StoreBuilder::new().unwrap();

        // Load every certificate in the trusted CAs directory
        for entry in std::fs::read_dir(certs_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let cert = X509::from_pem(&std::fs::read(&path).unwrap()).unwrap();
            builder.add_cert(cert).unwrap();
        }

        Self(builder.build())
    }
}
