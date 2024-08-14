use std::ops::Deref;
use std::path::Path;

use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509NameEntryRef, X509NameRef, X509};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("openssl error")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("unexpected distinguished name format")]
    WrongDistinguished,
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

#[derive(Debug)]
pub struct SignerInfo {
    pub name: String,
    // TODO: put all the relevant information here
}

pub struct Signature(Pkcs7);

impl Signature {
    pub fn new(pkcs7_der_signature: &[u8]) -> Result<Signature, Error> {
        let pkcs7 = Pkcs7::from_der(pkcs7_der_signature)?;
        Ok(Signature(pkcs7))
    }

    pub fn get_signers_info(&self) -> Result<Vec<SignerInfo>, Error> {
        let empty_stack = Stack::new()?;
        let signers = self.0.signers(&empty_stack, Pkcs7Flags::empty())?;

        let signers_info = signers
            .iter()
            .map(|signer| {
                let dn = signer.subject_name();
                let cn = get_only_entry(dn, Nid::COMMONNAME)?;
                Ok(SignerInfo {
                    name: cn.data().as_utf8()?.to_string(),
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(signers_info)
    }

    pub fn verify(&self, signed_data: &[u8], ca_bundle: &CaBundle) -> Result<(), Error> {
        let empty_stack = Stack::new()?;
        let mut output = Vec::new();
        self.0.verify(
            &empty_stack,
            &ca_bundle.0,
            Some(signed_data),
            Some(&mut output),
            Pkcs7Flags::empty(),
        )?;
        Ok(())
    }
}

/// Errors out if there is not exactly one entry with the given NID in the
/// distinguished name.
fn get_only_entry(name: &X509NameRef, nid: Nid) -> Result<&X509NameEntryRef, Error> {
    let mut entries = name.entries_by_nid(nid);
    match (entries.next(), entries.next()) {
        (Some(entry), None) => Ok(entry),
        _ => Err(Error::WrongDistinguished),
    }
}

fn print_certificate_info(certificate: &X509) {
    // Extract and print basic information from the certificate
    let subject_name = certificate.subject_name();
    let issuer_name = certificate.issuer_name();

    println!("Certificate:");
    println!(
        "  Subject: {}",
        subject_name
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
    );
    println!(
        "  Issuer: {}",
        issuer_name
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
    );

    // Extract and print the certificate's serial number
    let serial_number = certificate.serial_number();
    println!(
        "  Serial Number: {}",
        serial_number.to_bn().unwrap().to_hex_str().unwrap()
    );

    // Extract and print the signature algorithm
    let signature_algorithm = certificate.signature_algorithm();
    println!(
        "  Signature Algorithm: {:?}",
        signature_algorithm.object().nid()
    );
}
