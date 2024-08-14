mod validate_signature;
mod verify_pdf;

fn main() {
    // Load CA bundle only once and reuse
    let ca_bundle = validate_signature::CaBundle::load();

    for file in [
        "sample/unsigned.pdf",
        "sample/signed-visible.pdf",
        "sample/signed-visible-twice.pdf",
        "sample/signed-invisible.pdf",
    ] {
        println!("processing {}", file);
        let pdf_bytes = std::fs::read(file).unwrap();
        let result = verify_pdf::verify_and_get_signers(&pdf_bytes, &ca_bundle);
        eprintln!("{:?}", result);
    }
}
