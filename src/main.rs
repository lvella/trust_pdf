mod validate_signature;
mod verify_pdf;

fn main() {
    // Load CA bundle only once and reuse
    let ca_bundle = validate_signature::CaBundle::load();

    let reference = std::fs::read("sample/unsigned.pdf").unwrap();

    for file in [
        "sample/signed-visible.pdf",
        "sample/signed-visible-twice.pdf",
        "sample/signed-invisible.pdf",
    ] {
        println!("processing {}", file);
        let pdf_bytes = std::fs::read(file).unwrap();

        // TODO: check if the signature box is inside the allowed area
        let result = verify_pdf::verify_from_reference(&reference, &pdf_bytes, &ca_bundle);
        eprintln!("{:?}", result);
    }
}
