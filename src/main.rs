mod verify_pdf;

fn main() {
    for file in ["sample/unsigned.pdf", "sample/signed-visible.pdf", "sample/signed-invisible.pdf"] {
        println!("processing {}", file);
        let pdf_bytes = std::fs::read(file).unwrap();
        verify_pdf::extract_valid_signatures(&pdf_bytes);
    }
}
