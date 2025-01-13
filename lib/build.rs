fn main() {
    uniffi::generate_scaffolding("src/rust-cktap.udl").expect("Failed to generate FFI scaffolding");
}
