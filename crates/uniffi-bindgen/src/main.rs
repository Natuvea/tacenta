//! The bindgen entrypoint: `cargo run -p tacenta-uniffi-bindgen -- generate ...`
//! produces the Swift / Kotlin sources from the built tacenta-ffi library.
fn main() {
    uniffi::uniffi_bindgen_main()
}
