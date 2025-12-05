use blake3;
use std::{env, fs, path::Path};

fn main() {
    // TODO: Compute and write the binary hash and validate
    let out = env::var("OUT_DIR").unwrap();
    let hash_file = Path::new(&out).join("binary_hash.txt");
    fs::write(&hash_file, "UNHASHED\n").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
