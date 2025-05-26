use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("sha256.txt");
    fs::copy("circuit/sha256.txt", &dest_path).unwrap();
    println!("cargo:rerun-if-changed=circuit/sha256.txt");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("aes256.txt");
    fs::copy("circuit/aes256.txt", &dest_path).unwrap();
    println!("cargo:rerun-if-changed=circuit/aes256.txt");
}
