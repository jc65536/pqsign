use std::path::Path;
use std::process::Command;

const OBJS: [&str; 10] = [
    "codec.o", "common.o", "falcon.o", "fft.o", "fpr.o", "keygen.o", "rng.o", "shake.o", "sign.o",
    "vrfy.o",
];

fn main() {
    let falcon_path = Path::new("falcon");

    if !falcon_path.exists() {
        panic!(
            "Falcon path not found. Download Falcon and extract into a directory called `falcon`."
        );
    }

    println!("cargo::rerun-if-changed={}", falcon_path.display());

    Command::new("make")
        .current_dir(falcon_path)
        .status()
        .unwrap_or_else(|e| panic!("Error building Falcon: {e}"));

    Command::new("ar")
        .arg("rcs")
        .arg("libfalcon.a")
        .args(OBJS)
        .current_dir(falcon_path)
        .status()
        .unwrap_or_else(|e| panic!("Error creating static library: {e}"));

    println!("cargo::rustc-link-search={}", falcon_path.display());

    println!("cargo::rustc-link-lib=falcon");
}
