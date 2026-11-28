use std::{env, fs, path::Path};

fn copy_modules(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_modules(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn main() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/shoes/src/rustls_config_util");
    let out = std::path::PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", root.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.with_extension("rs").display()
    );
    // External #[path] on foo.rs changes nested-module lookup. Rehouse the
    // unmodified production file as foo/mod.rs with its actual child modules.
    copy_modules(&root, &out.join("rustls_config_util"));
    fs::copy(
        root.with_extension("rs"),
        out.join("rustls_config_util/mod.rs"),
    )
    .unwrap();
    fs::write(
        out.join("production.rs"),
        format!(
            "#[path = {:?}] mod rustls_config_util;\n",
            out.join("rustls_config_util/mod.rs"),
        ),
    )
    .unwrap();
}
