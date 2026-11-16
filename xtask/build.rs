//! O commit do rustc que compila o `xtask`, para a conferência do
//! compilador (`src/compilador.rs`): um `xtask` compilado por outro rustc —
//! um `cargo --config build.rustc=...`, um binário de outro toolchain rodado
//! direto — é um desvio, e a execução não é oficial.

use std::process::Command;

fn main() {
    // O cargo passa ao build script o rustc que compila o pacote.
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let commit = Command::new(&rustc)
        .arg("-vV")
        .output()
        .ok()
        .filter(|s| s.status.success())
        .and_then(|s| {
            String::from_utf8_lossy(&s.stdout)
                .lines()
                .find_map(|l| l.strip_prefix("commit-hash:"))
                .map(|c| c.trim().to_string())
        })
        .unwrap_or_else(|| String::from("desconhecido"));
    println!("cargo:rustc-env=XTASK_RUSTC_COMMIT={commit}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");
}
