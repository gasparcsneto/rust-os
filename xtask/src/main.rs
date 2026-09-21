//! Build system do projeto.
//!
//! Segue o padrão `xtask` da comunidade Rust: em vez de Makefile ou scripts
//! shell, as tarefas de build são um binário Rust comum. Isso dá tipos,
//! portabilidade e o mesmo toolchain do resto do projeto.
//!
//! Comandos disponíveis:
//!
//! ```text
//! cargo xtask build          # compila o kernel e gera as imagens de disco
//! cargo xtask run            # build + sobe no QEMU (saída na serial)
//! cargo xtask test           # roda a suíte de testes do kernel dentro do QEMU
//! ```
//!
//! Aceita `--release` em qualquer um deles.

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

/// Porta de I/O do `isa-debug-exit`. Precisa casar com `kernel/src/qemu.rs`.
const EXIT_IOBASE: &str = "0xf4";

/// Código com que o QEMU sai quando o kernel reporta sucesso.
///
/// O kernel escreve `0x10`; o QEMU transforma em `(0x10 << 1) | 1` = 33.
const QEMU_SUCCESS: i32 = 33;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let release = args.iter().any(|a| a == "--release");
    let comando = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(String::as_str)
        .unwrap_or("help");

    let resultado = match comando {
        "build" => build(release).map(|_| ExitCode::SUCCESS),
        "run" => run(release),
        "test" => test(release),
        "help" | "-h" | "--help" => {
            ajuda();
            Ok(ExitCode::SUCCESS)
        }
        outro => Err(format!(
            "comando desconhecido: `{outro}` (use `cargo xtask help`)"
        )),
    };

    match resultado {
        Ok(code) => code,
        Err(erro) => {
            eprintln!("\nerro: {erro}");
            ExitCode::FAILURE
        }
    }
}

fn ajuda() {
    println!(
        "\
build system do kernel

USO:
    cargo xtask <comando> [--release]

COMANDOS:
    build    compila o kernel e gera as imagens BIOS e UEFI
    run      compila e executa no QEMU, com a serial ligada ao terminal
    test     executa a suíte de testes do kernel dentro do QEMU
    help     mostra esta mensagem"
    );
}

/// Raiz do repositório.
///
/// `CARGO_MANIFEST_DIR` aponta para `xtask/` em tempo de compilação; o pai é a
/// raiz. Isso torna o xtask independente do diretório de onde foi invocado.
fn raiz_do_projeto() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ sempre tem um diretório pai")
        .to_path_buf()
}

/// Imagens geradas por [`build`].
struct Imagens {
    bios: PathBuf,
    #[allow(dead_code, reason = "usado quando adicionarmos boot UEFI ao `run`")]
    uefi: PathBuf,
}

/// Compila o kernel e empacota as imagens de disco bootáveis.
fn build(release: bool) -> Result<Imagens, String> {
    let raiz = raiz_do_projeto();
    let dir_kernel = raiz.join("kernel");

    let perfil = if release { "release" } else { "debug" };
    println!("[xtask] compilando o kernel ({perfil})...");

    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .current_dir(&dir_kernel)
        .args(["build", "--target", "x86_64-unknown-none"]);
    if release {
        cargo.arg("--release");
    }

    // O cargo exporta variáveis que descrevem o build *do xtask*. Se elas
    // vazarem para o processo filho, o build do kernel herda o target e o
    // diretório de saída errados. Limpar é obrigatório.
    for var in ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS", "CARGO_TARGET_DIR"] {
        cargo.env_remove(var);
    }

    let status = cargo
        .status()
        .map_err(|e| format!("não foi possível invocar o cargo: {e}"))?;
    if !status.success() {
        return Err("a compilação do kernel falhou".into());
    }

    let elf = dir_kernel
        .join("target")
        .join("x86_64-unknown-none")
        .join(perfil)
        .join("kernel");
    if !elf.exists() {
        return Err(format!(
            "o cargo reportou sucesso mas o binário não apareceu em {}",
            elf.display()
        ));
    }

    let saida = raiz.join("target").join("imagens");
    std::fs::create_dir_all(&saida)
        .map_err(|e| format!("não foi possível criar {}: {e}", saida.display()))?;

    // Geramos as duas variantes porque elas bootam por caminhos diferentes:
    // a imagem BIOS usa o boot legado por MBR (o QEMU roda sem firmware
    // extra), e a UEFI é o que máquinas modernas de verdade usam.
    let bios = saida.join("os-bios.img");
    println!("[xtask] gerando imagem BIOS -> {}", bios.display());
    bootloader::BiosBoot::new(&elf)
        .create_disk_image(&bios)
        .map_err(|e| format!("falha ao gerar a imagem BIOS: {e}"))?;

    let uefi = saida.join("os-uefi.img");
    println!("[xtask] gerando imagem UEFI -> {}", uefi.display());
    bootloader::UefiBoot::new(&elf)
        .create_disk_image(&uefi)
        .map_err(|e| format!("falha ao gerar a imagem UEFI: {e}"))?;

    Ok(Imagens { bios, uefi })
}

/// Argumentos base do QEMU, compartilhados por `run` e `test`.
fn qemu_base(imagem: &Path) -> Command {
    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.args([
        "-drive",
        &format!("format=raw,file={}", imagem.display()),
        // 128 MiB é folgado para a fase 0 e mantém o boot rápido.
        "-m",
        "128M",
        // Liga a serial do kernel ao stdout do host: é assim que vemos a
        // saída do kernel e, mais adiante, como o agente conversa com ele.
        "-serial",
        "stdio",
        // Sem janela gráfica: este ambiente é headless, e toda a informação
        // que nos importa já sai pela serial.
        "-display",
        "none",
        // O dispositivo que permite ao kernel encerrar o QEMU (ver qemu.rs).
        "-device",
        &format!("isa-debug-exit,iobase={EXIT_IOBASE},iosize=0x04"),
    ]);
    qemu
}

fn run(release: bool) -> Result<ExitCode, String> {
    let imagens = build(release)?;
    println!("[xtask] iniciando o QEMU (ctrl-a x para sair)\n");

    let status = qemu_base(&imagens.bios)
        .status()
        .map_err(|e| format!("não foi possível iniciar o qemu-system-x86_64: {e}"))?;

    // `hlt_loop` nunca retorna, então a saída normal aqui é o usuário matar o
    // QEMU. Qualquer código é aceitável; só repassamos.
    Ok(match status.code() {
        Some(QEMU_SUCCESS) | Some(0) | None => ExitCode::SUCCESS,
        Some(_) => ExitCode::SUCCESS,
    })
}

fn test(release: bool) -> Result<ExitCode, String> {
    let imagens = build(release)?;
    println!("[xtask] executando a suíte de testes no QEMU\n");

    let status = qemu_base(&imagens.bios)
        .status()
        .map_err(|e| format!("não foi possível iniciar o qemu-system-x86_64: {e}"))?;

    match status.code() {
        Some(QEMU_SUCCESS) => {
            println!("\n[xtask] todos os testes passaram");
            Ok(ExitCode::SUCCESS)
        }
        Some(code) => {
            eprintln!("\n[xtask] os testes falharam (qemu saiu com {code})");
            Ok(ExitCode::FAILURE)
        }
        None => Err("o QEMU foi terminado por um sinal".into()),
    }
}
