//! Build system do projeto.
//!
//! Segue o padrão `xtask` da comunidade Rust: em vez de Makefile ou scripts
//! shell, as tarefas de build são um binário Rust comum. Isso dá tipos,
//! portabilidade e o mesmo toolchain do resto do projeto.
//!
//! ```text
//! cargo xtask build                       # compila o kernel e gera as imagens
//! cargo xtask run                         # sobe no QEMU (serial no terminal)
//! cargo xtask test                        # roda a suíte de testes no QEMU
//! cargo xtask agent <metodo> [params]     # fala JSON-RPC com o kernel
//! ```
//!
//! Aceita `--release` em qualquer um deles.

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Duration,
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
    let posicionais: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();

    let comando = posicionais.first().copied().unwrap_or("help");

    let resultado = match comando {
        "build" => build(release).map(|_| ExitCode::SUCCESS),
        "run" => run(release),
        "test" => test(release),
        "agent" => {
            let metodo = posicionais.get(1).copied().unwrap_or("agent.describe");
            let params = posicionais.get(2).copied().unwrap_or("{}");
            agente(metodo, params)
        }
        "help" | "-h" => {
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
    build                     compila o kernel e gera as imagens BIOS e UEFI
    run                       compila e executa no QEMU, com a serial no terminal
    test                      executa a suíte de testes do kernel dentro do QEMU
    agent <metodo> [params]   envia uma chamada JSON-RPC ao kernel em execução
    help                      mostra esta mensagem

EXEMPLOS:
    cargo xtask agent agent.describe
    cargo xtask agent system.info
    cargo xtask agent log.tail '{{\"count\":5,\"min_level\":\"info\"}}'"
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

/// Onde o canal do agente (COM2) é exposto no host.
fn caminho_socket() -> PathBuf {
    raiz_do_projeto().join("target").join("agent.sock")
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

/// Monta a linha de comando do QEMU.
///
/// A ordem das opções `-serial` é significativa: a primeira vira a COM1 e a
/// segunda a COM2. O kernel conta com exatamente esse mapeamento — COM1 para
/// o console humano, COM2 para o canal do agente.
fn qemu_base(imagem: &Path, socket_agente: Option<&Path>) -> Result<Command, String> {
    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.args([
        "-drive",
        &format!("format=raw,file={}", imagem.display()),
        // 128 MiB é folgado para a fase 0 e mantém o boot rápido.
        "-m",
        "128M",
        // COM1 -> stdout do host.
        "-serial",
        "stdio",
    ]);

    if let Some(socket) = socket_agente {
        // Um socket obsoleto de uma execução anterior faria o QEMU falhar ao
        // tentar criar o novo.
        let _ = std::fs::remove_file(socket);

        qemu.args([
            "-chardev",
            // `server=on` faz o QEMU escutar; `wait=off` o impede de travar o
            // boot esperando um cliente conectar. O kernel precisa subir mesmo
            // quando ninguém está falando com ele.
            &format!(
                "socket,id=canal-agente,path={},server=on,wait=off",
                socket.display()
            ),
            // COM2 -> o socket acima.
            "-serial",
            "chardev:canal-agente",
        ]);
    }

    qemu.args([
        // Sem janela gráfica: este ambiente é headless, e toda a informação
        // que nos importa já sai pelas seriais.
        "-display",
        "none",
        // O dispositivo que permite ao kernel encerrar o QEMU (ver qemu.rs).
        "-device",
        &format!("isa-debug-exit,iobase={EXIT_IOBASE},iosize=0x04"),
    ]);

    Ok(qemu)
}

fn run(release: bool) -> Result<ExitCode, String> {
    let imagens = build(release)?;
    let socket = caminho_socket();

    println!("[xtask] canal do agente em {}", socket.display());
    println!("[xtask] fale com o kernel de outro terminal:");
    println!("[xtask]     cargo xtask agent agent.describe\n");

    qemu_base(&imagens.bios, Some(&socket))?
        .status()
        .map_err(|e| format!("não foi possível iniciar o qemu-system-x86_64: {e}"))?;

    Ok(ExitCode::SUCCESS)
}

fn test(release: bool) -> Result<ExitCode, String> {
    let imagens = build(release)?;
    println!("[xtask] executando a suíte de testes no QEMU\n");

    let status = qemu_base(&imagens.bios, None)?
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

/// Cliente do canal do agente.
///
/// Conecta no socket Unix onde a COM2 do kernel está exposta, envia uma
/// requisição JSON-RPC e imprime a resposta. É o comando que torna o kernel
/// operável de fora com uma única linha de shell.
fn agente(metodo: &str, params: &str) -> Result<ExitCode, String> {
    let socket = caminho_socket();

    let mut fluxo = UnixStream::connect(&socket).map_err(|e| {
        format!(
            "não foi possível conectar em {}: {e}\n\
             dica: o kernel precisa estar rodando — inicie `cargo xtask run` em outro terminal",
            socket.display()
        )
    })?;

    // Sem timeout, um kernel travado deixaria o cliente pendurado para sempre.
    // Falhar em cinco segundos é muito mais útil do que não falhar nunca.
    fluxo
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("não foi possível configurar o timeout: {e}"))?;

    let requisicao =
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{metodo}\",\"params\":{params}}}\n");

    fluxo
        .write_all(requisicao.as_bytes())
        .and_then(|()| fluxo.flush())
        .map_err(|e| format!("falha ao enviar a requisição: {e}"))?;

    let mut leitor = BufReader::new(fluxo);
    let mut resposta = String::new();
    let lidos = leitor
        .read_line(&mut resposta)
        .map_err(|e| format!("falha ao ler a resposta: {e}"))?;

    if lidos == 0 {
        return Err("o kernel fechou o canal sem responder".into());
    }

    print!("{resposta}");
    Ok(ExitCode::SUCCESS)
}
