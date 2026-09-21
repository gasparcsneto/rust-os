//! Build system do projeto.
//!
//! Segue o padrão `xtask` da comunidade Rust: em vez de Makefile ou scripts
//! shell, as tarefas de build são um binário Rust comum. Isso dá tipos,
//! portabilidade e o mesmo toolchain do resto do projeto.
//!
//! ```text
//! cargo xtask build [--arch A]                   # compila
//! cargo xtask run   [--arch A]                   # sobe no QEMU
//! cargo xtask test  [--arch A]                   # suíte de testes no QEMU
//! cargo xtask agent [--arch A] <metodo> [params] # fala JSON-RPC com o kernel
//! ```
//!
//! `A` é `x86_64` (padrão) ou `aarch64`. Aceita também `--release`.

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Duration,
};

/// As arquiteturas que o kernel suporta.
///
/// As duas diferem em quase tudo no caminho de boot — daí este enum carregar
/// não só o alvo do Rust, mas também como a imagem é produzida e como o QEMU
/// é invocado.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arquitetura {
    X86_64,
    Aarch64,
}

impl Arquitetura {
    fn de_nome(nome: &str) -> Result<Self, String> {
        match nome {
            "x86_64" | "x86-64" | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" | "arm" => Ok(Self::Aarch64),
            outro => Err(format!(
                "arquitetura desconhecida: `{outro}` (use x86_64 ou aarch64)"
            )),
        }
    }

    fn nome(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// O alvo do Rust.
    ///
    /// No ARM usamos a variante `-softfloat`, que proíbe o compilador de
    /// emitir instruções de ponto flutuante e NEON. Num kernel isso é
    /// desejável: usar esses registradores em EL1 sem antes habilitar o acesso
    /// gera uma exceção difícil de rastrear.
    fn alvo(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-none",
            Self::Aarch64 => "aarch64-unknown-none-softfloat",
        }
    }

    fn qemu(self) -> &'static str {
        match self {
            Self::X86_64 => "qemu-system-x86_64",
            Self::Aarch64 => "qemu-system-aarch64",
        }
    }

    /// Código com que o QEMU sai quando o kernel reporta sucesso.
    ///
    /// No x86 o kernel escreve `0x10` no `isa-debug-exit` e o QEMU transforma
    /// em `(0x10 << 1) | 1` = 33. No ARM o encerramento é por semihosting, que
    /// repassa o código literalmente — então sucesso é 0.
    fn codigo_de_sucesso(self) -> i32 {
        match self {
            Self::X86_64 => 33,
            Self::Aarch64 => 0,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let arch = match extrair_arch(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("erro: {e}");
            return ExitCode::FAILURE;
        }
    };
    let release = args.iter().any(|a| a == "--release");

    // Posicionais: tudo que não é flag nem valor de flag.
    let mut posicionais: Vec<&str> = Vec::new();
    let mut pular = false;
    for a in &args {
        if pular {
            pular = false;
            continue;
        }
        if a == "--arch" {
            pular = true;
        } else if !a.starts_with("--") {
            posicionais.push(a);
        }
    }

    let comando = posicionais.first().copied().unwrap_or("help");

    let resultado = match comando {
        "build" => build(arch, release).map(|_| ExitCode::SUCCESS),
        "run" => run(arch, release),
        "test" => test(arch, release),
        "agent" => {
            let metodo = posicionais.get(1).copied().unwrap_or("agent.describe");
            let params = posicionais.get(2).copied().unwrap_or("{}");
            agente(arch, metodo, params)
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

fn extrair_arch(args: &[String]) -> Result<Arquitetura, String> {
    let mut i = 0;
    while i < args.len() {
        if let Some(valor) = args[i].strip_prefix("--arch=") {
            return Arquitetura::de_nome(valor);
        }
        if args[i] == "--arch" {
            let valor = args
                .get(i + 1)
                .ok_or_else(|| "--arch precisa de um valor".to_string())?;
            return Arquitetura::de_nome(valor);
        }
        i += 1;
    }
    Ok(Arquitetura::X86_64)
}

fn ajuda() {
    println!(
        "\
build system do kernel

USO:
    cargo xtask <comando> [--arch x86_64|aarch64] [--release]

COMANDOS:
    build                     compila o kernel (e gera as imagens, no x86)
    run                       executa no QEMU com o canal do agente ativo
    test                      executa a suíte de testes dentro do QEMU
    agent <metodo> [params]   envia uma chamada JSON-RPC ao kernel em execução
    help                      mostra esta mensagem

EXEMPLOS:
    cargo xtask run
    cargo xtask run --arch aarch64
    cargo xtask agent system.info
    cargo xtask agent --arch aarch64 agent.describe
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

/// Onde o canal do agente é exposto no host.
///
/// Um socket por arquitetura, para que dá para ter um kernel x86 e um ARM
/// rodando lado a lado sem que um sobrescreva o canal do outro.
fn caminho_socket(arch: Arquitetura) -> PathBuf {
    raiz_do_projeto()
        .join("target")
        .join(format!("agent-{}.sock", arch.nome()))
}

/// O que o build produziu e o QEMU precisa carregar.
enum Artefato {
    /// x86: uma imagem de disco bootável por BIOS (e outra por UEFI).
    ImagemDeDisco { bios: PathBuf, _uefi: PathBuf },
    /// ARM: uma imagem binária crua com cabeçalho arm64.
    ///
    /// Não há imagem de disco porque não há bootloader. Em vez disso seguimos
    /// o protocolo de boot do arm64: um binário cru cujos primeiros 64 bytes
    /// são um cabeçalho que diz a quem carrega onde depositá-lo e quanta RAM
    /// reservar. Em troca, recebemos o endereço do device tree em `x0` — que
    /// é o que o QEMU *não* faz quando lhe entregamos um ELF.
    Binario(PathBuf),
}

/// Compila o kernel e prepara o que o QEMU vai carregar.
fn build(arch: Arquitetura, release: bool) -> Result<Artefato, String> {
    let raiz = raiz_do_projeto();
    let dir_kernel = raiz.join("kernel");

    let perfil = if release { "release" } else { "debug" };
    println!("[xtask] compilando o kernel ({}, {perfil})...", arch.nome());

    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .current_dir(&dir_kernel)
        .args(["build", "--target", arch.alvo()]);
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
        .join(arch.alvo())
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

    match arch {
        Arquitetura::Aarch64 => {
            // O ELF carrega metadados que o protocolo de boot do arm64 não
            // entende. `objcopy -O binary` extrai apenas os bytes que vão para
            // a memória, na ordem em que vão — que é exatamente o que um
            // carregador de imagem crua espera.
            let img = saida.join("kernel-arm64.img");
            println!("[xtask] gerando imagem arm64 -> {}", img.display());

            let objcopy = localizar_objcopy()?;
            let status = Command::new(&objcopy)
                .args(["-O", "binary"])
                .arg(&elf)
                .arg(&img)
                .status()
                .map_err(|e| format!("não foi possível executar {}: {e}", objcopy.display()))?;
            if !status.success() {
                return Err("objcopy falhou ao gerar a imagem arm64".into());
            }

            Ok(Artefato::Binario(img))
        }

        Arquitetura::X86_64 => {

            // Geramos as duas variantes porque elas bootam por caminhos
            // diferentes: a imagem BIOS usa o boot legado por MBR (o QEMU roda
            // sem firmware extra) e a UEFI é o que máquinas modernas usam.
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

            Ok(Artefato::ImagemDeDisco { bios, _uefi: uefi })
        }
    }
}

/// Encontra o `llvm-objcopy` que acompanha o toolchain Rust.
///
/// Preferimos este ao `objcopy` do sistema porque o do sistema costuma ser
/// compilado só para a arquitetura do host e não sabe ler um ELF aarch64. O
/// do LLVM lida com todos os alvos que o próprio rustc sabe gerar — ele vem
/// no componente `llvm-tools`, declarado no `rust-toolchain.toml`.
fn localizar_objcopy() -> Result<PathBuf, String> {
    let saida = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("não foi possível consultar o sysroot do rustc: {e}"))?;
    let sysroot = PathBuf::from(String::from_utf8_lossy(&saida.stdout).trim().to_string());

    let rustlib = sysroot.join("lib").join("rustlib");
    let entradas = std::fs::read_dir(&rustlib)
        .map_err(|e| format!("não foi possível ler {}: {e}", rustlib.display()))?;

    for entrada in entradas.flatten() {
        let candidato = entrada.path().join("bin").join("llvm-objcopy");
        if candidato.is_file() {
            return Ok(candidato);
        }
    }

    Err(format!(
        "llvm-objcopy não encontrado em {}\n\
         instale o componente com: rustup component add llvm-tools",
        rustlib.display()
    ))
}

/// Monta a linha de comando do QEMU para a arquitetura em questão.
fn comando_qemu(
    arch: Arquitetura,
    artefato: &Artefato,
    socket_agente: Option<&Path>,
) -> Result<Command, String> {
    let mut qemu = Command::new(arch.qemu());

    match (arch, artefato) {
        (Arquitetura::X86_64, Artefato::ImagemDeDisco { bios, .. }) => {
            qemu.args(["-drive", &format!("format=raw,file={}", bios.display())]);
            // O dispositivo que permite ao kernel encerrar o QEMU.
            qemu.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
        }
        (Arquitetura::Aarch64, Artefato::Binario(img)) => {
            qemu.args([
                // `virt` é a máquina genérica do QEMU para ARM: sem
                // peculiaridades de placa real, com um device tree gerado na
                // hora descrevendo tudo. É onde nosso parser de FDT trabalha.
                "-machine",
                "virt",
                "-cpu",
                "cortex-a72",
                // O QEMU lê o cabeçalho arm64 da imagem, a deposita em
                // `base_da_RAM + text_offset` e salta para lá com o endereço
                // do device tree em x0. É todo o "bootloader" que o ARM
                // precisa — o protocolo é o contrato.
                "-kernel",
                &img.display().to_string(),
                // O ARM não tem `isa-debug-exit`; o encerramento é por
                // semihosting, que precisa ser habilitado explicitamente.
                "-semihosting-config",
                "enable=on,target=native",
            ]);
        }
        _ => return Err("artefato incompatível com a arquitetura".into()),
    }

    qemu.args(["-m", "128M"]);

    // A ordem das opções `-serial` é significativa: a primeira vira a COM1 do
    // x86, a segunda a COM2. No ARM só existe a PL011, que recebe a primeira.
    match arch {
        Arquitetura::X86_64 => {
            // COM1 -> stdout do host (console humano).
            qemu.args(["-serial", "stdio"]);
            if let Some(socket) = socket_agente {
                anexar_socket(&mut qemu, socket);
            }
        }
        Arquitetura::Aarch64 => match socket_agente {
            // A única porta vai para o canal do agente.
            Some(socket) => anexar_socket(&mut qemu, socket),
            // Sem canal (modo teste), mandamos para o terminal.
            None => {
                qemu.args(["-serial", "stdio"]);
            }
        },
    }

    // Sem janela gráfica: este ambiente é headless, e toda a informação que
    // nos importa já sai pelas seriais.
    qemu.args(["-display", "none"]);

    Ok(qemu)
}

fn anexar_socket(qemu: &mut Command, socket: &Path) {
    // Um socket obsoleto de uma execução anterior faria o QEMU falhar ao
    // tentar criar o novo.
    let _ = std::fs::remove_file(socket);

    qemu.args([
        "-chardev",
        // `server=on` faz o QEMU escutar; `wait=off` o impede de travar o boot
        // esperando um cliente conectar. O kernel precisa subir mesmo quando
        // ninguém está falando com ele.
        &format!(
            "socket,id=canal-agente,path={},server=on,wait=off",
            socket.display()
        ),
        "-serial",
        "chardev:canal-agente",
    ]);
}

fn run(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release)?;
    let socket = caminho_socket(arch);

    println!("[xtask] canal do agente em {}", socket.display());
    println!("[xtask] fale com o kernel de outro terminal:");
    println!(
        "[xtask]     cargo xtask agent --arch {} agent.describe\n",
        arch.nome()
    );
    if arch == Arquitetura::Aarch64 {
        println!(
            "[xtask] nota: no ARM a única serial é o canal do agente, então não\n\
             [xtask]       há log em texto aqui. Use `log.tail` para ver os registros.\n"
        );
    }

    comando_qemu(arch, &artefato, Some(&socket))?
        .status()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    Ok(ExitCode::SUCCESS)
}

fn test(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release)?;
    println!("[xtask] executando a suíte de testes no QEMU ({})\n", arch.nome());

    let status = comando_qemu(arch, &artefato, None)?
        .status()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    match status.code() {
        Some(code) if code == arch.codigo_de_sucesso() => {
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
/// Conecta no socket Unix onde a serial do kernel está exposta, envia uma
/// requisição JSON-RPC e imprime a resposta. É o comando que torna o kernel
/// operável de fora com uma única linha de shell — e é idêntico nas duas
/// arquiteturas, porque o protocolo é o mesmo.
fn agente(arch: Arquitetura, metodo: &str, params: &str) -> Result<ExitCode, String> {
    let socket = caminho_socket(arch);

    let mut fluxo = UnixStream::connect(&socket).map_err(|e| {
        format!(
            "não foi possível conectar em {}: {e}\n\
             dica: o kernel precisa estar rodando — inicie \
             `cargo xtask run --arch {}` em outro terminal",
            socket.display(),
            arch.nome()
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
