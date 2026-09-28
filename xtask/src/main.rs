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

use std::collections::BTreeMap;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode},
    time::{Duration, Instant},
};

/// Teto de tempo para a suíte de testes.
///
/// Um kernel tem formas demais de travar para que esperar indefinidamente seja
/// aceitável: o bootloader pode falhar e reiniciar em laço, uma exceção não
/// tratada pode causar triple fault e reboot, um teste pode entrar num laço
/// sem saída. Sem teto, qualquer um desses casos vira um job de CI pendurado
/// que não diz nada — o pior modo de falhar. Dois minutos é muito acima dos
/// poucos segundos que a suíte leva.
const TETO_DOS_TESTES: Duration = Duration::from_secs(120);

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

    /// Endereço virtual onde a imagem do kernel é carregada.
    ///
    /// É o deslocamento entre um endereço em tempo de execução e o endereço
    /// correspondente dentro do binário — o número que transforma o `pc` de
    /// uma exceção em arquivo e linha.
    ///
    /// No x86 o kernel é um executável independente de posição, ligado a
    /// partir do zero, e o iniciador o reloca para a metade alta do espaço
    /// virtual — para [`protocolo::mapa::BASE_DO_KERNEL`], que é daqui que o
    /// número sai. No ARM o script do linker já fixa os endereços finais,
    /// então não há deslocamento nenhum.
    fn base_do_kernel(self) -> u64 {
        match self {
            Self::X86_64 => protocolo::mapa::BASE_DO_KERNEL,
            Self::Aarch64 => 0,
        }
    }

    /// O depurador que consegue falar com esta arquitetura nesta máquina.
    ///
    /// O `gdb` das distribuições costuma ser compilado para um alvo só, então
    /// o do host não depura ARM (isso é o `gdb-multiarch`). O `lldb` é
    /// construído sobre o LLVM e carrega todos os alvos no mesmo binário, o
    /// que o torna a escolha portátil para a arquitetura cruzada.
    fn depurador(self) -> &'static str {
        match self {
            Self::X86_64 => "gdb",
            Self::Aarch64 => "lldb",
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
    /// repassa o código literalmente, e o kernel repassa 33 de propósito.
    ///
    /// # Por que não 0 no ARM
    ///
    /// Porque 0 é o que o QEMU devolve em toda saída limpa, e a maioria delas
    /// não é a suíte terminando: um desligamento por PSCI, um `quit` no
    /// monitor, uma máquina que morreu antes do primeiro caso. Enquanto
    /// sucesso foi 0, este `match` aprovava qualquer um deles — dava para
    /// desligar a máquina antes de rodar um único teste e ler "todos os
    /// testes passaram". Exigir um número que só um encerramento deliberado
    /// produz é o que separa "a suíte passou" de "o processo terminou".
    fn codigo_de_sucesso(self) -> i32 {
        match self {
            Self::X86_64 => 33,
            Self::Aarch64 => 33,
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

    // Qual teclado a máquina da fumaça vai ter. Ver [`Teclado`] sobre por que
    // é um e não os dois.
    let teclado = match extrair_valor(&args, "--teclado") {
        None | Some("nativo") => Teclado::Nativo,
        Some("usb") => Teclado::Usb,
        Some(outro) => {
            eprintln!("erro: teclado desconhecido `{outro}`; use `nativo` ou `usb`");
            return ExitCode::FAILURE;
        }
    };

    // Posicionais: tudo que não é flag nem valor de flag.
    let mut posicionais: Vec<&str> = Vec::new();
    let mut pular = false;
    for a in &args {
        if pular {
            pular = false;
            continue;
        }
        if a == "--arch" || a == "--teclado" {
            pular = true;
        } else if !a.starts_with("--") {
            posicionais.push(a);
        }
    }

    let comando = posicionais.first().copied().unwrap_or("help");

    let resultado = match comando {
        "build" => build(arch, release, false).map(|_| ExitCode::SUCCESS),
        "run" => run(arch, release),
        "test" => test(arch, release),
        "fumaca" => fumaca(arch, release, teclado),
        "agent" => {
            let metodo = posicionais.get(1).copied().unwrap_or("agent.describe");
            let params = posicionais.get(2).copied().unwrap_or("{}");
            agente(arch, metodo, params)
        }
        "debug" => depurar(arch, release),
        "simbolo" => simbolizar(arch, release, &posicionais[1..]),
        "asm" => match posicionais.get(1) {
            Some(simbolo) => desmontar(arch, release, simbolo),
            None => Err("uso: cargo xtask asm <simbolo>".into()),
        },
        "elf" => conferir_elfs(arch, release),
        "invariantes" => conferir_invariantes(),
        "iniciador" => iniciador(arch, release),
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

/// O valor de uma opção `--nome valor` ou `--nome=valor`, se houver.
///
/// Espelha [`extrair_arch`], que veio antes e é específica demais para
/// reaproveitar: ela devolve uma arquitetura, não o texto.
fn extrair_valor<'a>(args: &'a [String], nome: &str) -> Option<&'a str> {
    let prefixo = alloc_prefixo(nome);
    let mut i = 0;
    while i < args.len() {
        if let Some(valor) = args[i].strip_prefix(prefixo.as_str()) {
            return Some(valor);
        }
        if args[i] == nome {
            return args.get(i + 1).map(|v| v.as_str());
        }
        i += 1;
    }
    None
}

/// `--nome=`, montado uma vez.
fn alloc_prefixo(nome: &str) -> String {
    let mut p = String::with_capacity(nome.len() + 1);
    p.push_str(nome);
    p.push('=');
    p
}

fn ajuda() {
    println!(
        "\
build system do Duke

USO:
    cargo xtask <comando> [--arch x86_64|aarch64] [--release]
                          [--teclado nativo|usb]   (só na fumaça)

COMANDOS:
    build                     compila o kernel (e gera as imagens, no x86)
    run                       executa no QEMU com o canal do agente ativo
    test                      executa a suíte de testes dentro do QEMU
    fumaca                    sobe o kernel de produção e conversa pelo canal
    agent <metodo> [params]   envia uma chamada JSON-RPC ao kernel em execução
    debug                     sobe o kernel parado, esperando um depurador
    simbolo <endereco>...     traduz endereços de execução em arquivo e linha
    asm <simbolo>             desmonta uma função do binário compilado
    elf                       confere os programas de usuário embutidos
    invariantes               confere as regras de fonte dos dois lados
    iniciador                 sobe o iniciador UEFI no OVMF e confere o relatório
    help                      mostra esta mensagem

EXEMPLOS:
    cargo xtask run
    cargo xtask run --arch aarch64
    cargo xtask agent system.info
    cargo xtask agent --arch aarch64 agent.describe
    cargo xtask agent log.tail '{{\"count\":5,\"min_level\":\"info\"}}'

    cargo xtask debug --arch aarch64
    cargo xtask simbolo 0xffff80000000b697
    cargo xtask asm --release duke::testes::consumir_pilha"
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

/// Qual teclado a máquina vai ter.
///
/// # Por que isto é uma escolha, e não os dois de uma vez
///
/// Porque o QEMU entrega cada tecla a **um** dispositivo. Medido: com o
/// teclado virtio e o USB na mesma máquina ARM, `sendkey` alimentou o virtio e
/// o USB não viu nada (`device_events` 12, `usb_reports` 0); no x86, com o
/// 8042 e o USB, foi o USB que recebeu e a IRQ 1 nunca disparou.
///
/// Com os dois presentes, portanto, um dos drivers fica sem exercício — e sem
/// que nada acuse, porque a sonda passa pelo outro caminho. Uma máquina com um
/// teclado só é o que torna a sonda uma afirmação sobre qual driver funciona.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Teclado {
    /// O que a máquina tem de fábrica: o 8042 no x86, o virtio no ARM.
    Nativo,
    /// Um teclado USB, atrás do controlador xHCI. O mesmo dispositivo e o
    /// mesmo driver nas duas arquiteturas.
    Usb,
}

/// Onde fica o monitor do emulador desta arquitetura.
///
/// # Para que o monitor serve aqui
///
/// Para injetar teclas. O teclado é o único subsistema deste kernel que não
/// se consegue exercitar nem pela suíte nem pelo canal do agente: a suíte não
/// tem como acionar o controlador 8042 nem o dispositivo virtio, e o canal só
/// mostra o resultado. O monitor do QEMU tem `sendkey`, que entrega a tecla
/// ao dispositivo pelo mesmo caminho que um teclado de verdade entregaria.
///
/// É a mesma ideia do `llvm-readobj` conferindo os ELFs de usuário: quem
/// produz o estímulo não é quem o interpreta.
fn caminho_monitor(arch: Arquitetura) -> PathBuf {
    raiz_do_projeto()
        .join("target")
        .join(format!("monitor-{}.sock", arch.nome()))
}

/// O que o build produziu e o QEMU precisa carregar.
enum Artefato {
    /// x86: o disco de testes, com o iniciador e o kernel na ESP.
    ///
    /// Não há mais uma imagem por caminho de boot. O firmware UEFI carrega o
    /// `\EFI\BOOT\BOOTX64.EFI` da partição de sistema, e é o iniciador
    /// deste projeto que põe o kernel de pé — o mesmo disco de onde o kernel
    /// depois lê a raiz em Btrfs.
    Disco(PathBuf),
    /// ARM: uma imagem binária crua com cabeçalho arm64.
    ///
    /// Não é o único caminho: o ARM também boota do disco, pelo mesmo
    /// iniciador UEFI do x86, e é assim que a sonda do `xtask` o exercita.
    /// Este aqui é o caminho sem carregador nenhum — o protocolo de boot do
    /// arm64, um binário cru cujos primeiros 64 bytes são um cabeçalho que
    /// diz a quem carrega onde depositá-lo e quanta RAM reservar. Em troca,
    /// recebemos o endereço do device tree em `x0`, que é o que o QEMU *não*
    /// faz quando lhe entregamos um ELF.
    ///
    /// Ele continua sendo o padrão do `test` e do `fumaca` porque sobe em
    /// segundos, sem disco montado e sem firmware instalado.
    Binario(PathBuf),
}

/// Nome do executável que o cargo produz para o kernel.
///
/// É o `name` do pacote em `kernel/Cargo.toml` — ou seja, o nome do sistema.
/// Fica numa constante porque o xtask precisa dele em dois caminhos
/// diferentes (a imagem que o QEMU carrega e o ELF que o depurador lê), e
/// descobrir só na hora de rodar que um dos dois ficou para trás é o tipo de
/// erro que custa uma sessão de depuração inteira.
const NOME_DO_BINARIO: &str = "duke";

/// Compila o kernel e prepara o que o QEMU vai carregar.
///
/// Com `modo_teste`, o kernel é compilado com a feature que troca o laço do
/// agente pelo executor da suíte de testes.
fn build(arch: Arquitetura, release: bool, modo_teste: bool) -> Result<Artefato, String> {
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
    if modo_teste {
        cargo.args(["--features", "modo-teste"]);
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
        .join(NOME_DO_BINARIO);
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
            // O x86 boota pela UEFI, com o iniciador deste projeto. Os dois
            // vão para a ESP do disco de testes: o `.efi` no caminho que todo
            // firmware procura, e o ELF do kernel ao lado.
            //
            // É sempre este kernel, e não o da execução anterior: a cópia é
            // incondicional porque `test`, `fumaca` e `run` compilam binários
            // diferentes, e bootar o errado dá um resultado que não é sobre o
            // que se pediu.
            let efi = build_do_iniciador(arch, release)?;
            let disco = disco_de_testes()?;
            instalar_iniciador(arch, &disco, &efi, &elf)?;
            Ok(Artefato::Disco(disco))
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
    ferramenta_llvm("llvm-objcopy")
}

/// Localiza uma ferramenta do LLVM distribuída junto com a toolchain.
///
/// Preferimos a do `rustup` à do sistema por um motivo prático: ela é a mesma
/// versão do LLVM que compilou o binário, então entende o DWARF que ele
/// contém. Uma `llvm-symbolizer` mais velha que o compilador pode silenciar
/// informação de linha em vez de falhar, que é o pior desfecho possível numa
/// ferramenta de diagnóstico.
fn ferramenta_llvm(nome: &str) -> Result<PathBuf, String> {
    let saida = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("não foi possível consultar o sysroot do rustc: {e}"))?;
    let sysroot = PathBuf::from(String::from_utf8_lossy(&saida.stdout).trim().to_string());

    let rustlib = sysroot.join("lib").join("rustlib");
    let entradas = std::fs::read_dir(&rustlib)
        .map_err(|e| format!("não foi possível ler {}: {e}", rustlib.display()))?;

    for entrada in entradas.flatten() {
        let candidato = entrada.path().join("bin").join(nome);
        if candidato.is_file() {
            return Ok(candidato);
        }
    }

    // Fora do rustup, a do sistema serve — com a ressalva de versão acima.
    if Command::new(nome).arg("--version").output().is_ok() {
        return Ok(PathBuf::from(nome));
    }

    Err(format!(
        "{nome} não encontrado em {}\n\
         instale o componente com: rustup component add llvm-tools",
        rustlib.display()
    ))
}

/// O `llvm-readobj` do componente `llvm-tools`, no modo de saída do GNU.
///
/// # Por que não o `llvm-readelf`
///
/// Porque ele **não vem** no componente. As duas ferramentas são o mesmo
/// binário do LLVM com nomes diferentes — `llvm-readelf` é o `llvm-readobj`
/// com `--elf-output-style=GNU` — e o `rustup` empacota só o segundo.
///
/// Pedir `llvm-readelf` funcionava nesta máquina de desenvolvimento por um
/// acidente: o pacote `llvm` do Ubuntu põe um `/usr/bin/llvm-readelf`, e o
/// localizador cai nesse atalho quando não acha o do `rustup`. Num runner
/// limpo esse arquivo não existe, e o passo do iniciador na CI falhou com
/// "llvm-readelf não encontrado" — depois de o iniciador ter feito todo o
/// trabalho dele certo.
///
/// É a classe de defeito que este projeto já conhece: uma dependência do
/// ambiente de quem escreveu, invisível para quem escreveu.
fn conferidor_de_elf() -> Result<(PathBuf, &'static str), String> {
    Ok((ferramenta_llvm("llvm-readobj")?, "--elf-output-style=GNU"))
}

/// O alvo em que o iniciador UEFI compila, por arquitetura.
///
/// Não é o alvo do kernel: uma aplicação EFI é um **PE/COFF** com uma ABI de
/// chamada própria, e não um ELF bare-metal. O firmware é quem a carrega, e
/// ele só conhece um formato.
const fn alvo_do_iniciador(arch: Arquitetura) -> &'static str {
    match arch {
        Arquitetura::X86_64 => "x86_64-unknown-uefi",
        Arquitetura::Aarch64 => "aarch64-unknown-uefi",
    }
}

/// Onde o firmware procura o programa de boot num disco removível.
///
/// O caminho é fixado pela especificação, e é a razão de a aplicação não
/// precisar de nenhuma entrada no NVRAM da máquina: qualquer firmware UEFI,
/// sem configuração nenhuma, procura este arquivo na partição de sistema.
///
/// O nome carrega a arquitetura porque a ESP é uma só: um disco pode ser
/// posto numa máquina x86 hoje e numa ARM amanhã, e os dois programas
/// convivem sem que nenhum firmware precise escolher.
const fn caminho_na_esp(arch: Arquitetura) -> &'static str {
    match arch {
        Arquitetura::X86_64 => "::/EFI/BOOT/BOOTX64.EFI",
        Arquitetura::Aarch64 => "::/EFI/BOOT/BOOTAA64.EFI",
    }
}

/// Onde o kernel fica na mesma partição, para o iniciador achá-lo.
///
/// O outro lado deste contrato é o `CAMINHO_DO_KERNEL` do iniciador, escrito
/// em UTF-16. Divergir os dois faz o boot parar com "o kernel nao esta na
/// particao de sistema" — que é um erro claro, e é a razão de a mensagem
/// dizer isso em vez de um código do firmware.
const KERNEL_NA_ESP: &str = "::/duke.elf";

/// Firmwares UEFI que este comando sabe procurar, em ordem de preferência.
///
/// A variante `_4M` é a da versão nova do OVMF, com o espaço de variáveis
/// separado do código; a outra é o arquivo único das versões antigas. Ambas
/// existem em distribuições diferentes, e o `xtask` não escolhe por
/// distribuição — escolhe pelo que está no disco.
const FIRMWARES_X86: &[(&str, &str)] = &[
    (
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    ),
    (
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
    ),
    (
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    ),
];

/// O mesmo para o ARM: o EDK II compilado para aarch64, que as distribuições
/// chamam de AAVMF. É a **mesma** base de código do OVMF, compilada para
/// outro processador — o que é justamente o ponto do iniciador ser o mesmo
/// programa.
const FIRMWARES_ARM: &[(&str, &str)] = &[
    (
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/AAVMF/AAVMF_VARS.fd",
    ),
    (
        "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw",
        "/usr/share/edk2/aarch64/vars-template-pflash.raw",
    ),
];

const fn firmwares(arch: Arquitetura) -> &'static [(&'static str, &'static str)] {
    match arch {
        Arquitetura::X86_64 => FIRMWARES_X86,
        Arquitetura::Aarch64 => FIRMWARES_ARM,
    }
}

/// Compila o iniciador e devolve o `.efi` produzido.
fn build_do_iniciador(arch: Arquitetura, release: bool) -> Result<PathBuf, String> {
    let raiz = raiz_do_projeto();
    let dir = raiz.join("iniciador");
    let perfil = if release { "release" } else { "debug" };
    let alvo = alvo_do_iniciador(arch);
    println!("[xtask] compilando o iniciador UEFI ({alvo}, {perfil})...");

    let mut cargo = Command::new(env!("CARGO"));
    cargo.current_dir(&dir).args(["build", "--target", alvo]);
    if release {
        cargo.arg("--release");
    }
    // Pela mesma razão do build do kernel: as variáveis que o cargo exporta
    // descrevem o build *do xtask*, e herdá-las manda o filho para o target
    // errado.
    for var in ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS", "CARGO_TARGET_DIR"] {
        cargo.env_remove(var);
    }

    let status = cargo
        .status()
        .map_err(|e| format!("não foi possível invocar o cargo: {e}"))?;
    if !status.success() {
        return Err("a compilação do iniciador falhou".into());
    }

    let efi = dir
        .join("target")
        .join(alvo)
        .join(perfil)
        .join("iniciador.efi");
    if !efi.exists() {
        return Err(format!(
            "o cargo reportou sucesso mas o .efi não apareceu em {}",
            efi.display()
        ));
    }
    Ok(efi)
}

/// Copia o iniciador para a ESP do disco de testes.
///
/// # Por que o disco de testes, e não uma imagem só para isto
///
/// Porque ele já é uma GPT de verdade com uma ESP em FAT32 — foi montado para
/// que o kernel tivesse um disco para ler, e é exatamente o disco de que o
/// firmware precisa para ter de onde bootar. Duas imagens diferentes, uma
/// para bootar e outra para ler, seriam duas verdades sobre a mesma máquina.
///
/// A cópia acontece a cada execução, por cima do que estiver lá. O disco é
/// cacheado por uma receita que não menciona o iniciador, de propósito:
/// recompilá-lo não deve custar a remontagem de 192 MiB, e sobrescrever um
/// arquivo de 35 KiB é barato o bastante para ser incondicional.
fn instalar_iniciador(
    arch: Arquitetura,
    disco: &Path,
    efi: &Path,
    kernel: &Path,
) -> Result<(), String> {
    let imagem = format!("{}@@1M", disco.display());

    // `mmd` reclama se o diretório já existe, e existir é o caso comum. O
    // erro é ignorado aqui e o `mcopy` abaixo é quem diz se algo deu errado
    // de verdade — ele falha se o caminho não existir.
    for dir in ["::/EFI", "::/EFI/BOOT"] {
        let _ = Command::new("mmd").args(["-i", &imagem, dir]).output();
    }

    for (origem, destino) in [(efi, caminho_na_esp(arch)), (kernel, KERNEL_NA_ESP)] {
        ferramenta(
            "mcopy",
            &["-o", "-i", &imagem, &origem.display().to_string(), destino],
        )?;
        println!(
            "[xtask] {} -> {} ({} KiB)",
            origem.file_name().unwrap_or_default().display(),
            destino.trim_start_matches("::"),
            origem.metadata().map(|m| m.len()).unwrap_or(0) / 1024
        );
    }
    Ok(())
}

/// Acha o firmware UEFI e prepara uma cópia gravável das variáveis.
///
/// O arquivo de variáveis **precisa** ser gravável e nosso: o firmware
/// escreve nele durante o boot, e apontar o QEMU para o do sistema ou falha
/// por permissão ou suja a instalação da máquina.
fn firmware_uefi(arch: Arquitetura) -> Result<(PathBuf, PathBuf), String> {
    let candidatos = firmwares(arch);
    let (codigo, variaveis) = candidatos
        .iter()
        .map(|(c, v)| (PathBuf::from(c), PathBuf::from(v)))
        .find(|(c, v)| c.is_file() && v.is_file())
        .ok_or_else(|| {
            let procurados: Vec<&str> = candidatos.iter().map(|(c, _)| *c).collect();
            let pacote = match arch {
                Arquitetura::X86_64 => "`ovmf` (Debian/Ubuntu) ou `edk2-ovmf` (Fedora)",
                Arquitetura::Aarch64 => "`qemu-efi-aarch64` (Debian/Ubuntu) ou `edk2-aarch64`",
            };
            format!(
                "nenhum firmware UEFI de {} encontrado. Procurei em: {}.\n\
                 Instale o pacote {pacote}.",
                arch.nome(),
                procurados.join(", ")
            )
        })?;

    let nossas = raiz_do_projeto()
        .join("target")
        .join(format!("uefi-vars-{}.fd", arch.nome()));
    std::fs::copy(&variaveis, &nossas).map_err(|e| {
        format!(
            "não foi possível copiar {} para {}: {e}",
            variaveis.display(),
            nossas.display()
        )
    })?;
    Ok((codigo, nossas))
}

/// Quanto o iniciador tem para relatar e desligar a máquina.
///
/// Folgado: o firmware sozinho leva alguns segundos para inicializar o vídeo
/// e varrer os barramentos, e o relatório em si é instantâneo. O teto não
/// está aqui para medir desempenho — está para que um iniciador que trave
/// vire um erro em vez de um job pendurado.
const TETO_DO_INICIADOR: Duration = Duration::from_secs(240);

/// A linha com que o kernel anuncia o framebuffer que adotou.
///
/// É o que a sonda do x86 **espera** ver, e não a primeira linha do kernel.
/// A diferença é o que ela prova: a primeira linha diz que o salto chegou, e
/// esta diz que o kernel chegou até a tela e ficou com a que o iniciador lhe
/// deu. Esperar a segunda custa algumas centenas de milissegundos e inclui a
/// primeira, que continua sendo conferida no texto capturado.
const MARCA_DA_TELA: &str = "framebuffer ";

/// A primeira linha que o kernel escreve depois de assumir a máquina.
///
/// É ela que prova o salto. Tudo que vem antes é o iniciador falando sobre o
/// que pretende fazer; esta linha é outro programa, noutro espaço de
/// endereços, dizendo que está de pé.
const fn marca_do_kernel(arch: Arquitetura) -> &'static str {
    match arch {
        Arquitetura::X86_64 => "Duke iniciado em x86_64",
        Arquitetura::Aarch64 => "Duke iniciado em aarch64",
    }
}

/// O relatório que o iniciador do x86 precisa produzir, do começo ao salto.
///
/// Cada linha aqui é uma afirmação sobre o que foi conferido do outro lado, e
/// não sobre o texto: `as tres tabelas conferem` só é impressa depois de três
/// assinaturas e três CRCs baterem. Procurar a linha é procurar a conferência.
const ESPERADO_DO_INICIADOR: &[&str] = &[
    "vivo em x86_64, carregado pelo firmware",
    "tabela do sistema confere",
    "as tres tabelas conferem",
    "esp: duke.elf aberto e lido",
    "relocacoes aplicadas",
    "mapa confere",
    "fim do relatorio",
    "a tela em",
    "saindo dos servicos de boot",
    "a maquina e do Duke",
];

/// O que o iniciador do ARM precisa dizer.
///
/// As quatro primeiras linhas são idênticas às do x86 porque o código que as
/// escreve é o mesmo — a UEFI é a mesma especificação nas duas máquinas. O
/// que difere é o meio: lá o iniciador monta um mapa de tradução, aqui ele
/// desfaz o que o firmware deixou, porque a UEFI do ARM entrega a máquina
/// com a MMU ligada e mapeada por identidade.
const ESPERADO_DO_INICIADOR_ARM: &[&str] = &[
    "vivo em aarch64, carregado pelo firmware",
    "tabela do sistema confere",
    "as tres tabelas conferem",
    "esp: duke.elf aberto e lido",
    // O kernel do ARM é ligado num endereço fixo, e não independente de
    // posição como o do x86. Exigir a linha registra o fato onde ele
    // importa: é a razão de o iniciador pedir ao firmware **aquele**
    // endereço em vez de qualquer um.
    "endereco fixo",
    "kernel conferido",
    "device tree em",
    // O endereço da PL011 está fixado no código do iniciador — ele precisa
    // estar, porque é por ela que ele relata qualquer coisa. Esta linha é
    // a placa confirmando o número, e exigi-la aqui é o que impede a
    // conferência de sumir sem ninguém notar.
    "a placa confirma a pl011",
    "carga: imagem em",
    "fim do relatorio",
    "a tela em",
    "saindo dos servicos de boot",
    "a maquina e do Duke",
];

const fn esperado_do_iniciador(arch: Arquitetura) -> &'static [&'static str] {
    match arch {
        Arquitetura::X86_64 => ESPERADO_DO_INICIADOR,
        Arquitetura::Aarch64 => ESPERADO_DO_INICIADOR_ARM,
    }
}

/// Sobe o iniciador no firmware de verdade e confere o que ele relatou.
fn iniciador(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let efi = build_do_iniciador(arch, release)?;

    // O kernel também vai para a ESP: é o que o iniciador vai abrir. Compilar
    // é o mesmo `build` de sempre — o que muda é para onde o ELF vai.
    //
    // # Por que o ARM boota a compilação de teste
    //
    // Porque é a única que fala. A máquina `virt` expõe **uma** PL011, e
    // fora do modo de teste ela é o canal do agente: o kernel do ARM não tem
    // console humano, e o log de boot vai só para o anel de registros. Esta
    // sonda lê a serial, então um kernel que não escreve nela é
    // indistinguível de um kernel que não subiu — e foi exatamente assim que
    // o primeiro boot por UEFI no ARM pareceu ter falhado, com o `-d int` do
    // QEMU mostrando o kernel vivo, tratando interrupções pelos vetores
    // dele.
    //
    // No modo de teste a porta vira console, e a primeira linha do kernel
    // aparece. É o mesmo kernel, com a mesma imagem e o mesmo caminho de
    // boot; o que muda é ter para onde falar.
    let modo_teste = arch == Arquitetura::Aarch64;
    build(arch, release, modo_teste)?;
    let kernel = caminho_elf(arch, release);

    let disco = disco_de_testes()?;
    let mut falhou = false;

    // A rodada que importa: o kernel de verdade, e o relatório inteiro.
    instalar_iniciador(arch, &disco, &efi, &kernel)?;
    println!("\n[xtask] iniciador: o kernel de verdade");

    // O desfecho difere, e a diferença é o que o ARM ganhou de novo.
    //
    // No x86 a sonda sobe o kernel de **produção** e espera a primeira linha
    // dele: é a prova de que o salto funcionou, e o kernel fica de pé depois
    // disso — esperar um desligamento seria esperar para sempre.
    //
    // No ARM ela sobe a compilação de teste, que é a única com console (ver
    // o `build` acima). E já que é ela que está lá, a sonda deixa a suíte
    // **inteira** rodar em vez de parar na primeira linha. A diferença não é
    // cosmética: o mapa de memória que o firmware entrega tem trinta e três
    // regiões, e o do device tree tem uma. Todo o resto do kernel — o
    // alocador de frames, a cópia na escrita, o coletor, o Btrfs — roda
    // sobre esse mapa pela primeira vez aqui. Passar no `-kernel` não diz
    // nada sobre passar por este caminho.
    let marca = marca_do_kernel(arch);
    let espera = match arch {
        Arquitetura::X86_64 => Desenlace::Marca(MARCA_DA_TELA),
        Arquitetura::Aarch64 => Desenlace::Desligamento,
    };
    let (desfecho, relatorio, bruto) = subir_no_firmware(arch, &disco, &espera)?;
    for linha in &relatorio {
        println!("  [iniciador] {linha}");
    }
    if relatorio.is_empty() {
        return Err(
            "o iniciador não disse nada: ou o firmware não o encontrou na ESP, ou ele \
             morreu antes da primeira linha"
                .into(),
        );
    }

    if let Err(motivo) = conferir_desfecho(arch, desfecho, &espera) {
        eprintln!("[xtask] iniciador: {motivo}");
        falhou = true;
    }
    let como_str: Vec<&str> = relatorio.iter().map(|l| l.as_str()).collect();
    for esperado in esperado_do_iniciador(arch) {
        if !como_str.iter().any(|l| l.contains(esperado)) {
            eprintln!("[xtask] iniciador: faltou `{esperado}` no relatório");
            falhou = true;
        }
    }
    for linha in &como_str {
        if linha.starts_with("ERRO") || linha.starts_with("PANICO") {
            eprintln!("[xtask] iniciador: {linha}");
            falhou = true;
        }
    }
    if let Err(motivo) = conferir_numeros_do_iniciador(arch, &como_str) {
        eprintln!("[xtask] iniciador: {motivo}");
        falhou = true;
    }
    if let Err(motivo) = conferir_elf_contra_readelf(arch, &como_str, &kernel) {
        eprintln!("[xtask] iniciador: {motivo}");
        falhou = true;
    }
    // O kernel falou? A linha não tem o prefixo do iniciador, então ela vem
    // do texto cru — e é a única prova de que o salto chegou do outro lado.
    if !bruto.contains(marca) {
        eprintln!("[xtask] iniciador: o kernel nao disse `{marca}`");
        falhou = true;
    } else {
        println!("  [conferido] o kernel assumiu a maquina e disse `{marca}`");
    }

    // A tela em que o kernel desenha é a que o iniciador lhe entregou?
    match conferir_a_tela_do_kernel(&como_str, &bruto) {
        Ok(tela) => println!(
            "  [conferido] o kernel desenha na tela de {}x{} que o iniciador entregou, e os \
             {} KiB que ela ocupa cabem no buffer do firmware",
            tela.largura, tela.altura, tela.kib
        ),
        Err(motivo) => {
            eprintln!("[xtask] iniciador: {motivo}");
            falhou = true;
        }
    }

    // E, no ARM, a suíte inteira rodou sobre o mapa de memória do firmware.
    if arch == Arquitetura::Aarch64 {
        match conferir_a_suite(&bruto) {
            Ok(quantos) => {
                println!("  [conferido] {quantos} casos da suite passaram sobre o mapa da UEFI")
            }
            Err(motivo) => {
                eprintln!("[xtask] iniciador: {motivo}");
                falhou = true;
            }
        }
    }

    // E as rodadas das recusas: kerneis estragados de propósito, que o
    // iniciador tem de rejeitar em vez de carregar.
    let de_outra = recusa_de_outra_arquitetura(arch);
    let casos: Vec<&Recusa> = RECUSAS.iter().chain(core::iter::once(&de_outra)).collect();
    println!(
        "\n[xtask] iniciador: {} kerneis estragados de proposito, que tem de ser recusados",
        casos.len()
    );
    for caso in casos {
        match rodada_de_recusa(arch, &disco, &efi, &kernel, caso) {
            Ok(()) => println!("  [recusa] ok  {} foi recusado", caso.nome),
            Err(motivo) => {
                eprintln!(
                    "  [recusa] {} NAO foi recusado como devia: {motivo}",
                    caso.nome
                );
                falhou = true;
            }
        }
    }

    // O disco fica com o kernel bom, e não com o último adulterado: ele é
    // compartilhado com todo o resto do `xtask`, e deixá-lo quebrado faria a
    // próxima execução falhar por um motivo que nada tem a ver com ela.
    instalar_iniciador(arch, &disco, &efi, &kernel)?;

    if falhou {
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] iniciador: o firmware carregou o Duke e o relatório confere");
    Ok(ExitCode::SUCCESS)
}

/// Um kernel deliberadamente estragado, e o que o iniciador tem de dizer.
///
/// # Por que isto existe
///
/// Porque as conferências do leitor de ELF não são falsificáveis contra um
/// arquivo bom. Desligar a que exige que o ponto de entrada caia dentro de um
/// segmento não reprovava nada: o kernel de verdade sempre passa nela.
///
/// Medido por mutação, e é o que estes casos corrigem. Cada um adultera uma
/// cópia do kernel num byte e exige a recusa **pelo motivo certo** — recusar
/// pelo motivo errado é quase tão ruim quanto aceitar, porque manda quem
/// depura procurar no lugar errado.
struct Recusa {
    /// Como o kernel foi estragado, escrito para caber em "… foi recusado".
    ///
    /// O nome descreve o **arquivo**, e não o erro: a primeira versão deste
    /// campo dizia coisas como "a maquina errada", e a linha saía
    /// `[recusa] ok a maquina errada` — que se lê como um defeito, e não como
    /// um caso que passou. Uma saída que precisa de quem a escreveu para ser
    /// entendida é uma saída errada.
    nome: &'static str,
    /// Onde escrever, no ELF.
    em: usize,
    /// O que escrever ali.
    bytes: &'static [u8],
    /// O pedaço da mensagem de erro que o iniciador tem de emitir.
    esperado: &'static str,
}

const RECUSAS: &[Recusa] = &[
    Recusa {
        nome: "um kernel com a entrada fora de qualquer segmento",
        // `e_entry`, no deslocamento 24 do cabeçalho ELF64.
        em: 24,
        bytes: &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        esperado: "a entrada do kernel nao cai em segmento nenhum",
    },
    Recusa {
        nome: "um kernel com cabecalhos de programa menores que o formato",
        // `e_phentsize`, no deslocamento 54.
        em: 54,
        bytes: &[8, 0],
        esperado: "os cabecalhos de programa sao menores que o formato",
    },
    Recusa {
        nome: "um arquivo que nao e um ELF",
        // O primeiro byte da identificação.
        em: 0,
        bytes: b"X",
        esperado: "nao e um ELF64 little-endian",
    },
];

/// A recusa que depende de para onde se está compilando.
///
/// O caso é "um kernel de outra arquitetura", e o byte a escrever é o número
/// da **outra**: num iniciador de x86, o do ARM; num de ARM, o do x86.
///
/// Escrever `0xB7` fixo funcionava enquanto só havia o x86, e virou um caso
/// que passa sem testar nada no dia em que o ARM chegou: o kernel do ARM já
/// é `0xB7`, então adulterá-lo para `0xB7` é copiar o valor por cima dele
/// mesmo. O iniciador aceitava o arquivo, com razão, e a rodada reprovava —
/// que foi como o defeito apareceu.
const fn recusa_de_outra_arquitetura(arch: Arquitetura) -> Recusa {
    Recusa {
        nome: "um kernel compilado para outra arquitetura",
        // `e_machine`, no deslocamento 18 do cabeçalho ELF64.
        em: 18,
        bytes: match arch {
            // 0xB7 é `EM_AARCH64`.
            Arquitetura::X86_64 => &[0xB7, 0x00],
            // 0x3E é `EM_X86_64`.
            Arquitetura::Aarch64 => &[0x3E, 0x00],
        },
        esperado: "o kernel nao e desta arquitetura",
    }
}

/// Põe um kernel adulterado na ESP e exige que o iniciador o recuse.
fn rodada_de_recusa(
    arch: Arquitetura,
    disco: &Path,
    efi: &Path,
    kernel: &Path,
    caso: &Recusa,
) -> Result<(), String> {
    let mut bytes = std::fs::read(kernel)
        .map_err(|e| format!("não foi possível ler {}: {e}", kernel.display()))?;
    let fim = caso.em + caso.bytes.len();
    if fim > bytes.len() {
        return Err("o kernel é menor que o byte a adulterar".into());
    }
    bytes[caso.em..fim].copy_from_slice(caso.bytes);

    let estragado = raiz_do_projeto().join("target").join("duke-estragado.elf");
    std::fs::write(&estragado, &bytes)
        .map_err(|e| format!("não foi possível escrever {}: {e}", estragado.display()))?;
    instalar_iniciador(arch, disco, efi, &estragado)?;

    let espera = Desenlace::Desligamento;
    let (desfecho, relatorio, _) = subir_no_firmware(arch, disco, &espera)?;
    // O iniciador precisa **sobreviver** à recusa: ele relata e desliga. Um
    // travamento aqui é tão defeito quanto aceitar o arquivo.
    conferir_desfecho(arch, desfecho, &espera)?;

    if !relatorio.iter().any(|l| l.contains(caso.esperado)) {
        for linha in &relatorio {
            eprintln!("    [iniciador] {linha}");
        }
        return Err(format!("nao disse `{}`", caso.esperado));
    }
    if relatorio.iter().any(|l| l.contains("fim do relatorio")) {
        return Err("chegou ao fim do relatório com um kernel estragado".into());
    }
    Ok(())
}

/// O que a sonda do iniciador espera do emulador.
enum Desenlace {
    /// Que a máquina desligue sozinha. É o desfecho de uma recusa: o
    /// iniciador relata o motivo e encerra.
    Desligamento,
    /// Que esta marca apareça na saída, e então o emulador é encerrado.
    ///
    /// É o desfecho de um boot que deu certo. O iniciador não desliga nada —
    /// ele entrega a máquina ao kernel, que fica de pé. Esperar o
    /// desligamento aqui seria esperar para sempre; o que se espera é o
    /// **kernel falando**, que é a única prova de que o salto funcionou.
    Marca(&'static str),
}

/// Sobe o QEMU com o firmware e devolve o desfecho e as linhas do iniciador.
fn subir_no_firmware(
    arch: Arquitetura,
    disco: &Path,
    espera: &Desenlace,
) -> Result<(Desfecho, Vec<String>, String), String> {
    // A saída da serial vai para um arquivo, e não para um cano lido em
    // memória. O motivo é o teto de tempo logo abaixo: `Command::output()`
    // espera o processo terminar, e um iniciador que não chegue ao
    // `desligar` deixa o emulador vivo para sempre.
    //
    // Não é hipótese: a primeira versão deste comando não tinha teto, e a
    // primeira mutação que rodei — trocar de lugar os dois conjuntos de
    // serviços na tabela do sistema — fez o desligamento chamar a função
    // errada. O QEMU ficou de pé, e o `xtask` com ele.
    let registro = raiz_do_projeto().join("target").join("iniciador.log");
    let arquivo = std::fs::File::create(&registro)
        .map_err(|e| format!("não foi possível criar {}: {e}", registro.display()))?;

    // A máquina é a **mesma** que `test`, `run` e `fumaca` montam, e vem da
    // mesma função. Ela já sabe bootar pelo firmware desde que o artefato
    // seja um disco.
    //
    // Ela veio a ser a mesma depois de custar caro. Esta sonda montava uma
    // definição própria — mais curta, com `virtio-blk-device` no lugar do
    // `virtio-blk-pci` e sem semihosting —, e enquanto ela só olhava a
    // primeira linha do kernel, a diferença não aparecia. No dia em que a
    // suíte inteira passou a rodar aqui, vinte e nove casos reprovaram
    // dizendo que a máquina não tinha disco, nem vídeo, nem PCI. Nenhum
    // deles era defeito do kernel: era a segunda definição descrevendo
    // outro computador.
    let mut qemu = comando_qemu(
        arch,
        &Artefato::Disco(disco.to_path_buf()),
        None,
        Teclado::Nativo,
    )?;
    qemu.stdout(arquivo);
    // Sem rede: nada aqui precisa dela, e o firmware tentaria PXE antes do
    // disco se ela existisse.
    qemu.args(["-net", "none"]);

    let filho = qemu
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    let desfecho = match espera {
        Desenlace::Desligamento => aguardar_com_teto(filho, TETO_DO_INICIADOR)?,
        Desenlace::Marca(marca) => aguardar_a_marca(filho, &registro, marca, TETO_DO_INICIADOR)?,
    };

    let bruto = std::fs::read(&registro)
        .map_err(|e| format!("não foi possível ler {}: {e}", registro.display()))?;
    let texto = String::from_utf8_lossy(&bruto);
    let relatorio = texto
        .lines()
        .filter_map(|l| l.split("iniciador: ").nth(1).map(String::from))
        .collect();
    // O texto cru vai junto porque o relatório é só o que o **iniciador**
    // disse. O que o kernel diz depois do salto não tem esse prefixo, e é
    // justamente o que prova que ele assumiu a máquina.
    Ok((desfecho, relatorio, texto.into_owned()))
}

/// Espera uma marca aparecer na saída, e então encerra o emulador.
///
/// Devolve `Codigo(0)` quando a marca apareceu — não porque o processo saiu
/// com zero, mas porque o que se queria aconteceu. Quem chama confere o
/// desfecho pela mesma função dos outros casos, e o que distingue um boot
/// que funcionou de um que travou é justamente ter chegado aqui.
fn aguardar_a_marca(
    mut filho: Child,
    registro: &Path,
    marca: &str,
    teto: Duration,
) -> Result<Desfecho, String> {
    let inicio = Instant::now();

    loop {
        // O arquivo é lido a cada volta porque o emulador escreve nele
        // enquanto roda. Ler o que já chegou é o que permite reagir antes de
        // o processo terminar — e ele não vai terminar sozinho.
        if let Ok(bytes) = std::fs::read(registro)
            && String::from_utf8_lossy(&bytes).contains(marca)
        {
            let _ = filho.kill();
            let _ = filho.wait();
            return Ok(Desfecho::Codigo(0));
        }

        // Um emulador que morreu antes da marca é defeito, e esperar o teto
        // inteiro por ele só atrasa o diagnóstico.
        if let Some(status) = filho
            .try_wait()
            .map_err(|e| format!("falha ao aguardar o emulador: {e}"))?
        {
            return Ok(match status.code() {
                Some(code) => Desfecho::Codigo(code),
                None => Desfecho::Sinal,
            });
        }

        if inicio.elapsed() >= teto {
            let _ = filho.kill();
            let _ = filho.wait();
            return Ok(Desfecho::Estourou);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// O desfecho do emulador é uma afirmação sobre o iniciador.
///
/// Numa recusa, quem desliga a máquina é a última linha do iniciador; num
/// boot que deu certo, quem fala é o kernel. Um estouro de tempo significa
/// que aquilo não aconteceu.
fn conferir_desfecho(
    arch: Arquitetura,
    desfecho: Desfecho,
    espera: &Desenlace,
) -> Result<(), String> {
    match desfecho {
        Desfecho::Codigo(0) => Ok(()),
        // Quando quem desliga a máquina é a **suíte**, o código de saída é o
        // dela — o mesmo que `cargo xtask test` aprova. Um iniciador que
        // desliga por ter recusado o kernel sai com zero; os dois desfechos
        // são legítimos e distintos, e tratar o segundo como erro reprovaria
        // justamente a rodada que foi até o fim.
        Desfecho::Codigo(codigo) if codigo == arch.codigo_de_sucesso() => Ok(()),
        Desfecho::Codigo(codigo) => Err(format!("o emulador saiu com codigo {codigo}")),
        Desfecho::Sinal => Err("o emulador foi terminado por um sinal".into()),
        // O estouro significa coisas diferentes conforme o que se esperava, e
        // dizer a errada manda quem depura olhar o lugar errado. Um boot que
        // não chegou ao kernel não é "a máquina não desligou" — é o salto que
        // não aconteceu.
        Desfecho::Estourou => Err(match espera {
            Desenlace::Desligamento => format!(
                "a maquina nao desligou em {}s — o iniciador nao chegou ao fim",
                TETO_DO_INICIADOR.as_secs()
            ),
            Desenlace::Marca(marca) => format!(
                "o kernel nao disse `{marca}` em {}s — ou o salto nao chegou nele, ou ele \
                 parou antes dessa linha",
                TETO_DO_INICIADOR.as_secs()
            ),
        }),
    }
}

/// Confere que os números do relatório descrevem a máquina que pedimos.
///
/// # Por que isto não é redundante com as linhas
///
/// Porque um iniciador que lesse o mapa de memória com o passo errado ainda
/// imprimiria a linha inteira, com números. O que denuncia o passo errado é o
/// **valor**: pedimos 128 MiB ao emulador, e uma leitura desalinhada não
/// devolve nada perto disso.
/// Confere que a suíte de testes rodou inteira, e passou.
///
/// # Por que a sonda do boot também olha para a suíte
///
/// Porque são a mesma pergunta vista de dois lados. O boot por UEFI entrega
/// ao kernel um mapa de memória com dezenas de regiões, vindo do firmware;
/// o boot por imagem crua entrega uma, vinda do device tree. Tudo que
/// depende de saber o que é memória livre — o alocador de frames, a cópia
/// na escrita, o coletor de espaços, o leitor de Btrfs — roda sobre esse
/// mapa, e passar num não diz nada sobre passar no outro.
///
/// Deixar a suíte correr custa os mesmos segundos que ela já custa, e
/// transforma "o kernel disse uma linha" em "as cento e quarenta e nove
/// afirmações valem também por aqui".
fn conferir_a_suite(bruto: &str) -> Result<u64, String> {
    let reprovados: Vec<&str> = bruto
        .lines()
        .filter(|l| l.contains("FALHOU"))
        .map(|l| l.trim())
        .collect();
    if !reprovados.is_empty() {
        return Err(format!(
            "{} caso(s) da suíte reprovaram no boot por UEFI:\n      {}",
            reprovados.len(),
            reprovados.join("\n      ")
        ));
    }

    // O placar é a linha "N de M passaram". Exigi-lo — em vez de só a
    // ausência de reprovações — é o que distingue "todos passaram" de "a
    // suíte nem chegou ao fim", que sem ele seriam a mesma saída.
    //
    // A linha é reconhecida pela **forma** dela, campo por campo, e não por
    // conter " de ". A primeira versão procurava a substring, e a primeira
    // linha do log que a contém é `janela de MMIO em ...` — o placar nunca
    // era achado, e a sonda dizia que a suíte não terminara enquanto ela
    // terminava com 149 de 149 logo abaixo.
    let placar = bruto.lines().find_map(|linha| {
        let mut campos = linha.split_whitespace();
        let passaram: u64 = campos.next()?.parse().ok()?;
        (campos.next()? == "de").then_some(())?;
        let total: u64 = campos.next()?.parse().ok()?;
        (campos.next()? == "passaram").then_some((passaram, total))
    });

    let Some((passaram, total)) = placar else {
        return Err("a suíte não chegou ao placar; o kernel parou antes do fim".into());
    };
    if passaram != total || total == 0 {
        return Err(format!("a suíte terminou em {passaram} de {total}"));
    }
    Ok(total)
}

/// Onde a tela caiu no mapa de memória, e por que a resposta certa difere.
///
/// # O que esta conferência existe para pegar
///
/// O iniciador protege o framebuffer de virar memória livre: se ele cair
/// numa região que o firmware declarou utilizável, o kernel receberia como
/// livres as páginas que o vídeo está lendo sessenta vezes por segundo.
///
/// A proteção tem dois desfechos que, sem esta linha, seriam a mesma
/// ausência de saída: "não precisou agir" e "não rodou". O segundo é o
/// defeito, e foi real — a primeira versão comparava o endereço **virtual**
/// da tela com o mapa, que é todo físico, e portanto nunca casava. A
/// conferência o encontrou na primeira execução.
///
/// # Por que o número esperado é diferente nas duas máquinas
///
/// Porque a tela está em lugares de natureza diferente. No x86 ela é um BAR
/// de PCI em `0x8000_0000`, fora da RAM — e o mapa de memória da UEFI
/// descreve memória, não barramento, então ela **não aparece nele**. Zero é
/// a resposta certa, e exigir zero é o que documenta isso.
///
/// No ARM da máquina `virt` ela é o `ramfb`: RAM comum que o firmware
/// alocou, dentro do mapa. Exigir pelo menos uma região é a metade
/// falsificável — é ela que reprova se a comparação parar de acontecer.
fn conferir_a_tela(arch: Arquitetura, relatorio: &[&str]) -> Result<(), String> {
    let tela = relatorio
        .iter()
        .find(|l| l.starts_with("a tela em"))
        .ok_or("o relatório não disse onde a tela caiu no mapa")?;
    let regioes: u64 = extrair_numero_antes(tela, "regiao(oes) do mapa")
        .ok_or_else(|| format!("não consegui ler as regiões da tela de `{tela}`"))?;

    match arch {
        Arquitetura::X86_64 if regioes != 0 => Err(format!(
            "a tela caiu em {regioes} região(ões) do mapa de memória; no x86 ela é um \
             BAR de PCI e não deveria aparecer nele: `{tela}`"
        )),
        Arquitetura::Aarch64 if regioes == 0 => Err(format!(
            "a tela não caiu em região nenhuma do mapa: `{tela}`; no ARM ela é RAM, \
             então ou o `ramfb` mudou de lugar ou a comparação não aconteceu"
        )),
        _ => Ok(()),
    }
}

/// A geometria que o iniciador diz ter encontrado, lida do relatório dele.
///
/// Mora numa função porque duas conferências diferentes precisam do mesmo
/// par: uma pergunta se ele descreve um modo de vídeo que exista, e a outra
/// se o kernel adotou **esse** modo. Lidos em dois lugares, os dois
/// analisadores divergiriam na primeira mudança de formato da linha.
fn geometria_do_iniciador(relatorio: &[&str]) -> Result<Tela, String> {
    let video = relatorio
        .iter()
        .find(|l| l.starts_with("video:"))
        .ok_or("o relatório não trouxe a linha de vídeo")?;
    let (largura, altura) = video
        .split_whitespace()
        .nth(1)
        .and_then(|g| g.split_once('x'))
        .and_then(|(l, a)| Some((l.parse::<u32>().ok()?, a.parse::<u32>().ok()?)))
        .ok_or_else(|| format!("não consegui ler a geometria de `{video}`"))?;
    let kib = extrair_numero_antes(video, "KiB")
        .ok_or_else(|| format!("não consegui ler a extensão da tela de `{video}`"))?;
    Ok(Tela {
        largura,
        altura,
        kib,
    })
}

/// A tela como cada uma das duas pontas a descreve.
///
/// O endereço fica **fora** desta struct de propósito: o iniciador relata o
/// físico e o kernel desenha pelo virtual, e no x86 os dois diferem. Comparar
/// endereços aqui seria escrever uma regra que só vale numa arquitetura —
/// exatamente o defeito que este projeto já pagou algumas vezes.
///
/// O `kib` também não é a mesma grandeza nos dois lados, e descobrir isso
/// custou uma reprovação: o iniciador relata o tamanho que o **firmware
/// alocou** (`FrameBufferSize` do protocolo de vídeo da UEFI), e o kernel
/// relata o que a **geometria ocupa** (`stride * altura * bytes por pixel`).
/// No x86 os dois coincidem; no ARM da máquina `virt` o EDK II aloca 3072
/// KiB para uma tela de 800x600x4, que ocupa 1875. A relação que vale nas
/// duas é de continência, não de igualdade — ver
/// [`conferir_a_tela_do_kernel`].
#[derive(Clone, Copy)]
struct Tela {
    largura: u32,
    altura: u32,
    kib: u64,
}

/// O kernel desenha na tela que o iniciador lhe entregou — ou em outra?
///
/// # O que esta conferência existe para pegar
///
/// Um defeito que ficou meses no repositório sem sintoma: o kernel do ARM
/// lia a entrega inteira, **descartava** o vídeo dela e ia procurar um
/// adaptador `bochs-display` no PCI. As duas telas funcionavam, as duas
/// desenhavam, e nada no log dizia que o framebuffer que o firmware havia
/// configurado estava sendo ignorado — a máquina simplesmente tinha dois
/// vídeos e usava o segundo.
///
/// O que denuncia isso é a **geometria**: o firmware entrega 800x600, e o
/// adaptador do PCI é programado pelo kernel em 1280x720. Comparar os dois
/// números é o que transforma "há uma tela" em "há a tela certa".
///
/// A segunda conferência é de **extensão**, e ela pergunta outra coisa: o
/// que o kernel desenha cabe no buffer que o firmware alocou? É a única
/// grandeza dos dois relatos que depende do `stride`, e a relação entre as
/// duas é de continência e não de igualdade — ver [`Tela`].
///
/// Vale nas duas arquiteturas, e de propósito: é justamente o tipo de regra
/// que este projeto já viu ser escrita de um lado só.
fn conferir_a_tela_do_kernel(relatorio: &[&str], bruto: &str) -> Result<Tela, String> {
    let entregue = geometria_do_iniciador(relatorio)?;

    let linha = bruto
        .lines()
        .find(|l| l.contains(MARCA_DA_TELA))
        .ok_or("o kernel não anunciou framebuffer nenhum")?;
    let (largura, altura) = linha
        .split(MARCA_DA_TELA)
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|g| g.split_once('x'))
        .and_then(|(l, a)| Some((l.parse::<u32>().ok()?, a.parse::<u32>().ok()?)))
        .ok_or_else(|| {
            format!(
                "não consegui ler a geometria do kernel de `{}`",
                linha.trim()
            )
        })?;
    let kib = extrair_numero_antes(linha, "KiB").ok_or_else(|| {
        format!(
            "não consegui ler a extensão da tela do kernel de `{}`",
            linha.trim()
        )
    })?;
    let usada = Tela {
        largura,
        altura,
        kib,
    };

    if (usada.largura, usada.altura) != (entregue.largura, entregue.altura) {
        return Err(format!(
            "o iniciador entregou uma tela de {}x{} e o kernel desenha numa de {}x{}: ele \
             está ignorando a entrega e usando outra",
            entregue.largura, entregue.altura, usada.largura, usada.altura
        ));
    }
    // E o que o kernel desenha cabe no que o firmware alocou.
    //
    // Não é igualdade: as duas pontas medem coisas diferentes (ver
    // [`Tela`]). É continência, e é a relação que importa — o que passa do
    // fim do buffer não vira pixel, vira escrita em memória de outra pessoa.
    //
    // A conferência não é redundante com a da geometria: a extensão é o
    // único número dos dois relatos que depende do `stride`, e uma tela com
    // a geometria certa e o passo de linha errado sai inclinada, sem erro
    // nenhum. Ela também pega, por outro caminho, a tela trocada: o
    // `bochs-display` em 1280x720x4 ocupa 3600 KiB e não caberia nos 3072
    // que o firmware alocou.
    if usada.kib > entregue.kib {
        return Err(format!(
            "o kernel desenha {} KiB de tela e o firmware alocou {}: ele escreve depois do \
             fim do buffer",
            usada.kib, entregue.kib
        ));
    }
    Ok(usada)
}

fn conferir_numeros_do_iniciador(arch: Arquitetura, relatorio: &[&str]) -> Result<(), String> {
    let memoria = relatorio
        .iter()
        .find(|l| l.starts_with("memoria:"))
        .ok_or("o relatório não trouxe a linha de memória")?;

    let livres: u64 = extrair_numero_antes(memoria, "MiB livres")
        .ok_or_else(|| format!("não consegui ler os MiB livres de `{memoria}`"))?;
    // O emulador recebe `-m 128M`. O firmware fica com uma parte, então o
    // piso é folgado; o teto não, porque não há de onde sair mais memória.
    if !(64..=128).contains(&livres) {
        return Err(format!(
            "o mapa de memória diz {livres} MiB livres numa máquina de 128 MiB"
        ));
    }

    let por_descritor: u64 = extrair_numero_antes(memoria, "bytes,")
        .ok_or_else(|| format!("não consegui ler o tamanho do descritor de `{memoria}`"))?;
    // 40 é o tamanho do formato documentado. Menos que isso significa que o
    // firmware e o iniciador discordam sobre o que é um descritor.
    if por_descritor < 40 {
        return Err(format!(
            "descritores de {por_descritor} bytes, menos que o formato"
        ));
    }

    conferir_a_tela(arch, relatorio)?;

    // O nome do firmware é o primeiro campo depois do cabeçalho, e é por ele
    // que se vê se os deslocamentos da tabela batem. Um ponteiro lido do lugar
    // errado não dá um nome curto — dá interrogações, que é o que o iniciador
    // imprime no lugar de um byte que não é ASCII.
    let fabricante = relatorio
        .iter()
        .find(|l| l.starts_with("firmware `"))
        .ok_or("o relatório não trouxe o nome do firmware")?;
    let nome = fabricante
        .split('`')
        .nth(1)
        .ok_or_else(|| format!("não consegui ler o nome do firmware de `{fabricante}`"))?;
    if nome.len() < 4 || nome.contains('?') {
        return Err(format!("o nome do firmware veio como `{nome}`"));
    }

    // E o vídeo. Uma geometria de zero, ou um buffer no endereço zero, é o que
    // sai de um protocolo lido no deslocamento errado — e a linha continuaria
    // impressa do mesmo jeito.
    let video = relatorio
        .iter()
        .find(|l| l.starts_with("video:"))
        .ok_or("o relatório não trouxe a linha de vídeo")?;
    let geometria = geometria_do_iniciador(relatorio)?;
    if geometria.largura < 640 || geometria.altura < 480 {
        return Err(format!(
            "o vídeo veio com {}x{}, menor que qualquer modo de verdade",
            geometria.largura, geometria.altura
        ));
    }
    let buffer = video
        .split("buffer em ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("não consegui ler o endereço do buffer de `{video}`"))?;
    if buffer == 0 {
        return Err("o framebuffer está no endereço zero".into());
    }

    // O modo em uso tem de ser um dos que existem. É a conferência que pega
    // dois campos vizinhos trocados de lugar — e foi precisa: com
    // `quantos_modos` e `modo_atual` invertidos na struct, o relatório saía
    // com "modo 30 de 0" e todo o resto conferia. A geometria vem de outra
    // estrutura, então ela continuava certa.
    let (atual, total) = video
        .rsplit("modo ")
        .next()
        .and_then(|r| r.split_once(" de "))
        .and_then(|(a, t)| Some((a.trim().parse::<u32>().ok()?, t.trim().parse::<u32>().ok()?)))
        .ok_or_else(|| format!("não consegui ler o modo de `{video}`"))?;
    if total == 0 || atual >= total {
        return Err(format!(
            "o vídeo diz estar no modo {atual} de {total}, que não é um modo que exista"
        ));
    }

    Ok(())
}

/// O CRC-32 do Ethernet, para conferir o que o iniciador leu do disco.
///
/// # Por que uma segunda implementação
///
/// Pela mesma razão do `marca_do_setor`: as duas pontas rodam em máquinas
/// diferentes. Esta soma bytes que estão no disco do hospedeiro; a do
/// iniciador soma os bytes que chegaram à memória do emulador depois de
/// passarem pelo FAT, pelo firmware e por um laço de leitura. Um lugar comum
/// onde as duas coubessem não existe — o que impede a divergência é a
/// comparação, que é justamente o que se quer testar.
fn crc32_do_arquivo(caminho: &Path) -> Result<u32, String> {
    let bytes = std::fs::read(caminho)
        .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;

    let mut soma = !0u32;
    for byte in &bytes {
        soma ^= *byte as u32;
        for _ in 0..8 {
            // A forma refletida do polinômio 0x04C11DB7, que é o do Ethernet
            // e o que a UEFI usa.
            soma = if soma & 1 != 0 {
                (soma >> 1) ^ 0xEDB8_8320
            } else {
                soma >> 1
            };
        }
    }
    Ok(!soma)
}

/// Confronta o que o iniciador leu do ELF com o que o `llvm-readobj` lê.
///
/// # Por que isto é o teste que importa
///
/// Porque o iniciador e o `xtask` são o mesmo projeto: se eu errar o
/// deslocamento de `e_entry` no iniciador e conferir o resultado contra um
/// número que eu mesmo escrevi aqui, as duas metades concordam no erro.
///
/// O `llvm-readobj` não tem nada a ver com este projeto. Ele lê o **mesmo
/// arquivo** que foi para a ESP e diz o ponto de entrada e quantos segmentos
/// carregáveis existem. Se a leitura do iniciador divergir da dele, um dos
/// dois está errado — e não é o `llvm-readobj`.
///
/// É a mesma disciplina do `cargo xtask elf` sobre os programas de usuário, e
/// do `sgdisk`/`btrfs inspect-internal` sobre o disco.
fn conferir_elf_contra_readelf(
    arch: Arquitetura,
    relatorio: &[&str],
    kernel: &Path,
) -> Result<(), String> {
    let (readelf, estilo) = conferidor_de_elf()?;
    let saida = Command::new(&readelf)
        .args([estilo, "--file-header", "--program-headers"])
        .arg(kernel)
        .output()
        .map_err(|e| format!("não foi possível invocar o {}: {e}", readelf.display()))?;
    if !saida.status.success() {
        return Err("o llvm-readobj recusou o ELF do kernel".into());
    }
    let texto = String::from_utf8_lossy(&saida.stdout);

    let entrada_de_fora = texto
        .lines()
        .find_map(|l| l.trim().strip_prefix("Entry point address:"))
        .and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
        .ok_or("o llvm-readobj não disse o ponto de entrada")?;
    // As linhas de segmento começam com o tipo; `LOAD` é o que vai para a
    // memória. Elas aparecem uma vez cada na listagem de program headers.
    let carregaveis_de_fora = texto
        .lines()
        .filter(|l| l.trim_start().starts_with("LOAD "))
        .count();

    // Antes do cabeçalho, os bytes: o iniciador leu o arquivo inteiro, ou leu
    // o começo dele e acreditou? O CRC responde, e o cabeçalho ELF não.
    let esperado = crc32_do_arquivo(kernel)?;
    let esp = relatorio
        .iter()
        .find(|l| l.starts_with("esp:"))
        .ok_or("o iniciador não relatou a leitura da ESP")?;
    let lido = esp
        .split("crc ")
        .nth(1)
        .and_then(|h| u32::from_str_radix(h.trim().trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("não consegui ler o crc de `{esp}`"))?;
    if lido != esperado {
        return Err(format!(
            "o iniciador leu bytes com crc {lido:#010x}; o arquivo no disco tem \
             {esperado:#010x}"
        ));
    }
    let tamanho_de_fora = std::fs::metadata(kernel)
        .map(|m| m.len())
        .map_err(|e| format!("não foi possível medir {}: {e}", kernel.display()))?;
    let tamanho_do_iniciador: u64 = extrair_numero_antes(esp, "bytes em")
        .ok_or_else(|| format!("não consegui ler o tamanho de `{esp}`"))?;
    if tamanho_do_iniciador != tamanho_de_fora {
        return Err(format!(
            "o iniciador mediu o kernel em {tamanho_do_iniciador} bytes; o arquivo tem \
             {tamanho_de_fora}"
        ));
    }

    let linha = relatorio
        .iter()
        .find(|l| l.starts_with("elf:"))
        .ok_or("o iniciador não relatou o cabeçalho do ELF")?;
    let entrada_do_iniciador = linha
        .split("entrada em ")
        .nth(1)
        .and_then(|r| r.split(',').next())
        .and_then(|h| u64::from_str_radix(h.trim().trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("não consegui ler a entrada de `{linha}`"))?;

    let resumo = relatorio
        .iter()
        .find(|l| l.starts_with("kernel:"))
        .ok_or("o iniciador não relatou o resumo dos segmentos")?;
    let carregaveis_do_iniciador: usize = extrair_numero_antes(resumo, "segmentos")
        .ok_or_else(|| format!("não consegui contar os segmentos de `{resumo}`"))?
        as usize;

    if entrada_do_iniciador != entrada_de_fora {
        return Err(format!(
            "o iniciador leu a entrada como {entrada_do_iniciador:#x}; o llvm-readobj diz \
             {entrada_de_fora:#x}"
        ));
    }
    if carregaveis_do_iniciador != carregaveis_de_fora {
        return Err(format!(
            "o iniciador contou {carregaveis_do_iniciador} segmentos carregáveis; o \
             llvm-readobj conta {carregaveis_de_fora}"
        ));
    }

    // E as relocações. O iniciador do x86 aplica uma a uma; o do ARM ainda só
    // as classifica. Nos dois casos o número tem de bater com o que o
    // `llvm-readobj` conta no arquivo: uma tabela percorrida com o passo
    // errado, ou interrompida no meio, dá um número diferente — e no x86 isso
    // é um kernel que boota e falha no primeiro ponteiro constante que usar.
    //
    // Conferir o mesmo número nos dois lados é o que faz esta etapa do ARM
    // valer alguma coisa: ela afirma que o iniciador leu a tabela inteira e
    // reconheceu **todas** as entradas, que é a pergunta que o salto vai
    // depender de ter sido respondida.
    let relocacoes_de_fora = contar_relocacoes(&readelf, estilo, kernel)?;
    let (prefixo, sufixo) = match arch {
        Arquitetura::X86_64 => ("carga:", "relocacoes aplicadas"),
        Arquitetura::Aarch64 => ("kernel conferido:", "relocacoes relativas"),
    };
    let carga = relatorio
        .iter()
        .find(|l| l.starts_with(prefixo))
        .ok_or("o iniciador não relatou as relocações")?;
    let relocacoes_do_iniciador: u64 = extrair_numero_antes(carga, sufixo)
        .ok_or_else(|| format!("não consegui contar as relocações de `{carga}`"))?;
    if relocacoes_do_iniciador != relocacoes_de_fora {
        return Err(format!(
            "o iniciador aplicou {relocacoes_do_iniciador} relocações; o llvm-readobj \
             conta {relocacoes_de_fora} no arquivo"
        ));
    }

    println!(
        "  [conferido] {tamanho_de_fora} bytes com crc {esperado:#010x}, entrada \
         {entrada_de_fora:#x}, {carregaveis_de_fora} segmentos e {relocacoes_de_fora} \
         relocações — os três últimos iguais aos do llvm-readobj"
    );
    Ok(())
}

/// Quantas relocações o arquivo tem, segundo a ferramenta de fora.
fn contar_relocacoes(readelf: &Path, estilo: &str, kernel: &Path) -> Result<u64, String> {
    let saida = Command::new(readelf)
        .args([estilo, "--dyn-relocations"])
        .arg(kernel)
        .output()
        .map_err(|e| format!("não foi possível invocar o llvm-readobj: {e}"))?;
    if !saida.status.success() {
        return Err("o llvm-readobj recusou listar as relocações".into());
    }

    let texto = String::from_utf8_lossy(&saida.stdout);
    let relativas = texto
        .lines()
        .filter(|l| l.contains("R_X86_64_RELATIVE"))
        .count() as u64;

    // Qualquer outro tipo significa que o iniciador teria de resolver
    // símbolos, que ele recusa fazer. Contar só as relativas esconderia isso;
    // o total é que diz se há algo além delas.
    let total = texto.lines().filter(|l| l.contains("R_X86_64_")).count() as u64;
    if total != relativas {
        return Err(format!(
            "o kernel tem {} relocações que não são relativas; o iniciador as recusa",
            total - relativas
        ));
    }
    Ok(relativas)
}

/// O número que aparece imediatamente antes de `marca` numa linha.
fn extrair_numero_antes(linha: &str, marca: &str) -> Option<u64> {
    let antes = linha.split(marca).next()?;
    antes.split_whitespace().next_back()?.parse().ok()
}

/// Confere as imagens ELF dos programas de usuário com ferramenta de fora.
///
/// # Por que este comando existe
///
/// Os ELFs dos programas de exemplo são montados à mão, no mesmo bloco de
/// assembly que contém o código. O arranjo tem uma vantagem — cada byte do
/// cabeçalho é escolhido e conferível — e uma fraqueza óbvia: quem escreve o
/// cabeçalho e quem o lê são a mesma pessoa. Um mal-entendido sobre o formato
/// apareceria nos dois lados e se cancelaria, e o carregador "funcionaria"
/// sobre um ELF que nenhuma outra ferramenta aceitaria.
///
/// Este comando extrai as imagens de dentro do binário do kernel e as entrega
/// ao `llvm-readobj`, que não tem nada a ver com este projeto. Se ele lê os
/// cabeçalhos e os segmentos, o formato está certo por um caminho
/// independente.
fn conferir_elfs(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    build(arch, release, false)?;
    let kernel = caminho_elf(arch, release);
    let (readelf, estilo) = conferidor_de_elf()?;

    let bytes = std::fs::read(&kernel)
        .map_err(|e| format!("não foi possível ler {}: {e}", kernel.display()))?;
    let simbolos = simbolos_do_kernel(&kernel)?;

    let saida = raiz_do_projeto().join("target").join("elfs");
    std::fs::create_dir_all(&saida)
        .map_err(|e| format!("não foi possível criar {saida:?}: {e}"))?;

    // A lista sai dos **símbolos do kernel**, e não de um array aqui.
    //
    // Era um array, com quatro nomes escritos à mão. Ele já tinha divergido:
    // um programa novo entrou na tabela de embutidos do kernel e não aqui, e
    // a conferência independente — que é a razão de este comando existir —
    // simplesmente não o cobria. Nada reclamou, porque o array continuava
    // certo sobre os quatro que ele listava.
    //
    // Derivando do binário, um programa novo é conferido no dia em que
    // nasce, e um programa removido some daqui sozinho.
    let nomes = programas_embutidos(&simbolos);
    if nomes.is_empty() {
        return Err("nenhum simbolo `programa_*_inicio` no binario do kernel".into());
    }

    let mut falhou = false;
    for nome in &nomes {
        let inicio = buscar(&simbolos, &format!("programa_{nome}_inicio"))?;
        let fim = buscar(&simbolos, &format!("programa_{nome}_fim"))?;

        let a = deslocamento_no_arquivo(&bytes, inicio)?;
        let b = deslocamento_no_arquivo(&bytes, fim)?;
        if b <= a {
            return Err(format!("os rótulos de `{nome}` estão fora de ordem"));
        }

        let caminho = saida.join(format!("{nome}.elf"));
        std::fs::write(&caminho, &bytes[a..b])
            .map_err(|e| format!("não foi possível escrever {caminho:?}: {e}"))?;

        println!("\n[xtask] {nome}: {} bytes -> {}", b - a, caminho.display());
        let status = Command::new(&readelf)
            .args([estilo, "--file-header", "--program-headers"])
            .arg(&caminho)
            .status()
            .map_err(|e| format!("não foi possível invocar o llvm-readobj: {e}"))?;
        if !status.success() {
            eprintln!("[xtask] o llvm-readobj recusou a imagem de `{nome}`");
            falhou = true;
        }
    }

    if falhou {
        return Err("uma das imagens nao passou pelo llvm-readobj".into());
    }
    println!("\n[xtask] as imagens sao ELF64 validos para ferramenta de fora");
    Ok(ExitCode::SUCCESS)
}

/// Tabela `nome -> endereço` dos símbolos do kernel, via `llvm-nm`.
fn simbolos_do_kernel(kernel: &Path) -> Result<Vec<(String, u64)>, String> {
    let nm = ferramenta_llvm("llvm-nm")?;
    let saida = Command::new(&nm)
        .arg(kernel)
        .output()
        .map_err(|e| format!("não foi possível invocar o llvm-nm: {e}"))?;
    if !saida.status.success() {
        return Err("o llvm-nm falhou ao ler o binário do kernel".into());
    }

    let texto = String::from_utf8_lossy(&saida.stdout);
    let mut tabela = Vec::new();
    for linha in texto.lines() {
        // `<endereço> <tipo> <nome>`; símbolos indefinidos vêm sem endereço.
        let campos: Vec<&str> = linha.split_whitespace().collect();
        if campos.len() == 3
            && let Ok(endereco) = u64::from_str_radix(campos[0], 16)
        {
            tabela.push((campos[2].to_string(), endereco));
        }
    }
    Ok(tabela)
}

/// Confere que todo bloco `unsafe` declara a invariante de que depende.
///
/// # A convenção, e por que ela precisava de um fiscal
///
/// Este kernel escreve um comentário `SAFETY` acima de cada bloco `unsafe`,
/// dizendo o que torna aquela operação válida. Quando o bloco está dentro de
/// uma `unsafe fn` cujo doc já tem uma seção `# Safety`, a invariante é a da
/// função e não se repete.
///
/// A convenção é seguida em **todos** os blocos do projeto — quantos são, o
/// próprio comando diz ao terminar, e por isso o número não mora aqui
/// envelhecendo. O que faltava era fiscal: o primeiro bloco sem justificativa
/// entraria sem
/// que ninguém notasse, e o que se perde aí não é estilo. Um `unsafe` sem
/// invariante escrita é um `unsafe` cuja invariante ninguém conferiu — e num
/// kernel isso volta como corrupção em outro lugar.
///
/// # Como se sabe que ela confere alguma coisa
///
/// Semeando blocos que ela **tem** de reprovar e blocos que ela **tem** de
/// aceitar, e olhando quais aparecem. Foi assim que as duas primeiras versões
/// da regra caíram — ver [`tem_safety_cobrindo`], que conta as duas.
///
/// # A regra, deliberadamente frouxa
///
/// Ou há um `SAFETY` subindo até dez linhas sem atravessar o fim de outro
/// bloco, ou o bloco está dentro de uma `unsafe fn` com `# Safety` no doc —
/// ver [`tem_safety_cobrindo`], que conta como a regra chegou a essa forma.
/// Frouxa porque o objetivo é pegar o esquecimento, não arbitrar a redação:
/// exigir mais produziria ruído, e ruído é o que faz uma conferência ser
/// desligada.
fn conferir_invariantes() -> Result<ExitCode, String> {
    let passos = [
        conferir_blocos_unsafe()?,
        conferir_parametros_do_agente()?,
        conferir_arvore_do_readme()?,
        conferir_fase_do_readme()?,
    ];
    if passos.iter().all(|p| *p == ExitCode::SUCCESS) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

/// Confere que a fase que o kernel publica é a última que o roteiro dá por
/// feita.
///
/// # Por que isto virou conferência
///
/// Porque o banner, a primeira linha de log e o `phase` de `system.info`
/// disseram "fase 0" durante cinco fases. O número estava escrito à mão em
/// três lugares do kernel e o roteiro, noutro arquivo, dizia outra coisa; um
/// agente que perguntasse em que ponto o sistema estava recebia a resposta
/// do primeiro dia.
///
/// O kernel passou a ter um lugar só, `FASE` em `kernel/src/main.rs`. Esta
/// função liga esse lugar ao roteiro: a fase publicada tem de ser a maior
/// marcada como feita (`- [x] **Fase N`).
fn conferir_fase_do_readme() -> Result<ExitCode, String> {
    let raiz = raiz_do_projeto();
    let readme = std::fs::read_to_string(raiz.join("README.md"))
        .map_err(|e| format!("não foi possível ler o README: {e}"))?;
    let main = std::fs::read_to_string(raiz.join("kernel/src/main.rs"))
        .map_err(|e| format!("não foi possível ler o main.rs do kernel: {e}"))?;

    let feita = readme
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- [x] **Fase "))
        .filter_map(|resto| {
            let digitos: String = resto.chars().take_while(char::is_ascii_digit).collect();
            digitos.parse::<u32>().ok()
        })
        .max()
        .ok_or("o roteiro do README não tem nenhuma fase marcada como feita")?;

    let publicada = apos(&main, "pub const FASE: &str = \"")
        .and_then(|resto| resto.split('"').next())
        .ok_or("`pub const FASE` não foi encontrada em kernel/src/main.rs")?;

    if publicada == feita.to_string() {
        println!("[xtask] fase: o kernel publica a fase {feita}, a última feita no roteiro");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "[xtask] fase: o kernel publica a fase {publicada}, e a última marcada como feita \
             no roteiro do README é a {feita}"
        );
        Ok(ExitCode::FAILURE)
    }
}

/// Confere que a árvore de arquivos do README é a árvore que existe.
///
/// # Por que isto virou conferência
///
/// Porque tinha apodrecido. Quando esta função foi escrita, trinta dos oitenta
/// e nove arquivos de fonte não apareciam na árvore do README — um terço do
/// projeto, incluindo subsistemas inteiros: o sistema de arquivos, os
/// dispositivos virtio, o USB, a tela. E a árvore listava um `serial.rs` no
/// iniciador que já não existia.
///
/// Nada disso quebra o build, e é justamente esse o problema. Um mapa errado
/// é pior que nenhum mapa: quem chega ao projeto pelo README procura o código
/// de disco onde ele não está e conclui que não há.
///
/// # Como a conferência é feita, e por que por contagem
///
/// Contando nomes de arquivo, dos dois lados. Reconstruir o caminho completo
/// de cada linha exigiria interpretar o recuo dos desenhos de árvore, o que é
/// frágil por um ganho pequeno; contar pega as duas direções que importam —
/// um arquivo novo que ninguém documentou, e um documentado que já não
/// existe. Nomes repetem (`mod.rs` aparece dezenas de vezes), então o que se
/// compara é quantas vezes cada nome aparece em cada lado.
fn conferir_arvore_do_readme() -> Result<ExitCode, String> {
    use std::collections::BTreeMap;

    let raiz = raiz_do_projeto();
    let readme = std::fs::read_to_string(raiz.join("README.md"))
        .map_err(|e| format!("não foi possível ler o README: {e}"))?;

    let arvore = {
        let de = readme
            .find("kernel/src/\n")
            .ok_or("a árvore de arquivos não foi encontrada no README")?;
        let ate = readme[de..]
            .find("```")
            .ok_or("o fim da árvore de arquivos não foi encontrado")?;
        &readme[de..de + ate]
    };

    let mut no_readme: BTreeMap<&str, usize> = BTreeMap::new();
    for linha in arvore.lines() {
        for palavra in linha.split_whitespace() {
            if palavra.ends_with(".rs") || palavra.ends_with(".ld") {
                *no_readme.entry(palavra).or_default() += 1;
            }
        }
    }

    let mut no_disco: BTreeMap<String, usize> = BTreeMap::new();
    for sub in ["kernel/src", "iniciador/src", "protocolo/src", "xtask/src"] {
        percorrer_fontes_e_ligacao(&raiz.join(sub), &mut |caminho| {
            let nome = caminho
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("nome de arquivo ilegível")?
                .to_string();
            *no_disco.entry(nome).or_default() += 1;
            Ok(())
        })?;
    }

    let mut queixas: Vec<String> = Vec::new();
    for (nome, quantos) in &no_disco {
        let documentados = no_readme.get(nome.as_str()).copied().unwrap_or(0);
        if documentados < *quantos {
            queixas.push(format!(
                "`{nome}` existe {quantos}x e a árvore do README mostra {documentados}x"
            ));
        }
    }
    for (nome, quantos) in &no_readme {
        let existem = no_disco.get(*nome).copied().unwrap_or(0);
        if existem < *quantos {
            queixas.push(format!(
                "a árvore do README mostra `{nome}` {quantos}x e existem {existem}x"
            ));
        }
    }

    if !queixas.is_empty() {
        eprintln!("[xtask] a árvore do README não é a árvore que existe:");
        for q in &queixas {
            eprintln!("  {q}");
        }
        eprintln!(
            "\nA seção `## Arquitetura` do README é o mapa por onde alguém entra neste \
             projeto. Um arquivo novo entra nela junto com o código."
        );
        return Ok(ExitCode::FAILURE);
    }

    let total: usize = no_disco.values().sum();
    println!("[xtask] {total} arquivos de fonte, todos na árvore do README");
    Ok(ExitCode::SUCCESS)
}

/// Confere que um comando do agente diz a mesma coisa nos três lugares onde
/// ele é descrito.
///
/// # A regra, e por que ela cai calada
///
/// Cada comando do agente declara seus parâmetros num `ParamSpec` e os lê
/// com `member("...")` no handler. Os dois lados têm de dizer o mesmo nome, e
/// nada os obriga:
///
/// - um nome declarado e não lido é um parâmetro que o agente pode mandar e
///   que não faz nada. Pior: a validação o **aceita**, porque ele consta da
///   lista, então nem erro sai;
/// - um nome lido e não declarado é um parâmetro que o handler usaria e que a
///   validação **recusa** antes de chegar lá, porque ela reprova todo campo
///   que não esteja na lista. O comando fica com uma opção inalcançável.
///
/// Nas duas direções o sintoma é o mesmo: silêncio. Nenhum teste de resposta
/// pega isso, porque a resposta continua saindo — só ignora o que lhe
/// pediram.
///
/// # O terceiro lugar
///
/// A tabela de comandos do README, que é uma cópia à mão desta. O README
/// afirmava que ela era gerada do registro e que refletia sempre a verdade;
/// seis comandos tinham entrado no kernel sem passar por ela. Um comando fora
/// da tabela existe e ninguém descobre — e a afirmação de que não podia
/// acontecer era o que garantia que ninguém fosse conferir.
///
/// Nenhuma divergência quando esta função foi escrita, em comando nenhum. É
/// por isso mesmo que ela existe — a primeira vai entrar do mesmo jeito que
/// estas não entraram, sem ninguém notar.
fn conferir_parametros_do_agente() -> Result<ExitCode, String> {
    let caminho = raiz_do_projeto().join("kernel/src/agent/commands.rs");
    let texto = std::fs::read_to_string(&caminho)
        .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;

    let tabela = {
        let de = texto
            .find("pub static COMANDOS")
            .ok_or("a tabela COMANDOS não foi encontrada")?;
        let ate = texto[de..]
            .find("\n];\n")
            .ok_or("o fim da tabela COMANDOS não foi encontrado")?;
        &texto[de..de + ate]
    };

    let readme = std::fs::read_to_string(raiz_do_projeto().join("README.md"))
        .map_err(|e| format!("não foi possível ler o README: {e}"))?;

    let mut queixas: Vec<String> = Vec::new();
    let mut conferidos = 0usize;
    let mut na_tabela: Vec<String> = Vec::new();

    for bloco in tabela.split("Command {").skip(1) {
        let nomes: Vec<&str> = entre_aspas_apos(bloco, "nome: \"");
        let Some((comando, params)) = nomes.split_first() else {
            continue;
        };
        let Some(handler) = apos(bloco, "handler: ").map(identificador) else {
            queixas.push(format!("{comando}: não declara handler"));
            continue;
        };

        let Some(corpo) = corpo_da_funcao(&texto, handler) else {
            queixas.push(format!(
                "{comando}: o handler `{handler}` não foi encontrado"
            ));
            continue;
        };
        let lidos = entre_aspas_apos(corpo, "member(\"");
        conferidos += 1;
        na_tabela.push((*comando).to_string());

        // A tabela do README é uma cópia à mão do que está aqui. Quando esta
        // conferência entrou, seis comandos já tinham escapado dela — e o
        // próprio README dizia que ela era gerada e refletia sempre a verdade.
        if !readme.contains(&format!("| `{comando}` |")) {
            queixas.push(format!("{comando}: não aparece na tabela do README"));
        }

        for p in params {
            if !lidos.contains(p) {
                queixas.push(format!("{comando}: declara `{p}` e nunca o lê"));
            }
        }
        for l in &lidos {
            if !params.contains(l) {
                queixas.push(format!("{comando}: lê `{l}` e não o declara"));
            }
        }
    }

    // E a direção contrária: uma linha do README para um comando que saiu.
    for linha in readme.lines() {
        let Some(resto) = linha.strip_prefix("| `") else {
            continue;
        };
        let Some(nome) = resto.split('`').next() else {
            continue;
        };
        // Só o que tem forma de nome de comando: `<subsistema>.<ação>`, que é a
        // convenção do módulo. Sem isto, qualquer outra tabela do README com
        // uma célula em crase e um ponto — um `Cargo.toml`, um `0.1.0` —
        // viraria um comando inexistente.
        if !parece_nome_de_comando(nome) {
            continue;
        }
        if !na_tabela.iter().any(|c| c == nome) {
            queixas.push(format!("{nome}: está na tabela do README e não existe"));
        }
    }

    if !queixas.is_empty() {
        eprintln!("[xtask] o agente descrito de um lado só:");
        for q in &queixas {
            eprintln!("  {q}");
        }
        eprintln!(
            "\nUm comando do agente é descrito em três lugares, e os três têm de dizer \
             o mesmo: o `ParamSpec` que o declara, o `member(\"...\")` que o handler lê \
             e a linha da tabela do README. A validação recusa todo campo fora da \
             lista e ignora em silêncio todo campo da lista que o handler não leia; a \
             tabela do README é por onde alguém descobre que o comando existe."
        );
        return Ok(ExitCode::FAILURE);
    }

    println!(
        "[xtask] {conferidos} comandos do agente: parâmetros declarados e lidos batem, \
         e todos estão na tabela do README"
    );
    Ok(ExitCode::SUCCESS)
}

/// Tem forma de nome de comando do agente: `<subsistema>.<ação>`.
fn parece_nome_de_comando(nome: &str) -> bool {
    let Some((sub, acao)) = nome.split_once('.') else {
        return false;
    };
    let identificador = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    identificador(sub) && identificador(acao)
}

/// O texto logo depois de `marca`, se ela aparecer.
fn apos<'t>(texto: &'t str, marca: &str) -> Option<&'t str> {
    texto.find(marca).map(|i| &texto[i + marca.len()..])
}

/// O identificador no começo de `texto`.
fn identificador(texto: &str) -> &str {
    let fim = texto
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(texto.len());
    &texto[..fim]
}

/// Cada trecho entre aspas que venha logo depois de uma ocorrência de `marca`.
fn entre_aspas_apos<'t>(texto: &'t str, marca: &str) -> Vec<&'t str> {
    let mut achados = Vec::new();
    let mut resto = texto;
    while let Some(depois) = apos(resto, marca) {
        match depois.find('"') {
            Some(fim) => {
                achados.push(&depois[..fim]);
                resto = &depois[fim..];
            }
            None => break,
        }
    }
    achados
}

/// O corpo de `fn <nome>(`, do cabeçalho até a chave que o fecha na coluna
/// zero.
fn corpo_da_funcao<'t>(texto: &'t str, nome: &str) -> Option<&'t str> {
    let marca = format!("\nfn {nome}(");
    let de = texto.find(&marca)?;
    let resto = &texto[de + 1..];
    let ate = resto.find("\n}\n")?;
    Some(&resto[..ate])
}

fn conferir_blocos_unsafe() -> Result<ExitCode, String> {
    let raiz = raiz_do_projeto();
    let mut faltando: Vec<String> = Vec::new();
    let mut total = 0usize;

    for sub in ["kernel/src", "iniciador/src", "protocolo/src"] {
        percorrer_fontes(&raiz.join(sub), &mut |caminho| {
            let texto = std::fs::read_to_string(caminho)
                .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
            let linhas: Vec<&str> = texto.lines().collect();

            for (i, linha) in linhas.iter().enumerate() {
                if !bloco_unsafe(linha) {
                    continue;
                }
                total += 1;
                if tem_safety_cobrindo(&linhas, i) {
                    continue;
                }
                if dentro_de_unsafe_fn_documentada(&linhas, i) {
                    continue;
                }
                faltando.push(format!("{}:{}  {}", caminho.display(), i + 1, linha.trim()));
            }
            Ok(())
        })?;
    }

    if !faltando.is_empty() {
        eprintln!(
            "[xtask] {} bloco(s) `unsafe` sem invariante declarada:",
            faltando.len()
        );
        for f in &faltando {
            eprintln!("  {f}");
        }
        eprintln!(
            "\nEscreva um comentário `SAFETY:` acima do bloco, dizendo o que o torna \
             válido — ou ponha o bloco dentro de uma `unsafe fn` cujo doc tenha `# Safety`."
        );
        return Ok(ExitCode::FAILURE);
    }

    println!("[xtask] {total} blocos `unsafe`, todos com a invariante declarada");
    Ok(ExitCode::SUCCESS)
}

/// Há um `SAFETY` cobrindo o bloco da linha `i`?
///
/// # As duas versões erradas que vieram antes
///
/// A primeira olhava oito linhas para trás e aceitava qualquer `SAFETY` nelas.
/// Oito linhas é mais ou menos a distância entre dois blocos vizinhos, então
/// um bloco herdava a justificativa do bloco anterior — e isso não é um risco
/// teórico: foi assim que a primeira mutação semeada passou sem ser vista.
///
/// A segunda parava no primeiro pedaço de código, exigindo o comentário
/// colado. Reprovou dez blocos legítimos do projeto, todos do mesmo formato:
///
/// ```text
/// // SAFETY: ...
/// let status =
///     unsafe { (boot.alocar_pool)(...) };
/// ```
///
/// O `unsafe` mora na continuação de uma expressão cuja primeira linha é que
/// leva o comentário. Exigir colagem aí seria exigir que o código fosse
/// escrito de outro jeito para agradar a conferência.
///
/// # A regra que ficou
///
/// Sobe até dez linhas, atravessando código e comentário, e **para numa chave
/// de fechamento**. A chave é a fronteira que faltava: ela marca o fim do
/// bloco anterior, e é justamente o que separa "o `SAFETY` é meu" de "o
/// `SAFETY` é do vizinho".
fn tem_safety_cobrindo(linhas: &[&str], i: usize) -> bool {
    const ALCANCE: usize = 10;
    for j in (i.saturating_sub(ALCANCE)..i).rev() {
        let l = linhas[j].trim_start();
        if l.starts_with('}') {
            return false;
        }
        if l.starts_with("//") && l.contains("SAFETY") {
            return true;
        }
    }
    false
}

/// Uma linha que abre um bloco `unsafe`, e não uma que só menciona a palavra.
fn bloco_unsafe(linha: &str) -> bool {
    let Some(em) = linha.find("unsafe") else {
        return false;
    };
    // `unsafe fn`, `unsafe impl` e `unsafe trait` não são blocos.
    let resto = linha[em + "unsafe".len()..].trim_start();
    resto.starts_with('{')
}

/// O bloco da linha `i` está dentro de uma `unsafe fn` com `# Safety`?
fn dentro_de_unsafe_fn_documentada(linhas: &[&str], i: usize) -> bool {
    // Sobe até a primeira assinatura de função. É uma heurística de coluna,
    // e basta: este projeto não aninha funções dentro de funções fora de
    // blocos de teste, e lá o `unsafe` vem com `SAFETY` próprio.
    for j in (0..=i).rev() {
        let l = linhas[j];
        let recuo = l.len() - l.trim_start().len();
        let t = l.trim_start();
        let assinatura = t.starts_with("fn ")
            || t.starts_with("pub fn ")
            || t.starts_with("unsafe fn ")
            || t.starts_with("pub unsafe fn ")
            || t.starts_with("pub(crate) unsafe fn ")
            || t.starts_with("pub(crate) fn ")
            || t.starts_with("const fn ")
            || t.starts_with("pub const fn ")
            || t.contains(" fn ");
        if !assinatura || recuo > 4 {
            continue;
        }
        if !t.contains("unsafe fn ") {
            return false;
        }
        // O doc fica acima da assinatura, possivelmente com atributos no meio.
        let mut k = j;
        while k > 0 {
            k -= 1;
            let d = linhas[k].trim_start();
            if let Some(corpo) = d.strip_prefix("///") {
                // O cabeçalho da seção, e não a menção a ela: uma linha de
                // prosa dizendo "veja a `# Safety` da função" satisfazia a
                // conferência sem que seção nenhuma existisse. Medido — foi
                // exatamente assim que a primeira mutação escapou.
                if corpo.trim() == "# Safety" {
                    return true;
                }
                continue;
            }
            if d.starts_with("#[") || d.starts_with("//") || d.is_empty() {
                continue;
            }
            break;
        }
        return false;
    }
    false
}

/// Chama `f` para cada arquivo `.rs` ou `.ld` sob `dir`.
///
/// O `linker.ld` entra porque ele é fonte como qualquer outra: o layout de
/// memória do kernel ARM mora lá, e a árvore do README o documenta.
fn percorrer_fontes_e_ligacao(
    dir: &Path,
    f: &mut impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let entradas = std::fs::read_dir(dir)
        .map_err(|e| format!("não foi possível listar {}: {e}", dir.display()))?;
    for entrada in entradas {
        let entrada = entrada.map_err(|e| format!("erro ao listar {}: {e}", dir.display()))?;
        let caminho = entrada.path();
        if caminho.is_dir() {
            percorrer_fontes_e_ligacao(&caminho, f)?;
        } else if caminho.extension().is_some_and(|e| e == "rs" || e == "ld") {
            f(&caminho)?;
        }
    }
    Ok(())
}

/// Chama `f` para cada arquivo `.rs` sob `dir`.
fn percorrer_fontes(
    dir: &Path,
    f: &mut impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let entradas = std::fs::read_dir(dir)
        .map_err(|e| format!("não foi possível listar {}: {e}", dir.display()))?;
    for entrada in entradas {
        let entrada = entrada.map_err(|e| format!("erro ao listar {}: {e}", dir.display()))?;
        let caminho = entrada.path();
        if caminho.is_dir() {
            percorrer_fontes(&caminho, f)?;
        } else if caminho.extension().is_some_and(|e| e == "rs") {
            f(&caminho)?;
        }
    }
    Ok(())
}

/// Os programas embutidos, deduzidos dos símbolos `programa_<nome>_inicio`.
///
/// Ordenados para que a saída do comando não dependa da ordem em que o
/// `llvm-nm` resolveu listar: um relatório que muda de ordem entre execuções
/// é um relatório que ninguém consegue comparar com o anterior.
fn programas_embutidos(tabela: &[(String, u64)]) -> Vec<String> {
    let mut nomes: Vec<String> = tabela
        .iter()
        .filter_map(|(s, _)| s.strip_prefix("programa_")?.strip_suffix("_inicio"))
        .map(str::to_string)
        .collect();
    nomes.sort();
    nomes.dedup();
    nomes
}

fn buscar(tabela: &[(String, u64)], nome: &str) -> Result<u64, String> {
    tabela
        .iter()
        .find(|(s, _)| s == nome)
        .map(|(_, e)| *e)
        .ok_or_else(|| format!("símbolo `{nome}` não encontrado no binário do kernel"))
}

/// Onde, dentro do arquivo, mora um endereço virtual do kernel.
///
/// Percorre os segmentos `PT_LOAD` do próprio binário. É um parser de ELF de
/// dez linhas porque é tudo que precisamos — e porque a alternativa seria
/// interpretar a saída de texto de outra ferramenta, que muda de formato entre
/// versões sem avisar.
fn deslocamento_no_arquivo(elf: &[u8], virtual_: u64) -> Result<usize, String> {
    let ler_u64 = |p: usize| -> u64 {
        let mut o = [0u8; 8];
        o.copy_from_slice(&elf[p..p + 8]);
        u64::from_le_bytes(o)
    };
    let ler_u16 = |p: usize| -> u16 { u16::from_le_bytes([elf[p], elf[p + 1]]) };

    if elf.len() < 64 || &elf[..4] != b"\x7fELF" {
        return Err("o binário do kernel não é um ELF".into());
    }
    let tabela = ler_u64(32) as usize;
    let tamanho = ler_u16(54) as usize;
    let quantos = ler_u16(56) as usize;

    for i in 0..quantos {
        let base = tabela + i * tamanho;
        if base + 56 > elf.len() {
            break;
        }
        // 1 = PT_LOAD.
        if u32::from_le_bytes([elf[base], elf[base + 1], elf[base + 2], elf[base + 3]]) != 1 {
            continue;
        }
        let deslocamento = ler_u64(base + 8);
        let vaddr = ler_u64(base + 16);
        let no_arquivo = ler_u64(base + 32);
        if virtual_ >= vaddr && virtual_ < vaddr + no_arquivo {
            return Ok((deslocamento + (virtual_ - vaddr)) as usize);
        }
    }
    Err(format!(
        "o endereço {virtual_:#x} não está em nenhum segmento carregável"
    ))
}

/// Caminho do ELF compilado, que é onde vivem os símbolos e o DWARF.
///
/// O que o QEMU carrega é outra coisa: no x86 uma imagem de disco, no ARM um
/// binário cru sem metadado nenhum. Depurar exige os dois lados — o emulador
/// executa a imagem, o depurador lê o ELF.
fn caminho_elf(arch: Arquitetura, release: bool) -> PathBuf {
    raiz_do_projeto()
        .join("kernel")
        .join("target")
        .join(arch.alvo())
        .join(if release { "release" } else { "debug" })
        .join(NOME_DO_BINARIO)
}

/// Porta TCP onde o QEMU expõe o protocolo de depuração remota.
const PORTA_GDB: u16 = 1234;

/// Sobe o kernel parado na primeira instrução, esperando um depurador.
///
/// # O que isto resolve
///
/// Até agora a depuração deste kernel se apoiava no canal do agente: o
/// próprio sistema conta o que aconteceu. É uma ferramenta excelente, mas tem
/// dois limites intransponíveis. Ela não funciona *antes* de o canal existir —
/// o trecho de boot mais escuro é justamente o anterior a ele —, e não
/// funciona quando o kernel morre de um jeito que o modo post-mortem não
/// alcança, como um triple fault que reinicia a máquina.
///
/// O QEMU resolve os dois de uma vez: ele implementa o protocolo de depuração
/// remota do GDB, o que dá breakpoint, execução passo a passo, pilha de
/// chamadas, variáveis locais e registradores num kernel bare-metal, desde a
/// primeira instrução. Isto aqui é só a plumbagem: sobe o emulador congelado e
/// imprime a linha exata para conectar.
fn depurar(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release, false)?;
    let elf = caminho_elf(arch, release);
    let socket = caminho_socket(arch);

    let mut qemu = comando_qemu(arch, &artefato, Some(&socket), Teclado::Nativo)?;
    // `-S` congela a CPU antes da primeira instrução; `-gdb` abre o servidor.
    // Sem o `-S`, o kernel bootaria inteiro antes de dar tempo de conectar, e
    // qualquer breakpoint de boot seria perdido.
    qemu.arg("-S").args(["-gdb", &format!("tcp::{PORTA_GDB}")]);

    println!("[xtask] kernel congelado antes da primeira instrucao");
    println!("[xtask] servidor de depuracao em localhost:{PORTA_GDB}\n");
    println!("[xtask] conecte de outro terminal com:\n");
    for linha in receita_do_depurador(arch, &elf) {
        println!("    {linha}");
    }
    println!("\n[xtask] ja conectado, um primeiro passo util:\n");
    for linha in primeiros_passos(arch) {
        println!("    {linha}");
    }
    println!(
        "\n[xtask] o canal do agente continua em {}\n",
        socket.display()
    );

    qemu.status()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    Ok(ExitCode::SUCCESS)
}

/// A linha de comando que conecta o depurador certo ao kernel certo.
///
/// O x86 precisa do `add-symbol-file` com deslocamento porque o binário é
/// independente de posição e o bootloader o carrega na metade alta; sem isso o
/// GDB conecta, funciona, e mostra endereços sem nome nenhum — a pior forma de
/// falhar, porque parece estar funcionando.
fn receita_do_depurador(arch: Arquitetura, elf: &Path) -> Vec<String> {
    let dep = arch.depurador();
    match arch {
        Arquitetura::X86_64 => vec![format!(
            "{dep} -ex 'target remote localhost:{PORTA_GDB}' \\\n         \
             -ex 'add-symbol-file {} -o {:#x}'",
            elf.display(),
            arch.base_do_kernel()
        )],
        Arquitetura::Aarch64 => vec![format!(
            "{dep} -o 'settings set target.default-arch aarch64' \\\n         \
             -o 'target create {}' \\\n         \
             -o 'gdb-remote localhost:{PORTA_GDB}'",
            elf.display()
        )],
    }
}

/// O primeiro comando útil depois de conectar, na sintaxe de cada depurador.
///
/// Os dois falam o mesmo protocolo com o QEMU, mas não a mesma língua: o GDB
/// resolve um caminho de módulo Rust inteiro em `break`, enquanto o LLDB casa
/// por nome de função em `breakpoint set --name` e não aceita o caminho
/// completo — um detalhe que custa uns minutos de confusão na primeira vez.
fn primeiros_passos(arch: Arquitetura) -> Vec<&'static str> {
    match arch {
        Arquitetura::X86_64 => vec!["break duke::inicio_comum", "continue", "bt", "info locals"],
        Arquitetura::Aarch64 => vec![
            "breakpoint set --name inicio_comum",
            "continue",
            "bt",
            "frame variable",
        ],
    }
}

/// Traduz endereços de execução em arquivo, linha e função.
///
/// # Por que este comando existe
///
/// O canal do agente reporta o `pc` de uma exceção como um número cru — é a
/// decisão certa para o protocolo, porque o kernel não tem como carregar sua
/// própria tabela de símbolos. Mas do lado de fora esse número é inútil até
/// ser cruzado com o DWARF do binário, e fazer isso à mão toda vez é
/// exatamente o tipo de trabalho que some quando vira um comando.
///
/// Fecha o ciclo com `traps.stats`:
///
/// ```text
/// cargo xtask agent traps.stats        -> "pc": 18446603336221365869
/// cargo xtask simbolo 18446603336221365869
/// ```
fn simbolizar(arch: Arquitetura, release: bool, enderecos: &[&str]) -> Result<ExitCode, String> {
    if enderecos.is_empty() {
        return Err("uso: cargo xtask simbolo <endereco>... (decimal ou 0x...)".into());
    }

    let elf = caminho_elf(arch, release);
    if !elf.exists() {
        return Err(format!(
            "binário não encontrado em {}\ncompile antes com: cargo xtask build --arch {}{}",
            elf.display(),
            arch.nome(),
            if release { " --release" } else { "" }
        ));
    }

    let symbolizer = ferramenta_llvm("llvm-symbolizer")?;
    let base = arch.base_do_kernel();

    for bruto in enderecos {
        let endereco = interpretar_endereco(bruto)?;

        if endereco < base {
            println!("{bruto}: abaixo da base do kernel ({base:#x}); nao pertence a imagem");
            continue;
        }

        // O endereço que o DWARF conhece é o do binário, não o da execução.
        // `--adjust-vma` faz o `llvm-symbolizer` somar a base aos endereços do
        // binário antes de comparar, em vez de nós subtrairmos e perdermos a
        // referência original na saída.
        let saida = Command::new(&symbolizer)
            .arg(format!("--obj={}", elf.display()))
            .arg(format!("--adjust-vma={base:#x}"))
            .arg("--demangle")
            .arg("--functions=linkage")
            // Num kernel quase tudo é inlinado, e o quadro mais interno
            // costuma ser uma função da `core` que não diz nada — `pc` caindo
            // em `ptr::write_volatile` só vira informação quando se vê quem a
            // chamou. Esta opção traz a cadeia inteira.
            .arg("--inlining=true")
            .arg(format!("{endereco:#x}"))
            .output()
            .map_err(|e| format!("não foi possível invocar o llvm-symbolizer: {e}"))?;

        let texto = String::from_utf8_lossy(&saida.stdout);
        // A saída vem em pares: uma linha de função, uma de arquivo:linha. O
        // primeiro par é o quadro mais interno; os seguintes são quem o
        // inlinou, do mais próximo para o mais distante.
        let linhas: Vec<&str> = texto.lines().filter(|l| !l.trim().is_empty()).collect();

        println!("{endereco:#x}");
        if linhas.is_empty() || linhas[0] == "??" {
            // `??` é como o symbolizer diz "não sei", e repassar isso cru
            // deixaria o usuário achando que a ferramenta quebrou.
            println!("  sem informacao de simbolo neste endereco");
            println!("  (o binario corresponde ao que esta rodando? tente --release)");
            continue;
        }

        for (nivel, par) in linhas.chunks(2).enumerate() {
            let funcao = par[0];
            let local = par.get(1).map(|l| l.trim()).unwrap_or("");
            let marca = if nivel == 0 { "  " } else { "  inlinado em " };
            println!("{marca}{funcao}");
            if !local.is_empty() {
                println!("      {local}");
            }
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Aceita um endereço em decimal ou em hexadecimal com `0x`.
///
/// Os dois formatos aparecem de verdade: o canal do agente emite números JSON,
/// que são decimais, e um depurador imprime hexadecimal.
fn interpretar_endereco(bruto: &str) -> Result<u64, String> {
    let limpo = bruto.trim().replace('_', "");
    let resultado = match limpo
        .strip_prefix("0x")
        .or_else(|| limpo.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => limpo.parse(),
    };
    resultado.map_err(|_| format!("`{bruto}` não é um endereço válido (decimal ou 0x...)"))
}

/// Desmonta uma função do binário compilado.
///
/// # Por que isto ganhou um comando
///
/// Porque um bug real deste projeto teria sido encontrado em segundos por
/// aqui. O teste de estouro de pilha passava em debug e pendurava em release:
/// o otimizador reconhecia a recursão e a convertia num laço, que roda para
/// sempre sem consumir pilha. A evidência era direta — a versão release da
/// função não tinha instrução de chamada nenhuma —, mas só se alguém olhasse.
///
/// O filtro é por subcadeia porque nomes de símbolo em Rust carregam sufixo de
/// hash, e ninguém os digita por inteiro.
fn desmontar(arch: Arquitetura, release: bool, simbolo: &str) -> Result<ExitCode, String> {
    let elf = caminho_elf(arch, release);
    if !elf.exists() {
        return Err(format!(
            "binário não encontrado em {}\ncompile antes com: cargo xtask build --arch {}{}",
            elf.display(),
            arch.nome(),
            if release { " --release" } else { "" }
        ));
    }

    let objdump = ferramenta_llvm("llvm-objdump")?;
    let saida = Command::new(&objdump)
        .arg("--disassemble")
        .arg("--demangle")
        // Sem isto a saída é só instrução; com isto, cada trecho vem anotado
        // com a linha de Rust que o gerou, que é o que torna a comparação
        // entre debug e release legível.
        .arg("--source")
        .arg("--no-show-raw-insn")
        .arg(&elf)
        .output()
        .map_err(|e| format!("não foi possível invocar o llvm-objdump: {e}"))?;

    if !saida.status.success() {
        return Err(format!(
            "llvm-objdump falhou: {}",
            String::from_utf8_lossy(&saida.stderr).trim()
        ));
    }

    let texto = String::from_utf8_lossy(&saida.stdout);
    let mut dentro = false;
    let mut achou = false;

    for linha in texto.lines() {
        // Um cabeçalho de função tem a forma `<endereco> <nome>:`.
        if linha.ends_with(">:") {
            dentro = linha.contains(simbolo);
            if dentro {
                achou = true;
                println!();
            }
        }
        if dentro {
            println!("{linha}");
        }
    }

    if !achou {
        return Err(format!(
            "nenhum símbolo contendo `{simbolo}` no binário {}\n\
             dica: funções pequenas somem por inlining em release",
            elf.display()
        ));
    }

    Ok(ExitCode::SUCCESS)
}

/// O disco de testes, em setores de 512 bytes.
///
/// # Por que um disco de verdade, e não um padrão sintético
///
/// Porque o que veio antes era um megabyte preenchido por este arquivo, com
/// uma assinatura nossa no primeiro setor — e quem escrevia e quem lia eram
/// as duas metades do mesmo projeto. Servia para provar que o driver lia o
/// setor certo, e não servia para mais nada: não havia partição, tabela nem
/// sistema de arquivos para um kernel encontrar.
///
/// Agora o disco é montado pelas ferramentas do hospedeiro — `sgdisk`,
/// `mkfs.vfat`, `mkfs.btrfs` —, que não têm nada a ver com este projeto. O
/// que o kernel lê é uma GPT de verdade, uma ESP de verdade e um Btrfs de
/// verdade, e a conferência de fora existe: `mdir -i disco.img@@1M` lista a
/// ESP e `btrfs inspect-internal dump-tree` lê a raiz, os dois sem montar
/// nada e sem privilégio. É a mesma disciplina do `llvm-readelf` conferindo
/// os ELFs de usuário.
mod disco {
    /// O disco inteiro.
    pub const SETORES: u64 = 192 * 1024 * 1024 / 512;

    /// Onde a ESP começa e quanto ocupa.
    ///
    /// 2048 é onde toda ferramenta de particionamento começa a primeira
    /// partição: alinha a um mebibyte, que é o tamanho de bloco de apagamento
    /// de qualquer mídia moderna.
    pub const ESP_EM: u64 = 2048;
    pub const ESP_SETORES: u64 = 48 * 1024 * 1024 / 512;

    /// E a raiz, logo depois.
    pub const RAIZ_EM: u64 = ESP_EM + ESP_SETORES;
    pub const RAIZ_SETORES: u64 = 128 * 1024 * 1024 / 512;

    /// A faixa que a GPT reserva e ninguém usa: do fim das entradas de
    /// partição até o começo da primeira.
    ///
    /// É onde o padrão por setor continua morando. Ele não descreve mais o
    /// disco inteiro, mas o que ele prova é o mesmo de antes — que o driver
    /// leu o setor **certo**, e não um vizinho — e isso nenhum sistema de
    /// arquivos prova enquanto não existir.
    pub const PADRAO_DE: u64 = 34;
    pub const PADRAO_ATE: u64 = ESP_EM - 1;

    /// O byte com que o setor `numero` é preenchido.
    ///
    /// Esta regra é metade de um contrato cujo outro lado está no `testes.rs`
    /// do kernel. Duplicá-la é o preço de o disco ser gerado por um programa
    /// que roda no hospedeiro e lido por outro que roda no emulador — e é o
    /// teste do kernel que denuncia se as duas metades divergirem.
    pub fn marca_do_setor(numero: u64) -> u8 {
        (numero as u8).wrapping_mul(7).wrapping_add(1)
    }

    /// O que vai dentro da ESP e da raiz.
    ///
    /// Poucos arquivos, e com conteúdo reconhecível: o ponto não é exercitar
    /// um sistema de arquivos cheio, é ter alvos que um teste possa exigir
    /// pelo nome.
    pub const NA_ESP: &[(&str, &str)] = &[("NOTA.TXT", "esta nota mora na ESP\n")];
    pub const NA_RAIZ: &[(&str, &str)] = &[
        ("saudacao.txt", "ola do btrfs, lido pelo duke\n"),
        // Num subdiretório que **não** é `/bin`, de propósito: `/bin` é onde
        // os programas embutidos estão montados, e a regra da montagem mais
        // longa faria este arquivo ficar inalcançável. Um arquivo que o teste
        // não consegue abrir não testa a descida em subdiretório.
        ("dados/nota.txt", "uma nota num subdiretorio\n"),
    ];

    /// Quantos arquivos de enchimento a raiz leva, e por quê.
    ///
    /// # A árvore precisa ter por onde descer
    ///
    /// Com meia dúzia de arquivos e o tamanho de nó padrão, a árvore de
    /// arquivos do Btrfs cabe numa folha só. Um leitor que só soubesse ler
    /// uma folha passava em tudo — e passava **porque a imagem não tinha
    /// como reprová-lo**, não porque estivesse certo.
    ///
    /// Estes arquivos existem para que a árvore tenha nós internos de
    /// verdade. Combinados com [`TAMANHO_DE_NO`], eles espalham os itens por
    /// quatro folhas: os inodes dos arquivos nomeados caem em folhas
    /// diferentes, então abrir qualquer um deles exige descer pelas chaves.
    ///
    /// O conteúdo de cada um é o próprio número, e não um texto fixo: dois
    /// arquivos idênticos seriam deduplicados no mesmo item de extensão, e
    /// o enchimento encheria menos do que parece.
    pub const ENCHIMENTO: usize = 24;

    /// O tamanho de nó com que a imagem é formatada.
    ///
    /// # Por que quatro kilobytes, e não os dezesseis do padrão
    ///
    /// Porque é o que faz a árvore ganhar níveis com uma quantidade
    /// razoável de arquivos: com nós de dezesseis, seriam precisos uns
    /// duzentos arquivos para o mesmo efeito, e a imagem cresceria sem que
    /// nada além do enchimento mudasse.
    ///
    /// Ele também cobre uma segunda coisa de graça. O leitor do kernel lê o
    /// tamanho de nó do superbloco, e um valor diferente do padrão é o que
    /// prova que ele o **lê** em vez de assumir dezesseis kilobytes — uma
    /// constante escondida que só apareceria no primeiro disco formatado
    /// por outra pessoa.
    pub const TAMANHO_DE_NO: &str = "4096";

    /// Um arquivo grande demais para caber dentro do próprio item.
    ///
    /// # Por que ele existe
    ///
    /// Porque o Btrfs guarda arquivos pequenos **embutidos** no item de
    /// extensão, e todos os outros desta imagem são pequenos. Um leitor que
    /// só soubesse ler embutidos passaria em tudo, e o primeiro arquivo de
    /// verdade — um programa, um texto — cairia no caminho que ninguém
    /// exercitou.
    ///
    /// # Por que quarenta e oito kilobytes, e não oito
    ///
    /// Oito já passariam do teto de dois que o `mkfs.btrfs` usa para embutir,
    /// e já dariam uma extensão normal. Mas o driver de disco monta no
    /// máximo dezesseis kilobytes por ida, e o `ler_tudo` do VFS chama o
    /// sistema de arquivos **em laço** justamente porque uma leitura pode
    /// voltar pela metade. Com oito kilobytes o laço dava uma volta só, o
    /// deslocamento era sempre zero, e a aritmética que soma o deslocamento
    /// ao endereço lógico nunca era exercitada: dava para apagá-la e todo
    /// caso passava.
    ///
    /// Quarenta e oito forçam três voltas, com deslocamento 0, 16 Ki e 32 Ki.
    pub const GRANDE: (&str, usize) = ("grande.txt", 48 * 1024);

    /// O byte que mora na posição `i` do arquivo grande.
    ///
    /// # Por que não é uma palavra repetida
    ///
    /// Porque era, e não testava o que parecia testar. Com `duke` repetido,
    /// o pedaço que começa em 16 Ki é **idêntico** ao que começa em 0 — a
    /// palavra tem quatro bytes e 16384 é múltiplo de quatro. Uma volta do
    /// laço que fosse ao lugar errado traria bytes iguais aos certos, e a
    /// conferência byte a byte aprovava. Foi medido: `w[0..16384] ==
    /// w[16384..32768]`.
    ///
    /// Qualquer regra da forma "o byte `i` depende de `i % P`" tem o mesmo
    /// problema quando `P` divide 16384 — e 4, 256 e 512 todos dividem.
    ///
    /// Esta soma duas coisas: o índice do bloco de 256 bytes, que muda a cada
    /// bloco e só se repete depois de 64 Ki, e o próprio `i` vezes sete, que
    /// muda a cada byte. Um deslocamento de 16 Ki muda a primeira parcela;
    /// um de um byte muda a segunda. Nenhum dos dois passa despercebido.
    ///
    /// É metade de um contrato, como o `marca_do_setor`: a outra metade está
    /// no `testes.rs` do kernel.
    pub fn marca_do_grande(i: usize) -> u8 {
        ((i / 256) as u8).wrapping_add((i as u8).wrapping_mul(7))
    }
}

/// As ferramentas que montam o disco, e o pacote de cada uma.
const FERRAMENTAS_DO_DISCO: &[(&str, &str)] = &[
    ("sgdisk", "gdisk"),
    ("mkfs.vfat", "dosfstools"),
    ("mcopy", "mtools"),
    ("mkfs.btrfs", "btrfs-progs"),
];

/// A descrição de tudo que decide o conteúdo do disco.
///
/// # Por que um resumo, e não a comparação do arquivo inteiro
///
/// Porque o disco passou de um megabyte para cento e noventa e dois, e ele é
/// lido uma vez por invocação do QEMU. A versão anterior comparava byte a
/// byte, o que era barato no tamanho antigo e não é mais.
///
/// O que a comparação garantia continua garantido: o arquivo sobrevive ao que
/// o gerou — mora em `target/`, que o CI mantém em cache — e um disco gerado
/// por uma versão anterior desta função continuaria sendo usado por esta. O
/// resumo cobre tudo que entra na receita, então mudar qualquer coisa aqui
/// invalida o disco que está lá.
/// Todos os arquivos que vão para dentro da partição de dados.
///
/// # Por que uma função, e não duas listas
///
/// Porque quem monta a imagem e quem decide se ela precisa ser remontada
/// precisam olhar **a mesma coisa**. Enquanto eram dois lugares, um arquivo
/// novo entrava na imagem sem entrar na receita — e a imagem velha ficava no
/// lugar, com a suíte rodando contra um disco que já não era o que o código
/// descrevia.
fn arquivos_da_raiz() -> Vec<(String, Vec<u8>)> {
    let mut arquivos: Vec<(String, Vec<u8>)> = disco::NA_RAIZ
        .iter()
        .map(|(nome, conteudo)| ((*nome).to_string(), conteudo.as_bytes().to_vec()))
        .collect();

    let (nome_grande, tamanho) = disco::GRANDE;
    arquivos.push((
        nome_grande.to_string(),
        (0..tamanho).map(disco::marca_do_grande).collect(),
    ));

    // O enchimento que dá níveis à árvore. Ver `disco::ENCHIMENTO`.
    for i in 1..=disco::ENCHIMENTO {
        arquivos.push((
            format!("enche-{i}.txt"),
            format!("enchimento numero {i}\n").into_bytes(),
        ));
    }
    arquivos
}

/// Os argumentos com que a partição de dados é formatada.
///
/// Mesma razão da lista acima: eles entram na receita inteiros, então um
/// parâmetro novo de formatação passa a exigir a remontagem sem que ninguém
/// precise lembrar de acrescentá-lo em dois lugares.
fn argumentos_do_mkfs(arvore: &Path, raiz: &str) -> Vec<String> {
    vec![
        "--rootdir".into(),
        arvore.display().to_string(),
        "--nodesize".into(),
        disco::TAMANHO_DE_NO.into(),
        "-f".into(),
        "-L".into(),
        "duke-raiz".into(),
        raiz.into(),
    ]
}

fn receita_do_disco() -> String {
    // Tudo que muda a imagem precisa estar aqui, e isso não é uma regra que
    // alguém precise lembrar: a receita é montada a partir das **mesmas**
    // funções que montam o disco. Foi o que faltava quando o tamanho de nó
    // entrou — a lista de parâmetros era uma segunda cópia, o disco velho
    // ficou no lugar, e os casos da descida reprovaram dizendo a verdade
    // sobre uma imagem que já não existia no código.
    let mut receita = format!(
        "v6 setores={} esp={}+{} raiz={}+{} padrao={}..{}\n",
        disco::SETORES,
        disco::ESP_EM,
        disco::ESP_SETORES,
        disco::RAIZ_EM,
        disco::RAIZ_SETORES,
        disco::PADRAO_DE,
        disco::PADRAO_ATE,
    );

    // Os argumentos de formatação, com os caminhos neutralizados: eles
    // dependem de onde o projeto está, e a receita precisa descrever a
    // imagem, não a máquina que a montou.
    receita.push_str("mkfs =");
    for argumento in argumentos_do_mkfs(Path::new("<arvore>"), "<raiz>") {
        receita.push(' ');
        receita.push_str(&argumento);
    }
    receita.push('\n');

    for (nome, conteudo) in disco::NA_ESP {
        receita.push_str(&format!("{nome} = {conteudo}"));
    }

    // Os arquivos da raiz entram por resumo, e não por conteúdo: o
    // `grande.txt` sozinho tem quarenta e oito kilobytes, e uma receita
    // desse tamanho seria relida a cada invocação do `xtask`. O tamanho mais
    // um byte do meio distinguem tudo que muda de verdade — é a mesma
    // aposta que a marca do arquivo grande já faz.
    for (nome, conteudo) in arquivos_da_raiz() {
        let meio = conteudo.get(conteudo.len() / 2).copied().unwrap_or(0);
        receita.push_str(&format!("{nome} = {} bytes, meio={meio}\n", conteudo.len()));
    }
    receita
}

/// Escreve um arquivo dentro da árvore que vai virar a raiz, criando os
/// diretórios do caminho.
fn escrever_na_arvore(arvore: &Path, nome: &str, conteudo: &[u8]) -> Result<(), String> {
    let destino = arvore.join(nome);
    if let Some(pai) = destino.parent() {
        std::fs::create_dir_all(pai)
            .map_err(|e| format!("não foi possível criar {}: {e}", pai.display()))?;
    }
    std::fs::write(&destino, conteudo).map_err(|e| format!("não foi possível escrever {nome}: {e}"))
}

/// Roda uma ferramenta do hospedeiro e devolve erro com o que ela disse.
fn ferramenta(nome: &str, args: &[&str]) -> Result<(), String> {
    let saida = Command::new(nome)
        .args(args)
        .output()
        .map_err(|e| format!("não foi possível executar `{nome}`: {e}"))?;
    if saida.status.success() {
        return Ok(());
    }
    Err(format!(
        "`{nome}` falhou: {}{}",
        String::from_utf8_lossy(&saida.stderr).trim(),
        String::from_utf8_lossy(&saida.stdout).trim()
    ))
}

/// Monta o disco de testes com as ferramentas do hospedeiro.
fn montar_disco(caminho: &Path) -> Result<(), String> {
    let faltando: Vec<&str> = FERRAMENTAS_DO_DISCO
        .iter()
        .filter(|(binario, _)| which(binario).is_none())
        .map(|(_, pacote)| *pacote)
        .collect();
    if !faltando.is_empty() {
        return Err(format!(
            "o disco de testes precisa de ferramentas que não estão instaladas.\n\
             instale: apt-get install -y {}",
            faltando.join(" ")
        ));
    }

    let alvo = caminho.parent().ok_or("o disco não tem diretório")?;
    std::fs::create_dir_all(alvo)
        .map_err(|e| format!("não foi possível criar o diretório do disco: {e}"))?;

    let imagem = caminho.display().to_string();
    let esp = alvo.join("esp.img").display().to_string();
    let raiz = alvo.join("raiz.img").display().to_string();
    let arvore = alvo.join("raiz-do-disco");

    // A imagem inteira, zerada, antes de qualquer coisa.
    let vazio = vec![0u8; (disco::SETORES * 512) as usize];
    std::fs::write(caminho, &vazio)
        .map_err(|e| format!("não foi possível criar a imagem do disco: {e}"))?;

    // A tabela de partições. `sgdisk` escreve também o MBR de proteção, que é
    // o que impede uma ferramenta antiga de achar o disco vazio e o
    // reparticionar.
    ferramenta("sgdisk", &["-o", &imagem])?;
    ferramenta(
        "sgdisk",
        &[
            "-n",
            // O `M` do sufixo não é decoração: sem ele o `sgdisk` lê o número
            // como **setores**, e a partição sai mil vezes menor. Foi o que
            // aconteceu, e quem acusou foi o `sgdisk -p` conferindo de fora —
            // as duas partições tinham o conteúdo certo, depositado por
            // deslocamento, e a tabela descrevia 24 KiB e 64 KiB.
            &format!(
                "1:{}:+{}M",
                disco::ESP_EM,
                disco::ESP_SETORES * 512 / 1024 / 1024
            ),
            "-t",
            "1:ef00",
            "-c",
            "1:ESP",
            &imagem,
        ],
    )?;
    ferramenta(
        "sgdisk",
        &[
            "-n",
            &format!(
                "2:{}:+{}M",
                disco::RAIZ_EM,
                disco::RAIZ_SETORES * 512 / 1024 / 1024
            ),
            "-t",
            "2:8300",
            "-c",
            "2:raiz",
            &imagem,
        ],
    )?;

    // A ESP, com os arquivos dentro. Ela é montada num arquivo próprio e
    // depositada na imagem depois: `mkfs.vfat` não sabe escrever a partir de
    // um deslocamento.
    std::fs::write(&esp, vec![0u8; (disco::ESP_SETORES * 512) as usize])
        .map_err(|e| format!("não foi possível criar a imagem da ESP: {e}"))?;
    ferramenta("mkfs.vfat", &["-F", "32", "-n", "DUKE-ESP", &esp])?;
    for (nome, conteudo) in disco::NA_ESP {
        let temporario = alvo.join(nome);
        std::fs::write(&temporario, conteudo)
            .map_err(|e| format!("não foi possível escrever {nome}: {e}"))?;
        ferramenta(
            "mcopy",
            &[
                "-i",
                &esp,
                &temporario.display().to_string(),
                &format!("::/{nome}"),
            ],
        )?;
        let _ = std::fs::remove_file(&temporario);
    }

    // E a raiz. `mkfs.btrfs --rootdir` monta o sistema de arquivos já com o
    // conteúdo de um diretório, sem montar nada e sem privilégio — que é o
    // que torna isto possível dentro de um contêiner.
    let _ = std::fs::remove_dir_all(&arvore);
    for (nome, conteudo) in arquivos_da_raiz() {
        escrever_na_arvore(&arvore, &nome, &conteudo)?;
    }

    std::fs::write(&raiz, vec![0u8; (disco::RAIZ_SETORES * 512) as usize])
        .map_err(|e| format!("não foi possível criar a imagem da raiz: {e}"))?;

    let argumentos = argumentos_do_mkfs(&arvore, &raiz);
    let emprestados: Vec<&str> = argumentos.iter().map(String::as_str).collect();
    ferramenta("mkfs.btrfs", &emprestados)?;

    // As duas partições no lugar, e o padrão por setor na faixa reservada.
    let mut conteudo =
        std::fs::read(caminho).map_err(|e| format!("não foi possível reler a imagem: {e}"))?;
    for (origem, em) in [(&esp, disco::ESP_EM), (&raiz, disco::RAIZ_EM)] {
        let bytes =
            std::fs::read(origem).map_err(|e| format!("não foi possível ler {origem}: {e}"))?;
        let inicio = (em * 512) as usize;
        conteudo[inicio..inicio + bytes.len()].copy_from_slice(&bytes);
    }
    for numero in disco::PADRAO_DE..=disco::PADRAO_ATE {
        let inicio = (numero * 512) as usize;
        conteudo[inicio..inicio + 512].fill(disco::marca_do_setor(numero));
    }
    std::fs::write(caminho, &conteudo)
        .map_err(|e| format!("não foi possível gravar a imagem: {e}"))?;

    let _ = std::fs::remove_file(&esp);
    let _ = std::fs::remove_file(&raiz);
    let _ = std::fs::remove_dir_all(&arvore);
    Ok(())
}

/// Onde um executável está, se estiver no caminho.
fn which(nome: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| Path::new(dir).join(nome))
        .find(|caminho| caminho.is_file())
}

/// Cria o disco de testes, ou o recria se a receita mudou.
fn disco_de_testes() -> Result<PathBuf, String> {
    let caminho = raiz_do_projeto().join("target").join("disco.img");
    let receita = raiz_do_projeto().join("target").join("disco.receita");
    let esperada = receita_do_disco();

    if caminho.is_file() && std::fs::read_to_string(&receita).is_ok_and(|atual| atual == esperada) {
        return Ok(caminho);
    }

    println!("[xtask] montando o disco de testes (GPT, ESP em FAT32, raiz em Btrfs)");
    montar_disco(&caminho)?;
    std::fs::write(&receita, &esperada)
        .map_err(|e| format!("não foi possível gravar a receita do disco: {e}"))?;
    println!("[xtask] disco de testes em {}", caminho.display());
    Ok(caminho)
}

/// Monta a linha de comando do QEMU para a arquitetura em questão.
fn comando_qemu(
    arch: Arquitetura,
    artefato: &Artefato,
    socket_agente: Option<&Path>,
    teclado: Teclado,
) -> Result<Command, String> {
    let mut qemu = Command::new(arch.qemu());

    match (arch, artefato) {
        (Arquitetura::X86_64, Artefato::Disco(disco)) => {
            // A CPU precisa oferecer SMEP, e a padrão do QEMU não oferece.
            //
            // O kernel liga o bit quando o processador o tem, e sem ele a
            // proteção não existe — o anel zero volta a poder executar página
            // de usuário. Medido antes desta linha: o kernel registrava
            // `esta cpu nao oferece SMEP` e o caso da suíte não afirmava
            // nada, porque não havia o que afirmar.
            //
            // `+smep` sobre o modelo padrão, e não um `-cpu host` ou `max`:
            // acrescentar a característica que se quer exercitar mantém o
            // resto da máquina igual ao que era, e diz no próprio argumento
            // por que ela está ali.
            qemu.args(["-cpu", "qemu64,+smep"]);

            // O firmware, em duas partes: o código, que é somente leitura, e
            // as variáveis, que ele escreve durante o boot e por isso são uma
            // cópia nossa.
            let (codigo, variaveis) = firmware_uefi(arch)?;
            qemu.args([
                "-drive",
                &format!("if=pflash,format=raw,readonly=on,file={}", codigo.display()),
            ]);
            qemu.args([
                "-drive",
                &format!("if=pflash,format=raw,file={}", variaveis.display()),
            ]);
            // E o disco de onde o firmware boota, que é o mesmo que o kernel
            // depois lê. O `-drive` sem `if=` o liga ao controlador padrão da
            // máquina, que é de onde o firmware procura uma ESP.
            qemu.args(["-drive", &format!("format=raw,file={}", disco.display())]);
            // O dispositivo que permite ao kernel encerrar o QEMU.
            qemu.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
        }
        (Arquitetura::Aarch64, Artefato::Disco(disco)) => {
            // O mesmo caminho do x86: o firmware é quem carrega, e o
            // iniciador está na ESP deste disco. O que difere é a máquina.
            let (codigo, variaveis) = firmware_uefi(arch)?;
            qemu.args([
                "-machine",
                // `acpi=off` não é detalhe: é o que faz o firmware publicar
                // o **device tree** na tabela de configuração. Com ACPI
                // ligada o EDK II do ARM publica só a RSDP, e este kernel
                // não lê ACPI — ele descobre a RAM, o controlador de
                // interrupções e o ECAM do PCI pelo device tree.
                "virt,acpi=off",
                "-cpu",
                "cortex-a72",
            ]);
            qemu.args([
                "-drive",
                &format!("if=pflash,format=raw,readonly=on,file={}", codigo.display()),
            ]);
            qemu.args([
                "-drive",
                &format!("if=pflash,format=raw,file={}", variaveis.display()),
            ]);
            // O encerramento por semihosting vale igual: quem sai do
            // emulador é o kernel, e como ele chegou lá não muda isso.
            qemu.args(["-semihosting-config", "enable=on,target=native"]);
            let _ = disco;
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

    // Um disco virtio, nas duas arquiteturas. `if=none` mais `-device` em vez
    // de `if=virtio` porque só assim o dispositivo aparece no barramento PCI
    // no ARM, onde não há o atalho que o x86 aceita.
    //
    // No x86 é **o mesmo arquivo** que o firmware acabou de usar para bootar,
    // e por isso ele é aberto em modo compartilhado: o QEMU recusa abrir a
    // mesma imagem duas vezes com trava exclusiva, e recusa com uma mensagem
    // sobre travas que não diz nada sobre o que se estava tentando fazer.
    //
    // Que seja o mesmo disco não é economia: é o que faz o kernel ler a raiz
    // em Btrfs do disco de onde a máquina ligou, como numa máquina de
    // verdade.
    let disco = disco_de_testes()?;
    let compartilhado = if arch == Arquitetura::X86_64 {
        ",file.locking=off"
    } else {
        ""
    };
    qemu.args([
        "-drive",
        &format!(
            "format=raw,file={},if=none,id=disco0{compartilhado}",
            disco.display()
        ),
    ]);
    qemu.args(["-device", "virtio-blk-pci,drive=disco0"]);

    // E uma placa de rede virtio, tambem nas duas.
    //
    // `user` e a rede em modo usuario do QEMU: uma pilha TCP/IP inteira
    // implementada no hospedeiro, que responde como se fosse um roteador em
    // 10.0.2.2. Ela nao precisa de privilegio nenhum — uma `tap` precisaria —
    // e responde a ARP, que e o menor teste de ponta a ponta que existe: o
    // kernel transmite um quadro e recebe uma resposta que so pode ter vindo
    // de fora dele.
    // E um adaptador de vídeo, também nas duas.
    //
    // No x86 já vem um por padrão — a VGA da máquina `pc` — e este `-device`
    // seria um segundo. No ARM a máquina `virt` não traz nenhum: sem isto, o
    // kernel não tem o que programar, e uma pessoa não tem o que olhar.
    //
    // `bochs-display` e não `virtio-gpu` porque é o **mesmo** dispositivo que
    // o x86 já tem (`1234:1111`), com a mesma interface de programação. Um
    // driver serve as duas arquiteturas; virtio-gpu seria um segundo caminho
    // para a mesma coisa, e este kernel já pagou caro por regras que valem em
    // uma arquitetura só.
    if arch == Arquitetura::Aarch64 {
        qemu.args(["-device", "bochs-display"]);

        // E uma segunda tela, que não é para o kernel: é para o **firmware**.
        //
        // O EDK II do ARM não tem driver de bochs — pedir o protocolo de
        // vídeo a ele numa máquina que só tem bochs devolve
        // `EFI_NOT_FOUND`, medido. Sem um adaptador que ele saiba dirigir,
        // o iniciador não descobre tela nenhuma, e o caminho que lê a
        // geometria e protege o framebuffer do alocador de frames nunca
        // roda no ARM.
        //
        // O `ramfb` é o que ele dirige: um framebuffer linear anunciado por
        // `fw_cfg`, sem barramento. Como não é PCI, ele não aparece na
        // varredura do kernel — os dois adaptadores convivem sem que nenhum
        // dos dois lados precise escolher.
        //
        // Qual deles o kernel usa depende de como ele subiu, e não de uma
        // escolha nossa: pela UEFI ele adota a tela que a entrega traz, que
        // é a do `ramfb`, e nem chega a procurar no PCI; por imagem crua não
        // há entrega, e o `bochs-display` acima é a única tela que existe.
        //
        // A terceira opção, `virtio-gpu-pci`, tem driver no EDK II e publica
        // um modo só de transferência, sem buffer linear. O iniciador o
        // recusa, com razão, e o caminho continuaria sem rodar.
        qemu.args(["-device", "ramfb"]);
    }

    // E um teclado. Qual, depende do que se quer exercitar — ver [`Teclado`].
    //
    // O nativo do x86 é o controlador 8042, peça da máquina `pc` desde antes
    // de haver barramento para conectar coisas, e que não se pode remover. O
    // da `virt` do ARM não existe: lá o teclado entra pelo PCI, como tudo o
    // mais.
    match (teclado, arch) {
        (Teclado::Nativo, Arquitetura::Aarch64) => {
            qemu.args(["-device", "virtio-keyboard-pci"]);
        }
        (Teclado::Nativo, Arquitetura::X86_64) => {}
        (Teclado::Usb, _) => {
            // O controlador antes do dispositivo: o `usb-kbd` precisa de um
            // barramento USB para se pendurar, e é o `qemu-xhci` que o cria.
            qemu.args(["-device", "qemu-xhci"]);
            qemu.args(["-device", "usb-kbd"]);
        }
    }

    qemu.args(["-netdev", "user,id=rede0"]);
    qemu.args(["-device", "virtio-net-pci,netdev=rede0"]);

    qemu.args(["-m", "128M"]);

    // O monitor acompanha o canal do agente: os dois existem quando alguém vai
    // conversar com a máquina, e não quando ela sobe para rodar a suíte e
    // morrer. Ver [`caminho_monitor`] sobre por que ele é necessário.
    if socket_agente.is_some() {
        anexar_monitor(&mut qemu, &caminho_monitor(arch));
    }

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

/// Anexa o monitor do emulador a um socket.
fn anexar_monitor(qemu: &mut Command, monitor: &Path) {
    let _ = std::fs::remove_file(monitor);
    qemu.args([
        "-monitor",
        &format!("unix:{},server=on,wait=off", monitor.display()),
    ]);
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
    let artefato = build(arch, release, false)?;
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

    comando_qemu(arch, &artefato, Some(&socket), Teclado::Nativo)?
        .status()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    Ok(ExitCode::SUCCESS)
}

/// Quanto esperar o canal do agente responder ao primeiro pedido.
const ESPERA_PELA_FUMACA: Duration = Duration::from_secs(90);

/// Uma requisição que não cabe no buffer de linha do kernel (2048 bytes).
///
/// Montada em tempo de compilação para que o número fique visível: o que
/// importa é que seja folgadamente maior que o teto, e não quanto exatamente.
const LINHA_LONGA: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"agent.ping","params":{"x":""#,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    r#""}}"#
);

/// Um pedido do teste de fumaça e o que a resposta precisa provar.
struct Sonda {
    /// A linha crua enviada. Crua de propósito: parte do que se testa é o que
    /// o kernel faz com um quadro que nenhum cliente bem-comportado montaria.
    pedido: &'static str,
    /// Trechos que precisam aparecer na resposta.
    exige: &'static [&'static str],
}

/// O que o laço de produção precisa provar que faz.
///
/// Todos numa conexão só, na ordem: um canal que atende o primeiro pedido e
/// morre no segundo é um canal quebrado, e uma sonda por conexão não veria
/// isso.
/// A linha vazia que um cliente manda ao conectar.
///
/// Cópia de `agent::LIMPAR_AO_CONECTAR`: o xtask é outro workspace e não
/// enxerga o crate do kernel. O que impede as duas cópias de divergirem é a
/// sonda de `agent.describe`, que exige o valor publicado em `on_connect`.
const LIMPAR_AO_CONECTAR: &[u8] = b"\n";

/// Quanto um quadro pode ficar parado antes de o kernel o dar por abandonado.
///
/// Cópia de `agent::TETO_DO_QUADRO_EM_TIQUES` (50 tiques a 100 Hz). Aqui ela
/// não é contrato: é o que [`sob_reconexao`] usa para saber se conseguiu
/// reconectar **dentro** da janela que pretende exercitar. Se o kernel
/// encurtar o teto sem que esta cópia acompanhe, a sonda fica exigente demais
/// e reprova — que é o lado certo para errar.
const TETO_DE_OCIOSIDADE: Duration = Duration::from_millis(500);

const SONDAS: &[Sonda] = &[
    Sonda {
        pedido: r#"{"jsonrpc":"2.0","id":1,"method":"agent.ping"}"#,
        exige: &[r#""id":1"#, r#""pong":true"#],
    },
    // O `id` volta com o tipo que chegou. Ecoá-lo como número quebraria a
    // correlação de qualquer cliente que use string.
    Sonda {
        pedido: r#"{"jsonrpc":"2.0","id":"p2","method":"system.info"}"#,
        exige: &[r#""id":"p2""#, r#""kernel":"duke""#],
    },
    // `describe` também publica a convenção de conexão. Está exigido aqui
    // porque as duas constantes abaixo são cópias do que o kernel define, e
    // esta sonda é o que impede que uma ponta mude sem a outra.
    Sonda {
        pedido: r#"{"jsonrpc":"2.0","id":3,"method":"agent.describe"}"#,
        exige: &[
            r#""id":3"#,
            r#""commands""#,
            "agent.ping",
            r#""on_connect""#,
            r#""send":"\n""#,
        ],
    },
    // Um método inexistente é erro de protocolo, não silêncio.
    Sonda {
        pedido: r#"{"jsonrpc":"2.0","id":4,"method":"nao.existe"}"#,
        exige: &[r#""id":4"#, "-32601"],
    },
    // JSON que nem chega a ser objeto.
    Sonda {
        pedido: "isto nao e json",
        exige: &[r#""id":null"#, "-32700"],
    },
    // Um `id` que a varredura aceita mas que não é JSON. Ecoá-lo cru fazia o
    // kernel emitir uma resposta que nenhum cliente lê — e depois de já ter
    // executado o comando.
    Sonda {
        pedido: r#"{"jsonrpc":"2.0","id":abc,"method":"agent.ping"}"#,
        exige: &[r#""id":null"#, "-32600"],
    },
    // Uma linha maior que o buffer de quadro do kernel. O enquadrador tem um
    // teto fixo — não há heap para crescer — e o que ele faz ao estourar é a
    // única coisa entre um cliente falante e uma escrita fora do buffer.
    //
    // A sonda mora aqui, e não na suíte, porque o enquadrador só existe de pé
    // no laço de produção: em `modo-teste` ele nem é instanciado. Uma mutação
    // que dobrasse o teto passava por toda a suíte sem que nada reclamasse.
    Sonda {
        pedido: LINHA_LONGA,
        exige: &[r#""id":null"#, "-32000"],
    },
    // E o canal continua vivo depois de todas as recusas: é esta última que
    // separa "recusou" de "recusou e caiu".
    Sonda {
        pedido: r#"{"jsonrpc":"2.0","id":7,"method":"log.tail","params":{"count":3}}"#,
        exige: &[r#""id":7"#, r#""records""#],
    },
];

/// Sobe o kernel em modo de produção e conversa com ele pelo canal do agente.
///
/// # Por que isto existe
///
/// Porque a suíte não alcança o laço que o kernel entregue roda. Tudo que
/// `cargo xtask test` exercita está sob `modo-teste`, e `modo-teste` **troca**
/// o laço do agente pelo executor de testes: o `Executor`, a tarefa
/// `agent::atender`, a espera por byte via interrupção e a serialização na
/// porta ficam fora de toda rodada verde, por construção.
///
/// As peças têm caso: o enquadrador, o parser, os comandos. A composição não
/// tinha nenhum — e é a composição que o agente usa.
///
/// # O que ele prova, e o que não prova
///
/// Prova que o kernel compilado como se entrega sobe, publica o canal,
/// responde a uma sequência de pedidos numa conexão só e continua respondendo
/// depois de recusar os malformados.
///
/// Não substitui a suíte: não confere nenhum invariante interno. É a outra
/// metade — a suíte olha o kernel por dentro, isto olha pelo buraco da
/// fechadura por onde o agente olha.
fn fumaca(arch: Arquitetura, release: bool, teclado: Teclado) -> Result<ExitCode, String> {
    let artefato = build(arch, release, false)?;
    let socket = caminho_socket(arch);

    println!(
        "[xtask] fumaça: subindo o kernel de produção no QEMU ({})",
        arch.nome()
    );

    let mut filho = comando_qemu(arch, &artefato, Some(&socket), teclado)?
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    // A sonda de reconexão vem depois de `conversar` e não dentro dela porque
    // precisa da conexão principal **fechada**: o que ela exercita é o que um
    // cliente novo herda de um cliente que sumiu.
    let resultado = conversar(&socket, &caminho_monitor(arch), teclado, filho.id())
        .and_then(|()| sob_reconexao(&socket));

    // O emulador morre aconteça o que acontecer: um QEMU órfão segura a
    // imagem de disco e faz a *próxima* execução falhar por um motivo que
    // nada tem a ver com ela.
    let _ = filho.kill();
    let _ = filho.wait();
    let _ = std::fs::remove_file(&socket);

    match resultado {
        Ok(()) => {
            println!("\n[xtask] fumaça: o canal do agente respondeu a tudo");
            Ok(ExitCode::SUCCESS)
        }
        Err(motivo) => {
            eprintln!("\n[xtask] fumaça: {motivo}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Espera o canal subir e roda as sondas numa conexão só.
fn conversar(socket: &Path, monitor: &Path, teclado: Teclado, qemu: u32) -> Result<(), String> {
    let limite = std::time::Instant::now() + ESPERA_PELA_FUMACA;

    // Conectar não é o mesmo que ser atendido. O QEMU aceita a conexão assim
    // que cria o chardev — muito antes de o kernel bootar —, e os bytes
    // enviados nessa janela são **descartados** de propósito na subida da
    // porta, junto com o lixo que uma UART produz ao ser configurada.
    //
    // Medido na primeira execução deste comando, que mandava o primeiro pedido
    // na primeira conexão que abrisse:
    //
    //     [16] 880ms warn agent  39 bytes descartados: chegaram antes do canal
    //                            subir
    //     [xtask] fumaça: sonda 1: sem resposta
    //
    // O aperto de mão é reconectar e repetir um `agent.ping` barato até vir
    // resposta. Só então a conversa de verdade começa, e daí em diante um
    // silêncio é defeito e não impaciência. É a mesma disciplina de
    // [`agente`], pela mesma razão.
    let mut rodada: u32 = 0;
    let fluxo = loop {
        rodada += 1;
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "o canal não respondeu em {}s (qemu pid {qemu})",
                ESPERA_PELA_FUMACA.as_secs()
            ));
        }

        let Ok(tentativa) = UnixStream::connect(socket) else {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        if tentativa
            .set_read_timeout(Some(Duration::from_millis(500)))
            .is_err()
        {
            return Err("não foi possível configurar o timeout".into());
        }

        let mut escrita = match tentativa.try_clone() {
            Ok(f) => f,
            Err(e) => return Err(format!("não foi possível duplicar o fluxo: {e}")),
        };
        // Um `id` por tentativa, e não zero em todas.
        //
        // O QEMU guarda a saída do hóspede e a entrega a quem estiver
        // conectado: a resposta de uma tentativa que estourou o prazo chega na
        // conexão **seguinte**. Com o mesmo `id` em todas, essa resposta velha
        // satisfaz o aperto de mão, e a resposta da tentativa atual fica na
        // tubulação deslocando toda sonda que vier depois em um quadro.
        //
        // Foi o que a CI pegou: a sonda 1 recebeu `"id":0` — a resposta do
        // aperto de mão — em vez da dela.
        let id_do_aperto = 90_000 + rodada;
        let vivo = escrita
            .write_all(
                // A linha vazia da frente é a convenção de `on_connect`: uma
                // tentativa de aperto de mão que estourou o prazo pode ter
                // deixado um quadro pela metade, e é esta conexão que herda.
                format!(
                    "{}{{\"jsonrpc\":\"2.0\",\"id\":{id_do_aperto},\"method\":\"agent.ping\"}}\n",
                    String::from_utf8_lossy(LIMPAR_AO_CONECTAR),
                )
                .as_bytes(),
            )
            .and_then(|()| escrita.flush())
            .is_ok()
            && {
                let mut eco = String::new();
                BufReader::new(&tentativa).read_line(&mut eco).is_ok()
                    && eco.starts_with(&format!(r#"{{"jsonrpc":"2.0","id":{id_do_aperto},"#))
            };

        if vivo {
            break tentativa;
        }
        drop(tentativa);
        std::thread::sleep(Duration::from_millis(500));
    };

    // E, mesmo com o `id` conferido, drenar o que tiver sobrado de uma
    // tentativa anterior antes de começar. Conferir o `id` impede aceitar uma
    // resposta velha como boa; só drenar impede que ela fique no caminho.
    fluxo
        .set_read_timeout(Some(Duration::from_millis(300)))
        .map_err(|e| format!("não foi possível reduzir o timeout: {e}"))?;
    {
        let mut sobras = BufReader::new(
            fluxo
                .try_clone()
                .map_err(|e| format!("não foi possível duplicar o fluxo: {e}"))?,
        );
        loop {
            let mut resto = String::new();
            match sobras.read_line(&mut resto) {
                Ok(0) => return Err("o canal fechou logo depois do aperto de mão".into()),
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    println!(
        "[xtask] fumaça: canal de pé; rodando {} sondas",
        SONDAS.len()
    );

    // A partir daqui um silêncio é defeito, não paciência.
    fluxo
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("não foi possível configurar o timeout: {e}"))?;

    let mut escrita = fluxo
        .try_clone()
        .map_err(|e| format!("não foi possível duplicar o fluxo: {e}"))?;
    let mut leitor = BufReader::new(fluxo);

    for (n, sonda) in SONDAS.iter().enumerate() {
        escrita
            .write_all(format!("{}\n", sonda.pedido).as_bytes())
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("sonda {}: falha ao enviar: {e}", n + 1))?;

        let resposta = ler_resposta(&mut leitor)
            .map_err(|e| format!("sonda {}: {e}\n  pedido: {}", n + 1, sonda.pedido))?;
        let resposta = resposta.trim();
        for exigido in sonda.exige {
            if !resposta.contains(exigido) {
                return Err(format!(
                    "sonda {}: a resposta não traz {exigido}\n  pedido:   {}\n  resposta: {resposta}",
                    n + 1,
                    sonda.pedido
                ));
            }
        }

        // Uma resposta que não fecha as chaves não é um quadro: o cliente
        // seguinte leria o resto dela como se fosse a resposta dele.
        if !quadro_fechado(resposta) {
            return Err(format!(
                "sonda {}: a resposta não é um objeto JSON fechado\n  resposta: {resposta}",
                n + 1
            ));
        }

        println!("  [{}/{}] ok  {}", n + 1, SONDAS.len(), sonda.pedido);
    }

    sob_carga(&mut escrita, &mut leitor)?;
    sob_despejo(&mut escrita, &mut leitor)?;
    sob_teclado(monitor, teclado, &mut escrita, &mut leitor)?;
    sob_interpretador(monitor, &mut escrita, &mut leitor)?;
    sob_fragmento(&mut escrita, &mut leitor)
}

/// O que as três teclas da sonda devem produzir.
const ESPERADO_DO_TECLADO: &str = "abC";

/// O valor que vem logo depois de uma chave, sem interpretar o JSON inteiro.
///
/// Serve para os dois formatos que esta sonda lê — uma string entre aspas e um
/// número — e devolve o texto cru nos dois casos. Não é um interpretador: é o
/// mínimo para não escrever um, num lugar onde a resposta é conhecida e curta.
fn valor_de(resposta: &str, chave: &str) -> Option<String> {
    let resto = &resposta[resposta.find(chave)? + chave.len()..];
    Some(match resto.strip_prefix('"') {
        Some(texto) => texto[..texto.find('"')?].to_string(),
        None => resto
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>(),
    })
}

/// As teclas que uma pessoa digita chegam ao kernel.
///
/// # Por que esta sonda é a única que exercita o teclado
///
/// Porque a suíte não alcança nenhum dos dois drivers. Ela roda dentro do
/// kernel e não tem como fazer o controlador 8042 levantar uma interrupção
/// nem o dispositivo virtio entregar um evento — o que ela testa é a tabela
/// comum aos dois, que é o depois. O antes só se exercita de fora.
///
/// O `sendkey` do monitor do QEMU entrega a tecla ao dispositivo pelo mesmo
/// caminho que um teclado de verdade entregaria: no x86 vira scancode no
/// 8042, no ARM vira evento na fila do virtio. Os dois caminhos são
/// diferentes, o resultado esperado é o mesmo, e é por isso que esta sonda
/// roda nas duas arquiteturas.
///
/// `shift-c` está aqui de propósito: ele exercita o estado de modificador,
/// que é a parte com memória — e portanto a que pode ficar presa.
fn sob_teclado(
    monitor: &Path,
    teclado: Teclado,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!(
        "[xtask] fumaça: teclas pelo monitor do emulador (teclado {})",
        match teclado {
            Teclado::Nativo => "nativo",
            Teclado::Usb => "usb",
        }
    );

    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("teclado: o monitor nao aceitou conexao: {e}"))?;
    mon.set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| format!("teclado: timeout do monitor: {e}"))?;

    for tecla in ["a", "b", "shift-c"] {
        mon.write_all(format!("sendkey {tecla}\n").as_bytes())
            .and_then(|()| mon.flush())
            .map_err(|e| format!("teclado: falha ao mandar `{tecla}`: {e}"))?;
    }

    // Perguntar em laço, e não uma vez depois de um sono fixo.
    //
    // O caminho tem etapas com relógio próprio: o dispositivo entrega quando
    // quer, o kernel recolhe no pulso de dez milissegundos, e a leitura tira
    // da fila o que houver **naquele** instante. Um sono fixo transforma
    // qualquer uma delas em intermitência — e foi o que aconteceu medindo à
    // mão: meio segundo bastou no ARM e não no x86, e a conclusão errada
    // seria "o driver do x86 nao entrega".
    let limite = std::time::Instant::now() + Duration::from_secs(5);
    let mut digitado = String::new();
    let mut ultima = String::new();

    while std::time::Instant::now() < limite && digitado != ESPERADO_DO_TECLADO {
        escrita
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":5555,\"method\":\"keyboard.read\"}\n")
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("teclado: falha ao pedir o que foi digitado: {e}"))?;

        let resposta = ler_resposta(leitor).map_err(|e| format!("teclado: {e}"))?;
        let resposta = resposta.trim().to_string();
        if !resposta.contains(r#""id":5555"#) {
            return Err(format!(
                "teclado: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        digitado.push_str(&valor_de(&resposta, r#""text":"#).unwrap_or_default());
        ultima = resposta;

        if digitado != ESPERADO_DO_TECLADO {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    if digitado != ESPERADO_DO_TECLADO {
        return Err(format!(
            "teclado: o kernel recebeu `{digitado}`, e nao `{ESPERADO_DO_TECLADO}`\n  {ultima}"
        ));
    }

    // E por **onde** chegou. Sem esta parte a sonda diria apenas que algum
    // teclado funciona, e uma máquina com dois provaria só aquele que o
    // emulador escolhesse — deixando o outro driver sem exercício e sem nada
    // acusando.
    let relatorios = valor_de(&ultima, r#""usb_reports":"#)
        .unwrap_or_default()
        .parse::<u64>()
        .unwrap_or(0);
    match teclado {
        Teclado::Usb if relatorios == 0 => {
            return Err(format!(
                "teclado: as teclas chegaram sem passar pelo USB\n  {ultima}"
            ));
        }
        Teclado::Nativo if relatorios > 0 => {
            return Err(format!(
                "teclado: as teclas passaram pelo USB numa maquina sem teclado USB\n  {ultima}"
            ));
        }
        _ => {}
    }

    println!("  [teclado] ok  `a`, `b` e `shift-c` chegaram como `{ESPERADO_DO_TECLADO}`");
    Ok(())
}

/// O que uma pessoa digita vira um comando executado.
///
/// # O que esta sonda fecha
///
/// A composição. As peças já têm prova: as teclas chegam ao kernel (a sonda
/// anterior), o texto chega ao framebuffer (a suíte), e o registro de
/// comandos responde (as oito primeiras sondas). O que ninguém exercitava era
/// o caminho inteiro — tecla, linha, despacho — que é o que uma pessoa
/// **faz**.
///
/// A evidência sai pelo log, e não pela tela. O interpretador registra o que
/// executou, então o canal do agente enxerga o que foi digitado na máquina
/// sem precisar ler pixels. Uma sonda que conferisse a tela teria de
/// reconhecer glifos, e passaria a testar o reconhecedor.
///
/// O `ret` da frente não é enfeite: a sonda anterior digitou `abC` e essa
/// linha ainda está aberta no interpretador. Executá-la — e receber
/// "comando desconhecido" — é o que devolve a linha vazia, e de quebra
/// exercita o caminho de recusa.
fn sob_interpretador(
    monitor: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: um comando digitado no teclado da máquina");

    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("interpretador: o monitor nao aceitou conexao: {e}"))?;

    let mut tecla = |nome: &str| -> Result<(), String> {
        mon.write_all(format!("sendkey {nome}\n").as_bytes())
            .and_then(|()| mon.flush())
            .map_err(|e| format!("interpretador: falha ao mandar `{nome}`: {e}"))?;
        // O emulador entrega uma tecla por vez, e mandá-las sem respiro faz
        // algumas se perderem entre o monitor e o dispositivo.
        std::thread::sleep(Duration::from_millis(20));
        Ok(())
    };

    tecla("ret")?;
    for nome in ["a", "g", "e", "n", "t", "dot", "p", "i", "n", "g", "ret"] {
        tecla(nome)?;
    }

    // Em laço, pelo mesmo motivo da sonda anterior: entre a tecla e o log há
    // o pulso do relógio, o executor e o despacho, cada um com o seu tempo.
    let limite = std::time::Instant::now() + Duration::from_secs(5);
    let mut ultima = String::new();
    while std::time::Instant::now() < limite {
        escrita
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":6666,\"method\":\"log.tail\",\"params\":{\"count\":12}}\n")
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("interpretador: falha ao pedir o log: {e}"))?;

        ultima = ler_resposta(leitor)
            .map_err(|e| format!("interpretador: {e}"))?
            .trim()
            .to_string();
        if !ultima.contains(r#""id":6666"#) {
            return Err(format!(
                "interpretador: veio a resposta de outro pedido\n  {ultima}"
            ));
        }
        if ultima.contains("executado: agent.ping") {
            println!("  [interpretador] ok  `agent.ping` digitado e executado");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "interpretador: o comando digitado nao chegou a ser executado\n  {ultima}"
    ))
}

/// Um pedaço de requisição abandonado não pode colar no pedido seguinte.
///
/// # O cenário
///
/// Um agente cai no meio de uma requisição e reconecta. O kernel não enxerga a
/// desconexão — não há linha de modem entre ele e o socket —, então o
/// fragmento fica pendurado no enquadrador.
///
/// Medido antes do teto: o fragmento `{"jsonrpc":"2.0","id":2,"method":"agent.pi`
/// colou no `agent.ping` do cliente seguinte, que teve o pedido engolido e
/// recebeu `{"id":2,"error":{"code":-32601,...}}` — o `id` de outra pessoa,
/// para um método que ele não chamou. Com um fragmento mais infeliz, o quadro
/// colado vira uma requisição válida que ninguém fez.
///
/// A sonda não precisa desconectar: o enquadrador só vê bytes, e o que decide
/// é o relógio parado entre eles.
fn sob_fragmento(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: fragmento abandonado");

    escrita
        .write_all(br#"{"jsonrpc":"2.0","id":2,"method":"agent.pi"#)
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("fragmento: falha ao enviar o pedaço: {e}"))?;

    // Acima do teto de ociosidade do enquadrador (meio segundo), com folga
    // para o relógio dele. Três vezes o teto: a espera existe para que o teto
    // dispare, não para medir onde ele está.
    std::thread::sleep(Duration::from_millis(1_500));

    escrita
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":7777,\"method\":\"agent.ping\"}\n")
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("fragmento: falha ao enviar o pedido: {e}"))?;

    let mut resposta = String::new();
    leitor
        .read_line(&mut resposta)
        .map_err(|e| format!("fragmento: o pedido depois do fragmento ficou sem resposta: {e}"))?;

    if !resposta.starts_with(r#"{"jsonrpc":"2.0","id":7777,"#) {
        return Err(format!(
            "fragmento: o pedido colou no pedaço abandonado\n  {}",
            resposta.trim()
        ));
    }

    println!("  [fragmento] ok  pedaço abandonado, pedido seguinte intacto");
    Ok(())
}

/// O `id` do pedido que precisa ser respondido depois da reconexão.
///
/// Fora da faixa do aperto de mão (90_000+) e de qualquer sonda, para que
/// casar por `id` aqui não dependa de mais nada.
const ID_DA_RECONEXAO: u32 = 8888;

/// Quem conecta depois de um cliente que sumiu no meio de um quadro não pode
/// herdar o pedaço dele.
///
/// # O cenário, e por que [`sob_fragmento`] não o cobre
///
/// Ali o mesmo cliente deixa um pedaço e espera o teto de ociosidade passar —
/// o que se exercita é o teto. Aqui o cliente **desconecta** e outro entra
/// logo em seguida, dentro do teto, de propósito: o que se exercita é a linha
/// vazia que `agent.describe` publica em `on_connect`.
///
/// Medido antes dela, seis ciclos de seis: o cliente novo pedia um
/// `agent.ping` com `id` 8888 e recebia
///
///     {"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"JSON malformado"}}
///
/// — o erro do lixo alheio no lugar da resposta dele, e o pedido perdido. Com
/// a linha vazia, zero de seis: vêm dois quadros, o erro referente ao lixo
/// anterior e, atrás dele, a resposta com o `id` certo.
///
/// # O que a sonda exige
///
/// Não que o erro do lixo anterior venha ou deixe de vir — isso depende de
/// onde o fragmento parou, e o contrato publicado em `on_connect.expect` já
/// diz que ele pode vir. Exige o que o cliente precisa: **o pedido dele
/// respondido, com o `id` dele**.
fn sob_reconexao(socket: &Path) -> Result<(), String> {
    println!("[xtask] fumaça: reconexão no meio de um quadro");

    // Cliente 1: meio pedido e some. Sem `\n` — é justamente o quadro que
    // ficou aberto que envenena o próximo.
    {
        let mut caido = UnixStream::connect(socket)
            .map_err(|e| format!("reconexão: o cliente que cai não conectou: {e}"))?;
        caido
            .write_all(br#"{"jsonrpc":"2.0","id":4,"method":"agent.pi"#)
            .and_then(|()| caido.flush())
            .map_err(|e| format!("reconexão: falha ao enviar o pedaço: {e}"))?;
    }
    let caiu_em = std::time::Instant::now();

    // Cliente 2, o mais rápido possível. O QEMU precisa de um instante para
    // notar a desconexão e voltar a escutar, então a conexão é tentada em
    // laço — mas com pressa, porque uma reconexão lenta deixaria o teto de
    // ociosidade limpar o fragmento e a sonda passaria sem ter exercitado
    // nada.
    let fluxo = loop {
        match UnixStream::connect(socket) {
            Ok(f) => break f,
            Err(e) => {
                if caiu_em.elapsed() > Duration::from_secs(5) {
                    return Err(format!("reconexão: o canal não aceitou a reconexão: {e}"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    fluxo
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("reconexão: não foi possível configurar o timeout: {e}"))?;
    let mut escrita = fluxo
        .try_clone()
        .map_err(|e| format!("reconexão: não foi possível duplicar o fluxo: {e}"))?;
    let mut leitor = BufReader::new(fluxo);

    let pedido = format!(
        "{}{{\"jsonrpc\":\"2.0\",\"id\":{ID_DA_RECONEXAO},\"method\":\"agent.ping\"}}\n",
        // A linha vazia de `on_connect`, e a única coisa que separa esta sonda
        // do defeito que ela reproduz.
        String::from_utf8_lossy(LIMPAR_AO_CONECTAR),
    );
    escrita
        .write_all(pedido.as_bytes())
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("reconexão: falha ao enviar o pedido: {e}"))?;

    let janela = caiu_em.elapsed();
    if janela >= TETO_DE_OCIOSIDADE {
        return Err(format!(
            "reconexão: a reconexão levou {} ms, mais que o teto de ociosidade do \
             enquadrador ({} ms) — o fragmento foi limpo pelo teto e a sonda não \
             exercitou a linha vazia",
            janela.as_millis(),
            TETO_DE_OCIOSIDADE.as_millis(),
        ));
    }

    // Pode vir o erro referente ao lixo do cliente anterior antes da resposta;
    // o que não pode é a resposta não vir. Casar por `id` é o que o próprio
    // `on_connect.expect` manda o cliente fazer.
    let meu = format!(r#""id":{ID_DA_RECONEXAO},"#);
    let mut alheios: Vec<String> = Vec::new();
    // Como a espera terminou, que não é a mesma coisa que por que ela falhou.
    let fim = loop {
        if alheios.len() >= 4 {
            break "quatro quadros seguidos e nenhum era a resposta";
        }
        let mut linha = String::new();
        match leitor.read_line(&mut linha) {
            Ok(0) => break "o canal fechou",
            Ok(_) => {}
            Err(_) => break "o prazo estourou",
        }
        if linha.contains(&meu) {
            println!(
                "  [reconexão] ok  pedido respondido {} ms depois da queda, \
                 com {} quadro(s) de lixo alheio antes",
                janela.as_millis(),
                alheios.len()
            );
            return Ok(());
        }
        alheios.push(linha.trim().to_string());
    };

    // Separar o desfecho da acusação. Quadro alheio na frente é o
    // envenenamento que esta sonda existe para pegar; silêncio pode ser ele
    // ou pode ser o canal ter morrido antes, e dizer uma coisa pela outra é
    // mandar quem for investigar para o lugar errado.
    if alheios.is_empty() {
        return Err(format!(
            "reconexão: {fim} e o pedido do cliente novo ficou sem resposta \
             nenhuma — isto não é o envenenamento que a sonda procura, o canal \
             emudeceu"
        ));
    }
    Err(format!(
        "reconexão: {fim}; o pedido do cliente novo herdou o quadro do cliente \
         que caiu\n  quadros recebidos: {}",
        alheios.join("\n                     ")
    ))
}

/// Quantos bytes despejar de uma vez, sem ler nada no meio.
///
/// Cinco vezes a fila de bytes de entrada do kernel (4096). O ponto é
/// atropelá-la de propósito: aqui não se testa o caminho feliz.
const DESPEJO: usize = 20_000;

/// Um despejo maior do que o kernel consegue absorver não pode sumir calado.
///
/// # O que isto pega
///
/// Bytes descartados por fila cheia não deixam marca no que sobra. O quadro
/// remontado é indistinguível de um íntegro, e se calhar de ser JSON válido o
/// kernel o executa — uma requisição que ninguém enviou.
///
/// Medido antes da correção, com este mesmo despejo: no x86 vinha um erro de
/// linha longa demais; no ARM, **nenhuma resposta** em dois de cada três
/// despejos, porque o `\n` final era descartado junto com o excesso. O pedido
/// seguinte era engolido pelo quadro quebrado, e o erro que voltava era
/// atribuído a ele.
///
/// O que a sonda exige não é um código de erro específico — o certo depende do
/// que de fato aconteceu, e as duas arquiteturas perdem em pontos diferentes.
/// Exige o contrato: **uma** resposta, que seja erro, e o pedido seguinte
/// respondido com o próprio `id`.
fn sob_despejo(escrita: &mut UnixStream, leitor: &mut BufReader<UnixStream>) -> Result<(), String> {
    // Três vezes seguidas, e não uma. O segundo despejo chega com a fila
    // recém-esvaziada pelo primeiro, e é o que exercita o caminho em que um
    // marcador de fim de quadro precisa entrar numa fila que já esteve cheia.
    for rodada in 1..=3u32 {
        um_despejo(escrita, leitor).map_err(|e| format!("despejo {rodada}: {e}"))?;
    }
    Ok(())
}

fn um_despejo(escrita: &mut UnixStream, leitor: &mut BufReader<UnixStream>) -> Result<(), String> {
    println!("[xtask] fumaça: despejo de {DESPEJO} bytes numa fila de 4096");

    let mut linha = String::with_capacity(DESPEJO + 80);
    linha.push_str(r#"{"jsonrpc":"2.0","id":1,"method":"agent.ping","params":{"x":""#);
    for _ in 0..DESPEJO {
        linha.push('b');
    }
    linha.push_str("\"}}\n");

    escrita
        .write_all(linha.as_bytes())
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("despejo: falha ao enviar: {e}"))?;

    let mut resposta = String::new();
    leitor
        .read_line(&mut resposta)
        .map_err(|e| format!("despejo: o kernel engoliu {DESPEJO} bytes sem dizer nada: {e}"))?;

    if !resposta.contains(r#""error""#) {
        return Err(format!(
            "despejo: era para vir erro, e veio outra coisa\n  {}",
            resposta.trim()
        ));
    }
    if !quadro_fechado(resposta.trim()) {
        return Err(format!(
            "despejo: a resposta não é um objeto JSON fechado\n  {}",
            resposta.trim()
        ));
    }

    // A metade que importa: o canal volta, e volta alinhado.
    //
    // # Por que com retentativa, depois de eu ter tirado a retentativa
    //
    // Porque a versão sem ela exigia do kernel uma garantia que ele não
    // promete, e eu afirmei o contrário. O texto do commit dizia
    // "determinístico por construção"; a CI seguinte reprovou na primeira
    // execução, no ARM, com o pedido seguinte sem resposta.
    //
    // O que acontece é que o aviso de perda sai quando a perda é **detectada**
    // — com a fila cheia nos primeiros quatro mil bytes de um despejo de vinte
    // mil. O cliente é avisado enquanto o kernel ainda está descartando o
    // resto, e o que ele mandar nessa janela é descartado junto. Nesta máquina
    // o kernel absorve o despejo inteiro mais rápido que a ida e volta e a
    // janela nunca é atingida; num runner mais lento, é.
    //
    // Tentei mover o aviso para o fim do quadro perdido, o que fecharia a
    // janela. O resultado foi um travamento do canal no ARM que eu não
    // consegui explicar — e código que eu não entendo não entra. Fica
    // registrado como trabalho em aberto.
    //
    // Então a sonda passa a exigir o que o contrato de fato promete, e que
    // está escrito em `RpcError::ENTRADA_PERDIDA`: o erro manda reenviar, e o
    // canal volta alinhado. Três tentativas, cada uma conferida pelo próprio
    // `id` — uma resposta com o `id` de outro pedido é falha, não recuperação.
    let mut voltou = 0u32;
    for tentativa in 0..3u32 {
        let id = 4242 + tentativa;
        escrita
            .write_all(
                format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"agent.ping\"}}\n")
                    .as_bytes(),
            )
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("falha ao enviar o pedido seguinte: {e}"))?;

        let mut seguinte = String::new();
        match leitor.read_line(&mut seguinte) {
            Ok(0) => return Err("o canal fechou depois do despejo".into()),
            Ok(_) => {}
            // Silêncio é o sintoma de um pedido engolido pela janela de
            // descarte: reenviar é exatamente o que o erro mandou fazer.
            Err(_) => continue,
        }
        if seguinte.starts_with(&format!(r#"{{"jsonrpc":"2.0","id":{id},"#)) {
            voltou = tentativa + 1;
            break;
        }
    }
    if voltou == 0 {
        return Err("o canal não voltou em três tentativas".into());
    }
    if voltou > 1 {
        println!("  [despejo] canal de volta na tentativa {voltou}");
    }

    println!("  [despejo] ok  {DESPEJO} bytes recusados, canal alinhado");
    Ok(())
}

/// Quantas requisições a rajada envia ao todo.
const RAJADA: usize = 400;

/// Quantas cabem no ar de uma vez.
///
/// A fila de bytes de entrada do kernel tem 4096 bytes, e a primeira versão
/// desta sonda despejou as quatrocentas de uma vez — dezoito mil bytes. O
/// kernel descartou o excesso e contabilizou, exatamente como manda o
/// contrato, e a sonda leu isso como defeito do kernel. Era defeito da sonda.
///
/// Um lote de sessenta e quatro são pouco menos de três mil bytes: folga
/// suficiente para não estourar, e rajada suficiente para encher a fila de
/// prontas se o kernel voltar a duplicar despertares — o defeito que esta
/// sonda existe para pegar aparecia com oitenta e uma requisições.
const LOTE: usize = 64;

/// Martela o canal e exige que nada tenha sido perdido em silêncio.
///
/// # O que isto pega, e o que uma sonda avulsa não pegaria
///
/// As sondas acima mandam uma requisição por vez e olham a resposta. Um
/// kernel pode responder a todas e ainda assim estar perdendo trabalho por
/// dentro — foi exatamente o que acontecia: cada byte da serial enfileirava a
/// tarefa do agente outra vez, a fila de prontas enchia de duplicatas, e
/// quatro mil despertares eram descartados. O canal respondia a tudo.
///
/// A prova não está nas respostas, está nos contadores que o próprio kernel
/// publica. Cada um deles existe porque uma perda silenciosa já custou caro em
/// algum lugar, e todos precisam continuar em zero depois da rajada.
fn sob_carga(escrita: &mut UnixStream, leitor: &mut BufReader<UnixStream>) -> Result<(), String> {
    println!("[xtask] fumaça: rajada de {RAJADA} requisições em lotes de {LOTE}");

    // A medida é a **variação**, e não o valor absoluto. `dropped_before_ready`
    // já vem diferente de zero por culpa desta própria ferramenta: o aperto de
    // mão manda pings em conexões abertas antes de o canal subir, e o kernel
    // descarta esses bytes de propósito. Exigir zero seria a sonda acusando o
    // kernel do que ela mesma fez.
    let antes = contadores_de_perda(escrita, leitor)?;

    let mut enviadas = 0;
    while enviadas < RAJADA {
        let neste = LOTE.min(RAJADA - enviadas);

        for i in 0..neste {
            let id = enviadas + i;
            escrita
                .write_all(
                    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"agent.ping\"}}\n")
                        .as_bytes(),
                )
                .map_err(|e| format!("rajada: falha ao enviar a {}a: {e}", id + 1))?;
        }
        escrita
            .flush()
            .map_err(|e| format!("rajada: falha ao despachar: {e}"))?;

        for i in 0..neste {
            let id = enviadas + i;
            let mut resposta = String::new();
            match leitor.read_line(&mut resposta) {
                Ok(0) => return Err(format!("rajada: o canal fechou na {}a resposta", id + 1)),
                Ok(_) => {}
                Err(e) => return Err(format!("rajada: sem resposta na {}a: {e}", id + 1)),
            }
            // Prefixo exato, e não `contains`: procurar `"id":4` solto casaria
            // com a resposta de 40 e faria a sonda aprovar uma troca de ordem.
            let esperado = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},");
            if !resposta.starts_with(&esperado) {
                return Err(format!(
                    "rajada: a {}a resposta não é a do pedido correspondente\n  {}",
                    id + 1,
                    resposta.trim()
                ));
            }
        }

        enviadas += neste;
    }

    // Os contadores, depois da poeira baixar.
    let depois = contadores_de_perda(escrita, leitor)?;

    for (nome, o_que_significa) in CONTADORES_DE_PERDA {
        let (a, d) = (antes[nome], depois[nome]);
        if d > a {
            return Err(format!(
                "rajada: {o_que_significa}\n  {nome}: {a} -> {d} (+{})",
                d - a
            ));
        }
    }

    println!("  [carga] ok  {RAJADA} requisições, nenhuma perda nos contadores");
    Ok(())
}

/// Os contadores de perda que a rajada não pode fazer crescer.
///
/// Cada um existe porque uma perda silenciosa já custou caro em algum lugar
/// deste kernel, e o nome ao lado é o que dizer quando ele se mexer.
const CONTADORES_DE_PERDA: &[(&str, &str)] = &[
    (
        "never_scheduled",
        "despertares descartados por fila de prontas cheia",
    ),
    ("dropped", "bytes descartados por fila de entrada cheia"),
    (
        "dropped_before_ready",
        "bytes descartados antes de o canal subir",
    ),
    ("without_slot", "adormecidos que caíram em espera ativa"),
];

/// Lê `tasks.stats` e extrai os contadores de perda.
fn contadores_de_perda(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<BTreeMap<&'static str, u64>, String> {
    escrita
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":999,\"method\":\"tasks.stats\"}\n")
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("falha ao pedir as estatísticas: {e}"))?;

    let mut stats = String::new();
    leitor
        .read_line(&mut stats)
        .map_err(|e| format!("sem estatísticas: {e}"))?;

    let mut lidos = BTreeMap::new();
    for (nome, _) in CONTADORES_DE_PERDA {
        let chave = format!("\"{nome}\":");
        let valor = stats
            .find(&chave)
            .map(|i| &stats[i + chave.len()..])
            .and_then(|resto| {
                let fim = resto
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(resto.len());
                resto[..fim].parse::<u64>().ok()
            })
            .ok_or_else(|| format!("`tasks.stats` não traz `{nome}`\n  {}", stats.trim()))?;
        lidos.insert(*nome, valor);
    }
    Ok(lidos)
}

/// Lê a próxima resposta, pulando quadros que sobraram de antes.
///
/// # Por que pular, e não apenas ler
///
/// Porque um quadro alheio na frente da fila desloca **toda** sonda seguinte
/// em um, e o que se lê então é a resposta do pedido anterior — um erro que
/// aponta para o lugar errado.
///
/// Foi o que a CI pegou: a sonda 1 pediu `id` 1 e recebeu `"id":0`, a resposta
/// do aperto de mão. O QEMU guarda a saída do hóspede e a entrega a quem
/// estiver conectado, então a resposta de uma tentativa de aperto de mão que
/// estourou o prazo chega na conexão seguinte.
///
/// O aperto de mão passou a usar um `id` próprio por tentativa e a drenar o
/// que sobrar, o que resolve esse caso. Isto aqui é a defesa que não depende
/// de tempo nenhum: qualquer quadro que não seja uma resposta a este pedido é
/// pulado, e o que se reporta quando nada serve são os quadros pulados.
fn ler_resposta(leitor: &mut BufReader<UnixStream>) -> Result<String, String> {
    let mut pulados: Vec<String> = Vec::new();

    for _ in 0..8 {
        let mut linha = String::new();
        match leitor.read_line(&mut linha) {
            Ok(0) => return Err("o canal fechou sem responder".into()),
            Ok(_) => {}
            Err(e) => {
                if pulados.is_empty() {
                    return Err(format!("sem resposta: {e}"));
                }
                return Err(format!(
                    "sem resposta; antes vieram {} quadro(s) alheio(s):\n  {}",
                    pulados.len(),
                    pulados.join("\n  ")
                ));
            }
        }

        // Os `id` do aperto de mão começam em 90_000, faixa que sonda nenhuma
        // usa. Pular por prefixo, e não por número exato, porque quem lê aqui
        // não sabe em qual tentativa o aperto de mão parou.
        if linha.starts_with(r#"{"jsonrpc":"2.0","id":9"#) {
            pulados.push(linha.trim().to_string());
            continue;
        }
        return Ok(linha);
    }

    Err(format!(
        "oito quadros seguidos e nenhum era resposta:\n  {}",
        pulados.join("\n  ")
    ))
}

/// Se a linha é um objeto JSON com todas as chaves fechadas.
///
/// Não é um parser: é a conferência que o `contains` acima não faz. Um quadro
/// truncado traria os trechos exigidos e ainda assim quebraria o cliente, que
/// é exatamente o defeito difícil de enxergar num teste por substring.
///
/// Strings são puladas inteiras, e dentro delas a barra invertida consome o
/// byte seguinte — sem isso, um `}` dentro de aspas contaria como fechamento.
fn quadro_fechado(linha: &str) -> bool {
    let b = linha.as_bytes();
    if b.first() != Some(&b'{') {
        return false;
    }

    let mut nivel = 0usize;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'{' | b'[' => nivel += 1,
            b'}' | b']' => match nivel.checked_sub(1) {
                Some(n) => nivel = n,
                None => return false,
            },
            _ => {}
        }
        i += 1;
    }

    nivel == 0
}

fn test(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release, true)?;
    println!(
        "[xtask] executando a suíte de testes no QEMU ({})\n",
        arch.nome()
    );

    let filho = comando_qemu(arch, &artefato, None, Teclado::Nativo)?
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    match aguardar_com_teto(filho, TETO_DOS_TESTES)? {
        Desfecho::Codigo(code) if code == arch.codigo_de_sucesso() => {
            println!("\n[xtask] todos os testes passaram");
            Ok(ExitCode::SUCCESS)
        }
        Desfecho::Codigo(code) => {
            eprintln!("\n[xtask] os testes falharam (emulador saiu com {code})");
            Ok(ExitCode::FAILURE)
        }
        Desfecho::Sinal => Err("o emulador foi terminado por um sinal".into()),
        Desfecho::Estourou => Err(format!(
            "os testes nao terminaram em {}s e o emulador foi encerrado\n\
             causas tipicas: laco sem saida num teste, triple fault reiniciando \
             a maquina, ou o dispositivo de saida do emulador sem funcionar",
            TETO_DOS_TESTES.as_secs()
        )),
    }
}

/// Como um processo do emulador terminou.
enum Desfecho {
    Codigo(i32),
    Sinal,
    Estourou,
}

/// Aguarda o processo, matando-o se passar do teto.
fn aguardar_com_teto(mut filho: Child, teto: Duration) -> Result<Desfecho, String> {
    let inicio = Instant::now();

    loop {
        match filho
            .try_wait()
            .map_err(|e| format!("falha ao aguardar o emulador: {e}"))?
        {
            Some(status) => {
                return Ok(match status.code() {
                    Some(code) => Desfecho::Codigo(code),
                    None => Desfecho::Sinal,
                });
            }
            None => {
                if inicio.elapsed() >= teto {
                    // Melhor um processo morto e um diagnóstico claro que um
                    // job de CI pendurado sem explicação.
                    let _ = filho.kill();
                    let _ = filho.wait();
                    return Ok(Desfecho::Estourou);
                }
                // 50 ms mantém a espera barata sem atrasar perceptivelmente o
                // fim de uma suíte que leva segundos.
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Cliente do canal do agente.
///
/// Conecta no socket Unix onde a serial do kernel está exposta, envia uma
/// requisição JSON-RPC e imprime a resposta. É o comando que torna o kernel
/// operável de fora com uma única linha de shell — e é idêntico nas duas
/// arquiteturas, porque o protocolo é o mesmo.
fn agente(arch: Arquitetura, metodo: &str, params: &str) -> Result<ExitCode, String> {
    let limite = std::time::Instant::now() + ESPERA_PELO_CANAL;
    let mut avisou = false;

    loop {
        match tentar_agente(arch, metodo, params) {
            Ok(code) => return Ok(code),
            // O kernel ainda não subiu o canal: insistir é o comportamento
            // certo, e desistir cedo transformaria uma espera em erro.
            Err(Espera::AindaNaoRespondeu) if std::time::Instant::now() < limite => {
                if !avisou {
                    eprintln!("[xtask] o canal ainda não respondeu; aguardando o boot...");
                    avisou = true;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(Espera::AindaNaoRespondeu) => {
                return Err(format!(
                    "o kernel não respondeu em {}s\n\
                     dica: ele sobe o canal depois do firmware e do bootloader; \
                     confira se `cargo xtask run --arch {}` está de pé",
                    ESPERA_PELO_CANAL.as_secs(),
                    arch.nome()
                ));
            }
            Err(Espera::Fatal(motivo)) => return Err(motivo),
        }
    }
}

/// O que separa "ainda não" de "não vai dar".
enum Espera {
    /// O canal existe mas ninguém respondeu ainda. Vale tentar de novo.
    AindaNaoRespondeu,
    /// Erro que não melhora com o tempo.
    Fatal(String),
}

fn tentar_agente(arch: Arquitetura, metodo: &str, params: &str) -> Result<ExitCode, Espera> {
    let socket = caminho_socket(arch);

    let mut fluxo = UnixStream::connect(&socket).map_err(|e| {
        Espera::Fatal(format!(
            "não foi possível conectar em {}: {e}\n\
             dica: o kernel precisa estar rodando — inicie \
             `cargo xtask run --arch {}` em outro terminal",
            socket.display(),
            arch.nome()
        ))
    })?;

    // Sem timeout, um kernel travado deixaria o cliente pendurado para sempre.
    // Falhar em cinco segundos é muito mais útil do que não falhar nunca — e
    // quem decide se vale insistir é `agente`, não esta função.
    fluxo
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Espera::Fatal(format!("não foi possível configurar o timeout: {e}")))?;

    // A convenção que `agent.describe` publica em `on_connect`: uma linha vazia
    // fecha o quadro que um cliente anterior possa ter deixado pela metade. O
    // kernel não vê a desconexão; quem sabe que a conexão é nova é o cliente.
    let requisicao = format!(
        "{}{{\"jsonrpc\":\"2.0\",\"id\":{ID_DO_PEDIDO},\"method\":\"{metodo}\",\"params\":{params}}}\n",
        String::from_utf8_lossy(LIMPAR_AO_CONECTAR),
    );

    fluxo
        .write_all(requisicao.as_bytes())
        .and_then(|()| fluxo.flush())
        .map_err(|e| Espera::Fatal(format!("falha ao enviar a requisição: {e}")))?;

    let mut leitor = BufReader::new(fluxo);
    loop {
        let mut linha = String::new();
        match leitor.read_line(&mut linha) {
            // Silêncio dentro do prazo: o canal pode não ter subido ainda.
            Ok(0) => return Err(Espera::AindaNaoRespondeu),
            Ok(_) if e_a_resposta(&linha, ID_DO_PEDIDO) => {
                print!("{linha}");
                return Ok(ExitCode::SUCCESS);
            }
            // Qualquer outra coisa não é a resposta, e imprimi-la como se
            // fosse era o defeito — ver [`e_a_resposta`]. Segue lendo: se o
            // pedido se perdeu antes de o kernel subir, o prazo vence e
            // `agente` tenta de novo com uma conexão nova.
            Ok(_) => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(Espera::AindaNaoRespondeu);
            }
            Err(e) => return Err(Espera::Fatal(format!("falha ao ler a resposta: {e}"))),
        }
    }
}

/// O `id` que `cargo xtask agent` põe no pedido, e pelo qual reconhece a
/// resposta.
const ID_DO_PEDIDO: u32 = 1;

/// Esta linha é a resposta ao pedido `id`?
///
/// # Por que a primeira linha não serve
///
/// Porque no x86 a porta do canal não é só do kernel. Antes de ele existir, o
/// firmware escreve nas duas seriais que encontra, e um cliente que conecta
/// cedo lê `BdsDxe: loading Boot0001 ...` com as sequências de terminal do
/// EDK II na frente. Este cliente imprimia essa linha como a resposta e saía
/// com sucesso — reproduzido duas vezes em duas, conectando assim que o
/// socket aparece. Um agente que confiasse no código de saída tomaria texto
/// do firmware pelo resultado do comando que pediu.
///
/// E mesmo depois de o kernel subir, a linha vazia de `on_connect` pode
/// render um quadro de erro sobre o lixo de um cliente anterior, com `id`
/// nulo. O que `agent.describe` manda fazer — casar a resposta pelo `id` e
/// ignorar o resto — vale para este cliente também.
///
/// O `id` lido é o **primeiro** da linha. Este leitor não interpreta JSON, e
/// não precisa: o kernel escreve o `id` do envelope antes do resultado (ver
/// `envelope_ok` no kernel), então um `"id"` que apareça dentro de um
/// resultado vem sempre depois.
fn e_a_resposta(linha: &str, id: u32) -> bool {
    let linha = linha.trim();
    if !linha.starts_with('{') || !linha.contains("\"jsonrpc\":\"2.0\"") {
        return false;
    }
    let Some(depois) = apos(linha, "\"id\":") else {
        return false;
    };
    let valor = depois.split([',', '}']).next().unwrap_or("");
    valor == id.to_string()
}

/// Quanto tempo insistir antes de desistir do canal.
///
/// O socket existe desde que o QEMU sobe, mas o kernel só chega ao canal do
/// agente depois do firmware e do bootloader — vários segundos, em emulação.
/// Quem manda a requisição nessa janela fala com um socket que ainda não tem
/// ninguém do outro lado, e o kernel **descarta** o que chegou antes de o
/// canal subir, de propósito, para não contaminar a requisição seguinte.
///
/// Sem esperar, o `run` convida a falar com o kernel e a primeira tentativa
/// falha. Insistir aqui é o que faz a instrução impressa pelo `run` valer
/// desde o instante em que ela aparece.
const ESPERA_PELO_CANAL: Duration = Duration::from_secs(30);

#[cfg(test)]
mod testes {
    use super::*;

    /// O comando `simbolo` recebe endereços de duas origens com formatos
    /// diferentes: o canal do agente emite números JSON, que são decimais, e
    /// um depurador imprime hexadecimal. Aceitar os dois sem exigir conversão
    /// manual é o ponto, e é também onde um erro silencioso doeria mais — um
    /// decimal lido como hexadecimal aponta para o símbolo errado sem reclamar
    /// de nada.
    #[test]
    fn a_resposta_e_reconhecida_pelo_id_e_nao_pela_ordem() {
        // O que o firmware do x86 escreve na porta antes de o kernel subir.
        let firmware = "\u{1b}[2J\u{1b}[01;01HBdsDxe: loading Boot0001 \"UEFI QEMU HARDDISK\"";
        assert!(!e_a_resposta(firmware, 1));
        // O quadro de erro que a linha vazia de `on_connect` pode render.
        assert!(!e_a_resposta(
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"JSON malformado"}}"#,
            1
        ));
        // A resposta a outro pedido, inclusive com um id que começa igual.
        assert!(!e_a_resposta(r#"{"jsonrpc":"2.0","id":12,"result":{}}"#, 1));
        assert!(!e_a_resposta(r#"{"jsonrpc":"2.0","id":2,"result":{}}"#, 1));
        // A nossa.
        assert!(e_a_resposta(
            r#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#,
            1
        ));
        assert!(e_a_resposta(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}"#,
            1
        ));
        // Um `"id":1` dentro do resultado não faz de outra resposta a nossa:
        // vale o primeiro `id` da linha, que é o do envelope.
        assert!(!e_a_resposta(
            r#"{"jsonrpc":"2.0","id":7,"result":{"tasks":[{"id":1,"name":"agent"}]}}"#,
            1
        ));
    }

    #[test]
    fn enderecos_em_decimal_e_hexadecimal() {
        assert_eq!(interpretar_endereco("4096"), Ok(4096));
        assert_eq!(interpretar_endereco("0x1000"), Ok(0x1000));
        assert_eq!(interpretar_endereco("0X1000"), Ok(0x1000));
        // O `pc` de uma falha real, como o `traps.stats` o reporta.
        assert_eq!(
            interpretar_endereco("18446603336221253026"),
            Ok(0xffff_8000_0000_dda2)
        );
        // Sublinhados aparecem quando alguém copia de um literal Rust.
        assert_eq!(
            interpretar_endereco("0xFFFF_8000_0000_0000"),
            Ok(0xFFFF_8000_0000_0000)
        );
        // Espaço em volta é comum ao colar de um terminal.
        assert_eq!(interpretar_endereco("  0x40 "), Ok(0x40));
    }

    #[test]
    fn enderecos_invalidos_sao_recusados() {
        assert!(interpretar_endereco("").is_err());
        assert!(interpretar_endereco("0x").is_err());
        assert!(interpretar_endereco("xyz").is_err());
        // Dígitos hexadecimais sem o prefixo são ambíguos, e adivinhar seria
        // pior que recusar: `dead` em decimal não existe, mas `10` existe nas
        // duas bases com valores diferentes.
        assert!(interpretar_endereco("dead").is_err());
    }

    /// A base do x86 é o que transforma endereço de execução em endereço de
    /// binário; se ela divergir de `arch::x86_64::BASE_DO_KERNEL`, a
    /// simbolização aponta para o lugar errado em silêncio. Os dois arquivos
    /// não compartilham código — um é bare-metal, o outro é do host —, então
    /// esta é a única amarra possível.
    /// A receita do disco cobre tudo que muda a imagem.
    ///
    /// # O defeito que este caso existe para pegar
    ///
    /// A imagem só é remontada quando a receita muda. Enquanto a receita era
    /// uma lista escrita à mão, um parâmetro novo de formatação entrava no
    /// `mkfs` sem entrar nela — e o disco antigo ficava no lugar. Foi
    /// exatamente o que aconteceu quando o tamanho de nó mudou: a suíte
    /// reprovou dizendo que a árvore cabia numa folha, e dizia a verdade
    /// sobre uma imagem que já não era a do código.
    ///
    /// O conserto foi estrutural — a receita é montada a partir das mesmas
    /// funções que montam o disco —, e este caso é o que segura a estrutura:
    /// ele afirma que os argumentos do `mkfs` e cada arquivo da raiz
    /// aparecem na receita. Voltar a escrever a lista à mão o reprova.
    #[test]
    fn a_receita_cobre_o_que_monta_a_imagem() {
        let receita = receita_do_disco();

        for argumento in argumentos_do_mkfs(Path::new("<arvore>"), "<raiz>") {
            assert!(
                receita.contains(&argumento),
                "a receita não menciona o argumento `{argumento}` do mkfs:\n{receita}"
            );
        }

        for (nome, conteudo) in arquivos_da_raiz() {
            assert!(
                receita.contains(&format!("{nome} = {} bytes", conteudo.len())),
                "a receita não menciona o arquivo `{nome}`:\n{receita}"
            );
        }

        // E os caminhos da máquina ficam **fora**: eles mudam de um
        // computador para outro sem que a imagem mude, e uma receita que os
        // carregasse remontaria o disco a cada clone do repositório.
        assert!(
            !receita.contains("/home") && !receita.contains("target/"),
            "a receita carrega um caminho da máquina:\n{receita}"
        );
    }

    #[test]
    fn nome_do_binario_confere_com_o_pacote_do_kernel() {
        let manifesto = std::fs::read_to_string(raiz_do_projeto().join("kernel/Cargo.toml"))
            .expect("o manifesto do kernel precisa existir");

        assert!(
            manifesto.contains(&format!("name = \"{NOME_DO_BINARIO}\"")),
            "o pacote do kernel não se chama mais {NOME_DO_BINARIO}; \
             atualize NOME_DO_BINARIO"
        );
    }
}
