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
    /// partir do zero, e o bootloader o deposita na metade alta do espaço
    /// virtual (ver `BASE_DO_KERNEL` em `arch::x86_64`). No ARM o script do
    /// linker já fixa os endereços finais, então não há deslocamento nenhum.
    fn base_do_kernel(self) -> u64 {
        match self {
            Self::X86_64 => 0xFFFF_8000_0000_0000,
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
/// É a mesma ideia do `llvm-readelf` conferindo os ELFs de usuário: quem
/// produz o estímulo não é quem o interpreta.
fn caminho_monitor(arch: Arquitetura) -> PathBuf {
    raiz_do_projeto()
        .join("target")
        .join(format!("monitor-{}.sock", arch.nome()))
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
/// ao `llvm-readelf`, que não tem nada a ver com este projeto. Se ele lê os
/// cabeçalhos e os segmentos, o formato está certo por um caminho
/// independente.
fn conferir_elfs(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    build(arch, release, false)?;
    let kernel = caminho_elf(arch, release);
    let readelf = ferramenta_llvm("llvm-readelf")?;

    let bytes = std::fs::read(&kernel)
        .map_err(|e| format!("não foi possível ler {}: {e}", kernel.display()))?;
    let simbolos = simbolos_do_kernel(&kernel)?;

    let saida = raiz_do_projeto().join("target").join("elfs");
    std::fs::create_dir_all(&saida)
        .map_err(|e| format!("não foi possível criar {saida:?}: {e}"))?;

    let mut falhou = false;
    for nome in ["exemplo", "filho", "invasor"] {
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
            .args(["--file-header", "--program-headers"])
            .arg(&caminho)
            .status()
            .map_err(|e| format!("não foi possível invocar o llvm-readelf: {e}"))?;
        if !status.success() {
            eprintln!("[xtask] o llvm-readelf recusou a imagem de `{nome}`");
            falhou = true;
        }
    }

    if falhou {
        return Err("uma das imagens nao passou pelo llvm-readelf".into());
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
fn receita_do_disco() -> String {
    let mut receita = format!(
        "v5 setores={} esp={}+{} raiz={}+{} padrao={}..{}\n",
        disco::SETORES,
        disco::ESP_EM,
        disco::ESP_SETORES,
        disco::RAIZ_EM,
        disco::RAIZ_SETORES,
        disco::PADRAO_DE,
        disco::PADRAO_ATE
    );
    for (nome, conteudo) in disco::NA_ESP.iter().chain(disco::NA_RAIZ) {
        receita.push_str(&format!("{nome} = {conteudo}"));
    }
    let (nome, tamanho) = disco::GRANDE;
    receita.push_str(&format!(
        "{nome} = {tamanho} bytes, marca({tamanho}/2)={}\n",
        disco::marca_do_grande(tamanho / 2)
    ));
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
    for (nome, conteudo) in disco::NA_RAIZ {
        escrever_na_arvore(&arvore, nome, conteudo.as_bytes())?;
    }

    let (nome_grande, tamanho) = disco::GRANDE;
    let grande: Vec<u8> = (0..tamanho).map(disco::marca_do_grande).collect();
    escrever_na_arvore(&arvore, nome_grande, &grande)?;
    std::fs::write(&raiz, vec![0u8; (disco::RAIZ_SETORES * 512) as usize])
        .map_err(|e| format!("não foi possível criar a imagem da raiz: {e}"))?;
    ferramenta(
        "mkfs.btrfs",
        &[
            "--rootdir",
            &arvore.display().to_string(),
            "-f",
            "-L",
            "duke-raiz",
            &raiz,
        ],
    )?;

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

    // Um disco virtio, nas duas arquiteturas. `if=none` mais `-device` em vez
    // de `if=virtio` porque só assim o dispositivo aparece no barramento PCI
    // no ARM, onde não há o atalho que o x86 aceita.
    let disco = disco_de_testes()?;
    qemu.args([
        "-drive",
        &format!("format=raw,file={},if=none,id=disco0", disco.display()),
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
        "{}{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{metodo}\",\"params\":{params}}}\n",
        String::from_utf8_lossy(LIMPAR_AO_CONECTAR),
    );

    fluxo
        .write_all(requisicao.as_bytes())
        .and_then(|()| fluxo.flush())
        .map_err(|e| Espera::Fatal(format!("falha ao enviar a requisição: {e}")))?;

    let mut leitor = BufReader::new(fluxo);
    let mut resposta = String::new();
    match leitor.read_line(&mut resposta) {
        // Silêncio dentro do prazo: o canal pode não ter subido ainda.
        Ok(0) => Err(Espera::AindaNaoRespondeu),
        Ok(_) => {
            print!("{resposta}");
            Ok(ExitCode::SUCCESS)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(Espera::AindaNaoRespondeu)
        }
        Err(e) => Err(Espera::Fatal(format!("falha ao ler a resposta: {e}"))),
    }
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
    #[test]
    fn base_do_kernel_confere_com_a_do_kernel() {
        let fonte =
            std::fs::read_to_string(raiz_do_projeto().join("kernel/src/arch/x86_64/mod.rs"))
                .expect("o backend x86_64 do kernel precisa existir");

        assert!(
            fonte.contains("pub const BASE_DO_KERNEL: u64 = 0xFFFF_8000_0000_0000;"),
            "a base do kernel mudou em arch::x86_64; atualize Arquitetura::base_do_kernel"
        );
        assert_eq!(Arquitetura::X86_64.base_do_kernel(), 0xFFFF_8000_0000_0000);
        assert_eq!(Arquitetura::Aarch64.base_do_kernel(), 0);
    }

    /// Mesmo raciocínio da amarra anterior: o nome do executável vem do
    /// `Cargo.toml` do kernel, e o xtask precisa adivinhá-lo para achar o ELF.
    /// Se o pacote for renomeado sem atualizar a constante, o build "passa" e
    /// só o `cargo xtask debug` quebra — longe da causa.
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
