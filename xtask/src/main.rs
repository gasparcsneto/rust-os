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
        "build" => build(arch, release, false).map(|_| ExitCode::SUCCESS),
        "run" => run(arch, release),
        "test" => test(arch, release),
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

fn ajuda() {
    println!(
        "\
build system do Duke

USO:
    cargo xtask <comando> [--arch x86_64|aarch64] [--release]

COMANDOS:
    build                     compila o kernel (e gera as imagens, no x86)
    run                       executa no QEMU com o canal do agente ativo
    test                      executa a suíte de testes dentro do QEMU
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

    let mut qemu = comando_qemu(arch, &artefato, Some(&socket))?;
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

/// Tamanho do disco de testes.
const TAMANHO_DO_DISCO: u64 = 1024 * 1024;

/// Bytes reconhecíveis no começo do primeiro setor.
///
/// O driver de disco precisa de algo que prove que leu o **setor certo** e não
/// um buffer zerado que por acaso parecia plausível. Um padrão conhecido é a
/// diferença entre "a leitura retornou" e "a leitura funcionou".
const ASSINATURA_DO_DISCO: &[u8] = b"DUKE-DISCO-v1";

/// Cria o disco de testes se ele ainda não existir.
///
/// O conteúdo é gerado, e não versionado: um arquivo binário de 1 MiB no
/// repositório seria peso morto que ninguém revisa. A regra de preenchimento
/// está aqui e no teste do kernel, que é o par que precisa concordar.
fn disco_de_testes() -> Result<PathBuf, String> {
    let caminho = raiz_do_projeto().join("target").join("disco.img");
    if caminho.exists() {
        return Ok(caminho);
    }

    std::fs::create_dir_all(caminho.parent().unwrap())
        .map_err(|e| format!("não foi possível criar o diretório do disco: {e}"))?;

    let mut conteudo = vec![0u8; TAMANHO_DO_DISCO as usize];
    conteudo[..ASSINATURA_DO_DISCO.len()].copy_from_slice(ASSINATURA_DO_DISCO);

    // Cada setor é preenchido com um byte que deriva do próprio número. Ler o
    // setor errado devolve um padrão que não confere, o que torna um erro de
    // deslocamento visível — diferente de zeros, que parecem plausíveis em
    // qualquer lugar.
    for (numero, setor) in conteudo.chunks_mut(512).enumerate() {
        let marca = (numero as u8).wrapping_mul(7).wrapping_add(1);
        for (i, byte) in setor.iter_mut().enumerate() {
            if numero == 0 && i < ASSINATURA_DO_DISCO.len() {
                continue;
            }
            *byte = marca;
        }
    }

    std::fs::write(&caminho, &conteudo)
        .map_err(|e| format!("não foi possível escrever o disco de testes: {e}"))?;
    println!("[xtask] disco de testes criado em {}", caminho.display());
    Ok(caminho)
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

    // Um disco virtio, nas duas arquiteturas. `if=none` mais `-device` em vez
    // de `if=virtio` porque só assim o dispositivo aparece no barramento PCI
    // no ARM, onde não há o atalho que o x86 aceita.
    let disco = disco_de_testes()?;
    qemu.args([
        "-drive",
        &format!("format=raw,file={},if=none,id=disco0", disco.display()),
    ]);
    qemu.args(["-device", "virtio-blk-pci,drive=disco0"]);

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

    comando_qemu(arch, &artefato, Some(&socket))?
        .status()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    Ok(ExitCode::SUCCESS)
}

fn test(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release, true)?;
    println!(
        "[xtask] executando a suíte de testes no QEMU ({})\n",
        arch.nome()
    );

    let filho = comando_qemu(arch, &artefato, None)?
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

    let requisicao =
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{metodo}\",\"params\":{params}}}\n");

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
