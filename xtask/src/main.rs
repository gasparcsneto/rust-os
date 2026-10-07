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

mod persistencia;

use std::collections::BTreeMap;
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, ExitCode, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Quanto a suíte pode ficar sem terminar caso nenhum antes de o emulador
/// ser encerrado.
///
/// Um kernel tem formas demais de travar para que esperar indefinidamente seja
/// aceitável: o bootloader pode falhar e reiniciar em laço, uma exceção não
/// tratada pode causar triple fault e reboot, um teste pode entrar num laço
/// sem saída. Sem limite, qualquer um desses casos vira um job de CI
/// pendurado que não diz nada — o pior modo de falhar.
///
/// # Por que o limite é do andamento, e não da suíte inteira
///
/// O limite era um teto da suíte inteira, e foi subido três vezes — de dois
/// minutos a cinco, a dez e a vinte —, cada uma pela mesma conta: a suíte
/// cresceu, a máquina variou, e o teto passou a reprovar uma suíte saudável;
/// o novo era o dobro do pior medido. Um teto do total cresce com cada caso
/// novo, e a quarta vez chegou: com a conferência da ordem das travas e os
/// casos do armazém, a suíte do x86 num núcleo só passou dos vinte minutos
/// — andando, sem laço nenhum.
///
/// O que se quer pegar não é uma suíte longa, é uma suíte **parada**. Todas
/// as formas de travar de cima param de terminar casos: o laço sem saída
/// não termina o dele; o reboot em laço nunca chega a terminar um; um laço
/// que só escreve log também não. Então o limite é o tempo sem um caso
/// terminado — `ok` ou `FALHOU` —, contado desde o último, ou desde a
/// partida para o primeiro (o boot entra nele). Ele depende do caso mais
/// lento, e não de quantos casos há.
///
/// # Por que dez minutos
///
/// O caso mais lento medido é o do contador do TPM, que abre a persistência
/// várias vezes: 47 segundos de relógio do convidado no x86 com um núcleo,
/// uns 85 de parede nesta bancada. O ARM no emulador é mais lento, e as
/// máquinas da CI variaram de 1 a 1,7 vez entre execuções seguidas; o pior
/// esperado fica abaixo de cinco minutos, e dez são o dobro. Cada execução
/// diz o maior intervalo que mediu entre dois casos, para que esta conta
/// seja refeita com o número da CI, e não com uma estimativa.
const JANELA_SEM_PROGRESSO: Duration = Duration::from_secs(600);

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

    // Qual adaptador de vídeo a máquina vai ter. Ver [`Video`].
    let video = match extrair_valor(&args, "--video") {
        None | Some("linear") => Video::Linear,
        Some("virtio") => Video::Virtio,
        Some(outro) => {
            eprintln!("erro: video desconhecido `{outro}`; use `linear` ou `virtio`");
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
        if a == "--arch" || a == "--teclado" || a == "--canal" {
            pular = true;
        } else if !a.starts_with("--") {
            posicionais.push(a);
        }
    }

    let comando = posicionais.first().copied().unwrap_or("help");

    let resultado = match comando {
        "build" => build(arch, release, false).map(|_| ExitCode::SUCCESS),
        "run" => run(arch, release, video),
        "test" => test(arch, release, video),
        "fumaca" => fumaca(arch, release, teclado, video),
        "agent" => {
            let metodo = posicionais.get(1).copied().unwrap_or("agent.describe");
            let params = posicionais.get(2).copied().unwrap_or("{}");
            match extrair_valor(&args, "--canal").map(str::parse::<u8>) {
                None => agente(arch, 0, metodo, params),
                Some(Ok(canal)) if canal <= PORTAS_DE_AGENTE => agente(arch, canal, metodo, params),
                Some(_) => Err(format!(
                    "--canal vai de 0 (a serial) a {PORTAS_DE_AGENTE} (as portas do console virtio)"
                )),
            }
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
        "persistencia" => persistencia::persistencia(arch, release),
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
    persistencia              a mesma máquina em vários boots: corte de energia,
                              disco restaurado, relógio para trás
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

/// Quantas portas de agente a máquina tem, no console virtio — as sessões 1
/// a 4 do kernel. A 0 é a serial, em [`caminho_socket`].
const PORTAS_DE_AGENTE: u8 = 4;

/// Onde fica o socket da porta de agente `porta`, de 1 a
/// [`PORTAS_DE_AGENTE`] — ou o da serial, na 0.
fn caminho_canal(arch: Arquitetura, porta: u8) -> PathBuf {
    if porta == 0 {
        return caminho_socket(arch);
    }
    raiz_do_projeto()
        .join("target")
        .join(format!("agente-{porta}-{}.sock", arch.nome()))
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

/// O adaptador de vídeo da máquina.
///
/// Duas máquinas porque são dois caminhos de tela no kernel, e um caminho
/// que nenhuma máquina exercita é um caminho que só falha na de alguém.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Video {
    /// Um framebuffer que o dispositivo varre sozinho: a VGA do x86 posta
    /// pelo firmware, o `bochs-display` do ARM programado pelo kernel.
    Linear,
    /// Só um `virtio-gpu`, que mostra apenas o que o kernel manda. É a
    /// máquina de nuvem ARM típica, e a que o UTM monta num Mac.
    Virtio,
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

/// Onde fica o QMP do emulador desta arquitetura.
///
/// # Por que o QMP, além do monitor
///
/// Para o mouse. O `mouse_move` do monitor manda movimento relativo, e um
/// tablet — o `virtio-tablet` do ARM — só entende posição absoluta: o evento
/// se perde. O `input-send-event` do QMP manda os dois tipos, e cada
/// dispositivo recebe o que entende. É o mesmo caminho que um mouse de
/// verdade, porque o emulador entrega o evento ao dispositivo, e o
/// dispositivo ao kernel.
fn caminho_qmp(arch: Arquitetura) -> PathBuf {
    raiz_do_projeto()
        .join("target")
        .join(format!("qmp-{}.sock", arch.nome()))
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
    let features: &[&str] = if modo_teste { &["modo-teste"] } else { &[] };
    build_com(arch, release, features)
}

/// [`build`] com estas features do kernel. A única além de `modo-teste` é a
/// `quedas`, da bancada de persistência — e o `cargo xtask invariantes`
/// confere que só ela a pede.
pub(crate) fn build_com(
    arch: Arquitetura,
    release: bool,
    features: &[&str],
) -> Result<Artefato, String> {
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
    if !features.is_empty() {
        cargo.args(["--features", &features.join(",")]);
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
            conferir_sem_simd(&elf)?;
            let efi = build_do_iniciador(arch, release)?;
            let disco = disco_de_testes()?;
            instalar_iniciador(arch, &disco, &efi, &kernel_para_a_esp(&elf)?)?;
            Ok(Artefato::Disco(disco))
        }
    }
}

/// Confere que o kernel do x86 não usa registrador de SIMD nenhum.
///
/// # Por que é preciso conferir
///
/// Os registradores `xmm`, `ymm` e `zmm` são do processo que estava rodando:
/// este kernel não os salva ao entrar, e uma instrução que os use dentro do
/// kernel corrompe o estado de quem foi interrompido — sem erro, só números
/// errados num programa que nem sabia que tinha sido interrompido.
///
/// O alvo `x86_64-unknown-none` impede o compilador de gerar SIMD por conta
/// própria. O que ele não impede é o código que **pede** SIMD, função a
/// função, depois de perguntar ao processador — e as primitivas do canal
/// seguro fazem isso. Três opções em `kernel/.cargo/config.toml` desligam
/// esse caminho.
///
/// # O que foi medido, e o que não
///
/// Tirar as opções hoje não chega a pôr SIMD no binário: dois dos pacotes
/// deixam de compilar para este alvo, e o terceiro compila sem gerar — ver o
/// `config.toml`. O defeito que esta conferência pega é o de amanhã: uma
/// versão nova de um destes pacotes, ou um pacote novo, que compile e gere.
/// Que ela o pega foi medido de outro jeito: uma instrução `pxor xmm0`
/// injetada à mão em `aleatorio::chave` fez o build parar, com a função e a
/// instrução no erro.
///
/// Só o x86. No ARM o alvo `-softfloat` não deixa o NEON existir nem em
/// código que o peça: a função não compila.
fn conferir_sem_simd(elf: &Path) -> Result<(), String> {
    let objdump = ferramenta_llvm("llvm-objdump")?;
    let saida = Command::new(&objdump)
        .args(["-d", "--no-show-raw-insn"])
        .arg(elf)
        .output()
        .map_err(|e| format!("não foi possível invocar o llvm-objdump: {e}"))?;
    if !saida.status.success() {
        return Err(format!(
            "llvm-objdump falhou: {}",
            String::from_utf8_lossy(&saida.stderr)
        ));
    }
    let texto = String::from_utf8_lossy(&saida.stdout);
    let mut funcao = "";
    let mut achados: Vec<String> = Vec::new();
    let mut total = 0usize;
    for linha in texto.lines() {
        if linha.ends_with(">:") {
            funcao = linha;
            continue;
        }
        if ["%xmm", "%ymm", "%zmm"].iter().any(|r| linha.contains(r)) {
            total += 1;
            if achados.len() < 5 {
                achados.push(format!("{funcao}\n      {}", linha.trim()));
            }
        }
    }
    if total > 0 {
        return Err(format!(
            "o kernel usa registradores de SIMD em {total} instrução(ões) — os de um processo \
             interrompido, que este kernel não salva. As primeiras:\n  {}\n\
             Confira as opções de backend em `kernel/.cargo/config.toml`.",
            achados.join("\n  ")
        ));
    }
    Ok(())
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

/// O kernel como ele vai para a ESP: sem as seções de depuração.
///
/// O iniciador lê o arquivo inteiro para a memória antes de carregar os
/// segmentos, e o DWARF — mais da metade do arquivo, e nunca lido no boot —
/// chegou a passar dos 32 MiB que ele aceita: o kernel de release com a
/// suíte ficou com 33 MiB quando o Ed25519 entrou, e o boot parava antes do
/// kernel. A simbolização é feita aqui no hospedeiro (`cargo xtask simbolo`,
/// o gdb), com o ELF inteiro em `target/`, que não muda; a tabela de
/// símbolos e tudo o que o iniciador usa ficam no da ESP.
///
/// É separado de [`instalar_iniciador`] porque nem todo arquivo que vai para
/// a ESP é um ELF que o `objcopy` aceite: os kernels estragados de propósito
/// da etapa `iniciador` são justamente os que ele recusaria, e precisam
/// chegar ao iniciador byte a byte como foram adulterados.
fn kernel_para_a_esp(kernel: &Path) -> Result<PathBuf, String> {
    let sem_depuracao = kernel.with_extension("esp.elf");
    ferramenta(
        &localizar_objcopy()?.display().to_string(),
        &[
            "--strip-debug",
            &kernel.display().to_string(),
            &sem_depuracao.display().to_string(),
        ],
    )?;
    Ok(sem_depuracao)
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

/// Quanto o iniciador tem para relatar e chegar à primeira linha do kernel.
///
/// Folgado: o firmware sozinho leva alguns segundos para inicializar o vídeo
/// e varrer os barramentos, e o relatório em si é instantâneo. O teto não
/// está aqui para medir desempenho — está para que um iniciador que trave
/// vire um erro em vez de um job pendurado.
///
/// Quando o que se espera é o desligamento, o teto é outro: no ARM, quem
/// desliga a máquina é a suíte inteira, rodando sobre o mapa da UEFI, e ela
/// espera pelo andamento dela — ver [`JANELA_SEM_PROGRESSO`]. Os 240 segundos daqui
/// serviram para isso enquanto a suíte cabia neles; com a persistência, a
/// mesma suíte em debug passou a levar de 320 a 340 segundos na CI pelo
/// `-kernel`, e o passo do iniciador passou a estourar ao acaso.
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
    // Daqui em diante, `kernel` é o arquivo da ESP, e não o de `target/`: é
    // ele que o iniciador lê, e é contra ele que o CRC, os segmentos e as
    // relocações do relatório têm de bater. Os estragados também partem
    // dele, para que a única diferença do bom seja o byte adulterado.
    let kernel = kernel_para_a_esp(&caminho_elf(arch, release))?;

    let disco = disco_de_testes()?;
    zerar_o_estado(arch)?;
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
    let ambiente = Ambiente::ligar(arch, None)?;
    let mut qemu = comando_qemu(
        arch,
        &Artefato::Disco(disco.to_path_buf()),
        None,
        Teclado::Nativo,
        Video::Linear,
        &ambiente,
    )?;
    qemu.stdout(Stdio::piped());
    // Sem rede: nada aqui precisa dela, e o firmware tentaria PXE antes do
    // disco se ela existisse.
    qemu.args(["-net", "none"]);

    let mut filho = qemu
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;
    let andamento = acompanhar(&mut filho, arquivo)?;

    // O desligamento, no ARM, é o fim da suíte inteira, e espera como a
    // suíte espera: pelo andamento. Num kernel estragado é a recusa, que
    // chega em segundos — o relatório diz se o iniciador chegou ao fim. A
    // marca é a primeira linha do kernel, e tem o teto do iniciador.
    let desfecho = match espera {
        Desenlace::Desligamento => aguardar_com_andamento(filho, andamento, JANELA_SEM_PROGRESSO)?,
        Desenlace::Marca(marca) => {
            let desfecho = aguardar_a_marca(filho, &registro, marca, TETO_DO_INICIADOR)?;
            let _ = andamento.leitor.join();
            desfecho
        }
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
                "a maquina ficou {}s sem terminar um caso e sem desligar — o iniciador nao \
                 chegou ao fim",
                JANELA_SEM_PROGRESSO.as_secs()
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

    conferir_programas_compilados(arch, &readelf, estilo)?;
    Ok(ExitCode::SUCCESS)
}

/// Confere os programas do pacote `programas` com o `llvm-readobj`.
///
/// # O que esta conferência fecha
///
/// O script de ligação dos programas repete o endereço de
/// `protocolo::usuario::BASE`, porque um script não inclui Rust. É uma
/// segunda declaração, e das que divergem em silêncio: um executável ligado
/// noutro endereço seria recusado pelo carregador com "fora do espaço do
/// usuário", no boot, longe de quem mudou o script. Aqui a divergência
/// aparece no build, lida por ferramenta de fora, contra as constantes do
/// próprio `protocolo`.
///
/// E o resto do que o carregador exige, pela mesma ferramenta: executável de
/// endereço fixo, sem relocação, e nenhum segmento gravável e executável.
fn conferir_programas_compilados(
    arch: Arquitetura,
    readelf: &Path,
    estilo: &str,
) -> Result<(), String> {
    use protocolo::usuario::{BASE, MAPEAVEL};

    let programas = programas_do_disco()?;
    let prefixo = format!("programas/{}/", arch.nome());
    let saida = raiz_do_projeto().join("target").join("elfs");
    let mut conferidos = 0;
    for (nome, bytes) in programas.iter().filter(|(n, _)| n.starts_with(&prefixo)) {
        let curto = &nome[prefixo.len()..];
        let caminho = saida.join(format!("programa-{curto}.elf"));
        std::fs::write(&caminho, bytes)
            .map_err(|e| format!("não foi possível escrever {caminho:?}: {e}"))?;
        let relatorio = Command::new(readelf)
            .args([
                estilo,
                "--file-header",
                "--program-headers",
                "--relocations",
            ])
            .arg(&caminho)
            .output()
            .map_err(|e| format!("não foi possível invocar o llvm-readobj: {e}"))?;
        if !relatorio.status.success() {
            return Err(format!("o llvm-readobj recusou o programa `{curto}`"));
        }
        let texto = String::from_utf8_lossy(&relatorio.stdout);

        let erro = |motivo: &str| format!("programa `{curto}`: {motivo}\n{texto}");
        if !texto
            .lines()
            .any(|l| l.trim_start().starts_with("Type:") && l.contains("EXEC"))
        {
            return Err(erro("não é um executável de endereço fixo"));
        }
        let entrada = texto
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("Entry point address:"))
            .and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| erro("o llvm-readobj não disse o ponto de entrada"))?;
        // O programa mora entre `BASE` e o começo do que `mapear` dá.
        let faixa = BASE..MAPEAVEL.0;
        if !faixa.contains(&entrada) {
            return Err(erro(&format!(
                "a entrada {entrada:#x} está fora de {:#x}..{:#x} — o script de ligação divergiu do protocolo?",
                faixa.start, faixa.end
            )));
        }
        let mut segmentos = 0;
        for linha in texto.lines().filter(|l| l.trim_start().starts_with("LOAD")) {
            let campos: Vec<&str> = linha.split_whitespace().collect();
            // LOAD <offset> <vaddr> <paddr> <filesz> <memsz> <flags...> <align>
            let numero = |i: usize| {
                campos
                    .get(i)
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            };
            let (Some(inicio), Some(tamanho)) = (numero(2), numero(5)) else {
                return Err(erro(&format!("segmento ilegível: `{linha}`")));
            };
            if inicio < faixa.start || inicio + tamanho > faixa.end {
                return Err(erro(&format!(
                    "o segmento em {inicio:#x} sai de {:#x}..{:#x}",
                    faixa.start, faixa.end
                )));
            }
            let bandeiras = campos[6..campos.len() - 1].concat();
            if bandeiras.contains('W') && bandeiras.contains('E') {
                return Err(erro("um segmento é gravável e executável"));
            }
            segmentos += 1;
        }
        if segmentos == 0 {
            return Err(erro("nenhum segmento carregável"));
        }
        // O manifesto: todo programa do disco declara o que exerce, e o
        // segmento de notas é onde o kernel o procura. Só o `anonimo` não
        // declara — é o caso que confere que sem manifesto não há nada.
        // O script de ligação declara o segmento sempre; vazio, é de quem
        // não declarou nada. NOTE <offset> <vaddr> <paddr> <filesz> ...
        let tem_notas = texto.lines().any(|l| {
            let campos: Vec<&str> = l.split_whitespace().collect();
            campos.first() == Some(&"NOTE")
                && campos
                    .get(4)
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                    .is_some_and(|n| n > 0)
        });
        if tem_notas != (curto != "anonimo") {
            return Err(erro(if tem_notas {
                "o programa sem manifesto tem um segmento de notas"
            } else {
                "o programa não declara manifesto: falta `programas::manifesto!`"
            }));
        }
        if !texto.contains("There are no relocations in this file") {
            return Err(erro(
                "o executável tem relocações, que o carregador não faz",
            ));
        }
        println!(
            "[xtask] programa {curto}: EXEC, entrada {entrada:#x}, {segmentos} segmentos, sem relocação"
        );
        conferidos += 1;
    }
    if conferidos == 0 {
        return Err(format!("nenhum programa compilado para {}", arch.nome()));
    }
    Ok(())
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
        conferir_travas_do_post_mortem()?,
        conferir_janelas_pelo_toolkit()?,
        conferir_ponto_unico_de_decisao()?,
        conferir_remetente_da_sessao()?,
        conferir_auditoria_so_relatada()?,
    ];
    if passos.iter().all(|p| *p == ExitCode::SUCCESS) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

/// Confere que toda trava estática do kernel é destravada no caminho fatal.
///
/// # Por que isto virou conferência
///
/// Porque o post-mortem é o canal respondendo depois de uma falha, e a falha
/// pode ter acontecido com qualquer trava na mão. `traps::fatal` as destrava à
/// força antes de voltar a atender; uma que fique de fora pendura, na primeira
/// pergunta que a tocar, o canal inteiro — e com ele a autópsia.
///
/// A lista é escrita à mão, e ficou para trás duas vezes. Na primeira cobria
/// cinco travas de dezesseis. Na segunda faltavam cinco módulos que entraram
/// depois dela: o teclado, o teclado virtio, o xHCI, o VFS e a pilha gráfica —
/// esta última escrita na mesma semana em que a lista foi revisada.
///
/// # A regra
///
/// Todo arquivo do kernel que declare um `static` com `Mutex` ou `Fila` (que
/// tem um `Mutex` dentro) precisa ter o seu módulo chamado em `traps.rs` como
/// `crate::<modulo>::destravar()`. Os backends de arquitetura respondem por
/// `crate::arch::destravar_paginacao()`, que é a única trava deles; o próprio
/// `traps.rs` destrava as suas no lugar.
///
/// O que a regra não alcança: o **conteúdo** de cada `destravar` — um módulo
/// com duas travas que solte uma passa aqui —, e uma trava embrulhada num tipo
/// próprio que não seja `Fila`. O `Alocador` do heap é o caso que existe hoje;
/// ele está na lista, mas por leitura, não por esta regra.
fn conferir_travas_do_post_mortem() -> Result<ExitCode, String> {
    let raiz = raiz_do_projeto();
    let fonte = raiz.join("kernel/src");
    let traps = std::fs::read_to_string(fonte.join("traps.rs"))
        .map_err(|e| format!("não foi possível ler traps.rs: {e}"))?;

    let mut modulos = 0usize;
    let mut faltando: Vec<String> = Vec::new();
    percorrer_fontes(&fonte, &mut |caminho| {
        let relativo = caminho
            .strip_prefix(&fonte)
            .map_err(|_| format!("{} fora de kernel/src", caminho.display()))?;
        let nome = relativo.to_string_lossy().replace('\\', "/");
        if nome == "traps.rs" || nome == "testes.rs" {
            return Ok(());
        }
        let texto = std::fs::read_to_string(caminho)
            .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
        let tem_trava = texto.lines().any(|l| {
            let l = l.trim_start();
            let l = l.strip_prefix("pub ").unwrap_or(l);
            l.starts_with("static ")
                && l.split_once(':').is_some_and(|(_, tipo)| {
                    let tipo = tipo.trim_start();
                    tipo.contains("Mutex<") && tipo.find("Mutex<") < tipo.find('=')
                        || tipo.starts_with("Fila<")
                })
        });
        if !tem_trava {
            return Ok(());
        }
        modulos += 1;

        let chamada = if nome.starts_with("arch/") {
            "crate::arch::destravar_paginacao()".to_string()
        } else {
            let caminho_do_modulo = nome
                .trim_end_matches(".rs")
                .trim_end_matches("/mod")
                .replace('/', "::");
            format!("crate::{caminho_do_modulo}::destravar()")
        };
        if !traps.contains(&chamada) {
            faltando.push(format!("{nome}: falta `{chamada}` em traps.rs"));
        }
        Ok(())
    })?;

    if faltando.is_empty() {
        println!(
            "[xtask] {modulos} módulos com trava estática, todos destravados no caminho fatal"
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("[xtask] travas que o post-mortem não solta:");
        for f in &faltando {
            eprintln!("  {f}");
        }
        eprintln!(
            "\nUma falha que pegue uma destas na mão pendura o canal na primeira pergunta \
             que a tocar. Escreva o `destravar` do módulo e chame-o em `traps::fatal`."
        );
        Ok(ExitCode::FAILURE)
    }
}

/// Os programas que desenham ou descrevem uma superfície à mão, e por quê:
/// eles conferem a ABI crua do kernel, por baixo do runtime.
const SUPERFICIE_CRUA: &[(&str, &str)] = &[
    (
        "bin/superficie.rs",
        "confere as recusas de `descrever` e o que o compositor mostra dos pixels do processo",
    ),
    (
        "bin/entrada.rs",
        "uma superfície crua, fora do runtime, para conferir a entrada por superfície",
    ),
    (
        "bin/cobrir.rs",
        "um programa hostil, que pinta uma barra falsa e tenta pô-la sobre a do kernel",
    ),
    (
        "bin/herdeira.rs",
        "depois de um `exec`, desenha na superfície dela para conferir que a herdada não é a sua",
    ),
];

/// O que numa linha de programa desenha ou descreve uma janela sem o
/// toolkit: a memória de pixels, a chamada ao kernel, o escritor, um
/// elemento.
const A_MAO: &[&str] = &[".pixels()", "sistema::descrever(", "Escritor", ".elemento("];

/// A primeira linha de `texto` — o número e ela — que desenha ou descreve
/// uma janela à mão, fora dos comentários.
fn linha_a_mao(texto: &str) -> Option<(usize, &str)> {
    texto.lines().enumerate().find_map(|(i, linha)| {
        let codigo = linha.trim_start();
        let a_mao = !codigo.starts_with("//") && A_MAO.iter().any(|t| codigo.contains(t));
        a_mao.then_some((i + 1, codigo))
    })
}

/// Confere que só o toolkit e a moldura do runtime desenham e descrevem
/// janelas.
///
/// # Por que isto virou conferência
///
/// Porque a árvore semântica é como um agente opera o Duke, e uma descrição
/// escrita à mão ao lado do desenho é a segunda superfície que o toolkit
/// existe para não ter. Até a fase 11, o servidor de janelas e o Terminal
/// escreviam as suas: o retângulo do texto e o do desenho eram contas
/// separadas, e bastava uma mudar para o agente ler o que não estava na
/// tela. Agora o desenho e a descrição saem dos widgets — e esta
/// conferência impede a próxima janela de voltar a fazer um dos dois à mão:
/// o pixel pintado fora de um widget é o que a pessoa vê e o agente não lê.
///
/// # A regra
///
/// Nenhum arquivo de `programas/src` pega a memória de pixels, chama
/// `sistema::descrever`, usa o `Escritor` ou acrescenta um `.elemento(` — a
/// não ser `janela.rs`, a moldura do runtime, que desenha a interface e
/// entrega ao kernel o que ela gerou, e os programas de
/// [`SUPERFICIE_CRUA`], que conferem a ABI crua.
fn conferir_janelas_pelo_toolkit() -> Result<ExitCode, String> {
    let raiz = raiz_do_projeto();
    let fonte = raiz.join("programas/src");
    let mut arquivos = 0usize;
    let mut fora: Vec<String> = Vec::new();
    percorrer_fontes(&fonte, &mut |caminho| {
        let nome = caminho
            .strip_prefix(&fonte)
            .map_err(|_| format!("{} fora de programas/src", caminho.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        arquivos += 1;
        if nome == "janela.rs" || SUPERFICIE_CRUA.iter().any(|(a, _)| *a == nome) {
            return Ok(());
        }
        let texto = std::fs::read_to_string(caminho)
            .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
        if let Some((n, linha)) = linha_a_mao(&texto) {
            fora.push(format!("programas/src/{nome}:{n}: {linha}"));
        }
        Ok(())
    })?;
    if fora.is_empty() {
        println!(
            "[xtask] {arquivos} arquivos de programas: as janelas são desenhadas e descritas só pelo toolkit \
             ({} com a ABI crua, para conferi-la)",
            SUPERFICIE_CRUA.len()
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("[xtask] janelas desenhadas ou descritas à mão:");
        for f in &fora {
            eprintln!("  {f}");
        }
        eprintln!(
            "\nUma janela se desenha e se descreve pelo toolkit: monte widgets numa `Interface`, e a \
             `Janela::com_interface` do runtime gera o desenho e a descrição do mesmo estado."
        );
        Ok(ExitCode::FAILURE)
    }
}

/// As chamadas que executam uma operação protegida, e os únicos arquivos
/// onde cada uma pode aparecer.
const CHAMADAS_PROTEGIDAS: &[(&str, &[&str])] = &[
    // O handler de um comando: só a licença de `autorizacao::autorizar`.
    (".handler)(", &["kernel/src/autorizacao.rs"]),
    // Escrever no disco: só o journal de estado e o volume do armazém, cada
    // um pela sua janela — o journal na de estado, o volume na dele. As
    // janelas, só o boot (e a definição delas no driver). O driver confere
    // a janela em toda escrita, contra qualquer chamador — isto confere que
    // não há outro chamador, e que nenhum dos dois escreve pela janela do
    // outro. A suíte, que esta conferência não lê, exercita os três.
    (
        ".gravar_setores(",
        &["kernel/src/persistencia.rs", "kernel/src/volume.rs"],
    ),
    (
        ".descarregar_disco(",
        &["kernel/src/persistencia.rs", "kernel/src/volume.rs"],
    ),
    (
        "Janela::Estado",
        &[
            "kernel/src/persistencia.rs",
            "kernel/src/virtio/blk.rs",
            "kernel/src/main.rs",
        ],
    ),
    (
        "Janela::Armazem",
        &[
            "kernel/src/volume.rs",
            "kernel/src/virtio/blk.rs",
            "kernel/src/main.rs",
        ],
    ),
    (
        "fixar_janela_de_escrita(",
        &["kernel/src/virtio/blk.rs", "kernel/src/main.rs"],
    ),
    // E o journal se abre uma vez, no boot.
    ("persistencia::abrir()", &["kernel/src/main.rs"]),
    // Uma operação administrativa: só depois da prova e da decisão.
    (
        "(operacao.executar)(",
        &["kernel/src/agent/administracao.rs"],
    ),
    // A exceção do boot: a chave privada, os registros e a política são
    // lidos antes de haver o que decidir — e só ali. A leitura do diretório
    // reservado é definida no VFS e chamada só pela identidade e pelo
    // registro de pessoas; as três cargas, só pelo boot.
    (
        "ler_segredo(",
        &[
            "kernel/src/vfs/mod.rs",
            "kernel/src/identidade.rs",
            "kernel/src/pessoas.rs",
        ],
    ),
    ("identidade::carregar()", &["kernel/src/main.rs"]),
    ("autorizacao::carregar()", &["kernel/src/main.rs"]),
    ("pessoas::carregar()", &["kernel/src/main.rs"]),
    // Agir na interface: o `ui.act` do agente só pelo handler — que só a
    // licença do ponto de decisão chama —, e a pessoa só pelo
    // interpretador, depois da decisão com a sessão dela. O clique na barra
    // também. Nenhum caminho interno aciona um elemento por fora.
    ("ui::agir_com_versao(", &["kernel/src/agent/commands.rs"]),
    (
        "ui::agir(",
        &["kernel/src/interpretador.rs", "kernel/src/ponteiro.rs"],
    ),
    ("ponteiro::tratar_clique(", &["kernel/src/interpretador.rs"]),
    // A linha de comando do físico se edita e se confirma, por fora do
    // interpretador, só pela interface — onde a coordenação confere o
    // arrendamento e a versão antes.
    ("interpretador::definir(", &["kernel/src/ui.rs"]),
    ("interpretador::confirmar(", &["kernel/src/ui.rs"]),
    // Quebrar o arrendamento de outro só pela operação administrativa,
    // com a prova.
    (
        "coordenacao::revogar(",
        &["kernel/src/agent/administracao.rs"],
    ),
    // As mensagens: mandar, ler, confirmar, cancelar e consultar só pelos
    // handlers — depois da decisão — e pela operação administrativa, com a
    // prova. O titular sai da sessão autenticada, ou da prova; o
    // destinatário, da decisão.
    (
        "mensagens::enviar(",
        &[
            "kernel/src/agent/commands.rs",
            "kernel/src/agent/administracao.rs",
        ],
    ),
    ("mensagens::ler(", &["kernel/src/agent/commands.rs"]),
    (
        "mensagens::confirmar(",
        &[
            "kernel/src/agent/commands.rs",
            "kernel/src/agent/administracao.rs",
        ],
    ),
    ("mensagens::cancelar(", &["kernel/src/agent/commands.rs"]),
    ("mensagens::estado(", &["kernel/src/agent/commands.rs"]),
    ("Remetente::da_sessao(", &["kernel/src/agent/commands.rs"]),
    (
        "Remetente::do_administrador(",
        &["kernel/src/agent/administracao.rs"],
    ),
    (
        "autorizacao::destino_decidido(",
        &["kernel/src/agent/commands.rs"],
    ),
    // O armazém: uma mutação, um rascunho, um arrendamento ou a soltura
    // dele só pelos handlers dos comandos `fs.*` — depois da decisão do
    // gate. O lote vai ao volume e é confirmado no journal de estado só
    // pelo módulo do armazém, na ordem dele; a confirmação também pelo
    // volume, ao criá-lo e ao compactar o journal dele. O volume se abre
    // só pela persistência, no boot, com o que o journal de estado
    // confirmou, e só o volume troca o armazém em memória pelo reposto.
    ("armazem::mudar(", &["kernel/src/agent/commands.rs"]),
    ("armazem::rascunho(", &["kernel/src/agent/commands.rs"]),
    ("armazem::descartar(", &["kernel/src/agent/commands.rs"]),
    ("armazem::arrendar(", &["kernel/src/agent/commands.rs"]),
    ("armazem::soltar(", &["kernel/src/agent/commands.rs"]),
    (
        "persistencia::confirmar_armazem(",
        &["kernel/src/armazem.rs", "kernel/src/volume.rs"],
    ),
    ("volume::escrever_lote(", &["kernel/src/armazem.rs"]),
    ("volume::confirmar(", &["kernel/src/armazem.rs"]),
    ("volume::abrir(", &["kernel/src/persistencia.rs"]),
    ("volume::sem_persistencia(", &["kernel/src/persistencia.rs"]),
    ("armazem::trocar(", &["kernel/src/volume.rs"]),
    ("coordenacao::conferir(", &["kernel/src/armazem.rs"]),
    ("coordenacao::tomar_por(", &["kernel/src/armazem.rs"]),
    ("coordenacao::soltar_por(", &["kernel/src/armazem.rs"]),
    // Revogar a credencial de um administrador, e descartar os desafios
    // pendentes, só pela operação de quórum.
    (
        "identidade::revogar_administrador(",
        &["kernel/src/agent/administracao.rs"],
    ),
    (
        "identidade::descartar_desafios(",
        &["kernel/src/agent/administracao.rs"],
    ),
    // Tirar a mensagem de outro, ou esvaziar a caixa de outro, só com
    // prova; anular, só a revogação.
    ("mensagens::purgar(", &["kernel/src/agent/administracao.rs"]),
    (
        "mensagens::purgar_caixa(",
        &["kernel/src/agent/administracao.rs"],
    ),
    (
        "mensagens::anular_titular(",
        &["kernel/src/identidade.rs", "kernel/src/pessoas.rs"],
    ),
    // Quem agiu por último só se conta no ponto de decisão — depois do
    // `ALLOW` de um comando, de uma ação da pessoa, ou de uma operação
    // administrativa que executou. Sem os parênteses: um `use` que trouxesse
    // a função para chamá-la sem o caminho também é pego.
    ("atividade::registrar", &["kernel/src/autorizacao.rs"]),
    (
        "autorizacao::contar_administracao(",
        &["kernel/src/agent/administracao.rs"],
    ),
    ("atividade::sessao_acabou(", &["kernel/src/sessoes.rs"]),
    // Nenhuma camada sobe acima da barra, a não ser o cursor; e uma
    // superfície de processo só vai aonde a ABI deixa.
    (
        ".fixar_no_topo(",
        &["kernel/src/barra.rs", "kernel/src/ponteiro.rs"],
    ),
    (
        "superficie::posicao_permitida(",
        &["kernel/src/superficies.rs"],
    ),
    ("mover_sem_limite(", &["kernel/src/superficies.rs"]),
];

/// As funções que tratam um pedido de mensagem: os handlers da sessão e as
/// operações administrativas.
const FUNCOES_DE_MENSAGEM: &[&str] = &[
    "message_send",
    "message_read",
    "message_ack",
    "message_cancel",
    "message_status",
    "escrever_caixa",
    "mandar_mensagem",
    "ler_mensagens",
    "confirmar_mensagem",
    "purgar_mensagem",
    "esvaziar_caixa",
];

/// Confere que o remetente de uma mensagem nunca vem do pedido.
///
/// Quem manda é a sessão autenticada — ou a prova do administrador —, e o
/// kernel o deriva: `Remetente::da_sessao` e `Remetente::do_administrador`.
/// Nenhuma função que trata um pedido de mensagem lê `from`, nem `sender`,
/// nem `owner`; e o módulo de mensagens não lê parâmetro nenhum — recebe o
/// titular pronto. Um `member("from")` num handler de mensagem seria o
/// remetente escolhido por quem pede.
///
/// `net.arp` tem um `from` legítimo — o endereço de origem —, e por isso a
/// conferência é das funções de mensagem, e não de todo o kernel.
/// Confere que a cadeia da auditoria só é lida por quem a guarda, por quem
/// a grava e pelos relatórios.
///
/// # Por que isto virou conferência
///
/// Um registro só de auditoria não avança o contador do TPM, e os que vêm
/// depois do último que avançou podem sumir num rollback do disco para essa
/// âncora. Isso só é aceitável enquanto nenhuma decisão depender da
/// auditoria: se o ponto de decisão, uma cota ou um arrendamento passasse a
/// ler a cadeia, a perda do rabo dela mudaria uma decisão — e o rollback
/// que o contador não vê passaria a restaurar comportamento.
///
/// # A regra
///
/// `com_auditoria(` só aparece em `autorizacao.rs`, que a guarda, em
/// `persistencia.rs`, que a grava e a compacta, e — em `agent/commands.rs` —
/// só dentro de `audit_tail`, `audit_head` e `audit_verify`, os relatórios.
/// A suíte, que confere a cadeia, fica de fora.
fn conferir_auditoria_so_relatada() -> Result<ExitCode, String> {
    const RELATORIOS: [&str; 3] = ["audit_tail", "audit_head", "audit_verify"];
    let raiz = raiz_do_projeto();
    let fontes = raiz.join("kernel/src");
    let mut fora = Vec::new();
    let mut achadas = 0;
    percorrer_fontes(&fontes, &mut |caminho| {
        let relativo = caminho
            .strip_prefix(&fontes)
            .map_err(|_| format!("{} fora de kernel/src", caminho.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        if matches!(
            relativo.as_str(),
            "autorizacao.rs" | "persistencia.rs" | "testes.rs"
        ) {
            return Ok(());
        }
        let texto = std::fs::read_to_string(caminho)
            .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
        let mut funcao = "";
        for (n, linha) in texto.lines().enumerate() {
            if let Some(resto) = linha
                .trim_start()
                .strip_prefix("fn ")
                .or(linha.trim_start().strip_prefix("pub fn "))
                .or(linha.trim_start().strip_prefix("pub(crate) fn "))
            {
                funcao = resto.split(['(', '<']).next().unwrap_or("");
            }
            if !linha.contains("com_auditoria(") {
                continue;
            }
            achadas += 1;
            if relativo == "agent/commands.rs" && RELATORIOS.contains(&funcao) {
                continue;
            }
            fora.push(format!(
                "kernel/src/{relativo}:{}: {funcao}: {}",
                n + 1,
                linha.trim()
            ));
        }
        Ok(())
    })?;
    if achadas == 0 {
        fora.push(
            "nenhuma leitura da auditoria fora da persistência: a conferência está cega".into(),
        );
    }
    if fora.is_empty() {
        println!(
            "[xtask] a cadeia da auditoria só é lida pela persistência e pelos relatórios: \
             nenhuma decisão depende de um registro que um rollback pode levar"
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!("[xtask] a auditoria lida fora da persistência e dos relatórios:");
        for f in &fora {
            println!("  {f}");
        }
        println!(
            "\nO rabo da auditoria não tem a proteção do contador do TPM: nenhuma decisão pode \
             depender dele."
        );
        Ok(ExitCode::FAILURE)
    }
}

fn conferir_remetente_da_sessao() -> Result<ExitCode, String> {
    let raiz = raiz_do_projeto();
    let mut fora = Vec::new();
    for arquivo in [
        "kernel/src/agent/commands.rs",
        "kernel/src/agent/administracao.rs",
    ] {
        let texto = std::fs::read_to_string(raiz.join(arquivo))
            .map_err(|e| format!("não foi possível ler {arquivo}: {e}"))?;
        let mut achadas = 0;
        let mut dentro: Option<&str> = None;
        for (n, linha) in texto.lines().enumerate() {
            if let Some(resto) = linha
                .strip_prefix("fn ")
                .or(linha.strip_prefix("pub(crate) fn "))
            {
                let nome = resto.split(['(', '<']).next().unwrap_or("");
                dentro = FUNCOES_DE_MENSAGEM.iter().copied().find(|f| *f == nome);
                achadas += usize::from(dentro.is_some());
            }
            if let Some(f) = dentro
                && ["\"from\"", "\"sender\"", "\"owner\""]
                    .iter()
                    .any(|c| linha.contains(&format!("member({c})")))
            {
                fora.push(format!("{arquivo}:{}: {f}: {}", n + 1, linha.trim()));
            }
        }
        if achadas == 0 {
            fora.push(format!(
                "{arquivo}: nenhuma função de mensagem: a conferência está cega"
            ));
        }
    }
    let modulo = std::fs::read_to_string(raiz.join("kernel/src/mensagens.rs"))
        .map_err(|e| format!("não foi possível ler kernel/src/mensagens.rs: {e}"))?;
    for (n, linha) in modulo.lines().enumerate() {
        if linha.contains(".member(") {
            fora.push(format!(
                "kernel/src/mensagens.rs:{}: {}",
                n + 1,
                linha.trim()
            ));
        }
    }
    if fora.is_empty() {
        println!(
            "[xtask] o remetente de uma mensagem vem da sessão, ou da prova: nenhuma função de \
             mensagem lê `from`, e o módulo de mensagens não lê parâmetro"
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!("[xtask] o remetente de uma mensagem lido do pedido:");
        for f in &fora {
            println!("  {f}");
        }
        println!(
            "\nQuem manda uma mensagem é a sessão autenticada, ou a prova de um administrador — \
             nunca um parâmetro."
        );
        Ok(ExitCode::FAILURE)
    }
}

/// Confere que nenhum caminho chega a uma operação protegida sem passar pelo
/// ponto de decisão.
///
/// # A regra
///
/// O handler de um comando é chamado num lugar só — `Autorizado::executar`,
/// que só existe depois de `autorizacao::autorizar` decidir — e a operação
/// administrativa num lugar só, depois da prova e do papel. Uma chamada
/// direta em qualquer outro arquivo é um atalho: o canal, o interpretador ou
/// um módulo novo executando sem decisão e sem auditoria.
///
/// E a única exceção — o boot, que carrega a chave, o registro e a política
/// antes de haver ponto de decisão — fica presa ao boot: a leitura do
/// diretório reservado só é chamada pela identidade, e as duas cargas só
/// pelo `main.rs`. Nenhum comando, chamada de sistema ou caminho do console
/// as alcança.
///
/// O compilador não pega isso: o handler é um ponteiro de função público, e
/// chamá-lo é uma linha que compila em qualquer lugar. Antes desta etapa
/// havia dois lugares que o chamavam — o canal e o interpretador — e o
/// segundo não validava nem os parâmetros.
///
/// A suíte (`testes.rs`) fica de fora: ela chama handlers para conferir as
/// respostas deles, e não é caminho de produção — não é compilada sem
/// `modo-teste`.
/// A feature `quedas` só na bancada: o texto `"quedas"` aparece, no
/// `xtask`, só em `xtask/src/persistencia.rs`. Devolve o que estiver fora.
fn conferir_quedas_so_na_bancada(raiz: &Path) -> Result<Vec<String>, String> {
    let mut fora = Vec::new();
    let mut achou = false;
    percorrer_fontes(&raiz.join("xtask/src"), &mut |caminho| {
        let relativo = caminho
            .strip_prefix(raiz)
            .map_err(|_| format!("{} fora do projeto", caminho.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let texto = std::fs::read_to_string(caminho)
            .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
        for (n, linha) in texto.lines().enumerate() {
            // A própria conferência menciona a feature entre crases.
            if linha.contains("\"quedas\"") && !linha.contains("`\"quedas\"`") {
                if relativo == "xtask/src/persistencia.rs" {
                    achou = true;
                } else {
                    fora.push(format!(
                        "{relativo}:{}: a feature `quedas` fora da bancada: {}",
                        n + 1,
                        linha.trim()
                    ));
                }
            }
        }
        Ok(())
    })?;
    if !achou {
        fora.push("a bancada não pede a feature `quedas`: a conferência está cega".into());
    }
    Ok(fora)
}

/// A abertura da persistência antes de quem atende: devolve o que estiver
/// fora de ordem no `kernel/src/main.rs`.
fn conferir_a_ordem_do_boot(raiz: &Path) -> Result<Vec<String>, String> {
    const ABRIR: &str = "persistencia::abrir()";
    const DEPOIS: [&str; 2] = ["agent::atender(", "testes::executar_todos()"];
    let caminho = raiz.join("kernel/src/main.rs");
    let texto = std::fs::read_to_string(&caminho)
        .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
    let linhas: Vec<&str> = texto.lines().collect();
    let abrir: Vec<usize> = (0..linhas.len())
        .filter(|&n| linhas[n].contains(ABRIR))
        .collect();
    let [abrir] = abrir[..] else {
        return Ok(vec![format!(
            "kernel/src/main.rs: `{ABRIR}` aparece {} vezes, e não uma",
            abrir.len()
        )]);
    };
    let mut fora = Vec::new();
    for depois in DEPOIS {
        let Some(primeira) = linhas.iter().position(|l| l.contains(depois)) else {
            fora.push(format!(
                "kernel/src/main.rs: `{depois}` não aparece: a conferência da ordem está cega"
            ));
            continue;
        };
        if primeira < abrir {
            fora.push(format!(
                "kernel/src/main.rs:{}: `{depois}` antes de `{ABRIR}` (linha {}): o journal \
                 tem de se reaplicar antes de alguém ser atendido",
                primeira + 1,
                abrir + 1
            ));
        }
    }
    Ok(fora)
}

fn conferir_ponto_unico_de_decisao() -> Result<ExitCode, String> {
    let raiz = raiz_do_projeto();
    let fonte = raiz.join("kernel/src");
    let mut fora: Vec<String> = Vec::new();
    let mut achadas = vec![0usize; CHAMADAS_PROTEGIDAS.len()];
    percorrer_fontes(&fonte, &mut |caminho| {
        let relativo = caminho
            .strip_prefix(&raiz)
            .map_err(|_| format!("{} fora do projeto", caminho.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        if relativo == "kernel/src/testes.rs" {
            return Ok(());
        }
        let texto = std::fs::read_to_string(caminho)
            .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
        for (n, linha) in texto.lines().enumerate() {
            for (i, (chamada, donos)) in CHAMADAS_PROTEGIDAS.iter().enumerate() {
                if !linha.contains(chamada) {
                    continue;
                }
                if donos.contains(&relativo.as_str()) {
                    achadas[i] += 1;
                } else {
                    fora.push(format!("{relativo}:{}: {}", n + 1, linha.trim()));
                }
            }
        }
        Ok(())
    })?;
    // A compilação com os pontos de queda é só da bancada: a feature não
    // aparece em nenhum outro lugar do `xtask`, e nenhuma outra compilação
    // a pede.
    fora.extend(conferir_quedas_so_na_bancada(&raiz)?);
    // O journal se reaplica antes de alguém poder falar: no `main.rs`, a
    // abertura da persistência vem antes da primeira tarefa que atende um
    // agente e antes da suíte. Uma abertura depois disso seria uma janela
    // em que a credencial revogada da imagem ainda está ativa.
    fora.extend(conferir_a_ordem_do_boot(&raiz)?);
    // A chamada legítima tem de existir: uma busca que não acha nem ela
    // está procurando a coisa errada, e passaria por qualquer atalho.
    for ((chamada, donos), quantas) in CHAMADAS_PROTEGIDAS.iter().zip(&achadas) {
        if *quantas < donos.len() {
            fora.push(format!(
                "`{chamada}` não aparece em todos de {donos:?}: a conferência está cega"
            ));
        }
    }
    if fora.is_empty() {
        println!(
            "[xtask] o handler de um comando, a operação administrativa e as ações na interface \
             só passam pelo ponto de decisão; o arrendamento de outro só cai com prova; as \
             mensagens só pelos handlers, pela prova e pela revogação; o armazém só pelos \
             comandos fs.*, pela gravação dele e pela reposição do boot; quem agiu só se conta \
             na decisão; nenhuma camada sobe acima da barra; e as cargas do boot só pelo boot"
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("[xtask] uma operação protegida chamada fora do ponto de decisão:");
        for f in &fora {
            eprintln!("  {f}");
        }
        eprintln!(
            "\nUm comando executa por `autorizacao::autorizar` e `Autorizado::executar`, que \
             decidem pela política e gravam na auditoria; uma operação administrativa, por \
             `admin.execute`, depois da prova."
        );
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

    let feita = ultima_fase_completa(&readme)
        .ok_or("o roteiro do README não tem nenhuma fase marcada como feita")?;

    let publicada = apos(&main, "pub const FASE: &str = \"")
        .and_then(|resto| resto.split('"').next())
        .ok_or("`pub const FASE` não foi encontrada em kernel/src/main.rs")?;

    if publicada == feita.to_string() {
        println!("[xtask] fase: o kernel publica a fase {feita}, a última completa no roteiro");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "[xtask] fase: o kernel publica a fase {publicada}, e a última completa \
             no roteiro do README é a {feita}"
        );
        Ok(ExitCode::FAILURE)
    }
}

/// A última fase **completa** do roteiro: a maior `N` tal que todo item de
/// fase até `N` está marcado como feito.
///
/// # Por que não a maior marcada
///
/// Porque era isso, e deixou de servir no dia em que a fase 10 terminou com
/// as de 6 a 9 abertas. A maior marcada seria 10, e o kernel passaria a
/// publicar uma fase que promete vários núcleos que ele não tem — o que a
/// documentação de `FASE` avisa desde que ela existe. Completa é até onde
/// não há buraco.
fn ultima_fase_completa(readme: &str) -> Option<u32> {
    let mut fases: Vec<(u32, bool)> = readme
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (feita, resto) = if let Some(r) = l.strip_prefix("- [x] **Fase ") {
                (true, r)
            } else {
                (false, l.strip_prefix("- [ ] **Fase ")?)
            };
            let digitos: String = resto.chars().take_while(char::is_ascii_digit).collect();
            Some((digitos.parse().ok()?, feita))
        })
        .collect();
    fases.sort_by_key(|&(n, _)| n);
    let mut completa = None;
    for (n, feita) in fases {
        if !feita {
            break;
        }
        completa = Some(n);
    }
    completa
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
    for sub in [
        "kernel/src",
        "iniciador/src",
        "protocolo/src",
        "tipografia/src",
        "aparencia/src",
        "toolkit/src",
        "sigilo/src",
        "politica/src",
        "ancora/src",
        "diario/src",
        "armazem/src",
        "programas/src",
        "xtask/src",
    ] {
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
    // E o script de ligação dos programas, que mora fora de `src` — ao lado
    // do `Cargo.toml` que o usa, e não no meio do código.
    if raiz.join("programas").join("usuario.ld").is_file() {
        *no_disco.entry("usuario.ld".to_string()).or_default() += 1;
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

    for sub in [
        "kernel/src",
        "iniciador/src",
        "protocolo/src",
        "tipografia/src",
        "aparencia/src",
        "toolkit/src",
        "sigilo/src",
        "politica/src",
        "programas/src",
    ] {
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

    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?;
    let mut qemu = comando_qemu(
        arch,
        &artefato,
        Some(&socket),
        Teclado::Nativo,
        Video::Linear,
        &ambiente,
    )?;
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
/// As chaves do canal seguro das portas de agente.
///
/// # Geradas uma vez, e guardadas
///
/// Em `target/chaves/`, uma por arquivo, em hexadecimal: a do Duke, a de
/// cada agente das portas, a do administrador e a de um **intruso** — uma
/// chave válida que não está em registro nenhum, para a fumaça conferir que
/// ela é recusada.
///
/// Fora do repositório de propósito: uma chave privada versionada é uma
/// chave pública. Quem clona gera as suas na primeira execução, e o disco de
/// testes é montado com elas.
///
/// # O que vai para a imagem
///
/// A chave **privada** do Duke, em `/etc/duke/privado/chave` — que o kernel
/// lê e não deixa ninguém mais ler —, e as **públicas** dos agentes e do
/// administrador. As privadas dos agentes ficam do lado de fora: são a
/// identidade de quem conversa com a máquina, e a máquina não tem por que
/// tê-las.
mod chaves {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    /// Quantos agentes têm chave: um por porta.
    pub const AGENTES: u8 = super::PORTAS_DE_AGENTE;

    pub struct Chaves {
        pub duke: [u8; 32],
        pub agentes: Vec<[u8; 32]>,
        pub administrador: [u8; 32],
        /// As outras credenciais do grupo de administradores: o quórum de
        /// `admin.revoke` é 2 de 3, e o grupo da imagem tem as três.
        pub outros_administradores: [[u8; 32]; 2],
        /// As chaves **privadas** Ed25519 com que as três credenciais
        /// assinam um quórum, na ordem do grupo. Ficam aqui, em
        /// `target/chaves/`, do lado de quem assina; a imagem recebe só as
        /// públicas.
        pub assinaturas_dos_administradores: [[u8; 32]; 3],
        pub intruso: [u8; 32],
        /// O segredo da pessoa de desenvolvimento: o identificador, o sal e
        /// a senha saem dele — ver [`Chaves::pessoa_dev`].
        pub pessoa_dev: [u8; 32],
    }

    /// O nome da pessoa de desenvolvimento.
    pub const NOME_DA_PESSOA_DEV: &str = "dev";

    /// O papel dela: um papel comum, como o de uma pessoa qualquer. Pessoa e
    /// agente estão no mesmo nível; o `sistema` não é papel de pessoa.
    pub const PAPEL_DA_PESSOA_DEV: &str = "operador";

    /// Onde as chaves moram.
    pub fn diretorio() -> PathBuf {
        super::raiz_do_projeto().join("target").join("chaves")
    }

    /// O nome do agente da porta `p`, no registro e no relatório.
    pub fn nome_do_agente(p: u8) -> String {
        format!("agente-{p}")
    }

    /// O papel do agente da porta `p` na imagem de desenvolvimento: três
    /// operadores e um de sistema. O observador da fumaça é o intruso, que
    /// entra registrado pela serial com esse papel — ver `sob_politica`.
    pub fn papel_do_agente(p: u8) -> &'static str {
        match p {
            1..=3 => "operador",
            _ => "sistema",
        }
    }

    /// Lê uma chave, ou a cria se ainda não existe.
    fn chave(nome: &str) -> Result<[u8; 32], String> {
        let caminho = diretorio().join(format!("{nome}.chave"));
        if let Ok(texto) = std::fs::read_to_string(&caminho) {
            return sigilo::de_hex(&texto)
                .ok_or_else(|| format!("{} não tem uma chave válida", caminho.display()));
        }
        std::fs::create_dir_all(diretorio())
            .map_err(|e| format!("não foi possível criar {}: {e}", diretorio().display()))?;
        let mut chave = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut chave))
            .map_err(|e| format!("sem /dev/urandom para gerar a chave {nome}: {e}"))?;
        // Só o dono lê: é uma chave privada, mesmo que de testes.
        let mut arquivo = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&caminho)
            .map_err(|e| format!("não foi possível criar {}: {e}", caminho.display()))?;
        writeln!(arquivo, "{}", sigilo::hex(&chave))
            .map_err(|e| format!("não foi possível escrever {}: {e}", caminho.display()))?;
        println!("[xtask] chave nova: {}", caminho.display());
        Ok(chave)
    }

    impl Chaves {
        /// As chaves, criando as que faltarem.
        pub fn garantir() -> Result<Chaves, String> {
            Ok(Chaves {
                duke: chave("duke")?,
                agentes: (1..=AGENTES)
                    .map(|p| chave(&nome_do_agente(p)))
                    .collect::<Result<_, _>>()?,
                administrador: chave("administrador")?,
                outros_administradores: [chave("administrador-2")?, chave("administrador-3")?],
                assinaturas_dos_administradores: [
                    chave("administrador-assinatura")?,
                    chave("administrador-2-assinatura")?,
                    chave("administrador-3-assinatura")?,
                ],
                intruso: chave("intruso")?,
                pessoa_dev: chave("pessoa-dev")?,
            })
        }

        /// A pessoa de desenvolvimento: o identificador, o sal e a senha.
        ///
        /// Existe **só** na imagem de desenvolvimento e de testes — é o
        /// mecanismo explícito para quem roda o Duke aqui ter com quem
        /// entrar, e não um login automático: a pessoa ainda digita a senha.
        /// Tudo sai de um arquivo de 32 bytes sorteados em `target/chaves/`,
        /// fora do repositório: os 8 primeiros são o identificador, os 16
        /// seguintes o sal, e os 8 últimos, em hexadecimal, a senha. A
        /// imagem tem só o verificador; a senha fica em
        /// `target/chaves/pessoa-dev.senha`.
        pub fn pessoa_dev(&self) -> ([u8; 8], [u8; 16], String) {
            let b = &self.pessoa_dev;
            let mut id = [0u8; 8];
            id.copy_from_slice(&b[..8]);
            let mut sal = [0u8; 16];
            sal.copy_from_slice(&b[8..24]);
            (id, sal, sigilo::hex_de(&b[24..]))
        }

        /// Escreve a senha da pessoa de desenvolvimento em
        /// `target/chaves/pessoa-dev.senha`, se ainda não está lá: é ela que
        /// se digita no console.
        pub fn escrever_senha_dev(&self) -> Result<(), String> {
            let caminho = diretorio().join("pessoa-dev.senha");
            if caminho.exists() {
                return Ok(());
            }
            let mut arquivo = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&caminho)
                .map_err(|e| format!("não foi possível criar {}: {e}", caminho.display()))?;
            writeln!(arquivo, "{}", self.pessoa_dev().2)
                .map_err(|e| format!("não foi possível escrever {}: {e}", caminho.display()))?;
            println!(
                "[xtask] pessoa de desenvolvimento `{NOME_DA_PESSOA_DEV}`: senha em {}",
                caminho.display()
            );
            Ok(())
        }

        /// O registro de pessoas da imagem: a pessoa de desenvolvimento, com
        /// o verificador Argon2id da senha dela e o custo padrão.
        pub fn registro_de_pessoas(&self) -> Result<String, String> {
            let (id, sal, senha) = self.pessoa_dev();
            let credencial =
                sigilo::credencial::nova(senha.as_bytes(), sal, sigilo::credencial::Custo::PADRAO)
                    .map_err(|e| format!("a credencial da pessoa dev: {}", e.motivo()))?;
            let pessoa = sigilo::pessoas::Pessoa {
                id: sigilo::pessoas::IdPessoa(id),
                nome: NOME_DA_PESSOA_DEV.to_string(),
                papel: PAPEL_DA_PESSOA_DEV.to_string(),
                estado: sigilo::pessoas::Estado::Ativa,
                credencial,
            };
            Ok(format!(
                "# As pessoas que podem entrar pelo console. So o verificador da senha.\n\
                 # Imagem de desenvolvimento: a pessoa `{NOME_DA_PESSOA_DEV}` existe para quem roda\n\
                 # o Duke aqui ter com quem entrar.\n{}",
                sigilo::pessoas::linha(&pessoa)
            ))
        }

        /// A chave privada do agente da porta `p`.
        pub fn do_agente(&self, p: u8) -> [u8; 32] {
            self.agentes[usize::from(p) - 1]
        }

        /// Os arquivos que vão para a imagem.
        pub fn arquivos(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
            let mut agentes =
                String::from("# Os agentes que podem abrir uma porta: chave publica e nome.\n");
            for p in 1..=AGENTES {
                agentes.push_str(&sigilo::registro::linha(
                    &sigilo::publica_de(&self.do_agente(p)),
                    &nome_do_agente(p),
                    Some(papel_do_agente(p)),
                ));
            }
            let mut administradores = String::from(
                "# Quem pode provar uma operacao administrativa. O grupo inteiro: o\n\
                 # quorum de admin.revoke e de M credenciais dele.\n",
            );
            let grupo = [
                ("administrador", &self.administrador),
                ("administrador-2", &self.outros_administradores[0]),
                ("administrador-3", &self.outros_administradores[1]),
            ];
            // A chave X25519 da credencial e a **pública** Ed25519 com que
            // ela assina um quórum. Nenhuma privada vai para a imagem.
            for ((nome, chave), assinatura) in
                grupo.iter().zip(&self.assinaturas_dos_administradores)
            {
                administradores.push_str(&sigilo::registro::linha_de_administrador(
                    &sigilo::publica_de(chave),
                    nome,
                    "administrador",
                    &sigilo::quorum::publica_de_assinatura(assinatura),
                ));
            }
            self.escrever_senha_dev()?;
            // A política só entra na imagem se cumpre o invariante que o
            // kernel confere no boot: só o sistema e o próprio
            // administrador alcançam o administrador. Uma imagem que o
            // violasse subiria com a política de emergência; aqui ela nem é
            // gerada, e o erro aparece antes de qualquer boot.
            let politica = politica::Politica::ler(politica::PADRAO)
                .map_err(|e| format!("a politica da imagem nao se le: {}", e.motivo()))?;
            politica
                .conferir_alcance_aos_administradores(&["administrador"])
                .map_err(|m| {
                    format!("a politica da imagem viola o alcance ao administrador: {m}")
                })?;
            // O teto não é posse: nem a serial, nem a autoridade local, nem
            // um agente da imagem decide pelo papel de um administrador — o
            // kernel recusaria, e a imagem nem é gerada.
            politica
                .conferir_tetos(&["administrador"])
                .map_err(|m| format!("a politica da imagem exerce um teto: {m}"))?;
            if let Some(p) = (1..=AGENTES).find(|&p| papel_do_agente(p) == "administrador") {
                return Err(format!(
                    "o agente {} da imagem tem o papel administrador, que e um teto: delega, nao se exerce",
                    nome_do_agente(p)
                ));
            }
            // O N de cada quórum é o grupo da imagem: uma política que
            // dissesse outro N deixaria a operação sem como acontecer — o
            // kernel a recusa —, e o erro aparece aqui, antes do boot.
            for operacao in politica::arquivo::OPERACOES_DE_QUORUM {
                if let Some(q) = politica.quorum(operacao)
                    && usize::from(q.n) != grupo.len()
                {
                    return Err(format!(
                        "o quorum de {operacao} e de {} credenciais, e a imagem tem {}",
                        q.n,
                        grupo.len()
                    ));
                }
            }
            Ok(vec![
                (
                    "etc/duke/privado/chave".to_string(),
                    format!("{}\n", sigilo::hex(&self.duke)).into_bytes(),
                ),
                // O registro de pessoas, no diretório reservado: o
                // verificador não é a senha, mas quem o tem testa palpites
                // fora da máquina.
                (
                    "etc/duke/privado/pessoas".to_string(),
                    self.registro_de_pessoas()?.into_bytes(),
                ),
                ("etc/duke/agentes".to_string(), agentes.into_bytes()),
                // A política: o mesmo texto que os testes do pacote
                // `politica` leem.
                (
                    "etc/duke/politica".to_string(),
                    politica::PADRAO.as_bytes().to_vec(),
                ),
                (
                    "etc/duke/administradores".to_string(),
                    administradores.into_bytes(),
                ),
            ])
        }
    }
}

mod disco {
    /// O disco inteiro: as quatro partições e a cópia da GPT no fim.
    pub const SETORES: u64 = 272 * 1024 * 1024 / 512;

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

    /// E a partição de estado, depois da raiz: a única área em que o kernel
    /// escreve, onde mora o journal da persistência.
    ///
    /// Um tipo GUID próprio do Duke, e não o `8300` da raiz: a escrita do
    /// kernel se restringe à partição **deste** tipo, e um tipo que qualquer
    /// partição de dados também tem deixaria a raiz ao alcance dela. O mesmo
    /// GUID está em `kernel/src/particoes.rs`, em bytes.
    pub const ESTADO_EM: u64 = RAIZ_EM + RAIZ_SETORES;
    pub const ESTADO_SETORES: u64 = 16 * 1024 * 1024 / 512;
    pub const GUID_DO_ESTADO: &str = "6D7A3C1E-5B2F-4E8A-9C41-D0A7E5C3F911";

    /// E o volume do armazém, depois do estado: a outra área em que o
    /// kernel escreve, por uma janela própria do driver — o conteúdo dos
    /// arquivos e o journal dos metadados deles. O estado de autoridade não
    /// divide partição com ele: encher o volume não enche o journal das
    /// credenciais. O mesmo GUID está em `kernel/src/particoes.rs`.
    pub const ARMAZEM_EM: u64 = ESTADO_EM + ESTADO_SETORES;
    pub const ARMAZEM_SETORES: u64 = 64 * 1024 * 1024 / 512;
    pub const GUID_DO_ARMAZEM: &str = "4A1F7C3B-92D6-4E5A-8B07-C3E91D6F2A58";

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
    ("swtpm", "swtpm"),
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

/// Os programas de usuário compilados, prontos para a raiz do disco.
///
/// Um por arquitetura, em `programas/<arquitetura>/<nome>`: o disco de
/// testes é um só para as duas máquinas, e um executável do x86 não roda no
/// ARM. Cada kernel procura no diretório da sua — ver
/// `crate::usuario::DIRETORIO_DOS_COMPILADOS` no kernel.
///
/// Compilados sempre em release, e sempre os dois: quem monta o disco não
/// sabe qual máquina vai usá-lo depois.
fn programas_do_disco() -> Result<Vec<(String, Vec<u8>)>, String> {
    let dir = raiz_do_projeto().join("programas");
    let nomes = nomes_dos_programas(&dir)?;
    let mut programas = Vec::new();
    for arch in [Arquitetura::X86_64, Arquitetura::Aarch64] {
        let mut cargo = Command::new(env!("CARGO"));
        cargo
            .current_dir(&dir)
            .args(["build", "--release", "--target", arch.alvo()]);
        // Pelo mesmo motivo do build do kernel: o que o cargo exporta para o
        // xtask descreve o build do xtask.
        for var in ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS", "CARGO_TARGET_DIR"] {
            cargo.env_remove(var);
        }
        let status = cargo
            .status()
            .map_err(|e| format!("não foi possível compilar os programas: {e}"))?;
        if !status.success() {
            return Err(format!("os programas não compilaram para {}", arch.nome()));
        }
        for nome in &nomes {
            let caminho = dir
                .join("target")
                .join(arch.alvo())
                .join("release")
                .join(nome);
            let bytes = std::fs::read(&caminho)
                .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
            programas.push((format!("programas/{}/{nome}", arch.nome()), bytes));
        }
    }
    Ok(programas)
}

/// Os nomes dos programas: um por arquivo em `programas/src/bin`, em ordem.
fn nomes_dos_programas(dir: &Path) -> Result<Vec<String>, String> {
    let bin = dir.join("src").join("bin");
    let mut nomes: Vec<String> = std::fs::read_dir(&bin)
        .map_err(|e| format!("não foi possível listar {}: {e}", bin.display()))?
        .filter_map(|entrada| {
            let caminho = entrada.ok()?.path();
            (caminho.extension()? == "rs")
                .then(|| caminho.file_stem()?.to_str().map(String::from))
                .flatten()
        })
        .collect();
    nomes.sort();
    Ok(nomes)
}

/// Um resumo de 64 bits do conteúdo inteiro (FNV-1a).
///
/// Para a receita do disco. Não é criptográfico, nem precisa: o que ele
/// separa é "o programa mudou" de "não mudou", e um executável recompilado
/// muda bytes no meio sem mudar de tamanho.
fn resumo(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
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

fn receita_do_disco(programas: &[(String, Vec<u8>)]) -> String {
    // Tudo que muda a imagem precisa estar aqui, e isso não é uma regra que
    // alguém precise lembrar: a receita é montada a partir das **mesmas**
    // funções que montam o disco. Foi o que faltava quando o tamanho de nó
    // entrou — a lista de parâmetros era uma segunda cópia, o disco velho
    // ficou no lugar, e os casos da descida reprovaram dizendo a verdade
    // sobre uma imagem que já não existia no código.
    let mut receita = format!(
        "v8 setores={} esp={}+{} raiz={}+{} estado={}+{}:{} armazem={}+{}:{} padrao={}..{}\n",
        disco::SETORES,
        disco::ESP_EM,
        disco::ESP_SETORES,
        disco::RAIZ_EM,
        disco::RAIZ_SETORES,
        disco::ESTADO_EM,
        disco::ESTADO_SETORES,
        disco::GUID_DO_ESTADO,
        disco::ARMAZEM_EM,
        disco::ARMAZEM_SETORES,
        disco::GUID_DO_ARMAZEM,
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

    // Os programas não: um executável recompilado muda bytes sem mudar de
    // tamanho, e o byte do meio é uma aposta que ele perde. Entram pelo
    // resumo do conteúdo inteiro, que é pequeno na receita e barato de
    // calcular sobre algumas dezenas de KiB.
    for (nome, conteudo) in programas {
        receita.push_str(&format!(
            "{nome} = {} bytes, resumo={:016x}\n",
            conteudo.len(),
            resumo(conteudo)
        ));
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
fn montar_disco(caminho: &Path, programas: &[(String, Vec<u8>)]) -> Result<(), String> {
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
    // A partição de estado nasce zerada: o journal ainda não existe, e é o
    // primeiro boot que o abre. Os zeros já estão lá — a imagem inteira
    // começou assim.
    ferramenta(
        "sgdisk",
        &[
            "-n",
            &format!(
                "3:{}:+{}M",
                disco::ESTADO_EM,
                disco::ESTADO_SETORES * 512 / 1024 / 1024
            ),
            "-t",
            &format!("3:{}", disco::GUID_DO_ESTADO),
            "-c",
            "3:duke-estado",
            &imagem,
        ],
    )?;
    // O volume do armazém nasce zerado também: é o primeiro boot que o
    // formata, e a criação é confirmada no journal de estado.
    ferramenta(
        "sgdisk",
        &[
            "-n",
            &format!(
                "4:{}:+{}M",
                disco::ARMAZEM_EM,
                disco::ARMAZEM_SETORES * 512 / 1024 / 1024
            ),
            "-t",
            &format!("4:{}", disco::GUID_DO_ARMAZEM),
            "-c",
            "4:duke-armazem",
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
    for (nome, conteudo) in programas {
        escrever_na_arvore(&arvore, nome, conteudo)?;
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
    // Os programas compilados e as chaves vão pela mesma lista: os dois são
    // gerados, e os dois entram na receita pelo resumo do conteúdo inteiro.
    // Uma chave nova muda bytes sem mudar o tamanho, e o byte do meio que
    // basta para os arquivos fixos seria uma aposta perdida uma vez em
    // duzentas e cinquenta e seis — com uma imagem velha, de chaves velhas,
    // ficando no lugar.
    let mut programas = programas_do_disco()?;
    programas.extend(chaves::Chaves::garantir()?.arquivos()?);
    let esperada = receita_do_disco(&programas);

    if caminho.is_file() && std::fs::read_to_string(&receita).is_ok_and(|atual| atual == esperada) {
        return Ok(caminho);
    }

    println!("[xtask] montando o disco de testes (GPT, ESP em FAT32, raiz em Btrfs)");
    montar_disco(&caminho, &programas)?;
    std::fs::write(&receita, &esperada)
        .map_err(|e| format!("não foi possível gravar a receita do disco: {e}"))?;
    println!("[xtask] disco de testes em {}", caminho.display());
    Ok(caminho)
}

/// Onde mora o estado do TPM de uma arquitetura: o diretório do `swtpm`.
fn diretorio_do_tpm(arch: Arquitetura) -> PathBuf {
    raiz_do_projeto()
        .join("target")
        .join(format!("tpm-{}", arch.nome()))
}

/// Zera o estado persistente da máquina: a partição de estado do disco e o
/// TPM. É o que cada comando faz antes de subir a primeira máquina.
///
/// # Por que a cada comando
///
/// Porque o disco é um só e fica em cache entre execuções, e o estado é o
/// que o kernel escreve nele. Uma suíte que herdasse o journal da fumaça
/// anterior testaria o que outra execução deixou, e a mesma rodada passaria
/// ou não conforme a ordem em que se rodou o resto. O TPM vai junto pela
/// mesma razão, e por uma a mais: o journal e a âncora são um par, e zerar
/// só um deles é exatamente o desacordo que o kernel trata como restauração.
///
/// Dentro de um comando o estado persiste: a bancada de persistência sobe a
/// mesma máquina várias vezes sobre ele, e é isso que ela testa.
fn zerar_o_estado(arch: Arquitetura) -> Result<(), String> {
    let disco = disco_de_testes()?;
    escrever_no_estado(&disco, &vec![0u8; (disco::ESTADO_SETORES * 512) as usize])?;
    zerar_o_armazem(&disco)?;
    let _ = std::fs::remove_dir_all(diretorio_do_signatario(arch));
    let tpm = diretorio_do_tpm(arch);
    let _ = std::fs::remove_dir_all(&tpm);
    std::fs::create_dir_all(tpm.join("estado"))
        .map_err(|e| format!("não foi possível criar {}: {e}", tpm.display()))
}

/// Zera o volume do armazém: um volume que sobra de um estado apagado não
/// tem confirmação que o explique, e o boot o recusaria.
fn zerar_o_armazem(disco: &Path) -> Result<(), String> {
    use std::io::{Seek, SeekFrom};
    let mut arquivo = std::fs::OpenOptions::new()
        .write(true)
        .open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    arquivo
        .seek(SeekFrom::Start(disco::ARMAZEM_EM * 512))
        .and_then(|_| arquivo.write_all(&vec![0u8; (disco::ARMAZEM_SETORES * 512) as usize]))
        .and_then(|()| arquivo.sync_all())
        .map_err(|e| format!("não foi possível zerar o volume do armazém: {e}"))
}

/// Os bytes da partição de estado do disco, inteiros.
fn ler_o_estado(disco: &Path) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut arquivo = std::fs::File::open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    let mut bytes = vec![0u8; (disco::ESTADO_SETORES * 512) as usize];
    arquivo
        .seek(SeekFrom::Start(disco::ESTADO_EM * 512))
        .and_then(|_| arquivo.read_exact(&mut bytes))
        .map_err(|e| format!("não foi possível ler a partição de estado: {e}"))?;
    Ok(bytes)
}

/// Escreve `bytes` no começo da partição de estado — e só nela.
fn escrever_no_estado(disco: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom};
    if bytes.len() as u64 > disco::ESTADO_SETORES * 512 {
        return Err("mais bytes que a partição de estado".into());
    }
    let mut arquivo = std::fs::OpenOptions::new()
        .write(true)
        .open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    arquivo
        .seek(SeekFrom::Start(disco::ESTADO_EM * 512))
        .and_then(|_| arquivo.write_all(bytes))
        .and_then(|()| arquivo.sync_all())
        .map_err(|e| format!("não foi possível escrever a partição de estado: {e}"))
}

/// O que uma máquina tem além do disco: o TPM e o relógio.
///
/// # O TPM
///
/// Um `swtpm` por boot, sobre o diretório de estado da arquitetura. Quando
/// a máquina sai com ordem, o QEMU manda o desligamento e o `swtpm` sai
/// sozinho; quando ela morre sem aviso, quem o desliga é este `Drop` — ou a
/// bancada de persistência, que corta a energia dos dois. O estado fica no
/// diretório, como o NV de um TPM de verdade fica no chip, e subir a
/// máquina de novo é subir outro `swtpm` sobre o mesmo diretório.
///
/// O dispositivo é o TIS, a interface de registradores que a especificação
/// de PC define e que os TPMs discretos implementam: `tpm-tis` no x86, no
/// endereço fixo de sempre, e `tpm-tis-device` no ARM, que a máquina `virt`
/// descreve no device tree. É o mesmo protocolo que um TPM físico fala, e
/// por isso o driver do kernel não muda quando ele chegar.
///
/// # O relógio
///
/// O RTC da máquina — o CMOS do x86, a PL031 do ARM — começa onde se mandar.
/// Sem nada, é a hora do hospedeiro; com uma data, é ela. É o que deixa a
/// bancada fazer o relógio andar para trás entre dois boots.
struct Ambiente {
    /// O `swtpm` e o socket dele; `None` numa máquina sem TPM — a da
    /// bancada que confere o que a persistência faz sem âncora.
    tpm: Option<(Child, PathBuf)>,
    relogio: Option<String>,
    /// No x86, o TPM pela interface CRB — a dos TPMs de firmware — em vez
    /// do TIS. O mesmo `swtpm` atrás das duas.
    crb: bool,
}

impl Ambiente {
    /// Liga o TPM para um boot, e fixa o relógio em `relogio` (uma data
    /// `AAAA-MM-DDTHH:MM:SS`), se houver.
    fn ligar(arch: Arquitetura, relogio: Option<&str>) -> Result<Ambiente, String> {
        let swtpm = which("swtpm").ok_or(
            "o `swtpm` não foi encontrado no PATH. Instale o pacote swtpm: é o TPM da máquina",
        )?;
        let dir = diretorio_do_tpm(arch);
        let estado = dir.join("estado");
        std::fs::create_dir_all(&estado)
            .map_err(|e| format!("não foi possível criar {}: {e}", estado.display()))?;
        let socket_do_tpm = dir.join("controle.sock");
        // Um socket Unix tem um teto de caminho (108 bytes no Linux, contando
        // o zero), e passar dele não dá erro do lado de quem cria: o `swtpm`
        // simplesmente sai, e a espera abaixo vencia dizendo só que o socket
        // não apareceu. Medido numa cópia do projeto num diretório fundo.
        if socket_do_tpm.as_os_str().len() >= 104 {
            return Err(format!(
                "o caminho do socket do TPM tem {} bytes, e um socket Unix aceita até 107: {}",
                socket_do_tpm.as_os_str().len(),
                socket_do_tpm.display()
            ));
        }
        let _ = std::fs::remove_file(&socket_do_tpm);
        let tpm = Command::new(swtpm)
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", estado.display()),
                "--ctrl",
                &format!("type=unixio,path={}", socket_do_tpm.display()),
                "--log",
                &format!("file={},level=1", dir.join("swtpm.log").display()),
            ])
            .spawn()
            .map_err(|e| format!("não foi possível iniciar o swtpm: {e}"))?;
        let mut ambiente = Ambiente {
            tpm: Some((tpm, socket_do_tpm.clone())),
            relogio: relogio.map(String::from),
            crb: false,
        };
        // O QEMU recusa um chardev cujo socket ainda não existe.
        let limite = Instant::now() + Duration::from_secs(10);
        while !socket_do_tpm.exists() {
            if let Some((tpm, _)) = ambiente.tpm.as_mut()
                && let Ok(Some(saida)) = tpm.try_wait()
            {
                return Err(format!(
                    "o swtpm saiu antes de abrir o socket ({saida}); ver {}",
                    dir.join("swtpm.log").display()
                ));
            }
            if Instant::now() >= limite {
                return Err("o swtpm não abriu o socket em 10s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(ambiente)
    }
}

impl Ambiente {
    /// Uma máquina sem TPM.
    fn sem_tpm(relogio: Option<&str>) -> Ambiente {
        Ambiente {
            tpm: None,
            relogio: relogio.map(String::from),
            crb: false,
        }
    }
}

impl Drop for Ambiente {
    /// O `swtpm` sai sozinho quando o QEMU sai com ordem; isto cobre o QEMU
    /// morto sem aviso, e o que nem chegou a conectar.
    fn drop(&mut self) {
        if let Some((tpm, _)) = self.tpm.as_mut() {
            let _ = tpm.kill();
            let _ = tpm.wait();
        }
    }
}

/// Quantos núcleos a máquina da bancada tem.
const NUCLEOS_DA_BANCADA: u32 = 4;

/// Os núcleos pedidos por `DUKE_NUCLEOS`, ou [`NUCLEOS_DA_BANCADA`].
///
/// Um valor fora do que a máquina de `arch` liga é recusado em voz alta, e
/// não trocado em silêncio pelo padrão: quem pediu `-smp 16` e recebeu 4 sem
/// aviso concluiria coisas erradas sobre o kernel. O teto é o da máquina, e
/// não um do kernel inteiro: o GICv2 do ARM endereça oito núcleos; no x86, o
/// teto é o do kernel — um núcleo por bit de uma máscara, sessenta e quatro.
fn nucleos_da_bancada(arch: Arquitetura) -> u32 {
    let teto = match arch {
        Arquitetura::X86_64 => 64,
        Arquitetura::Aarch64 => 8,
    };
    match std::env::var("DUKE_NUCLEOS") {
        Err(_) => NUCLEOS_DA_BANCADA,
        Ok(texto) => match texto.trim().parse::<u32>() {
            Ok(n) if (1..=teto).contains(&n) => n,
            _ => {
                eprintln!(
                    "DUKE_NUCLEOS={} nao e um numero de 1 a {}; usando {}",
                    texto, teto, NUCLEOS_DA_BANCADA
                );
                NUCLEOS_DA_BANCADA
            }
        },
    }
}

/// Monta a linha de comando do QEMU para a arquitetura em questão.
fn comando_qemu(
    arch: Arquitetura,
    artefato: &Artefato,
    socket_agente: Option<&Path>,
    teclado: Teclado,
    video: Video,
    ambiente: &Ambiente,
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

    // Vários núcleos, nas duas arquiteturas e nos dois caminhos de boot.
    //
    // Quatro por padrão: o bastante para que dois fios fixos em núcleos
    // diferentes disputem a mesma trava de verdade, com folga para um núcleo
    // travado de propósito sem tirar a concorrência dos outros. O teto é o
    // de cada máquina (oito no ARM, pelo GICv2; sessenta e quatro no x86,
    // pelo kernel), e `DUKE_NUCLEOS` escolhe outro número — `1` é o que roda
    // a suíte como ela rodava antes desta fase, e é como se confere que um
    // núcleo só continua funcionando.
    qemu.args(["-smp", &nucleos_da_bancada(arch).to_string()]);

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
    // `bochs-display` na máquina padrão porque é o **mesmo** dispositivo que
    // o x86 já tem (`1234:1111`), com a mesma interface de programação: um
    // driver serve as duas arquiteturas, e a máquina de todo dia exercita o
    // mesmo caminho nas duas.
    //
    // Tudo isto é a máquina **linear**. A outra — só um `virtio-gpu` — vem
    // logo abaixo. Ela não repete este caminho: é outro, em que a tela do
    // kernel mora sobre um adaptador que só mostra o que se manda, e existe
    // porque há máquinas de verdade que só têm esse.
    //
    // O `id=video0` é para o `screendump` da fumaça: ele fotografa a tela de
    // um dispositivo, e numa máquina com duas — o `bochs` e o `ramfb` — a
    // padrão pode ser a que o kernel não usa.
    if arch == Arquitetura::Aarch64 && video == Video::Linear {
        qemu.args(["-device", "bochs-display,id=video0"]);

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
    if video == Video::Virtio {
        // Só o `virtio-gpu`: no x86 a VGA de fábrica sai, no ARM o `bochs` e
        // o `ramfb` não entram. É a máquina em que o firmware não deixa tela
        // linear nenhuma — o EDK II dirige o `virtio-gpu` com um modo só de
        // transferência, que o iniciador recusa —, e o kernel precisa pôr a
        // tela de pé sozinho.
        if arch == Arquitetura::X86_64 {
            qemu.args(["-vga", "none"]);
        }
        qemu.args(["-device", "virtio-gpu-pci,id=video0"]);
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
            // E o ponteiro, que no ARM também é um `virtio-input`: um tablet,
            // que diz onde o ponteiro está. O x86 tem o mouse PS/2 de
            // fábrica, e não precisa de nada.
            qemu.args(["-device", "virtio-tablet-pci"]);
        }
        (Teclado::Nativo, Arquitetura::X86_64) => {}
        (Teclado::Usb, _) => {
            // O controlador antes dos dispositivos: o `usb-kbd` precisa de um
            // barramento USB para se pendurar, e é o `qemu-xhci` que o cria.
            qemu.args(["-device", "qemu-xhci"]);
            qemu.args(["-device", "usb-kbd"]);
            // E o mouse USB, pela mesma razão do teclado: o mesmo
            // dispositivo e o mesmo driver nas duas arquiteturas. No x86 ele
            // convive com o PS/2, e é ele que recebe o movimento — o
            // emulador entrega ao último mouse que o kernel começou a ler, e
            // a sonda confere que foi o USB.
            qemu.args(["-device", "usb-mouse"]);
        }
    }

    // A rede em modo usuário, com dois destinos de bancada, sem servidor
    // no hospedeiro e sem porta aberta nele:
    //
    // - `10.0.2.100:7`, um eco: cada conexão roda um `cat` ligado a ela, e o
    //   que chega volta. É o destino que a política de desenvolvimento
    //   enumera para `net.connect`;
    // - `10.0.2.100:9`, um outro lado que não fecha: cada conexão roda um
    //   `sleep`, que não lê nem fecha por trinta segundos. Nenhuma política
    //   o enumera; a suíte o põe numa política dela para provar que o fecho
    //   que não termina conta no teto de quem fechou.
    qemu.args([
        "-netdev",
        "user,id=rede0,guestfwd=tcp:10.0.2.100:7-cmd:cat,guestfwd=tcp:10.0.2.100:9-cmd:sleep 30",
    ]);
    qemu.args(["-device", "virtio-net-pci,netdev=rede0"]);

    // A fonte de entropia do kernel: o `/dev/urandom` do hospedeiro, pelo
    // `virtio-rng`. Sem ela as portas de agente recusam o aperto de mão.
    qemu.args(["-device", "virtio-rng-pci"]);

    // O TPM e o relógio — ver [`Ambiente`].
    if let Some((_, socket)) = &ambiente.tpm {
        qemu.args([
            "-chardev",
            &format!("socket,id=tpm0chr,path={}", socket.display()),
            "-tpmdev",
            "emulator,id=tpm0,chardev=tpm0chr",
            "-device",
            match arch {
                Arquitetura::X86_64 if ambiente.crb => "tpm-crb,tpmdev=tpm0",
                Arquitetura::X86_64 => "tpm-tis,tpmdev=tpm0",
                Arquitetura::Aarch64 => "tpm-tis-device,tpmdev=tpm0",
            },
        ]);
    }
    if let Some(data) = &ambiente.relogio {
        qemu.args(["-rtc", &format!("base={data},clock=vm")]);
    }

    qemu.args(["-m", "128M"]);

    // O monitor acompanha o canal do agente: os dois existem quando alguém vai
    // conversar com a máquina, e não quando ela sobe para rodar a suíte e
    // morrer. Ver [`caminho_monitor`] sobre por que ele é necessário.
    if socket_agente.is_some() {
        anexar_monitor(&mut qemu, &caminho_monitor(arch));
        let qmp = caminho_qmp(arch);
        let _ = std::fs::remove_file(&qmp);
        qemu.args([
            "-qmp",
            &format!("unix:{},server=on,wait=off", qmp.display()),
        ]);
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

    anexar_portas_de_agente(&mut qemu, arch, socket_agente.is_some());

    // Sem janela gráfica: este ambiente é headless, e toda a informação que
    // nos importa já sai pelas seriais.
    qemu.args(["-display", "none"]);

    Ok(qemu)
}

/// O console virtio com as portas de agente: uma por agente, cada uma num
/// socket próprio — ver `virtio::console` no kernel.
///
/// Na suíte, sem ninguém para conversar, as portas vão para o `null`: o
/// dispositivo e as portas existem, e o kernel as põe de pé, mas o que a
/// suíte confere nelas passa pela captura do driver.
fn anexar_portas_de_agente(qemu: &mut Command, arch: Arquitetura, com_sockets: bool) {
    // `max_ports` conta a porta 0, a do console do hospedeiro, que o Duke
    // não usa.
    qemu.args([
        "-device",
        &format!(
            "virtio-serial-pci,id=agentes,max_ports={}",
            PORTAS_DE_AGENTE + 1
        ),
    ]);
    for porta in 1..=PORTAS_DE_AGENTE {
        let chardev = if com_sockets {
            let caminho = caminho_canal(arch, porta);
            let _ = std::fs::remove_file(&caminho);
            format!(
                "socket,id=agente{porta},path={},server=on,wait=off",
                caminho.display()
            )
        } else {
            format!("null,id=agente{porta}")
        };
        qemu.args([
            "-chardev",
            &chardev,
            "-device",
            &format!(
                "virtserialport,bus=agentes.0,nr={porta},chardev=agente{porta},name=duke.agente.{porta}"
            ),
        ]);
    }
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

fn run(arch: Arquitetura, release: bool, video: Video) -> Result<ExitCode, String> {
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

    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?;
    comando_qemu(
        arch,
        &artefato,
        Some(&socket),
        Teclado::Nativo,
        video,
        &ambiente,
    )?
    .status()
    .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    Ok(ExitCode::SUCCESS)
}

/// Quanto esperar o canal do agente responder ao primeiro pedido.
const ESPERA_PELA_FUMACA: Duration = Duration::from_secs(90);

/// Uma requisição que não cabe no buffer de linha do kernel (4096 bytes).
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
    r#""}}"#,
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
fn fumaca(
    arch: Arquitetura,
    release: bool,
    teclado: Teclado,
    video: Video,
) -> Result<ExitCode, String> {
    let artefato = build(arch, release, false)?;
    let socket = caminho_socket(arch);

    println!(
        "[xtask] fumaça: subindo o kernel de produção no QEMU ({})",
        arch.nome()
    );

    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?;
    let mut filho = comando_qemu(arch, &artefato, Some(&socket), teclado, video, &ambiente)?
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;

    // A sonda de reconexão vem depois de `conversar` e não dentro dela porque
    // precisa da conexão principal **fechada**: o que ela exercita é o que um
    // cliente novo herda de um cliente que sumiu.
    // Qual tela o `screendump` fotografa. A padrão, na VGA do x86, que é a
    // única; o `video0` nas outras, onde a padrão pode ser uma que o kernel
    // não usa.
    let tela_no_monitor =
        (arch == Arquitetura::Aarch64 || video == Video::Virtio).then_some("video0");
    let resultado = conversar(
        arch,
        &socket,
        &caminho_monitor(arch),
        &caminho_qmp(arch),
        teclado,
        tela_no_monitor,
        filho.id(),
    )
    .and_then(|()| sob_reconexao(&socket));

    // O emulador morre aconteça o que acontecer: um QEMU órfão segura a
    // imagem de disco e faz a *próxima* execução falhar por um motivo que
    // nada tem a ver com ela.
    let _ = filho.kill();
    let _ = filho.wait();
    let _ = std::fs::remove_file(&socket);

    // O estouro de propósito precisa de um boot só dele: depois de uma
    // falha, o kernel só responde o relatório.
    let resultado = resultado.and_then(|()| {
        let tipos: &[&str] = match arch {
            Arquitetura::Aarch64 => &["stack_overflow", "stack_overflow_edge"],
            Arquitetura::X86_64 => &["stack_overflow"],
        };
        tipos.iter().try_for_each(|tipo| {
            sob_estouro(arch, release, &artefato, teclado, video, &socket, tipo)
        })
    });

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

/// Um estouro de verdade da pilha em que um handler de exceção roda vira uma
/// falha relatada como estouro, com o `pc` de quem estourou, e o post-mortem
/// segue de pé.
///
/// # Por que esta sonda existe
///
/// No ARM, a entrada dos vetores empilhava o quadro sem olhar onde: num
/// estouro, o `stp` falhava na guarda, a falha entrava de novo, descia mais
/// 272 bytes, e assim umas quinze vezes, até o quadro ser escrito no topo
/// da vaga vizinha — a pilha de exceção de outro núcleo, viva. O relatório
/// vinha depois disso e apontava para o próprio `stp`. A conferência da
/// entrada dos vetores troca isso por uma falha limpa, na própria vaga.
///
/// No x86 o desfecho já era o certo — a falha de página não tem onde
/// empilhar, e a falha dupla relata da pilha da IST —, e a sonda confere que
/// continua sendo.
///
/// # O que conta como passar
///
/// - o nome da falha: `estouro_da_pilha_de_excecao` no ARM, `double_fault`
///   no x86;
/// - no ARM, o endereço acusado na página de guarda de uma vaga da área de
///   pilhas, e o `pc` dentro da função que afunda — o relatório diz **quem**
///   estourou, e não a entrada dos vetores;
/// - o canal respondendo depois, que é o post-mortem de pé.
///
/// No ARM, dois estouros, um por boot: o da recursão (`stack_overflow`),
/// que chega à guarda pelo alto, e o da borda (`stack_overflow_edge`), que
/// põe `sp` nos 272 bytes de baixo dela — onde o quadro seguinte começaria
/// na vaga vizinha, e só a metade da conferência que olha o último byte do
/// quadro o pega. O endereço acusado da borda é a base da guarda mais 16, e
/// o `pc` é o da função que pisa lá.
fn sob_estouro(
    arch: Arquitetura,
    release: bool,
    artefato: &Artefato,
    teclado: Teclado,
    video: Video,
    socket: &Path,
    tipo: &str,
) -> Result<(), String> {
    println!("[xtask] fumaça: um estouro da pilha de excecao ({tipo}), num boot proprio");
    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?;
    let mut filho = comando_qemu(arch, artefato, Some(socket), teclado, video, &ambiente)?
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;
    let resultado = (|| -> Result<String, String> {
        let fluxo = canal_de_pe(socket, filho.id(), ESPERA_PELA_FUMACA)?;
        fluxo
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| format!("não foi possível configurar o timeout: {e}"))?;
        let mut escrita = fluxo
            .try_clone()
            .map_err(|e| format!("não foi possível duplicar o fluxo: {e}"))?;
        let mut leitor = BufReader::new(fluxo);
        let mut id = 8800;
        let pedido = pedir_pela_serial(
            &mut escrita,
            &mut leitor,
            &mut id,
            "debug.trigger",
            &format!(r#"{{"kind":"{tipo}"}}"#),
        )?;
        if !pedido.contains(&format!(r#""scheduled":"{tipo}""#)) {
            return Err(format!("falha: o estouro nao foi agendado\n  {pedido}"));
        }
        // O post-mortem sobe o canal de novo, em modo direto, e o que
        // estiver em trânsito nessa passagem se perde. Então a conversa
        // recomeça como a de um cliente novo: o mesmo aperto de mão do boot.
        drop((escrita, leitor));
        std::thread::sleep(Duration::from_secs(2));
        let fluxo = canal_de_pe(socket, filho.id(), Duration::from_secs(30))?;
        fluxo
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| format!("não foi possível configurar o timeout: {e}"))?;
        let mut escrita = fluxo
            .try_clone()
            .map_err(|e| format!("não foi possível duplicar o fluxo: {e}"))?;
        let mut leitor = BufReader::new(fluxo);
        pedir_pela_serial(&mut escrita, &mut leitor, &mut id, "traps.stats", "{}")
    })();
    let _ = filho.kill();
    let _ = filho.wait();
    let _ = std::fs::remove_file(socket);
    let stats = resultado?;

    let ultima = apos(&stats, r#""last":"#).unwrap_or("");
    let nome = campo_simples(ultima, "name").unwrap_or_default();
    let esperado = match arch {
        Arquitetura::Aarch64 => "estouro_da_pilha_de_excecao",
        Arquitetura::X86_64 => "double_fault",
    };
    if nome != esperado {
        return Err(format!(
            "falha: o estouro foi relatado como `{nome}`, e nao como `{esperado}`\n  {stats}"
        ));
    }
    if arch == Arquitetura::Aarch64 {
        let endereco = campo_simples(ultima, "address")
            .and_then(|a| a.parse::<u64>().ok())
            .ok_or_else(|| format!("falha: o estouro nao acusou endereco\n  {stats}"))?;
        // A área de pilhas começa em 0x20_0000_0000, em vagas de 64 KiB cuja
        // primeira página é a guarda.
        let na_guarda = endereco >= 0x20_0000_0000 && endereco & 0xF000 == 0;
        let na_borda = endereco & 0xFFFF == 16;
        if !na_guarda || (tipo == "stack_overflow_edge" && !na_borda) {
            return Err(format!(
                "falha: o endereco acusado {endereco:#x} nao e o da guarda que o estouro ({tipo}) tocou"
            ));
        }
        let pc = campo_simples(ultima, "pc")
            .and_then(|a| a.parse::<u64>().ok())
            .ok_or_else(|| format!("falha: o estouro nao trouxe pc\n  {stats}"))?;
        let simbolos = simbolos_do_kernel(&caminho_elf(arch, release))?;
        let dono = simbolos
            .iter()
            .filter(|(_, a)| *a <= pc)
            .max_by_key(|(_, a)| *a)
            .map(|(n, _)| n.as_str())
            .unwrap_or("");
        let quem = if tipo == "stack_overflow_edge" {
            "pisar_no_fundo_da_guarda"
        } else {
            "afundar"
        };
        if !dono.contains(quem) {
            return Err(format!(
                "falha: o pc {pc:#x} do estouro e de `{dono}`, e nao de `{quem}`"
            ));
        }
        println!("  [estouro] ok  {nome} na guarda {endereco:#x}, pc em {dono}");
    } else {
        println!("  [estouro] ok  {nome}, relatado pela pilha da IST");
    }
    Ok(())
}

/// Espera o canal da serial atender, e devolve a conexão já limpa.
///
/// É o aperto de mão da fumaça, separado dela porque a bancada de
/// persistência sobe a mesma máquina várias vezes, e cada boot precisa dele
/// igual.
fn canal_de_pe(socket: &Path, qemu: u32, espera: Duration) -> Result<UnixStream, String> {
    let limite = std::time::Instant::now() + espera;

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
                espera.as_secs()
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

    Ok(fluxo)
}

/// Espera o canal subir e roda as sondas numa conexão só.
fn conversar(
    arch: Arquitetura,
    socket: &Path,
    monitor: &Path,
    qmp: &Path,
    teclado: Teclado,
    tela_no_monitor: Option<&str>,
    qemu: u32,
) -> Result<(), String> {
    let fluxo = canal_de_pe(socket, qemu, ESPERA_PELA_FUMACA)?;

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
    sob_login_no_terminal(monitor, &mut escrita, &mut leitor)?;
    sob_interpretador(monitor, &mut escrita, &mut leitor)?;
    sob_terminal(&mut escrita, &mut leitor)?;
    sob_login_no_console(monitor, qmp, &mut escrita, &mut leitor)?;
    sob_arvore(&mut escrita, &mut leitor)?;
    sob_barra(monitor, &mut escrita, &mut leitor)?;
    sob_mouse(qmp, teclado, &mut escrita, &mut leitor)?;
    sob_janelas(qmp, &mut escrita, &mut leitor)?;
    sob_formulario(arch, monitor, qmp, &mut escrita, &mut leitor)?;
    sob_interface_nativa(arch, &mut escrita, &mut leitor)?;
    sob_o_armazem(arch, &mut escrita, &mut leitor)?;
    sob_a_rede(&mut escrita, &mut leitor)?;
    sob_agentes(arch)?;
    sob_sigilo(arch)?;
    sob_administracao(arch, &mut escrita, &mut leitor)?;
    sob_politica(arch, &mut escrita, &mut leitor)?;
    sob_tela(monitor, tela_no_monitor, &mut escrita, &mut leitor)?;
    sob_fragmento(&mut escrita, &mut leitor)?;
    // Um núcleo travado de propósito, **para sempre**: ele fica travado até
    // o fim, e a sonda da falha, a seguir, confere que a parada do caminho
    // fatal o alcança — ou diz que não o alcançou.
    let travado = sob_nucleo_travado(arch, &mut escrita, &mut leitor)?;
    // Por último, porque não há volta: depois dela o kernel só responde o
    // relatório da falha.
    sob_falha(monitor, tela_no_monitor, &mut escrita, &mut leitor)?;
    sob_falha_para_os_nucleos(arch, travado, &mut escrita, &mut leitor)
}

/// Os núcleos de um `system.info`: índice, estado e pulso de cada um.
fn nucleos_do_relatorio(resposta: &str) -> Vec<(u64, String, u64)> {
    let numero = |trecho: &str, chave: &str| -> Option<u64> {
        let de = trecho.find(&format!("\"{chave}\":"))? + chave.len() + 3;
        let fim = trecho[de..]
            .find(|c: char| !c.is_ascii_digit())
            .map_or(trecho.len(), |f| de + f);
        trecho[de..fim].parse().ok()
    };
    let texto = |trecho: &str, chave: &str| -> Option<String> {
        let de = trecho.find(&format!("\"{chave}\":\""))? + chave.len() + 4;
        let fim = de + trecho[de..].find('"')?;
        Some(trecho[de..fim].to_string())
    };
    resposta
        .split("{\"index\":")
        .skip(1)
        .filter_map(|pedaco| {
            let pedaco = format!("{{\"index\":{pedaco}");
            let fim = pedaco.find('}')?;
            let objeto = &pedaco[..fim];
            Some((
                numero(objeto, "index")?,
                texto(objeto, "state")?,
                numero(objeto, "ticks")?,
            ))
        })
        .collect()
}

/// O canal do agente continua respondendo com um núcleo travado.
///
/// # O que esta sonda prova, de fora
///
/// Pelo canal de verdade, e não por dentro do kernel: o último núcleo é
/// travado **para sempre** com as interrupções desligadas — o pior
/// travamento que não é uma falha —, e então:
///
/// - o canal segue respondendo, pedido após pedido;
/// - o pulso do travado para, e o dos outros anda — que é como um agente
///   enxerga, sem perguntar nada ao núcleo travado, que ele travou;
/// - o escalonador segue: as trocas de contexto continuam subindo;
/// - o fio do travamento aparece em `threads.list`, no núcleo que ele travou.
///
/// Devolve o índice do núcleo travado, que fica travado até o fim.
fn sob_nucleo_travado(
    arch: Arquitetura,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<u64, String> {
    println!("[xtask] fumaça: um núcleo travado não cala o canal");
    let mut id = 8800;
    let info = pedir_pela_serial(escrita, leitor, &mut id, "system.info", "{}")?;
    let nucleos = nucleos_do_relatorio(&info);
    let ligados: Vec<u64> = nucleos
        .iter()
        .filter(|(_, estado, _)| estado == "online")
        .map(|(i, _, _)| *i)
        .collect();
    if ligados.len() < 2 {
        return Err(format!(
            "nucleos: a bancada tem {} nucleo(s) ligado(s), e esta sonda precisa de dois\n  {info}",
            ligados.len()
        ));
    }
    let alvo = *ligados.last().expect("conferido acima");

    // Pedir para travar o primeiro é recusado: é o núcleo do canal.
    let recusa = pedir_pela_serial(
        escrita,
        leitor,
        &mut id,
        "debug.trigger",
        r#"{"kind":"hang_core","core":0}"#,
    )?;
    if !recusa.contains(r#""error":"#) {
        return Err(format!(
            "nucleos: travar o nucleo do canal nao foi recusado\n  {recusa}"
        ));
    }

    let trocas = |r: &str| -> Option<u64> {
        let de = r.find(r#""context_switches":"#)? + 19;
        let fim = de + r[de..].find(|c: char| !c.is_ascii_digit())?;
        r[de..fim].parse().ok()
    };
    let antes_das_trocas = trocas(&pedir_pela_serial(
        escrita,
        leitor,
        &mut id,
        "threads.stats",
        "{}",
    )?)
    .ok_or("nucleos: threads.stats sem context_switches")?;

    let travou = pedir_pela_serial(
        escrita,
        leitor,
        &mut id,
        "debug.trigger",
        &format!(r#"{{"kind":"hang_core","core":{alvo},"ms":0}}"#),
    )?;
    if !travou.contains(r#""triggered":"hang_core""#) {
        return Err(format!("nucleos: o travamento nao foi aceito\n  {travou}"));
    }

    // O fio do travamento leva um instante para ser escolhido.
    std::thread::sleep(Duration::from_millis(500));
    let primeira = nucleos_do_relatorio(&pedir_pela_serial(
        escrita,
        leitor,
        &mut id,
        "system.info",
        "{}",
    )?);
    // Muitos pedidos seguidos, com o núcleo travado: todos precisam voltar.
    for _ in 0..20 {
        pedir_pela_serial(escrita, leitor, &mut id, "agent.ping", "{}")?;
        std::thread::sleep(Duration::from_millis(50));
    }
    let segunda = nucleos_do_relatorio(&pedir_pela_serial(
        escrita,
        leitor,
        &mut id,
        "system.info",
        "{}",
    )?);

    let pulso = |amostra: &[(u64, String, u64)], i: u64| {
        amostra.iter().find(|(n, _, _)| *n == i).map(|(_, _, t)| *t)
    };
    for &i in &ligados {
        let (Some(a), Some(b)) = (pulso(&primeira, i), pulso(&segunda, i)) else {
            return Err(format!("nucleos: o nucleo {i} sumiu do system.info"));
        };
        if i == alvo && b > a + 1 {
            return Err(format!(
                "nucleos: o nucleo travado {i} continuou com pulso ({a} -> {b})"
            ));
        }
        if i != alvo && b <= a {
            return Err(format!(
                "nucleos: o nucleo {i} perdeu o pulso junto com o travado ({a} -> {b})"
            ));
        }
    }

    let fios = pedir_pela_serial(escrita, leitor, &mut id, "threads.list", "{}")?;
    if !fios.contains(r#""name":"travado","state":"running","scheduled":"#)
        || !fios.contains(&format!(r#""core":{alvo},"pinned":{alvo}"#))
    {
        return Err(format!(
            "nucleos: o fio do travamento nao aparece rodando no nucleo {alvo}\n  {fios}"
        ));
    }
    let depois_das_trocas = trocas(&pedir_pela_serial(
        escrita,
        leitor,
        &mut id,
        "threads.stats",
        "{}",
    )?)
    .ok_or("nucleos: threads.stats sem context_switches")?;
    if depois_das_trocas <= antes_das_trocas {
        return Err("nucleos: o escalonador parou junto com o nucleo travado".into());
    }

    println!(
        "  [nucleos] ok  nucleo {alvo} travado para sempre; o canal respondeu {} pedidos, o pulso dele parou e o dos outros {} andou ({})",
        24,
        ligados.len() - 1,
        arch.nome()
    );
    Ok(alvo)
}

/// Depois da falha, o relatório diz se a parada alcançou o núcleo travado.
///
/// # O que muda de uma arquitetura para a outra, e por quê
///
/// No x86 a parada vai por NMI, que atravessa a máscara de interrupções: o
/// núcleo travado **para**, e aparece na máscara dos parados. No ARM ela vai
/// por uma SGI do GIC v2, que um núcleo mascarado não ouve: ele aparece na
/// dos que **não responderam** — e o relatório segue sem ele, em vez de
/// esperá-lo para sempre. As duas respostas são verdadeiras; a sonda exige a
/// de cada uma.
fn sob_falha_para_os_nucleos(
    arch: Arquitetura,
    travado: u64,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    let mut id = 8950;
    let info = pedir_pela_serial(escrita, leitor, &mut id, "system.info", "{}")?;
    let mascara = |chave: &str| -> Option<u64> {
        let de = info.find(&format!("\"{chave}\":"))? + chave.len() + 3;
        let fim = de + info[de..].find(|c: char| !c.is_ascii_digit())?;
        info[de..fim].parse().ok()
    };
    let parados = mascara("fatal_stopped_mask").ok_or("falha: sem fatal_stopped_mask")?;
    let sem_resposta =
        mascara("fatal_unanswered_mask").ok_or("falha: sem fatal_unanswered_mask")?;
    let bit = 1u64 << travado;
    let (esperada, nome) = match arch {
        Arquitetura::X86_64 => (parados, "parado por NMI"),
        Arquitetura::Aarch64 => (sem_resposta, "sem resposta (SGI mascarada)"),
    };
    if esperada & bit == 0 {
        return Err(format!(
            "falha: o nucleo travado {travado} nao esta na mascara esperada ({nome}): parados {parados:#b}, sem resposta {sem_resposta:#b}"
        ));
    }
    println!(
        "  [falha] ok  o nucleo travado {travado} esta {nome}; parados {parados:#b}, sem resposta {sem_resposta:#b}"
    );
    Ok(())
}

/// A cor que a tela de falha pinta — `Cor::FALHA` do kernel.
const COR_DE_FALHA: [u8; 3] = [0x60, 0x10, 0x10];

/// A tela de falha chega ao monitor.
///
/// # Por que esta sonda existe
///
/// Porque o caminho fatal é o único que desenha sem o compositor — ele não
/// pode confiar na trava nem no heap que o compositor usa —, e nada o
/// exercitava: nem a suíte, que morreria junto, nem a fumaça.
///
/// # O porquê de ir por baixo
///
/// Ir direto à tela física é para a falha que acontece **dentro** do
/// compositor, com o quadro pela metade ou a trava no meio de uma operação —
/// e essa falha a sonda não sabe provocar: `debug.trigger` falha na tarefa
/// do agente. O que ela prova é o resto: a falha desliga o compositor, e
/// por isso pintar a camada do console em vez da tela física não chega mais
/// ao monitor. Com o compositor vivo, chegava — medido, essa mutação passava
/// por esta sonda.
///
/// # O que conta como passar
///
/// Nove décimos da foto na cor de falha. Não a foto inteira: depois da tela
/// de falha o post-mortem escreve por cima dela, e esse texto ocupa um
/// canto. O que a sonda recusa é a tela que continua mostrando o console —
/// que não tem quase nada dessa cor.
fn sob_falha(
    monitor: &Path,
    tela_no_monitor: Option<&str>,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: a tela de falha chega ao monitor");
    escrita
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":8901,\"method\":\"debug.trigger\",\"params\":{\"kind\":\"fatal\"}}\n",
        )
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("falha: nao consegui pedir a falha: {e}"))?;

    let destino = raiz_do_projeto()
        .join("target")
        .join(format!("falha-{}.ppm", std::process::id()));
    let mut fracao = 0.0f64;
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(500));
        let foto = fotografar(monitor, &destino, tela_no_monitor)?;
        let total = (foto.largura as usize * foto.altura as usize).max(1);
        let vermelhos = foto
            .pixels
            .as_chunks::<3>()
            .0
            .iter()
            .filter(|p| **p == COR_DE_FALHA)
            .count();
        fracao = vermelhos as f64 / total as f64;
        if fracao >= 0.9 {
            let _ = std::fs::remove_file(&destino);
            println!(
                "  [falha] ok  {:.1}% da tela na cor de falha ({}x{})",
                fracao * 100.0,
                foto.largura,
                foto.altura
            );
            return sob_falha_o_post_mortem_nao_desenha(
                monitor,
                tela_no_monitor,
                &destino,
                escrita,
                leitor,
            );
        }
    }
    let _ = std::fs::remove_file(&destino);
    Err(format!(
        "falha: a tela de falha nao chegou ao monitor; so {:.1}% da foto tem a cor dela",
        fracao * 100.0
    ))
}

/// Depois da tela de falha, o que o agente pede não desenha por cima dela.
///
/// # Por que esta parte existe
///
/// Porque desenhava. O canal do agente segue respondendo no post-mortem, e
/// um `ui.act` com `press` no botão da barra limpava o console e
/// redesenhava a barra pelo compositor, que continuava vivo. Medido nas duas
/// arquiteturas: a foto ia de 99,8% da tela na cor de falha para zero. Agora
/// o compositor é desligado na falha, e a interface recusa agir no
/// post-mortem.
///
/// # O que conta como passar
///
/// A ação recusada, com o motivo, e a tela ainda nove décimos na cor de
/// falha depois dela.
fn sob_falha_o_post_mortem_nao_desenha(
    monitor: &Path,
    tela_no_monitor: Option<&str>,
    destino: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    escrita
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":8902,\"method\":\"ui.act\",\"params\":{\"id\":5,\"action\":\"press\"}}\n",
        )
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("falha: nao consegui pedir o press: {e}"))?;
    // A resposta ao pedido da falha pode vir antes: ela sai inteira, e só
    // então o kernel falha.
    let mut resposta = String::new();
    for _ in 0..4 {
        resposta = ler_resposta(leitor).map_err(|e| format!("falha: {e}"))?;
        if e_a_resposta(&resposta, 8902) {
            break;
        }
    }
    if !e_a_resposta(&resposta, 8902) {
        return Err(format!(
            "falha: o press do post-mortem nao teve resposta\n  {resposta}"
        ));
    }
    if !resposta.contains(r#""ok":false"#) || !resposta.contains("post-mortem") {
        return Err(format!(
            "falha: a interface agiu no post-mortem\n  {}",
            resposta.trim()
        ));
    }

    std::thread::sleep(Duration::from_millis(500));
    let foto = fotografar(monitor, destino, tela_no_monitor)?;
    let _ = std::fs::remove_file(destino);
    let total = (foto.largura as usize * foto.altura as usize).max(1);
    let vermelhos = foto
        .pixels
        .as_chunks::<3>()
        .0
        .iter()
        .filter(|p| **p == COR_DE_FALHA)
        .count();
    let fracao = vermelhos as f64 / total as f64;
    if fracao < 0.9 {
        return Err(format!(
            "falha: o press do post-mortem apagou a tela de falha; so {:.1}% da foto tem a cor dela",
            fracao * 100.0
        ));
    }
    println!(
        "  [falha] ok  o press do post-mortem foi recusado, e a tela de falha ficou ({:.1}%)",
        fracao * 100.0
    );
    Ok(())
}

/// O que as três teclas da sonda devem produzir.
const ESPERADO_DO_TECLADO: &str = "abCde";

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
///
/// E `d-e`, as duas seguradas juntas: no USB, o relatório passa a carregar
/// duas teclas, e só a segunda é nova. Um driver que lesse o relatório pela
/// metade — os três primeiros bytes, que bastam para uma tecla de cada vez —
/// perderia o `e`. Medido: com essa mutação no pedido do xHCI, o resto da
/// fumaça passava.
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

    for tecla in ["a", "b", "shift-c", "d-e"] {
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

    println!("  [teclado] ok  `a`, `b`, `shift-c` e `d-e` chegaram como `{ESPERADO_DO_TECLADO}`");
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
/// O `ret` da frente não é enfeite: a sonda anterior digitou `abCde` e essa
/// linha ainda está aberta no interpretador. Executá-la — e receber
/// "comando desconhecido" — é o que devolve a linha vazia, e de quebra
/// exercita o caminho de recusa.
/// A tela que o kernel acha que desenhou é a que o hospedeiro mostra.
///
/// # A pergunta que nada mais responde
///
/// `video.sample` lê de volta a memória onde o kernel desenha. Num
/// framebuffer linear, o que está ali é o que aparece — o dispositivo varre
/// aquela memória sozinho. Num `virtio-gpu`, não: só aparece o que foi
/// transferido e descarregado, e o kernel pode ter a tela certa na memória e
/// o monitor preto. Os testes do kernel perguntam ao kernel, e o kernel não
/// tem como saber o que o hospedeiro mostra.
///
/// O hospedeiro tem: o `screendump` do monitor fotografa a tela como ela sai
/// do dispositivo. A sonda amostra pelo agente, fotografa, amostra de novo, e
/// compara ponto por ponto — os mesmos pontos, pela mesma conta de
/// `video.sample`. Se as duas amostras diferirem, a tela mudou no meio, e a
/// rodada é refeita.
///
/// Roda nas duas máquinas: na linear ela afirma que a tela do kernel é a do
/// monitor, o que já devia ser verdade e passa a ser conferido; na do
/// `virtio-gpu` ela afirma que a descarga acontece.
fn sob_tela(
    monitor: &Path,
    tela_no_monitor: Option<&str>,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: a tela que o kernel desenhou é a que o hospedeiro mostra");
    let destino = raiz_do_projeto()
        .join("target")
        .join(format!("tela-{}.ppm", std::process::id()));

    let mut motivo = String::from("nenhuma rodada chegou a comparar");
    for rodada in 0..5u32 {
        let antes = amostra_da_tela(escrita, leitor, 8801 + rodada * 2)?;
        let foto = fotografar(monitor, &destino, tela_no_monitor);
        let depois = amostra_da_tela(escrita, leitor, 8802 + rodada * 2)?;
        let foto = foto?;
        if antes != depois {
            motivo = "a tela mudou enquanto era fotografada, em todas as rodadas".into();
            std::thread::sleep(Duration::from_millis(300));
            continue;
        }
        match comparar_com_a_foto(&antes, &foto) {
            Ok(pontos) => {
                let _ = std::fs::remove_file(&destino);
                println!(
                    "  [tela] ok  {pontos} pontos iguais entre a amostra do kernel e o screendump do hospedeiro ({}x{})",
                    foto.largura, foto.altura
                );
                return Ok(());
            }
            Err(diferenca) => motivo = diferenca,
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let _ = std::fs::remove_file(&destino);
    Err(format!("tela: {motivo}"))
}

/// O que `video.sample` devolve.
#[derive(PartialEq, Eq, Debug)]
struct Amostra {
    largura: u32,
    altura: u32,
    colunas: u32,
    linhas: u32,
    grade: Vec<String>,
}

fn amostra_da_tela(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
    id: u32,
) -> Result<Amostra, String> {
    escrita
        .write_all(
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"video.sample","params":{{"columns":64,"rows":48}}}}"#
            )
            .as_bytes(),
        )
        .and_then(|()| escrita.write_all(b"\n"))
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("tela: falha ao pedir a amostra: {e}"))?;
    let resposta = ler_resposta(leitor).map_err(|e| format!("tela: {e}"))?;
    if !e_a_resposta(&resposta, id) {
        return Err(format!(
            "tela: veio a resposta de outro pedido\n  {resposta}"
        ));
    }
    ler_amostra(&resposta).ok_or_else(|| format!("tela: a amostra nao se le\n  {resposta}"))
}

/// Tira de uma resposta de `video.sample` o que a comparação precisa.
///
/// À mão, porque o `xtask` não depende de biblioteca de JSON, e o que se lê
/// aqui são quatro números e uma lista de strings sem escape nenhum — só
/// dígitos hexadecimais, espaços e pontos.
fn ler_amostra(resposta: &str) -> Option<Amostra> {
    let numero = |chave: &str| -> Option<u32> {
        let resto = apos(resposta, &format!("\"{chave}\":"))?;
        resto
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    };
    let grade_bruta = apos(resposta, "\"grid\":[")?.split(']').next()?;
    let grade: Vec<String> = grade_bruta
        .split('"')
        .skip(1)
        .step_by(2)
        .map(String::from)
        .collect();
    Some(Amostra {
        largura: numero("width")?,
        altura: numero("height")?,
        colunas: numero("columns")?,
        linhas: numero("rows")?,
        grade,
    })
}

/// Uma foto da tela, em RGB de 8 bits por componente.
struct Foto {
    largura: u32,
    altura: u32,
    pixels: Vec<u8>,
}

/// Pede ao monitor um `screendump` e espera o arquivo ficar inteiro.
///
/// O monitor não diz quando terminou de escrever; o que diz é o tamanho do
/// arquivo. Um PPM tem o cabeçalho e três bytes por pixel, e só com os dois
/// batendo a foto está pronta.
fn fotografar(monitor: &Path, destino: &Path, dispositivo: Option<&str>) -> Result<Foto, String> {
    let _ = std::fs::remove_file(destino);
    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("tela: o monitor nao aceitou conexao: {e}"))?;
    let comando = match dispositivo {
        Some(d) => format!("screendump {} -f ppm {d}\n", destino.display()),
        None => format!("screendump {} -f ppm\n", destino.display()),
    };
    mon.write_all(comando.as_bytes())
        .and_then(|()| mon.flush())
        .map_err(|e| format!("tela: falha ao pedir o screendump: {e}"))?;

    let limite = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < limite {
        if let Ok(bytes) = std::fs::read(destino)
            && let Some(foto) = ler_ppm(&bytes)
        {
            return Ok(foto);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "tela: o screendump nao produziu uma imagem inteira em {} em 5s",
        destino.display()
    ))
}

/// Lê um PPM binário (P6) de 8 bits. `None` se ele ainda não está inteiro.
fn ler_ppm(bytes: &[u8]) -> Option<Foto> {
    // O cabeçalho são quatro campos separados por espaço em branco — `P6`,
    // largura, altura e o valor máximo —, e depois dele um único espaço em
    // branco antes dos pixels.
    let mut campos = Vec::new();
    let mut i = 0;
    while campos.len() < 4 {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let inicio = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if inicio == i {
            return None;
        }
        campos.push(std::str::from_utf8(&bytes[inicio..i]).ok()?);
    }
    if campos[0] != "P6" || campos[3] != "255" {
        return None;
    }
    let largura: u32 = campos[1].parse().ok()?;
    let altura: u32 = campos[2].parse().ok()?;
    let pixels = bytes.get(i + 1..)?;
    (pixels.len() == largura as usize * altura as usize * 3).then(|| Foto {
        largura,
        altura,
        pixels: pixels.to_vec(),
    })
}

/// Compara a amostra do kernel com a foto, ponto por ponto. Devolve quantos
/// pontos foram comparados.
fn comparar_com_a_foto(amostra: &Amostra, foto: &Foto) -> Result<usize, String> {
    if (foto.largura, foto.altura) != (amostra.largura, amostra.altura) {
        return Err(format!(
            "o hospedeiro mostra uma tela de {}x{}, e o kernel desenha numa de {}x{}",
            foto.largura, foto.altura, amostra.largura, amostra.altura
        ));
    }
    if amostra.grade.len() != amostra.linhas as usize {
        return Err("a amostra nao tem as linhas que diz ter".into());
    }
    let mut pontos = 0;
    let mut diferentes = Vec::new();
    for (linha, cores) in amostra.grade.iter().enumerate() {
        let linha = linha as u32;
        // A mesma conta de `video.sample`: o centro de cada célula.
        let y = (linha * 2 + 1) * amostra.altura / (amostra.linhas * 2);
        for (coluna, cor) in cores.split(' ').enumerate() {
            let coluna = coluna as u32;
            let x = (coluna * 2 + 1) * amostra.largura / (amostra.colunas * 2);
            let i = (y as usize * foto.largura as usize + x as usize) * 3;
            let na_foto = format!(
                "{:02x}{:02x}{:02x}",
                foto.pixels[i],
                foto.pixels[i + 1],
                foto.pixels[i + 2]
            );
            pontos += 1;
            if na_foto != cor {
                diferentes.push(format!("({x},{y}): kernel {cor}, hospedeiro {na_foto}"));
            }
        }
    }
    if diferentes.is_empty() {
        Ok(pontos)
    } else {
        Err(format!(
            "{} de {} pontos diferem entre o que o kernel desenhou e o que o hospedeiro mostra; os primeiros:\n  {}",
            diferentes.len(),
            pontos,
            diferentes[..diferentes.len().min(5)].join("\n  ")
        ))
    }
}

/// O agente opera a máquina pela árvore semântica, no kernel de produção.
///
/// A suíte exercita a árvore no lugar do interpretador, porque em modo de
/// teste a tarefa dele não existe. Aqui ela existe: a linha de comando é a
/// que a pessoa na frente da máquina está vendo, e o que o agente faz nela
/// passa pela tarefa de verdade.
///
/// A prova fecha o ciclo inteiro por fora: o agente define o valor da linha,
/// confirma, e lê **pela própria árvore** a resposta desenhada no console —
/// sem amostrar pixel nenhum. E o log diz que foi o agente.
fn sob_arvore(escrita: &mut UnixStream, leitor: &mut BufReader<UnixStream>) -> Result<(), String> {
    println!("[xtask] fumaça: o agente age pela árvore semântica");

    let mut pedir = |id: u32, metodo: &str, params: &str| -> Result<String, String> {
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("arvore: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("arvore: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "arvore: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };

    let arvore = pedir(7701, "ui.tree", "{}")?;
    if !arvore.contains(r#""role":"text_field""#) {
        return Err(format!(
            "arvore: com o interpretador atendendo, a linha de comando nao esta na arvore\n  {arvore}"
        ));
    }

    let r = pedir(
        7702,
        "ui.act",
        r#"{"id":3,"action":"set_value","value":"system.uptime"}"#,
    )?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!("arvore: set_value recusado\n  {r}"));
    }
    let arvore = pedir(7703, "ui.tree", "{}")?;
    if !arvore.contains(r#""value":"system.uptime""#) {
        return Err(format!(
            "arvore: a linha de comando nao ficou com o valor\n  {arvore}"
        ));
    }

    let r = pedir(7704, "ui.act", r#"{"id":3,"action":"confirm"}"#)?;
    if !r.contains(r#""executed":"system.uptime""#) {
        return Err(format!("arvore: confirm nao executou a linha\n  {r}"));
    }

    // A resposta do comando foi desenhada no console, e a árvore a lê de lá.
    let arvore = pedir(7705, "ui.tree", "{}")?;
    if !arvore.contains("uptime_ms") {
        return Err(format!(
            "arvore: a resposta do comando nao apareceu no texto do console\n  {arvore}"
        ));
    }
    let log = pedir(7706, "log.tail", r#"{"count":16}"#)?;
    if !log.contains("executado: system.uptime (agente 0)") {
        return Err(format!(
            "arvore: o log nao registrou o agente como origem\n  {log}"
        ));
    }

    println!("  [arvore] ok  set_value, confirm e a resposta lida de volta pela arvore");
    Ok(())
}

/// Um pedido ao QMP, e a resposta dele.
///
/// O QMP responde uma linha por pedido, mas também manda eventos quando quer
/// — um `{"event": ...}` pode chegar antes da resposta. Lê até a resposta.
/// Abre o QMP do emulador e passa da saudação e da negociação.
fn qmp_abrir(qmp: &Path) -> Result<(UnixStream, BufReader<UnixStream>), String> {
    let fluxo = UnixStream::connect(qmp).map_err(|e| format!("mouse: o QMP nao aceitou: {e}"))?;
    fluxo
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("mouse: {e}"))?;
    let mut escrita = fluxo.try_clone().map_err(|e| format!("mouse: {e}"))?;
    let mut leitor = BufReader::new(fluxo);
    let mut saudacao = String::new();
    leitor
        .read_line(&mut saudacao)
        .map_err(|e| format!("mouse: o QMP nao saudou: {e}"))?;
    qmp_pedir(
        &mut escrita,
        &mut leitor,
        r#"{"execute":"qmp_capabilities"}"#,
    )?;
    Ok((escrita, leitor))
}

/// Manda eventos de entrada pelo QMP.
///
/// O QMP recusa o formato que nenhum dispositivo da máquina entende — o
/// relativo numa máquina só com o tablet, o absoluto numa sem tablet — com
/// "Input handler not found". Essa recusa é esperada, e devolve falso;
/// qualquer outra é defeito.
fn qmp_eventos(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
    lista: &str,
    formato: &str,
) -> Result<bool, String> {
    let r = qmp_pedir(
        escrita,
        leitor,
        &format!(r#"{{"execute":"input-send-event","arguments":{{"events":[{lista}]}}}}"#),
    )?;
    if !r.contains("\"error\"") {
        return Ok(true);
    }
    if r.contains(&format!("Input handler not found for event type {formato}")) {
        return Ok(false);
    }
    Err(format!("mouse: o QMP recusou o movimento\n  {r}"))
}

fn qmp_pedir(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
    pedido: &str,
) -> Result<String, String> {
    escrita
        .write_all(pedido.as_bytes())
        .and_then(|()| escrita.write_all(b"\n"))
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("mouse: falha ao falar com o QMP: {e}"))?;
    loop {
        let mut linha = String::new();
        leitor
            .read_line(&mut linha)
            .map_err(|e| format!("mouse: o QMP nao respondeu: {e}"))?;
        if linha.is_empty() {
            return Err("mouse: o QMP fechou a conexao".into());
        }
        if linha.contains("\"return\"") || linha.contains("\"error\"") {
            return Ok(linha);
        }
    }
}

/// O ponteiro, pelo mouse da máquina: vai até o botão da barra e clica.
///
/// O movimento sai do QMP do emulador nos dois formatos — posição absoluta
/// e deslocamento — e cada dispositivo recebe o que entende: o tablet virtio
/// do ARM, a posição; o mouse PS/2 do x86 e o mouse USB, o deslocamento. O
/// relativo anda a diferença entre onde o kernel diz que o ponteiro está e o
/// botão.
///
/// Onde está o botão sai da árvore semântica, e não de um número escrito
/// aqui: a sonda clica onde a árvore diz que ele está, e é isso que ela
/// confere — que o clique e a árvore concordam.
fn sob_mouse(
    qmp: &Path,
    teclado: Teclado,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: o mouse, até o botão da barra");
    const BOTAO: u32 = 5;

    let mut pedir = |id: u32, metodo: &str, params: &str| -> Result<String, String> {
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("mouse: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("mouse: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "mouse: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };

    // O centro do botão, pela moldura que a árvore publica.
    let arvore = pedir(7901, "ui.tree", "{}")?;
    let marca = format!(r#""id":{BOTAO},"role":"button""#);
    let resto = &arvore[arvore
        .find(&marca)
        .ok_or_else(|| format!("mouse: a arvore nao tem o botao\n  {arvore}"))?..];
    let numero = |chave: &str| -> Result<u32, String> {
        valor_de(resto, &format!(r#""{chave}":"#))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("mouse: a moldura do botao nao tem `{chave}`"))
    };
    let (bx, by, bl, ba) = (
        numero("x")?,
        numero("y")?,
        numero("width")?,
        numero("height")?,
    );
    let (cx, cy) = (bx + bl / 2, by + ba / 2);
    let info = pedir(7902, "display.info", "{}")?;
    let dimensao = |chave: &str| -> Result<u32, String> {
        valor_de(&info, &format!(r#""{chave}":"#))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("mouse: display.info nao tem `{chave}`\n  {info}"))
    };
    let (largura, altura) = (dimensao("width")?, dimensao("height")?);

    let (mut qmp_escrita, mut qmp_leitor) = qmp_abrir(qmp)?;
    // A escala do QMP para posição absoluta vai de 0 a 32767.
    let escala = |v: u32, lado: u32| (v as u64 * 32767 / (lado.max(2) - 1) as u64) as u32;
    let absoluto = format!(
        r#"{{"type":"abs","data":{{"axis":"x","value":{}}}}},{{"type":"abs","data":{{"axis":"y","value":{}}}}}"#,
        escala(cx, largura),
        escala(cy, altura)
    );
    let relativo = |dx: i64, dy: i64| {
        format!(
            r#"{{"type":"rel","data":{{"axis":"x","value":{dx}}}}},{{"type":"rel","data":{{"axis":"y","value":{dy}}}}}"#
        )
    };
    let absoluto_aceito = qmp_eventos(&mut qmp_escrita, &mut qmp_leitor, &absoluto, "abs")?;
    std::thread::sleep(Duration::from_millis(150));

    // O relativo anda a diferença entre onde o ponteiro está e o botão, em
    // passos de até cem. Não um salto só, nem um "vá para o canto" antes: o
    // mouse PS/2 do emulador acumula o deslocamento e o entrega aos pedaços,
    // conforme a fila dele esvazia, e um salto grande fica pendurado no
    // acumulador e engole o movimento seguinte — medido, um -4000 para o
    // canto seguido de +96 deixou o ponteiro em zero.
    let info = pedir(7903, "display.info", "{}")?;
    let ponteiro = info.find(r#""pointer":"#).map(|i| &info[i..]).unwrap_or("");
    let px: i64 = valor_de(ponteiro, r#""x":"#)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let py: i64 = valor_de(ponteiro, r#""y":"#)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let (mut faltam_x, mut faltam_y) = (cx as i64 - px, cy as i64 - py);
    let mut relativo_aceito = false;
    while faltam_x != 0 || faltam_y != 0 {
        let passo_x = faltam_x.clamp(-100, 100);
        let passo_y = faltam_y.clamp(-100, 100);
        if !qmp_eventos(
            &mut qmp_escrita,
            &mut qmp_leitor,
            &relativo(passo_x, passo_y),
            "rel",
        )? {
            break;
        }
        relativo_aceito = true;
        faltam_x -= passo_x;
        faltam_y -= passo_y;
        std::thread::sleep(Duration::from_millis(30));
    }
    if !absoluto_aceito && !relativo_aceito && (px, py) != (cx as i64, cy as i64) {
        return Err("mouse: nenhum dispositivo da maquina aceitou movimento".into());
    }

    // O ponteiro chegou ao botão — pelo que o kernel diz.
    let limite = std::time::Instant::now() + Duration::from_secs(5);
    let mut id = 7904;
    let mut ultima: String;
    let chegou = loop {
        ultima = pedir(id, "display.info", "{}")?;
        id += 1;
        let ponteiro = ultima
            .find(r#""pointer":"#)
            .map(|i| &ultima[i..])
            .unwrap_or("");
        let px: u32 = valor_de(ponteiro, r#""x":"#)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let py: u32 = valor_de(ponteiro, r#""y":"#)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if px.abs_diff(cx) <= 2 && py.abs_diff(cy) <= 2 {
            break true;
        }
        if std::time::Instant::now() >= limite {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if !chegou {
        return Err(format!(
            "mouse: o ponteiro nao chegou ao botao em ({cx}, {cy})\n  {ultima}"
        ));
    }
    if !ultima.contains(r#""name":"cursor""#) || !ultima.contains(r#""blend":"alpha""#) {
        return Err(format!("mouse: o cursor nao esta nas camadas\n  {ultima}"));
    }
    // E por **onde** andou, pela mesma razão da sonda do teclado: numa
    // máquina com dois mouses, sem esta parte ela provaria só aquele que o
    // emulador escolhesse.
    let ponteiro = ultima
        .find(r#""pointer":"#)
        .map(|i| &ultima[i..])
        .unwrap_or("");
    let relatorios: u64 = valor_de(ponteiro, r#""usb_reports":"#)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    match teclado {
        Teclado::Usb if relatorios == 0 => {
            return Err(format!(
                "mouse: o ponteiro andou sem passar pelo mouse USB\n  {ultima}"
            ));
        }
        Teclado::Nativo if relatorios > 0 => {
            return Err(format!(
                "mouse: o ponteiro passou pelo USB numa maquina sem mouse USB\n  {ultima}"
            ));
        }
        _ => {}
    }
    println!("  [mouse] ok  o ponteiro chegou ao botao em ({cx}, {cy}), com o cursor na tela");

    // O clique.
    for down in [true, false] {
        qmp_eventos(
            &mut qmp_escrita,
            &mut qmp_leitor,
            &format!(r#"{{"type":"btn","data":{{"down":{down},"button":"left"}}}}"#),
            "btn",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    }
    let pessoa = format!("pessoa: press no elemento {BOTAO}");
    let limite = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < limite {
        ultima = pedir(id, "log.tail", r#"{"count":16}"#)?;
        id += 1;
        if ultima.contains(&pessoa) {
            println!("  [mouse] ok  o clique pressionou o botao, pela pessoa");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "mouse: o clique nao pressionou o botao\n  {ultima}"
    ))
}

/// Leva o ponteiro da máquina a `(x, y)`, pelo mouse do emulador, e espera
/// o kernel dizer que ele chegou.
///
/// O mesmo arranjo de [`sob_mouse`]: uma posição absoluta, para quem tem
/// tablet, e o resto em passos relativos de até cem, para quem tem mouse — o
/// PS/2 do emulador engole um salto grande. Chegou quando o kernel diz, a
/// dois pixels.
fn levar_o_ponteiro(
    qmp_escrita: &mut UnixStream,
    qmp_leitor: &mut BufReader<UnixStream>,
    pedir: &mut dyn FnMut(&str, &str) -> Result<String, String>,
    (x, y): (u32, u32),
    (largura, altura): (u32, u32),
) -> Result<(), String> {
    let escala = |v: u32, lado: u32| (v as u64 * 32767 / (lado.max(2) - 1) as u64) as u32;
    let posicao = |info: &str| -> (i64, i64) {
        let ponteiro = info.find(r#""pointer":"#).map(|i| &info[i..]).unwrap_or("");
        let eixo = |chave: &str| {
            valor_de(ponteiro, chave)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        };
        (eixo(r#""x":"#), eixo(r#""y":"#))
    };
    qmp_eventos(
        qmp_escrita,
        qmp_leitor,
        &format!(
            r#"{{"type":"abs","data":{{"axis":"x","value":{}}}}},{{"type":"abs","data":{{"axis":"y","value":{}}}}}"#,
            escala(x, largura),
            escala(y, altura)
        ),
        "abs",
    )?;
    std::thread::sleep(Duration::from_millis(150));
    let (px, py) = posicao(&pedir("display.info", "{}")?);
    let (mut faltam_x, mut faltam_y) = (x as i64 - px, y as i64 - py);
    while faltam_x != 0 || faltam_y != 0 {
        let (passo_x, passo_y) = (faltam_x.clamp(-100, 100), faltam_y.clamp(-100, 100));
        if !qmp_eventos(
            qmp_escrita,
            qmp_leitor,
            &format!(
                r#"{{"type":"rel","data":{{"axis":"x","value":{passo_x}}}}},{{"type":"rel","data":{{"axis":"y","value":{passo_y}}}}}"#
            ),
            "rel",
        )? {
            break;
        }
        faltam_x -= passo_x;
        faltam_y -= passo_y;
        std::thread::sleep(Duration::from_millis(30));
    }
    let limite = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let info = pedir("display.info", "{}")?;
        let (px, py) = posicao(&info);
        if px.abs_diff(x as i64) <= 2 && py.abs_diff(y as i64) <= 2 {
            return Ok(());
        }
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "janelas: o ponteiro nao chegou a ({x}, {y}); esta em ({px}, {py})"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Aperta, ou solta, o botão esquerdo do mouse da máquina.
fn botao_do_mouse(
    qmp_escrita: &mut UnixStream,
    qmp_leitor: &mut BufReader<UnixStream>,
    apertado: bool,
) -> Result<(), String> {
    qmp_eventos(
        qmp_escrita,
        qmp_leitor,
        &format!(r#"{{"type":"btn","data":{{"down":{apertado},"button":"left"}}}}"#),
        "btn",
    )?;
    std::thread::sleep(Duration::from_millis(100));
    Ok(())
}

/// A moldura `(x, y, largura, altura)` do primeiro elemento da árvore
/// depois de `marca`.
fn moldura_depois(arvore: &str, marca: &str) -> Option<(u32, u32, u32, u32)> {
    let resto = &arvore[arvore.find(marca)?..];
    let resto = &resto[resto.find(r#""frame":"#)?..];
    let numero = |chave: &str| valor_de(resto, chave)?.parse().ok();
    Some((
        numero(r#""x":"#)?,
        numero(r#""y":"#)?,
        numero(r#""width":"#)?,
        numero(r#""height":"#)?,
    ))
}

/// A primeira janela: "Sobre o Duke", aberta pelo clique no botão da barra,
/// arrastada pela barra de título e fechada pela caixa — tudo pelo mouse da
/// máquina.
///
/// # O que esta sonda prova que a suíte não prova
///
/// A suíte opera o servidor de janelas pelas funções que os drivers chamam.
/// Esta passa pelos drivers de verdade — o PS/2, o `virtio-tablet`, o USB —,
/// pelo servidor lançado no boot de produção, e confere pelo que o agente
/// lê: a árvore semântica, onde a janela aparece, anda e some.
fn sob_janelas(
    qmp: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: a janela Sobre o Duke, pelo mouse");
    const SOBRE: u32 = 8;
    const TITULO: &str = r#""role":"window","label":"Sobre o Duke""#;

    let mut id = 8100;
    let mut pedir = |metodo: &str, params: &str| -> Result<String, String> {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("janelas: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("janelas: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "janelas: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };
    // Espera a árvore satisfazer `condicao`, e a devolve.
    let esperar_arvore = |pedir: &mut dyn FnMut(&str, &str) -> Result<String, String>,
                          condicao: &dyn Fn(&str) -> bool,
                          o_que: &str|
     -> Result<String, String> {
        let limite = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let arvore = pedir("ui.tree", "{}")?;
            if condicao(&arvore) {
                return Ok(arvore);
            }
            if std::time::Instant::now() >= limite {
                return Err(format!("janelas: {o_que}\n  {arvore}"));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    };

    let info = pedir("display.info", "{}")?;
    let dimensao = |chave: &str| -> Result<u32, String> {
        valor_de(&info, &format!(r#""{chave}":"#))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("janelas: display.info nao tem `{chave}`\n  {info}"))
    };
    let tela = (dimensao("width")?, dimensao("height")?);
    let (mut qe, mut ql) = qmp_abrir(qmp)?;

    // Abrir: o clique no botão "Sobre", pela moldura que a árvore publica.
    let arvore = pedir("ui.tree", "{}")?;
    let (bx, by, bl, ba) = moldura_depois(&arvore, &format!(r#""id":{SOBRE},"role":"button""#))
        .ok_or_else(|| format!("janelas: a arvore nao tem o botao Sobre\n  {arvore}"))?;
    levar_o_ponteiro(
        &mut qe,
        &mut ql,
        &mut pedir,
        (bx + bl / 2, by + ba / 2),
        tela,
    )?;
    botao_do_mouse(&mut qe, &mut ql, true)?;
    botao_do_mouse(&mut qe, &mut ql, false)?;
    let arvore = esperar_arvore(
        &mut pedir,
        &|a| a.contains(TITULO),
        "o clique no botao Sobre nao abriu a janela",
    )?;
    let (jx, jy, _, _) =
        moldura_depois(&arvore, TITULO).ok_or("janelas: a janela nao tem moldura")?;
    println!("  [janelas] ok  o clique no botao abriu \"Sobre o Duke\" em ({jx}, {jy})");

    // Arrastar pela barra de título: aperta, anda, solta.
    levar_o_ponteiro(&mut qe, &mut ql, &mut pedir, (jx + 100, jy + 10), tela)?;
    botao_do_mouse(&mut qe, &mut ql, true)?;
    levar_o_ponteiro(&mut qe, &mut ql, &mut pedir, (jx + 180, jy + 70), tela)?;
    botao_do_mouse(&mut qe, &mut ql, false)?;
    let (ax, ay) = (jx + 80, jy + 60);
    let arvore = esperar_arvore(
        &mut pedir,
        &|a| {
            moldura_depois(a, TITULO)
                .is_some_and(|(x, y, _, _)| x.abs_diff(ax) <= 3 && y.abs_diff(ay) <= 3)
        },
        "a janela arrastada nao foi para onde o mouse a levou",
    )?;
    println!("  [janelas] ok  arrastada pela barra de titulo para ({ax}, {ay})");

    // Fechar pela caixa, pela moldura do botão "Fechar" da janela.
    let depois = &arvore[arvore.find(TITULO).unwrap_or(0)..];
    let (fx, fy, fl, fa) = moldura_depois(depois, r#""role":"button","label":"Fechar""#)
        .ok_or_else(|| format!("janelas: a janela nao tem o botao Fechar\n  {arvore}"))?;
    levar_o_ponteiro(
        &mut qe,
        &mut ql,
        &mut pedir,
        (fx + fl / 2, fy + fa / 2),
        tela,
    )?;
    botao_do_mouse(&mut qe, &mut ql, true)?;
    botao_do_mouse(&mut qe, &mut ql, false)?;
    esperar_arvore(
        &mut pedir,
        &|a| !a.contains(TITULO),
        "o clique na caixa de fechar nao fechou a janela",
    )?;
    println!("  [janelas] ok  fechada pela caixa, e fora da arvore");

    // De novo, para o OK: o botão do toolkit, apertado no meio da moldura
    // que a árvore publica para ele.
    levar_o_ponteiro(
        &mut qe,
        &mut ql,
        &mut pedir,
        (bx + bl / 2, by + ba / 2),
        tela,
    )?;
    botao_do_mouse(&mut qe, &mut ql, true)?;
    botao_do_mouse(&mut qe, &mut ql, false)?;
    let arvore = esperar_arvore(
        &mut pedir,
        &|a| a.contains(TITULO),
        "o clique no botao Sobre nao abriu a janela de novo",
    )?;
    let depois = &arvore[arvore.find(TITULO).unwrap_or(0)..];
    let (ox, oy, ol, oa) = moldura_depois(depois, r#""role":"button","label":"OK""#)
        .ok_or_else(|| format!("janelas: a janela nao tem o botao OK\n  {arvore}"))?;
    levar_o_ponteiro(
        &mut qe,
        &mut ql,
        &mut pedir,
        (ox + ol / 2, oy + oa / 2),
        tela,
    )?;
    botao_do_mouse(&mut qe, &mut ql, true)?;
    botao_do_mouse(&mut qe, &mut ql, false)?;
    esperar_arvore(
        &mut pedir,
        &|a| !a.contains(TITULO),
        "o clique no OK nao fechou a janela",
    )?;
    println!("  [janelas] ok  o OK do toolkit fechou a janela, pelo clique");
    Ok(())
}

/// Por que um aperto de mão numa porta não deu certo.
enum FalhaDoAperto {
    /// O Duke respondeu com uma recusa, e disse por quê.
    Recusado(String),
    /// Ninguém respondeu no prazo: o kernel pode não ter subido ainda.
    Silencio,
    /// Algo que não melhora com o tempo.
    Outra(String),
}

/// Bytes do `/dev/urandom` do hospedeiro: a chave efêmera do cliente.
fn aleatorios() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut chave = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut chave))
        .map_err(|e| format!("sem /dev/urandom: {e}"))?;
    Ok(chave)
}

/// Um agente numa porta do console virtio, pelo canal cifrado: o aperto de
/// mão, e os pedidos por ele.
///
/// É o mesmo `sigilo` que o kernel usa do lado dele — ver o pacote. A chave
/// do agente é a de `target/chaves/`, e a pública do Duke sai da privada que
/// o `xtask` gerou: quem provisiona a máquina conhece as duas. Um cliente de
/// verdade receberia só a pública.
struct AgenteNaPorta {
    porta: u8,
    fluxo: UnixStream,
    transporte: sigilo::Transporte,
    leitor: sigilo::quadro::Leitor,
    /// Texto decifrado que ainda não fechou uma linha.
    pendente: Vec<u8>,
    proximo_id: u32,
    /// O que o Duke disse ao completar o aperto: a sessão e o nome.
    boas_vindas: String,
}

impl AgenteNaPorta {
    /// Conecta pela porta `porta` com a chave do agente dela.
    fn conectar(arch: Arquitetura, porta: u8) -> Result<AgenteNaPorta, String> {
        let chaves = chaves::Chaves::garantir()?;
        Self::conectar_com(arch, porta, &chaves.do_agente(porta), &chaves.duke)
    }

    /// Conecta pela porta `porta` com uma chave qualquer, insistindo enquanto
    /// o kernel não responde. Uma recusa é a resposta, e não se insiste.
    fn conectar_com(
        arch: Arquitetura,
        porta: u8,
        chave: &[u8; 32],
        duke: &[u8; 32],
    ) -> Result<AgenteNaPorta, String> {
        let limite = Instant::now() + Duration::from_secs(30);
        loop {
            match Self::tentar_aperto(arch, porta, chave, duke) {
                Ok(agente) => return Ok(agente),
                Err(FalhaDoAperto::Recusado(motivo)) => {
                    return Err(format!("agentes: porta {porta}: recusado: {motivo}"));
                }
                Err(FalhaDoAperto::Outra(e)) => return Err(format!("agentes: porta {porta}: {e}")),
                Err(FalhaDoAperto::Silencio) if Instant::now() < limite => {
                    std::thread::sleep(Duration::from_millis(300));
                }
                Err(FalhaDoAperto::Silencio) => {
                    return Err(format!(
                        "agentes: porta {porta}: o aperto nao foi respondido"
                    ));
                }
            }
        }
    }

    fn tentar_aperto(
        arch: Arquitetura,
        porta: u8,
        chave: &[u8; 32],
        duke: &[u8; 32],
    ) -> Result<AgenteNaPorta, FalhaDoAperto> {
        use sigilo::quadro::{Tipo, montar};
        let mut fluxo = UnixStream::connect(caminho_canal(arch, porta))
            .map_err(|e| FalhaDoAperto::Outra(format!("a porta nao aceitou conexao: {e}")))?;
        fluxo
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| FalhaDoAperto::Outra(e.to_string()))?;

        let efemera = aleatorios().map_err(FalhaDoAperto::Outra)?;
        let mut mensagem = vec![0u8; 1024];
        let (n, aguardando) =
            sigilo::Iniciador::novo(sigilo::PROLOGO, chave, &sigilo::publica_de(duke))
                .escrever(efemera, b"", &mut mensagem)
                .map_err(|e| FalhaDoAperto::Outra(e.motivo().to_string()))?;
        let quadro = montar(Tipo::Inicio, &mensagem[..n])
            .map_err(|e| FalhaDoAperto::Outra(e.motivo().to_string()))?;
        fluxo
            .write_all(&quadro)
            .and_then(|()| fluxo.flush())
            .map_err(|e| FalhaDoAperto::Outra(e.to_string()))?;

        let mut leitor = sigilo::quadro::Leitor::novo();
        let (tipo, corpo) = match ler_quadro(&mut fluxo, &mut leitor) {
            Ok(Some(q)) => q,
            Ok(None) => return Err(FalhaDoAperto::Silencio),
            Err(e) => return Err(FalhaDoAperto::Outra(e)),
        };
        match tipo {
            Tipo::Resposta => {
                let mut carga = vec![0u8; corpo.len()];
                let (m, transporte) = aguardando.ler(&corpo, &mut carga).map_err(|e| {
                    FalhaDoAperto::Outra(format!("a resposta do aperto nao abriu: {}", e.motivo()))
                })?;
                fluxo
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .map_err(|e| FalhaDoAperto::Outra(e.to_string()))?;
                Ok(AgenteNaPorta {
                    porta,
                    fluxo,
                    transporte,
                    leitor,
                    pendente: Vec::new(),
                    proximo_id: porta as u32 * 100_000,
                    boas_vindas: String::from_utf8_lossy(&carga[..m]).into_owned(),
                })
            }
            Tipo::Recusa => Err(FalhaDoAperto::Recusado(
                String::from_utf8_lossy(&corpo).into_owned(),
            )),
            _ => Err(FalhaDoAperto::Outra("quadro inesperado no aperto".into())),
        }
    }

    /// Um pedido cifrado, num quadro pronto, sem mandar. Para as sondas que
    /// adulteram ou repetem.
    fn quadro_do_pedido(&mut self, metodo: &str, params: &str) -> Result<(u32, Vec<u8>), String> {
        self.proximo_id += 1;
        let id = self.proximo_id;
        let linha = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{metodo}\",\"params\":{params}}}\n"
        );
        let mut quadros = Vec::new();
        let mut cifrado = vec![0u8; sigilo::MAIOR_MENSAGEM];
        for pedaco in linha.as_bytes().chunks(sigilo::Transporte::MAIOR_CLARO) {
            let n = self
                .transporte
                .cifrar(pedaco, &mut cifrado)
                .map_err(|e| format!("agentes: nao cifrou: {}", e.motivo()))?;
            quadros.extend(
                sigilo::quadro::montar(sigilo::quadro::Tipo::Dados, &cifrado[..n])
                    .map_err(|e| e.motivo().to_string())?,
            );
        }
        Ok((id, quadros))
    }

    /// Manda bytes crus pela porta.
    fn mandar(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.fluxo
            .write_all(bytes)
            .and_then(|()| self.fluxo.flush())
            .map_err(|e| format!("agentes: a porta {} nao aceitou o pedido: {e}", self.porta))
    }

    /// A próxima linha de resposta, decifrada. `Err` com o motivo se o Duke
    /// mandou uma recusa.
    fn proxima_linha(&mut self) -> Result<String, String> {
        loop {
            if let Some(fim) = self.pendente.iter().position(|&b| b == b'\n') {
                let linha: Vec<u8> = self.pendente.drain(..=fim).collect();
                return Ok(String::from_utf8_lossy(&linha).trim_end().to_string());
            }
            let (tipo, corpo) = ler_quadro(&mut self.fluxo, &mut self.leitor)?
                .ok_or_else(|| format!("agentes: porta {}: sem resposta", self.porta))?;
            match tipo {
                sigilo::quadro::Tipo::Dados => {
                    let mut claro = vec![0u8; corpo.len()];
                    let n = self.transporte.decifrar(&corpo, &mut claro).map_err(|e| {
                        format!(
                            "agentes: porta {}: resposta que nao abre: {}",
                            self.porta,
                            e.motivo()
                        )
                    })?;
                    self.pendente.extend_from_slice(&claro[..n]);
                }
                sigilo::quadro::Tipo::Recusa => {
                    return Err(format!("recusa: {}", String::from_utf8_lossy(&corpo)));
                }
                _ => return Err(format!("agentes: porta {}: quadro inesperado", self.porta)),
            }
        }
    }

    /// Um pedido com anexo: os bytes vão antes, em quadros cujo claro
    /// começa com zero, e o pedido os declara em `attachment` — que
    /// `params` não traz; ele é acrescentado aqui.
    fn pedir_com_anexo(
        &mut self,
        metodo: &str,
        params: &str,
        anexo: &[u8],
    ) -> Result<String, String> {
        // Quadros de 4 KiB: bem acima do menor que o kernel reserva para o
        // enquadramento, e pequenos o bastante para nenhum ficar preso.
        let mut cifrado = vec![0u8; sigilo::MAIOR_MENSAGEM];
        let mut quadros = Vec::new();
        for pedaco in anexo.chunks(4096) {
            let mut claro = Vec::with_capacity(pedaco.len() + 1);
            claro.push(0u8);
            claro.extend_from_slice(pedaco);
            let n = self
                .transporte
                .cifrar(&claro, &mut cifrado)
                .map_err(|e| format!("agentes: o anexo nao cifrou: {}", e.motivo()))?;
            quadros.extend(
                sigilo::quadro::montar(sigilo::quadro::Tipo::Dados, &cifrado[..n])
                    .map_err(|e| e.motivo().to_string())?,
            );
        }
        self.mandar(&quadros)?;
        let corpo = params
            .trim_end()
            .strip_suffix('}')
            .ok_or("agentes: os parametros nao sao um objeto")?;
        let separador = if corpo.trim_end().ends_with('{') {
            ""
        } else {
            ","
        };
        let params = format!(r#"{corpo}{separador}"attachment":{}}}"#, anexo.len());
        self.pedir(metodo, &params)
    }

    fn pedir(&mut self, metodo: &str, params: &str) -> Result<String, String> {
        let (id, quadro) = self.quadro_do_pedido(metodo, params)?;
        self.mandar(&quadro)?;
        loop {
            let resposta = self.proxima_linha()?;
            if e_a_resposta(&resposta, id) {
                return Ok(resposta);
            }
        }
    }

    /// Pede `metodo` até a resposta satisfazer `condicao`, por oito segundos.
    fn esperar(
        &mut self,
        metodo: &str,
        params: &str,
        condicao: &dyn Fn(&str) -> bool,
        o_que: &str,
    ) -> Result<String, String> {
        let limite = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let r = self.pedir(metodo, params)?;
            if condicao(&r) {
                return Ok(r);
            }
            if std::time::Instant::now() >= limite {
                return Err(format!("agentes: {o_que}\n  {r}"));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }
}

/// Lê bytes até um quadro se completar. `Ok(None)` se o prazo do fluxo
/// venceu sem quadro inteiro.
fn ler_quadro(
    fluxo: &mut UnixStream,
    leitor: &mut sigilo::quadro::Leitor,
) -> Result<Option<(sigilo::quadro::Tipo, Vec<u8>)>, String> {
    use std::io::Read;
    let mut byte = [0u8; 1];
    loop {
        match fluxo.read(&mut byte) {
            Ok(0) => return Err("a porta fechou".into()),
            Ok(_) => {
                if let Some((tipo, corpo)) = leitor
                    .empurrar(byte[0])
                    .map_err(|e| e.motivo().to_string())?
                {
                    return Ok(Some((tipo, corpo.to_vec())));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Quatro agentes ao mesmo tempo, cada um na sua porta do console virtio.
///
/// # O que esta sonda prova que a suíte não prova
///
/// A suíte atende as portas à mão, com o que ela mesma põe na entrada. Esta
/// passa pelo dispositivo de verdade e pelos sockets do hospedeiro, com os
/// quatro agentes falando **ao mesmo tempo**, em fios do hospedeiro: cada um
/// recebe só as respostas dele, com o número da sessão dele. E um deles
/// opera o Terminal pela linha de comando da janela, e o log do
/// interpretador diz que foi ele — o número atravessa a porta, a ação, o
/// Terminal e o pseudo-terminal.
fn sob_agentes(arch: Arquitetura) -> Result<(), String> {
    println!("[xtask] fumaça: quatro agentes ao mesmo tempo, cada um na sua porta");
    const PEDIDOS: u32 = 50;
    let inicio = Instant::now();
    let fios: Vec<_> = (1..=PORTAS_DE_AGENTE)
        .map(|porta| {
            std::thread::spawn(move || -> Result<(), String> {
                let mut agente = AgenteNaPorta::conectar(arch, porta)?;
                let esperado = format!(
                    "\"session\":{porta},\"transport\":\"virtio-console\",\"authenticated\":true,\"agent\":\"{}\"",
                    chaves::nome_do_agente(porta)
                );
                for _ in 0..PEDIDOS {
                    let r = agente.pedir("agent.session", "{}")?;
                    if !r.contains(&esperado) {
                        return Err(format!(
                            "agentes: a porta {porta} respondeu outra sessao\n  {r}"
                        ));
                    }
                }
                Ok(())
            })
        })
        .collect();
    for fio in fios {
        fio.join()
            .map_err(|_| "agentes: um fio do hospedeiro morreu".to_string())??;
    }
    // O tempo inclui os quatro apertos de mão: é o custo de um agente
    // chegar e trabalhar, e não só o de um pedido.
    let total = inicio.elapsed();
    println!(
        "  [agentes] ok  {} pedidos em cada uma das {PORTAS_DE_AGENTE} portas, ao mesmo tempo, cada resposta na sua \
         ({} ms ao todo, aperto incluso; {:.1} ms por ida e volta em cada porta)",
        PEDIDOS,
        total.as_millis(),
        total.as_secs_f64() * 1000.0 / f64::from(PEDIDOS)
    );

    // O agente da porta 2 no Terminal, pela linha de comando da janela.
    const GRADE: &str = r#""role":"text_area","label":"terminal""#;
    const LINHA: &str = r#""role":"text_field","label":"linha de comando""#;
    let mut agente = AgenteNaPorta::conectar(arch, 2)?;
    let arvore = agente.pedir("ui.tree", "{}")?;
    let linha = arvore
        .find(GRADE)
        .and_then(|i| id_antes(&arvore[i..], LINHA))
        .ok_or_else(|| format!("agentes: o Terminal nao tem a linha de comando\n  {arvore}"))?;
    let r = agente.pedir(
        "ui.act",
        &format!(r#"{{"id":{linha},"action":"set_value","value":"system.info"}}"#),
    )?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!(
            "agentes: o set_value da porta 2 foi recusado\n  {r}"
        ));
    }
    agente.esperar(
        "ui.tree",
        "{}",
        &|a| {
            a.find(GRADE)
                .map(|i| &a[i..])
                .and_then(|g| g.find(LINHA).map(|j| &g[j..]))
                .is_some_and(|l| l.contains(r#""value":"system.info""#))
        },
        "o set_value da porta 2 nao chegou a linha de comando do Terminal",
    )?;
    let r = agente.pedir("ui.act", &format!(r#"{{"id":{linha},"action":"confirm"}}"#))?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!("agentes: o confirm da porta 2 foi recusado\n  {r}"));
    }
    agente.esperar(
        "log.tail",
        r#"{"count":24}"#,
        &|l| l.contains("executado: system.info (agente 2)"),
        "o comando do agente da porta 2 nao executou, ou o log nao diz que foi ele",
    )?;
    println!("  [agentes] ok  o agente da porta 2 executou no Terminal, e o log diz `agente 2`");

    // As mensagens, pelo cliente de verdade: a porta 1 manda à 3; o
    // remetente é a sessão — e `from` no pedido é recusado —; a 3 lê duas
    // vezes o mesmo id, confirma, e a caixa fica vazia; o reenvio pelo
    // mesmo nonce devolve o mesmo id.
    let mut um = AgenteNaPorta::conectar(arch, 1)?;
    let mut tres = AgenteNaPorta::conectar(arch, 3)?;
    let para = chaves::nome_do_agente(3);
    let r = um.pedir(
        "message.send",
        &format!(r#"{{"to":"{para}","body":"oi, porta 3","nonce":1,"from":"outro"}}"#),
    )?;
    if !r.contains(r#""data":"from""#) {
        return Err(format!("mensagens: um pedido com `from` foi aceito\n  {r}"));
    }
    let pedido = format!(r#"{{"to":"{para}","body":"oi, porta 3","nonce":1}}"#);
    // O id da mensagem é texto; o do envelope JSON-RPC, um número — e vem
    // antes.
    let id_de = |r: &str| {
        let chave = r#""id":""#;
        let resto = &r[r.find(chave)? + chave.len()..];
        Some(resto[..resto.find('"')?].to_string())
    };
    let r = um.pedir("message.send", &pedido)?;
    let id = id_de(&r)
        .filter(|_| r.contains(r#""ok":true"#))
        .ok_or_else(|| format!("mensagens: o envio foi recusado\n  {r}"))?;
    let de_novo = um.pedir("message.send", &pedido)?;
    if id_de(&de_novo).as_deref() != Some(id.as_str()) || !de_novo.contains(r#""duplicate":true"#) {
        return Err(format!(
            "mensagens: o reenvio nao devolveu o mesmo id\n  {de_novo}"
        ));
    }
    let lida = tres.pedir("message.read", "{}")?;
    let de = format!(
        r#""from":{{"type":"agent","name":"{}""#,
        chaves::nome_do_agente(1)
    );
    if !lida.contains(&id) || !lida.contains(&de) || !lida.contains("oi, porta 3") {
        return Err(format!(
            "mensagens: a porta 3 nao leu a mensagem da porta 1\n  {lida}"
        ));
    }
    if !tres.pedir("message.read", "{}")?.contains(&id) {
        return Err("mensagens: a leitura consumiu a mensagem".into());
    }
    let r = tres.pedir("message.ack", &format!(r#"{{"id":"{id}"}}"#))?;
    if !r.contains(r#""state":"acked""#) || tres.pedir("message.read", "{}")?.contains(&id) {
        return Err(format!("mensagens: o ack nao tirou a mensagem\n  {r}"));
    }
    println!(
        "  [mensagens] ok  da porta 1 para a 3: o remetente da sessao, `from` recusado, o reenvio \
         com o mesmo id, lida sem consumir e confirmada"
    );

    // Quem está agindo, no kernel de produção: a porta 3 se vê e vê a 1 no
    // `agent.list`; o último a agir foi a 1 — o `ack` da 3 é leitura da
    // própria caixa, e não conta —; e a barra diz o mesmo, na árvore.
    let nome_um = chaves::nome_do_agente(1);
    let lista = tres.pedir("agent.list", "{}")?;
    let ultimo = format!(r#""last":{{"actor":"{nome_um}","#);
    if !lista.contains(&format!(r#""name":"{nome_um}""#))
        || !lista.contains(&format!(r#""name":"{para}""#))
        || !lista.contains(r#""last_action":{"method":"message.send""#)
        || !lista.contains(r#""last_command":{"method":"agent.list""#)
        || !lista.contains(&ultimo)
        || lista.contains("oi, porta 3")
    {
        return Err(format!(
            "atividade: agent.list nao diz quem esta conectado e quem agiu\n  {lista}"
        ));
    }
    let arvore = tres.pedir("ui.tree", "{}")?;
    let na_barra = format!("· último: {nome_um} (");
    if !arvore.contains(r#""role":"static_text","label":"agentes""#) || !arvore.contains(&na_barra)
    {
        return Err(format!(
            "atividade: a barra nao mostra quem agiu por ultimo\n  {arvore}"
        ));
    }
    println!(
        "  [atividade] ok  a porta 3 ve as duas no agent.list, com o ultimo comando e a ultima \
         acao; a barra diz que a porta 1 agiu por ultimo"
    );
    // As sessões já abertas vão para os fios, em vez de sair e voltar:
    // fechar uma porta e reconectar logo em seguida é uma corrida — o aviso
    // de que a conexão antiga caiu pode chegar ao kernel depois do aperto
    // da nova, e derrubá-la. A porta 4 está livre, e conecta. Os nonces da
    // rodada começam em 10: a sessão da porta 1 já mandou com o 1.
    let mut abertas: Vec<Option<AgenteNaPorta>> = vec![Some(um), Some(agente), Some(tres), None];

    // Os quatro ao mesmo tempo, de verdade: um fio do hospedeiro por porta,
    // soltos juntos por uma barreira. Cada um manda uma mensagem a cada um
    // dos outros três, e espera os outros terminarem; então cada um lê a
    // própria caixa: exatamente uma de cada um dos outros, em ordem de
    // aceitação, sem duplicata. A porta 4, de papel `sistema`, confere a
    // cadeia da auditoria no fim.
    let barreira = std::sync::Arc::new(Encontro::novo(usize::from(PORTAS_DE_AGENTE)));
    let fios: Vec<_> = (1..=PORTAS_DE_AGENTE)
        .map(|porta| {
            let barreira = barreira.clone();
            let aberta = abertas[usize::from(porta) - 1].take();
            std::thread::spawn(move || -> Result<(), String> {
                let mut agente = match aberta {
                    Some(a) => a,
                    None => AgenteNaPorta::conectar(arch, porta)?,
                };
                barreira.esperar()?;
                let outros: Vec<u8> = (1..=PORTAS_DE_AGENTE).filter(|&q| q != porta).collect();
                for (n, para) in outros.iter().enumerate() {
                    let r = agente.pedir(
                        "message.send",
                        &format!(
                            r#"{{"to":"{}","body":"todos: de {porta} para {para}","nonce":{}}}"#,
                            chaves::nome_do_agente(*para),
                            n + 10
                        ),
                    )?;
                    if !r.contains(r#""ok":true"#) {
                        return Err(format!("todos: a porta {porta} nao mandou a {para}\n  {r}"));
                    }
                }
                barreira.esperar()?;
                let lida = agente.pedir("message.read", "{}")?;
                let de_cada = outros
                    .iter()
                    .all(|q| lida.matches(&format!("todos: de {q} para {porta}")).count() == 1);
                // Os ids das mensagens desta rodada, na ordem da caixa.
                let ordens: Vec<u64> = lida
                    .match_indices(r#""id":""#)
                    .filter_map(|(i, m)| {
                        let resto = &lida[i + m.len()..];
                        let id = &resto[..resto.find('"')?];
                        id.rsplit(':').next()?.parse().ok()
                    })
                    .collect();
                let em_ordem = ordens.windows(2).all(|w| w[0] < w[1]);
                if !de_cada || !em_ordem {
                    return Err(format!(
                        "todos: a caixa da porta {porta} nao tem uma de cada, em ordem\n  {lida}"
                    ));
                }
                barreira.esperar()?;
                if porta == PORTAS_DE_AGENTE {
                    let lista = agente.pedir("agent.list", "{}")?;
                    if !lista.contains(&format!(r#""connected":{PORTAS_DE_AGENTE}"#)) {
                        return Err(format!("todos: agent.list nao ve os quatro\n  {lista}"));
                    }
                    let cadeia = agente.pedir("audit.verify", "{}")?;
                    if !cadeia.contains(r#""ok":true"#) {
                        return Err(format!("todos: a auditoria nao confere\n  {cadeia}"));
                    }
                }
                barreira.esperar()?;
                Ok(())
            })
        })
        .collect();
    // Todos os erros, e o da causa primeiro: os que só esperaram no
    // encontro vêm depois do que falhou de verdade.
    let mut erros: Vec<String> = fios
        .into_iter()
        .filter_map(|fio| match fio.join() {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(_) => Some("todos: um fio do hospedeiro morreu".to_string()),
        })
        .collect();
    erros.sort_by_key(|e| e.contains("encontro"));
    if !erros.is_empty() {
        return Err(erros.join("\n"));
    }
    println!(
        "  [todos] ok  quatro portas ao mesmo tempo, cada uma mandando a cada outra: cada caixa \
         com uma de cada, em ordem; agent.list ve os quatro; a auditoria confere"
    );
    Ok(())
}

/// Uma barreira com prazo: os fios da fumaça se encontram nela, e um que
/// falhou não deixa os outros esperando para sempre — quem espera demais
/// recebe um erro, e a fumaça falha em vez de pendurar o CI.
struct Encontro {
    quantos: usize,
    estado: std::sync::Mutex<(usize, u64)>,
    acordar: std::sync::Condvar,
}

impl Encontro {
    fn novo(quantos: usize) -> Encontro {
        Encontro {
            quantos,
            estado: std::sync::Mutex::new((0, 0)),
            acordar: std::sync::Condvar::new(),
        }
    }

    /// Espera os outros chegarem, por até trinta segundos.
    fn esperar(&self) -> Result<(), String> {
        let mut estado = self.estado.lock().map_err(|_| "encontro envenenado")?;
        let rodada = estado.1;
        estado.0 += 1;
        if estado.0 == self.quantos {
            *estado = (0, rodada + 1);
            self.acordar.notify_all();
            return Ok(());
        }
        let (estado, prazo) = self
            .acordar
            .wait_timeout_while(estado, Duration::from_secs(30), |e| e.1 == rodada)
            .map_err(|_| "encontro envenenado")?;
        if prazo.timed_out() && estado.1 == rodada {
            return Err("todos: um fio nao chegou ao encontro — outro falhou antes".into());
        }
        Ok(())
    }
}

/// O canal cifrado das portas, por fora: o que ele recusa.
///
/// # O que esta sonda prova que a suíte não prova
///
/// A suíte conversa com o kernel pela captura do driver, com o `sigilo`
/// dentro do próprio kernel dos dois lados. Esta conversa pelos sockets do
/// QEMU, com o cliente do `xtask` do lado de fora: o aperto atravessa o
/// dispositivo, e as recusas chegam como quadros ao hospedeiro.
fn sob_sigilo(arch: Arquitetura) -> Result<(), String> {
    println!("[xtask] fumaça: o canal cifrado das portas, e o que ele recusa");
    let chaves = chaves::Chaves::garantir()?;

    // A chave do intruso é válida — ele tem a privada —, e não está no
    // registro.
    match AgenteNaPorta::conectar_com(arch, 1, &chaves.intruso, &chaves.duke) {
        Err(e) if e.contains("recusado: chave fora do registro") => {}
        Err(e) => {
            return Err(format!(
                "sigilo: o intruso foi recusado pelo motivo errado: {e}"
            ));
        }
        Ok(_) => return Err("sigilo: uma chave fora do registro entrou".into()),
    }
    println!("  [sigilo] ok  uma chave fora do registro e recusada no aperto, com o motivo");

    // O Duke diz quem o agente é: a sessão e o nome do registro.
    let agente = AgenteNaPorta::conectar(arch, 2)?;
    let esperado = format!(r#"{{"session":2,"agent":"{}"}}"#, chaves::nome_do_agente(2));
    if agente.boas_vindas != esperado {
        return Err(format!(
            "sigilo: o aperto nao disse quem o agente e\n  {}",
            agente.boas_vindas
        ));
    }
    drop(agente);

    // Um bit trocado: a sessão acaba, com uma recusa.
    let mut agente = AgenteNaPorta::conectar(arch, 3)?;
    let (_, mut quadro) = agente.quadro_do_pedido("agent.ping", "{}")?;
    // (As sondas seguintes são em outras portas; esta conexão fecha no fim
    // da função, e nenhuma outra nesta porta espera por ela.)
    let ultimo = quadro.len() - 1;
    quadro[ultimo] ^= 0x01;
    agente.mandar(&quadro)?;
    match agente.proxima_linha() {
        Err(e) if e.contains("recusa: a autenticacao falhou") => {}
        outro => {
            return Err(format!(
                "sigilo: um quadro adulterado nao encerrou a sessao: {outro:?}"
            ));
        }
    }
    println!("  [sigilo] ok  um quadro adulterado encerra a sessao");

    // O mesmo quadro duas vezes: a primeira é respondida, a segunda acaba
    // com a sessão.
    let mut agente = AgenteNaPorta::conectar(arch, 4)?;
    let (id, quadro) = agente.quadro_do_pedido("agent.ping", "{}")?;
    agente.mandar(&quadro)?;
    let r = agente.proxima_linha()?;
    if !e_a_resposta(&r, id) {
        return Err(format!(
            "sigilo: o pedido original nao foi respondido\n  {r}"
        ));
    }
    agente.mandar(&quadro)?;
    match agente.proxima_linha() {
        Err(e) if e.contains("recusa:") => {}
        outro => {
            return Err(format!(
                "sigilo: um quadro repetido nao encerrou a sessao: {outro:?}"
            ));
        }
    }
    println!("  [sigilo] ok  um quadro repetido encerra a sessao");

    // E uma conexão nova na mesma porta recomeça do aperto.
    //
    // A anterior fecha antes, e explicitamente. O socket do QEMU atende um
    // cliente por vez, e um segundo `connect` com o primeiro aberto não é
    // recusado: fica na fila de espera do hospedeiro — e, com ela cheia, o
    // `connect` do Linux bloqueia sem prazo. Foi o que aconteceu: sombrear a
    // variável não a fecha, e a fumaça parou aqui.
    drop(agente);
    let mut agente = AgenteNaPorta::conectar(arch, 4)?;
    agente.pedir("agent.ping", "{}")?;
    println!("  [sigilo] ok  depois da recusa, uma conexao nova recomeca do aperto");
    Ok(())
}

/// Uma operação administrativa pela serial, com a prova do administrador.
///
/// # O que esta sonda prova
///
/// Que a serial — aberta, o canal de emergência — não registra ninguém sem
/// prova, e que com a prova o registro vale na hora: o intruso, recusado na
/// sonda anterior, entra depois de registrado. E que o desafio vale uma vez.
fn sob_administracao(
    arch: Arquitetura,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: registrar um agente pela serial, com prova");
    let chaves = chaves::Chaves::garantir()?;
    // Fora da faixa que comeca em 9, que `ler_resposta` pula — ver la.
    let mut id = 6300;
    let intruso = sigilo::publica_de(&chaves.intruso);
    let parametros = format!(
        r#"{{"key":"{}","name":"intruso","role":"observador"}}"#,
        sigilo::hex(&intruso)
    );

    let mut executar = |prova_de: &str| -> Result<String, String> {
        let mut pedir = |metodo: &str, params: &str| {
            pedir_pela_serial(escrita, leitor, &mut id, metodo, params)
        };
        let desafio = pedir("admin.challenge", "{}")?;
        let pedido = pedido_administrativo(
            &chaves,
            0,
            &desafio,
            "agent.register",
            &parametros,
            prova_de,
        )?;
        let primeira = pedir("admin.execute", &pedido)?;
        // O mesmo pedido de novo: o desafio já foi gasto.
        let segunda = pedir("admin.execute", &pedido)?;
        if !segunda.contains("desafio desconhecido nesta sessao") {
            return Err(format!("admin: um desafio valeu duas vezes\n  {segunda}"));
        }
        Ok(primeira)
    };

    // A prova feita para outros parâmetros não registra.
    let r = executar(&parametros.replace("intruso", "outro"))?;
    if !r.contains("a prova nao confere") {
        return Err(format!(
            "admin: uma prova de outros parametros passou\n  {r}"
        ));
    }
    // A prova certa registra.
    let r = executar(&parametros)?;
    if !r.contains(r#""executed":true"#) {
        return Err(format!("admin: a prova certa nao registrou\n  {r}"));
    }
    println!(
        "  [admin] ok  sem a prova certa nada entra; com ela o registro vale, uma vez por desafio"
    );

    let mut agente = AgenteNaPorta::conectar_com(arch, 1, &chaves.intruso, &chaves.duke)?;
    let r = agente.pedir("agent.session", "{}")?;
    if !r.contains(r#""authenticated":true,"agent":"intruso""#) {
        return Err(format!(
            "admin: o agente registrado entrou com outro nome\n  {r}"
        ));
    }
    println!("  [admin] ok  o agente registrado pela serial entra pela porta 1");
    drop(agente);
    revogar_por_quorum(arch, escrita, leitor, &chaves, &mut id)
}

/// `admin.revoke` no kernel de produção, pela serial: as assinaturas Ed25519
/// feitas aqui, com as chaves privadas que só o hospedeiro tem, e conferidas
/// lá com as públicas da imagem.
///
/// # O que esta sonda prova
///
/// Que o protocolo de quórum fecha com as ferramentas de verdade — a chave
/// privada de cada credencial do lado de quem assina, a pública no registro
/// da imagem —; que uma assinatura só não revoga; que duas revogam; que o
/// pedido não vale duas vezes; e que a assinatura confere fora do Duke, só
/// com a chave pública.
fn revogar_por_quorum(
    arch: Arquitetura,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
    chaves: &chaves::Chaves,
    id: &mut u32,
) -> Result<(), String> {
    let alvo = sigilo::publica_de(&chaves.outros_administradores[1]);
    let (r, _) = revogacao_por_quorum(arch, (escrita, leitor, id), chaves, &alvo, &[0], "fumaca")?;
    if !r.contains("quorum incompleto: 1 de 2") {
        return Err(format!("quorum: uma assinatura so revogou\n  {r}"));
    }
    let (r, pedido) = revogacao_por_quorum(
        arch,
        (escrita, leitor, id),
        chaves,
        &alvo,
        &[0, 1],
        "fumaca",
    )?;
    if !r.contains(r#""executed":true"#)
        || !r.contains(r#""signed_by":["administrador","administrador-2"]"#)
    {
        return Err(format!("quorum: duas assinaturas nao revogaram\n  {r}"));
    }
    let r = pedir_pela_serial(escrita, leitor, id, "admin.execute", &pedido)?;
    if !r.contains("desafio desconhecido") {
        return Err(format!(
            "quorum: o pedido de revogacao valeu duas vezes\n  {r}"
        ));
    }
    println!(
        "  [admin] ok  admin.revoke: uma assinatura Ed25519 nao revoga; duas revogam, uma vez; a assinatura confere fora do Duke"
    );
    Ok(())
}

/// Os nomes das três credenciais administrativas da imagem, na ordem de
/// [`credencial_administrativa`].
const NOMES_DOS_ADMINISTRADORES: [&str; 3] =
    ["administrador", "administrador-2", "administrador-3"];

/// A credencial `i` da imagem: a chave X25519 que a identifica e a privada
/// Ed25519 com que assina.
fn credencial_administrativa(chaves: &chaves::Chaves, i: usize) -> ([u8; 32], [u8; 32]) {
    let x25519 = match i {
        0 => chaves.administrador,
        n => chaves.outros_administradores[n - 1],
    };
    (
        sigilo::publica_de(&x25519),
        chaves.assinaturas_dos_administradores[i],
    )
}

/// Onde o signatário de cada credencial guarda a maior geração que já
/// assinou. Zerado com o estado da máquina: é a memória de quem administra
/// **esta** instalação.
fn diretorio_do_signatario(arch: Arquitetura) -> PathBuf {
    raiz_do_projeto()
        .join("target")
        .join(format!("signatario-{}", arch.nome()))
}

/// O signatário confere a geração que vai assinar contra a maior que já
/// assinou, e guarda a nova. Uma geração menor é um Duke mostrando um
/// estado anterior ao que este signatário já viu — um disco restaurado, por
/// exemplo —, e ele se recusa a assinar sobre isso.
///
/// É a âncora do lado de quem tem a chave privada. A do TPM é outra, e uma
/// não substitui a outra: ver `docs/PERSISTENCIA.md`, R5 e R6.
fn signatario_aceita(arch: Arquitetura, nome: &str, geracao: u64) -> Result<(), String> {
    let dir = diretorio_do_signatario(arch);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("não foi possível criar {}: {e}", dir.display()))?;
    let arquivo = dir.join(format!("{nome}.geracao"));
    let vista: u64 = std::fs::read_to_string(&arquivo)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0);
    if geracao < vista {
        return Err(format!(
            "o signatario de `{nome}` ja assinou na geracao {vista}, e recusa assinar sobre a {geracao}"
        ));
    }
    std::fs::write(&arquivo, geracao.to_string())
        .map_err(|e| format!("não foi possível gravar {}: {e}", arquivo.display()))
}

/// Pede a revogação de `alvo` por quórum, assinada pelas credenciais
/// `quem` (índices de [`credencial_administrativa`]). Cada assinatura é
/// conferida aqui, fora do Duke, só com a chave pública. Devolve a resposta
/// e o pedido, para quem quiser repeti-lo.
pub(crate) fn revogacao_por_quorum(
    arch: Arquitetura,
    (escrita, leitor, id): (&mut UnixStream, &mut BufReader<UnixStream>, &mut u32),
    chaves: &chaves::Chaves,
    alvo: &[u8; 32],
    quem: &[usize],
    motivo: &str,
) -> Result<(String, String), String> {
    let alvo = sigilo::hex(alvo);
    let parametros = format!(r#"{{"key":"{alvo}","reason":"{motivo}"}}"#);
    let desafio = pedir_pela_serial(
        escrita,
        leitor,
        id,
        "admin.challenge",
        r#"{"for":"admin.revoke"}"#,
    )?;
    let numero = |nome: &str| -> Result<u64, String> {
        campo_simples(&desafio, nome)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("quorum: o desafio nao diz `{nome}`\n  {desafio}"))
    };
    let hex = |nome: &str| -> Result<[u8; 32], String> {
        campo_simples(&desafio, nome)
            .and_then(|v| sigilo::de_hex(&v))
            .ok_or_else(|| format!("quorum: o desafio nao diz `{nome}`\n  {desafio}"))
    };
    let (nonce, efemera) = (hex("nonce")?, hex("ephemeral")?);
    let geracao = numero("generation")?;
    let conteudo = sigilo::quorum::Conteudo {
        operacao: numero("challenge")?,
        nonce: &nonce,
        sessao: 0,
        efemera: &efemera,
        versao_da_politica: numero("policy_version")?,
        geracao,
        m: numero("m")? as u8,
        n: numero("n")? as u8,
        comando: "admin.revoke",
        alvo: &alvo,
        parametros: &parametros,
    };
    let mut assinaturas = Vec::new();
    for &i in quem {
        signatario_aceita(arch, NOMES_DOS_ADMINISTRADORES[i], geracao)?;
        let (credencial, privada) = credencial_administrativa(chaves, i);
        let assinatura = sigilo::quorum::assinar(&privada, &conteudo);
        // Confere aqui, fora do Duke, só com a pública.
        let publica = sigilo::quorum::publica_de_assinatura(&privada);
        if !sigilo::quorum::conferir(&publica, &conteudo, &assinatura) {
            return Err("quorum: a assinatura nao confere com a chave publica".to_string());
        }
        assinaturas.push(format!(
            "{}:{}",
            sigilo::hex(&credencial),
            sigilo::hex_de(&assinatura)
        ));
    }
    let pedido = format!(
        r#"{{"challenge":{},"command":"admin.revoke","params":"{}","signatures":"{}"}}"#,
        conteudo.operacao,
        parametros.replace('"', "\\\""),
        assinaturas.join(",")
    );
    let resposta = pedir_pela_serial(escrita, leitor, id, "admin.execute", &pedido)?;
    Ok((resposta, pedido))
}

/// Pede pela serial, em claro, e devolve a resposta deste pedido.
fn pedir_pela_serial(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
    id: &mut u32,
    metodo: &str,
    params: &str,
) -> Result<String, String> {
    *id += 1;
    let id = *id;
    escrita
        .write_all(
            format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                .as_bytes(),
        )
        .and_then(|()| escrita.write_all(b"\n"))
        .and_then(|()| escrita.flush())
        .map_err(|e| format!("falha ao pedir `{metodo}` pela serial: {e}"))?;
    loop {
        let resposta = ler_resposta(leitor)?;
        if e_a_resposta(&resposta, id) {
            return Ok(resposta);
        }
    }
}

/// O valor cru de um campo simples de uma resposta: o texto sem aspas, ou o
/// número.
fn campo_simples(r: &str, nome: &str) -> Option<String> {
    let depois = apos(r, &format!("\"{nome}\":"))?;
    let depois = depois.trim_start_matches('"');
    Some(depois.split(['"', ',', '}']).next()?.to_string())
}

/// Os parâmetros de um `admin.execute` de `comando` com `parametros`, e a
/// prova do administrador da imagem sobre `prova_de`, para o desafio que
/// `admin.challenge` devolveu na sessão `sessao`.
fn pedido_administrativo(
    chaves: &chaves::Chaves,
    sessao: u8,
    desafio: &str,
    comando: &str,
    parametros: &str,
    prova_de: &str,
) -> Result<String, String> {
    pedido_administrativo_de(
        &chaves.administrador,
        sessao,
        desafio,
        comando,
        parametros,
        prova_de,
    )
}

/// Como [`pedido_administrativo`], com a prova da credencial `privada`.
fn pedido_administrativo_de(
    privada: &[u8; 32],
    sessao: u8,
    desafio: &str,
    comando: &str,
    parametros: &str,
    prova_de: &str,
) -> Result<String, String> {
    let numero: u64 = campo_simples(desafio, "challenge")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("admin: sem desafio\n  {desafio}"))?;
    let nonce = campo_simples(desafio, "nonce")
        .and_then(|v| sigilo::de_hex(&v))
        .ok_or("admin: sem nonce")?;
    let efemera = campo_simples(desafio, "ephemeral")
        .and_then(|v| sigilo::de_hex(&v))
        .ok_or("admin: sem efemera")?;
    let publica = sigilo::publica_de(privada);
    let contexto = sigilo::administracao::Contexto {
        nonce: &nonce,
        sessao,
        administrador: &publica,
        efemera: &efemera,
        comando,
        parametros: prova_de,
    };
    let prova = sigilo::administracao::provar(privada, &contexto)
        .map_err(|e| format!("admin: sem prova: {}", e.motivo()))?;
    Ok(format!(
        r#"{{"challenge":{numero},"command":"{comando}","params":"{}","admin":"{}","proof":"{}"}}"#,
        parametros.replace('"', "\\\""),
        sigilo::hex(&publica),
        sigilo::hex(&prova)
    ))
}

/// A resposta é a recusa da política com `codigo`.
fn recusado_com(resposta: &str, codigo: &str) -> bool {
    let rpc = if codigo == "RATE_LIMIT" {
        -32011
    } else {
        -32010
    };
    resposta.contains(&format!(r#""code":{rpc}"#))
        && resposta.contains(&format!(r#""data":"{codigo}""#))
}

/// Um objeto JSON plano: os campos, com o valor sem escape — `None` para
/// `null`.
type ObjetoPlano = Vec<(String, Option<String>)>;

/// Os objetos de um array JSON de objetos planos — campos de texto, número
/// ou `null` —, cada um como pares de nome e valor já sem escape.
///
/// É o que `audit.tail` devolve. O `xtask` não tem um leitor de JSON, e
/// esta é a forma mais curta que respeita aspas e escapes: um `,` ou um `}`
/// dentro de um texto não fecha nada.
fn objetos_planos(texto: &str) -> Result<Vec<ObjetoPlano>, String> {
    let b: Vec<char> = texto.chars().collect();
    let mut i = 0;
    let mut objetos = Vec::new();
    let texto_em = |i: &mut usize| -> Result<String, String> {
        let mut s = String::new();
        *i += 1;
        while *i < b.len() && b[*i] != '"' {
            if b[*i] == '\\' {
                *i += 1;
                match b.get(*i) {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some('u') => {
                        let hex: String = b
                            .get(*i + 1..*i + 5)
                            .ok_or("escape curto")?
                            .iter()
                            .collect();
                        let c = u32::from_str_radix(&hex, 16)
                            .ok()
                            .and_then(char::from_u32)
                            .ok_or("escape invalido")?;
                        s.push(c);
                        *i += 4;
                    }
                    Some(c) => s.push(*c),
                    None => return Err("texto sem fim".into()),
                }
            } else {
                s.push(b[*i]);
            }
            *i += 1;
        }
        *i += 1;
        Ok(s)
    };
    while i < b.len() {
        if b[i] != '{' {
            i += 1;
            continue;
        }
        i += 1;
        let mut campos = Vec::new();
        loop {
            while i < b.len() && (b[i] == ',' || b[i].is_whitespace()) {
                i += 1;
            }
            if i >= b.len() {
                return Err("objeto sem fim".into());
            }
            if b[i] == '}' {
                i += 1;
                break;
            }
            if b[i] != '"' {
                return Err(format!("esperava um nome na posicao {i}"));
            }
            let nome = texto_em(&mut i)?;
            while i < b.len() && (b[i] == ':' || b[i].is_whitespace()) {
                i += 1;
            }
            let valor = if b.get(i) == Some(&'"') {
                Some(texto_em(&mut i)?)
            } else {
                let inicio = i;
                while i < b.len() && b[i] != ',' && b[i] != '}' {
                    i += 1;
                }
                let cru: String = b[inicio..i].iter().collect();
                let cru = cru.trim().to_string();
                (cru != "null").then_some(cru)
            };
            campos.push((nome, valor));
        }
        objetos.push(campos);
    }
    Ok(objetos)
}

/// A política, por fora: papéis que recusam, a taxa, a revogação, as regras
/// de quem administra, e a auditoria refeita no hospedeiro.
///
/// # O que esta sonda prova que a suíte não prova
///
/// Que o que a suíte confere por dentro vale pelo dispositivo, com o cliente
/// de verdade: as recusas chegam como erros JSON-RPC com o código no `data`,
/// a revogação derruba uma conexão do hospedeiro, e a cadeia da auditoria é
/// refeita fora da máquina com o mesmo `politica` — que é o que a ancoragem
/// externa vai fazer.
fn sob_politica(
    arch: Arquitetura,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: a política — papéis, taxa, revogação, administração e auditoria");
    let chaves = chaves::Chaves::garantir()?;
    let mut id = 6400;
    let mut pedir =
        |metodo: &str, params: &str| pedir_pela_serial(escrita, leitor, &mut id, metodo, params);
    // As provas mandadas, para conferir no fim que nenhuma foi gravada.
    let provas: std::cell::RefCell<Vec<String>> = Default::default();
    let administrar = |pedir: &mut dyn FnMut(&str, &str) -> Result<String, String>,
                       comando: &str,
                       parametros: &str|
     -> Result<String, String> {
        let desafio = pedir("admin.challenge", "{}")?;
        let pedido = pedido_administrativo(&chaves, 0, &desafio, comando, parametros, parametros)?;
        provas.borrow_mut().extend(campo_simples(&pedido, "proof"));
        pedir("admin.execute", &pedido)
    };

    // O intruso, registrado como observador: observa, e não lê arquivos.
    let mut intruso = AgenteNaPorta::conectar_com(arch, 1, &chaves.intruso, &chaves.duke)?;
    let r = intruso.pedir("system.info", "{}")?;
    if !r.contains(r#""result":"#) {
        return Err(format!("politica: o observador nao observou\n  {r}"));
    }
    let r = intruso.pedir("fs.list", r#"{"path":"/bin"}"#)?;
    if !recusado_com(&r, "DENY_PERMISSION") {
        return Err(format!("politica: o observador listou arquivos\n  {r}"));
    }
    // Um operador: lê o que o recurso dele alcança, e nada além.
    let mut operador = AgenteNaPorta::conectar(arch, 2)?;
    let r = operador.pedir("fs.list", r#"{"path":"/bin"}"#)?;
    if !r.contains(r#""result":"#) {
        return Err(format!("politica: o operador nao listou /bin\n  {r}"));
    }
    for caminho in [
        "/etc/duke/agentes",
        "/etc/duke/privado/chave",
        "/bin/../etc/duke/agentes",
    ] {
        let r = operador.pedir("fs.read", &format!(r#"{{"path":"{caminho}"}}"#))?;
        if !recusado_com(&r, "DENY_RESOURCE") {
            return Err(format!("politica: o operador leu {caminho}\n  {r}"));
        }
    }
    println!(
        "  [politica] ok  o observador observa e nao le arquivos; o operador le so o alcance dele"
    );

    // O operador tenta administrar a própria sessão, com a prova do
    // administrador: a prova confere, e a regra recusa.
    for (comando, parametros) in [
        (
            "policy.assign",
            r#"{"agent":"agente-2","role":"observador"}"#,
        ),
        (
            "policy.write",
            r#"{"line":"papel operador @observador ui.act"}"#,
        ),
    ] {
        let desafio = operador.pedir("admin.challenge", "{}")?;
        let pedido = pedido_administrativo(&chaves, 2, &desafio, comando, parametros, parametros)?;
        provas.borrow_mut().extend(campo_simples(&pedido, "proof"));
        let r = operador.pedir("admin.execute", &pedido)?;
        if !r.contains(r#""code":"DENY_POLICY""#) {
            return Err(format!(
                "politica: {comando} mudou o papel da propria sessao\n  {r}"
            ));
        }
    }
    let r = administrar(
        &mut pedir,
        "policy.write",
        r#"{"line":"papel administrador agent.read"}"#,
    )?;
    if !r.contains(r#""code":"DENY_POLICY""#) {
        return Err(format!("politica: o papel do administrador mudou\n  {r}"));
    }
    println!(
        "  [politica] ok  ninguem muda o proprio papel nem o de quem administra, com prova e tudo"
    );

    // Um papel novo, com taxa curta, escrito em memória e atribuído ao
    // intruso: vale no pedido seguinte dele.
    for (comando, parametros) in [
        ("policy.write", r#"{"line":"papel leitor agent.read"}"#),
        ("policy.write", r#"{"line":"taxa leitor 1 2"}"#),
        ("policy.assign", r#"{"agent":"intruso","role":"leitor"}"#),
    ] {
        let r = administrar(&mut pedir, comando, parametros)?;
        if !r.contains(r#""executed":true"#) {
            return Err(format!(
                "politica: {comando} {parametros} nao executou\n  {r}"
            ));
        }
    }
    let r = intruso.pedir("system.info", "{}")?;
    if !recusado_com(&r, "DENY_PERMISSION") {
        return Err(format!(
            "politica: a atribuicao nao valeu no pedido seguinte\n  {r}"
        ));
    }
    let mut limitado = false;
    for _ in 0..4 {
        let r = intruso.pedir("agent.ping", "{}")?;
        limitado |= recusado_com(&r, "RATE_LIMIT");
    }
    if !limitado {
        return Err("politica: quatro pedidos seguidos passaram de uma rajada de dois".into());
    }
    println!(
        "  [politica] ok  policy.write e policy.assign valem no pedido seguinte; a taxa limita"
    );

    // Revogado, o intruso cai na hora: a recusa chega sem ele pedir nada.
    let parametros = format!(
        r#"{{"key":"{}"}}"#,
        sigilo::hex(&sigilo::publica_de(&chaves.intruso))
    );
    let r = administrar(&mut pedir, "agent.revoke", &parametros)?;
    if !r.contains(r#""executed":true"#) || !r.contains(r#""sessions_closed":[1]"#) {
        return Err(format!(
            "politica: a revogacao nao derrubou a sessao\n  {r}"
        ));
    }
    match intruso.proxima_linha() {
        Err(e) if e.contains("recusa: chave revogada") => {}
        outro => {
            return Err(format!(
                "politica: o agente revogado nao recebeu a recusa: {outro:?}"
            ));
        }
    }
    drop(intruso);
    println!("  [politica] ok  revogar derruba a sessao viva da chave, com a recusa");

    // A auditoria, refeita aqui fora.
    let cauda = pedir("audit.tail", r#"{"count":128}"#)?;
    let cabeca = pedir("audit.head", "{}")?;
    let registros = objetos_planos(
        apos(&cauda, r#""records":["#).ok_or("politica: audit.tail sem registros")?,
    )?;
    let mut anterior: Option<[u8; 32]> = None;
    let mut codigos = std::collections::BTreeSet::new();
    for campos in &registros {
        let campo = |nome: &str| -> Result<String, String> {
            campos
                .iter()
                .find(|(n, _)| n == nome)
                .and_then(|(_, v)| v.clone())
                .ok_or_else(|| format!("politica: registro sem `{nome}`"))
        };
        let hex32 = |nome: &str| -> Result<[u8; 32], String> {
            sigilo::de_hex(&campo(nome)?).ok_or_else(|| format!("politica: `{nome}` nao e hex"))
        };
        let numero = |nome: &str| -> Result<u64, String> {
            campo(nome)?
                .parse()
                .map_err(|_| format!("politica: `{nome}` nao e numero"))
        };
        let codigo = politica::Codigo::de_nome(&campo("code")?)
            .ok_or("politica: codigo desconhecido na auditoria")?;
        codigos.insert(codigo.nome());
        let evento = politica::auditoria::Evento {
            ts_ms: numero("ts_ms")?,
            titular: politica::auditoria::Titular::de_nome(&campo("holder")?)
                .ok_or("politica: titular desconhecido na auditoria")?,
            sessao: numero("session")? as u8,
            sessao_de_pessoa: campo("person_session")
                .ok()
                .and_then(|k| sigilo::de_hex_fixo(&k)),
            agente: campo("agent")?,
            chave: campo("key").ok().and_then(|k| sigilo::de_hex(&k)),
            papel: campo("role")?,
            metodo: campo("method")?,
            recurso: campo("resource")?,
            codigo,
            parametros: hex32("params")?,
            detalhe: campo("detail")?,
        };
        let seq = numero("seq")?;
        let prev = hex32("prev")?;
        if anterior.is_some_and(|a| a != prev)
            || politica::auditoria::elo(&prev, seq, &evento) != hex32("link")?
        {
            return Err(format!(
                "politica: o registro {seq} da auditoria nao refaz o elo\n  {evento:?}"
            ));
        }
        anterior = Some(hex32("link")?);
    }
    // O `audit.tail` também foi gravado, depois de responder: a cabeça
    // agora está um elo além da cauda. O `audit.head` é o elo de quem o
    // pediu — e o anterior dele é o último da cauda.
    let ultimo = anterior.ok_or("politica: a auditoria veio vazia")?;
    if campo_simples(&cabeca, "head").is_none() || registros.len() < 16 {
        return Err(format!(
            "politica: a cabeca ou a cauda vieram curtas\n  {cabeca}"
        ));
    }
    for esperado in [
        "ALLOW",
        "DENY_PERMISSION",
        "DENY_RESOURCE",
        "DENY_POLICY",
        "RATE_LIMIT",
    ] {
        if !codigos.contains(esperado) {
            return Err(format!("politica: a auditoria nao tem nenhum {esperado}"));
        }
    }
    // Nada de material criptográfico: as provas mandadas nesta sonda não
    // aparecem em lugar nenhum da auditoria.
    let provas = provas.borrow();
    if provas.is_empty() || provas.iter().any(|p| cauda.contains(p.as_str())) {
        return Err("politica: uma prova administrativa foi parar na auditoria".into());
    }
    let verificada = pedir("audit.verify", "{}")?;
    if !verificada.contains(r#""ok":true"#) {
        return Err(format!(
            "politica: a cadeia guardada nao confere\n  {verificada}"
        ));
    }
    println!(
        "  [politica] ok  {} registros da auditoria refeitos aqui fora, elo a elo, ate {}…; sem nenhuma prova dentro",
        registros.len(),
        &sigilo::hex(&ultimo)[..16]
    );
    Ok(())
}

/// O `id` do elemento da árvore marcado por `marca` — o papel e o rótulo,
/// que vêm logo depois dele no objeto.
fn id_antes(arvore: &str, marca: &str) -> Option<u64> {
    let antes = &arvore[..arvore.find(marca)?];
    let inicio = antes.rfind(r#""id":"#)? + r#""id":"#.len();
    antes[inicio..].trim_end_matches(',').parse().ok()
}

/// Um formulário do toolkit, preenchido pelo agente e pela pessoa.
///
/// # O que esta sonda prova que a suíte não prova
///
/// A suíte age no campo pelas funções do kernel. Esta passa pelo canal do
/// agente de verdade — o `ui.act` com o `set_value`, que atravessa o JSON,
/// a fila da superfície e a chamada `valor` até o widget —, e pelo teclado e
/// o mouse da máquina: a pessoa digita no mesmo campo, confirma com o Enter,
/// e fecha a janela pela caixa. O programa é lançado pelo `user.run`, como
/// um agente lançaria.
fn sob_formulario(
    arch: Arquitetura,
    monitor: &Path,
    qmp: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: um formulário do toolkit, pelo agente e pela pessoa");
    const TITULO: &str = r#""role":"window","label":"Formulário""#;

    let mut id = 8600;
    let mut pedir = |metodo: &str, params: &str| -> Result<String, String> {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("formulario: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("formulario: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "formulario: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };
    // Espera `condicao` valer na resposta de `metodo`, e a devolve.
    let esperar = |pedir: &mut dyn FnMut(&str, &str) -> Result<String, String>,
                   (metodo, params): (&str, &str),
                   condicao: &dyn Fn(&str) -> bool,
                   o_que: &str|
     -> Result<String, String> {
        let limite = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let resposta = pedir(metodo, params)?;
            if condicao(&resposta) {
                return Ok(resposta);
            }
            if std::time::Instant::now() >= limite {
                return Err(format!("formulario: {o_que}\n  {resposta}"));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    };
    let arvore = ("ui.tree", "{}");
    let log = ("log.tail", r#"{"count":24}"#);
    // O que vem na árvore depois do título da janela: a janela dela.
    let da_janela = |a: &str| a.find(TITULO).map(|i| a[i..].to_string());

    let lancado = pedir(
        "user.run",
        &format!(r#"{{"path":"/programas/{}/formulario"}}"#, arch.nome()),
    )?;
    if !lancado.contains(r#""launched":true"#) {
        return Err(format!("formulario: o user.run nao o lancou\n  {lancado}"));
    }
    let a = esperar(
        &mut pedir,
        arvore,
        &|a| a.contains(TITULO),
        "a janela do formulario nao apareceu na arvore",
    )?;
    let janela = da_janela(&a).unwrap_or_default();
    let campo = |rotulo: &str| {
        id_antes(
            &janela,
            &format!(r#""role":"text_field","label":"{rotulo}""#),
        )
        .ok_or_else(|| format!("formulario: a janela nao tem o campo {rotulo}\n  {janela}"))
    };
    let (nome, sobrenome) = (campo("nome")?, campo("sobrenome")?);
    let ok = id_antes(&janela, r#""role":"button","label":"OK""#)
        .ok_or_else(|| format!("formulario: a janela nao tem o OK\n  {janela}"))?;

    // O agente: os dois campos pelo `set_value`, e o OK pelo `press`.
    for (campo, valor) in [(nome, "Ana"), (sobrenome, "Souza")] {
        let r = pedir(
            "ui.act",
            &format!(r#"{{"id":{campo},"action":"set_value","value":"{valor}"}}"#),
        )?;
        if !r.contains(r#""ok":true"#) {
            return Err(format!("formulario: o set_value foi recusado\n  {r}"));
        }
    }
    esperar(
        &mut pedir,
        arvore,
        &|a| {
            da_janela(a)
                .is_some_and(|j| j.contains(r#""value":"Ana""#) && j.contains(r#""value":"Souza""#))
        },
        "os valores do agente nao chegaram aos campos",
    )?;
    let r = pedir("ui.act", &format!(r#"{{"id":{ok},"action":"press"}}"#))?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!("formulario: o press no OK foi recusado\n  {r}"));
    }
    esperar(
        &mut pedir,
        log,
        &|l| l.contains("formulario: acionado 3 [Ana] [Souza]"),
        "o OK do agente nao chegou ao programa com os valores",
    )?;
    println!("  [formulario] ok  preenchido e confirmado pelo agente, pela arvore");

    // Os campos que o agente editou são dele até soltar: a árvore mostra o
    // arrendamento, e o agente o solta para a pessoa digitar.
    let a = pedir("ui.tree", "{}")?;
    if !da_janela(&a).is_some_and(|j| j.contains(r#""holder":"agent""#)) {
        return Err(format!(
            "formulario: a arvore nao mostra o arrendamento dos campos\n  {a}"
        ));
    }
    for campo in [nome, sobrenome] {
        let r = pedir("ui.release", &format!(r#"{{"id":{campo}}}"#))?;
        if !r.contains(r#""ok":true"#) {
            return Err(format!("formulario: o ui.release foi recusado\n  {r}"));
        }
    }
    println!("  [formulario] ok  os campos editados arrendados ao agente, e soltos por ele");

    // A pessoa: uma letra no campo com o foco — o primeiro —, e o Enter,
    // pelo teclado da máquina.
    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("formulario: o monitor nao aceitou conexao: {e}"))?;
    for tecla in ["x", "ret"] {
        mon.write_all(format!("sendkey {tecla}\n").as_bytes())
            .and_then(|()| mon.flush())
            .map_err(|e| format!("formulario: falha ao mandar `{tecla}`: {e}"))?;
        std::thread::sleep(Duration::from_millis(20));
    }
    esperar(
        &mut pedir,
        log,
        &|l| l.contains("formulario: acionado 1 [Anax] [Souza]"),
        "o que a pessoa digitou nao chegou ao campo, ou o Enter nao o confirmou",
    )?;
    println!("  [formulario] ok  a pessoa digitou no mesmo campo e confirmou com o Enter");

    // E fecha pela caixa, com o mouse.
    let info = pedir("display.info", "{}")?;
    let dimensao = |chave: &str| -> Result<u32, String> {
        valor_de(&info, &format!(r#""{chave}":"#))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("formulario: display.info nao tem `{chave}`\n  {info}"))
    };
    let tela = (dimensao("width")?, dimensao("height")?);
    let a = pedir("ui.tree", "{}")?;
    let janela = da_janela(&a).unwrap_or_default();
    let (fx, fy, fl, fa) = moldura_depois(&janela, r#""role":"button","label":"Fechar""#)
        .ok_or_else(|| format!("formulario: a janela nao tem o botao Fechar\n  {janela}"))?;
    let (mut qe, mut ql) = qmp_abrir(qmp)?;
    levar_o_ponteiro(
        &mut qe,
        &mut ql,
        &mut pedir,
        (fx + fl / 2, fy + fa / 2),
        tela,
    )?;
    botao_do_mouse(&mut qe, &mut ql, true)?;
    botao_do_mouse(&mut qe, &mut ql, false)?;
    esperar(
        &mut pedir,
        arvore,
        &|a| !a.contains(TITULO),
        "o clique na caixa de fechar nao fechou o formulario",
    )?;
    println!("  [formulario] ok  fechado pela caixa, pelo mouse");
    Ok(())
}

/// A interface nativa no kernel de produção: o pedido de um programa vai à
/// tarefa `programas` do executor — que a suíte não tem: lá quem espera um
/// processo o atende —, e a tarefa acorda o processo com a resposta.
///
/// `contido` declara só `system.read` e confere de dentro que o resto é
/// recusado; `anonimo`, sem manifesto, que nada passa. Lançados pela serial,
/// que é do papel `sistema`: o que os recusa é o manifesto, e não o papel.
fn sob_interface_nativa(
    arch: Arquitetura,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: a interface nativa, pelo executor de verdade");
    let mut id = 8700;
    let mut pedir = |metodo: &str, params: &str| -> Result<String, String> {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("nativo: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("nativo: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "nativo: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };
    let pedidos = |r: &str| -> u64 {
        r.split(r#""native_requests":"#)
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    };
    let antes = pedidos(&pedir("user.stats", "{}")?);
    for (programa, codigo) in [("contido", 75), ("anonimo", 76)] {
        let lancado = pedir(
            "user.run",
            &format!(r#"{{"path":"/programas/{}/{programa}"}}"#, arch.nome()),
        )?;
        if !lancado.contains(r#""launched":true"#) {
            return Err(format!(
                "nativo: o user.run nao lancou {programa}\n  {lancado}"
            ));
        }
        let procurada = format!("processo encerrou com codigo {codigo}");
        let limite = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let log = pedir("log.tail", r#"{"count":32}"#)?;
            if log.contains(&procurada) {
                break;
            }
            if std::time::Instant::now() >= limite {
                return Err(format!(
                    "nativo: {programa} nao saiu com {codigo} — o executor nao atendeu, ou o manifesto nao valeu\n  {log}"
                ));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        println!("  [nativo] ok  {programa} saiu com {codigo}");
    }
    let depois = pedidos(&pedir("user.stats", "{}")?);
    // `contido`: system.info e message.send; `anonimo`: system.info.
    if depois < antes + 3 {
        return Err(format!(
            "nativo: o executor atendeu {} pedidos dos programas, e eram 3",
            depois - antes
        ));
    }
    println!(
        "  [nativo] ok  {} pedidos atendidos pela tarefa `programas`",
        depois - antes
    );
    Ok(())
}

/// A rede no kernel de produção — ver "Rede nativa" no README: pela
/// serial, que é do papel `sistema`, o endereço que o DHCP deu, uma conexão
/// ao eco da bancada com o texto indo e voltando, a recusa de um destino
/// fora do alcance, e a conexão fechada que deixa de responder. Pelo
/// executor de verdade, que é quem atende o canal fora da suíte.
fn sob_a_rede(escrita: &mut UnixStream, leitor: &mut BufReader<UnixStream>) -> Result<(), String> {
    println!("[xtask] fumaça: a rede, pelo gate");
    let mut id = 8500;
    let mut pedir = |metodo: &str, params: &str| -> Result<String, String> {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("rede: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("rede: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "rede: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };
    let limite = std::time::Instant::now() + Duration::from_secs(20);
    let info = loop {
        let info = pedir("net.info", "{}")?;
        if info.contains(r#""address":"10.0.2.15/24""#) {
            break info;
        }
        if std::time::Instant::now() > limite {
            return Err(format!("rede: o DHCP nao deu endereco\n  {info}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if !info.contains(r#""gateway":"10.0.2.2""#) {
        return Err(format!("rede: o roteador nao e o do emulador\n  {info}"));
    }
    println!("  [rede] ok  10.0.2.15/24 pelo DHCP, roteador 10.0.2.2");

    let fora = pedir("net.connect", r#"{"to":"tcp:10.0.2.100:8"}"#)?;
    if !fora.contains("DENY_RESOURCE") {
        return Err(format!(
            "rede: um destino fora do alcance foi discado\n  {fora}"
        ));
    }
    let aberta = pedir("net.connect", r#"{"to":"tcp:10.0.2.100:7"}"#)?;
    let conexao: u64 = aberta
        .split(r#""connection":"#)
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("rede: o eco nao abriu\n  {aberta}"))?;
    let frase = "ola, rede do Duke";
    let mut mandado = false;
    let mut voltou = String::new();
    let limite = std::time::Instant::now() + Duration::from_secs(20);
    while !voltou.contains(frase) {
        if !mandado {
            let r = pedir(
                "net.send",
                &format!(r#"{{"connection":{conexao},"content":"{frase}"}}"#),
            )?;
            mandado = r.contains(&format!(r#""sent":{}"#, frase.len()));
        }
        let r = pedir("net.recv", &format!(r#"{{"connection":{conexao}}}"#))?;
        if let Some(conteudo) = r.split(r#""content":""#).nth(1) {
            voltou.push_str(conteudo.split('"').next().unwrap_or(""));
        }
        if std::time::Instant::now() > limite {
            return Err(format!(
                "rede: o eco nao devolveu a frase (mandada: {mandado})\n  {r}"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "  [rede] ok  conexao {conexao} ao eco: a frase foi e voltou; a porta ao lado, DENY_RESOURCE"
    );
    let fechada = pedir("net.close", &format!(r#"{{"connection":{conexao}}}"#))?;
    if !fechada.contains(r#""closed":true"#) {
        return Err(format!("rede: a conexao nao fechou\n  {fechada}"));
    }
    let depois = pedir("net.recv", &format!(r#"{{"connection":{conexao}}}"#))?;
    if !depois.contains("DENY_RESOURCE") {
        return Err(format!(
            "rede: a conexao fechada ainda respondeu\n  {depois}"
        ));
    }
    println!("  [rede] ok  fechada, o numero deixou de valer");
    Ok(())
}

/// O armazém no kernel de produção — ver `docs/ARMAZENAMENTO.md`: pela
/// serial, que é do papel `sistema`, uma gravação confirmada no journal, o
/// conflito de versão da gravação velha e a leitura pelo VFS; e o programa
/// `guardar`, que faz o mesmo de dentro, pelo `pedir` e pelo descritor.
fn sob_o_armazem(
    arch: Arquitetura,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: o armazém, gravado no journal");
    let mut id = 8800;
    let mut pedir = |metodo: &str, params: &str| -> Result<String, String> {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("armazem: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("armazem: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "armazem: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };
    let versao = |r: &str, campo: &str| -> Option<u64> {
        r.split(&format!(r#""{campo}":"#))
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
    };
    // Os diretórios são explícitos: o volume nasce vazio, e o compartilhado
    // é criado pelo sistema — que já existir, de uma volta anterior, não é
    // erro.
    let criado = pedir("fs.mkdir", r#"{"path":"/armazem/compartilhado"}"#)?;
    if !criado.contains(r#""ok":true"#) && !criado.contains("ja ha algo nesse caminho") {
        return Err(format!(
            "armazem: o mkdir do compartilhado falhou\n  {criado}"
        ));
    }
    const C: &str = "/armazem/compartilhado/fumaca.txt";
    let estado = pedir("fs.stat", &format!(r#"{{"path":"{C}"}}"#))?;
    let antes = versao(&estado, "version")
        .ok_or_else(|| format!("armazem: fs.stat sem versao\n  {estado}"))?;
    let gravado = pedir(
        "fs.write",
        &format!(r#"{{"path":"{C}","content":"da fumaca","expect_version":{antes}}}"#),
    )?;
    if !gravado.contains(r#""ok":true"#) || !gravado.contains(r#""durable":true"#) {
        return Err(format!(
            "armazem: a gravacao nao foi confirmada\n  {gravado}"
        ));
    }
    let velha = pedir(
        "fs.write",
        &format!(r#"{{"path":"{C}","content":"de quem leu antes","expect_version":{antes}}}"#),
    )?;
    if !velha.contains(r#""conflict":"version""#)
        || versao(&velha, "current_version") != versao(&gravado, "version")
    {
        return Err(format!(
            "armazem: a gravacao contra a versao velha nao foi conflito\n  {velha}"
        ));
    }
    let lido = pedir("fs.read", &format!(r#"{{"path":"{C}"}}"#))?;
    if !lido.contains(r#""content":"da fumaca""#) {
        return Err(format!(
            "armazem: o VFS nao leu o que foi gravado\n  {lido}"
        ));
    }
    println!("  [armazem] ok  gravado, conflito de versao, lido pelo VFS");

    let lancado = pedir(
        "user.run",
        &format!(r#"{{"path":"/programas/{}/guardar"}}"#, arch.nome()),
    )?;
    if !lancado.contains(r#""launched":true"#) {
        return Err(format!(
            "armazem: o user.run nao lancou guardar\n  {lancado}"
        ));
    }
    let procurada = "processo encerrou com codigo 77";
    let limite = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let log = pedir("log.tail", r#"{"count":32}"#)?;
        if log.contains(procurada) {
            break;
        }
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "armazem: guardar nao saiu com 77 — o armazem nao respondeu de dentro\n  {log}"
            ));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    println!("  [armazem] ok  guardar saiu com 77");

    // Um agente de verdade, numa porta, manda binário fora do JSON: todos
    // os bytes, o zero e o fim de linha incluídos, em quadros de anexo da
    // sessão cifrada — e o kernel grava exatamente aquele tamanho.
    let mut agente = AgenteNaPorta::conectar(arch, 1)?;
    const B: &str = "/armazem/compartilhado/fumaca.bin";
    let estado = agente.pedir("fs.stat", &format!(r#"{{"path":"{B}"}}"#))?;
    let antes = versao(&estado, "version")
        .ok_or_else(|| format!("armazem: fs.stat do binario sem versao\n  {estado}"))?;
    let bytes: Vec<u8> = (0..20_000u32).map(|i| (i % 256) as u8).collect();
    let gravado = agente.pedir_com_anexo(
        "fs.write",
        &format!(r#"{{"path":"{B}","expect_version":{antes}}}"#),
        &bytes,
    )?;
    if !gravado.contains(r#""ok":true"#) || versao(&gravado, "size") != Some(bytes.len() as u64) {
        return Err(format!(
            "armazem: o anexo do agente nao foi gravado inteiro\n  {gravado}"
        ));
    }
    // E um anexo que o pedido não declara não chega a lugar nenhum.
    let sem = agente.pedir_com_anexo("agent.ping", "{}", b"sobra")?;
    if !sem.contains(r#""error""#) {
        return Err(format!(
            "armazem: um anexo num comando que nao o aceita passou\n  {sem}"
        ));
    }
    drop(agente);
    println!(
        "  [armazem] ok  binario de um agente pelo anexo, {} bytes",
        bytes.len()
    );
    Ok(())
}

/// O botão da barra superior, pressionado pelos dois caminhos.
///
/// O agente pede `press` pela árvore; a pessoa aperta F1 no teclado da
/// máquina — pelo `sendkey` do monitor, que entrega a tecla ao dispositivo
/// como um teclado de verdade: o 8042 no x86, o virtio no ARM, o USB quando
/// a fumaça roda com `--teclado usb`. Os dois têm de chegar à mesma ação, e
/// o log tem de dizer quem foi em cada vez.
fn sob_barra(
    monitor: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: o botão da barra, pelo agente e pela pessoa");
    const BOTAO: u32 = 5;

    let mut pedir = |id: u32, metodo: &str, params: &str| -> Result<String, String> {
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("barra: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("barra: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "barra: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };

    let arvore = pedir(7801, "ui.tree", "{}")?;
    let botao = format!(r#""id":{BOTAO},"role":"button""#);
    if !arvore.contains(r#""role":"menu_bar""#) || !arvore.contains(&botao) {
        return Err(format!(
            "barra: a arvore nao mostra a barra com o botao\n  {arvore}"
        ));
    }

    // O relógio anda sozinho. Quem o redesenha é uma tarefa do executor, que
    // só existe no kernel de produção: a suíte chama o redesenho à mão, e
    // esta é a única conferência de que a tarefa roda.
    let relogio = |arvore: &str| {
        let resto = &arvore[arvore.find(r#""label":"tempo ligado""#)?..];
        valor_de(resto, r#""value":"#)
    };
    let antes = relogio(&arvore)
        .ok_or_else(|| format!("barra: a arvore nao mostra o relogio\n  {arvore}"))?;
    std::thread::sleep(Duration::from_millis(2200));
    let depois = relogio(&pedir(7810, "ui.tree", "{}")?).unwrap_or_default();
    if antes == depois {
        return Err(format!("barra: o relogio parou em `{antes}`"));
    }
    println!("  [barra] ok  o relogio anda sozinho: `{antes}` -> `{depois}`");

    let r = pedir(
        7802,
        "ui.act",
        &format!(r#"{{"id":{BOTAO},"action":"press"}}"#),
    )?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!("barra: o press do agente foi recusado\n  {r}"));
    }
    let agente = format!("agente 0: press no elemento {BOTAO}");
    let log = pedir(7803, "log.tail", r#"{"count":16}"#)?;
    if !log.contains(&agente) {
        return Err(format!(
            "barra: o log nao registrou o press do agente\n  {log}"
        ));
    }
    println!("  [barra] ok  press pelo agente, pela arvore");

    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("barra: o monitor nao aceitou conexao: {e}"))?;
    mon.write_all(b"sendkey f1\n")
        .and_then(|()| mon.flush())
        .map_err(|e| format!("barra: falha ao mandar F1: {e}"))?;

    let pessoa = format!("pessoa: press no elemento {BOTAO}");
    let limite = std::time::Instant::now() + Duration::from_secs(5);
    let mut ultima = String::new();
    let mut id = 7804;
    while std::time::Instant::now() < limite {
        ultima = pedir(id, "log.tail", r#"{"count":16}"#)?;
        id += 1;
        if ultima.contains(&pessoa) {
            println!("  [barra] ok  F1 pela pessoa, pelo teclado da maquina");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("barra: F1 nao pressionou o botao\n  {ultima}"))
}

/// O nome de uma tecla no `sendkey` do monitor, para um caractere do que a
/// fumaça digita: letras minúsculas, dígitos, o ponto, o hífen e o Enter.
fn tecla_do_monitor(c: char) -> Option<String> {
    match c {
        'a'..='z' | '0'..='9' => Some(c.to_string()),
        '.' => Some("dot".into()),
        '-' => Some("minus".into()),
        ' ' => Some("spc".into()),
        '\n' => Some("ret".into()),
        _ => None,
    }
}

/// Digita um texto no teclado da máquina, pelo monitor, uma tecla por vez.
fn digitar_pelo_monitor(mon: &mut UnixStream, texto: &str, quem: &str) -> Result<(), String> {
    for c in texto.chars() {
        let nome = tecla_do_monitor(c)
            .ok_or_else(|| format!("{quem}: a fumaca nao sabe digitar {c:?}"))?;
        mon.write_all(format!("sendkey {nome}\n").as_bytes())
            .and_then(|()| mon.flush())
            .map_err(|e| format!("{quem}: falha ao mandar `{nome}`: {e}"))?;
        // O emulador entrega uma tecla por vez, e mandá-las sem respiro faz
        // algumas se perderem entre o monitor e o dispositivo.
        //
        // E depois do Enter, mais: no console da máquina, cheio, cada linha
        // nova rola a tela e a recompõe inteira, com as interrupções
        // desligadas — no build de depuração, perto de um quarto de segundo.
        // As teclas que chegam nesse meio esperam na fila do PS/2 do
        // emulador, que é curta: medido, a vinte milissegundos por tecla o
        // Enter depois do nome se perdia, e a senha entrava ecoada no nome.
        let respiro = if c == '\n' { 600 } else { 20 };
        std::thread::sleep(Duration::from_millis(respiro));
    }
    Ok(())
}

/// As sessões abertas da pessoa de desenvolvimento, pelos consoles delas,
/// como `person.registry` as mostra.
fn consoles_da_pessoa_dev(registro: &str) -> Vec<String> {
    let marca = format!(r#""name":"{}""#, chaves::NOME_DA_PESSOA_DEV);
    let Some(resto) = registro.find(&marca).map(|i| &registro[i..]) else {
        return Vec::new();
    };
    // Até o fim do objeto dela: o próximo `"id":"pessoa:` é de outra.
    let fim = resto[1..]
        .find(r#""id":"pessoa:"#)
        .map_or(resto.len(), |i| i + 1);
    let mut consoles = Vec::new();
    let mut texto = &resto[..fim];
    while let Some(i) = texto.find(r#""console":""#) {
        texto = &texto[i + r#""console":""#.len()..];
        if let Some(f) = texto.find('"') {
            consoles.push(texto[..f].to_string());
        }
    }
    consoles
}

/// Espera a pessoa de desenvolvimento ter uma sessão num console cujo nome
/// começa com `prefixo`.
fn esperar_sessao_dev(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
    id: &mut u32,
    prefixo: &str,
    quem: &str,
) -> Result<Vec<String>, String> {
    let limite = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let registro = pedir_pela_serial(escrita, leitor, id, "person.registry", "{}")
            .map_err(|e| format!("{quem}: {e}"))?;
        let consoles = consoles_da_pessoa_dev(&registro);
        if consoles.iter().any(|c| c.starts_with(prefixo)) {
            return Ok(consoles);
        }
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "{quem}: a pessoa `{}` nao entrou em {prefixo}\n  {registro}",
                chaves::NOME_DA_PESSOA_DEV
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Entrar no Terminal: antes do login nada passa, e com a senha de
/// `target/chaves/` a pessoa de desenvolvimento entra — e a senha não fica
/// no que `keyboard.read` devolve.
///
/// # O que esta sonda prova que a suíte não prova
///
/// A suíte entrega os caracteres ao console à mão. Aqui eles saem do
/// teclado da máquina, vão à janela do Terminal — que tem o foco desde o
/// boot —, ao pseudo-terminal dele, e ao console dele; a credencial é a da
/// imagem, calculada pelo `xtask` no hospedeiro e conferida pelo Argon2id
/// do kernel.
fn sob_login_no_terminal(
    monitor: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: entrar no Terminal");
    let senha = chaves::Chaves::garantir()?.pessoa_dev().2;
    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("login: o monitor nao aceitou conexao: {e}"))?;
    let mut id = 6600;

    // Antes do login: o comando é recusado, e gravado com o console.
    digitar_pelo_monitor(&mut mon, "\nagent.ping\n", "login")?;
    let limite = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        let cauda = pedir_pela_serial(escrita, leitor, &mut id, "audit.tail", r#"{"count":32}"#)
            .map_err(|e| format!("login: {e}"))?;
        let registros = objetos_planos(apos(&cauda, r#""records":["#).unwrap_or(""))?;
        let recusado = registros.iter().any(|campos| {
            let campo = |nome: &str| {
                campos
                    .iter()
                    .find(|(n, _)| n == nome)
                    .and_then(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            campo("method") == "agent.ping"
                && campo("holder") == "anonymous"
                && campo("code") == "DENY_NOT_AUTHENTICATED"
                && campo("resource").starts_with("terminal:")
        });
        if recusado {
            break;
        }
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "login: o comando antes do login nao foi recusado e gravado\n  {cauda}"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!(
        "  [login] ok  antes do login, `agent.ping` no Terminal e DENY_NOT_AUTHENTICATED, gravado"
    );

    // O histórico, vazio antes de digitar o login.
    let _ = pedir_pela_serial(escrita, leitor, &mut id, "keyboard.read", r#"{"max":256}"#);
    digitar_pelo_monitor(
        &mut mon,
        &format!("login\n{}\n{senha}\n", chaves::NOME_DA_PESSOA_DEV),
        "login",
    )?;
    let consoles = esperar_sessao_dev(escrita, leitor, &mut id, "terminal:", "login")?;
    println!(
        "  [login] ok  `{}` entrou no Terminal, com a senha da imagem ({})",
        chaves::NOME_DA_PESSOA_DEV,
        consoles.join(", ")
    );

    // A senha não ficou no histórico do teclado; o nome, sim.
    let historico = pedir_pela_serial(escrita, leitor, &mut id, "keyboard.read", r#"{"max":256}"#)
        .map_err(|e| format!("login: {e}"))?;
    if historico.contains(&senha) || !historico.contains(chaves::NOME_DA_PESSOA_DEV) {
        return Err(format!(
            "login: o historico do teclado nao e o que devia — a senha nao entra, o nome entra\n  {historico}"
        ));
    }
    println!("  [login] ok  a senha nao entrou no historico do teclado");
    Ok(())
}

/// Entrar no console físico também: um clique fora das janelas devolve o
/// foco ao console, e a mesma pessoa entra nele — duas sessões, a mesma
/// identidade.
fn sob_login_no_console(
    monitor: &Path,
    qmp: &Path,
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: entrar no console da máquina");
    let senha = chaves::Chaves::garantir()?.pessoa_dev().2;
    let mut id = 6650;
    let info = pedir_pela_serial(escrita, leitor, &mut id, "display.info", "{}")
        .map_err(|e| format!("login: {e}"))?;
    let dimensao = |chave: &str| -> Result<u32, String> {
        valor_de(&info, &format!(r#""{chave}":"#))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("login: display.info nao tem `{chave}`\n  {info}"))
    };
    let (largura, altura) = (dimensao("width")?, dimensao("height")?);
    // O canto de baixo, à direita: a área do console, longe do Terminal.
    let fora = (largura - 40, altura - 40);
    let (mut qmp_escrita, mut qmp_leitor) = qmp_abrir(qmp)?;
    {
        let mut pedir = |metodo: &str, params: &str| {
            pedir_pela_serial(escrita, leitor, &mut id, metodo, params)
                .map_err(|e| format!("login: {e}"))
        };
        levar_o_ponteiro(
            &mut qmp_escrita,
            &mut qmp_leitor,
            &mut pedir,
            fora,
            (largura, altura),
        )?;
    }
    botao_do_mouse(&mut qmp_escrita, &mut qmp_leitor, true)?;
    botao_do_mouse(&mut qmp_escrita, &mut qmp_leitor, false)?;

    let mut mon = UnixStream::connect(monitor)
        .map_err(|e| format!("login: o monitor nao aceitou conexao: {e}"))?;
    digitar_pelo_monitor(
        &mut mon,
        &format!("\nlogin\n{}\n{senha}\n", chaves::NOME_DA_PESSOA_DEV),
        "login",
    )?;
    let consoles = esperar_sessao_dev(escrita, leitor, &mut id, "console", "login")?;
    if !consoles.iter().any(|c| c.starts_with("terminal:")) {
        return Err(format!(
            "login: entrar no console tirou a pessoa do Terminal ({})",
            consoles.join(", ")
        ));
    }
    println!(
        "  [login] ok  a mesma pessoa no console e no Terminal: duas sessoes ({})",
        consoles.join(", ")
    );
    Ok(())
}

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
        // Com a origem: foi uma pessoa, pelo teclado. É a metade da
        // auditoria que a sonda da árvore semântica não alcança.
        if ultima.contains("executado: agent.ping (pessoa)") {
            println!("  [interpretador] ok  `agent.ping` digitado e executado, pela pessoa");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Executado, mas atribuído a quem não o digitou, é outro defeito — e a
    // mensagem precisa dizer qual, ou manda quem depura procurar no teclado.
    if ultima.contains("executado: agent.ping") {
        return Err(format!(
            "interpretador: o comando digitado foi executado, mas o log nao o atribui a pessoa\n  {ultima}"
        ));
    }
    Err(format!(
        "interpretador: o comando digitado nao chegou a ser executado\n  {ultima}"
    ))
}

/// O comando que a sonda anterior digitou aparece no Terminal, com a
/// resposta.
///
/// # O que esta sonda prova
///
/// Que o Terminal lançado no boot é o caminho da pessoa até o interpretador:
/// com o foco nele, as teclas da máquina vão ao canal dele, ele as escreve
/// no pseudo-terminal, o interpretador as executa, e o que ele imprime volta
/// ao Terminal pelo mesmo pseudo-terminal. A sonda anterior já viu o
/// comando executado, pelo log; esta vê o que a pessoa vê, pela árvore —
/// a linha digitada depois do prompt, e o `"pong": true` da resposta, que o
/// interpretador escreve indentada.
fn sob_terminal(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    println!("[xtask] fumaça: o comando digitado aparece no Terminal");
    const TITULO: &str = r#""role":"window","label":"Terminal""#;
    let limite = std::time::Instant::now() + Duration::from_secs(8);
    let mut id = 6700;
    loop {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ui.tree","params":{{}}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("terminal: falha ao pedir a arvore: {e}"))?;
        let arvore = ler_resposta(leitor).map_err(|e| format!("terminal: {e}"))?;
        if !e_a_resposta(&arvore, id) {
            return Err(format!(
                "terminal: veio a resposta de outro pedido\n  {arvore}"
            ));
        }
        // O texto da janela do Terminal: o que vem depois do título dela.
        let janela = arvore.find(TITULO).map(|i| &arvore[i..]);
        let mostra = janela
            .is_some_and(|j| j.contains("duke> agent.ping") && j.contains(r#"\"pong\": true"#));
        if mostra {
            println!("  [terminal] ok  `agent.ping` e a resposta, na janela do Terminal");
            return sob_terminal_pelo_agente(escrita, leitor);
        }
        if std::time::Instant::now() >= limite {
            return Err(match janela {
                None => format!("terminal: a arvore nao tem a janela do Terminal\n  {arvore}"),
                Some(j) => format!("terminal: o Terminal nao mostra o comando e a resposta\n  {j}"),
            });
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// O agente digita no Terminal pelo mesmo caminho: a linha de comando dele,
/// na árvore.
///
/// A sonda anterior viu a pessoa digitar; esta pede, pelo canal do agente,
/// o `set_value` e o `confirm` na linha de comando do Terminal — o campo
/// dentro da grade dele, e não o do console do kernel —, e confere que o
/// comando executou atribuído ao agente, e que a resposta está na grade.
fn sob_terminal_pelo_agente(
    escrita: &mut UnixStream,
    leitor: &mut BufReader<UnixStream>,
) -> Result<(), String> {
    const GRADE: &str = r#""role":"text_area","label":"terminal""#;
    const LINHA: &str = r#""role":"text_field","label":"linha de comando""#;
    let mut id = 6800;
    let mut pedir = |metodo: &str, params: &str| -> Result<String, String> {
        id += 1;
        escrita
            .write_all(
                format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{metodo}","params":{params}}}"#)
                    .as_bytes(),
            )
            .and_then(|()| escrita.write_all(b"\n"))
            .and_then(|()| escrita.flush())
            .map_err(|e| format!("terminal: falha ao pedir `{metodo}`: {e}"))?;
        let resposta = ler_resposta(leitor).map_err(|e| format!("terminal: {e}"))?;
        if !e_a_resposta(&resposta, id) {
            return Err(format!(
                "terminal: veio a resposta de outro pedido\n  {resposta}"
            ));
        }
        Ok(resposta)
    };
    // O que vem depois da grade do Terminal: a linha de comando é o elemento
    // seguinte. O texto da grade vai escapado, e não tem como conter a marca.
    let arvore = pedir("ui.tree", "{}")?;
    let linha = arvore
        .find(GRADE)
        .and_then(|i| id_antes(&arvore[i..], LINHA))
        .ok_or_else(|| format!("terminal: a grade nao tem a linha de comando\n  {arvore}"))?;
    for (acao, valor) in [
        ("set_value", r#","value":"system.uptime""#),
        ("confirm", ""),
    ] {
        let r = pedir(
            "ui.act",
            &format!(r#"{{"id":{linha},"action":"{acao}"{valor}}}"#),
        )?;
        if !r.contains(r#""ok":true"#) {
            return Err(format!(
                "terminal: o `{acao}` na linha de comando foi recusado\n  {r}"
            ));
        }
        // O `confirm` depois de o eco chegar: é a linha na tela que ele
        // executa.
        if acao == "set_value" {
            let limite = std::time::Instant::now() + Duration::from_secs(8);
            loop {
                let a = pedir("ui.tree", "{}")?;
                let chegou = a
                    .find(GRADE)
                    .map(|i| &a[i..])
                    .and_then(|g| g.find(LINHA).map(|j| &g[j..]))
                    .is_some_and(|l| l.contains(r#""value":"system.uptime""#));
                if chegou {
                    break;
                }
                if std::time::Instant::now() >= limite {
                    return Err(format!(
                        "terminal: o set_value nao chegou a linha de comando\n  {a}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }
    let limite = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        let log = pedir("log.tail", r#"{"count":24}"#)?;
        if log.contains("executado: system.uptime (agente 0)") {
            break;
        }
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "terminal: o comando do agente nao executou, ou nao foi atribuido a ele\n  {log}"
            ));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    println!("  [terminal] ok  `system.uptime` pelo agente, na linha de comando do Terminal");
    Ok(())
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

fn test(arch: Arquitetura, release: bool, video: Video) -> Result<ExitCode, String> {
    let artefato = build(arch, release, true)?;
    println!(
        "[xtask] executando a suíte de testes no QEMU ({}, video {})\n",
        arch.nome(),
        match video {
            Video::Linear => "linear",
            Video::Virtio => "virtio",
        }
    );

    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?;
    let mut filho = comando_qemu(arch, &artefato, None, Teclado::Nativo, video, &ambiente)?
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;
    let andamento = acompanhar(&mut filho, std::io::stdout())?;

    match aguardar_com_andamento(filho, andamento, JANELA_SEM_PROGRESSO)? {
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
            "nenhum caso terminou em {}s e o emulador foi encerrado\n\
             causas tipicas: laco sem saida num teste, triple fault reiniciando \
             a maquina, ou o dispositivo de saida do emulador sem funcionar",
            JANELA_SEM_PROGRESSO.as_secs()
        )),
    }
}

/// Como um processo do emulador terminou.
enum Desfecho {
    Codigo(i32),
    Sinal,
    Estourou,
}

/// O andamento da suíte, lido da saída do emulador a caminho do destino
/// dela: quantos casos terminaram até agora.
struct Andamento {
    casos: Arc<AtomicU64>,
    leitor: std::thread::JoinHandle<()>,
}

/// Toma a saída do emulador — que tem de ter sido pedida em cano —,
/// repassa cada byte a `destino` assim que chega, e conta os casos que
/// terminam nela.
///
/// O repasse é byte a byte, e não por linha: o que o kernel escreve aparece
/// na hora, como aparecia com a saída herdada.
fn acompanhar(
    filho: &mut Child,
    mut destino: impl Write + Send + 'static,
) -> Result<Andamento, String> {
    let mut saida: ChildStdout = filho
        .stdout
        .take()
        .ok_or("a saida do emulador nao veio em cano")?;
    let casos = Arc::new(AtomicU64::new(0));
    let contados = Arc::clone(&casos);
    let leitor = std::thread::spawn(move || {
        let mut bloco = [0u8; 4096];
        let mut linha = Vec::new();
        loop {
            let n = match saida.read(&mut bloco) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let _ = destino.write_all(&bloco[..n]);
            let _ = destino.flush();
            for &b in &bloco[..n] {
                if b == b'\n' {
                    if termina_um_caso(&linha) {
                        contados.fetch_add(1, Ordering::Release);
                    }
                    linha.clear();
                } else if linha.len() < 1024 {
                    linha.push(b);
                }
            }
        }
    });
    Ok(Andamento { casos, leitor })
}

/// Se a linha é a de um caso terminado: `  <nome>  ok`, ou
/// `  <nome>  FALHOU -- <motivo>`, como `testes::executar` as escreve.
fn termina_um_caso(linha: &[u8]) -> bool {
    let texto = String::from_utf8_lossy(linha);
    let texto = texto.trim_end_matches('\r');
    texto.starts_with("  ") && (texto.ends_with(" ok") || texto.contains(" FALHOU -- "))
}

/// Aguarda o processo, matando-o se passar `janela` —
/// [`JANELA_SEM_PROGRESSO`] na suíte — sem terminar um caso — ver lá por que o limite é do andamento. No fim, diz
/// quantos casos contou e o maior intervalo entre dois.
fn aguardar_com_andamento(
    mut filho: Child,
    andamento: Andamento,
    janela: Duration,
) -> Result<Desfecho, String> {
    let mut ultimo = Instant::now();
    let mut vistos = 0;
    let mut maior = Duration::ZERO;
    let desfecho = loop {
        let casos = andamento.casos.load(Ordering::Acquire);
        if casos != vistos {
            vistos = casos;
            maior = maior.max(ultimo.elapsed());
            ultimo = Instant::now();
        }
        match filho
            .try_wait()
            .map_err(|e| format!("falha ao aguardar o emulador: {e}"))?
        {
            Some(status) => {
                break match status.code() {
                    Some(code) => Desfecho::Codigo(code),
                    None => Desfecho::Sinal,
                };
            }
            None if ultimo.elapsed() >= janela => {
                // Melhor um processo morto e um diagnóstico claro que um
                // job de CI pendurado sem explicação.
                let _ = filho.kill();
                let _ = filho.wait();
                break Desfecho::Estourou;
            }
            // 50 ms mantém a espera barata sem atrasar perceptivelmente o
            // fim de uma suíte que leva segundos.
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    // O emulador saiu e o cano fechou: o leitor termina com o que restou.
    let _ = andamento.leitor.join();
    if vistos > 0 {
        println!(
            "[xtask] {vistos} caso(s) terminado(s); o maior intervalo sem terminar um foi de {}s",
            maior.as_secs()
        );
    }
    Ok(desfecho)
}

/// Cliente do canal do agente.
///
/// Conecta no socket Unix onde a serial do kernel está exposta, envia uma
/// requisição JSON-RPC e imprime a resposta. É o comando que torna o kernel
/// operável de fora com uma única linha de shell — e é idêntico nas duas
/// arquiteturas, porque o protocolo é o mesmo.
fn agente(arch: Arquitetura, canal: u8, metodo: &str, params: &str) -> Result<ExitCode, String> {
    let limite = std::time::Instant::now() + ESPERA_PELO_CANAL;
    let mut avisou = false;

    loop {
        match tentar_agente(arch, canal, metodo, params) {
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

fn tentar_agente(
    arch: Arquitetura,
    canal: u8,
    metodo: &str,
    params: &str,
) -> Result<ExitCode, Espera> {
    // Uma porta de agente só fala depois do aperto de mão, com a chave do
    // agente dela — ver [`AgenteNaPorta`]. A serial continua em claro: é o
    // canal de emergência.
    if canal != 0 {
        let mut agente = AgenteNaPorta::conectar(arch, canal).map_err(Espera::Fatal)?;
        let resposta = agente.pedir(metodo, params).map_err(Espera::Fatal)?;
        println!("{resposta}");
        return Ok(ExitCode::SUCCESS);
    }
    let socket = caminho_canal(arch, canal);

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
    /// O andamento conta o que a suíte escreve ao fim de cada caso, e não
    /// o log que um caso escreve no meio — nem o de um laço que só escreve.
    #[test]
    fn o_andamento_conta_so_casos_terminados() {
        use super::termina_um_caso as termina;
        assert!(termina(b"  rede: ARP vai e volta                      ok"));
        assert!(termina(
            b"  rede: ARP vai e volta                      ok\r"
        ));
        assert!(termina(
            b"  armazem: o lote e inteiro                  FALHOU -- o lote valeu pela metade"
        ));
        for log in [
            &b"[ 1375]   681810ms error virtio   a placa devolveu a cadeia 0; desligada"[..],
            b"[ 1374]   681780ms info  teste    10.0.2.2 responde: ok",
            b"  suite de testes :: x86_64 :: 379 casos",
            b"  378 de 379 passaram",
            b"",
        ] {
            assert!(!termina(log), "{}", String::from_utf8_lossy(log));
        }
    }

    /// Um processo de verdade, com a janela curta: o que para de terminar
    /// casos é encerrado, e o que continua terminando passa da janela sem
    /// ser — o limite é do andamento, e não do total.
    #[test]
    fn a_janela_e_do_andamento_e_nao_do_total() {
        use super::*;
        let correr = |roteiro: &str| {
            let mut filho = Command::new("sh")
                .args(["-c", roteiro])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let andamento = acompanhar(&mut filho, std::io::sink()).unwrap();
            let inicio = Instant::now();
            let desfecho =
                aguardar_com_andamento(filho, andamento, Duration::from_secs(1)).unwrap();
            (desfecho, inicio.elapsed())
        };
        // Parado depois do primeiro caso, escrevendo log: encerrado.
        let (d, t) =
            correr("echo '  um  ok'; while true; do echo '[ 1] 1ms info log'; sleep 0.1; done");
        assert!(matches!(d, Desfecho::Estourou) && t < Duration::from_secs(5));
        // Um caso a cada 0,4 s por 2,4 s — mais que a janela no total: sai sozinho.
        let (d, t) = correr("for i in 1 2 3 4 5 6; do sleep 0.4; echo \"  caso $i  ok\"; done");
        assert!(matches!(d, Desfecho::Codigo(0)) && t > Duration::from_secs(2));
    }

    #[test]
    fn a_janela_a_mao_e_achada_fora_dos_comentarios() {
        use super::linha_a_mao as linha_que_descreve;
        // O comentário que fala da chamada não é a chamada.
        assert_eq!(
            linha_que_descreve("// ver `sistema::descrever(`\n/// o `Escritor`\nfn f() {}"),
            None
        );
        assert_eq!(
            linha_que_descreve("fn f() {\n    sistema::descrever(fd, \"janela\\tx\");\n}"),
            Some((2, "sistema::descrever(fd, \"janela\\tx\");"))
        );
        assert_eq!(
            linha_que_descreve("let e = Escritor::nova(\"x\");").map(|(n, _)| n),
            Some(1)
        );
        assert_eq!(
            linha_que_descreve("x\n  d.elemento(Tipo::Botao, 1, r, \"OK\", \"\");").map(|(n, _)| n),
            Some(2)
        );
        assert_eq!(
            linha_que_descreve("janela.superficie().pixels().fill(0);").map(|(n, _)| n),
            Some(1)
        );
        assert_eq!(linha_que_descreve("let ui = Interface::nova(c);"), None);
    }

    #[test]
    fn a_fase_completa_e_ate_o_primeiro_buraco() {
        let roteiro = "\
- [x] **Fase 0 — A.**
- [x] **Fase 0 — B.**
- [x] **Fase 1 — C.**
- [ ] **Fase 2 — D.**
- [x] **Fase 3 — E.**
";
        assert_eq!(super::ultima_fase_completa(roteiro), Some(1));
        assert_eq!(super::ultima_fase_completa("- [ ] **Fase 0 — A.**"), None);
        assert_eq!(
            super::ultima_fase_completa("- [x] **Fase 0 — A.**\n- [x] **Fase 1 — B.**"),
            Some(1)
        );
    }

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
        // Dois executáveis falsos, do mesmo tamanho e com o mesmo byte do
        // meio, diferentes num byte só: a receita precisa separá-los.
        let mut um = vec![0u8; 64];
        let mut outro = vec![0u8; 64];
        um[3] = 1;
        outro[3] = 2;
        let receita = receita_do_disco(&[("programas/x86_64/ola".to_string(), um.clone())]);
        assert!(
            receita.contains("programas/x86_64/ola = 64 bytes"),
            "a receita não menciona o programa:\n{receita}"
        );
        assert_ne!(
            receita,
            receita_do_disco(&[("programas/x86_64/ola".to_string(), outro)]),
            "dois programas diferentes de mesmo tamanho deram a mesma receita"
        );
        let receita = receita_do_disco(&[("programas/x86_64/ola".to_string(), um)]);

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
