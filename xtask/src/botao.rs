//! A bancada do botão de energia: `cargo xtask botao`.
//!
//! O botão de verdade, pelo emulador: o `system_powerdown` do QMP é o que o
//! QEMU faz quando alguém aperta o botão da máquina — no x86 (`pc`, com o
//! PIIX4), o `PWRBTN_STS` do PM1 e o SCI; no ARM (`virt`, sem ACPI), a
//! borda no pino 3 do PL061 da tecla `gpio-keys`. Nada se simula dentro do
//! kernel: o caminho é o do hardware até o fio do botão, e dele ao gate —
//! ver `kernel/src/botao.rs`.
//!
//! Cada cenário numa máquina nova — o estado do disco de testes zerado, ou
//! uma cópia da imagem de produção —, e o que ela mostra é lido como o
//! operador o lê: o `system.info` e a auditoria, pela serial; e o QEMU, que
//! só sai sozinho quando a máquina se desliga.
//!
//! Na imagem de desenvolvimento: o aperto desliga, com o pedido no journal
//! e o arquivo de antes inteiro; o aperto no meio de uma rajada de
//! gravações, sem perder nenhuma confirmada nem estragar nenhuma; dois
//! apertos, um desligamento; o aperto com um reinício a caminho, que segue
//! sendo um reinício; a energia cortada no meio do desligamento; o aperto
//! antes de o sistema estar de pé, que não pede nada; e a máquina sem
//! persistência, que recusa e segue. Na imagem de produção — a do
//! `provisionar`, com a identidade nascida no primeiro boot —: o aperto
//! desliga pela política do exemplo; e, com a política tirando o
//! `system.power` do papel da autoridade local, o aperto é recusado pelo
//! gate, e a máquina segue.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::persistencia::{self as p, Ligada, Rastro};
use super::{Ambiente, Arquitetura, Artefato, producao};

/// Quanto esperar a máquina sair sozinha depois do aperto: a resposta, o
/// meio segundo da energia, a descarga, e o firmware.
const ESPERA_PELO_DESLIGAMENTO: Duration = Duration::from_secs(60);

/// Quanto uma máquina que não deve desligar fica olhada depois do aperto.
const ESPERA_DE_QUEM_SEGUE: Duration = Duration::from_secs(6);

/// O arquivo que cada cenário grava antes do aperto, e o conteúdo dele.
const DIRETORIO: &str = "/armazem/sistema";
const ARQUIVO: &str = "/armazem/sistema/antes-do-aperto.txt";
const CONTEUDO: &str = "gravado antes do aperto";

/// A bancada: a imagem de desenvolvimento, e — quando um cenário de
/// produção vai rodar — os moldes de produção, que cada cenário copia.
struct Bancada {
    arch: Arquitetura,
    dev: Artefato,
    /// O disco da máquina de produção do cenário.
    disco: PathBuf,
    /// Os moldes: a política do exemplo, e a que tira o `system.power` do
    /// papel da autoridade local.
    producao: Option<PathBuf>,
    producao_negada: Option<PathBuf>,
}

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    producao: bool,
    rodar: fn(&Bancada) -> Result<String, String>,
}

const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "o aperto desliga a maquina, com o pedido no journal",
        producao: false,
        rodar: o_aperto_desliga_a_maquina,
    },
    Cenario {
        nome: "o aperto no meio das gravacoes nao perde nem estraga nenhuma",
        producao: false,
        rodar: o_aperto_no_meio_das_gravacoes,
    },
    Cenario {
        nome: "dois apertos sao um desligamento",
        producao: false,
        rodar: dois_apertos_sao_um_desligamento,
    },
    Cenario {
        nome: "com o reinicio a caminho, o aperto nao o troca",
        producao: false,
        rodar: com_o_reinicio_a_caminho,
    },
    Cenario {
        nome: "a energia cortada no meio do desligamento pelo botao",
        producao: false,
        rodar: o_corte_no_meio_do_desligamento,
    },
    Cenario {
        nome: "o aperto antes de o sistema estar de pe nao pede nada",
        producao: false,
        rodar: o_aperto_antes_do_sistema,
    },
    Cenario {
        nome: "sem persistencia, o aperto e recusado e a maquina segue",
        producao: false,
        rodar: sem_persistencia_a_maquina_segue,
    },
    Cenario {
        nome: "a imagem de producao desliga pelo aperto",
        producao: true,
        rodar: a_producao_desliga_pelo_aperto,
    },
    Cenario {
        nome: "a politica de producao que nega: o aperto e recusado, e a maquina segue",
        producao: true,
        rodar: a_politica_que_nega,
    },
];

/// Como o emulador avisa o aperto, como o `system.info` o diz.
fn via(arch: Arquitetura) -> &'static str {
    match arch {
        Arquitetura::X86_64 => "acpi",
        Arquitetura::Aarch64 => "gpio-keys",
    }
}

/// O botão do emulador, apertado: o `system_powerdown` do QMP.
fn apertar(arch: Arquitetura) -> Result<(), String> {
    let (mut escrita, mut leitor) = super::qmp_abrir(&super::caminho_qmp(arch))?;
    let r = super::qmp_pedir(
        &mut escrita,
        &mut leitor,
        r#"{"execute":"system_powerdown"}"#,
    )?;
    if r.contains("\"error\"") {
        return Err(format!("o QMP recusou o aperto\n  {r}"));
    }
    Ok(())
}

/// O botão como o `system.info` o diz.
#[derive(Debug)]
struct BotaoVisto {
    via: String,
    apertos: u64,
    pedidos: u64,
    ignorados: u64,
    desligado: bool,
}

fn botao_visto(m: &mut Ligada) -> Result<BotaoVisto, String> {
    let r = m.pedir("system.info", "{}")?;
    let b = r
        .split(r#""power_button":{"#)
        .nth(1)
        .and_then(|b| b.split('}').next())
        .ok_or_else(|| format!("o system.info nao diz o botao de energia\n  {r}"))?;
    let numero = |n: &str| -> Result<u64, String> {
        super::campo_simples(b, n)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("o botao nao diz `{n}`: {b}"))
    };
    Ok(BotaoVisto {
        via: super::campo_simples(b, "via").unwrap_or_default(),
        apertos: numero("presses")?,
        pedidos: numero("requests")?,
        ignorados: numero("ignored")?,
        desligado: !b.contains(r#""disabled":null"#),
    })
}

/// A máquina de pé, com a persistência disponível, o botão ligado pelo
/// que o emulador tem e sem aperto nenhum, e o arquivo de antes gravado.
fn de_pe_com_o_arquivo(arch: Arquitetura, m: &mut Ligada) -> Result<p::Persistencia, String> {
    let estado = p::persistencia_de(m)?;
    if estado.estado != "available" {
        return Err(format!(
            "a persistencia nao subiu: {} ({})",
            estado.estado, estado.motivo
        ));
    }
    let b = botao_visto(m)?;
    if b.via != via(arch) || b.apertos != 0 || b.desligado {
        return Err(format!(
            "o botao nao esta ligado como o emulador o tem: {b:?}"
        ));
    }
    confirmado(m, "fs.mkdir", &format!(r#"{{"path":"{DIRETORIO}"}}"#)).or_else(|e| {
        if e.contains("ja existe") {
            Ok(String::new())
        } else {
            Err(e)
        }
    })?;
    confirmado(
        m,
        "fs.write",
        &format!(r#"{{"path":"{ARQUIVO}","content":"{CONTEUDO}","expect_version":0}}"#),
    )?;
    Ok(estado)
}

/// Um pedido ao armazém pela serial, que tem de ser confirmado.
fn confirmado(m: &mut Ligada, metodo: &str, params: &str) -> Result<String, String> {
    let r = m.pedir(metodo, params)?;
    if !r.contains(r#""ok":true"#) || !r.contains(r#""durable":true"#) {
        return Err(format!("{metodo} {params} nao foi confirmado\n  {r}"));
    }
    Ok(r)
}

/// O conteúdo de um arquivo do armazém, se ele existe.
fn conteudo_de(m: &mut Ligada, caminho: &str) -> Result<Option<String>, String> {
    let r = m.pedir("fs.read", &format!(r#"{{"path":"{caminho}"}}"#))?;
    if r.contains(r#""error""#) {
        return Ok(None);
    }
    p::texto_do_resultado(&r, "content")
        .map(Some)
        .ok_or_else(|| format!("fs.read sem conteudo\n  {r}"))
}

/// O que o aperto deixou na auditoria, depois de `depois`: o aperto, pelo
/// kernel; a decisão do gate sobre o `system.poweroff`, pelo sistema; e o
/// pedido de desligar, quando a energia o aceitou.
struct DoAperto<'a> {
    aperto: &'a Rastro,
    decisao: &'a Rastro,
    pedido: Option<&'a Rastro>,
}

fn do_aperto<'a>(
    arch: Arquitetura,
    cauda: &'a [Rastro],
    depois: u64,
) -> Result<DoAperto<'a>, String> {
    let apertos: Vec<&Rastro> = cauda
        .iter()
        .filter(|r| r.seq > depois && r.metodo == "power.button" && r.codigo == "ALLOW")
        .collect();
    let [aperto] = apertos[..] else {
        return Err(format!(
            "a auditoria nao tem um aperto so depois de {depois}: {apertos:?}"
        ));
    };
    if aperto.titular != "kernel" || aperto.recurso != via(arch) {
        return Err(format!(
            "o aperto na auditoria nao e o do kernel: {aperto:?}"
        ));
    }
    let decisoes: Vec<&Rastro> = cauda
        .iter()
        .filter(|r| r.seq > aperto.seq && r.metodo == "system.poweroff" && r.recurso != "poweroff")
        .collect();
    let [decisao] = decisoes[..] else {
        return Err(format!(
            "o gate nao decidiu um pedido so depois do aperto: {decisoes:?}"
        ));
    };
    if decisao.titular != "system" {
        return Err(format!("o pedido nao foi o do sistema: {decisao:?}"));
    }
    let pedido = cauda
        .iter()
        .find(|r| r.seq > decisao.seq && r.metodo == "system.poweroff" && r.recurso == "poweroff");
    Ok(DoAperto {
        aperto,
        decisao,
        pedido,
    })
}

/// O desligamento pelo aperto, conferido no boot seguinte: a máquina subiu
/// de novo, com a persistência disponível; o aperto, a decisão do sistema
/// e o pedido de desligar voltaram do journal, nessa ordem; a cadeia se
/// verifica; e o arquivo de antes está inteiro.
fn conferir_o_desligamento(
    b: &Bancada,
    m: &mut Ligada,
    antes: &p::Persistencia,
) -> Result<String, String> {
    let depois = p::persistencia_de(m)?;
    if depois.estado != "available" || depois.boots <= antes.boots {
        return Err(format!(
            "o boot seguinte: {} ({}), boot {} depois de {}",
            depois.estado, depois.motivo, depois.boots, antes.boots
        ));
    }
    let cauda = p::cauda_da_auditoria(m)?;
    let feito = do_aperto(b.arch, &cauda, 0)?;
    let pedido = feito
        .pedido
        .ok_or("o pedido de desligar nao voltou do journal")?;
    if feito.decisao.codigo != "ALLOW" || pedido.codigo != "ALLOW" || !pedido.duravel {
        return Err(format!(
            "a decisao ou o pedido nao foram os de um desligamento aceito: {:?} {pedido:?}",
            feito.decisao
        ));
    }
    p::auditoria_verifica(m)?;
    if conteudo_de(m, ARQUIVO)?.as_deref() != Some(CONTEUDO) {
        return Err("o arquivo gravado antes do aperto nao voltou inteiro".into());
    }
    Ok(format!(
        "o aperto {}, a decisao {} e o pedido {} voltaram do journal no boot {}",
        feito.aperto.seq, feito.decisao.seq, pedido.seq, depois.boots
    ))
}

/// O aperto desliga a máquina: o QEMU sai sozinho, com sucesso; e no boot
/// seguinte o aperto, a decisão do sistema e o pedido de desligar estão no
/// journal, a cadeia se verifica e o arquivo de antes está inteiro.
fn o_aperto_desliga_a_maquina(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = de_pe_com_o_arquivo(b.arch, &mut m)?;
    apertar(b.arch)?;
    let status = m.esperar_sair(ESPERA_PELO_DESLIGAMENTO)?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let r = conferir_o_desligamento(b, &mut m, &antes)?;
    m.cortar_a_energia()?;
    Ok(format!("o QEMU saiu sozinho ({status}); {r}"))
}

/// O aperto no meio de uma rajada de gravações: as confirmadas antes de a
/// máquina parar voltam todas, inteiras; as outras, ou não existem, ou
/// estão inteiras — nenhuma pela metade; e a verificação do armazém não
/// acha nada.
fn o_aperto_no_meio_das_gravacoes(b: &Bancada) -> Result<String, String> {
    const RAJADA: usize = 24;
    let caminho = |i: usize| format!("{DIRETORIO}/rajada-{i}.txt");
    // Sem vírgula: o leitor de campo da bancada para nela.
    let conteudo = |i: usize| format!("a gravacao {i} da rajada inteira");
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = de_pe_com_o_arquivo(b.arch, &mut m)?;
    let mut ids = Vec::new();
    for i in 0..RAJADA {
        ids.push(m.mandar(
            "fs.write",
            &format!(
                r#"{{"path":"{}","content":"{}","expect_version":0}}"#,
                caminho(i),
                conteudo(i)
            ),
        )?);
    }
    // O aperto logo depois da primeira resposta: a rajada segue na fila da
    // serial, uma gravação de cada vez.
    let mut confirmadas = Vec::new();
    let (id, r) = m.proxima_resposta()?;
    if r.contains(r#""durable":true"#) {
        confirmadas.push(id);
    }
    apertar(b.arch)?;
    while let Ok((id, r)) = m.proxima_resposta() {
        if r.contains(r#""durable":true"#) {
            confirmadas.push(id);
        }
    }
    let status = m.esperar_sair(ESPERA_PELO_DESLIGAMENTO)?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    conferir_o_desligamento(b, &mut m, &antes)?;
    let mut voltaram = 0;
    for (i, id) in ids.iter().enumerate() {
        match conteudo_de(&mut m, &caminho(i))? {
            Some(c) if c == conteudo(i) => voltaram += 1,
            Some(c) => return Err(format!("a gravacao {i} voltou estragada: {c:?}")),
            None if confirmadas.contains(id) => {
                return Err(format!("a gravacao {i}, confirmada, nao voltou"));
            }
            None => {}
        }
    }
    let v = m.pedir("fs.verify", r#"{"path":"/armazem"}"#)?;
    if !v.contains(r#""ok":true"#) {
        return Err(format!("a verificacao do armazem achou estrago\n  {v}"));
    }
    m.cortar_a_energia()?;
    Ok(format!(
        "{} de {RAJADA} confirmadas antes da parada, {voltaram} voltaram inteiras, nenhuma pela metade",
        confirmadas.len()
    ))
}

/// Dois apertos seguidos: a máquina se desliga uma vez, e a auditoria tem
/// um aperto que pediu e uma decisão — o segundo aperto chegou com a
/// máquina parando, ou depois de ela parar.
fn dois_apertos_sao_um_desligamento(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = de_pe_com_o_arquivo(b.arch, &mut m)?;
    apertar(b.arch)?;
    // O segundo pode achar o emulador já saindo: a recusa do QMP não conta.
    let segundo = apertar(b.arch).is_ok();
    let status = m.esperar_sair(ESPERA_PELO_DESLIGAMENTO)?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let r = conferir_o_desligamento(b, &mut m, &antes)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o segundo aperto {}; {r}",
        if segundo {
            "chegou ao emulador"
        } else {
            "achou o emulador saindo"
        }
    ))
}

/// Com um reinício a caminho, o aperto não o troca por um desligamento: a
/// máquina reinicia — o QEMU não sai —, e a auditoria do boot seguinte tem
/// o pedido de reiniciar e nenhum aperto que pediu.
fn com_o_reinicio_a_caminho(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = de_pe_com_o_arquivo(b.arch, &mut m)?;
    let r = m.pedir("system.reboot", "{}")?;
    if !r.contains(r#""state":"rebooting""#) {
        return Err(format!("o reinicio nao foi aceito\n  {r}"));
    }
    apertar(b.arch)?;
    let depois = m.esperar_o_boot_seguinte(antes.boots)?;
    let cauda = p::cauda_da_auditoria(&mut m)?;
    if !cauda
        .iter()
        .any(|r| r.metodo == "system.reboot" && r.recurso == "reboot" && r.codigo == "ALLOW")
    {
        return Err("o pedido de reiniciar nao voltou do journal".into());
    }
    let pediu: Vec<&Rastro> = cauda
        .iter()
        .filter(|r| {
            (r.metodo == "power.button" && r.codigo == "ALLOW")
                || (r.metodo == "system.poweroff" && r.recurso == "poweroff")
        })
        .collect();
    if !pediu.is_empty() {
        return Err(format!(
            "o aperto pediu com o reinicio a caminho: {pediu:?}"
        ));
    }
    let visto = botao_visto(&mut m)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "reiniciou: boot {} -> {}; nenhum aperto pediu; o botao do boot novo: {} aperto(s)",
        antes.boots, depois.boots, visto.apertos
    ))
}

/// A energia cortada no meio do desligamento pelo botão — com o pedido já
/// aceito e a máquina parando —: o boot seguinte abre a persistência, o
/// pedido de desligar voltou do journal, a cadeia se verifica e o arquivo
/// de antes está inteiro.
fn o_corte_no_meio_do_desligamento(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = de_pe_com_o_arquivo(b.arch, &mut m)?;
    apertar(b.arch)?;
    // O `system.info` diz `powering_off` assim que o pedido foi aceito, no
    // meio segundo antes de as gravações pararem: o corte é ali.
    let limite = Instant::now() + Duration::from_secs(20);
    let mut parando = false;
    while Instant::now() < limite {
        match m.pedir("system.info", "{}") {
            Ok(r) if r.contains(r#""power":"powering_off""#) => {
                parando = true;
                break;
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break,
        }
    }
    m.cortar_a_energia()?;
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let r = conferir_o_desligamento(b, &mut m, &antes)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "{}; {r}",
        if parando {
            "cortada com a maquina parando"
        } else {
            "a maquina parou antes do corte"
        }
    ))
}

/// O aperto antes de o sistema estar de pé — no firmware, no começo do
/// boot — não pede nada: a máquina sobe e segue, o botão não conta aperto
/// nenhum, e a auditoria não tem aperto; e o botão funciona depois.
fn o_aperto_antes_do_sistema(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    // O aperto o mais cedo que o QMP aceitar, enquanto a máquina sobe.
    let cedo = std::thread::spawn(move || {
        let limite = Instant::now() + Duration::from_secs(30);
        while Instant::now() < limite {
            if apertar(arch).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    });
    let mut m = Ligada::subir(arch, &b.dev, None)?;
    if !cedo.join().unwrap_or(false) {
        return Err("o QMP nao aceitou o aperto cedo".into());
    }
    std::thread::sleep(ESPERA_DE_QUEM_SEGUE);
    let visto = botao_visto(&mut m)?;
    if visto.apertos != 0 || visto.pedidos != 0 {
        return Err(format!("o aperto de antes contou: {visto:?}"));
    }
    let cauda = p::cauda_da_auditoria(&mut m)?;
    if cauda.iter().any(|r| r.metodo == "power.button") {
        return Err("o aperto de antes foi a auditoria".into());
    }
    let antes = de_pe_com_o_arquivo(arch, &mut m)?;
    apertar(arch)?;
    let status = m.esperar_sair(ESPERA_PELO_DESLIGAMENTO)?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = Ligada::subir(arch, &b.dev, None)?;
    let r = conferir_o_desligamento(b, &mut m, &antes)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o aperto cedo nao contou, e o de depois desligou; {r}"
    ))
}

/// Sem TPM, a persistência não abre; o aperto pede, o gate aceita, e a
/// energia recusa — o pedido não chegaria ao journal —: a máquina segue
/// ligada, e a recusa fica na auditoria.
fn sem_persistencia_a_maquina_segue(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir_com(b.arch, &b.dev, Ambiente::sem_tpm(None))?;
    let estado = p::persistencia_de(&mut m)?;
    if estado.estado == "available" {
        return Err("sem TPM, a persistencia abriu".into());
    }
    apertar(b.arch)?;
    if let Ok(status) = m.esperar_sair(ESPERA_DE_QUEM_SEGUE) {
        return Err(format!(
            "sem persistencia, a maquina se desligou ({status})"
        ));
    }
    let visto = botao_visto(&mut m)?;
    if visto.apertos != 1 || visto.pedidos != 1 {
        return Err(format!("o aperto nao foi contado e pedido: {visto:?}"));
    }
    let cauda = p::cauda_da_auditoria(&mut m)?;
    let feito = do_aperto(b.arch, &cauda, 0)?;
    let recusa = cauda
        .iter()
        .find(|r| r.seq > feito.decisao.seq && r.metodo == "system.poweroff" && r.codigo == "ERROR")
        .ok_or("a recusa da energia nao esta na auditoria")?;
    if !m.pedir("system.info", "{}")?.contains(r#""power":null"#) {
        return Err("a maquina ficou a caminho de parar".into());
    }
    m.cortar_a_energia()?;
    Ok(format!(
        "persistencia {}; o aperto {} pediu, o gate decidiu {} ({}), a energia recusou em {}",
        estado.estado, feito.aperto.seq, feito.decisao.seq, feito.decisao.codigo, recusa.seq
    ))
}

impl Bancada {
    /// A máquina de produção do cenário, pelo firmware, com o TPM dela, num
    /// disco copiado do `molde`.
    fn ligar_producao(&self, molde: &PathBuf) -> Result<Ligada, String> {
        std::fs::copy(molde, &self.disco)
            .map_err(|e| format!("não foi possível copiar o molde: {e}"))?;
        self.religar_producao()
    }

    /// A mesma máquina de produção, de novo, no disco dela.
    fn religar_producao(&self) -> Result<Ligada, String> {
        Ligada::subir_com(
            self.arch,
            &Artefato::Disco(self.disco.clone()),
            Ambiente::ligar(self.arch, None)?.com_disco(self.disco.clone()),
        )
    }
}

/// A imagem de produção desliga pelo aperto: a do `provisionar`, com a
/// política do exemplo — a autoridade local com o papel `sistema` —, a
/// identidade nascida no primeiro boot, e o mesmo desligamento.
fn a_producao_desliga_pelo_aperto(b: &Bancada) -> Result<String, String> {
    let molde = b.producao.as_ref().ok_or("sem o molde de producao")?;
    let mut m = b.ligar_producao(molde)?;
    let antes = de_pe_com_o_arquivo(b.arch, &mut m)?;
    apertar(b.arch)?;
    let status = m.esperar_sair(ESPERA_PELO_DESLIGAMENTO)?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = b.religar_producao()?;
    let r = conferir_o_desligamento(b, &mut m, &antes)?;
    m.cortar_a_energia()?;
    Ok(format!("producao: {r}"))
}

/// A política de produção que nega: com o papel `sistema` — o da linha
/// `local` — sem `system.power`, o aperto é recusado pelo gate com
/// `DENY_PERMISSION`, a máquina segue ligada, e o aperto e a recusa ficam
/// na auditoria; quem a desliga é o corte de energia.
fn a_politica_que_nega(b: &Bancada) -> Result<String, String> {
    let molde = b
        .producao_negada
        .as_ref()
        .ok_or("sem o molde de producao")?;
    let mut m = b.ligar_producao(molde)?;
    de_pe_com_o_arquivo(b.arch, &mut m)?;
    apertar(b.arch)?;
    if let Ok(status) = m.esperar_sair(ESPERA_DE_QUEM_SEGUE) {
        return Err(format!(
            "com a politica que nega, a maquina se desligou ({status})"
        ));
    }
    let visto = botao_visto(&mut m)?;
    if visto.apertos != 1 || visto.pedidos != 1 || visto.ignorados != 0 {
        return Err(format!("o aperto nao foi contado e pedido: {visto:?}"));
    }
    let cauda = p::cauda_da_auditoria(&mut m)?;
    let feito = do_aperto(b.arch, &cauda, 0)?;
    if feito.decisao.codigo != "DENY_PERMISSION" || feito.pedido.is_some() {
        return Err(format!(
            "o gate nao recusou o aperto pelo papel: {:?}",
            feito.decisao
        ));
    }
    if !m.pedir("system.info", "{}")?.contains(r#""power":null"#) {
        return Err("a maquina ficou a caminho de parar".into());
    }
    m.cortar_a_energia()?;
    Ok(format!(
        "o aperto {} recusado ({}), e a maquina seguiu ligada",
        feito.aperto.seq, feito.decisao.codigo
    ))
}

/// A política sem o `system.power` no papel `sistema` — o da linha
/// `local` do exemplo —: a autoridade local não desliga.
fn sem_energia_no_sistema(texto: &str) -> Result<String, String> {
    if !texto.lines().any(|l| l == "local sistema") {
        return Err("o exemplo nao tem a linha `local sistema`".into());
    }
    let mut tirou = false;
    let mut nova = String::new();
    for linha in texto.lines() {
        if linha.starts_with("papel sistema ")
            && linha.split_whitespace().any(|p| p == "system.power")
        {
            tirou = true;
            let sem: Vec<&str> = linha
                .split_whitespace()
                .filter(|p| *p != "system.power")
                .collect();
            nova.push_str(&sem.join(" "));
        } else {
            nova.push_str(linha);
        }
        nova.push('\n');
    }
    if !tirou {
        return Err("o papel sistema do exemplo nao tem system.power".into());
    }
    Ok(nova)
}

/// O molde de produção: o material de um operador — a política do exemplo
/// com a serial `sistema`, mudada por `mudar`; um agente `sistema`; três
/// administradores; uma pessoa; e a chave de atualização —, o kernel desta
/// bancada no slot A, assinado por ela, e nenhuma chave do Duke. A bancada
/// da troca da própria senha usa o mesmo molde, com a pessoa dele.
pub(crate) fn molde_de_producao(
    arch: Arquitetura,
    nome: &str,
    mudar: impl Fn(&str) -> Result<String, String>,
) -> Result<PathBuf, String> {
    let agentes = producao::chave_nova("agente", "sistema-1", Some("sistema"))?.1;
    molde_de_producao_com(arch, nome, mudar, &agentes)
}

/// [`molde_de_producao`], com o arquivo dos agentes dado: a bancada da
/// cópia de segurança põe um agente operador, cuja privada ela guarda.
pub(crate) fn molde_de_producao_com(
    arch: Arquitetura,
    nome: &str,
    mudar: impl Fn(&str) -> Result<String, String>,
    agentes: &str,
) -> Result<PathBuf, String> {
    let raiz = super::raiz_do_estado();
    let dir = raiz.join(format!("operador-{nome}-{}", arch.nome()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let escrever = |arquivo: &str, conteudo: &str| {
        std::fs::write(dir.join(arquivo), conteudo).map_err(|e| format!("{arquivo}: {e}"))
    };
    let exemplo = super::raiz_do_projeto().join("docs/exemplos/producao/politica");
    let do_exemplo =
        std::fs::read_to_string(&exemplo).map_err(|e| format!("{}: {e}", exemplo.display()))?;
    let com_a_serial = do_exemplo.replace("\nserial observador\n", "\nserial sistema\n");
    if com_a_serial == do_exemplo {
        return Err(format!(
            "{}: o exemplo nao tem a linha `serial observador`",
            exemplo.display()
        ));
    }
    escrever("politica", &mudar(&com_a_serial)?)?;
    escrever("nome", &format!("bancada-{nome}\n"))?;
    escrever("agentes", agentes)?;
    let mut administradores = String::new();
    for adm in ["adm-a", "adm-b", "adm-c"] {
        administradores
            .push_str(&producao::chave_nova("administrador", adm, Some("administrador"))?.1);
    }
    escrever("administradores", &administradores)?;
    escrever("senha-ana", "uma senha comprida de teste\n")?;
    escrever("pessoas", "ana operador senha-ana\n")?;
    let (publicador, linha, _) = producao::chave_nova("atualizacao", "publicador-1", None)?;
    escrever("atualizacao", &linha)?;
    let op = producao::ler_o_operador(&dir)?;
    let politica = producao::conferir(&op)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&super::aleatorios()?[..16]);
    let arquivos = producao::arquivos_da_raiz(&op, &politica, id)?;
    let kernel = super::slots::kernel_da_imagem(&super::slots::imagem_do_slot(
        &super::disco_de_testes()?,
        atualizacao::Slot::A,
    )?)?;
    let slot = super::slots::imagem(
        &super::slots::Pedido {
            arch,
            kernel: &kernel,
            pacote: &producao::pacote_do_produto(arch)?,
            versao: "bancada-botao",
            geracao: 1,
            estado: (
                super::slots::FORMATO_DO_ESTADO,
                super::slots::FORMATO_DO_ESTADO,
            ),
        },
        &producao::chave_de_atualizacao_de_texto(&publicador)?,
    )?;
    super::slots::conferir_imagem(&slot.bytes, &op.atualizacao, arch)?;
    let molde = raiz.join(format!("{nome}-molde-{}.img", arch.nome()));
    let _ = std::fs::remove_file(&molde);
    producao::montar_o_disco(arch, false, &molde, &arquivos, &slot.bytes)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(molde)
}

pub(crate) fn botao(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let dev = super::build(arch, release, false)?;
    let _ = p::SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("botao-{}.serial", arch.nome())));
    // Um filtro opcional pelo nome, como o da persistência: pedaços do nome
    // separados por `|`.
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let escolhidos: Vec<&Cenario> = CENARIOS.iter().filter(|c| escolhido(c)).collect();
    let producao = escolhidos.iter().any(|c| c.producao);
    let bancada = Bancada {
        arch,
        dev,
        disco: super::raiz_do_estado().join(format!("botao-{}.img", arch.nome())),
        producao: if producao {
            Some(molde_de_producao(arch, "botao", |t| Ok(t.to_string()))?)
        } else {
            None
        },
        producao_negada: if producao {
            Some(molde_de_producao(
                arch,
                "botao-negado",
                sem_energia_no_sistema,
            )?)
        } else {
            None
        },
    };
    println!(
        "[xtask] botao: {} cenarios, cada um numa maquina nova ({})",
        escolhidos.len(),
        arch.nome()
    );
    let mut falhas = 0;
    for cenario in escolhidos {
        super::zerar_o_estado(arch)?;
        if let (None, Some(serial)) = (std::env::var_os("DUKE_BANCADA_LOG"), p::serial_do_cenario())
        {
            let _ = std::fs::write(serial, b"");
        }
        match (cenario.rodar)(&bancada) {
            Ok(detalhe) => println!("  [botao] ok  {}: {detalhe}", cenario.nome),
            Err(motivo) => {
                falhas += 1;
                println!("  [botao] FALHOU  {}: {motivo}", cenario.nome);
                p::mostrar_o_fim_da_serial();
            }
        }
    }
    super::zerar_o_estado(arch)?;
    for molde in [&bancada.producao, &bancada.producao_negada]
        .into_iter()
        .flatten()
    {
        let _ = std::fs::remove_file(molde);
    }
    let _ = std::fs::remove_file(&bancada.disco);
    if falhas > 0 {
        println!("\n[xtask] botao: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] botao: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}
