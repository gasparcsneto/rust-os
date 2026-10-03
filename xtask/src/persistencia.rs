//! A bancada de persistência: a mesma máquina, subida várias vezes sobre o
//! mesmo disco e o mesmo TPM.
//!
//! # O que ela tem que a fumaça não tem
//!
//! A fumaça sobe a máquina uma vez e conversa com ela. O que a persistência
//! promete só aparece **entre** boots: o que sobrevive a um corte de
//! energia, o que um disco restaurado de uma cópia antiga consegue fingir,
//! o que um relógio que andou para trás faz com os prazos. Esta bancada é
//! quem desliga a máquina no meio, fotografa a partição de estado, devolve
//! uma fotografia velha ao disco e sobe tudo de novo.
//!
//! # Desligar é cortar a energia
//!
//! Não há desligamento ordenado aqui: a máquina morre com `SIGKILL`, sem
//! aviso. É o caso difícil — o que foi confirmado tem de estar no disco
//! porque o kernel o pôs lá antes de confirmar, e não porque teve tempo de
//! arrumar a casa. Um desligamento educado esconderia exatamente o defeito
//! que esta bancada existe para achar.
//!
//! O TPM morre junto — ver [`Ligada::cortar_a_energia`] —, e o estado
//! dele fica no diretório, como o NV de um chip sem energia.

use super::{
    Ambiente, Arquitetura, Artefato, BufReader, Child, Command, Duration, ExitCode, Path, Teclado,
    UnixStream, Video, build, caminho_socket, canal_de_pe, comando_qemu, diretorio_do_tpm, disco,
    disco_de_testes, escrever_no_estado, ler_o_estado, pedir_pela_serial, zerar_o_estado,
};

/// Quanto esperar o canal de uma máquina recém-ligada responder.
const ESPERA_PELO_BOOT: Duration = Duration::from_secs(90);

/// Uma máquina de produção de pé, com o canal da serial aberto.
pub(crate) struct Ligada {
    filho: Child,
    escrita: UnixStream,
    leitor: BufReader<UnixStream>,
    id: u32,
    // Por último: o TPM sai depois do QEMU — ver o `Drop`.
    _ambiente: Ambiente,
}

impl Ligada {
    /// Liga a máquina, com o relógio em `relogio` se houver, e espera o
    /// canal da serial atender.
    pub(crate) fn subir(
        arch: Arquitetura,
        artefato: &Artefato,
        relogio: Option<&str>,
    ) -> Result<Ligada, String> {
        Ligada::subir_com(arch, artefato, Ambiente::ligar(arch, relogio)?)
    }

    /// Liga a máquina no ambiente dado — com ou sem TPM.
    pub(crate) fn subir_com(
        arch: Arquitetura,
        artefato: &Artefato,
        ambiente: Ambiente,
    ) -> Result<Ligada, String> {
        let socket = caminho_socket(arch);
        let mut qemu = comando_qemu(
            arch,
            artefato,
            Some(&socket),
            Teclado::Nativo,
            Video::Linear,
            &ambiente,
        )?;
        // A saída humana do x86 (COM1) não interessa aqui, e um terminal
        // cheio de log do firmware a cada boot esconderia o resultado.
        qemu.stdout(std::process::Stdio::null());
        let mut filho = qemu
            .spawn()
            .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;
        let fluxo = match canal_de_pe(&socket, filho.id(), ESPERA_PELO_BOOT) {
            Ok(f) => f,
            Err(e) => {
                let _ = filho.kill();
                let _ = filho.wait();
                return Err(e);
            }
        };
        fluxo
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| format!("não foi possível configurar o timeout: {e}"))?;
        let escrita = fluxo
            .try_clone()
            .map_err(|e| format!("não foi possível duplicar o fluxo: {e}"))?;
        Ok(Ligada {
            filho,
            escrita,
            leitor: BufReader::new(fluxo),
            // Longe das faixas da fumaça, que ninguém mais usa aqui, mas um
            // número reconhecível no log ajuda a ler uma falha.
            id: 70_000,
            _ambiente: ambiente,
        })
    }

    /// Um pedido pela serial, e a resposta dele.
    pub(crate) fn pedir(&mut self, metodo: &str, params: &str) -> Result<String, String> {
        pedir_pela_serial(
            &mut self.escrita,
            &mut self.leitor,
            &mut self.id,
            metodo,
            params,
        )
    }

    /// Corta a energia: `SIGKILL` no QEMU e no TPM, sem aviso a nenhum dos
    /// dois.
    ///
    /// O TPM morre junto, e por um gesto próprio. Medido: o `swtpm` só sai
    /// sozinho quando o QEMU sai **com ordem** — no `SIGTERM` o QEMU manda o
    /// desligamento pelo canal de controle; no `SIGKILL` não manda nada, e o
    /// `swtpm` fica esperando o próximo cliente com o estado volátil vivo. Um
    /// chip sem energia não guarda o volátil; o que sobrevive é só o que ele
    /// já tinha gravado no NV, e é isso que matá-lo reproduz.
    pub(crate) fn cortar_a_energia(mut self) -> Result<(), String> {
        let _ = self.filho.kill();
        let _ = self.filho.wait();
        match self._ambiente.tpm.as_mut() {
            Some((tpm, _)) => tpm
                .kill()
                .and_then(|()| tpm.wait().map(|_| ()))
                .map_err(|e| format!("não foi possível desligar o swtpm: {e}")),
            None => Ok(()),
        }
    }
}

impl Drop for Ligada {
    fn drop(&mut self) {
        let _ = self.filho.kill();
        let _ = self.filho.wait();
    }
}

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    rodar: fn(Arquitetura, &Artefato) -> Result<String, String>,
}

/// Os cenários, na ordem em que rodam. Cada um começa com o estado zerado.
const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "o disco tem a particao de estado, no tipo e no lugar declarados",
        rodar: a_particao_de_estado,
    },
    Cenario {
        nome: "a fotografia da particao de estado volta ao disco byte a byte",
        rodar: a_fotografia_volta,
    },
    Cenario {
        nome: "a maquina sobe duas vezes sobre o mesmo TPM, com o relogio onde se mandou",
        rodar: dois_boots_sobre_o_mesmo_tpm,
    },
    Cenario {
        nome: "o RTC que o kernel le e o que a maquina recebeu, para a frente e para tras",
        rodar: o_rtc_e_o_que_se_mandou,
    },
    Cenario {
        nome: "a revogacao por quorum sobrevive ao corte de energia, e a lapide vence a imagem",
        rodar: a_revogacao_sobrevive,
    },
    Cenario {
        nome: "o registro, o papel e a politica sobrevivem; a versao da politica e a geracao continuam",
        rodar: o_estado_sobrevive,
    },
    Cenario {
        nome: "a fotografia antiga devolvida ao disco e recusada, e a administracao fica bloqueada",
        rodar: a_fotografia_antiga_e_recusada,
    },
    Cenario {
        nome: "um journal adulterado e recusado, e nenhuma credencial revogada volta",
        rodar: o_journal_adulterado_e_recusado,
    },
    Cenario {
        nome: "a queda no meio da gravacao: o journal continua o atual, gravado ou nao",
        rodar: a_queda_no_meio_da_gravacao,
    },
    Cenario {
        nome: "o TPM limpo entre dois boots e recusado",
        rodar: o_tpm_limpo_e_recusado,
    },
    Cenario {
        nome: "sem TPM, nada de autoridade muda, e o que nao e autoridade continua",
        rodar: sem_tpm_nada_de_autoridade,
    },
    Cenario {
        nome: "o relogio logico nao volta quando o RTC volta, e anda quando o RTC passa dele",
        rodar: o_relogio_logico_nao_volta,
    },
    Cenario {
        nome: "o signatario recusa assinar sobre uma geracao menor que a que ja viu",
        rodar: o_signatario_recusa_geracao_menor,
    },
];

/// `cargo xtask persistencia`: roda os cenários e diz quais passaram.
pub(crate) fn persistencia(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release, false)?;
    println!(
        "[xtask] persistencia: {} cenarios, cada um sobre um estado zerado ({})",
        CENARIOS.len(),
        arch.nome()
    );
    let mut falhas = 0;
    for cenario in CENARIOS {
        zerar_o_estado(arch)?;
        match (cenario.rodar)(arch, &artefato) {
            Ok(detalhe) => println!("  [persistencia] ok  {}: {detalhe}", cenario.nome),
            Err(motivo) => {
                falhas += 1;
                println!("  [persistencia] FALHOU  {}: {motivo}", cenario.nome);
            }
        }
    }
    // O disco fica zerado para quem vier depois, como todo comando o deixa.
    zerar_o_estado(arch)?;
    if falhas > 0 {
        println!("\n[xtask] persistencia: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] persistencia: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}

/// A GPT diz o que o kernel vai procurar: a terceira partição, do tipo do
/// Duke, onde o `xtask` a declara — conferido pelo `sgdisk`, de fora.
fn a_particao_de_estado(_: Arquitetura, _: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    let saida = Command::new("sgdisk")
        .args(["-i", "3", &disco.display().to_string()])
        .output()
        .map_err(|e| format!("não foi possível rodar o sgdisk: {e}"))?;
    let texto = String::from_utf8_lossy(&saida.stdout);
    let ultimo = disco::ESTADO_EM + disco::ESTADO_SETORES - 1;
    for esperado in [
        format!("Partition GUID code: {}", disco::GUID_DO_ESTADO),
        format!("First sector: {} ", disco::ESTADO_EM),
        format!("Last sector: {ultimo} "),
        "Partition name: 'duke-estado'".to_string(),
    ] {
        if !texto.contains(&esperado) {
            return Err(format!("o sgdisk não diz `{esperado}`:\n{texto}"));
        }
    }
    Ok(format!(
        "setores {}..={ultimo}, tipo {}",
        disco::ESTADO_EM,
        disco::GUID_DO_ESTADO
    ))
}

/// Fotografar e restaurar é o que a bancada usa para simular um disco
/// devolvido a uma cópia antiga. Se a fotografia não voltar byte a byte, o
/// cenário de restauração testaria outra coisa.
fn a_fotografia_volta(_: Arquitetura, _: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    let vizinhos_antes = vizinhos_da_particao(&disco)?;
    let padrao: Vec<u8> = (0..disco::ESTADO_SETORES * 512)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 9) as u8))
        .collect();
    escrever_no_estado(&disco, &padrao)?;
    let foto = ler_o_estado(&disco)?;
    escrever_no_estado(&disco, &vec![0u8; padrao.len()])?;
    if ler_o_estado(&disco)? == foto {
        return Err("zerar não mudou a partição".into());
    }
    escrever_no_estado(&disco, &foto)?;
    if ler_o_estado(&disco)? != padrao {
        return Err("a fotografia restaurada não é a que foi tirada".into());
    }
    // E nada fora da partição foi tocado: o setor logo antes dela é da raiz,
    // e o logo depois é a sobra antes da cópia da GPT.
    if vizinhos_da_particao(&disco)? != vizinhos_antes {
        return Err("escrever na partição de estado mudou um setor vizinho".into());
    }
    Ok(format!(
        "{} KiB, e os setores vizinhos intactos",
        padrao.len() / 1024
    ))
}

/// O setor logo antes da partição de estado e o logo depois dela.
fn vizinhos_da_particao(disco: &Path) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut arquivo = std::fs::File::open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    let mut bytes = vec![0u8; 1024];
    for (i, setor) in [
        disco::ESTADO_EM - 1,
        disco::ESTADO_EM + disco::ESTADO_SETORES,
    ]
    .into_iter()
    .enumerate()
    {
        arquivo
            .seek(SeekFrom::Start(setor * 512))
            .and_then(|_| arquivo.read_exact(&mut bytes[i * 512..(i + 1) * 512]))
            .map_err(|e| format!("não foi possível ler o setor {setor}: {e}"))?;
    }
    Ok(bytes)
}

/// Dois boots, com corte de energia entre eles, sobre o mesmo diretório do
/// TPM. O segundo com o relógio numa data fixa.
fn dois_boots_sobre_o_mesmo_tpm(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let mut maquina = Ligada::subir(arch, artefato, None)?;
    let r = maquina.pedir("agent.ping", "{}")?;
    if !r.contains(r#""result""#) {
        return Err(format!("o primeiro boot não respondeu ao ping\n  {r}"));
    }
    maquina.cortar_a_energia()?;

    let nv = diretorio_do_tpm(arch)
        .join("estado")
        .join("tpm2-00.permall");
    if !Path::new(&nv).is_file() {
        return Err(format!(
            "o estado do TPM não ficou no disco do hospedeiro: {}",
            nv.display()
        ));
    }

    let mut maquina = Ligada::subir(arch, artefato, Some("2031-05-17T12:00:00"))?;
    let r = maquina.pedir("agent.ping", "{}")?;
    if !r.contains(r#""result""#) {
        return Err(format!("o segundo boot não respondeu ao ping\n  {r}"));
    }
    maquina.cortar_a_energia()?;
    Ok("dois cortes de energia, o NV do TPM no disco do hospedeiro entre eles".into())
}

/// O RTC lido pelo kernel, pelo `system.info`.
fn rtc_do_kernel(maquina: &mut Ligada) -> Result<u64, String> {
    let r = maquina.pedir("system.info", "{}")?;
    super::campo_simples(&r, "rtc")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("o system.info nao diz o rtc\n  {r}"))
}

/// A máquina sobe com o RTC numa data, e o kernel lê essa data — numa data
/// à frente, e depois numa atrás dela. É o que os cenários do relógio
/// lógico vão usar para fazer o tempo voltar entre dois boots.
fn o_rtc_e_o_que_se_mandou(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    // 2031-05-17 12:00:00 e 2024-01-01 00:00:00 UTC.
    let mut lidos = Vec::new();
    for (data, esperado) in [
        ("2031-05-17T12:00:00", 1_936_785_600u64),
        ("2024-01-01T00:00:00", 1_704_067_200u64),
    ] {
        let mut maquina = Ligada::subir(arch, artefato, Some(data))?;
        let rtc = rtc_do_kernel(&mut maquina)?;
        maquina.cortar_a_energia()?;
        // O boot leva segundos, e o relógio anda com a máquina.
        if !(esperado..esperado + 300).contains(&rtc) {
            return Err(format!(
                "a maquina subiu em {data} ({esperado}) e o kernel leu {rtc}"
            ));
        }
        lidos.push(rtc);
    }
    Ok(format!("{} e depois {}", lidos[0], lidos[1]))
}

// ---------------------------------------------------------------------------
// O estado administrativo durável (fase 7.3)
// ---------------------------------------------------------------------------

/// O que o `system.info` diz da persistência.
struct Persistencia {
    estado: String,
    motivo: String,
    geracao: u64,
    boots: u64,
    relogio: u64,
    descargas: u64,
}

fn persistencia_de(maquina: &mut Ligada) -> Result<Persistencia, String> {
    let r = maquina.pedir("system.info", "{}")?;
    let p = r
        .split(r#""persistence":{"#)
        .nth(1)
        .ok_or_else(|| format!("o system.info nao diz a persistencia\n  {r}"))?;
    let p = p.split('}').next().unwrap_or("");
    let texto = |n: &str| super::campo_simples(p, n).unwrap_or_default();
    let numero = |n: &str| -> Result<u64, String> {
        super::campo_simples(p, n)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("a persistencia nao diz `{n}`: {p}"))
    };
    Ok(Persistencia {
        estado: texto("state"),
        motivo: texto("reason"),
        geracao: numero("generation")?,
        boots: numero("boots")?,
        relogio: numero("clock")?,
        descargas: numero("disk_flushes")?,
    })
}

/// Uma operação administrativa provada pela credencial `privada`, pela
/// serial.
fn administrar(
    maquina: &mut Ligada,
    privada: &[u8; 32],
    comando: &str,
    params: &str,
) -> Result<String, String> {
    let desafio = maquina.pedir("admin.challenge", "{}")?;
    let pedido = super::pedido_administrativo_de(privada, 0, &desafio, comando, params, params)?;
    maquina.pedir("admin.execute", &pedido)
}

/// A revogação de `alvo` por quórum, assinada pelas credenciais `quem`.
fn revogar(
    arch: Arquitetura,
    maquina: &mut Ligada,
    chaves: &super::chaves::Chaves,
    alvo: usize,
    quem: &[usize],
) -> Result<String, String> {
    let (alvo, _) = super::credencial_administrativa(chaves, alvo);
    super::revogacao_por_quorum(
        arch,
        (&mut maquina.escrita, &mut maquina.leitor, &mut maquina.id),
        chaves,
        &alvo,
        quem,
        "bancada",
    )
    .map(|(r, _)| r)
}

/// A chave privada X25519 de uma credencial administrativa da imagem.
fn privada_administrativa(chaves: &super::chaves::Chaves, i: usize) -> [u8; 32] {
    match i {
        0 => chaves.administrador,
        n => chaves.outros_administradores[n - 1],
    }
}

fn executou(r: &str) -> bool {
    r.contains(r#""executed":true"#)
}

/// O pedido de registro de um agente com a chave privada `privada`.
fn registro_de_agente(privada: &[u8; 32], nome: &str, papel: &str) -> String {
    format!(
        r#"{{"key":"{}","name":"{nome}","role":"{papel}"}}"#,
        sigilo::hex(&sigilo::publica_de(privada))
    )
}

/// A revogação por quórum é gravada; corta-se a energia; no boot seguinte
/// — com a imagem trazendo a mesma credencial de sempre — ela continua
/// revogada: não prova uma operação de uma credencial só, não assina um
/// quórum. A geração e os boots continuam de onde pararam.
fn a_revogacao_sobrevive(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let antes = persistencia_de(&mut m)?;
    if antes.estado != "available" {
        return Err(format!(
            "a persistencia nao subiu: {} ({})",
            antes.estado, antes.motivo
        ));
    }
    // A credencial 3 age, antes: lê a caixa dela.
    let r = administrar(
        &mut m,
        &privada_administrativa(&chaves, 2),
        "message.read",
        "{}",
    )?;
    if !executou(&r) {
        return Err(format!("a credencial 3 nao agiu antes da revogacao\n  {r}"));
    }
    let r = revogar(arch, &mut m, &chaves, 2, &[0, 1])?;
    if !executou(&r) {
        return Err(format!("o quorum nao revogou\n  {r}"));
    }
    let depois = persistencia_de(&mut m)?;
    if depois.geracao != antes.geracao + 1 {
        return Err("a revogacao nao subiu a geracao em um".into());
    }
    m.cortar_a_energia()?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "available" || p.geracao != depois.geracao || p.boots != depois.boots + 1 {
        return Err(format!(
            "o segundo boot nao continuou o journal: {} ({}), geracao {} (era {}), boot {}",
            p.estado, p.motivo, p.geracao, depois.geracao, p.boots
        ));
    }
    let r = administrar(
        &mut m,
        &privada_administrativa(&chaves, 2),
        "message.read",
        "{}",
    )?;
    if executou(&r) || !r.contains("revogada") {
        return Err(format!(
            "a credencial revogada provou uma operacao depois do reboot\n  {r}"
        ));
    }
    let r = revogar(arch, &mut m, &chaves, 1, &[0, 2])?;
    if executou(&r) || !r.contains("credencial revogada") {
        return Err(format!(
            "a credencial revogada assinou um quorum depois do reboot\n  {r}"
        ));
    }
    m.cortar_a_energia()?;
    Ok(format!(
        "geracao {} antes do corte e depois dele, boot {}",
        depois.geracao, p.boots
    ))
}

/// Um agente registrado, o papel dele mudado e uma linha de política
/// escrita: tudo de volta depois do corte. O agente entra pela porta com a
/// chave dele; a política nova vale; a versão da política e a geração
/// continuam — não voltam ao que a imagem diria.
fn o_estado_sobrevive(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let descargas = persistencia_de(&mut m)?.descargas;
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&chaves.intruso, "persistente", "observador"),
    )?;
    if !executou(&r) {
        return Err(format!("o registro nao foi executado\n  {r}"));
    }
    // A resposta veio depois de uma descarga do disco: o registro estava
    // gravado quando ela saiu.
    if persistencia_de(&mut m)?.descargas <= descargas {
        return Err("o registro respondeu sem uma descarga do disco".into());
    }
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "policy.write",
        r#"{"line":"taxa observador 7 21"}"#,
    )?;
    if !executou(&r) {
        return Err(format!("o policy.write nao foi executado\n  {r}"));
    }
    let versao = versao_da_politica(&mut m)?;
    let antes = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "available" || p.geracao != antes.geracao {
        return Err(format!(
            "o journal nao voltou: {} ({}), geracao {} (era {})",
            p.estado, p.motivo, p.geracao, antes.geracao
        ));
    }
    let depois = versao_da_politica(&mut m)?;
    if depois != versao {
        return Err(format!(
            "a versao da politica voltou: era {versao}, e depois do boot e {depois}"
        ));
    }
    let r = m.pedir("policy.read", "{}")?;
    if !r.contains("taxa observador 7 21") && !r.contains(r#""rate":{"per_second":7,"burst":21}"#) {
        // O relatório da política pode descrever a taxa em JSON; o que
        // importa é que a mudança voltou.
        if !r.contains("7") {
            return Err(format!("a linha de politica escrita nao voltou\n  {r}"));
        }
    }
    let mut agente = super::AgenteNaPorta::conectar_com(arch, 1, &chaves.intruso, &chaves.duke)?;
    let r = agente.pedir("agent.session", "{}")?;
    if !r.contains(r#""authenticated":true,"agent":"persistente""#) {
        return Err(format!(
            "o agente registrado nao entrou depois do boot\n  {r}"
        ));
    }
    drop(agente);
    m.cortar_a_energia()?;
    Ok(format!(
        "versao da politica {versao} nos dois boots, geracao {}",
        p.geracao
    ))
}

/// A versão da política em vigor, por um desafio de quórum.
fn versao_da_politica(m: &mut Ligada) -> Result<u64, String> {
    let r = m.pedir("admin.challenge", r#"{"for":"admin.revoke"}"#)?;
    super::campo_simples(&r, "policy_version")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("o desafio nao diz a versao da politica\n  {r}"))
}

/// A partição de estado é fotografada antes da revogação e devolvida ao
/// disco depois dela. Os registros da fotografia são autênticos — e a
/// âncora do TPM sabe que falta um. O boot recusa o journal, e a
/// administração inteira fica bloqueada, com o motivo.
fn a_fotografia_antiga_e_recusada(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let foto = ler_o_estado(&disco)?;
    let r = revogar(arch, &mut m, &chaves, 2, &[0, 1])?;
    if !executou(&r) {
        return Err(format!("o quorum nao revogou\n  {r}"));
    }
    m.cortar_a_energia()?;
    escrever_no_estado(&disco, &foto)?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "refused" || !p.motivo.contains("anterior") {
        return Err(format!(
            "o disco restaurado nao foi recusado: {} ({})",
            p.estado, p.motivo
        ));
    }
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0x51; 32], "restaurado", "observador"),
    )?;
    if executou(&r) || !r.contains("persistencia indisponivel") {
        return Err(format!(
            "uma operacao de autoridade passou sobre o disco restaurado\n  {r}"
        ));
    }
    // A credencial que a fotografia não sabe revogada: a administração
    // está bloqueada, e ela não faz nada de autoridade.
    let r = revogar(arch, &mut m, &chaves, 1, &[0, 2])?;
    if executou(&r) {
        return Err(format!(
            "a credencial que a fotografia traz de volta assinou um quorum\n  {r}"
        ));
    }
    m.cortar_a_energia()?;
    Ok(format!("{}: {}", p.estado, p.motivo))
}

/// Um byte trocado no meio do último registro confirmado: o boot lê até o
/// anterior, a âncora sabe que falta um, e o journal é recusado.
fn o_journal_adulterado_e_recusado(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = revogar(arch, &mut m, &chaves, 2, &[0, 1])?;
    if !executou(&r) {
        return Err(format!("o quorum nao revogou\n  {r}"));
    }
    m.cortar_a_energia()?;
    let mut estado = ler_o_estado(&disco)?;
    // O último setor com conteúdo é o fim do último registro; um byte do
    // meio dele, antes da etiqueta e dos zeros.
    let ultimo = estado
        .chunks(512)
        .rposition(|s| s.iter().any(|&b| b != 0))
        .ok_or("o journal esta vazio")?;
    let alvo = ultimo * 512 + 100;
    estado[alvo] ^= 0x40;
    escrever_no_estado(&disco, &estado)?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "refused" {
        return Err(format!(
            "o journal adulterado nao foi recusado: {} ({})",
            p.estado, p.motivo
        ));
    }
    let r = administrar(
        &mut m,
        &privada_administrativa(&chaves, 2),
        "message.read",
        "{}",
    )?;
    if executou(&r) {
        m.cortar_a_energia()?;
        return Err(format!(
            "com o registro da lapide estragado, a credencial revogada voltou a agir\n  {r}"
        ));
    }
    let r2 = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0x52; 32], "adulterado", "observador"),
    )?;
    if executou(&r2) {
        return Err(format!(
            "uma operacao de autoridade passou sobre o journal adulterado\n  {r2}"
        ));
    }
    m.cortar_a_energia()?;
    Ok(format!(
        "{} ({}); a credencial revogada, cuja lapide se perdeu, continua recusada",
        p.estado, p.motivo
    ))
}

/// O pedido de registro sai, e a energia cai logo depois — antes, durante
/// ou depois da gravação. No boot seguinte o journal é o atual (nunca
/// recusado: uma cauda cortada nunca foi confirmada), e o agente está ou
/// não está; se a resposta chegou antes do corte, ele está.
fn a_queda_no_meio_da_gravacao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut gravados = 0;
    let mut perdidos = 0;
    for (i, atraso_ms) in [0u64, 5, 20, 60, 150, 400, 1000].into_iter().enumerate() {
        let privada = [0x60 + i as u8; 32];
        let nome = format!("queda-{i}");
        let mut m = Ligada::subir(arch, artefato, None)?;
        let desafio = m.pedir("admin.challenge", "{}")?;
        let params = registro_de_agente(&privada, &nome, "observador");
        let pedido = super::pedido_administrativo_de(
            &chaves.administrador,
            0,
            &desafio,
            "agent.register",
            &params,
            &params,
        )?;
        use std::io::Write;
        m.id += 1;
        let linha = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"admin.execute","params":{pedido}}}"#,
            m.id
        );
        m.escrita
            .write_all(linha.as_bytes())
            .and_then(|()| m.escrita.write_all(b"\n"))
            .map_err(|e| format!("falha ao mandar o pedido: {e}"))?;
        std::thread::sleep(Duration::from_millis(atraso_ms));
        m.cortar_a_energia()?;

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        if p.estado != "available" {
            return Err(format!(
                "a queda com {atraso_ms} ms deixou o journal {} ({})",
                p.estado, p.motivo
            ));
        }
        let entrou = super::AgenteNaPorta::conectar_com(arch, 1, &privada, &chaves.duke)
            .and_then(|mut a| a.pedir("agent.session", "{}"))
            .is_ok_and(|r| r.contains(&format!(r#""agent":"{nome}""#)));
        if entrou {
            gravados += 1;
        } else {
            perdidos += 1;
        }
        m.cortar_a_energia()?;
    }
    // A queda depois de um segundo cai depois da gravação: sem nenhuma
    // gravada, o cenário não teria exercitado o lado de lá da janela.
    if gravados == 0 {
        return Err(
            "nenhuma das quedas aconteceu depois da gravacao: a janela nao foi exercitada".into(),
        );
    }
    Ok(format!(
        "7 quedas: {gravados} depois da gravacao, {perdidos} antes dela, nenhuma recusada"
    ))
}

/// O TPM limpo entre dois boots — o estado dele apagado —: o journal diz
/// que foi ancorado, e a âncora não existe. Recusado.
fn o_tpm_limpo_e_recusado(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let m = Ligada::subir(arch, artefato, None)?;
    m.cortar_a_energia()?;
    let estado = diretorio_do_tpm(arch).join("estado");
    let _ = std::fs::remove_dir_all(&estado);
    std::fs::create_dir_all(&estado).map_err(|e| e.to_string())?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;
    if p.estado != "refused" || !p.motivo.contains("TPM") {
        return Err(format!(
            "o TPM limpo nao foi recusado: {} ({})",
            p.estado, p.motivo
        ));
    }
    Ok(format!("{}: {}", p.estado, p.motivo))
}

/// Uma máquina sem TPM: sem âncora, a persistência é indisponível, e as
/// credenciais administrativas são recusadas com o motivo — para mudar
/// autoridade e para o resto. Os agentes continuam sendo atendidos.
fn sem_tpm_nada_de_autoridade(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir_com(arch, artefato, Ambiente::sem_tpm(None))?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "unavailable" || !p.motivo.contains("TPM") {
        m.cortar_a_energia()?;
        return Err(format!(
            "sem TPM, a persistencia disse {} ({})",
            p.estado, p.motivo
        ));
    }
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0x53; 32], "sem-tpm", "observador"),
    )?;
    if executou(&r) || !r.contains("persistencia indisponivel") {
        m.cortar_a_energia()?;
        return Err(format!("sem TPM, um registro passou\n  {r}"));
    }
    let r = administrar(&mut m, &chaves.administrador, "message.read", "{}")?;
    if executou(&r) {
        m.cortar_a_energia()?;
        return Err(format!(
            "sem TPM, uma credencial administrativa foi aceita\n  {r}"
        ));
    }
    let atendido = super::AgenteNaPorta::conectar(arch, 1)
        .and_then(|mut a| a.pedir("agent.ping", "{}"))
        .is_ok_and(|r| r.contains(r#""result""#));
    m.cortar_a_energia()?;
    if !atendido {
        return Err("sem TPM, o agente da porta 1 nao foi atendido".into());
    }
    Ok(format!(
        "{}; o agente da porta 1 continua atendido",
        p.motivo
    ))
}

/// O tempo lógico: num boot em 2031 ele está em 2031, e uma operação o
/// grava; no seguinte, com o RTC em 2024, ele continua em 2031 — o piso
/// do journal —; no terceiro, com o RTC em 2032, anda.
fn o_relogio_logico_nao_volta(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const EM_2031: u64 = 1_936_785_600;
    const EM_2032: u64 = 1_968_408_000; // 2032-05-17 12:00:00
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir(arch, artefato, Some("2031-05-17T12:00:00"))?;
    let a = persistencia_de(&mut m)?.relogio;
    // Uma operação gravada depois da leitura: o piso do journal passa a ser
    // pelo menos `a`. Uma leitura do relógio sozinha não grava nada — o
    // piso é o tempo do último registro, e é contra ele que o tempo lógico
    // não volta.
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0x54; 32], "relogio", "observador"),
    )?;
    if !executou(&r) {
        return Err(format!(
            "a operacao do primeiro boot nao foi executada\n  {r}"
        ));
    }
    m.cortar_a_energia()?;
    let mut m = Ligada::subir(arch, artefato, Some("2024-01-01T00:00:00"))?;
    let rtc = rtc_do_kernel(&mut m)?;
    let b = persistencia_de(&mut m)?.relogio;
    m.cortar_a_energia()?;
    let mut m = Ligada::subir(arch, artefato, Some("2032-05-17T12:00:00"))?;
    let c = persistencia_de(&mut m)?.relogio;
    m.cortar_a_energia()?;
    if !(EM_2031..EM_2031 + 300).contains(&a) {
        return Err(format!("no boot de 2031 o tempo logico e {a}"));
    }
    if rtc >= EM_2031 {
        return Err(format!("o RTC do segundo boot nao voltou: {rtc}"));
    }
    if b < a {
        return Err(format!(
            "o tempo logico voltou com o RTC: {a} no primeiro boot, {b} no segundo"
        ));
    }
    if c < EM_2032 {
        return Err(format!("o tempo logico nao andou com o RTC em 2032: {c}"));
    }
    Ok(format!("{a} -> {b} (RTC em {rtc}) -> {c}"))
}

/// O signatário guarda a maior geração que assinou: depois de assinar
/// numa, recusa assinar numa menor — a de uma fotografia antiga do disco
/// num TPM que alguém tivesse conseguido voltar junto.
fn o_signatario_recusa_geracao_menor(arch: Arquitetura, _: &Artefato) -> Result<String, String> {
    super::signatario_aceita(arch, "administrador", 5)?;
    super::signatario_aceita(arch, "administrador", 5)?;
    super::signatario_aceita(arch, "administrador", 6)?;
    match super::signatario_aceita(arch, "administrador", 4) {
        Err(e) if e.contains("recusa") => Ok(e),
        Err(e) => Err(format!("recusou pelo motivo errado: {e}")),
        Ok(()) => Err("o signatario assinou uma geracao menor que a que ja viu".into()),
    }
}
