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
        let (mut filho, socket) = lancar(arch, artefato, &ambiente)?;
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

/// Liga o QEMU, sem esperar nada dele. Devolve o processo e o socket da
/// serial do agente.
fn lancar(
    arch: Arquitetura,
    artefato: &Artefato,
    ambiente: &Ambiente,
) -> Result<(Child, std::path::PathBuf), String> {
    let socket = caminho_socket(arch);
    let mut qemu = comando_qemu(
        arch,
        artefato,
        Some(&socket),
        Teclado::Nativo,
        Video::Linear,
        ambiente,
    )?;
    // A saída humana do x86 (COM1) não interessa aqui, e um terminal cheio
    // de log do firmware a cada boot esconderia o resultado. Para depurar
    // um cenário, `DUKE_BANCADA_LOG` diz um arquivo onde acumulá-la.
    let saida = std::env::var("DUKE_BANCADA_LOG")
        .ok()
        .and_then(|caminho| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(caminho)
                .ok()
        })
        .map_or_else(std::process::Stdio::null, std::process::Stdio::from);
    qemu.stdout(saida);
    let filho = qemu
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o {}: {e}", arch.qemu()))?;
    Ok((filho, socket))
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
        nome: "o journal recusado: o agente revogado nele nao volta, nenhuma credencial vale, e a serial continua",
        rodar: o_journal_recusado_ainda_tira,
    },
    Cenario {
        nome: "as mensagens sobrevivem ao corte, nos mesmos ids, estados e versoes, e a epoca continua",
        rodar: as_mensagens_sobrevivem,
    },
    Cenario {
        nome: "o prazo de uma mensagem e do tempo logico: nao volta com o RTC, e o vencido nao volta a pendente",
        rodar: o_prazo_e_do_tempo_logico,
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

/// Os cenários que precisam do kernel da bancada, com os pontos de queda.
const CENARIOS_DE_QUEDA: &[Cenario] = &[
    Cenario {
        nome: "a queda em cada fronteira de uma operacao: vale se o registro esta no disco, e nada fica recusado",
        rodar: as_quedas_numa_operacao,
    },
    Cenario {
        nome: "a queda em cada fronteira de uma mensagem: ela existe se o registro esta no disco",
        rodar: as_quedas_numa_mensagem,
    },
    Cenario {
        nome: "a queda na criacao da ancora e retomada, e nunca recusada para sempre",
        rodar: as_quedas_na_criacao,
    },
    Cenario {
        nome: "a fotografia tirada na fronteira, ou na criacao, e recusada depois que o TPM andou",
        rodar: a_fotografia_da_fronteira_e_recusada,
    },
];

/// `cargo xtask persistencia`: roda os cenários e diz quais passaram.
///
/// Os de queda vêm por último, sobre outra compilação do kernel — a de
/// produção mais os pontos de queda —, que substitui a primeira no disco.
pub(crate) fn persistencia(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release, false)?;
    println!(
        "[xtask] persistencia: {} cenarios, cada um sobre um estado zerado ({})",
        CENARIOS.len() + CENARIOS_DE_QUEDA.len(),
        arch.nome()
    );
    let mut falhas = 0;
    // Um filtro opcional pelo nome, para rodar só alguns — o que uma
    // mutação dirigida precisa. Sem ele, todos.
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &Cenario| filtro.as_deref().is_none_or(|f| c.nome.contains(f));
    let mut rodar = |cenarios: &[Cenario], artefato: &Artefato| -> Result<(), String> {
        for cenario in cenarios.iter().filter(|c| escolhido(c)) {
            zerar_o_estado(arch)?;
            match (cenario.rodar)(arch, artefato) {
                Ok(detalhe) => println!("  [persistencia] ok  {}: {detalhe}", cenario.nome),
                Err(motivo) => {
                    falhas += 1;
                    println!("  [persistencia] FALHOU  {}: {motivo}", cenario.nome);
                }
            }
        }
        Ok(())
    };
    rodar(CENARIOS, &artefato)?;
    if CENARIOS_DE_QUEDA.iter().any(escolhido) {
        let da_bancada = super::build_com(arch, release, &[FEATURE_DE_QUEDAS])?;
        rodar(CENARIOS_DE_QUEDA, &da_bancada)?;
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
    registros: u64,
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
        registros: numero("records")?,
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
    let r = m.pedir("policy.show", "{}")?;
    if !r.contains(r#""rate":{"per_second":7,"burst":21}"#) {
        return Err(format!("a linha de politica escrita nao voltou\n  {r}"));
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
    // E as mensagens continuam, só em memória, dizendo isso.
    let enviada = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
        a.pedir(
            "message.send",
            &format!(
                r#"{{"to":"{}","body":"sem tpm","nonce":1}}"#,
                super::chaves::nome_do_agente(3)
            ),
        )
    })?;
    m.cortar_a_energia()?;
    if !atendido {
        return Err("sem TPM, o agente da porta 1 nao foi atendido".into());
    }
    if !enviada.contains(r#""ok":true"#)
        || !enviada.contains(r#""durable":false"#)
        || !enviada.contains(r#""memory_only""#)
    {
        return Err(format!(
            "sem TPM, a mensagem nao foi, ou nao disse que vale so em memoria\n  {enviada}"
        ));
    }
    Ok(format!(
        "{}; o agente da porta 1 continua atendido, e a mensagem vai so em memoria",
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

/// Um agente da imagem é revogado, e depois uma política é escrita; o
/// registro da política é estragado. O boot recusa o journal — e mesmo
/// assim o registro da revogação, que abre, é reaplicado: o agente
/// revogado não entra pela porta. As sessões de agente continuam sendo
/// atendidas com o journal recusado, e é por isso que reaplicar antes de
/// julgar importa também para elas.
fn o_journal_recusado_ainda_tira(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    // Uma mensagem à serial, gravada antes do registro que vai se estragar:
    // com o journal recusado, ela não pode reaparecer — o journal pode ser
    // um disco antigo, e ela, uma já confirmada.
    let r = super::AgenteNaPorta::conectar(arch, 1)?.pedir(
        "message.send",
        r#"{"to":"serial","body":"antes da recusa","nonce":1}"#,
    )?;
    if !r.contains(r#""durable":true"#) {
        return Err(format!("a mensagem a serial nao foi duravel\n  {r}"));
    }
    let revogado = sigilo::publica_de(&chaves.do_agente(2));
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.revoke",
        &format!(r#"{{"key":"{}"}}"#, sigilo::hex(&revogado)),
    )?;
    if !executou(&r) {
        return Err(format!("a revogacao do agente nao foi executada\n  {r}"));
    }
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "policy.write",
        r#"{"line":"taxa observador 6 18"}"#,
    )?;
    if !executou(&r) {
        return Err(format!("o policy.write nao foi executado\n  {r}"));
    }
    m.cortar_a_energia()?;
    let mut estado = ler_o_estado(&disco)?;
    let ultimo = estado
        .chunks(512)
        .rposition(|s| s.iter().any(|&b| b != 0))
        .ok_or("o journal esta vazio")?;
    estado[ultimo * 512 + 100] ^= 0x40;
    escrever_no_estado(&disco, &estado)?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "refused" {
        m.cortar_a_energia()?;
        return Err(format!(
            "o journal estragado nao foi recusado: {}",
            p.estado
        ));
    }
    let revogado_entrou = super::AgenteNaPorta::conectar(arch, 2)
        .and_then(|mut a| a.pedir("agent.ping", "{}"))
        .is_ok_and(|r| r.contains(r#""result""#));
    // Nenhuma credencial vale com o journal recusado: o que ele perdeu
    // pode ser a revogação de qualquer uma. A serial, sem credencial,
    // continua — é por ela que se vê o que houve.
    let outro =
        super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| a.pedir("agent.ping", "{}"));
    let serial = m.pedir("agent.ping", "{}")?;
    let caixa = m.pedir("message.read", "{}")?;
    m.cortar_a_energia()?;
    if caixa.contains("antes da recusa") {
        return Err(format!(
            "com o journal recusado, a mensagem dele reapareceu\n  {caixa}"
        ));
    }
    if revogado_entrou {
        return Err("com o journal recusado, o agente revogado nele voltou a entrar".into());
    }
    if outro.as_ref().is_ok_and(|r| r.contains(r#""result""#)) {
        return Err(format!(
            "com o journal recusado, a chave do agente da porta 1 valeu\n  {outro:?}"
        ));
    }
    if !serial.contains(r#""result""#) {
        return Err(format!(
            "com o journal recusado, a serial nao foi atendida\n  {serial}"
        ));
    }
    Ok(
        "o agente revogado continua fora, nenhuma chave vale, a serial atende, e a mensagem do journal recusado nao volta"
            .into(),
    )
}

/// O id de mensagem de uma resposta: o primeiro `"id":"..."` com texto.
fn id_de_mensagem(r: &str) -> Option<String> {
    let chave = r#""id":""#;
    let resto = &r[r.find(chave)? + chave.len()..];
    Some(resto[..resto.find('"')?].to_string())
}

/// O número de um id de mensagem — a parte depois da época.
fn numero_de(id: &str) -> u64 {
    id.rsplit(':')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// O estado de uma mensagem para o agente da porta `porta`, numa conexão
/// nova — que só se abre com a porta livre: o QEMU atende um cliente por
/// socket, e um segundo fica esperando o aperto que o primeiro segura.
fn estado_de(arch: Arquitetura, porta: u8, id: &str) -> Result<String, String> {
    estado_por(&mut super::AgenteNaPorta::conectar(arch, porta)?, id)
}

/// O estado de uma mensagem, pela conexão `agente`.
fn estado_por(agente: &mut super::AgenteNaPorta, id: &str) -> Result<String, String> {
    let r = agente.pedir("message.status", &format!(r#"{{"id":"{id}"}}"#))?;
    super::campo_simples(&r, "state").ok_or_else(|| format!("sem estado\n  {r}"))
}

/// As mensagens respondidas com `durable: true` sobrevivem a um corte de
/// energia: a porta 1 manda três à porta 3, que lê duas e confirma uma.
/// No boot seguinte a confirmada continua confirmada, a entregue continua
/// entregue, a pendente continua lá, os ids são os mesmos — com a mesma
/// época —, e o próximo id continua de onde parou.
fn as_mensagens_sobrevivem(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let para = super::chaves::nome_do_agente(3);
    let m = Ligada::subir(arch, artefato, None)?;
    let mut um = super::AgenteNaPorta::conectar(arch, 1)?;
    let mut ids = Vec::new();
    for n in 1..=3 {
        let r = um.pedir(
            "message.send",
            &format!(r#"{{"to":"{para}","body":"sobrevive {n}","nonce":{n}}}"#),
        )?;
        if !r.contains(r#""durable":true"#) {
            return Err(format!("o envio {n} nao foi duravel\n  {r}"));
        }
        ids.push(id_de_mensagem(&r).ok_or_else(|| format!("sem id\n  {r}"))?);
    }
    let mut tres = super::AgenteNaPorta::conectar(arch, 3)?;
    let lida = tres.pedir("message.read", r#"{"max":2}"#)?;
    let confirmada = tres.pedir("message.ack", &format!(r#"{{"id":"{}"}}"#, ids[0]))?;
    if !lida.contains(r#""durable":true"#) || !confirmada.contains(r#""durable":true"#) {
        return Err(format!(
            "a leitura ou a confirmacao nao foi duravel\n  {lida}\n  {confirmada}"
        ));
    }
    drop((um, tres));
    m.cortar_a_energia()?;

    let m = Ligada::subir(arch, artefato, None)?;
    let estados = [
        estado_de(arch, 1, &ids[0])?,
        estado_de(arch, 1, &ids[1])?,
        estado_de(arch, 1, &ids[2])?,
    ];
    let esperados = ["acked", "delivered", "pending"];
    if estados != esperados {
        m.cortar_a_energia()?;
        return Err(format!(
            "depois do corte, os estados sao {estados:?}, e nao {esperados:?}"
        ));
    }
    let lida = super::AgenteNaPorta::conectar(arch, 3)?.pedir("message.read", "{}")?;
    let r = super::AgenteNaPorta::conectar(arch, 1)?.pedir(
        "message.send",
        &format!(r#"{{"to":"{para}","body":"depois","nonce":1}}"#),
    )?;
    m.cortar_a_energia()?;
    if !lida.contains(&ids[1]) || !lida.contains(&ids[2]) || lida.contains(&ids[0]) {
        return Err(format!(
            "a caixa depois do corte nao e a de antes\n  {lida}"
        ));
    }
    let novo = id_de_mensagem(&r).ok_or_else(|| format!("sem id\n  {r}"))?;
    let epoca = |id: &str| id.split(':').next().unwrap_or("").to_string();
    if epoca(&novo) != epoca(&ids[0]) || numero_de(&novo) <= numero_de(&ids[2]) {
        return Err(format!(
            "o id depois do corte nao continua os de antes: {novo} depois de {}",
            ids[2]
        ));
    }
    Ok(format!(
        "{} confirmada, {} entregue, {} pendente; o proximo e {novo}",
        ids[0], ids[1], ids[2]
    ))
}

/// O prazo de uma mensagem corre no tempo lógico. Num boot em 2031 a porta
/// 1 manda duas: uma de um minuto e uma de um segundo, que vence e é
/// gravada vencida. No boot seguinte, com o RTC em 2024, o tempo lógico
/// está no piso de 2031: a de um minuto não venceu, e a vencida não voltou
/// a pendente. No terceiro, em 2032, a de um minuto venceu.
fn o_prazo_e_do_tempo_logico(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let para = super::chaves::nome_do_agente(3);
    let m = Ligada::subir(arch, artefato, Some("2031-05-17T12:00:00"))?;
    let mut um = super::AgenteNaPorta::conectar(arch, 1)?;
    let mut ids = Vec::new();
    for (n, prazo) in [(1, 60_000), (2, 1_000)] {
        let r = um.pedir(
            "message.send",
            &format!(r#"{{"to":"{para}","body":"prazo {n}","nonce":{n},"ttl_ms":{prazo}}}"#),
        )?;
        ids.push(id_de_mensagem(&r).ok_or_else(|| format!("sem id\n  {r}"))?);
    }
    // A curta vence em até dois segundos lógicos; a consulta a vence e grava.
    let limite = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if estado_por(&mut um, &ids[1])? == "expired" {
            break;
        }
        if std::time::Instant::now() >= limite {
            return Err("a mensagem de um segundo nao venceu".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    drop(um);
    m.cortar_a_energia()?;

    let m = Ligada::subir(arch, artefato, Some("2024-01-01T00:00:00"))?;
    let em_2024 = [estado_de(arch, 1, &ids[0])?, estado_de(arch, 1, &ids[1])?];
    m.cortar_a_energia()?;
    if em_2024 != ["pending", "expired"] {
        return Err(format!(
            "com o RTC em 2024, os estados sao {em_2024:?}: o prazo andou para tras"
        ));
    }
    let m = Ligada::subir(arch, artefato, Some("2032-05-17T12:00:00"))?;
    let em_2032 = estado_de(arch, 1, &ids[0])?;
    m.cortar_a_energia()?;
    if em_2032 != "expired" {
        return Err(format!("com o RTC em 2032, a de um minuto esta {em_2032}"));
    }
    Ok(
        "em 2024 a de um minuto continua pendente e a vencida continua vencida; em 2032 venceu"
            .into(),
    )
}

// ---------------------------------------------------------------------------
// As quedas nas fronteiras entre o journal e a âncora
// ---------------------------------------------------------------------------

/// A feature do kernel com os pontos de queda — ver `kernel/src/quedas.rs`.
/// Só esta bancada a pede.
const FEATURE_DE_QUEDAS: &str = "quedas";

/// Os pontos de queda, com os números de `kernel/src/quedas.rs`.
mod ponto {
    pub const ANCORA_DEFINIDA: u8 = 1;
    pub const ANCORA_AVANCADA: u8 = 2;
    pub const NASCIMENTO_GUARDADO: u8 = 3;
    pub const ANTES_DA_ESCRITA: u8 = 10;
    pub const DEPOIS_DA_ESCRITA: u8 = 11;
    pub const DEPOIS_DA_DESCARGA: u8 = 12;
    pub const DEPOIS_DO_CONTADOR: u8 = 13;
}

/// Quanto esperar o aviso da queda depois do pedido que a provoca.
const ESPERA_PELA_QUEDA: Duration = Duration::from_secs(60);

/// Escreve `bytes` (um setor) no setor `setor` da partição de estado.
fn escrever_setor_do_estado(disco: &Path, setor: u64, bytes: &[u8; 512]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let mut arquivo = std::fs::OpenOptions::new()
        .write(true)
        .open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    arquivo
        .seek(SeekFrom::Start((disco::ESTADO_EM + setor) * 512))
        .and_then(|_| arquivo.write_all(bytes))
        .and_then(|()| arquivo.sync_all())
        .map_err(|e| format!("não foi possível escrever no estado: {e}"))
}

/// O plano da queda: no último setor da partição, como o kernel o lê.
fn plano_de_queda(disco: &Path, ponto: u8, gravacao: u32) -> Result<(), String> {
    let mut setor = [0u8; 512];
    setor[..8].copy_from_slice(b"DUKEQUED");
    setor[8] = ponto;
    setor[12..16].copy_from_slice(&gravacao.to_le_bytes());
    escrever_setor_do_estado(disco, disco::ESTADO_SETORES - 1, &setor)
}

fn sem_plano(disco: &Path) -> Result<(), String> {
    escrever_setor_do_estado(disco, disco::ESTADO_SETORES - 1, &[0; 512])
}

/// Os registros do journal no disco, pelo cabeçalho em claro de cada um:
/// onde começa e quantos setores tem. Para no primeiro setor que não é
/// cabeçalho.
fn registros_no_disco(disco: &Path) -> Result<Vec<(u64, u64)>, String> {
    let estado = ler_o_estado(disco)?;
    let mut v = Vec::new();
    let mut setor = 0usize;
    while let Some(c) = estado.get(setor * 512..setor * 512 + 64) {
        if &c[..8] != b"DUKEDIA1" {
            break;
        }
        let n = u32::from_le_bytes([c[12], c[13], c[14], c[15]]) as usize;
        if n == 0 {
            break;
        }
        v.push((setor as u64, n as u64));
        setor += n;
    }
    Ok(v)
}

/// A escrita que não foi descarregada se perde: os setores do último
/// registro voltam a zero, como num disco que não chegou a gravá-los.
fn perder_o_ultimo_registro(disco: &Path) -> Result<(), String> {
    let (inicio, n) = *registros_no_disco(disco)?
        .last()
        .ok_or("o journal esta vazio")?;
    for s in inicio..inicio + n {
        escrever_setor_do_estado(disco, s, &[0; 512])?;
    }
    Ok(())
}

/// O número do ponto num aviso de queda, se a linha é um.
fn aviso_de_queda(linha: &str) -> Option<u8> {
    let resto = linha.split(r#"{"queda":"#).nth(1)?;
    resto.split('}').next()?.trim().parse().ok()
}

/// Lê linhas de `leitor` até o aviso da queda, ou até `espera` passar.
fn esperar_o_aviso(leitor: &mut BufReader<UnixStream>, espera: Duration) -> Result<u8, String> {
    use std::io::BufRead;
    let limite = std::time::Instant::now() + espera;
    let mut linha = String::new();
    while std::time::Instant::now() < limite {
        match leitor.read_line(&mut linha) {
            Ok(0) => return Err("o canal fechou antes do aviso da queda".into()),
            Ok(_) => {
                if let Some(p) = aviso_de_queda(&linha) {
                    return Ok(p);
                }
                linha.clear();
            }
            // Um tempo sem nada: o que veio pela metade continua em `linha`.
            Err(_) => {}
        }
    }
    Err(format!(
        "a maquina nao avisou a queda em {}s",
        espera.as_secs()
    ))
}

impl Ligada {
    /// Manda um pedido que o plano faz cair: espera o aviso, e corta a
    /// energia. Devolve o ponto em que caiu.
    fn pedir_ate_cair(mut self, metodo: &str, params: &str) -> Result<u8, String> {
        use std::io::Write;
        self.id += 1;
        let linha = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"{metodo}","params":{params}}}"#,
            self.id
        );
        self.escrita
            .write_all(linha.as_bytes())
            .and_then(|()| self.escrita.write_all(b"\n"))
            .map_err(|e| format!("falha ao mandar o pedido: {e}"))?;
        let caiu = esperar_o_aviso(&mut self.leitor, ESPERA_PELA_QUEDA);
        self.cortar_a_energia()?;
        caiu
    }

    /// Espera o aviso de uma queda que vem de outro lugar — um pedido numa
    /// porta —, e corta a energia.
    fn esperar_a_queda(mut self) -> Result<u8, String> {
        let caiu = esperar_o_aviso(&mut self.leitor, ESPERA_PELA_QUEDA);
        self.cortar_a_energia()?;
        caiu
    }
}

/// Liga a máquina com um plano que a faz cair no boot, antes de o canal
/// atender: lê a serial desde o começo até o aviso, e corta a energia.
fn subir_ate_cair(arch: Arquitetura, artefato: &Artefato) -> Result<u8, String> {
    let mut ambiente = Ambiente::ligar(arch, None)?;
    let (mut filho, socket) = lancar(arch, artefato, &ambiente)?;
    let limite = std::time::Instant::now() + ESPERA_PELO_BOOT;
    let conectado = loop {
        if let Ok(f) = UnixStream::connect(&socket) {
            break Ok(f);
        }
        if std::time::Instant::now() >= limite {
            break Err("o socket da serial nao abriu".to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let caiu = conectado.and_then(|f| {
        f.set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| e.to_string())?;
        esperar_o_aviso(&mut BufReader::new(f), ESPERA_PELO_BOOT)
    });
    let _ = filho.kill();
    let _ = filho.wait();
    if let Some((tpm, _)) = ambiente.tpm.as_mut() {
        let _ = tpm.kill();
        let _ = tpm.wait();
    }
    caiu
}

/// Uma operação administrativa que o plano faz cair.
fn administrar_ate_cair(
    mut maquina: Ligada,
    privada: &[u8; 32],
    comando: &str,
    params: &str,
) -> Result<u8, String> {
    let desafio = maquina.pedir("admin.challenge", "{}")?;
    let pedido = super::pedido_administrativo_de(privada, 0, &desafio, comando, params, params)?;
    maquina.pedir_ate_cair("admin.execute", &pedido)
}

/// Se o agente de chave `privada` entra, e é quem o registro diz.
fn agente_entra(arch: Arquitetura, privada: &[u8; 32], nome: &str) -> Result<bool, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    Ok(
        super::AgenteNaPorta::conectar_com(arch, 1, privada, &chaves.duke)
            .and_then(|mut a| a.pedir("agent.session", "{}"))
            .is_ok_and(|r| r.contains(&format!(r#""agent":"{nome}""#))),
    )
}

/// O caso de uma queda dentro de uma gravação: o ponto, se a escrita sem
/// descarga se perde, se a operação vale depois, e como se lê.
type Caso = (u8, bool, bool, &'static str);

/// As quedas dentro de uma gravação, em cada fronteira. Valer ou não valer
/// é o que o ponto decide; o que nunca pode acontecer é o boot seguinte
/// recusar, ou o próximo registro não gravar.
const QUEDAS_NA_GRAVACAO: [Caso; 5] = [
    (ponto::ANTES_DA_ESCRITA, false, false, "antes da escrita"),
    (
        ponto::DEPOIS_DA_ESCRITA,
        false,
        true,
        "depois da escrita, que chegou ao disco",
    ),
    (
        ponto::DEPOIS_DA_ESCRITA,
        true,
        false,
        "depois da escrita, que se perdeu sem a descarga",
    ),
    (
        ponto::DEPOIS_DA_DESCARGA,
        false,
        true,
        "depois da descarga, antes do contador",
    ),
    (
        ponto::DEPOIS_DO_CONTADOR,
        false,
        true,
        "depois do contador, antes da resposta",
    ),
];

/// Depois de uma queda: a persistência de pé, com `registros` registros e
/// a geração `geracao`.
fn conferir_depois_da_queda(
    p: &Persistencia,
    caso: &str,
    registros: u64,
    geracao: u64,
) -> Result<(), String> {
    if p.estado != "available" {
        return Err(format!(
            "{caso}: o boot seguinte deixou a persistencia {} ({})",
            p.estado, p.motivo
        ));
    }
    if p.registros != registros || p.geracao != geracao {
        return Err(format!(
            "{caso}: {} registros e geracao {}, e nao {registros} e {geracao}",
            p.registros, p.geracao
        ));
    }
    Ok(())
}

/// A queda em cada fronteira de uma operação de autoridade — o registro de
/// um agente —: antes de escrever, depois de escrever (a escrita chegou ao
/// disco, ou se perdeu por não ter sido descarregada), depois de
/// descarregar e antes do contador, depois do contador e antes da resposta.
/// Em todos, o boot seguinte sobe com a persistência de pé, a operação vale
/// exatamente quando o registro dela está no disco, e a próxima operação
/// grava e sobrevive a mais um boot.
fn as_quedas_numa_operacao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    for (i, (ponto, perder, vale, caso)) in QUEDAS_NA_GRAVACAO.into_iter().enumerate() {
        zerar_o_estado(arch)?;
        // A abertura e o boot são as gravações 1 e 2; a operação, a 3.
        plano_de_queda(&disco, ponto, 3)?;
        let privada = [0x70 + i as u8; 32];
        let nome = format!("fronteira-{i}");
        let m = Ligada::subir(arch, artefato, None)?;
        let caiu = administrar_ate_cair(
            m,
            &chaves.administrador,
            "agent.register",
            &registro_de_agente(&privada, &nome, "observador"),
        )?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        // Valendo: abertura, boot, a operação e o boot de agora.
        conferir_depois_da_queda(&p, caso, if vale { 4 } else { 3 }, u64::from(vale))?;
        if agente_entra(arch, &privada, &nome)? != vale {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: o agente {} depois da queda",
                if vale { "nao entrou" } else { "entrou" }
            ));
        }
        let r = administrar(
            &mut m,
            &chaves.administrador,
            "agent.register",
            &registro_de_agente(&[0x90 + i as u8; 32], &format!("depois-{i}"), "observador"),
        )?;
        m.cortar_a_energia()?;
        if !executou(&r) {
            return Err(format!(
                "{caso}: a operacao seguinte nao foi executada\n  {r}"
            ));
        }
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        m.cortar_a_energia()?;
        conferir_depois_da_queda(&p, caso, if vale { 6 } else { 5 }, u64::from(vale) + 1)?;
    }
    Ok(format!(
        "{} quedas: cada uma vale exatamente quando o registro esta no disco, e nenhuma deixa o estado recusado",
        QUEDAS_NA_GRAVACAO.len()
    ))
}

/// A mesma coisa para uma mensagem: a porta 1 manda à 3, e a energia cai
/// em cada fronteira da gravação. A mensagem existe depois exatamente
/// quando o registro dela está no disco — e uma que não foi respondida
/// pode existir, mas uma respondida com `durable: true` nunca some (essa
/// promessa é do cenário das mensagens que sobrevivem).
fn as_quedas_numa_mensagem(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    let para = super::chaves::nome_do_agente(3);
    for (i, (ponto, perder, vale, caso)) in QUEDAS_NA_GRAVACAO.into_iter().enumerate() {
        zerar_o_estado(arch)?;
        plano_de_queda(&disco, ponto, 3)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let corpo = format!("fronteira {i}");
        let pedido = format!(r#"{{"to":"{para}","body":"{corpo}","nonce":1}}"#);
        // O pedido na porta não volta: a máquina congela no meio dele. Ele
        // vai num fio à parte, e o aviso vem pela serial.
        let fio = std::thread::spawn(move || {
            super::AgenteNaPorta::conectar(arch, 1)
                .and_then(|mut a| a.pedir("message.send", &pedido))
        });
        let caiu = m.esperar_a_queda();
        let _ = fio.join();
        let caiu = caiu?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        // A mensagem não sobe a geração.
        conferir_depois_da_queda(&p, caso, if vale { 4 } else { 3 }, 0)?;
        let lida = super::AgenteNaPorta::conectar(arch, 3)
            .and_then(|mut a| a.pedir("message.read", "{}"))?;
        m.cortar_a_energia()?;
        if lida.contains(&corpo) != vale {
            return Err(format!(
                "{caso}: a mensagem {} depois da queda\n  {lida}",
                if vale { "sumiu" } else { "apareceu" }
            ));
        }
    }
    Ok(format!(
        "{} quedas: a mensagem existe exatamente quando o registro esta no disco",
        QUEDAS_NA_GRAVACAO.len()
    ))
}

/// A queda na criação da âncora, no primeiro boot de todos: com o contador
/// definido e nunca avançado, avançado e sem nascimento, com o nascimento e
/// sem a abertura, e dentro da gravação da abertura. Nenhuma deixa o
/// sistema recusado para sempre: o boot seguinte retoma a criação ou a
/// completa, e o journal começa normalmente.
fn as_quedas_na_criacao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let casos: [(u8, &str); 6] = [
        (
            ponto::ANCORA_DEFINIDA,
            "o contador definido e nunca avancado",
        ),
        (
            ponto::ANCORA_AVANCADA,
            "o contador avancado, sem nascimento",
        ),
        (
            ponto::NASCIMENTO_GUARDADO,
            "o nascimento guardado, sem abertura",
        ),
        (ponto::ANTES_DA_ESCRITA, "a abertura montada e nao escrita"),
        (
            ponto::DEPOIS_DA_DESCARGA,
            "a abertura descarregada, sem contador",
        ),
        (ponto::DEPOIS_DO_CONTADOR, "a abertura ancorada, sem o boot"),
    ];
    for (ponto, caso) in casos {
        zerar_o_estado(arch)?;
        plano_de_queda(&disco, ponto, 1)?;
        let caiu = subir_ate_cair(arch, artefato)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        conferir_depois_da_queda(&p, caso, 2, 0)?;
        let r = administrar(
            &mut m,
            &chaves.administrador,
            "agent.register",
            &registro_de_agente(
                &[0xA0 + ponto; 32],
                &format!("criacao-{ponto}"),
                "observador",
            ),
        )?;
        m.cortar_a_energia()?;
        if !executou(&r) {
            return Err(format!(
                "{caso}: a primeira operacao nao foi executada\n  {r}"
            ));
        }
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        m.cortar_a_energia()?;
        conferir_depois_da_queda(&p, caso, 4, 1)?;
    }
    Ok("6 quedas na criacao: cada uma retomada ou completada no boot seguinte".into())
}

/// A fotografia tirada na fronteira não volta: com a energia caída depois
/// da descarga e antes do contador, o disco tem um registro que o TPM ainda
/// não viu. O boot seguinte completa o avanço, a vida segue — e devolver ao
/// disco aquela fotografia é devolver um disco anterior ao que o TPM já
/// confirmou: recusado. O mesmo com a fotografia da criação interrompida,
/// com o journal ainda vazio: depois de o contador passar do nascimento,
/// ela é um disco apagado.
fn a_fotografia_da_fronteira_e_recusada(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut motivos = Vec::new();
    for na_criacao in [false, true] {
        zerar_o_estado(arch)?;
        if na_criacao {
            plano_de_queda(&disco, ponto::NASCIMENTO_GUARDADO, 1)?;
            subir_ate_cair(arch, artefato)?;
        } else {
            plano_de_queda(&disco, ponto::DEPOIS_DA_DESCARGA, 3)?;
            let m = Ligada::subir(arch, artefato, None)?;
            administrar_ate_cair(
                m,
                &chaves.administrador,
                "agent.register",
                &registro_de_agente(&[0xB0; 32], "fotografado", "observador"),
            )?;
        }
        sem_plano(&disco)?;
        let foto = ler_o_estado(&disco)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let r = administrar(
            &mut m,
            &chaves.administrador,
            "agent.register",
            &registro_de_agente(&[0xB1; 32], "depois-da-foto", "observador"),
        )?;
        m.cortar_a_energia()?;
        if !executou(&r) {
            return Err(format!("a operacao depois da fotografia falhou\n  {r}"));
        }
        escrever_no_estado(&disco, &foto)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        m.cortar_a_energia()?;
        if p.estado != "refused" {
            return Err(format!(
                "a fotografia {} voltou e foi aceita: {}",
                if na_criacao {
                    "da criacao"
                } else {
                    "da fronteira"
                },
                p.estado
            ));
        }
        motivos.push(p.motivo);
    }
    Ok(motivos.join("; "))
}
