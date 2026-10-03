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
        let socket = caminho_socket(arch);
        let ambiente = Ambiente::ligar(arch, relogio)?;
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
        self._ambiente
            .tpm
            .kill()
            .and_then(|()| self._ambiente.tpm.wait().map(|_| ()))
            .map_err(|e| format!("não foi possível desligar o swtpm: {e}"))
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
