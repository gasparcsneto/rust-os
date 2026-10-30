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

use super::disco_hostil::{Corte, DiscoHostil, Faixa, Gatilho, Sentido};
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
        Ligada::subir_esperando(arch, artefato, ambiente, ESPERA_PELO_BOOT)
    }

    /// [`Ligada::subir_com`], esperando o canal por `espera`: a máquina que
    /// reinicia sozinha antes de atender — a versão nova que entra em
    /// pânico, as tentativas que o iniciador conta — leva vários boots.
    pub(crate) fn subir_esperando(
        arch: Arquitetura,
        artefato: &Artefato,
        ambiente: Ambiente,
        espera: Duration,
    ) -> Result<Ligada, String> {
        let (mut filho, socket) = lancar(arch, artefato, &ambiente)?;
        let fluxo = match canal_de_pe(&socket, filho.id(), espera) {
            Ok(f) => f,
            Err(e) => {
                let estado = match filho.try_wait() {
                    Ok(Some(saida)) => format!("o emulador ja tinha saido ({saida})"),
                    _ => format!("o emulador, pelo QMP: {}", estado_do_emulador(arch)),
                };
                let _ = filho.kill();
                let _ = filho.wait();
                return Err(format!("{e}\n  {estado}"));
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

    /// Manda um pedido pela serial sem esperar a resposta: o número dele,
    /// para quem lê depois com [`Ligada::proxima_resposta`]. Os pedidos da
    /// serial são atendidos na ordem, um de cada vez.
    pub(crate) fn mandar(&mut self, metodo: &str, params: &str) -> Result<u32, String> {
        use std::io::Write;
        self.id += 1;
        let id = self.id;
        self.escrita
            .write_all(
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{metodo}\",\"params\":{params}}}\n"
                )
                .as_bytes(),
            )
            .and_then(|()| self.escrita.flush())
            .map_err(|e| format!("falha ao mandar `{metodo}` pela serial: {e}"))?;
        Ok(id)
    }

    /// A próxima resposta da serial, de qualquer pedido: o número dele e a
    /// linha inteira.
    pub(crate) fn proxima_resposta(&mut self) -> Result<(u32, String), String> {
        loop {
            let linha = super::ler_resposta(&mut self.leitor)?;
            if let Some(id) = super::campo_simples(&linha, "id").and_then(|v| v.parse().ok()) {
                return Ok((id, linha));
            }
        }
    }

    /// Quanto a leitura da serial espera por uma resposta: um pedido que
    /// espera o prazo do disco leva mais que os 15 s de sempre.
    pub(crate) fn esperar_respostas_por(&mut self, prazo: Duration) -> Result<(), String> {
        self.leitor
            .get_ref()
            .set_read_timeout(Some(prazo))
            .map_err(|e| format!("não foi possível configurar o timeout: {e}"))
    }

    /// Uma operação de quórum pela serial — ver
    /// [`super::quorum_pela_serial`] —: a resposta.
    pub(crate) fn quorum(
        &mut self,
        arch: Arquitetura,
        chaves: &super::chaves::Chaves,
        comando: &str,
        parametros: &str,
        quem: &[usize],
    ) -> Result<String, String> {
        super::quorum_pela_serial(
            arch,
            (&mut self.escrita, &mut self.leitor, &mut self.id),
            chaves,
            comando,
            parametros,
            quem,
        )
        .map(|(r, _)| r)
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
        self.cortar()
    }

    /// [`Ligada::cortar_a_energia`] sem largar a máquina: quem a tem fica com
    /// ela morta — a bancada do enlace a troca pela do boot seguinte, no
    /// lugar dela.
    pub(crate) fn cortar(&mut self) -> Result<(), String> {
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

/// O que o emulador vivo diz de si pelo QMP, para o boot que não atendeu:
/// se roda, onde está cada processador — e se parado num `hlt` —, e o que
/// o disco da máquina já leu e escreveu, com há quanto tempo está ocioso.
///
/// Na CI 359, um primeiro boot parou no iniciador, lendo o kernel do slot,
/// e a serial só dizia até onde o hóspede tinha escrito: não dizia se o
/// processador girava à espera do disco, se o disco tinha um pedido
/// pendurado, ou se o próprio emulador tinha parado. Um emulador que não
/// responde ao QMP é essa terceira resposta.
fn estado_do_emulador(arch: Arquitetura) -> String {
    let perguntar = || -> Result<String, String> {
        let (mut escrita, mut leitor) = super::qmp_abrir(&super::caminho_qmp(arch))?;
        let mut pedir = |pedido: &str| super::qmp_pedir(&mut escrita, &mut leitor, pedido);
        let status = pedir(r#"{"execute":"query-status"}"#)?;
        let monitor = |comando: &str| {
            format!(
                r#"{{"execute":"human-monitor-command","arguments":{{"command-line":"{comando}"}}}}"#
            )
        };
        let registros = pedir(&monitor("info registers -a"))?;
        let disco = pedir(&monitor("info blockstats"))?;
        let mut partes = vec![
            status
                .split("\"status\": \"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or(status.trim())
                .to_string(),
        ];
        // A saída do monitor humano vem dentro de uma string JSON, com as
        // quebras de linha escapadas.
        for linha in registros.split("\\r\\n").chain(disco.split("\\r\\n")) {
            let linha = linha.trim();
            if linha.starts_with("CPU#")
                || linha.starts_with("RIP=")
                || linha.starts_with("PC=")
                || linha.starts_with("disco0")
            {
                partes.push(linha.to_string());
            }
        }
        Ok(partes.join("; "))
    };
    perguntar()
        .unwrap_or_else(|e| format!("sem resposta ({e}): o emulador vivo e parado por dentro"))
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
    // A saída humana do x86 (COM1) não vai para o terminal: um terminal
    // cheio de log do firmware a cada boot esconderia o resultado. Na
    // bancada de persistência ela vai para a serial do cenário, que só
    // aparece quando ele reprova — ver [`serial_do_cenario`].
    let saida = serial_do_cenario()
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
        nome: "a auditoria sobrevive ao corte: o que estava gravado volta igual, e a cadeia continua",
        rodar: a_auditoria_sobrevive,
    },
    Cenario {
        nome: "as mensagens sobrevivem ao corte, nos mesmos ids, estados e versoes, e a epoca continua",
        rodar: as_mensagens_sobrevivem,
    },
    Cenario {
        nome: "as chaves de assinatura sobrevivem ao corte, e a destruida nao volta nem por uma fotografia antiga",
        rodar: as_chaves_sobrevivem,
    },
    Cenario {
        nome: "o disco tem a particao do armazem, no tipo e no lugar declarados, depois da de estado",
        rodar: a_particao_do_armazem,
    },
    Cenario {
        nome: "o armazem sobrevive ao corte: os mesmos nos, conteudos, donos e versoes, e uma versao dada nao volta",
        rodar: o_armazem_sobrevive,
    },
    Cenario {
        nome: "o volume do armazem devolvido a uma fotografia anterior e recusado, e a autoridade segue",
        rodar: o_volume_antigo_e_recusado,
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
        nome: "a auditoria do coletor nao gasta o contador; o boot e a operacao gastam um cada",
        rodar: a_auditoria_nao_gasta_o_contador,
    },
    Cenario {
        nome: "o rabo da auditoria volta com o disco, e o estado protegido nao",
        rodar: o_rabo_da_auditoria_nao_traz_estado,
    },
    Cenario {
        nome: "o TPM devolvido a um estado anterior e recusado, e o revogado nao volta",
        rodar: o_tpm_devolvido_e_recusado,
    },
    Cenario {
        nome: "o TPM tirado da maquina, com um disco antigo, e recusado, e o revogado nao volta",
        rodar: o_tpm_tirado_e_recusado,
    },
    Cenario {
        nome: "o mesmo TPM pela CRB e pelo TIS: a mesma EK, o mesmo journal",
        rodar: o_tpm_pela_crb_e_pelo_tis,
    },
    Cenario {
        nome: "o TPM limpo entre dois boots e recusado",
        rodar: o_tpm_limpo_e_recusado,
    },
    Cenario {
        nome: "as chaves seladas diante de outro TPM: a EK fixada recusa, e nada assina",
        rodar: as_chaves_seladas_diante_de_outro_tpm,
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
        nome: "o reinicio pelo comando: o pedido ja esta no journal, e a maquina volta sozinha",
        rodar: o_reinicio_pelo_comando,
    },
    Cenario {
        nome: "o desligamento pelo comando: a maquina para sozinha, e o pedido esta no journal no boot seguinte",
        rodar: o_desligamento_pelo_comando,
    },
    Cenario {
        nome: "o heap do kernel segue a memoria: 8 MiB na maquina de 128 MiB, 64 MiB na de 1 GiB",
        rodar: o_heap_segue_a_memoria,
    },
    Cenario {
        nome: "a rede fixa da imagem: o endereco do arquivo sem DHCP, e o arquivo ilegivel deixa a maquina sem endereco",
        rodar: a_rede_fixa_da_imagem,
    },
    Cenario {
        nome: "o disco do sistema no NVMe: o firmware boota dele, o armazem e a cadeia sobrevivem ao corte, e o desligamento avisa o controlador",
        rodar: o_disco_nvme_do_sistema,
    },
    Cenario {
        nome: "o signatario recusa assinar sobre uma geracao menor que a que ja viu",
        rodar: o_signatario_recusa_geracao_menor,
    },
    Cenario {
        nome: "a imagem de producao: so o material do operador, a marca dela, a identidade nascida no primeiro boot, e nada da bancada",
        rodar: a_imagem_de_producao,
    },
    Cenario {
        nome: "o disco que perde o que nao foi descarregado: o confirmado volta depois do corte, e o resto nao conta",
        rodar: o_disco_que_perde_o_cache,
    },
    Cenario {
        nome: "o erro de midia no journal: a persistencia se declara indisponivel, o disk.info conta, e a maquina segue",
        rodar: o_erro_de_midia_no_journal,
    },
    Cenario {
        nome: "o disco que para de responder: o driver o desliga no prazo, a persistencia fica indisponivel, e o boot seguinte volta",
        rodar: o_disco_que_para_de_responder,
    },
    Cenario {
        nome: "a placa Intel como a unica da maquina: DHCP, o agente por TCP, e o cabo que sai e volta",
        rodar: a_placa_intel,
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
        nome: "a queda em cada fronteira da criacao e da destruicao de uma chave: vale se o registro esta no disco",
        rodar: as_quedas_numa_chave,
    },
    Cenario {
        nome: "a queda entre os tres passos de uma morte de chave: o boot completa o avanco da geracao ou o confirma",
        rodar: as_quedas_na_geracao,
    },
    Cenario {
        nome: "a queda em cada passo da migracao das chaves antigas: seladas, e nenhuma semente fica no disco",
        rodar: as_quedas_na_migracao,
    },
    Cenario {
        nome: "a queda em cada fronteira de um registro so de auditoria: ele vale se esta no disco, e a cadeia continua",
        rodar: as_quedas_na_auditoria,
    },
    Cenario {
        nome: "a queda entre o lote no volume e a confirmacao: o lote nao vale, e o volume segue",
        rodar: a_queda_entre_o_volume_e_a_confirmacao,
    },
    Cenario {
        nome: "a queda em cada fronteira da confirmacao de um lote: ele vale inteiro exatamente quando o registro de estado esta no disco",
        rodar: as_quedas_num_lote,
    },
    Cenario {
        nome: "a compactacao do coletor sobrevive ao corte: o estado, a geracao e a auditoria continuam",
        rodar: a_compactacao_sobrevive,
    },
    Cenario {
        nome: "a queda em cada fronteira da compactacao: ela vale se o fecho esta no disco, e nada volta atras",
        rodar: as_quedas_na_compactacao,
    },
    Cenario {
        nome: "a fotografia de antes da compactacao, devolvida depois dela, e recusada",
        rodar: a_fotografia_de_antes_da_compactacao,
    },
    Cenario {
        nome: "a base sem fecho, sozinha no disco, e recusada: nunca vale pela metade",
        rodar: a_base_sem_fecho_sozinha,
    },
    Cenario {
        nome: "a regiao cheia falha fechada, e o boot seguinte compacta e recupera",
        rodar: a_regiao_cheia_falha_fechada,
    },
    Cenario {
        nome: "o coletor nao grava nada antes da abertura do journal",
        rodar: o_coletor_espera_a_abertura,
    },
    Cenario {
        nome: "a queda no boot entre a chave do TPM e o contador nao muda nada",
        rodar: a_queda_depois_da_chave,
    },
    Cenario {
        nome: "o contador que anda de fora e recusado, e o estado do disco nao volta como atual",
        rodar: o_contador_de_fora_e_recusado,
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
    let _ = SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("persistencia-{}.serial", arch.nome())));
    println!(
        "[xtask] persistencia: {} cenarios, cada um sobre um estado zerado ({})",
        CENARIOS.len() + CENARIOS_DE_QUEDA.len(),
        arch.nome()
    );
    let mut falhas = 0;
    // Um filtro opcional pelo nome, para rodar só alguns — o que uma
    // mutação dirigida precisa: pedaços do nome separados por `|`, e vale
    // o cenário que tiver qualquer um deles. Sem ele, todos.
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let mut rodar = |cenarios: &[Cenario], artefato: &Artefato| -> Result<(), String> {
        for cenario in cenarios.iter().filter(|c| escolhido(c)) {
            zerar_o_estado(arch)?;
            if let (None, Some(serial)) =
                (std::env::var_os("DUKE_BANCADA_LOG"), serial_do_cenario())
            {
                let _ = std::fs::write(serial, b"");
            }
            match (cenario.rodar)(arch, artefato) {
                Ok(detalhe) => println!("  [persistencia] ok  {}: {detalhe}", cenario.nome),
                Err(motivo) => {
                    falhas += 1;
                    println!("  [persistencia] FALHOU  {}: {motivo}", cenario.nome);
                    mostrar_o_fim_da_serial();
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

/// A serial da bancada de persistência, posta pelo [`persistencia`]: a
/// fumaça e a bancada de tempo, que sobem a máquina por aqui também, jogam
/// a saída humana fora, como sempre.
pub(crate) static SERIAL_DA_BANCADA: std::sync::OnceLock<std::path::PathBuf> =
    std::sync::OnceLock::new();

/// Onde vai a saída humana das máquinas do cenário que roda (a COM1 do
/// x86): cada boot acrescenta a sua, e o começo de cada cenário a esvazia.
/// Com `DUKE_BANCADA_LOG`, vai para esse arquivo, que acumula todos.
///
/// Ela existe para o cenário que reprova: na CI 335, o primeiro boot de um
/// cenário não respondeu em 90 s, e nada dizia onde a máquina parou — o
/// firmware, o iniciador, ou que passo do kernel.
pub(crate) fn serial_do_cenario() -> Option<std::path::PathBuf> {
    std::env::var_os("DUKE_BANCADA_LOG")
        .map(std::path::PathBuf::from)
        .or_else(|| SERIAL_DA_BANCADA.get().cloned())
}

/// O fim da serial do cenário que reprovou, na saída: as últimas linhas,
/// sem os controles de terminal do firmware.
pub(crate) fn mostrar_o_fim_da_serial() {
    const LINHAS: usize = 40;
    let Some(caminho) = serial_do_cenario() else {
        return;
    };
    let Ok(bytes) = std::fs::read(&caminho) else {
        return;
    };
    let texto: String = String::from_utf8_lossy(&bytes)
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    let linhas: Vec<&str> = texto.lines().collect();
    println!(
        "  [persistencia]   as ultimas {} linhas da serial ({}):",
        LINHAS.min(linhas.len()),
        caminho.display()
    );
    for linha in &linhas[linhas.len().saturating_sub(LINHAS)..] {
        println!("  [serial] {}", linha.trim_end());
    }
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

impl Ligada {
    /// Espera o QEMU sair sozinho — a máquina se desligou —, até `prazo`.
    pub(crate) fn esperar_sair(
        &mut self,
        prazo: Duration,
    ) -> Result<std::process::ExitStatus, String> {
        let limite = std::time::Instant::now() + prazo;
        loop {
            match self.filho.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if std::time::Instant::now() < limite => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(None) => return Err(format!("a maquina nao se desligou em {prazo:?}")),
                Err(e) => return Err(format!("nao foi possivel esperar o QEMU: {e}")),
            }
        }
    }

    /// Espera o boot seguinte ao de `boots` responder — a máquina reiniciou
    /// sozinha, e o canal da serial é o mesmo —, até [`ESPERA_PELO_BOOT`].
    /// Os pedidos feitos no meio do reinício se perdem, e são feitos de
    /// novo.
    pub(crate) fn esperar_o_boot_seguinte(&mut self, boots: u64) -> Result<Persistencia, String> {
        self.esperar_o_boot_ate(boots, ESPERA_PELO_BOOT)
    }

    /// [`Ligada::esperar_o_boot_seguinte`], até `espera`: a atualização
    /// atravessa vários boots antes de um atender.
    pub(crate) fn esperar_o_boot_ate(
        &mut self,
        boots: u64,
        espera: Duration,
    ) -> Result<Persistencia, String> {
        let limite = std::time::Instant::now() + espera;
        let mut ultimo = String::from("nenhuma resposta");
        while std::time::Instant::now() < limite {
            if let Ok(Some(status)) = self.filho.try_wait() {
                return Err(format!("a maquina saiu em vez de reiniciar: {status}"));
            }
            match persistencia_de(self) {
                Ok(p) if p.boots > boots => return Ok(p),
                Ok(p) => ultimo = format!("ainda o boot {}", p.boots),
                Err(e) => ultimo = e,
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(format!("o boot seguinte nao respondeu: {ultimo}"))
    }
}

/// O registro do pedido de energia `registro`, na cauda da auditoria: o
/// método, o recurso — o nome da ação — e o desfecho.
fn pedido_de_energia_na_cauda(
    cauda: &[Rastro],
    registro: u64,
    metodo: &str,
    acao: &str,
) -> Result<(), String> {
    match cauda.iter().find(|r| r.seq == registro) {
        Some(r) if r.metodo == metodo && r.recurso == acao && r.codigo == "ALLOW" => Ok(()),
        Some(r) => Err(format!("o registro {registro} nao e o pedido: {r:?}")),
        None => Err(format!(
            "o registro {registro} do pedido nao voltou do journal; a cauda vai de {:?} a {:?}",
            cauda.first().map(|r| r.seq),
            cauda.last().map(|r| r.seq)
        )),
    }
}

/// O reinício pedido pelo comando, numa máquina de produção: a resposta
/// diz o registro do pedido, e ele já está no journal quando ela sai; a
/// máquina reinicia sozinha — o QEMU não sai —, e no boot seguinte o
/// registro está lá, a persistência disponível e a cadeia inteira.
fn o_reinicio_pelo_comando(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let mut m = Ligada::subir(arch, artefato, None)?;
    let antes = persistencia_de(&mut m)?;
    if antes.estado != "available" {
        return Err(format!(
            "a persistencia nao subiu: {} ({})",
            antes.estado, antes.motivo
        ));
    }
    let r = m.pedir("system.reboot", "{}")?;
    let registro: u64 = texto_do_resultado(&r, "record")
        .or_else(|| super::campo_simples(&r, "record"))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            format!(
                "o reinicio nao foi aceito
  {r}"
            )
        })?;
    if !r.contains(r#""state":"rebooting""#) {
        return Err(format!(
            "a resposta nao diz que reinicia
  {r}"
        ));
    }
    let depois = m.esperar_o_boot_seguinte(antes.boots)?;
    if depois.estado != "available" {
        return Err(format!(
            "o boot depois do reinicio nao abriu a persistencia: {} ({})",
            depois.estado, depois.motivo
        ));
    }
    if depois.auditoria_gravada < registro {
        return Err(format!(
            "o journal do boot seguinte vai ate {}, antes do pedido {registro}",
            depois.auditoria_gravada
        ));
    }
    let cauda = cauda_da_auditoria(&mut m)?;
    pedido_de_energia_na_cauda(&cauda, registro, "system.reboot", "reboot")?;
    auditoria_verifica(&mut m)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "boot {} -> {}; o pedido {registro} voltou do journal; a cadeia se verifica",
        antes.boots, depois.boots
    ))
}

/// O desligamento pedido pelo comando: a máquina para sozinha — o QEMU sai,
/// com sucesso —, e no boot seguinte o registro do pedido está no journal,
/// com a persistência disponível.
fn o_desligamento_pelo_comando(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let mut m = Ligada::subir(arch, artefato, None)?;
    let antes = persistencia_de(&mut m)?;
    let r = m.pedir("system.poweroff", "{}")?;
    let registro: u64 = texto_do_resultado(&r, "record")
        .or_else(|| super::campo_simples(&r, "record"))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            format!(
                "o desligamento nao foi aceito
  {r}"
            )
        })?;
    let status = m.esperar_sair(Duration::from_secs(60))?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = Ligada::subir(arch, artefato, None)?;
    let depois = persistencia_de(&mut m)?;
    if depois.estado != "available" || depois.boots <= antes.boots {
        return Err(format!(
            "o boot seguinte: {} ({}), boot {} depois de {}",
            depois.estado, depois.motivo, depois.boots, antes.boots
        ));
    }
    let cauda = cauda_da_auditoria(&mut m)?;
    pedido_de_energia_na_cauda(&cauda, registro, "system.poweroff", "poweroff")?;
    auditoria_verifica(&mut m)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o QEMU saiu sozinho ({status}); o pedido {registro} voltou do journal no boot {}",
        depois.boots
    ))
}

/// O total do heap do kernel, pelo `heap.stats`.
fn heap_do_kernel(maquina: &mut Ligada) -> Result<u64, String> {
    let r = maquina.pedir("heap.stats", "{}")?;
    texto_do_resultado(&r, "total_bytes")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("o heap.stats nao diz o total\n  {r}"))
}

/// O heap do kernel segue a memória da máquina: a de 128 MiB — a de toda a
/// bancada — fica no piso de 8 MiB, e a de 1 GiB tem 64 MiB, um dezesseis
/// avos dela; e a máquina maior atende como a outra.
fn o_heap_segue_a_memoria(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const MIB: u64 = 1024 * 1024;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let pequena = heap_do_kernel(&mut m)?;
    m.cortar_a_energia()?;
    if pequena != 8 * MIB {
        return Err(format!("a maquina de 128 MiB tem {pequena} bytes de heap"));
    }
    let ambiente = Ambiente::ligar(arch, None)?.com_memoria(1024);
    let mut m = Ligada::subir_com(arch, artefato, ambiente)?;
    let grande = heap_do_kernel(&mut m)?;
    let r = m.pedir("agent.ping", "{}")?;
    m.cortar_a_energia()?;
    // Um dezesseis avos da memória utilizável: um pouco menos que 64 MiB,
    // o que o firmware e o iniciador guardam para si.
    if !(48 * MIB..=64 * MIB).contains(&grande) {
        return Err(format!("a maquina de 1 GiB tem {grande} bytes de heap"));
    }
    if !r.contains(r#""result""#) {
        return Err(format!("a maquina de 1 GiB nao respondeu\n  {r}"));
    }
    Ok(format!(
        "{} MiB na de 128 MiB, {} MiB na de 1 GiB",
        pequena / MIB,
        grande / MIB
    ))
}

/// O disco do sistema num controlador NVMe, de ponta a ponta, num kernel
/// de produção — o disco de uma máquina de verdade: no x86 o firmware boota
/// dele (não há outro disco na máquina); o `disk.info` diz o driver; a
/// persistência abre; o que se grava no armazém e se confirma sobrevive a
/// um corte de energia, com a cadeia da auditoria inteira; e o
/// desligamento pelo comando — a descarga e o aviso ao controlador — deixa
/// o pedido no journal do boot seguinte, e o arquivo lá.
fn o_disco_nvme_do_sistema(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const A: &str = "/armazem/sistema/nvme.txt";
    const CONTEUDO: &str = "gravado no NVMe";
    let nvme = || Ambiente::ligar(arch, None).map(Ambiente::com_nvme);
    let mut m = Ligada::subir_com(arch, artefato, nvme()?)?;
    let r = m.pedir("disk.info", "{}")?;
    if !r.contains(r#""driver":"nvme""#) || !r.contains(r#""durable":true"#) {
        return Err(format!("o disk.info nao diz o NVMe duravel\n  {r}"));
    }
    let antes = persistencia_de(&mut m)?;
    if antes.estado != "available" {
        return Err(format!(
            "a persistencia nao abriu no NVMe: {} ({})",
            antes.estado, antes.motivo
        ));
    }
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/sistema"}"#)?;
    no_armazem(
        &mut m,
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"{CONTEUDO}","expect_version":0}}"#),
    )?;
    let versao = versao_no_armazem(&mut m, A)?;
    let r = m.pedir("fs.verify", r#"{"path":"/armazem"}"#)?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!("o armazem no NVMe nao conferiu\n  {r}"));
    }
    m.cortar_a_energia()?;

    let mut m = Ligada::subir_com(arch, artefato, nvme()?)?;
    let depois = persistencia_de(&mut m)?;
    if depois.estado != "available" || depois.boots <= antes.boots {
        return Err(format!(
            "depois do corte: {} ({}), boot {} depois de {}",
            depois.estado, depois.motivo, depois.boots, antes.boots
        ));
    }
    let lido = m.pedir("fs.read", &format!(r#"{{"path":"{A}"}}"#))?;
    if !lido.contains(CONTEUDO) || versao_no_armazem(&mut m, A)? != versao {
        return Err(format!(
            "o arquivo nao sobreviveu ao corte no NVMe\n  {lido}"
        ));
    }
    auditoria_verifica(&mut m)?;
    let r = m.pedir("system.poweroff", "{}")?;
    let registro: u64 = texto_do_resultado(&r, "record")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("o desligamento nao foi aceito\n  {r}"))?;
    let status = m.esperar_sair(Duration::from_secs(60))?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);

    let mut m = Ligada::subir_com(arch, artefato, nvme()?)?;
    let terceiro = persistencia_de(&mut m)?;
    if terceiro.estado != "available" || terceiro.boots <= depois.boots {
        return Err(format!(
            "depois do desligamento: {} ({}), boot {} depois de {}",
            terceiro.estado, terceiro.motivo, terceiro.boots, depois.boots
        ));
    }
    let cauda = cauda_da_auditoria(&mut m)?;
    pedido_de_energia_na_cauda(&cauda, registro, "system.poweroff", "poweroff")?;
    auditoria_verifica(&mut m)?;
    let lido = m.pedir("fs.read", &format!(r#"{{"path":"{A}"}}"#))?;
    m.cortar_a_energia()?;
    if !lido.contains(CONTEUDO) {
        return Err(format!(
            "o arquivo nao estava la depois do desligamento\n  {lido}"
        ));
    }
    Ok(format!(
        "boots {} -> {} -> {}; o arquivo e a cadeia sobreviveram ao corte; o desligamento pelo comando deixou o pedido {registro} no journal",
        antes.boots, depois.boots, terceiro.boots
    ))
}

/// A imagem de produção, montada pelo provisionamento do material de um
/// operador — a política de `docs/exemplos/producao`, a rede do emulador
/// escrita, e chaves geradas aqui como `cargo xtask chave` as gera. No
/// primeiro boot a identidade do Duke nasce, selada no TPM, e a
/// persistência abre; o `system.info` diz produção, com o nome e o id da
/// marca, e a pública da identidade nascida; só os agentes, os
/// administradores e a pessoa do operador existem; o agente dele entra
/// fixando a pública que a máquina mostrou, e o da bancada é recusado; a prova de um administrador dele
/// registra um agente, e a do administrador da bancada não; nada da
/// bancada está na raiz — nem a âncora TLS dela, nem a PocketIC, nem os
/// arquivos da suíte —; a rede é a do arquivo; e a serial é `observador`:
/// lê o estado, e não a auditoria.
fn a_imagem_de_producao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    use super::producao;
    let dir = super::raiz_do_estado().join(format!("operador-{}", arch.nome()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let escrever = |nome: &str, conteudo: &str| {
        std::fs::write(dir.join(nome), conteudo).map_err(|e| format!("{nome}: {e}"))
    };
    let exemplo = super::raiz_do_projeto().join("docs/exemplos/producao/politica");
    escrever(
        "politica",
        &std::fs::read_to_string(&exemplo).map_err(|e| format!("{}: {e}", exemplo.display()))?,
    )?;
    escrever("nome", "bancada-producao\n")?;
    escrever(
        "rede",
        "endereco 10.0.2.15/24\nroteador 10.0.2.2\ndns 10.0.2.3\n",
    )?;
    let (operador, linha_do_operador, _) =
        producao::chave_nova("agente", "operador-1", Some("operador"))?;
    let (sistema, linha_do_sistema, _) =
        producao::chave_nova("agente", "sistema-1", Some("sistema"))?;
    escrever("agentes", &format!("{linha_do_operador}{linha_do_sistema}"))?;
    let mut administradores = String::new();
    let mut credenciais = Vec::new();
    for nome in ["adm-a", "adm-b", "adm-c"] {
        let (privada, linha, _) =
            producao::chave_nova("administrador", nome, Some("administrador"))?;
        administradores.push_str(&linha);
        credenciais.push(privada);
    }
    escrever("administradores", &administradores)?;
    escrever("senha-ana", "uma senha comprida de teste\n")?;
    escrever("pessoas", "ana operador senha-ana\n")?;
    let (publicador, linha_do_publicador, _) =
        producao::chave_nova("atualizacao", "publicador-1", None)?;
    escrever("atualizacao", &linha_do_publicador)?;

    let op = producao::ler_o_operador(&dir)?;
    let politica = producao::conferir(&op)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&super::aleatorios()?[..16]);
    let arquivos = producao::arquivos_da_raiz(&op, &politica, id)?;
    if arquivos
        .iter()
        .any(|(nome, _)| nome == "etc/duke/privado/chave")
    {
        return Err("a raiz de producao leva uma chave do Duke".into());
    }
    // A imagem do slot, como o `publicar` a monta: o kernel de produção
    // desta bancada — o do slot A do disco de testes —, o pacote do
    // produto, e o manifesto assinado pela chave de atualização do
    // operador. Conferida pelo registro dele, como o `provisionar` faz.
    let _ = artefato;
    let kernel = super::slots::kernel_da_imagem(&super::slots::imagem_do_slot(
        &disco_de_testes()?,
        atualizacao::Slot::A,
    )?)?;
    let pacote = producao::pacote_do_produto(arch)?;
    let slot = super::slots::imagem(
        &super::slots::Pedido {
            arch,
            kernel: &kernel,
            pacote: &pacote,
            versao: "bancada-producao",
            geracao: 1,
            estado: (
                super::slots::FORMATO_DO_ESTADO,
                super::slots::FORMATO_DO_ESTADO,
            ),
        },
        &producao::chave_de_atualizacao_de_texto(&publicador)?,
    )?;
    super::slots::conferir_imagem(&slot.bytes, &op.atualizacao, arch)?;
    let disco = super::raiz_do_estado().join(format!("producao-{}.img", arch.nome()));
    producao::montar_o_disco(arch, false, &disco, &arquivos, &slot.bytes)?;
    // Pelo firmware, nas duas arquiteturas: o iniciador da ESP, o slot A,
    // o pacote montado por cima da raiz — o caminho de uma máquina de
    // verdade.
    let da_imagem = Artefato::Disco(disco.clone());
    let mut m = Ligada::subir_com(
        arch,
        &da_imagem,
        Ambiente::ligar(arch, None)?.com_disco(disco.clone()),
    )?;
    let resultado = (|| -> Result<String, String> {
        let r = m.pedir("system.info", "{}")?;
        let id = sigilo::hex_de(&id);
        if !r.contains(&format!(
            r#""image":{{"kind":"production","name":"bancada-producao","id":"{id}"}}"#
        )) {
            return Err(format!("o system.info nao diz a imagem de producao\n  {r}"));
        }
        // A identidade nasceu neste boot, e a máquina mostra a pública: a
        // que o operador lê no console e dá aos agentes dele.
        let publica = identidade_com_origem(&mut m, "born")?;
        let p = persistencia_de(&mut m)?;
        if p.estado != "available" {
            return Err(format!(
                "a persistencia nao abriu no primeiro boot da imagem de producao: {} ({})",
                p.estado, p.motivo
            ));
        }
        let registro = m.pedir("agent.registry", "{}")?;
        if !registro.contains(&format!(r#""duke_key":"{}""#, sigilo::hex(&publica))) {
            return Err(format!(
                "o agent.registry nao diz a identidade que o system.info mostrou\n  {registro}"
            ));
        }
        if !registro.contains("operador-1")
            || !registro.contains("sistema-1")
            || registro.contains("agente-1")
        {
            return Err(format!(
                "os agentes da imagem nao sao os do operador\n  {registro}"
            ));
        }
        let pessoas = m.pedir("person.registry", "{}")?;
        if !pessoas.contains(r#""name":"ana""#) || pessoas.contains(r#""name":"dev""#) {
            return Err(format!(
                "as pessoas da imagem nao sao as do operador\n  {pessoas}"
            ));
        }
        let rede = m.pedir("net.info", "{}")?;
        if texto_do_resultado(&rede, "mode").as_deref() != Some("static") {
            return Err(format!("a rede nao e a do arquivo do operador\n  {rede}"));
        }
        // A serial do operador e `observador`: le o estado, e nao a
        // auditoria.
        let r = m.pedir("audit.tail", "{}")?;
        if !r.contains("DENY") {
            return Err(format!("a serial de observador leu a auditoria\n  {r}"));
        }

        // O agente do operador entra, fixando a pública que a máquina
        // mostrou; o da bancada, não.
        let chave_do_operador = producao::chave_de_agente_de_texto(&operador)?;
        let mut agente =
            super::AgenteNaPorta::conectar_com_publica(arch, 1, &chave_do_operador, &publica)?;
        let s = agente.pedir("agent.session", "{}")?;
        if !s.contains(r#""agent":"operador-1""#) {
            return Err(format!("o agente do operador entrou com outro nome\n  {s}"));
        }
        let bancada = super::chaves::Chaves::garantir()?;
        match super::AgenteNaPorta::conectar_com_publica(arch, 2, &bancada.do_agente(4), &publica) {
            Err(e) if e.contains("recusado") => {}
            Err(e) => return Err(format!("o agente da bancada nao foi recusado: {e}")),
            Ok(_) => return Err("o agente da bancada entrou na imagem de producao".into()),
        }

        // Nada da bancada na raiz, lido pelo agente `sistema` do operador —
        // a serial, `observador`, nem lê arquivo: uma recusa dela não
        // provaria ausência nenhuma.
        let chave_do_sistema = producao::chave_de_agente_de_texto(&sistema)?;
        let mut sis =
            super::AgenteNaPorta::conectar_com_publica(arch, 3, &chave_do_sistema, &publica)?;
        let raiz = sis.pedir("fs.list", r#"{"path":"/"}"#)?;
        if !raiz.contains("etc") || raiz.contains("saudacao.txt") || raiz.contains("enche-1.txt") {
            return Err(format!(
                "a raiz da imagem de producao tem os arquivos da suite\n  {raiz}"
            ));
        }
        let programas = sis.pedir(
            "fs.list",
            &format!(r#"{{"path":"/programas/{}"}}"#, arch.nome()),
        )?;
        for programa in producao::PROGRAMAS_DO_PRODUTO {
            if !programas.contains(&format!(r#""{programa}""#)) {
                return Err(format!(
                    "o programa `{programa}` nao esta na imagem de producao\n  {programas}"
                ));
            }
        }
        if programas.contains(r#""carga""#) || programas.contains(r#""cifrado""#) {
            return Err(format!(
                "a imagem de producao leva programas da suite\n  {programas}"
            ));
        }
        // A pessoa do operador entra pelo Terminal, pelo teclado da
        // máquina: a senha do arquivo dela, conferida pelo Argon2id do
        // kernel contra o verificador que o provisionamento gravou. Antes,
        // um comando sem login, para saber que o Terminal já lê o teclado.
        let mut mon = UnixStream::connect(super::caminho_monitor(arch))
            .map_err(|e| format!("login: o monitor nao aceitou conexao: {e}"))?;
        super::digitar_pelo_monitor(&mut mon, "\nagent.ping\n", "login")?;
        let limite = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let cauda = sis.pedir("audit.tail", r#"{"count":32}"#)?;
            if cauda.contains(r#""method":"agent.ping""#)
                && cauda.contains("DENY_NOT_AUTHENTICATED")
                && cauda.contains(r#""resource":"terminal:"#)
            {
                break;
            }
            if std::time::Instant::now() >= limite {
                return Err(format!(
                    "o Terminal da imagem de producao nao recusou o comando sem login\n  {cauda}"
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        super::digitar_pelo_monitor(
            &mut mon,
            "login\nana\numa senha comprida de teste\n",
            "login",
        )?;
        let limite = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let registro = m.pedir("person.registry", "{}")?;
            if super::consoles_da_pessoa(&registro, "ana")
                .iter()
                .any(|c| c.starts_with("terminal:"))
            {
                break;
            }
            if std::time::Instant::now() >= limite {
                return Err(format!(
                    "a pessoa do operador nao entrou no Terminal com a senha dela\n  {registro}"
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let ancora = sis.pedir("fs.read", r#"{"path":"/dados/tls/bancada.pem"}"#)?;
        if !ancora.contains("nao encontrado") {
            return Err(format!(
                "a ancora TLS da bancada esta na imagem de producao\n  {ancora}"
            ));
        }
        let publicas = sis.pedir("fs.read", r#"{"path":"/dados/tls/publicas.pem"}"#)?;
        if !publicas.contains("BEGIN CERTIFICATE") {
            return Err(format!(
                "as ancoras publicas nao estao na imagem de producao\n  {publicas}"
            ));
        }
        let redes = sis.pedir("fs.read", r#"{"path":"/dados/icp/redes"}"#)?;
        if !redes.contains("rede mainnet") || redes.contains("icp.duke") {
            return Err(format!(
                "as redes do IC da imagem nao sao so a principal\n  {redes}"
            ));
        }
        drop(sis);

        // A prova de um administrador do operador registra um agente; a do
        // administrador da bancada, não.
        let sessao: u8 = super::campo_simples(&s, "session")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("a sessao do agente nao diz o numero\n  {s}"))?;
        let novo = super::aleatorios()?;
        let params = registro_de_agente(&novo, "registrado-1", "observador");
        let (credencial, _) = producao::chave_de_administrador_de_texto(&credenciais[0])?;
        let desafio = agente.pedir("admin.challenge", "{}")?;
        let pedido = super::pedido_administrativo_de(
            &credencial,
            sessao,
            &desafio,
            "agent.register",
            &params,
            &params,
        )?;
        let r = agente.pedir("admin.execute", &pedido)?;
        if !executou(&r) {
            return Err(format!(
                "a prova do administrador do operador nao valeu\n  {r}"
            ));
        }
        let desafio = agente.pedir("admin.challenge", "{}")?;
        let params = registro_de_agente(&super::aleatorios()?, "intruso-1", "sistema");
        let pedido = super::pedido_administrativo_de(
            &bancada.administrador,
            sessao,
            &desafio,
            "agent.register",
            &params,
            &params,
        )?;
        let r = agente.pedir("admin.execute", &pedido)?;
        if executou(&r) {
            return Err(format!(
                "a prova do administrador da bancada valeu na imagem de producao\n  {r}"
            ));
        }
        Ok(format!(
            "imagem `bancada-producao` ({id}): a identidade {} nascida no primeiro boot, persistencia {}, agentes e pessoa do operador, a pessoa entra no Terminal pelo teclado, o agente e o administrador da bancada recusados, a raiz sem nada da bancada, a rede do arquivo",
            &sigilo::hex(&publica)[..8],
            p.estado
        ))
    })();
    m.cortar_a_energia()?;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&disco);
    resultado
}

/// O socket do disco hostil de `arch`, em `target/`.
pub(crate) fn socket_do_disco_hostil(arch: Arquitetura) -> std::path::PathBuf {
    super::raiz_do_projeto()
        .join("target")
        .join(format!("disco-hostil-{}.sock", arch.nome()))
}

/// O disco de testes atrás do servidor do disco hostil, com o corte
/// `corte` — ver [`super::disco_hostil`].
fn disco_hostil(arch: Arquitetura, corte: Corte) -> Result<DiscoHostil, String> {
    DiscoHostil::servir(&disco_de_testes()?, &socket_do_disco_hostil(arch), corte)
}

/// Liga a máquina sobre o disco hostil. O boot que não atende diz também o
/// que o servidor viu: as conexões, e as leituras e escritas atendidas.
fn ligar_no_disco_hostil(
    arch: Arquitetura,
    artefato: &Artefato,
    disco: &DiscoHostil,
) -> Result<Ligada, String> {
    let ambiente = Ambiente::ligar(arch, None)?.com_disco_hostil(disco.socket());
    Ligada::subir_com(arch, artefato, ambiente)
        .map_err(|e| format!("{e}\n  o disco hostil: {:?}", disco.contas()))
}

/// Se a resposta de um comando do armazém é a de uma gravação confirmada —
/// a mesma regra do [`no_armazem`]: a recusa também vem em `result`.
fn confirmada(r: &str) -> bool {
    r.contains(r#""ok":true"#) && r.contains(r#""durable":true"#)
}

/// A faixa da partição de estado: o journal.
fn faixa_do_journal() -> Faixa {
    Faixa {
        primeiro: disco::ESTADO_EM,
        quantos: disco::ESTADO_SETORES,
    }
}

/// O disco que perde o que não foi descarregado: o servidor guarda cada
/// escrita num cache volátil até a descarga, e o corte o perde — todo, ou
/// uma parte sorteada, como um SSD sem capacitor. Doze gravações no
/// armazém pedidas de uma vez pela serial, e a energia acaba no meio
/// delas, num ponto exato: na `n`-ésima escrita, com ela no cache, ou na
/// `n`-ésima descarga, antes de gravar — o próprio servidor corta, ver
/// [`Gatilho`] —, e a máquina cortada não tem o disco de volta: a conexão
/// nova que o emulador abre sozinho é recusada até o cenário matá-lo e
/// religar. No boot seguinte a persistência abre — nada que foi
/// confirmado se perdeu, senão o journal ficaria atrás da âncora e seria
/// recusado —, cada gravação confirmada está lá, cada uma sem confirmação
/// está inteira ou não está, e a auditoria e o armazém conferem. Quatro
/// rodadas: o corte que perde tudo, e três que guardam partes diferentes.
///
/// É o que o arquivo sozinho não pegava: o que o emulador escreveu está no
/// cache do hospedeiro e sobrevive à morte dele — uma gravação confirmada
/// antes da descarga passaria do mesmo jeito.
fn o_disco_que_perde_o_cache(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const GRAVACOES: u32 = 12;
    let mut relato = Vec::new();
    for (corte, gatilho) in [
        (Corte::PerdeTudo, Gatilho::Escrita(4)),
        (Corte::GuardaParte(0x5eed_0001), Gatilho::Descarga(3)),
        (Corte::GuardaParte(0x5eed_0002), Gatilho::Escrita(9)),
        (Corte::GuardaParte(0x5eed_0003), Gatilho::Descarga(7)),
    ] {
        zerar_o_estado(arch)?;
        let disco = disco_hostil(arch, corte)?;
        let mut m = ligar_no_disco_hostil(arch, artefato, &disco)?;
        let antes = persistencia_de(&mut m)?;
        if antes.estado != "available" {
            return Err(format!(
                "{corte:?}: a persistencia nao abriu no disco hostil: {} ({})",
                antes.estado, antes.motivo
            ));
        }
        no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/hostil"}"#)?;
        disco.cortar_em(gatilho);
        let mut pedidos = Vec::new();
        for i in 0..GRAVACOES {
            let id = m.mandar(
                "fs.write",
                &format!(
                    r#"{{"path":"/armazem/hostil/{i}.txt","content":"confirmado {i}","expect_version":0}}"#
                ),
            )?;
            pedidos.push((id, i));
        }
        // As respostas, até o corte e o silêncio depois dele: sem o disco,
        // o que estava em curso falha ou fica sem resposta.
        m.esperar_respostas_por(Duration::from_secs(2))?;
        let limite = std::time::Instant::now() + Duration::from_secs(180);
        let mut confirmadas = Vec::new();
        loop {
            match m.proxima_resposta() {
                Ok((id, r)) => {
                    if let Some(&(_, i)) = pedidos.iter().find(|(p, _)| *p == id)
                        && confirmada(&r)
                    {
                        confirmadas.push(i);
                    }
                }
                Err(_) if disco.contas().cortes > 0 => break,
                Err(_) if std::time::Instant::now() > limite => {
                    return Err(format!(
                        "{corte:?}: o gatilho {gatilho:?} nao disparou: {:?}",
                        disco.contas()
                    ));
                }
                Err(_) => {}
            }
        }
        m.cortar_a_energia()?;
        let no_corte = disco.esperar_o_fim_da_conexao(1)?;
        if no_corte.cortes != 1 || no_corte.no_corte == 0 {
            return Err(format!(
                "{corte:?}: o corte em {gatilho:?} nao pegou nada no cache: {no_corte:?}"
            ));
        }
        if no_corte.conexoes != 1 {
            return Err(format!(
                "{corte:?}: depois do corte em {gatilho:?}, a maquina cortada teve o disco de volta: {no_corte:?}"
            ));
        }
        disco.religar();

        let mut m = ligar_no_disco_hostil(arch, artefato, &disco)?;
        let depois = persistencia_de(&mut m)?;
        if depois.estado != "available" || depois.boots <= antes.boots {
            return Err(format!(
                "{corte:?}, {gatilho:?}: depois do corte, a persistencia ficou {} ({}), boot {} depois de {}: algo confirmado nao estava descarregado",
                depois.estado, depois.motivo, depois.boots, antes.boots
            ));
        }
        let mut voltaram = 0;
        for i in 0..GRAVACOES {
            let lido = m.pedir(
                "fs.read",
                &format!(r#"{{"path":"/armazem/hostil/{i}.txt"}}"#),
            )?;
            let inteiro = lido.contains(&format!("confirmado {i}"));
            if confirmadas.contains(&i) && !inteiro {
                return Err(format!(
                    "{corte:?}, {gatilho:?}: a gravacao {i}, confirmada antes do corte, nao voltou\n  {lido}"
                ));
            }
            if !inteiro && !lido.contains(r#""error":"nao encontrado""#) {
                return Err(format!(
                    "{corte:?}, {gatilho:?}: a gravacao {i}, sem confirmacao, voltou diferente\n  {lido}"
                ));
            }
            voltaram += u32::from(inteiro);
        }
        auditoria_verifica(&mut m)?;
        let r = m.pedir("fs.verify", r#"{"path":"/armazem"}"#)?;
        if !r.contains(r#""ok":true"#) {
            return Err(format!(
                "{corte:?}, {gatilho:?}: o armazem nao conferiu depois do corte\n  {r}"
            ));
        }
        m.cortar_a_energia()?;
        relato.push(format!(
            "{corte:?} em {gatilho:?}: {} confirmadas, {voltaram} de {GRAVACOES} de volta; {} setores no cache no corte, {} guardados; {} reconexoes da maquina cortada recusadas",
            confirmadas.len(),
            no_corte.no_corte,
            no_corte.guardados_no_corte,
            no_corte.recusadas
        ));
    }
    Ok(relato.join("; "))
}

/// O erro de mídia na partição de estado: o servidor devolve `EIO` a toda
/// escrita no journal, e o NVMe do emulador a conclui como falha de
/// escrita. A gravação no armazém que precisava do registro não é
/// confirmada; a persistência se declara indisponível, com o motivo; o
/// `disk.info` diz o disco vivo e conta o erro, com o último; a máquina
/// segue respondendo, e o pedido seguinte que mudaria o estado é recusado.
/// Com o disco são de novo, o boot seguinte abre a persistência, e a
/// gravação que falhou não existe.
fn o_erro_de_midia_no_journal(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const A: &str = "/armazem/midia/a.txt";
    let disco = disco_hostil(arch, Corte::PerdeTudo)?;
    let mut m = ligar_no_disco_hostil(arch, artefato, &disco)?;
    let antes = persistencia_de(&mut m)?;
    if antes.estado != "available" {
        return Err(format!(
            "a persistencia nao abriu no disco hostil: {} ({})",
            antes.estado, antes.motivo
        ));
    }
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/midia"}"#)?;
    disco.erro_em(Some((faixa_do_journal(), Sentido::Escrita)));
    let r = m.pedir(
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"nunca confirmado","expect_version":0}}"#),
    )?;
    if confirmada(&r) {
        return Err(format!(
            "a gravacao foi confirmada com o journal recusando a escrita\n  {r}"
        ));
    }
    let p = persistencia_de(&mut m)?;
    if p.estado != "unavailable" || !p.motivo.contains("gravacao no journal falhou") {
        return Err(format!(
            "depois do erro de midia, a persistencia ficou {} ({})",
            p.estado, p.motivo
        ));
    }
    let d = m.pedir("disk.info", "{}")?;
    if !d.contains(r#""alive":true"#)
        || d.contains(r#""write":0"#)
        || !d.contains(r#""last":"o dispositivo recusou a escrita""#)
    {
        return Err(format!(
            "o disk.info nao contou o erro de midia com o disco vivo\n  {d}"
        ));
    }
    m.pedir("system.info", "{}")?;
    let r = m.pedir(
        "fs.write",
        r#"{"path":"/armazem/midia/b.txt","content":"depois","expect_version":0}"#,
    )?;
    if confirmada(&r) {
        return Err(format!(
            "com a persistencia indisponivel, uma gravacao foi confirmada\n  {r}"
        ));
    }
    let erros = disco.contas().erros;
    m.cortar_a_energia()?;
    disco.esperar_o_fim_da_conexao(1)?;
    disco.erro_em(None);

    let mut m = ligar_no_disco_hostil(arch, artefato, &disco)?;
    let depois = persistencia_de(&mut m)?;
    if depois.estado != "available" || depois.boots <= antes.boots {
        return Err(format!(
            "com o disco sao, o boot seguinte: {} ({}), boot {} depois de {}",
            depois.estado, depois.motivo, depois.boots, antes.boots
        ));
    }
    let lido = m.pedir("fs.read", &format!(r#"{{"path":"{A}"}}"#))?;
    if lido.contains("nunca confirmado") {
        return Err(format!("a gravacao que falhou existe\n  {lido}"));
    }
    auditoria_verifica(&mut m)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "{erros} escrita(s) do journal com EIO; a persistencia ficou indisponivel e voltou no boot {}",
        depois.boots
    ))
}

/// O disco que para de responder: o servidor retém, sem resposta nunca,
/// toda escrita no journal. O NVMe do emulador espera com ela; o driver do
/// Duke, depois do prazo do disco — trinta segundos, e não um laço sem
/// fim —, desliga o dispositivo. A gravação não é confirmada, a
/// persistência fica indisponível, o `disk.info` diz o disco desligado e o
/// tempo esgotado, e a máquina segue respondendo. Com o disco são de novo,
/// o boot seguinte abre a persistência sem a gravação.
fn o_disco_que_para_de_responder(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const A: &str = "/armazem/mudo/a.txt";
    let disco = disco_hostil(arch, Corte::PerdeTudo)?;
    let mut m = ligar_no_disco_hostil(arch, artefato, &disco)?;
    let antes = persistencia_de(&mut m)?;
    if antes.estado != "available" {
        return Err(format!(
            "a persistencia nao abriu no disco hostil: {} ({})",
            antes.estado, antes.motivo
        ));
    }
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/mudo"}"#)?;
    disco.reter_em(Some((faixa_do_journal(), Sentido::Escrita)));
    m.esperar_respostas_por(Duration::from_secs(120))?;
    let comeco = std::time::Instant::now();
    let r = m.pedir(
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"nunca confirmado","expect_version":0}}"#),
    )?;
    let esperou = comeco.elapsed();
    if confirmada(&r) {
        return Err(format!(
            "a gravacao foi confirmada com o journal sem resposta\n  {r}"
        ));
    }
    if esperou < Duration::from_secs(25) {
        return Err(format!(
            "o driver desistiu do disco em {esperou:?}, antes do prazo"
        ));
    }
    m.esperar_respostas_por(Duration::from_secs(15))?;
    let p = persistencia_de(&mut m)?;
    if p.estado != "unavailable" {
        return Err(format!(
            "com o disco sem resposta, a persistencia ficou {} ({})",
            p.estado, p.motivo
        ));
    }
    let d = m.pedir("disk.info", "{}")?;
    if !d.contains(r#""alive":false"#) || !d.contains(r#""last":"o dispositivo nao respondeu""#) {
        return Err(format!(
            "o disk.info nao diz o disco desligado pelo tempo esgotado\n  {d}"
        ));
    }
    m.pedir("system.info", "{}")?;
    let retidos = disco.contas().retidos;
    m.cortar_a_energia()?;
    disco.esperar_o_fim_da_conexao(1)?;
    disco.reter_em(None);

    let mut m = ligar_no_disco_hostil(arch, artefato, &disco)?;
    let depois = persistencia_de(&mut m)?;
    if depois.estado != "available" || depois.boots <= antes.boots {
        return Err(format!(
            "com o disco sao, o boot seguinte: {} ({}), boot {} depois de {}",
            depois.estado, depois.motivo, depois.boots, antes.boots
        ));
    }
    let lido = m.pedir("fs.read", &format!(r#"{{"path":"{A}"}}"#))?;
    if lido.contains("nunca confirmado") {
        return Err(format!("a gravacao sem resposta existe\n  {lido}"));
    }
    auditoria_verifica(&mut m)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "{retidos} pedido(s) retido(s); o driver desistiu em {:.1} s, e o boot {} abriu sem a gravacao",
        esperou.as_secs_f64(),
        depois.boots
    ))
}

/// O `/etc/duke/rede` da imagem, num kernel de produção, em dois discos
/// novos: com o arquivo, a máquina sobe com o endereço dele — um que o DHCP
/// do emulador não dá — e sem DHCP; com um arquivo que não se lê, sobe sem
/// endereço, e o `net.info` diz o motivo. Nos dois, o canal atende e a
/// persistência abre: a rede não é autoridade.
fn a_rede_fixa_da_imagem(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let dir = super::raiz_do_projeto().join("target").join("rede-fixa");
    let disco = dir.join("disco.img");
    let casos = [
        (
            "# a rede da bancada, escrita a mao\nendereco 10.0.2.16/24\nroteador 10.0.2.2\ndns 10.0.2.3\n",
            "static",
            "10.0.2.16/24",
            None,
        ),
        (
            "endereco 10.0.2.16/24\nroteador 10.0.3.1\n",
            "static-invalid",
            // O `campo_simples` lê o `null` do JSON como o texto dele.
            "null",
            Some("o roteador nao e outra maquina da sub-rede do endereco"),
        ),
    ];
    let mut vistos = Vec::new();
    let resultado = (|| -> Result<(), String> {
        for (arquivo, modo, endereco, erro) in casos {
            super::zerar_o_tpm(arch)?;
            let variante = super::disco_de_testes_com(
                artefato,
                &disco,
                vec![("etc/duke/rede".to_string(), arquivo.as_bytes().to_vec())],
            )?;
            let ambiente = Ambiente::ligar(arch, None)?.com_disco(disco.clone());
            let mut m = Ligada::subir_com(arch, &variante, ambiente)?;
            let r = m.pedir("net.info", "{}")?;
            let p = persistencia_de(&mut m)?;
            m.cortar_a_energia()?;
            if texto_do_resultado(&r, "mode").as_deref() != Some(modo)
                || texto_do_resultado(&r, "address").as_deref() != Some(endereco)
                || texto_do_resultado(&r, "config_error").as_deref() != erro
            {
                return Err(format!("com o arquivo {arquivo:?}, o net.info:\n  {r}"));
            }
            if p.estado != "available" {
                return Err(format!(
                    "com o arquivo {arquivo:?}, a persistencia nao abriu: {} ({})",
                    p.estado, p.motivo
                ));
            }
            vistos.push(format!("{modo} {}", erro.unwrap_or(endereco)));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    resultado?;
    Ok(vistos.join("; "))
}

/// Espera o `net.info` da máquina dizer `valor` em `campo`, por até
/// `segundos`, e devolve a última resposta.
fn esperar_net_info(
    m: &mut Ligada,
    campo: &str,
    valor: &str,
    segundos: u64,
) -> Result<String, String> {
    let limite = std::time::Instant::now() + Duration::from_secs(segundos);
    loop {
        let r = m.pedir("net.info", "{}")?;
        if texto_do_resultado(&r, campo).as_deref() == Some(valor) {
            return Ok(r);
        }
        if std::time::Instant::now() >= limite {
            return Err(format!(
                "o net.info nao disse {campo} {valor} em {segundos} s\n  {r}"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A máquina física de referência, na rede: a 82574L é a única placa — no
/// x86, atrás de uma ponte PCI, como numa placa PCIe de um PC —, e a pilha
/// sobe nela. O DHCP dá o endereço, e um agente de fora entra pelo canal
/// TCP. O cabo sai (o `set_link` do emulador): o `net.info` diz o enlace
/// caído, o ARP é recusado sem enlace, e a recusa é contada; nada desliga
/// a placa. O cabo volta: o enlace volta, a sessão TCP aberta antes do
/// corte continua respondendo, e uma nova entra.
fn a_placa_intel(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?.com_placa_intel();
    let mut m = Ligada::subir_com(arch, artefato, ambiente)?;
    let resultado = (|| -> Result<String, String> {
        let r = m.pedir("net.info", "{}")?;
        if texto_do_resultado(&r, "driver").as_deref() != Some("e1000e")
            || texto_do_resultado(&r, "link").as_deref() != Some("true")
        {
            return Err(format!(
                "a pilha nao subiu na placa Intel com enlace\n  {r}"
            ));
        }
        let r = esperar_net_info(&mut m, "mode", "dhcp", 30)?;
        let endereco = texto_do_resultado(&r, "address").unwrap_or_default();
        if !endereco.starts_with("10.0.2.") {
            return Err(format!("o DHCP nao deu endereco pela placa Intel\n  {r}"));
        }
        let mut antes = super::AgenteNaPorta::conectar_tcp(arch, 1)?;
        let s = antes.pedir("system.info", "{}")?;
        if !s.contains(r#""result""#) {
            return Err(format!("o agente pelo TCP nao foi atendido\n  {s}"));
        }

        super::mudar_o_enlace(arch, "rede0", false)?;
        esperar_net_info(&mut m, "link", "false", 10)?;
        let arp = m.pedir("net.arp", "{}")?;
        if !arp.contains("sem enlace") {
            return Err(format!(
                "o ARP sem enlace nao foi recusado pelo motivo\n  {arp}"
            ));
        }
        let r = m.pedir("net.info", "{}")?;
        let sem_enlace: u64 = super::campo_simples(&r, "frames_without_link")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if sem_enlace == 0 || texto_do_resultado(&r, "alive").as_deref() != Some("true") {
            return Err(format!(
                "sem enlace, a recusa nao foi contada ou a placa foi desligada\n  {r}"
            ));
        }

        super::mudar_o_enlace(arch, "rede0", true)?;
        esperar_net_info(&mut m, "link", "true", 10)?;
        let s = antes.pedir("system.info", "{}")?;
        if !s.contains(r#""result""#) {
            return Err(format!(
                "a sessao TCP de antes do corte nao respondeu depois dele\n  {s}"
            ));
        }
        let mut depois = super::AgenteNaPorta::conectar_tcp(arch, 2)?;
        let s = depois.pedir("system.info", "{}")?;
        if !s.contains(r#""result""#) {
            return Err(format!("um agente novo nao entrou depois do corte\n  {s}"));
        }
        let r = m.pedir("net.info", "{}")?;
        let reinicios = super::campo_simples(&r, "resets").unwrap_or_default();
        Ok(format!(
            "{endereco} pelo DHCP na 82574L, o agente por TCP antes e depois do cabo, {sem_enlace} quadros recusados sem enlace, {reinicios} reinicios"
        ))
    })();
    m.cortar_a_energia()?;
    resultado
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
pub(crate) struct Persistencia {
    pub(crate) estado: String,
    pub(crate) motivo: String,
    /// A interface do TPM, e a impressão da EK com que o journal fala.
    pub(crate) interface: String,
    pub(crate) ek: String,
    pub(crate) geracao: u64,
    /// Os registros do journal que não são só de auditoria: os de estado,
    /// de boot e de abertura. Os de auditoria o coletor grava quando quer,
    /// e a conta deles não é a de um cenário.
    pub(crate) registros: u64,
    /// Os registros só de auditoria do journal.
    pub(crate) de_auditoria: u64,
    /// O valor do contador que o journal confirmou por último.
    pub(crate) ancora: Option<u64>,
    /// A última sequência da auditoria no journal.
    pub(crate) auditoria_gravada: u64,
    /// Quantas compactações o journal já teve.
    pub(crate) compactacoes: u64,
    /// Quantos setores da região estão ocupados, e quantos ela tem.
    pub(crate) usados: u64,
    pub(crate) setores: u64,
    pub(crate) boots: u64,
    pub(crate) relogio: u64,
    pub(crate) descargas: u64,
}

pub(crate) fn persistencia_de(maquina: &mut Ligada) -> Result<Persistencia, String> {
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
        interface: texto("tpm_interface"),
        ek: texto("tpm_ek"),
        geracao: numero("generation")?,
        registros: numero("records")? - numero("audit_records")?,
        de_auditoria: numero("audit_records")?,
        ancora: super::campo_simples(p, "anchor").and_then(|v| v.parse().ok()),
        auditoria_gravada: numero("audit_durable_seq")?,
        compactacoes: numero("compactions")?,
        usados: numero("region_used")?,
        setores: numero("region_sectors")?,
        boots: numero("boots")?,
        relogio: numero("clock")?,
        descargas: numero("disk_flushes")?,
    })
}

/// Um registro da auditoria como o `audit.tail` o mostra — o que a
/// bancada confere dele.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rastro {
    pub(crate) seq: u64,
    pub(crate) elo: String,
    pub(crate) titular: String,
    pub(crate) metodo: String,
    pub(crate) recurso: String,
    pub(crate) codigo: String,
    /// O detalhe, até a primeira vírgula.
    pub(crate) detalhe: String,
    pub(crate) duravel: bool,
}

/// A cauda da auditoria: os últimos 128 registros, pela serial.
pub(crate) fn cauda_da_auditoria(maquina: &mut Ligada) -> Result<Vec<Rastro>, String> {
    rastros(&maquina.pedir("audit.tail", r#"{"count":128}"#)?)
}

/// Os registros de uma resposta do `audit.tail` — pela serial, ou por um
/// agente que lê a auditoria.
pub(crate) fn rastros(r: &str) -> Result<Vec<Rastro>, String> {
    let mut v = Vec::new();
    for pedaco in r.split(r#"{"seq":"#).skip(1) {
        let pedaco = format!(r#"{{"seq":{pedaco}"#);
        let campo = |n: &str| super::campo_simples(&pedaco, n).unwrap_or_default();
        v.push(Rastro {
            seq: campo("seq")
                .parse()
                .map_err(|_| format!("um registro da auditoria sem numero\n  {pedaco}"))?,
            elo: campo("link"),
            titular: campo("holder"),
            metodo: campo("method"),
            recurso: campo("resource"),
            codigo: campo("code"),
            detalhe: campo("detail"),
            duravel: campo("durable") == "true",
        });
    }
    if v.is_empty() {
        return Err(format!("o audit.tail nao trouxe registros\n  {r}"));
    }
    Ok(v)
}

/// A cadeia da auditoria se verifica, do começo da janela à cabeça.
pub(crate) fn auditoria_verifica(maquina: &mut Ligada) -> Result<(), String> {
    let r = maquina.pedir("audit.verify", "{}")?;
    if r.contains(r#""ok":true"#) {
        Ok(())
    } else {
        Err(format!("a cadeia da auditoria nao se verifica\n  {r}"))
    }
}

/// A sequência do `policy.load` deste boot: o primeiro registro que um boot
/// faz. Os anteriores a ela vieram do journal.
fn comeco_do_boot(cauda: &[Rastro]) -> Result<u64, String> {
    cauda
        .iter()
        .filter(|r| r.metodo == "policy.load" && r.titular == "kernel")
        .map(|r| r.seq)
        .max()
        .ok_or_else(|| "a cauda da auditoria nao tem o policy.load deste boot".into())
}

/// Espera a auditoria inteira estar no journal — o coletor a grava de
/// tempos em tempos —, e devolve a cauda.
fn esperar_a_auditoria_gravada(maquina: &mut Ligada) -> Result<Vec<Rastro>, String> {
    let limite = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let cauda = cauda_da_auditoria(maquina)?;
        // As leituras não são o que se espera: o `audit.tail` desta espera
        // — registrado antes de responder, e ainda não gravado — e os das
        // voltas de antes, e as do tecido de segurança, que lê a auditoria
        // pelo gate a cada registro novo e grava a leitura. O que se espera
        // é o último registro que não é leitura no journal: ele leva os de
        // antes, que o journal grava em ordem.
        let leitura = |r: &Rastro| {
            (r.metodo == "audit.tail" && r.titular == "serial") || r.titular == "service"
        };
        if cauda
            .iter()
            .rev()
            .find(|r| !leitura(r))
            .is_some_and(|r| r.duravel)
        {
            return Ok(cauda);
        }
        if std::time::Instant::now() >= limite {
            return Err("a auditoria nao foi ao journal em 20 s".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Uma operação administrativa provada pela credencial `privada`, pela
/// serial.
pub(crate) fn administrar(
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

pub(crate) fn executou(r: &str) -> bool {
    r.contains(r#""executed":true"#)
}

/// O pedido de registro de um agente com a chave privada `privada`.
pub(crate) fn registro_de_agente(privada: &[u8; 32], nome: &str, papel: &str) -> String {
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

/// Um byte trocado no meio do último registro confirmado — o da lápide, e
/// não o último no disco, que pode ser uma leitura do NSF: o boot lê até o
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
    estragar_o_registro(&disco, ultimo_confirmado(&disco)?)?;

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

/// Copia os arquivos de um diretório para outro, que é recriado vazio.
pub(crate) fn copiar_diretorio(de: &Path, para: &Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(para);
    std::fs::create_dir_all(para).map_err(|e| e.to_string())?;
    for e in std::fs::read_dir(de).map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        if e.file_type().map_err(|e| e.to_string())?.is_file() {
            std::fs::copy(e.path(), para.join(e.file_name())).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// O journal e a auditoria são persistência e histórico; o contador é a
/// monotonicidade do estado protegido. Leituras pela serial vão à
/// auditoria, e o coletor as grava em registros só de auditoria: vários,
/// e a âncora não se move. Entre dois cortes de energia, o boot seguinte
/// abre com a auditoria gravada inteira, e avança a âncora uma vez — pelo
/// registro de boot —; uma operação de autoridade, outra.
fn a_auditoria_nao_gasta_o_contador(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let antes = persistencia_de(&mut m)?;
    let ancora = antes.ancora.ok_or("a persistencia nao diz a ancora")?;
    let mut depois = persistencia_de(&mut m)?;
    for _ in 0..240 {
        if depois.de_auditoria >= antes.de_auditoria + 3 {
            break;
        }
        m.pedir("system.info", "{}")?;
        std::thread::sleep(Duration::from_millis(250));
        depois = persistencia_de(&mut m)?;
    }
    m.cortar_a_energia()?;
    if depois.de_auditoria < antes.de_auditoria + 3 {
        return Err(format!(
            "o coletor gravou {} registros so de auditoria, e nao tres",
            depois.de_auditoria - antes.de_auditoria
        ));
    }
    if depois.ancora != Some(ancora) {
        return Err(format!(
            "{} registros so de auditoria levaram a ancora de {ancora} a {:?}",
            depois.de_auditoria - antes.de_auditoria,
            depois.ancora
        ));
    }
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let verifica = auditoria_verifica(&mut m);
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0xC6; 32], "depois-da-auditoria", "observador"),
    )?;
    let q = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;
    verifica?;
    if p.estado != "available" || p.auditoria_gravada < depois.auditoria_gravada {
        return Err(format!(
            "o boot seguinte: {} ({}), auditoria gravada ate {} e nao {}",
            p.estado, p.motivo, p.auditoria_gravada, depois.auditoria_gravada
        ));
    }
    if p.ancora != Some(ancora + 1) || !executou(&r) || q.ancora != Some(ancora + 2) {
        return Err(format!(
            "a ancora era {ancora}: {:?} depois do boot, {:?} depois da operacao\n  {r}",
            p.ancora, q.ancora
        ));
    }
    Ok(format!(
        "{} registros so de auditoria na ancora {ancora}; o boot a levou a {} e a operacao a {}",
        depois.de_auditoria - antes.de_auditoria,
        ancora + 1,
        ancora + 2
    ))
}

/// A fronteira da limitação assumida: os registros só de auditoria depois
/// do último que avançou o contador podem sumir num rollback do disco — e
/// isso nunca traz de volta estado protegido.
///
/// Um agente é registrado e revogado; a partição de estado é fotografada
/// logo depois da revogação, e outra vez antes dela; e as leituras seguintes
/// vão, pelo coletor, a registros só de auditoria. A foto de depois da
/// revogação, devolvida ao disco, é aceita — o contador não protege o rabo —
/// e os registros da auditoria que ela não tinha somem: nenhum deles, com a
/// sequência e o elo de antes, está na cadeia do boot seguinte. Mas o agente
/// continua revogado. A foto de antes da revogação é recusada, e o agente
/// não volta.
fn o_rabo_da_auditoria_nao_traz_estado(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let privada = [0xC7; 32];
    let nome = "rabo-da-auditoria";
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = (|| -> Result<_, String> {
        registrar(&mut m, &chaves, &privada, nome)?;
        let antes_da_revogacao = ler_o_estado(&disco)?;
        revogar_agente(&mut m, &chaves, &privada)?;
        // A foto antes do estado: o que o coletor gravar entre as duas
        // leituras conta como dentro da foto, e não como rabo.
        let foto = ler_o_estado(&disco)?;
        let revogado = persistencia_de(&mut m)?;
        let mut depois = persistencia_de(&mut m)?;
        for _ in 0..240 {
            if depois.de_auditoria >= revogado.de_auditoria + 2 {
                break;
            }
            m.pedir("system.info", "{}")?;
            std::thread::sleep(Duration::from_millis(250));
            depois = persistencia_de(&mut m)?;
        }
        let rabo: Vec<Rastro> = cauda_da_auditoria(&mut m)?
            .into_iter()
            .filter(|r| r.duravel && r.seq > revogado.auditoria_gravada)
            .collect();
        Ok((antes_da_revogacao, revogado, foto, depois, rabo))
    })();
    m.cortar_a_energia()?;
    let (antes_da_revogacao, revogado, foto, depois, rabo) = r?;
    if depois.de_auditoria < revogado.de_auditoria + 2 || depois.ancora != revogado.ancora {
        return Err(format!(
            "o rabo: {} registros so de auditoria, e a ancora {:?} depois de {:?}",
            depois.de_auditoria - revogado.de_auditoria,
            depois.ancora,
            revogado.ancora
        ));
    }
    if rabo.is_empty() {
        return Err("nenhum registro duravel da auditoria depois da revogacao".into());
    }

    // A foto de depois da revogação, sem o rabo.
    escrever_no_estado(&disco, &foto)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let cadeia = cauda_da_auditoria(&mut m);
    let verifica = auditoria_verifica(&mut m);
    let entra = agente_entra(arch, &privada, nome)?;
    m.cortar_a_energia()?;
    verifica?;
    let cadeia = cadeia?;
    if p.estado != "available" || p.ancora != revogado.ancora.map(|a| a + 1) {
        return Err(format!(
            "a foto de depois da revogacao: {} ({}), ancora {:?}",
            p.estado, p.motivo, p.ancora
        ));
    }
    if entra {
        return Err("sem o rabo da auditoria, o agente revogado voltou".into());
    }
    if let Some(r) = rabo
        .iter()
        .find(|r| cadeia.iter().any(|c| c.seq == r.seq && c.elo == r.elo))
    {
        return Err(format!(
            "o registro {} do rabo, que a foto nao tinha, esta na cadeia",
            r.seq
        ));
    }

    // A foto de antes da revogação.
    escrever_no_estado(&disco, &antes_da_revogacao)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let q = persistencia_de(&mut m)?;
    let voltou = agente_entra(arch, &privada, nome)?;
    m.cortar_a_energia()?;
    if q.estado != "refused" || voltou {
        return Err(format!(
            "a foto de antes da revogacao: {} ({}), o revogado entra: {voltou}",
            q.estado, q.motivo
        ));
    }
    Ok(format!(
        "{} registros duraveis da auditoria sumiram com o rabo; o agente continua revogado; \
         a foto de antes da revogacao: {}",
        rabo.len(),
        q.motivo
    ))
}

/// O TPM devolvido a um estado anterior — o NV dele restaurado de uma
/// cópia, o que um TPM físico não deixa fazer e um emulado deixa —
/// diante do disco atual: o contador fica atrás do journal. Recusado, e o
/// agente revogado depois da cópia não volta.
fn o_tpm_devolvido_e_recusado(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = registrar(&mut m, &chaves, &[0xC1; 32], "tpm-antigo");
    m.cortar_a_energia()?;
    r?;
    let estado = diretorio_do_tpm(arch).join("estado");
    let copia = diretorio_do_tpm(arch).join("copia");
    copiar_diretorio(&estado, &copia)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = revogar_agente(&mut m, &chaves, &[0xC1; 32]);
    m.cortar_a_energia()?;
    r?;
    copiar_diretorio(&copia, &estado)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let voltou = agente_entra(arch, &[0xC1; 32], "tpm-antigo")?;
    m.cortar_a_energia()?;
    if p.estado != "refused" || !p.motivo.contains("passa da ancora") {
        return Err(format!(
            "o TPM devolvido nao foi recusado pelo que e: {} ({})",
            p.estado, p.motivo
        ));
    }
    if voltou {
        return Err("com o TPM devolvido, o agente revogado voltou".into());
    }
    Ok(format!("recusado: {}", p.motivo))
}

/// O TPM tirado da máquina, e o disco devolvido a uma cópia de antes de
/// uma revogação: sem o TPM, nada confirma que o disco é o atual. O journal
/// é recusado — e com ele as credenciais: o agente revogado não volta.
fn o_tpm_tirado_e_recusado(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = registrar(&mut m, &chaves, &[0xC2; 32], "sem-tpm-antigo");
    m.cortar_a_energia()?;
    r?;
    let foto = ler_o_estado(&disco)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = revogar_agente(&mut m, &chaves, &[0xC2; 32]);
    m.cortar_a_energia()?;
    r?;
    escrever_no_estado(&disco, &foto)?;
    let mut m = Ligada::subir_com(arch, artefato, Ambiente::sem_tpm(None))?;
    let p = persistencia_de(&mut m)?;
    let voltou = agente_entra(arch, &[0xC2; 32], "sem-tpm-antigo")?;
    let r = administrar(&mut m, &chaves.administrador, "message.read", "{}")?;
    m.cortar_a_energia()?;
    if p.estado != "refused" || !p.motivo.contains("nenhum TPM") {
        return Err(format!(
            "o journal sem TPM nao foi recusado: {} ({})",
            p.estado, p.motivo
        ));
    }
    if voltou || executou(&r) {
        return Err(format!(
            "sem TPM, o revogado voltou ou uma credencial administrativa passou\n  {r}"
        ));
    }
    Ok(format!("recusado: {}", p.motivo))
}

/// O mesmo TPM pelas duas interfaces: a CRB, a dos TPMs de firmware, e o
/// TIS, a dos discretos. O journal criado por uma abre pela outra: a mesma
/// EK, o mesmo contador. No ARM, a máquina `virt` só tem o TIS.
fn o_tpm_pela_crb_e_pelo_tis(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    if arch == Arquitetura::Aarch64 {
        return Ok("a maquina virt do ARM so oferece o TIS: nada a comparar".into());
    }
    let chaves = super::chaves::Chaves::garantir()?;
    let mut ambiente = Ambiente::ligar(arch, None)?;
    ambiente.crb = true;
    let mut m = Ligada::subir_com(arch, artefato, ambiente)?;
    let crb = persistencia_de(&mut m)?;
    let r = registrar(&mut m, &chaves, &[0xC3; 32], "pela-crb");
    m.cortar_a_energia()?;
    r?;
    if crb.estado != "available" || crb.interface != "CRB" {
        return Err(format!(
            "pela CRB: {} ({}), interface {}",
            crb.estado, crb.motivo, crb.interface
        ));
    }
    let mut m = Ligada::subir(arch, artefato, None)?;
    let tis = persistencia_de(&mut m)?;
    let entra = agente_entra(arch, &[0xC3; 32], "pela-crb")?;
    m.cortar_a_energia()?;
    if tis.estado != "available" || tis.interface != "TIS" || tis.ek != crb.ek || !entra {
        return Err(format!(
            "pelo TIS: {} ({}), interface {}, EK {} e nao {}, o agente entra: {entra}",
            tis.estado, tis.motivo, tis.interface, tis.ek, crb.ek
        ));
    }
    Ok(format!("EK {} pelas duas interfaces", crb.ek))
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

/// As chaves seladas diante de outro TPM — o disco levado para outra
/// máquina, ou o TPM trocado —: a EK não é a fixada, o journal é recusado
/// antes de o cofre abrir, e nenhuma chave assina. De volta ao TPM dela, a
/// mesma chave abre e assina igual.
fn as_chaves_seladas_diante_de_outro_tpm(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    const CRIAR: &str = r#"{"key":"chave:bancada","domain":"ic-request"}"#;
    let assinar = format!(
        r#"{{"key":"chave:bancada","domain":"ic-request","digest":"{}"}}"#,
        "5c".repeat(32)
    );
    let m = Ligada::subir(arch, artefato, None)?;
    let feito = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
        let criada = a.pedir("key.create", CRIAR)?;
        Ok((criada, a.pedir("key.sign", &assinar)?))
    });
    m.cortar_a_energia()?;
    let (criada, assinada) = feito?;
    if texto_do_resultado(&criada, "seal").as_deref() != Some("tpm") {
        return Err(format!("a chave nao nasceu selada no TPM\n  {criada}"));
    }
    let assinatura = texto_do_resultado(&assinada, "signature")
        .ok_or_else(|| format!("a chave nao assinou\n  {assinada}"))?;
    let estado = diretorio_do_tpm(arch).join("estado");
    let deste = diretorio_do_tpm(arch).join("deste");
    copiar_diretorio(&estado, &deste)?;
    // Outro TPM: um estado novo, com outra semente de endosso e outro dono.
    let _ = std::fs::remove_dir_all(&estado);
    std::fs::create_dir_all(&estado).map_err(|e| e.to_string())?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let pelo_outro =
        super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| a.pedir("key.sign", &assinar));
    m.cortar_a_energia()?;
    if p.estado != "refused" || !p.motivo.contains("TPM") {
        return Err(format!(
            "o journal diante de outro TPM nao foi recusado: {} ({})",
            p.estado, p.motivo
        ));
    }
    if pelo_outro.is_ok_and(|r| r.contains(r#""signed":true"#)) {
        return Err("a chave selada assinou diante de outro TPM".into());
    }
    let recusa = p.motivo;
    // De volta ao TPM dela.
    copiar_diretorio(&deste, &estado)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let de_volta =
        super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| a.pedir("key.sign", &assinar));
    m.cortar_a_energia()?;
    let de_volta = de_volta?;
    if p.estado != "available"
        || texto_do_resultado(&de_volta, "signature").as_deref() != Some(assinatura.as_str())
    {
        return Err(format!(
            "de volta ao TPM dela, a chave nao assinou igual: {} ({})\n  {de_volta}",
            p.estado, p.motivo
        ));
    }
    Ok(format!(
        "recusado diante de outro TPM ({recusa}), e de volta ao dele a chave assina igual"
    ))
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
    // A auditoria, só em memória: nada dela se diz gravado.
    if p.auditoria_gravada != 0 {
        m.cortar_a_energia()?;
        return Err(format!(
            "sem TPM, a auditoria se diz gravada ate {}",
            p.auditoria_gravada
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

/// O objeto `time` do `system.info`: o civil e o lógico, como o kernel os
/// diz.
struct Tempo {
    estado: String,
    civil_ms: u64,
    logico: u64,
    adiantado_ms: u64,
    marcas: String,
}

fn tempo_de(maquina: &mut Ligada) -> Result<Tempo, String> {
    let r = maquina.pedir("system.info", "{}")?;
    // Os campos do civil vêm antes do primeiro objeto aninhado.
    let t = super::apos(&r, r#""time":{"#)
        .and_then(|t| t.split(r#""sources":{"#).next())
        .ok_or_else(|| format!("o system.info nao diz o tempo\n  {r}"))?;
    let numero = |n: &str| -> Result<u64, String> {
        super::campo_simples(t, n)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("o tempo nao diz `{n}`: {t}"))
    };
    Ok(Tempo {
        estado: super::campo_simples(t, "state").unwrap_or_default(),
        civil_ms: numero("civil_ms")?,
        logico: numero("logical")?,
        adiantado_ms: numero("ahead_ms")?,
        marcas: super::apos(t, r#""marks":["#)
            .and_then(|m| m.split(']').next())
            .unwrap_or_default()
            .to_string(),
    })
}

/// O tempo lógico: num boot em 2031 ele está em 2031, e uma operação o
/// grava; no seguinte, com o RTC em 2024, ele continua em 2031 — o piso
/// do journal —; no terceiro, com o RTC em 2032, anda.
///
/// E o civil, separado: sem fonte de hora que responda — a bancada de
/// persistência não tem servidor de hora —, ele é o RTC, no estado `rtc`.
/// No segundo boot o lógico fica no piso, adiantado do civil, e o
/// `system.info time` o marca `adiantado`, com quanto; no terceiro, o
/// lógico é o civil, sem marca.
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
    let tempo_b = tempo_de(&mut m)?;
    m.cortar_a_energia()?;
    let mut m = Ligada::subir(arch, artefato, Some("2032-05-17T12:00:00"))?;
    let c = persistencia_de(&mut m)?.relogio;
    let tempo_c = tempo_de(&mut m)?;
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
    // O civil é o RTC, e não o piso; o lógico, no piso, adiantado dele. O
    // civil pode estar um segundo atrás do RTC lido antes dele: o RTC tem
    // resolução de um segundo, e o civil o relê no máximo uma vez por
    // segundo, só para a frente — o RTC pode virar o segundo entre as duas
    // leituras sem que o civil o tenha relido.
    let civil_b = tempo_b.civil_ms / 1000;
    if tempo_b.estado != "rtc"
        || !(rtc.saturating_sub(1)..rtc + 300).contains(&civil_b)
        || tempo_b.logico < a
        || !tempo_b.marcas.contains(r#""adiantado""#)
        || tempo_b.adiantado_ms < a.saturating_sub(civil_b + 1) * 1000
    {
        return Err(format!(
            "com o RTC em 2024 ({rtc}) e o piso em 2031, o system.info time diz estado {}, civil {} ms, logico {}, adiantado {} ms, marcas [{}]",
            tempo_b.estado, tempo_b.civil_ms, tempo_b.logico, tempo_b.adiantado_ms, tempo_b.marcas
        ));
    }
    // Com o RTC adiante do piso, o lógico é o civil, sem marca.
    let civil_c = tempo_c.civil_ms / 1000;
    if tempo_c.estado != "rtc"
        || civil_c < EM_2032
        || tempo_c.logico < civil_c
        || tempo_c.logico > civil_c + 1
        || tempo_c.marcas.contains(r#""adiantado""#)
    {
        return Err(format!(
            "com o RTC em 2032, o system.info time diz estado {}, civil {} ms, logico {}, marcas [{}]",
            tempo_c.estado, tempo_c.civil_ms, tempo_c.logico, tempo_c.marcas
        ));
    }
    Ok(format!(
        "{a} -> {b} (RTC em {rtc}; o civil no RTC, o logico {} s adiantado) -> {c}",
        tempo_b.adiantado_ms / 1000
    ))
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
    // O registro da política: o último confirmado, e não o último no disco.
    estragar_o_registro(&disco, ultimo_confirmado(&disco)?)?;

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
    let cauda = cauda_da_auditoria(&mut m);
    m.cortar_a_energia()?;
    // A auditoria do journal recusado também não é adotada: a cadeia
    // recomeça, só em memória, e diz por quê.
    let cauda = cauda?;
    if cauda.first().map(|r| r.seq) != Some(1)
        || cauda
            .iter()
            .any(|r| r.duravel || r.metodo == "agent.revoke")
        || !cauda
            .iter()
            .any(|r| r.metodo == "persistence.open" && r.codigo == "ERROR")
    {
        return Err(format!(
            "com o journal recusado, a auditoria dele foi adotada, ou a recusa nao foi auditada\n  {cauda:?}"
        ));
    }
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

/// A auditoria gravada sobrevive a um corte de energia: cada registro que
/// o `audit.tail` dizia `durable` volta igual — o mesmo número, o mesmo
/// elo —, a decisão da operação de autoridade está lá, e a cadeia do boot
/// seguinte continua dela e se verifica.
fn a_auditoria_sobrevive(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0x5A; 32], "auditado", "observador"),
    )?;
    if !executou(&r) {
        m.cortar_a_energia()?;
        return Err(format!("o registro do agente nao foi executado\n  {r}"));
    }
    // Uma recusa, que não muda estado: vai pelo coletor.
    let _ = m.pedir("nao.existe", "{}")?;
    let antes = esperar_a_auditoria_gravada(&mut m);
    m.cortar_a_energia()?;
    let antes: Vec<Rastro> = antes?.into_iter().filter(|r| r.duravel).collect();
    let decisao = |c: &[Rastro]| {
        c.iter()
            .any(|r| r.metodo == "agent.register" && r.codigo == "ALLOW" && r.recurso == "auditado")
    };
    if !decisao(&antes) || !antes.iter().any(|r| r.metodo == "nao.existe") {
        return Err("a decisao ou a recusa nao estavam na auditoria gravada".into());
    }

    let mut m = Ligada::subir(arch, artefato, None)?;
    let depois = cauda_da_auditoria(&mut m);
    let verifica = auditoria_verifica(&mut m);
    m.cortar_a_energia()?;
    let depois = depois?;
    verifica?;
    // Os de antes que a cauda de agora ainda alcança: os mais novos.
    let alcance = depois.first().map_or(u64::MAX, |r| r.seq);
    let mut conferidos = 0;
    for r in antes.iter().filter(|r| r.seq >= alcance) {
        match depois.iter().find(|d| d.seq == r.seq) {
            Some(d) if d.elo == r.elo && d.metodo == r.metodo && d.duravel => conferidos += 1,
            outro => {
                return Err(format!(
                    "o registro {} da auditoria gravada nao voltou igual: {r:?} / {outro:?}",
                    r.seq
                ));
            }
        }
    }
    if conferidos == 0 || !decisao(&depois) {
        return Err("a auditoria gravada nao voltou no boot seguinte".into());
    }
    let comeco = comeco_do_boot(&depois)?;
    let ultimo_de_antes = antes.iter().map(|r| r.seq).max().unwrap_or(0);
    if comeco <= ultimo_de_antes {
        return Err(format!(
            "o boot seguinte recomecou a cadeia em {comeco}, antes de {ultimo_de_antes}"
        ));
    }
    Ok(format!(
        "{conferidos} registros gravados voltaram iguais, com a decisao; a cadeia continua em {comeco} e se verifica"
    ))
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

/// A identidade do Duke como a máquina a mostra no `system.info` — o que
/// o operador lê no console no primeiro boot: de onde ela veio, a pública,
/// e por que não há uma.
pub(crate) struct IdentidadeVista {
    pub(crate) origem: String,
    pub(crate) publica: Option<[u8; 32]>,
    pub(crate) erro: Option<String>,
}

/// O que o `system.info` de `m` diz da identidade do Duke.
pub(crate) fn identidade_vista(m: &mut Ligada) -> Result<IdentidadeVista, String> {
    let r = m.pedir("system.info", "{}")?;
    let objeto = r
        .split(r#""identity":{"#)
        .nth(1)
        .and_then(|resto| resto.split('}').next())
        .ok_or_else(|| format!("o system.info nao diz a identidade do Duke\n  {r}"))?;
    let texto = |campo: &str| {
        objeto
            .split(&format!(r#""{campo}":""#))
            .nth(1)
            .and_then(|resto| resto.split('"').next())
            .map(String::from)
    };
    Ok(IdentidadeVista {
        origem: texto("origin")
            .ok_or_else(|| format!("a identidade do system.info nao diz a origem\n  {r}"))?,
        publica: texto("key").and_then(|k| sigilo::de_hex(&k)),
        erro: texto("error"),
    })
}

/// A pública da identidade de `m`, se ela é a `origem` — `born`, `sealed`
/// ou `image` —, ou o erro que diz o que a máquina mostrou.
pub(crate) fn identidade_com_origem(m: &mut Ligada, origem: &str) -> Result<[u8; 32], String> {
    let vista = identidade_vista(m)?;
    match vista.publica {
        Some(p) if vista.origem == origem => Ok(p),
        _ => Err(format!(
            "a identidade do Duke nao e {origem}: e {} ({})",
            vista.origem,
            vista.erro.as_deref().unwrap_or("sem motivo")
        )),
    }
}

/// Um campo de texto do resultado de uma resposta do agente.
pub(crate) fn texto_do_resultado(r: &str, campo: &str) -> Option<String> {
    let resultado = r.split(r#""result":"#).nth(1)?;
    super::campo_simples(resultado, campo)
}

/// A linha do log em que o boot diz o cofre aberto — a geração, quantas
/// chaves seladas abriu e em quanto tempo —, ou que ela não está lá.
fn linha_do_cofre(log: &str) -> String {
    log.split("cofre aberto: ")
        .nth(1)
        .and_then(|resto| resto.split('"').next())
        .map(|l| format!("cofre aberto: {l}"))
        .unwrap_or_else(|| "sem a linha do cofre no log".into())
}

/// As chaves de assinatura sobrevivem ao corte de energia: a viva volta
/// com a mesma pública e assina o mesmo resumo com a mesma assinatura — a
/// mesma privada —; a destruída volta destruída — não assina —, e o nome
/// dela não se cria de novo. A fotografia de antes da destruição, devolvida ao disco, é
/// recusada — e, com o journal recusado, credencial nenhuma entra: nada se
/// assina por ela —; o disco de agora, de volta, abre com a chave
/// destruída.
fn as_chaves_sobrevivem(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    let resumo = "5a".repeat(32);
    let criar = |a: &mut super::AgenteNaPorta, chave: &str| {
        a.pedir(
            "key.create",
            &format!(r#"{{"key":"{chave}","domain":"ic-request"}}"#),
        )
    };
    let assinar = |a: &mut super::AgenteNaPorta, chave: &str| {
        a.pedir(
            "key.sign",
            &format!(r#"{{"key":"{chave}","domain":"ic-request","digest":"{resumo}"}}"#),
        )
    };
    let ler = |a: &mut super::AgenteNaPorta, chave: &str| {
        a.pedir("key.read", &format!(r#"{{"key":"{chave}"}}"#))
    };

    let m = Ligada::subir(arch, artefato, None)?;
    let mut um = super::AgenteNaPorta::conectar(arch, 1)?;
    let viva = criar(&mut um, "chave:bancada")?;
    let morta = criar(&mut um, "chave:bancada-2")?;
    let publica = texto_do_resultado(&viva, "public")
        .ok_or_else(|| format!("a chave nao nasceu\n  {viva}"))?;
    if texto_do_resultado(&morta, "public").is_none() {
        return Err(format!("a segunda chave nao nasceu\n  {morta}"));
    }
    let r = assinar(&mut um, "chave:bancada")?;
    let assinatura = texto_do_resultado(&r, "signature")
        .ok_or_else(|| format!("a chave viva nao assinou\n  {r}"))?;
    let foto = ler_o_estado(&disco)?;
    let r = um.pedir("key.destroy", r#"{"key":"chave:bancada-2"}"#)?;
    if !r.contains(r#""destroyed":true"#) {
        return Err(format!("a chave nao foi destruida\n  {r}"));
    }
    drop(um);
    m.cortar_a_energia()?;

    // De volta: a viva assina igual, a destruída fica destruída. O log do
    // boot diz quanto o cofre levou para abrir a viva.
    let mut m = Ligada::subir(arch, artefato, None)?;
    let mut um = super::AgenteNaPorta::conectar(arch, 1)?;
    let lida = ler(&mut um, "chave:bancada")?;
    let de_novo = assinar(&mut um, "chave:bancada")?;
    let lapide = ler(&mut um, "chave:bancada-2")?;
    let pela_lapide = assinar(&mut um, "chave:bancada-2")?;
    let outra = criar(&mut um, "chave:bancada-2")?;
    drop(um);
    let cofre = m
        .pedir("log.tail", r#"{"count":256,"min_level":"info"}"#)
        .map(|log| linha_do_cofre(&log))
        .unwrap_or_else(|e| format!("sem o log: {e}"));
    m.cortar_a_energia()?;
    if texto_do_resultado(&lida, "public").as_deref() != Some(publica.as_str())
        || texto_do_resultado(&lida, "state").as_deref() != Some("active")
    {
        return Err(format!("a chave viva nao voltou igual\n  {lida}"));
    }
    if texto_do_resultado(&de_novo, "signature").as_deref() != Some(assinatura.as_str()) {
        return Err(format!(
            "a chave viva voltou com outra privada: outra assinatura\n  {de_novo}"
        ));
    }
    if texto_do_resultado(&lapide, "state").as_deref() != Some("destroyed") {
        return Err(format!(
            "a chave destruida nao voltou destruida\n  {lapide}"
        ));
    }
    if !pela_lapide.contains(r#""signed":false"#)
        || texto_do_resultado(&pela_lapide, "error").as_deref() != Some("a chave foi destruida")
    {
        return Err(format!(
            "a chave destruida assinou depois do corte\n  {pela_lapide}"
        ));
    }
    if !outra.contains(r#""created":false"#) {
        return Err(format!("o nome da chave destruida voltou\n  {outra}"));
    }
    let atual = ler_o_estado(&disco)?;

    // A fotografia de antes da destruição: recusada, e a chave destruída
    // não assina por ela.
    escrever_no_estado(&disco, &foto)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let assinou = super::AgenteNaPorta::conectar(arch, 1)
        .and_then(|mut a| assinar(&mut a, "chave:bancada-2"))
        .is_ok_and(|r| r.contains(r#""signed":true"#));
    m.cortar_a_energia()?;
    if p.estado != "refused" {
        return Err(format!(
            "a fotografia de antes da destruicao nao foi recusada: {} ({})",
            p.estado, p.motivo
        ));
    }
    if assinou {
        return Err("a chave destruida assinou pela fotografia antiga".into());
    }

    // O disco de agora, de volta: abre, e ela continua destruída.
    escrever_no_estado(&disco, &atual)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let lapide =
        super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| ler(&mut a, "chave:bancada-2"));
    m.cortar_a_energia()?;
    let lapide = lapide?;
    if p.estado != "available"
        || texto_do_resultado(&lapide, "state").as_deref() != Some("destroyed")
    {
        return Err(format!(
            "o disco de agora nao abriu com a chave destruida: {}\n  {lapide}",
            p.estado
        ));
    }
    Ok(format!(
        "a viva assina igual depois do corte, a destruida volta destruida, e a fotografia de antes e recusada; no boot, {cofre}"
    ))
}

/// A versão de um caminho do armazém, pelo `fs.stat` — 0 sem arquivo.
fn versao_no_armazem(m: &mut Ligada, caminho: &str) -> Result<u64, String> {
    let r = m.pedir("fs.stat", &format!(r#"{{"path":"{caminho}"}}"#))?;
    r.split(r#""version":"#)
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("fs.stat sem versao\n  {r}"))
}

/// Um pedido ao armazém pela serial, que tem de ser confirmado.
fn no_armazem(m: &mut Ligada, metodo: &str, params: &str) -> Result<String, String> {
    let r = m.pedir(metodo, params)?;
    if !r.contains(r#""ok":true"#) || !r.contains(r#""durable":true"#) {
        return Err(format!("{metodo} {params} nao foi confirmado\n  {r}"));
    }
    Ok(r)
}

/// A GPT diz onde o volume do armazém mora: a quarta partição, do tipo do
/// Duke para o armazém, logo depois da de estado — conferido pelo
/// `sgdisk`, de fora. As duas não se cruzam.
fn a_particao_do_armazem(_: Arquitetura, _: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    let saida = Command::new("sgdisk")
        .args(["-i", "4", &disco.display().to_string()])
        .output()
        .map_err(|e| format!("não foi possível rodar o sgdisk: {e}"))?;
    let texto = String::from_utf8_lossy(&saida.stdout);
    let ultimo = disco::ARMAZEM_EM + disco::ARMAZEM_SETORES - 1;
    for esperado in [
        format!("Partition GUID code: {}", disco::GUID_DO_ARMAZEM),
        format!("First sector: {} ", disco::ARMAZEM_EM),
        format!("Last sector: {ultimo} "),
        "Partition name: 'duke-armazem'".to_string(),
    ] {
        if !texto.contains(&esperado) {
            return Err(format!("o sgdisk não diz `{esperado}`:\n{texto}"));
        }
    }
    if disco::ARMAZEM_EM < disco::ESTADO_EM + disco::ESTADO_SETORES {
        return Err("a partição do armazém cruza a de estado".into());
    }
    Ok(format!(
        "setores {}..={ultimo}, tipo {}",
        disco::ARMAZEM_EM,
        disco::GUID_DO_ARMAZEM
    ))
}

/// O armazém sobrevive ao corte de energia: cada lote confirmado está no
/// volume e confirmado no journal de estado, e o boot o repõe — os mesmos
/// diretórios e arquivos, o mesmo conteúdo, a mesma versão; o apagado
/// continua apagado, o renomeado continua no lugar novo, e a próxima
/// versão não volta a uma já dada. Pela serial, que é do papel `sistema`.
fn o_armazem_sobrevive(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const D: &str = "/armazem/sistema/bancada";
    const A: &str = "/armazem/sistema/bancada/a.txt";
    const B: &str = "/armazem/sistema/bancada/b.txt";
    const C: &str = "/armazem/sistema/bancada/c.txt";
    let mut m = Ligada::subir(arch, artefato, None)?;
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/sistema"}"#)?;
    no_armazem(&mut m, "fs.mkdir", &format!(r#"{{"path":"{D}"}}"#))?;
    let gravar = |m: &mut Ligada, metodo: &str, caminho: &str, conteudo: Option<&str>| {
        let v = versao_no_armazem(m, caminho)?;
        let params = match conteudo {
            Some(t) => format!(r#"{{"path":"{caminho}","content":"{t}","expect_version":{v}}}"#),
            None => format!(r#"{{"path":"{caminho}","expect_version":{v}}}"#),
        };
        no_armazem(m, metodo, &params).map(|_| ())
    };
    gravar(&mut m, "fs.write", A, Some("um"))?;
    gravar(&mut m, "fs.write", B, Some("dois"))?;
    gravar(&mut m, "fs.append", A, Some(" e mais"))?;
    gravar(&mut m, "fs.delete", B, None)?;
    // Um lote: dois arquivos num registro só; e o rename de um deles.
    const E: &str = "/armazem/sistema/bancada/e.txt";
    no_armazem(
        &mut m,
        "fs.batch",
        &format!(
            r#"{{"ops":[{{"op":"write","path":"{B}","content":"de lote","expect_version":0}},{{"op":"write","path":"{E}","content":"tambem","expect_version":0}}]}}"#
        ),
    )?;
    let vb = versao_no_armazem(&mut m, B)?;
    no_armazem(
        &mut m,
        "fs.rename",
        &format!(r#"{{"path":"{B}","to":"{C}","expect_version":{vb}}}"#),
    )?;
    let va = versao_no_armazem(&mut m, A)?;
    let vc = versao_no_armazem(&mut m, C)?;
    m.cortar_a_energia()?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let lido = m.pedir("fs.read", &format!(r#"{{"path":"{A}"}}"#))?;
    let lido_c = m.pedir("fs.read", &format!(r#"{{"path":"{C}"}}"#))?;
    let depois_a = versao_no_armazem(&mut m, A)?;
    let depois_b = versao_no_armazem(&mut m, B)?;
    let depois_c = versao_no_armazem(&mut m, C)?;
    let novo = m.pedir(
        "fs.write",
        &format!(r#"{{"path":"{B}","content":"de novo","expect_version":0}}"#),
    )?;
    m.cortar_a_energia()?;
    if !lido.contains(r#""content":"um e mais""#) || depois_a != va {
        return Err(format!(
            "o arquivo nao voltou igual: versao {depois_a} e nao {va}\n  {lido}"
        ));
    }
    if !lido_c.contains(r#""content":"de lote""#) || depois_c != vc {
        return Err(format!(
            "o renomeado nao voltou no lugar novo: versao {depois_c} e nao {vc}\n  {lido_c}"
        ));
    }
    if depois_b != 0 {
        return Err(format!("um nome que saiu voltou, na versao {depois_b}"));
    }
    let vn = novo
        .split(r#""version":"#)
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| format!("a gravacao depois do corte foi recusada\n  {novo}"))?;
    if vn <= va.max(vc) {
        return Err(format!(
            "depois do corte, a versao {vn} nao passa das ja dadas ({va}, {vc})"
        ));
    }
    Ok(format!(
        "{A} na versao {va} e {C} na {vc}, iguais depois do corte; o que saiu nao voltou; a seguinte foi {vn}"
    ))
}

/// Os bytes do volume do armazém, inteiros.
fn ler_o_armazem(disco: &Path) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut arquivo = std::fs::File::open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    let mut bytes = vec![0u8; (disco::ARMAZEM_SETORES * 512) as usize];
    arquivo
        .seek(SeekFrom::Start(disco::ARMAZEM_EM * 512))
        .and_then(|_| arquivo.read_exact(&mut bytes))
        .map_err(|e| format!("não foi possível ler o volume do armazém: {e}"))?;
    Ok(bytes)
}

/// Devolve o volume do armazém a uma fotografia.
fn escrever_no_armazem(disco: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let mut arquivo = std::fs::OpenOptions::new()
        .write(true)
        .open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))?;
    arquivo
        .seek(SeekFrom::Start(disco::ARMAZEM_EM * 512))
        .and_then(|_| arquivo.write_all(bytes))
        .and_then(|()| arquivo.sync_all())
        .map_err(|e| format!("não foi possível escrever no volume do armazém: {e}"))
}

/// O volume devolvido a uma fotografia anterior: o journal de estado diz
/// que o último lote é um que o volume não tem — o volume não chega à
/// âncora confirmada, e o armazém fica indisponível, com o motivo. O
/// estado de autoridade não é do volume: a persistência segue disponível,
/// e uma operação que não é do armazém continua gravando.
fn o_volume_antigo_e_recusado(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const A: &str = "/armazem/sistema/a.txt";
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/sistema"}"#)?;
    no_armazem(
        &mut m,
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"um","expect_version":0}}"#),
    )?;
    let v1 = versao_no_armazem(&mut m, A)?;
    m.cortar_a_energia()?;
    let foto = ler_o_armazem(&disco)?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    no_armazem(
        &mut m,
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"dois","expect_version":{v1}}}"#),
    )?;
    m.cortar_a_energia()?;
    escrever_no_armazem(&disco, &foto)?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let estado = m.pedir("fs.stat", &format!(r#"{{"path":"{A}"}}"#))?;
    let gravar = m.pedir(
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"tres","expect_version":{v1}}}"#),
    )?;
    let p = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;
    if gravar.contains(r#""ok":true"#) {
        return Err(format!(
            "o volume antigo aceitou uma gravacao por cima do que o journal de estado confirmou\n  {gravar}"
        ));
    }
    if estado.contains(r#""content":"um""#) {
        return Err(format!("o volume antigo foi lido como atual\n  {estado}"));
    }
    if p.estado != "available" {
        return Err(format!(
            "o volume antigo derrubou o estado de autoridade: a persistencia esta {}",
            p.estado
        ));
    }
    Ok(format!(
        "a gravacao foi recusada ({}), e a persistencia segue {}",
        gravar
            .split(r#""error":""#)
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap_or("?"),
        p.estado
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
pub(crate) const FEATURE_DE_QUEDAS: &str = "quedas";

/// Os pontos de queda, com os números de `kernel/src/quedas.rs`.
pub(crate) mod ponto {
    pub const ANCORA_DEFINIDA: u8 = 1;
    pub const ANCORA_AVANCADA: u8 = 2;
    pub const NASCIMENTO_GUARDADO: u8 = 3;
    pub const ANTES_DA_ESCRITA: u8 = 10;
    pub const DEPOIS_DA_ESCRITA: u8 = 11;
    pub const DEPOIS_DA_DESCARGA: u8 = 12;
    pub const DEPOIS_DO_CONTADOR: u8 = 13;
    pub const DEPOIS_DA_PRIMEIRA_PARTE: u8 = 14;
    pub const DEPOIS_DO_INCREMENTO: u8 = 15;
    pub const DEPOIS_DA_CHAVE: u8 = 16;
    pub const LOTE_NO_VOLUME: u8 = 17;
    pub const GERACAO_PENDENTE: u8 = 18;
    pub const GERACAO_AVANCADA: u8 = 19;
    pub const ANTIGAS_SELADAS: u8 = 20;
    pub const LIMPEZA_COMECOU: u8 = 21;
    pub const LIMPEZA_NO_MEIO: u8 = 22;
    pub const LIMPEZA_TERMINADA: u8 = 23;
    pub const IDENTIDADE_SELADA: u8 = 27;
    pub const PRIMEIRA_COPIA: u8 = 28;
    pub const IDENTIDADE_GRAVADA: u8 = 29;
    pub const TROCA_DIGITADA: u8 = 30;
    pub const SENHA_CONFERIDA: u8 = 31;
    pub const TROCA_AUTORIZADA: u8 = 32;
    pub const TROCA_GRAVADA: u8 = 33;
    pub const COPIA_NO_MEIO: u8 = 34;
    pub const RESTAURACAO_CONFERIDA: u8 = 35;
    pub const RESTAURACAO_NA_PRIMEIRA_PARTE: u8 = 36;
    pub const RESTAURACAO_NA_BASE: u8 = 37;
    pub const RESTAURACAO_GRAVADA: u8 = 38;
}

/// Quanto esperar o aviso da queda depois do pedido que a provoca.
pub(crate) const ESPERA_PELA_QUEDA: Duration = Duration::from_secs(60);

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
/// Os tipos de registro do journal, para o plano de queda: a n-ésima
/// gravação de um tipo. Ver `diario::estado::tipo`.
pub(crate) mod tipo {
    pub use diario::estado::tipo::{
        ABERTURA, ARMAZEM, AUDITORIA, BASE_FIM, MENSAGENS, OPERACAO, SELAGEM,
    };
}

/// O plano: a energia cai no `ponto` da `gravacao`-ésima gravação de um
/// registro do tipo `tipo` desde o boot.
fn plano_de_queda(disco: &Path, ponto: u8, tipo: u16, gravacao: u32) -> Result<(), String> {
    plano(
        disco,
        Plano {
            ponto,
            tipo,
            gravacao,
            ..Plano::default()
        },
    )
}

/// O plano inteiro da bancada — ver `kernel/src/quedas.rs`.
#[derive(Clone, Copy, Default)]
pub(crate) struct Plano {
    /// Onde a energia cai; zero, em lugar nenhum.
    pub(crate) ponto: u8,
    pub(crate) tipo: u16,
    pub(crate) gravacao: u32,
    /// O tamanho de cada região do journal, em setores.
    pub(crate) limite: Option<u64>,
    /// Bit 0: o coletor não compacta; bit 1: o boot não compacta.
    pub(crate) bandeiras: u8,
}

/// O coletor não compacta.
const COLETOR_NAO_COMPACTA: u8 = 1;
/// O boot não compacta.
const BOOT_NAO_COMPACTA: u8 = 2;
/// A criação do journal espera, cedendo, antes de gravar a abertura.
const ESPERAR_NA_ABERTURA: u8 = 4;
/// O contador anda uma vez "de fora" no boot, antes de ser lido.
const CONTADOR_DE_FORA: u8 = 8;
/// O kernel no formato de antes do cofre: a criação grava a semente no
/// journal, e o boot não abre o cofre nem migra — ver `kernel/src/quedas.rs`.
const CHAVES_ANTIGAS: u8 = 16;

pub(crate) fn plano(disco: &Path, p: Plano) -> Result<(), String> {
    let mut setor = [0u8; 512];
    setor[..8].copy_from_slice(b"DUKEQUED");
    setor[8] = p.ponto;
    setor[12..16].copy_from_slice(&p.gravacao.to_le_bytes());
    setor[16..18].copy_from_slice(&p.tipo.to_le_bytes());
    setor[18..26].copy_from_slice(&p.limite.unwrap_or(0).to_le_bytes());
    setor[26] = p.bandeiras;
    escrever_setor_do_estado(disco, disco::ESTADO_SETORES - 1, &setor)
}

pub(crate) fn sem_plano(disco: &Path) -> Result<(), String> {
    escrever_setor_do_estado(disco, disco::ESTADO_SETORES - 1, &[0; 512])
}

/// Os registros do journal no disco, pelo cabeçalho em claro de cada um,
/// nas duas regiões — com o tamanho delas que o plano da bancada diz:
/// onde começa (na partição), quantos setores tem e a âncora. Em cada
/// região, para no primeiro setor que não é cabeçalho.
fn registros_no_disco(disco: &Path, limite: Option<u64>) -> Result<Vec<(u64, u64, u64)>, String> {
    let estado = ler_o_estado(disco)?;
    let mut v = Vec::new();
    for (inicio, tamanho) in diario::regioes(disco::ESTADO_SETORES, limite) {
        let mut setor = inicio as usize;
        let fim = (inicio + tamanho) as usize;
        while setor < fim {
            let Some(c) = estado.get(setor * 512..setor * 512 + 64) else {
                break;
            };
            if &c[..8] != b"DUKEDIA1" {
                break;
            }
            let n = u32::from_le_bytes([c[12], c[13], c[14], c[15]]) as usize;
            if n == 0 {
                break;
            }
            let mut ancora = [0u8; 8];
            ancora.copy_from_slice(&c[24..32]);
            v.push((setor as u64, n as u64, u64::from_le_bytes(ancora)));
            setor += n;
        }
    }
    Ok(v)
}

/// O primeiro setor do último registro confirmado pelo contador do TPM: o
/// primeiro, na sequência, dos de âncora maior. Não é sempre o último no
/// disco: um registro só de auditoria não avança a âncora — as leituras do
/// NSF depois de uma operação, por exemplo —, e o contador não protege o
/// rabo que eles fazem; estragar um deles é só perder o rabo.
fn ultimo_confirmado(disco: &Path) -> Result<u64, String> {
    let estado = ler_o_estado(disco)?;
    let registros = registros_no_disco(disco, None)?;
    let maior = registros
        .iter()
        .map(|&(_, _, a)| a)
        .max()
        .ok_or("o journal esta vazio")?;
    let sequencia = |setor: u64| {
        let c = setor as usize * 512;
        estado
            .get(c + 16..c + 24)
            .and_then(|b| b.try_into().ok())
            .map_or(u64::MAX, u64::from_le_bytes)
    };
    registros
        .into_iter()
        .filter(|&(_, _, a)| a == maior)
        .min_by_key(|&(s, _, _)| sequencia(s))
        .map(|(s, _, _)| s)
        .ok_or_else(|| "o journal esta vazio".to_string())
}

/// Troca um bit no meio do texto cifrado do registro que começa no setor
/// `inicio`: a etiqueta não confere, e o registro não abre.
fn estragar_o_registro(disco: &Path, inicio: u64) -> Result<(), String> {
    let mut estado = ler_o_estado(disco)?;
    let c = inicio as usize * 512;
    let tamanho = estado
        .get(c + 32..c + 36)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes) as usize;
    let byte = (tamanho > 0)
        .then(|| estado.get_mut(c + 64 + tamanho / 2))
        .flatten()
        .ok_or_else(|| format!("o registro do setor {inicio} nao tem texto cifrado"))?;
    *byte ^= 0x40;
    escrever_no_estado(disco, &estado)
}

/// A escrita que não foi descarregada se perde: os setores do último
/// registro escrito — o de âncora maior, e entre esses o que está mais
/// adiante, que numa base é o fecho — voltam a zero, como num disco que
/// não chegou a gravá-los.
pub(crate) fn perder_o_ultimo_registro(disco: &Path, limite: Option<u64>) -> Result<(), String> {
    let (inicio, n, _) = registros_no_disco(disco, limite)?
        .into_iter()
        .max_by_key(|&(s, _, a)| (a, s))
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
    pub(crate) fn pedir_ate_cair(mut self, metodo: &str, params: &str) -> Result<u8, String> {
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
    pub(crate) fn esperar_a_queda(mut self) -> Result<u8, String> {
        let caiu = esperar_o_aviso(&mut self.leitor, ESPERA_PELA_QUEDA);
        self.cortar_a_energia()?;
        caiu
    }
}

/// Liga a máquina com um plano que a faz cair no boot, antes de o canal
/// atender: lê a serial desde o começo até o aviso, e corta a energia.
pub(crate) fn subir_ate_cair(arch: Arquitetura, artefato: &Artefato) -> Result<u8, String> {
    subir_ate_cair_em(arch, artefato, ESPERA_PELO_BOOT)
}

/// [`subir_ate_cair`], esperando o aviso por `espera`: a queda num boot que
/// vem depois de outros — uma tentativa da atualização — demora mais.
pub(crate) fn subir_ate_cair_em(
    arch: Arquitetura,
    artefato: &Artefato,
    espera: Duration,
) -> Result<u8, String> {
    subir_ate_cair_com(arch, artefato, Ambiente::ligar(arch, None)?, espera)
}

/// [`subir_ate_cair_em`] no ambiente dado — o disco de uma imagem de
/// produção, digamos.
pub(crate) fn subir_ate_cair_com(
    arch: Arquitetura,
    artefato: &Artefato,
    mut ambiente: Ambiente,
    espera: Duration,
) -> Result<u8, String> {
    let (mut filho, socket) = lancar(arch, artefato, &ambiente)?;
    let limite = std::time::Instant::now() + espera;
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
        esperar_o_aviso(&mut BufReader::new(f), espera)
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

/// O registro de estado que confirma a criação do volume do armazém: um, no
/// primeiro boot que abre o journal sobre um disco zerado — o volume nasce
/// confirmado pelo journal de estado, como cada lote depois dele. Os
/// cenários que contam registros contam este também.
const CRIACAO_DO_VOLUME: u64 = 1;

/// O registro da linha de base da atualização A/B — ver
/// `docs/ATUALIZACAO.md`: o primeiro boot de um kernel vindo de um slot,
/// numa máquina sem estado de atualização, grava um registro de estado, e a
/// auditoria pendente vai junto com ele. Pelo firmware — o disco de testes,
/// no x86 — o kernel vem do slot A; pelo `-kernel` — o ARM da bancada —, de
/// fora de um slot, e a linha de base não existe. Os cenários que contam
/// registros contam este também.
fn linha_de_base(artefato: &Artefato) -> u64 {
    u64::from(matches!(artefato, Artefato::Disco(_)))
}

/// O caso de uma queda dentro de uma gravação: o ponto, se a escrita sem
/// descarga se perde, se a operação vale depois, e como se lê.
pub(crate) type Caso = (u8, bool, bool, &'static str);

/// As quedas dentro de uma gravação, em cada fronteira. Valer ou não valer
/// é o que o ponto decide; o que nunca pode acontecer é o boot seguinte
/// recusar, ou o próximo registro não gravar.
pub(crate) const QUEDAS_NA_GRAVACAO: [Caso; 6] = [
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
        ponto::DEPOIS_DO_INCREMENTO,
        false,
        true,
        "depois do incremento, antes da leitura de volta",
    ),
    (
        ponto::DEPOIS_DO_CONTADOR,
        false,
        true,
        "depois do contador, antes da resposta",
    ),
];

/// As quedas dentro de um registro só de auditoria: as mesmas, menos a do
/// incremento — um registro só de auditoria não avança o contador, e não há
/// incremento no meio dele.
const QUEDAS_NA_AUDITORIA: [Caso; 5] = [
    QUEDAS_NA_GRAVACAO[0],
    QUEDAS_NA_GRAVACAO[1],
    QUEDAS_NA_GRAVACAO[2],
    QUEDAS_NA_GRAVACAO[3],
    QUEDAS_NA_GRAVACAO[5],
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
/// descarregar e antes do contador, depois do incremento e antes da
/// leitura de volta, depois do contador e antes da resposta. Em todos, o boot seguinte sobe com a persistência de pé, a operação vale
/// exatamente quando o registro dela está no disco, e a próxima operação
/// grava e sobrevive a mais um boot.
fn as_quedas_numa_operacao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    for (i, (ponto, perder, vale, caso)) in QUEDAS_NA_GRAVACAO.into_iter().enumerate() {
        zerar_o_estado(arch)?;
        // A primeira operação do boot.
        plano_de_queda(&disco, ponto, tipo::OPERACAO, 1)?;
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
            perder_o_ultimo_registro(&disco, None)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        // Valendo: abertura, a criação do volume, a linha de base, boot, a
        // operação e o boot de agora.
        conferir_depois_da_queda(
            &p,
            caso,
            CRIACAO_DO_VOLUME + linha_de_base(artefato) + if vale { 4 } else { 3 },
            u64::from(vale),
        )?;
        if agente_entra(arch, &privada, &nome)? != vale {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: o agente {} depois da queda",
                if vale { "nao entrou" } else { "entrou" }
            ));
        }
        // A decisão que autorizou a operação está na auditoria exatamente
        // quando a operação está no journal: as duas vão no mesmo registro.
        let cauda = cauda_da_auditoria(&mut m)?;
        let decidida = cauda.iter().any(|r| {
            r.metodo == "agent.register" && r.codigo == "ALLOW" && r.recurso == nome && r.duravel
        });
        if decidida != vale {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: a decisao da operacao {} na auditoria, e a operacao {}",
                if decidida { "esta" } else { "nao esta" },
                if vale { "vale" } else { "nao vale" }
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
        conferir_depois_da_queda(
            &p,
            caso,
            CRIACAO_DO_VOLUME + linha_de_base(artefato) + if vale { 6 } else { 5 },
            u64::from(vale) + 1,
        )?;
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
        plano_de_queda(&disco, ponto, tipo::MENSAGENS, 1)?;
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
            perder_o_ultimo_registro(&disco, None)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        // A mensagem não sobe a geração.
        conferir_depois_da_queda(
            &p,
            caso,
            CRIACAO_DO_VOLUME + linha_de_base(artefato) + if vale { 4 } else { 3 },
            0,
        )?;
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

/// Pede `metodo` na porta 1 até a energia cair no meio dele: o pedido não
/// volta — a máquina congela —, e o aviso da queda vem pela serial.
fn pedir_na_porta_ate_cair(
    arch: Arquitetura,
    m: Ligada,
    metodo: &'static str,
    params: &'static str,
) -> Result<u8, String> {
    let fio = std::thread::spawn(move || {
        super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| a.pedir(metodo, params))
    });
    let caiu = m.esperar_a_queda();
    let _ = fio.join();
    caiu
}

/// A queda em cada fronteira da gravação de uma chave de assinatura: na
/// criação — a semente no journal, a primeira operação do boot — e na
/// destruição — a lápide, a primeira operação do boot seguinte ao da
/// criação. A chave existe depois exatamente quando o registro da criação
/// está no disco, e o nome de uma criação que não ficou volta livre: não
/// houve chave, e não há lápide. A destruída fica destruída exatamente
/// quando o registro da lápide está no disco, e não assina; quando não
/// está, a destruição não foi respondida, e a chave volta viva, com a
/// mesma privada.
fn as_quedas_numa_chave(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const CRIAR: &str = r#"{"key":"chave:bancada","domain":"ic-request"}"#;
    const CHAVE: &str = r#"{"key":"chave:bancada"}"#;
    let disco = disco_de_testes()?;
    let assinar = format!(
        r#"{{"key":"chave:bancada","domain":"ic-request","digest":"{}"}}"#,
        "5a".repeat(32)
    );
    for (ponto, perder, vale, caso) in QUEDAS_NA_GRAVACAO {
        // A criação.
        zerar_o_estado(arch)?;
        plano_de_queda(&disco, ponto, tipo::OPERACAO, 1)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let caiu = pedir_na_porta_ate_cair(arch, m, "key.create", CRIAR)?;
        if caiu != ponto {
            return Err(format!(
                "{caso}, na criacao: caiu no ponto {caiu}, e nao no {ponto}"
            ));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco, None)?;
        }
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        let depois = super::AgenteNaPorta::conectar(arch, 1)
            .and_then(|mut a| Ok((a.pedir("key.read", CHAVE)?, a.pedir("key.create", CRIAR)?)));
        m.cortar_a_energia()?;
        // Abertura, a criação do volume, a linha de base, o boot que caiu,
        // a criação se valeu, e o boot de agora; a criação sobe a geração.
        conferir_depois_da_queda(
            &p,
            &format!("{caso}, na criacao"),
            CRIACAO_DO_VOLUME + linha_de_base(artefato) + if vale { 4 } else { 3 },
            u64::from(vale),
        )?;
        let (lida, de_novo) = depois?;
        let viva = texto_do_resultado(&lida, "state").as_deref() == Some("active");
        let nome_livre = de_novo.contains(r#""created":true"#);
        if viva != vale || nome_livre == vale {
            return Err(format!(
                "{caso}, na criacao: a chave {} depois da queda, e o nome {}\n  {lida}\n  {de_novo}",
                if viva { "existe" } else { "nao existe" },
                if nome_livre {
                    "voltou livre"
                } else {
                    "ficou preso"
                }
            ));
        }

        // A destruição: a chave criada, e a assinatura dela, num boot; a
        // lápide no seguinte.
        zerar_o_estado(arch)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let assinada = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
            a.pedir("key.create", CRIAR)?;
            a.pedir("key.sign", &assinar)
        });
        m.cortar_a_energia()?;
        let assinada = assinada?;
        let assinatura = texto_do_resultado(&assinada, "signature")
            .ok_or_else(|| format!("{caso}: a chave da destruicao nao assinou\n  {assinada}"))?;
        plano_de_queda(&disco, ponto, tipo::OPERACAO, 1)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let antes = persistencia_de(&mut m)?;
        let caiu = pedir_na_porta_ate_cair(arch, m, "key.destroy", CHAVE)?;
        if caiu != ponto {
            return Err(format!(
                "{caso}, na destruicao: caiu no ponto {caiu}, e nao no {ponto}"
            ));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco, None)?;
        }
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        let depois = super::AgenteNaPorta::conectar(arch, 1)
            .and_then(|mut a| Ok((a.pedir("key.read", CHAVE)?, a.pedir("key.sign", &assinar)?)));
        m.cortar_a_energia()?;
        if p.estado != "available" || p.geracao != antes.geracao + u64::from(vale) {
            return Err(format!(
                "{caso}, na destruicao: a persistencia {} ({}), geracao {} depois de {}",
                p.estado, p.motivo, p.geracao, antes.geracao
            ));
        }
        let (lida, de_novo) = depois?;
        let destruida = texto_do_resultado(&lida, "state").as_deref() == Some("destroyed");
        let assinou_igual =
            texto_do_resultado(&de_novo, "signature").as_deref() == Some(assinatura.as_str());
        if destruida != vale || assinou_igual == vale {
            return Err(format!(
                "{caso}, na destruicao: a chave {} depois da queda, e {}\n  {lida}\n  {de_novo}",
                if destruida { "destruida" } else { "viva" },
                if assinou_igual {
                    "assinou com a mesma privada"
                } else {
                    "nao assinou"
                }
            ));
        }
    }
    Ok(format!(
        "{} quedas em cada uma: a chave existe exatamente quando a criacao esta no disco, e morre exatamente quando a lapide esta",
        QUEDAS_NA_GRAVACAO.len()
    ))
}

/// A morte de uma chave em três passos — o registro com a lápide, o selado
/// da viva para a geração seguinte e a pendente; o índice de geração
/// avançado; o registro que confirma —, e a energia caindo entre eles e
/// dentro da confirmação. A morte vale em todos: o registro dela estava no
/// disco antes de o índice andar. O boot seguinte completa o avanço, ou o
/// confirma, e sobe com a persistência de pé; a viva, aberta do cofre na
/// geração nova, assina igual; e mais um boot dá o mesmo.
fn as_quedas_na_geracao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const VIVA: &str = r#"{"key":"chave:bancada","domain":"ic-request"}"#;
    const MORTA: &str = r#"{"key":"chave:bancada-2","domain":"ic-request"}"#;
    const A_VIVA: &str = r#"{"key":"chave:bancada"}"#;
    const A_MORTA: &str = r#"{"key":"chave:bancada-2"}"#;
    let disco = disco_de_testes()?;
    let assinar = format!(
        r#"{{"key":"chave:bancada","domain":"ic-request","digest":"{}"}}"#,
        "5d".repeat(32)
    );
    let casos: [(u8, u16, bool, &str); 7] = [
        (
            ponto::GERACAO_PENDENTE,
            tipo::OPERACAO,
            false,
            "com os selados no journal, antes do avanco do indice",
        ),
        (
            ponto::GERACAO_AVANCADA,
            tipo::OPERACAO,
            false,
            "com o indice avancado, antes da confirmacao",
        ),
        (
            ponto::ANTES_DA_ESCRITA,
            tipo::SELAGEM,
            false,
            "na confirmacao, antes da escrita",
        ),
        (
            ponto::DEPOIS_DA_ESCRITA,
            tipo::SELAGEM,
            true,
            "na confirmacao, com a escrita perdida sem a descarga",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            tipo::SELAGEM,
            false,
            "na confirmacao, antes do contador",
        ),
        (
            ponto::DEPOIS_DO_INCREMENTO,
            tipo::SELAGEM,
            false,
            "na confirmacao, depois do incremento",
        ),
        (
            ponto::DEPOIS_DO_CONTADOR,
            tipo::SELAGEM,
            false,
            "na confirmacao, depois do contador",
        ),
    ];
    for (ponto, tipo_do_plano, perder, caso) in casos {
        zerar_o_estado(arch)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let feito = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
            a.pedir("key.create", VIVA)?;
            a.pedir("key.create", MORTA)?;
            a.pedir("key.sign", &assinar)
        });
        m.cortar_a_energia()?;
        let feito = feito?;
        let assinatura = texto_do_resultado(&feito, "signature")
            .ok_or_else(|| format!("{caso}: a viva nao assinou\n  {feito}"))?;
        plano_de_queda(&disco, ponto, tipo_do_plano, 1)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let caiu = pedir_na_porta_ate_cair(arch, m, "key.destroy", A_MORTA)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco, None)?;
        }
        for boot in ["no boot seguinte", "em mais um boot"] {
            let mut m = Ligada::subir(arch, artefato, None)?;
            let p = persistencia_de(&mut m)?;
            let depois = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
                Ok((
                    a.pedir("key.read", A_MORTA)?,
                    a.pedir("key.read", A_VIVA)?,
                    a.pedir("key.sign", &assinar)?,
                ))
            });
            m.cortar_a_energia()?;
            if p.estado != "available" {
                return Err(format!(
                    "{caso}, {boot}: a persistencia {} ({})",
                    p.estado, p.motivo
                ));
            }
            let (morta, viva, de_novo) = depois?;
            if texto_do_resultado(&morta, "state").as_deref() != Some("destroyed") {
                return Err(format!("{caso}, {boot}: a morte nao valeu\n  {morta}"));
            }
            if texto_do_resultado(&viva, "seal").as_deref() != Some("tpm")
                || texto_do_resultado(&de_novo, "signature").as_deref() != Some(assinatura.as_str())
            {
                return Err(format!(
                    "{caso}, {boot}: a viva nao voltou selada com a mesma privada\n  {viva}\n  {de_novo}"
                ));
            }
        }
    }
    Ok(format!(
        "{} quedas: a morte vale em todas, o boot completa o avanco ou o confirma, e a viva assina igual",
        casos.len()
    ))
}

/// Uma região do journal lida de uma fotografia da partição de estado,
/// para o hospedeiro percorrer com o `diario`.
struct RegiaoNaMemoria<'a> {
    bytes: &'a [u8],
}

impl diario::Meio for RegiaoNaMemoria<'_> {
    fn setores(&self) -> u64 {
        (self.bytes.len() / 512) as u64
    }

    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let i = setor as usize * 512;
        let origem = self
            .bytes
            .get(i..i + destino.len())
            .ok_or("leitura fora da regiao")?;
        destino.copy_from_slice(origem);
        Ok(())
    }

    fn escrever(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
        Err("so leitura")
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        Err("so leitura")
    }
}

/// A chave do journal, derivada da chave do Duke como o kernel a deriva:
/// quem tem o disco também a tem — a chave do Duke mora nele.
fn chave_do_journal(duke: &[u8; 32]) -> [u8; 32] {
    sigilo::resumo::hkdf_rfc5869(b"Duke persistencia v1", duke, &[b"journal: cifra"])
}

/// As duas regiões de uma fotografia da partição de estado, percorridas com
/// a chave do journal: cada registro que abre vai a `f`. Devolve o
/// percurso de cada uma.
fn percorrer_as_regioes(
    estado: &[u8],
    chave: &[u8; 32],
    mut f: impl FnMut(&diario::Registro),
) -> [diario::Percorrido; 2] {
    diario::regioes(disco::ESTADO_SETORES, None).map(|(inicio, tamanho)| {
        let fim = ((inicio + tamanho) as usize * 512).min(estado.len());
        let mut meio = RegiaoNaMemoria {
            bytes: &estado[inicio as usize * 512..fim],
        };
        diario::percorrer(&mut meio, chave, |r| {
            f(&r);
            Ok::<(), ()>(())
        })
        .unwrap_or_else(|_| diario::Percorrido::vazio())
    })
}

/// As entradas de um registro aberto, como campos: a lista de campos de
/// cada uma, das que se leem.
fn entradas_abertas(r: &diario::Registro) -> Vec<Vec<&[u8]>> {
    diario::estado::ler_campos(&r.conteudo)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| diario::estado::ler_campos(e).ok())
        .collect()
}

/// As sementes do formato de antes do cofre numa fotografia da partição: as
/// das entradas de criação que a chave do journal abre — o que quem tem o
/// disco lê dele.
fn sementes_antigas(estado: &[u8], duke: &[u8; 32]) -> Vec<[u8; 32]> {
    let criada = diario::estado::tipo::CHAVE_CRIADA.to_le_bytes();
    let mut v = Vec::new();
    percorrer_as_regioes(estado, &chave_do_journal(duke), |r| {
        for c in entradas_abertas(r) {
            if c.len() == 6
                && c[0] == &criada[..]
                && let Ok(s) = <[u8; 32]>::try_from(c[5])
                && !v.contains(&s)
            {
                v.push(s);
            }
        }
    });
    v
}

/// O disco depois da migração: nenhuma das `sementes` em claro em setor
/// nenhum, nem em registro nenhum que a chave do journal abra, em nenhuma
/// das regiões; nenhuma entrada do formato de antes; e, fora do journal —
/// tirada a reserva do fim —, só zeros.
fn o_disco_sem_as_sementes(
    disco: &Path,
    duke: &[u8; 32],
    sementes: &[[u8; 32]],
) -> Result<(), String> {
    let estado = ler_o_estado(disco)?;
    if sementes.iter().any(|s| estado.windows(32).any(|w| w == s)) {
        return Err("uma semente antiga em claro no disco".into());
    }
    let criada = diario::estado::tipo::CHAVE_CRIADA.to_le_bytes();
    let (mut com_semente, mut antigas) = (false, 0);
    let percorridas = percorrer_as_regioes(&estado, &chave_do_journal(duke), |r| {
        com_semente |= sementes
            .iter()
            .any(|s| r.conteudo.windows(32).any(|w| w == s));
        antigas += entradas_abertas(r)
            .iter()
            .filter(|c| c.first().copied() == Some(&criada[..]))
            .count();
    });
    if com_semente || antigas > 0 {
        return Err(format!(
            "o journal ainda abre o formato de antes: semente {com_semente}, {antigas} entradas"
        ));
    }
    let i = diario::escolher(&percorridas).ok_or("nenhuma regiao do journal esta inteira")?;
    let (inicio, _) = diario::regioes(disco::ESTADO_SETORES, None)[i];
    let fim = inicio + percorridas[i].proximo_setor;
    let reserva = disco::ESTADO_SETORES - diario::RESERVA_NO_FIM;
    for (s, setor) in estado.chunks(512).enumerate() {
        let s = s as u64;
        if (inicio..fim).contains(&s) || s >= reserva {
            continue;
        }
        if setor.iter().any(|&b| b != 0) {
            return Err(format!("o setor {s}, fora do journal, nao foi zerado"));
        }
    }
    Ok(())
}

/// A migração das chaves do formato de antes do cofre, com a energia
/// caindo em cada passo dela: as antigas seladas no TPM; o registro da
/// migração; a compactação; a limpeza, no começo, no meio e no fim; e o
/// registro do fim dela. O journal antigo é de verdade: o kernel da
/// bancada, no formato de antes, cria duas chaves — a semente no journal —
/// e destrói uma. Em cada queda, o boot seguinte termina a migração: sobe
/// de pé, a viva volta selada e assina igual, a morta continua morta, e o
/// disco fica sem nenhuma das sementes antigas — nem em claro, nem num
/// registro que a chave do journal abra — e só com zeros fora do journal.
fn as_quedas_na_migracao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const VIVA: &str = r#"{"key":"chave:bancada","domain":"ic-request"}"#;
    const MORTA: &str = r#"{"key":"chave:bancada-2","domain":"ic-request"}"#;
    const A_VIVA: &str = r#"{"key":"chave:bancada"}"#;
    const A_MORTA: &str = r#"{"key":"chave:bancada-2"}"#;
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let assinar = format!(
        r#"{{"key":"chave:bancada","domain":"ic-request","digest":"{}"}}"#,
        "5e".repeat(32)
    );
    // O journal de antes do cofre.
    zerar_o_estado(arch)?;
    plano(
        &disco,
        Plano {
            bandeiras: CHAVES_ANTIGAS | COLETOR_NAO_COMPACTA | BOOT_NAO_COMPACTA,
            ..Plano::default()
        },
    )?;
    let m = Ligada::subir_com(arch, artefato, Ambiente::ligar(arch, None)?)?;
    let feito = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
        let criada = a.pedir("key.create", VIVA)?;
        a.pedir("key.create", MORTA)?;
        a.pedir("key.destroy", A_MORTA)?;
        Ok((criada, a.pedir("key.sign", &assinar)?))
    });
    m.cortar_a_energia()?;
    let (criada, assinada) = feito?;
    if texto_do_resultado(&criada, "seal").as_deref() != Some("none") {
        return Err(format!(
            "o kernel de antes do cofre selou a chave\n  {criada}"
        ));
    }
    let assinatura = texto_do_resultado(&assinada, "signature")
        .ok_or_else(|| format!("a chave antiga nao assinou\n  {assinada}"))?;
    sem_plano(&disco)?;
    let antes = ler_o_estado(&disco)?;
    let sementes = sementes_antigas(&antes, &chaves.duke);
    if sementes.len() != 2 {
        return Err(format!(
            "o journal antigo devia abrir as duas sementes, e abre {}",
            sementes.len()
        ));
    }
    let tpm = diretorio_do_tpm(arch).join("estado");
    let tpm_antes = diretorio_do_tpm(arch).join("antes-do-cofre");
    copiar_diretorio(&tpm, &tpm_antes)?;

    let casos: [(u8, u16, u32, &str); 10] = [
        (
            ponto::ANTIGAS_SELADAS,
            0,
            0,
            "com as antigas seladas no TPM, antes do registro",
        ),
        (
            ponto::ANTES_DA_ESCRITA,
            tipo::SELAGEM,
            1,
            "no registro da migracao, antes da escrita",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            tipo::SELAGEM,
            1,
            "no registro da migracao, antes do contador",
        ),
        (
            ponto::DEPOIS_DO_CONTADOR,
            tipo::SELAGEM,
            1,
            "no registro da migracao, depois do contador",
        ),
        (
            ponto::DEPOIS_DA_PRIMEIRA_PARTE,
            tipo::BASE_FIM,
            1,
            "na compactacao, com a primeira parte escrita",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            tipo::BASE_FIM,
            1,
            "na compactacao, antes do contador",
        ),
        (ponto::LIMPEZA_COMECOU, 0, 0, "compactado, antes de zerar"),
        (ponto::LIMPEZA_NO_MEIO, 0, 0, "no meio da limpeza"),
        (
            ponto::LIMPEZA_TERMINADA,
            0,
            0,
            "zerado, antes do registro do fim",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            tipo::SELAGEM,
            2,
            "no registro do fim da limpeza, antes do contador",
        ),
    ];
    for (ponto, tipo_do_plano, gravacao, caso) in casos {
        escrever_no_estado(&disco, &antes)?;
        copiar_diretorio(&tpm_antes, &tpm)?;
        plano(
            &disco,
            Plano {
                ponto,
                tipo: tipo_do_plano,
                gravacao,
                ..Plano::default()
            },
        )?;
        let caiu = subir_ate_cair(arch, artefato)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        for boot in ["no boot seguinte", "em mais um boot"] {
            let mut m = Ligada::subir(arch, artefato, None)?;
            let p = persistencia_de(&mut m)?;
            let depois = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
                Ok((
                    a.pedir("key.read", A_VIVA)?,
                    a.pedir("key.read", A_MORTA)?,
                    a.pedir("key.sign", &assinar)?,
                ))
            });
            m.cortar_a_energia()?;
            if p.estado != "available" {
                return Err(format!(
                    "{caso}, {boot}: a persistencia {} ({})",
                    p.estado, p.motivo
                ));
            }
            let (viva, morta, de_novo) = depois?;
            if texto_do_resultado(&viva, "seal").as_deref() != Some("tpm")
                || texto_do_resultado(&de_novo, "signature").as_deref() != Some(assinatura.as_str())
            {
                return Err(format!(
                    "{caso}, {boot}: a antiga nao voltou selada com a mesma privada\n  {viva}\n  {de_novo}"
                ));
            }
            if texto_do_resultado(&morta, "state").as_deref() != Some("destroyed") {
                return Err(format!("{caso}, {boot}: a morta voltou\n  {morta}"));
            }
            o_disco_sem_as_sementes(&disco, &chaves.duke, &sementes)
                .map_err(|e| format!("{caso}, {boot}: {e}"))?;
        }
    }
    Ok(format!(
        "{} quedas: a migracao termina em todas, a antiga assina igual selada, e nenhuma semente fica no disco",
        casos.len()
    ))
}

/// A queda em cada fronteira de um registro só de auditoria: o primeiro
/// que o coletor grava depois do boot, que leva o `persistence.open` do
/// boot. O boot seguinte sobe com a persistência de pé; o registro vale
/// exatamente quando está no disco — o `persistence.open` do boot que
/// caiu está na cadeia, ou não está —; a cadeia continua do que foi
/// gravado e se verifica; e a próxima operação grava a decisão dela.
///
/// O boot que cai não é o primeiro da máquina, que tem gravações só dele:
/// a criação, e — pelo firmware, de um slot — a linha de base da
/// atualização A/B, um registro de estado que leva a auditoria pendente se
/// ganha do coletor a corrida até o journal. Um boot antes, sem plano, até
/// a auditoria dele estar gravada, e o que cai é um boot comum: depois da
/// abertura, só o coletor grava.
fn as_quedas_na_auditoria(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    for (i, (ponto, perder, vale, caso)) in QUEDAS_NA_AUDITORIA.into_iter().enumerate() {
        zerar_o_estado(arch)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let gravada = esperar_a_auditoria_gravada(&mut m);
        m.cortar_a_energia()?;
        gravada.map_err(|e| format!("{caso}: o boot antes da queda: {e}"))?;
        plano_de_queda(&disco, ponto, tipo::AUDITORIA, 1)?;
        // Ninguém pede nada: o `persistence.open` está pendente desde o
        // boot, e o coletor o grava sozinho.
        let caiu = subir_ate_cair(arch, artefato)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco, None)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        // Abertura, a criação do volume, a linha de base, os três boots; a
        // auditoria não sobe a geração.
        conferir_depois_da_queda(&p, caso, CRIACAO_DO_VOLUME + linha_de_base(artefato) + 4, 0)?;
        let cauda = cauda_da_auditoria(&mut m)?;
        let comeco = comeco_do_boot(&cauda)?;
        // O boot que caiu começa no `policy.load` dele, que o registro do
        // boot levou; o de antes ficou para trás.
        let caiu_em = cauda
            .iter()
            .filter(|r| r.metodo == "policy.load" && r.titular == "kernel" && r.seq < comeco)
            .map(|r| r.seq)
            .max()
            .ok_or_else(|| format!("{caso}: a cauda nao tem o policy.load do boot que caiu"))?;
        let abertos = cauda
            .iter()
            .filter(|r| r.metodo == "persistence.open" && r.seq > caiu_em && r.seq < comeco)
            .count();
        if (abertos == 1) != vale || abertos > 1 {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: o boot que caiu tem {abertos} persistence.open na cadeia, e o registro {}",
                if vale { "vale" } else { "nao vale" }
            ));
        }
        auditoria_verifica(&mut m)?;
        let nome = format!("auditoria-{i}");
        let r = administrar(
            &mut m,
            &chaves.administrador,
            "agent.register",
            &registro_de_agente(&[0xC0 + i as u8; 32], &nome, "observador"),
        )?;
        m.cortar_a_energia()?;
        if !executou(&r) {
            return Err(format!(
                "{caso}: a operacao seguinte nao foi executada\n  {r}"
            ));
        }
        let mut m = Ligada::subir(arch, artefato, None)?;
        let cauda = cauda_da_auditoria(&mut m);
        let verifica = auditoria_verifica(&mut m);
        m.cortar_a_energia()?;
        verifica?;
        if !cauda?
            .iter()
            .any(|r| r.metodo == "agent.register" && r.recurso == nome && r.duravel)
        {
            return Err(format!(
                "{caso}: a decisao da operacao seguinte nao voltou do journal"
            ));
        }
    }
    Ok(format!(
        "{} quedas: o registro de auditoria vale exatamente quando esta no disco, e a cadeia continua",
        QUEDAS_NA_AUDITORIA.len()
    ))
}

/// Os blocos livres do volume, pelo `fs.stat`.
fn livres_no_volume(m: &mut Ligada) -> Result<u64, String> {
    let r = m.pedir("fs.stat", r#"{"path":"/armazem"}"#)?;
    r.split(r#""volume_free_blocks":"#)
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("fs.stat sem volume_free_blocks\n  {r}"))
}

/// O conteúdo de um arquivo do armazém pelo `fs.read`, ou `None`.
fn conteudo_no_armazem(m: &mut Ligada, caminho: &str) -> Result<Option<String>, String> {
    let r = m.pedir("fs.read", &format!(r#"{{"path":"{caminho}"}}"#))?;
    Ok(r.split(r#""content":""#)
        .nth(1)
        .and_then(|r| r.split('"').next())
        .map(String::from))
}

/// A energia cai depois de o lote estar inteiro no volume — os blocos e o
/// registro do journal do armazém, descarregados —, e antes de a
/// confirmação começar no journal de estado. O boot seguinte não confirma
/// o que o journal de estado não confirmou: o arquivo é o de antes, na
/// versão de antes, os blocos do lote voltam a ser livres, e o volume
/// segue — o próximo lote grava por cima do registro que não valeu.
fn a_queda_entre_o_volume_e_a_confirmacao(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    const A: &str = "/armazem/sistema/a.txt";
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/sistema"}"#)?;
    no_armazem(
        &mut m,
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"um","expect_version":0}}"#),
    )?;
    let v1 = versao_no_armazem(&mut m, A)?;
    let livres = livres_no_volume(&mut m)?;
    m.cortar_a_energia()?;

    plano_de_queda(&disco, ponto::LOTE_NO_VOLUME, tipo::ARMAZEM, 1)?;
    let m = Ligada::subir(arch, artefato, None)?;
    let grande = "x".repeat(3000);
    let caiu = m.pedir_ate_cair(
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"{grande}","expect_version":{v1}}}"#),
    )?;
    sem_plano(&disco)?;
    if caiu != ponto::LOTE_NO_VOLUME {
        return Err(format!(
            "caiu no ponto {caiu}, e nao entre o volume e a confirmacao"
        ));
    }

    let mut m = Ligada::subir(arch, artefato, None)?;
    let depois = conteudo_no_armazem(&mut m, A)?;
    let vd = versao_no_armazem(&mut m, A)?;
    let livres_depois = livres_no_volume(&mut m)?;
    let r = no_armazem(
        &mut m,
        "fs.write",
        &format!(r#"{{"path":"{A}","content":"tres","expect_version":{v1}}}"#),
    );
    m.cortar_a_energia()?;
    if depois.as_deref() != Some("um") || vd != v1 {
        return Err(format!(
            "o lote que o journal de estado nao confirmou valeu: {depois:?} na versao {vd}"
        ));
    }
    if livres_depois != livres {
        return Err(format!(
            "os blocos do lote nao confirmado nao voltaram: {livres_depois} livres, e nao {livres}"
        ));
    }
    r?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let fim = conteudo_no_armazem(&mut m, A)?;
    m.cortar_a_energia()?;
    if fim.as_deref() != Some("tres") {
        return Err(format!(
            "o lote depois da queda nao sobreviveu a mais um boot: {fim:?}"
        ));
    }
    Ok(format!(
        "o lote no volume sem confirmacao nao valeu, {livres} blocos livres de novo, e o seguinte gravou"
    ))
}

/// A queda em cada fronteira da gravação do registro de estado que
/// confirma um lote de duas operações — o ponto de commit. O lote vale
/// **inteiro** exatamente quando o registro de estado está no disco, e
/// nunca uma operação sem a outra; o boot seguinte sobe com a persistência
/// e o volume de pé, e o próximo lote grava.
fn as_quedas_num_lote(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const A: &str = "/armazem/sistema/a.txt";
    const B: &str = "/armazem/sistema/b.txt";
    let disco = disco_de_testes()?;
    for (ponto, perder, vale, caso) in QUEDAS_NA_GRAVACAO {
        zerar_o_estado(arch)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/sistema"}"#)?;
        no_armazem(
            &mut m,
            "fs.write",
            &format!(r#"{{"path":"{A}","content":"um","expect_version":0}}"#),
        )?;
        let v1 = versao_no_armazem(&mut m, A)?;
        m.cortar_a_energia()?;

        plano_de_queda(&disco, ponto, tipo::ARMAZEM, 1)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let caiu = m.pedir_ate_cair(
            "fs.batch",
            &format!(
                r#"{{"ops":[{{"op":"write","path":"{A}","content":"dois","expect_version":{v1}}},{{"op":"write","path":"{B}","content":"novo","expect_version":0}}]}}"#
            ),
        )?;
        sem_plano(&disco)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        if perder {
            perder_o_ultimo_registro(&disco, None)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        let a = conteudo_no_armazem(&mut m, A)?;
        let b = conteudo_no_armazem(&mut m, B)?;
        let esperado = if vale {
            (Some("dois"), Some("novo"))
        } else {
            (Some("um"), None)
        };
        if (a.as_deref(), b.as_deref()) != esperado {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: depois da queda A={a:?} e B={b:?}, e nao {esperado:?} — o lote {}",
                if vale {
                    "devia valer inteiro"
                } else {
                    "nao devia valer"
                }
            ));
        }
        if p.estado != "available" {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: o boot seguinte deixou a persistencia {} ({})",
                p.estado, p.motivo
            ));
        }
        let va = versao_no_armazem(&mut m, A)?;
        let r = no_armazem(
            &mut m,
            "fs.write",
            &format!(r#"{{"path":"{A}","content":"tres","expect_version":{va}}}"#),
        );
        m.cortar_a_energia()?;
        r.map_err(|e| format!("{caso}: o lote seguinte nao gravou: {e}"))?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let fim = conteudo_no_armazem(&mut m, A)?;
        m.cortar_a_energia()?;
        if fim.as_deref() != Some("tres") {
            return Err(format!(
                "{caso}: o lote seguinte nao sobreviveu ao boot: {fim:?}"
            ));
        }
    }
    Ok(format!(
        "{} quedas: o lote vale inteiro exatamente quando o registro de estado esta no disco",
        QUEDAS_NA_GRAVACAO.len()
    ))
}

/// O tamanho das regiões nos cenários da compactação: 128 KiB cada, para
/// encher uma com poucas dezenas de operações.
const REGIAO_PEQUENA: u64 = 256;

/// Escreve linhas de política até a região passar de três quartos — ou
/// até `compactar` compactações acontecerem, se o coletor compacta. Devolve
/// quantas operações foram.
fn encher(
    m: &mut Ligada,
    chaves: &super::chaves::Chaves,
    compactacoes: Option<u64>,
) -> Result<u32, String> {
    for i in 0..400u32 {
        let p = persistencia_de(m)?;
        let cheia = p.usados * 4 >= p.setores * 3;
        match compactacoes {
            Some(n) if p.compactacoes >= n => return Ok(i),
            None if cheia => return Ok(i),
            _ => {}
        }
        let linha = format!(r#"{{"line":"taxa observador {} 18"}}"#, 5 + i % 4);
        let r = administrar(m, &chaves.administrador, "policy.write", &linha)?;
        if !executou(&r) {
            return Err(format!("uma linha de politica nao foi gravada\n  {r}"));
        }
    }
    Err("a regiao nao encheu em 400 operacoes".into())
}

/// Registra um agente, e confere que foi.
fn registrar(
    m: &mut Ligada,
    chaves: &super::chaves::Chaves,
    privada: &[u8; 32],
    nome: &str,
) -> Result<(), String> {
    let r = administrar(
        m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(privada, nome, "observador"),
    )?;
    if executou(&r) {
        Ok(())
    } else {
        Err(format!("o registro de `{nome}` nao foi executado\n  {r}"))
    }
}

/// Revoga um agente, e confere que foi.
fn revogar_agente(
    m: &mut Ligada,
    chaves: &super::chaves::Chaves,
    privada: &[u8; 32],
) -> Result<(), String> {
    let r = administrar(
        m,
        &chaves.administrador,
        "agent.revoke",
        &format!(
            r#"{{"key":"{}"}}"#,
            sigilo::hex(&sigilo::publica_de(privada))
        ),
    )?;
    if executou(&r) {
        Ok(())
    } else {
        Err(format!("a revogacao nao foi executada\n  {r}"))
    }
}

/// O coletor compacta a região que passou de três quartos, e tudo
/// sobrevive ao corte depois disso: o agente registrado entra, o revogado
/// não, a mensagem pendente continua, a geração é a mesma, a cadeia da
/// auditoria se verifica, e a próxima operação grava e sobrevive a mais
/// um boot.
fn a_compactacao_sobrevive(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let (fica, sai, depois) = ([0xD1u8; 32], [0xD2u8; 32], [0xD3u8; 32]);
    plano(
        &disco,
        Plano {
            limite: Some(REGIAO_PEQUENA),
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    registrar(&mut m, &chaves, &fica, "compacta-fica")?;
    registrar(&mut m, &chaves, &sai, "compacta-sai")?;
    revogar_agente(&mut m, &chaves, &sai)?;
    let r = super::AgenteNaPorta::conectar(arch, 1)?.pedir(
        "message.send",
        r#"{"to":"serial","body":"antes da compactacao","nonce":1}"#,
    )?;
    if !r.contains(r#""durable":true"#) {
        m.cortar_a_energia()?;
        return Err(format!("a mensagem nao foi duravel\n  {r}"));
    }
    const ARQUIVO: &str = "/armazem/sistema/compacta.txt";
    // Os diretórios são explícitos: o do sistema nasce aqui.
    no_armazem(&mut m, "fs.mkdir", r#"{"path":"/armazem/sistema"}"#)?;
    let v0 = versao_no_armazem(&mut m, ARQUIVO)?;
    let r = m.pedir(
        "fs.write",
        &format!(
            r#"{{"path":"{ARQUIVO}","content":"antes da compactacao","expect_version":{v0}}}"#
        ),
    )?;
    if !r.contains(r#""durable":true"#) {
        m.cortar_a_energia()?;
        return Err(format!("a gravacao no armazem nao foi duravel\n  {r}"));
    }
    let v_arquivo = versao_no_armazem(&mut m, ARQUIVO)?;
    let ops = encher(&mut m, &chaves, Some(1))?;
    let antes = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;

    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let caixa = m.pedir("message.read", "{}")?;
    let arquivo = m.pedir("fs.read", &format!(r#"{{"path":"{ARQUIVO}"}}"#))?;
    if !arquivo.contains(r#""content":"antes da compactacao""#)
        || versao_no_armazem(&mut m, ARQUIVO)? != v_arquivo
    {
        m.cortar_a_energia()?;
        return Err(format!(
            "o arquivo do armazem nao atravessou a compactacao igual\n  {arquivo}"
        ));
    }
    let verifica = auditoria_verifica(&mut m);
    if p.estado != "available" || p.compactacoes < 1 || p.geracao != antes.geracao {
        m.cortar_a_energia()?;
        return Err(format!(
            "depois do corte: {} ({}), {} compactacoes, geracao {} e nao {}",
            p.estado, p.motivo, p.compactacoes, p.geracao, antes.geracao
        ));
    }
    if !caixa.contains("antes da compactacao") {
        m.cortar_a_energia()?;
        return Err(format!(
            "a mensagem pendente sumiu na compactacao\n  {caixa}"
        ));
    }
    if !agente_entra(arch, &fica, "compacta-fica")? || agente_entra(arch, &sai, "compacta-sai")? {
        m.cortar_a_energia()?;
        return Err(
            "o agente registrado nao entra, ou o revogado entra, depois da compactacao".into(),
        );
    }
    if let Err(e) = verifica {
        m.cortar_a_energia()?;
        return Err(e);
    }
    registrar(&mut m, &chaves, &depois, "compacta-depois")?;
    m.cortar_a_energia()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let entra = agente_entra(arch, &depois, "compacta-depois")?;
    m.cortar_a_energia()?;
    if p.estado != "available" || !entra {
        return Err(format!(
            "a operacao depois da compactacao nao sobreviveu ao boot: {} ({})",
            p.estado, p.motivo
        ));
    }
    Ok(format!(
        "{ops} operacoes ate a compactacao; depois do corte, o estado, a geracao {} e a auditoria continuam",
        antes.geracao
    ))
}

/// Enche a região sem compactar, com um agente que fica e um que sai, e
/// devolve a geração. Com o pedido `assinar`, a `chave:bancada` nasce
/// antes — selada, no journal —, e a assinatura dela volta também.
fn preparar_a_compactacao(
    arch: Arquitetura,
    artefato: &Artefato,
    chaves: &super::chaves::Chaves,
    disco: &Path,
    assinar: Option<&str>,
) -> Result<(u64, Option<String>), String> {
    plano(
        disco,
        Plano {
            limite: Some(REGIAO_PEQUENA),
            bandeiras: COLETOR_NAO_COMPACTA | BOOT_NAO_COMPACTA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = (|| {
        let assinatura = match assinar {
            Some(pedido) => {
                let r = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
                    a.pedir(
                        "key.create",
                        r#"{"key":"chave:bancada","domain":"ic-request"}"#,
                    )?;
                    a.pedir("key.sign", pedido)
                })?;
                Some(
                    texto_do_resultado(&r, "signature")
                        .ok_or_else(|| format!("a chave da compactacao nao assinou\n  {r}"))?,
                )
            }
            None => None,
        };
        registrar(&mut m, chaves, &[0xD4; 32], "queda-fica")?;
        registrar(&mut m, chaves, &[0xD5; 32], "queda-sai")?;
        revogar_agente(&mut m, chaves, &[0xD5; 32])?;
        encher(&mut m, chaves, None)?;
        Ok((persistencia_de(&mut m)?.geracao, assinatura))
    })();
    m.cortar_a_energia()?;
    r
}

/// A energia cai em cada fronteira da compactação, feita no boot: antes de
/// escrever, depois da primeira parte, depois de escrever a base inteira
/// (que chegou ao disco, ou se perdeu sem a descarga), depois da descarga
/// e antes do contador, depois do incremento e antes da leitura de volta,
/// depois do contador. O boot seguinte sobe com a
/// persistência de pé; a compactação vale exatamente quando o fecho está
/// no disco; o estado é o mesmo — o agente que fica entra, o revogado não,
/// e a chave selada antes de encher volta selada e assina igual, levada ou
/// não pela base — e a geração também; e a próxima operação grava.
fn as_quedas_na_compactacao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let assinar = format!(
        r#"{{"key":"chave:bancada","domain":"ic-request","digest":"{}"}}"#,
        "5c".repeat(32)
    );
    let casos: [Caso; 7] = [
        (ponto::ANTES_DA_ESCRITA, false, false, "antes da escrita"),
        (
            ponto::DEPOIS_DA_PRIMEIRA_PARTE,
            false,
            false,
            "depois da primeira parte",
        ),
        (
            ponto::DEPOIS_DA_ESCRITA,
            false,
            true,
            "a base escrita, que chegou ao disco",
        ),
        (
            ponto::DEPOIS_DA_ESCRITA,
            true,
            false,
            "a base escrita, e o fecho perdido sem a descarga",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            false,
            true,
            "a base descarregada, antes do contador",
        ),
        (
            ponto::DEPOIS_DO_INCREMENTO,
            false,
            true,
            "o contador incrementado, antes da leitura de volta",
        ),
        (
            ponto::DEPOIS_DO_CONTADOR,
            false,
            true,
            "o contador avancado, antes de trocar de regiao",
        ),
    ];
    for (i, (ponto, perder, vale, caso)) in casos.into_iter().enumerate() {
        zerar_o_estado(arch)?;
        let (geracao, assinatura) =
            preparar_a_compactacao(arch, artefato, &chaves, &disco, Some(&assinar))?;
        plano(
            &disco,
            Plano {
                ponto,
                tipo: tipo::BASE_FIM,
                gravacao: 1,
                limite: Some(REGIAO_PEQUENA),
                bandeiras: COLETOR_NAO_COMPACTA,
            },
        )?;
        let caiu = subir_ate_cair(arch, artefato)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        if perder {
            perder_o_ultimo_registro(&disco, Some(REGIAO_PEQUENA))?;
        }
        plano(
            &disco,
            Plano {
                limite: Some(REGIAO_PEQUENA),
                bandeiras: COLETOR_NAO_COMPACTA | BOOT_NAO_COMPACTA,
                ..Plano::default()
            },
        )?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        let verifica = auditoria_verifica(&mut m);
        let fica = agente_entra(arch, &[0xD4; 32], "queda-fica")?;
        let sai = agente_entra(arch, &[0xD5; 32], "queda-sai")?;
        let chave = super::AgenteNaPorta::conectar(arch, 1).and_then(|mut a| {
            Ok((
                a.pedir("key.read", r#"{"key":"chave:bancada"}"#)?,
                a.pedir("key.sign", &assinar)?,
            ))
        });
        m.cortar_a_energia()?;
        if p.estado != "available" {
            return Err(format!(
                "{caso}: a persistencia ficou {} ({})",
                p.estado, p.motivo
            ));
        }
        let (lida, assinada) = chave.map_err(|e| format!("{caso}: {e}"))?;
        if texto_do_resultado(&lida, "seal").as_deref() != Some("tpm")
            || texto_do_resultado(&assinada, "signature") != assinatura
        {
            return Err(format!(
                "{caso}: a chave selada nao voltou igual da compactacao\n  {lida}\n  {assinada}"
            ));
        }
        if (p.compactacoes == 1) != vale || p.compactacoes > 1 {
            return Err(format!(
                "{caso}: {} compactacoes, e a compactacao {}",
                p.compactacoes,
                if vale { "vale" } else { "nao vale" }
            ));
        }
        if p.geracao != geracao || !fica || sai {
            return Err(format!(
                "{caso}: geracao {} (era {geracao}); o que fica entra: {fica}; o revogado entra: {sai}",
                p.geracao
            ));
        }
        verifica.map_err(|e| format!("{caso}: {e}"))?;
        plano(
            &disco,
            Plano {
                limite: Some(REGIAO_PEQUENA),
                ..Plano::default()
            },
        )?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let r = registrar(
            &mut m,
            &chaves,
            &[0xE0 + i as u8; 32],
            &format!("depois-{i}"),
        );
        m.cortar_a_energia()?;
        r.map_err(|e| format!("{caso}: {e}"))?;
    }
    Ok(format!(
        "{} quedas: a compactacao vale exatamente quando o fecho esta no disco, nada volta atras, e a chave selada assina igual",
        casos.len()
    ))
}

/// A fotografia do disco tirada antes da compactação, com um agente que
/// depois foi revogado, devolvida depois da compactação e da revogação: um
/// disco anterior ao que o TPM viu. Recusada, e o agente não volta.
fn a_fotografia_de_antes_da_compactacao(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    preparar_a_compactacao(arch, artefato, &chaves, &disco, None)?;
    // O agente que fica é o que vai ser revogado depois da compactação.
    let foto = ler_o_estado(&disco)?;
    plano(
        &disco,
        Plano {
            limite: Some(REGIAO_PEQUENA),
            bandeiras: COLETOR_NAO_COMPACTA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let revogado = revogar_agente(&mut m, &chaves, &[0xD4; 32]);
    m.cortar_a_energia()?;
    if p.compactacoes != 1 {
        return Err(format!(
            "o boot nao compactou: {} compactacoes",
            p.compactacoes
        ));
    }
    revogado?;
    escrever_no_estado(&disco, &foto)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let voltou = agente_entra(arch, &[0xD4; 32], "queda-fica")?;
    m.cortar_a_energia()?;
    if p.estado != "refused" {
        return Err(format!(
            "a fotografia de antes da compactacao foi aceita: {} ({})",
            p.estado, p.motivo
        ));
    }
    if voltou {
        return Err(
            "com a fotografia antiga, o agente revogado depois da compactacao voltou".into(),
        );
    }
    Ok(format!("recusada: {}", p.motivo))
}

/// A compactação cai depois da primeira parte, e a região antiga some do
/// disco: sobra uma base sem fecho, autêntica e pela metade — o começo da
/// história, talvez sem a revogação que veio depois. Ela nunca vale: o boot
/// recusa o journal, nenhuma credencial passa, e o agente revogado não
/// entra.
fn a_base_sem_fecho_sozinha(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    preparar_a_compactacao(arch, artefato, &chaves, &disco, None)?;
    plano(
        &disco,
        Plano {
            ponto: ponto::DEPOIS_DA_PRIMEIRA_PARTE,
            tipo: tipo::BASE_FIM,
            gravacao: 1,
            limite: Some(REGIAO_PEQUENA),
            bandeiras: COLETOR_NAO_COMPACTA,
        },
    )?;
    let caiu = subir_ate_cair(arch, artefato)?;
    if caiu != ponto::DEPOIS_DA_PRIMEIRA_PARTE {
        return Err(format!(
            "caiu no ponto {caiu}, e nao depois da primeira parte"
        ));
    }
    let mut estado = ler_o_estado(&disco)?;
    estado[..(REGIAO_PEQUENA * 512) as usize].fill(0);
    escrever_no_estado(&disco, &estado)?;
    plano(
        &disco,
        Plano {
            limite: Some(REGIAO_PEQUENA),
            bandeiras: COLETOR_NAO_COMPACTA | BOOT_NAO_COMPACTA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let r = administrar(
        &mut m,
        &chaves.administrador,
        "agent.register",
        &registro_de_agente(&[0xD9; 32], "metade", "observador"),
    );
    let sai = agente_entra(arch, &[0xD5; 32], "queda-sai")?;
    m.cortar_a_energia()?;
    if p.estado != "refused" || !p.motivo.contains("nenhuma regiao") {
        return Err(format!(
            "a base sem fecho nao foi recusada pelo que e: {} ({})",
            p.estado, p.motivo
        ));
    }
    if r.as_ref().is_ok_and(|r| executou(r)) || sai {
        return Err(format!(
            "com a base pela metade, a administracao passou ou o revogado entrou: {r:?}; {sai}"
        ));
    }
    Ok(format!("recusada: {}", p.motivo))
}

/// A região enche sem compactação: a operação que não cabe falha fechada —
/// não vale, e diz que não ficou gravada —, a persistência fica
/// indisponível, e nenhuma credencial administrativa passa. O boot
/// seguinte compacta e volta: o que valia continua valendo, o que falhou
/// não aparece, e a próxima operação grava.
fn a_regiao_cheia_falha_fechada(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    plano(
        &disco,
        Plano {
            limite: Some(REGIAO_PEQUENA),
            bandeiras: COLETOR_NAO_COMPACTA | BOOT_NAO_COMPACTA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = (|| -> Result<(u32, String, String), String> {
        registrar(&mut m, &chaves, &[0xD6; 32], "cheia-fica")?;
        for i in 0..400u32 {
            let linha = format!(r#"{{"line":"taxa observador {} 18"}}"#, 5 + i % 4);
            let r = administrar(&mut m, &chaves.administrador, "policy.write", &linha)?;
            if !executou(&r) {
                let depois = administrar(
                    &mut m,
                    &chaves.administrador,
                    "agent.register",
                    &registro_de_agente(&[0xD7; 32], "cheia-depois", "observador"),
                )?;
                return Ok((i, r, depois));
            }
        }
        Err("a regiao nao encheu em 400 operacoes".into())
    })();
    let p = persistencia_de(&mut m);
    m.cortar_a_energia()?;
    let (ops, falhou, depois) = r?;
    let p = p?;
    // A gravação que encontra a região cheia pode ser a da operação —
    // que diz que a partição encheu — ou um registro só de auditoria do
    // coletor, logo antes: aí a operação já encontra a persistência
    // indisponível. Nos dois casos, ela não vale.
    let cheia = falhou.contains("cheia") || falhou.contains("persistencia indisponivel");
    if !cheia || p.estado != "unavailable" || executou(&depois) {
        return Err(format!(
            "a regiao cheia nao falhou fechada: {} ({})\n  {falhou}\n  {depois}",
            p.estado, p.motivo
        ));
    }
    plano(
        &disco,
        Plano {
            limite: Some(REGIAO_PEQUENA),
            bandeiras: COLETOR_NAO_COMPACTA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let fica = agente_entra(arch, &[0xD6; 32], "cheia-fica")?;
    let veio = agente_entra(arch, &[0xD7; 32], "cheia-depois")?;
    let r = registrar(&mut m, &chaves, &[0xD8; 32], "cheia-recuperada");
    m.cortar_a_energia()?;
    if p.estado != "available" || p.compactacoes != 1 {
        return Err(format!(
            "o boot nao recuperou a regiao cheia: {} ({}), {} compactacoes",
            p.estado, p.motivo, p.compactacoes
        ));
    }
    if !fica || veio {
        return Err(format!(
            "depois da recuperacao, o que valia entra: {fica}; o que falhou entra: {veio}"
        ));
    }
    r?;
    Ok(format!(
        "{ops} operacoes ate encher; a seguinte falhou fechada, e o boot compactou e voltou"
    ))
}

/// O primeiro boot espera, com a persistência já disponível e a abertura
/// por gravar, duas voltas do coletor — que tem a auditoria do boot para
/// gravar. Ele não grava nada antes da abertura: o boot tem a ordem das
/// gravações. Se gravasse, a região não começaria pela abertura, e o boot
/// seguinte recusaria o journal.
fn o_coletor_espera_a_abertura(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    plano(
        &disco,
        Plano {
            bandeiras: ESPERAR_NA_ABERTURA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let primeiro = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;
    sem_plano(&disco)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;
    if primeiro.estado != "available" || p.estado != "available" || p.boots != 2 {
        return Err(format!(
            "depois da espera na abertura: {} e depois {} ({}), boot {}",
            primeiro.estado, p.estado, p.motivo, p.boots
        ));
    }
    Ok(format!(
        "a abertura veio primeiro; o boot seguinte abriu {} registros",
        p.registros
    ))
}

/// A queda no boot depois de a EK ser conferida e antes de o contador ser
/// lido: nada mudou — nem disco, nem contador —, e o boot seguinte abre, com
/// o que valia valendo.
fn a_queda_depois_da_chave(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = registrar(&mut m, &chaves, &[0xC4; 32], "antes-da-chave");
    let antes = persistencia_de(&mut m);
    m.cortar_a_energia()?;
    r?;
    let antes = antes?;
    plano_de_queda(&disco, ponto::DEPOIS_DA_CHAVE, 0, 0)?;
    let caiu = subir_ate_cair(arch, artefato)?;
    sem_plano(&disco)?;
    if caiu != ponto::DEPOIS_DA_CHAVE {
        return Err(format!("caiu no ponto {caiu}, e nao depois da chave"));
    }
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let entra = agente_entra(arch, &[0xC4; 32], "antes-da-chave")?;
    m.cortar_a_energia()?;
    if p.estado != "available" || p.geracao != antes.geracao || !entra || p.ek != antes.ek {
        return Err(format!(
            "depois da queda: {} ({}), geracao {} e nao {}, o agente entra: {entra}",
            p.estado, p.motivo, p.geracao, antes.geracao
        ));
    }
    Ok(format!("geracao {} e a EK {} de pe", p.geracao, p.ek))
}

/// O contador anda "de fora" entre dois boots — o que só quem tem a senha
/// dele faria —, e fica à frente do journal. Recusado: o journal não é o
/// atual para o TPM, e o estado dele não volta como se fosse. E continua
/// recusado no boot seguinte: o contador não volta.
fn o_contador_de_fora_e_recusado(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let r = registrar(&mut m, &chaves, &[0xC5; 32], "contador-de-fora");
    m.cortar_a_energia()?;
    r?;
    plano(
        &disco,
        Plano {
            bandeiras: CONTADOR_DE_FORA,
            ..Plano::default()
        },
    )?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let p = persistencia_de(&mut m)?;
    let entra = agente_entra(arch, &[0xC5; 32], "contador-de-fora")?;
    let r = administrar(&mut m, &chaves.administrador, "message.read", "{}")?;
    m.cortar_a_energia()?;
    sem_plano(&disco)?;
    let mut m = Ligada::subir(arch, artefato, None)?;
    let depois = persistencia_de(&mut m)?;
    m.cortar_a_energia()?;
    if p.estado != "refused" || !p.motivo.contains("anterior ao que a ancora") {
        return Err(format!(
            "o contador de fora nao foi recusado pelo que e: {} ({})",
            p.estado, p.motivo
        ));
    }
    if entra || executou(&r) {
        return Err(format!(
            "com o contador a frente, uma credencial passou\n  {r}"
        ));
    }
    if depois.estado != "refused" {
        return Err(format!(
            "no boot seguinte, o journal atrasado foi aceito: {} ({})",
            depois.estado, depois.motivo
        ));
    }
    Ok(format!("recusado: {}", p.motivo))
}

/// A queda na criação da âncora, no primeiro boot de todos: com o contador
/// definido e nunca avançado, avançado e sem nascimento, com o nascimento e
/// sem a abertura, e dentro da gravação da abertura. Nenhuma deixa o
/// sistema recusado para sempre: o boot seguinte retoma a criação ou a
/// completa, e o journal começa normalmente.
fn as_quedas_na_criacao(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    let casos: [(u8, &str); 7] = [
        (
            ponto::DEPOIS_DA_CHAVE,
            "a chave do TPM conferida, e nada definido",
        ),
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
        plano_de_queda(&disco, ponto, tipo::ABERTURA, 1)?;
        let caiu = subir_ate_cair(arch, artefato)?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        sem_plano(&disco)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let p = persistencia_de(&mut m)?;
        // A linha de base vem no boot de agora, depois da abertura.
        conferir_depois_da_queda(&p, caso, CRIACAO_DO_VOLUME + linha_de_base(artefato) + 2, 0)?;
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
        conferir_depois_da_queda(&p, caso, CRIACAO_DO_VOLUME + linha_de_base(artefato) + 4, 1)?;
    }
    Ok(format!(
        "{} quedas na criacao: cada uma retomada ou completada no boot seguinte",
        casos.len()
    ))
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
            plano_de_queda(&disco, ponto::NASCIMENTO_GUARDADO, tipo::ABERTURA, 1)?;
            subir_ate_cair(arch, artefato)?;
        } else {
            plano_de_queda(&disco, ponto::DEPOIS_DA_DESCARGA, tipo::OPERACAO, 1)?;
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
