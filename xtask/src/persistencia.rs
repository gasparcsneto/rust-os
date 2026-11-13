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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use super::disco_hostil::{Corte, DiscoHostil, Faixa, Gatilho, Sentido};
use super::{
    Ambiente, Arquitetura, Artefato, BufReader, Child, Command, Duration, ExitCode, Path, Teclado,
    UnixStream, Video, build, caminho_socket, canal_de_pe_com, comando_qemu, diretorio_do_tpm,
    disco, disco_de_testes, escrever_no_estado, ler_o_estado, pedir_pela_serial, zerar_o_estado,
};

/// Quanto uma máquina que sobe pode ficar sem andar antes de a bancada
/// desistir dela: nenhum byte novo na serial humana, nenhuma leitura,
/// escrita ou descarga nos discos, nada no canal — ver [`AndamentoDoBoot`].
///
/// # Por que a espera é pelo andamento
///
/// Ela era um prazo do boot inteiro, de noventa segundos, e reprovou na CI
/// 408 dois boots que andavam: num runner sem CPU, um parou nos noventa
/// segundos ainda no iniciador, conferindo o kernel de 15,8 MB — o disco
/// tinha lido 16,4 MB e estava ocioso havia 0,28 s —, e outro no kernel,
/// antes de ligar os outros núcleos — o disco ocioso havia 1,1 s. O que se
/// quer reprovar não é o boot lento, é o boot **parado** — o firmware da
/// CI 413, com a serial muda e o disco ocioso havia 253 segundos —, como a
/// suíte já faz com a [`super::JANELA_SEM_PROGRESSO`] dela.
///
/// # O que conta como andar
///
/// O que se vê de fora, sem mudar o firmware, o iniciador nem o kernel:
///
/// - a serial humana do cenário — a COM1 do x86, ver [`serial_do_cenario`]
///   —, que tem o console do firmware, o relatório do iniciador e os passos
///   do kernel;
/// - os contadores dos discos pelo QMP — bytes e operações de leitura, de
///   escrita e de descarga, de todos: o do firmware e o do kernel. É o que
///   cobre o trecho mudo do iniciador: ele lê o kernel do slot em pedaços
///   de um mebibyte, somando o resumo e o CRC de cada um antes de ler o
///   seguinte, e cada pedaço é uma leitura nova no disco;
/// - o que a máquina escreve no canal antes de atender — no ARM, onde a
///   única serial é o canal, o console do firmware e o relatório do
///   iniciador.
///
/// # Por que dois minutos
///
/// O trecho mudo mais longo de um boot que anda é o do firmware antes do
/// console: medido aqui, com o firmware do Ubuntu 24.04 (edk2 2024.02; o da
/// CI é o 2025.11), o OVMF escreveu o primeiro byte na COM1 seis segundos
/// depois de o emulador abrir o QMP, e o disco, meio segundo depois; o
/// AAVMF escreveu na PL011 meio segundo depois, e leu o disco um segundo
/// depois disso. Dois minutos são vinte vezes isso, e mais que os noventa
/// segundos do prazo antigo: um boot que passava nele passa aqui. A
/// bancada de persistência e a da atualização dizem no fim o maior
/// intervalo sem sinal novo que um boot que atendeu teve — ver
/// [`relatar_a_maior_parada`] —, para que esta conta se refaça com o
/// número da CI.
pub(crate) const JANELA_SEM_ANDAR: Duration = Duration::from_secs(120);

/// O teto de um boot que anda sem o canal atender: a máquina que reinicia
/// em laço, ou que só escreve, anda para sempre. Mais de três vezes o
/// prazo antigo de noventa segundos, para o runner lento da CI 408.
const TETO_DO_BOOT: Duration = Duration::from_secs(300);

/// Uma máquina de produção de pé, com o canal da serial aberto.
pub(crate) struct Ligada {
    filho: Child,
    escrita: UnixStream,
    leitor: BufReader<UnixStream>,
    id: u32,
    /// O que a bancada olha desta máquina de fora, com os caminhos da
    /// partida — ver [`Olhos`].
    olhos: Olhos,
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
        Ligada::subir_esperando(arch, artefato, ambiente, TETO_DO_BOOT)
    }

    /// [`Ligada::subir_com`], com o teto `teto`: a máquina que reinicia
    /// sozinha antes de atender — a versão nova que entra em pânico, as
    /// tentativas que o iniciador conta — leva vários boots.
    ///
    /// A espera é pelo andamento da máquina: ela segue enquanto a máquina
    /// anda, e desiste quando ela fica [`JANELA_SEM_ANDAR`] sem andar, ou
    /// no teto — ver [`AndamentoDoBoot`]. Desistindo, diz onde a máquina
    /// parou: o que o emulador diz de si pelo QMP, o TPM — se o `swtpm`
    /// vive, e o fim do log dele — e o fim do log de depuração do firmware.
    /// O fim da serial, quem mostra é o cenário que reprova (ver
    /// [`mostrar_o_fim_da_serial`]).
    pub(crate) fn subir_esperando(
        arch: Arquitetura,
        artefato: &Artefato,
        mut ambiente: Ambiente,
        teto: Duration,
    ) -> Result<Ligada, String> {
        let (mut filho, socket, mut olhos) = lancar(arch, artefato, &ambiente)?;
        let mut andamento = AndamentoDoBoot::novo(Instant::now(), JANELA_SEM_ANDAR, teto);
        let de_pe = canal_de_pe_com(&socket, |lidos| {
            olhos.ouvir_o_canal(lidos);
            if matches!(filho.try_wait(), Ok(Some(_))) {
                return Err("o emulador saiu antes de o canal atender".to_string());
            }
            let agora = Instant::now();
            andamento
                .olhar(agora, Some(olhos.sinais(agora)))
                .map_err(|d| d.to_string())
        });
        let fluxo = match de_pe {
            Ok(f) => {
                registrar_a_parada(andamento.maior_parada_ate(Instant::now()));
                f
            }
            Err(e) => {
                let estado = match filho.try_wait() {
                    Ok(Some(saida)) => format!("o emulador ja tinha saido ({saida})"),
                    _ => format!(
                        "o emulador, pelo QMP: {}",
                        estado_do_emulador(&olhos.qmp, olhos.codigo_do_firmware.as_deref())
                    ),
                };
                let tpm = tpm_e_firmware(&mut ambiente, olhos.firmware.as_deref());
                let _ = filho.kill();
                let _ = filho.wait();
                return Err(format!("{e}\n  {estado}{tpm}"));
            }
        };
        // Daqui em diante um erro não larga a máquina viva: solta, ela
        // seguraria o disco — e o fim do disco hostil espera a conexão dela
        // acabar (ver `disco_hostil`).
        let escrita = match fluxo
            .set_read_timeout(Some(Duration::from_secs(15)))
            .and_then(|()| fluxo.try_clone())
        {
            Ok(escrita) => escrita,
            Err(e) => {
                let _ = filho.kill();
                let _ = filho.wait();
                return Err(format!("não foi possível preparar o canal da máquina: {e}"));
            }
        };
        Ok(Ligada {
            filho,
            escrita,
            leitor: BufReader::new(fluxo),
            // Longe das faixas da fumaça, que ninguém mais usa aqui, mas um
            // número reconhecível no log ajuda a ler uma falha.
            id: 70_000,
            olhos,
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
                notar_a_resposta(&linha);
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
        // Antes do corte: a pergunta da recusa precisa da máquina viva —
        // ver [`notar_a_resposta`].
        self.perguntar_o_motivo_se_recusou();
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

    /// Para o TPM sem desligá-lo — `SIGSTOP` no `swtpm` — ou o solta
    /// (`SIGCONT`): o chip que demora a responder. O comando que o emulador
    /// já entregou fica no socket, e o `swtpm` o executa quando volta.
    pub(crate) fn segurar_o_tpm(&self, segurar: bool) -> Result<(), String> {
        let Some((tpm, _)) = self._ambiente.tpm.as_ref() else {
            return Err("esta maquina nao tem TPM para segurar".into());
        };
        segurar_o_swtpm(tpm.id(), segurar)
    }
}

/// `SIGSTOP` (`segurar`) ou `SIGCONT` no `swtpm` de número `pid` — ver
/// [`Ligada::segurar_o_tpm`].
fn segurar_o_swtpm(pid: u32, segurar: bool) -> Result<(), String> {
    let sinal = if segurar { "-STOP" } else { "-CONT" };
    let pid = pid.to_string();
    let saida = Command::new("kill")
        .args([sinal, &pid])
        .status()
        .map_err(|e| format!("não foi possível rodar o kill {sinal} {pid}: {e}"))?;
    if !saida.success() {
        return Err(format!("kill {sinal} {pid}: {saida}"));
    }
    Ok(())
}

/// O que o emulador vivo diz de si pelo QMP `qmp`, para o boot que não
/// atendeu: se roda, onde está cada processador — e se parado num `hlt` —,
/// e o que cada disco da máquina já leu e escreveu, com há quanto tempo
/// está ocioso.
///
/// Na CI 359, um primeiro boot parou no iniciador, lendo o kernel do slot,
/// e a serial só dizia até onde o hóspede tinha escrito: não dizia se o
/// processador girava à espera do disco, se o disco tinha um pedido
/// pendurado, ou se o próprio emulador tinha parado. Um emulador que não
/// responde ao QMP é essa terceira resposta.
///
/// Os discos são todos os que já leram ou escreveram, e não só o do
/// kernel: no x86 com o disco no virtio, o firmware e o iniciador leem o
/// disco de testes pelo IDE da máquina (`ide0-hd0`, o disco do boot — ver
/// [`super::argumentos_dos_discos`]), e o kernel, pelo virtio (`disco0`) —
/// o mesmo arquivo.
///
/// E, em linhas a seguir, o módulo em que cada processador está e os
/// retornos na pilha dele — ver [`super::firmware`]: na CI 436, o firmware
/// parou com um processador girando num endereço que, sozinho, não dizia
/// nada. Para isso a máquina é parada (`stop`) depois de dizer se rodava:
/// os registradores, a memória em volta de cada um e a pilha são de um
/// instante só. Quem chama este diagnóstico desliga a máquina em seguida.
/// O nome de uma imagem sem o CodeView sai de `codigo_do_firmware`, o
/// arquivo do firmware com que ela subiu.
fn estado_do_emulador(qmp: &Path, codigo_do_firmware: Option<&Path>) -> String {
    let perguntar = || -> Result<String, String> {
        let (mut escrita, mut leitor) = super::qmp_abrir(qmp)?;
        let mut pedir = |pedido: &str| super::qmp_pedir(&mut escrita, &mut leitor, pedido);
        let status = pedir(r#"{"execute":"query-status"}"#)?;
        let _ = pedir(r#"{"execute":"stop"}"#);
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
        for linha in registros.split("\\r\\n") {
            let linha = linha.trim();
            if linha.starts_with("CPU#") || linha.starts_with("RIP=") || linha.starts_with("PC=") {
                partes.push(linha.to_string());
            }
        }
        for linha in disco.split("\\r\\n") {
            let linha = linha.trim().trim_start_matches("{\"return\": \"");
            if atividade_dos_discos(linha).is_some_and(|a| a > 0) {
                partes.push(linha.to_string());
            }
        }
        let mut texto = partes.join("; ");
        let mut memoria = super::firmware::MemoriaPeloQmp {
            escrita: &mut escrita,
            leitor: &mut leitor,
            arquivo: qmp.with_extension("memoria"),
        };
        let mut fonte = || match codigo_do_firmware {
            Some(codigo) => super::firmware::modulos_do_arquivo(codigo),
            None => Err("o arquivo do firmware desta maquina nao e conhecido".to_string()),
        };
        let linhas = super::firmware::onde_cada_processador(&registros, &mut memoria, &mut fonte);
        if !linhas.is_empty() {
            texto.push_str("\n  onde cada processador esta, pela memoria:");
            for linha in linhas {
                texto.push_str("\n    ");
                texto.push_str(&linha);
            }
        }
        Ok(texto)
    };
    perguntar()
        .unwrap_or_else(|e| format!("sem resposta ({e}): o emulador vivo e parado por dentro"))
}

/// Liga o QEMU, sem esperar nada dele. Devolve o processo, o socket da
/// serial do agente e os olhos da máquina — com, no x86, o arquivo do log
/// de depuração do firmware, e, na máquina que sobe pelo firmware, o
/// arquivo do código dele.
fn lancar(
    arch: Arquitetura,
    artefato: &Artefato,
    ambiente: &Ambiente,
) -> Result<(Child, PathBuf, Olhos), String> {
    let socket = caminho_socket(arch);
    let mut qemu = comando_qemu(
        arch,
        artefato,
        Some(&socket),
        Teclado::Nativo,
        Video::Linear,
        ambiente,
    )?;
    // O log de depuração do firmware do x86: o EDK II escreve as mensagens
    // de depuração na porta 0x402, o `debugcon` do emulador, e é lá que
    // estaria o que um firmware parado esperava — o da CI 413 parou depois
    // do console, antes de carregar a opção de boot. O OVMF da CI — o do
    // Ubuntu 26.04, edk2 2025.11 — é uma compilação de release, sem as
    // mensagens (`BUILD_TYPE ?= RELEASE` no `debian/rules` do pacote, e o
    // `DEBUG_ON_SERIAL_PORT` comentado); o do Ubuntu 24.04, medido, não
    // escreve nada nem na 0x402 nem na 0xe9. Com eles o arquivo fica vazio;
    // um firmware de depuração escreve, e o boot que não atende mostra o
    // fim. O ARM não tem `debugcon`: o que o AAVMF diz vai para a PL011,
    // que na bancada é o canal — ver [`Olhos::ouvir_o_canal`]. O arquivo é
    // por raiz, como o QMP, e cada emulador que a bancada liga o começa de
    // novo; os boots de um mesmo emulador — o reinício pelo comando, a
    // tentativa que entra em pânico — vão um depois do outro nele.
    let firmware = (arch == Arquitetura::X86_64)
        .then(|| super::raiz_do_estado().join(format!("firmware-{}.log", arch.nome())));
    if let Some(caminho) = &firmware {
        qemu.args([
            "-debugcon",
            &format!("file:{}", caminho.display()),
            "-global",
            "isa-debugcon.iobase=0x402",
        ]);
    }
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
    // O código do firmware, para o diagnóstico nomear as imagens dele —
    // ver [`super::firmware`]. A máquina que sobe pelo `-kernel` não tem.
    let codigo = matches!(artefato, Artefato::Disco(_))
        .then(|| super::codigo_do_firmware(arch))
        .flatten();
    Ok((filho, socket, Olhos::da_partida(arch, firmware, codigo)))
}

/// O que a bancada vê de uma máquina que sobe, de fora, numa olhada: o
/// tamanho da serial humana do cenário, a soma do que os discos já fizeram
/// e os bytes que o canal já mostrou. Cada um só cresce; a máquina anda
/// quando algum muda — ver [`AndamentoDoBoot`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sinais {
    pub(crate) serial: u64,
    pub(crate) discos: u64,
    pub(crate) canal: u64,
}

/// A espera de uma máquina pelo andamento dela: segue enquanto algum dos
/// [`Sinais`] muda, desiste quando nenhum muda por `janela` — contada do
/// último que mudou, ou da partida —, e acaba no `teto`, andando ou não.
///
/// É só a conta, com o tempo dado por quem olha: as esperas da bancada —
/// o aperto de mão de um boot, o boot seguinte a um reinício, o aviso de
/// uma queda no boot — olham a máquina e perguntam aqui.
#[derive(Debug)]
pub(crate) struct AndamentoDoBoot {
    janela: Duration,
    teto: Duration,
    inicio: Instant,
    /// Quando um sinal mudou pela última vez — a partida, antes do primeiro.
    andou: Instant,
    /// Os sinais da última olhada; a primeira é a base.
    vistos: Option<Sinais>,
    /// O maior intervalo sem sinal novo até a última mudança.
    maior_parada: Duration,
}

/// Por que a espera de uma máquina acabou sem ela atender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Desistencia {
    /// Nenhum sinal mudou por `parada`; o último mudou `andou` depois da
    /// partida.
    Parou { parada: Duration, andou: Duration },
    /// O teto passou, com a máquina andando: o último sinal mudou há
    /// `parada`.
    Teto { teto: Duration, parada: Duration },
}

impl std::fmt::Display for Desistencia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Desistencia::Parou { parada, andou } => write!(
                f,
                "a maquina parou de andar: nada novo na serial, nos discos nem no canal ha {}s (o ultimo sinal veio {}s depois da partida)",
                parada.as_secs(),
                andou.as_secs()
            ),
            Desistencia::Teto { teto, parada } => write!(
                f,
                "a maquina passou do teto de {}s andando (o ultimo sinal veio ha {}s)",
                teto.as_secs(),
                parada.as_secs()
            ),
        }
    }
}

impl AndamentoDoBoot {
    /// A espera de uma máquina ligada em `inicio`.
    pub(crate) fn novo(inicio: Instant, janela: Duration, teto: Duration) -> AndamentoDoBoot {
        AndamentoDoBoot {
            janela,
            teto,
            inicio,
            andou: inicio,
            vistos: None,
            maior_parada: Duration::ZERO,
        }
    }

    /// Uma olhada na máquina, em `agora`, com os sinais dela — ou sem
    /// sinais: a olhada que não sabe nada novo só passa o tempo. `Ok`
    /// enquanto a espera segue.
    ///
    /// A primeira olhada com sinais é a base, e não conta como andar: o
    /// que veio antes dela não se sabe quando veio, e a janela já corre
    /// desde a partida.
    pub(crate) fn olhar(
        &mut self,
        agora: Instant,
        sinais: Option<Sinais>,
    ) -> Result<(), Desistencia> {
        match (self.vistos, sinais) {
            (None, Some(s)) => self.vistos = Some(s),
            (Some(antes), Some(s)) if antes != s => {
                self.maior_parada = self
                    .maior_parada
                    .max(agora.saturating_duration_since(self.andou));
                self.vistos = Some(s);
                self.andou = agora;
            }
            _ => {}
        }
        let parada = agora.saturating_duration_since(self.andou);
        if parada >= self.janela {
            return Err(Desistencia::Parou {
                parada,
                andou: self.andou.saturating_duration_since(self.inicio),
            });
        }
        if agora.saturating_duration_since(self.inicio) >= self.teto {
            return Err(Desistencia::Teto {
                teto: self.teto,
                parada,
            });
        }
        Ok(())
    }

    /// O maior intervalo sem sinal novo de uma máquina que atendeu em
    /// `agora`: o trecho do último sinal até o atendimento conta também —
    /// passando da janela, ela não teria atendido.
    pub(crate) fn maior_parada_ate(&self, agora: Instant) -> Duration {
        self.maior_parada
            .max(agora.saturating_duration_since(self.andou))
    }
}

/// O quanto os discos de uma máquina já fizeram, somado — os bytes e as
/// operações de leitura, de escrita e de descarga de cada um —, pela
/// resposta do `info blockstats` que o QMP devolve: uma linha por disco,
/// `<nome>: rd_bytes=… wr_bytes=… …`, dentro de uma string JSON com as
/// quebras de linha escapadas. Os tempos ficam de fora: o `idle_time_ns`
/// anda com o relógio, com o disco parado. `None` se a resposta não traz
/// contador nenhum — o QMP que ainda não respondeu, ou outra resposta.
pub(crate) fn atividade_dos_discos(resposta: &str) -> Option<u64> {
    const CONTADORES: [&str; 5] = [
        "rd_bytes",
        "wr_bytes",
        "rd_operations",
        "wr_operations",
        "flush_operations",
    ];
    let mut soma: Option<u64> = None;
    for palavra in resposta.split(|c: char| c.is_whitespace() || c == '\\' || c == '"') {
        if let Some((nome, valor)) = palavra.split_once('=')
            && CONTADORES.contains(&nome)
            && let Ok(v) = valor.parse::<u64>()
        {
            soma = Some(soma.unwrap_or(0).saturating_add(v));
        }
    }
    soma
}

/// Os discos de uma máquina, pelo QMP `qmp`: [`atividade_dos_discos`].
fn discos_pelo_qmp(qmp: &Path) -> Option<u64> {
    let (mut escrita, mut leitor) = super::qmp_abrir(qmp).ok()?;
    let r = super::qmp_pedir(
        &mut escrita,
        &mut leitor,
        r#"{"execute":"human-monitor-command","arguments":{"command-line":"info blockstats"}}"#,
    )
    .ok()?;
    atividade_dos_discos(&r)
}

/// Quem olha uma máquina de fora, para o [`AndamentoDoBoot`]: a serial
/// humana do cenário, os discos pelo QMP e o que o canal mostrou.
///
/// Os caminhos são os da partida. A raiz de uma máquina é a do fio que a
/// ligou — ver [`super::na_raiz`] —, e quem espera por ela depois, num
/// reinício, pode estar fora dessa raiz.
struct Olhos {
    /// O QMP do emulador.
    qmp: PathBuf,
    /// A serial humana do cenário — ver [`serial_do_cenario`].
    serial: Option<PathBuf>,
    /// O log de depuração do firmware, no x86 — ver [`lancar`].
    firmware: Option<PathBuf>,
    /// O arquivo do código do firmware, na máquina que sobe por ele: de
    /// onde o diagnóstico tira o nome das imagens sem o CodeView — ver
    /// [`super::firmware`].
    codigo_do_firmware: Option<PathBuf>,
    /// No ARM a única serial é o canal: o que as esperas leem dele antes de
    /// a máquina atender vai para a serial do cenário, como a COM1 do x86.
    canal_na_serial: bool,
    /// Os discos na última olhada que o QMP respondeu.
    discos: u64,
    /// Os bytes que o canal mostrou até aqui.
    canal: u64,
    /// Quando o QMP foi perguntado pela última vez: uma vez por segundo
    /// basta, e cada pergunta é uma conexão.
    qmp_olhado: Option<Instant>,
}

impl Olhos {
    /// Os olhos de uma máquina que `arch` acaba de ligar, com o log de
    /// depuração do firmware em `firmware` e o código dele em `codigo`.
    fn da_partida(arch: Arquitetura, firmware: Option<PathBuf>, codigo: Option<PathBuf>) -> Olhos {
        Olhos {
            qmp: super::caminho_qmp(arch),
            serial: serial_do_cenario(),
            firmware,
            codigo_do_firmware: codigo,
            canal_na_serial: arch == Arquitetura::Aarch64,
            discos: 0,
            canal: 0,
            qmp_olhado: None,
        }
    }

    /// O que uma espera leu do canal antes de a máquina atender: conta como
    /// andamento, e, no ARM, vai para a serial do cenário — é por ela que o
    /// cenário que reprova mostra onde o firmware e o iniciador pararam. São
    /// amostras, e não o fluxo inteiro (ver [`super::canal_de_pe_com`]):
    /// cada uma acaba numa quebra de linha, para não emendar na seguinte.
    fn ouvir_o_canal(&mut self, lidos: &[u8]) {
        use std::io::Write;
        if lidos.is_empty() {
            return;
        }
        self.canal = self.canal.saturating_add(lidos.len() as u64);
        if self.canal_na_serial
            && let Some(caminho) = &self.serial
            && let Ok(mut arquivo) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(caminho)
        {
            let _ = arquivo.write_all(lidos);
            if !lidos.ends_with(b"\n") {
                let _ = arquivo.write_all(b"\n");
            }
        }
    }

    /// Os sinais da máquina em `agora`. O QMP que não responde deixa os
    /// discos como estavam.
    fn sinais(&mut self, agora: Instant) -> Sinais {
        if self
            .qmp_olhado
            .is_none_or(|t| agora.saturating_duration_since(t) >= Duration::from_secs(1))
        {
            self.qmp_olhado = Some(agora);
            if let Some(d) = discos_pelo_qmp(&self.qmp) {
                self.discos = d;
            }
        }
        Sinais {
            serial: self
                .serial
                .as_deref()
                .and_then(|c| std::fs::metadata(c).ok())
                .map_or(0, |m| m.len()),
            discos: self.discos,
            canal: self.canal,
        }
    }
}

/// Quantas linhas do fim do log do `swtpm` o diagnóstico mostra.
const LINHAS_DO_TPM: usize = 15;

/// Quantas linhas do fim do log de depuração do firmware o diagnóstico
/// mostra.
const LINHAS_DO_FIRMWARE: usize = 25;

/// O TPM e o firmware de uma máquina que não atendeu, para o diagnóstico:
/// se o `swtpm` vive, o fim do log dele — no nível dos erros, que não
/// mostra segredo (ver [`Ambiente::ligar`]) —, e o fim do log de depuração
/// do firmware — ou que cada um está vazio. Cada parte numa linha nova, com
/// o recuo do diagnóstico.
///
/// Na CI 413, o firmware parou depois de um reinício pedido pelo kernel,
/// antes de carregar a opção de boot, e o TPM — que essa fase usa — era o
/// suspeito; nem o log do `swtpm` nem o do firmware saíam da CI.
fn tpm_e_firmware(ambiente: &mut Ambiente, firmware: Option<&Path>) -> String {
    let mut s = String::new();
    let log = ambiente.log_do_tpm();
    match ambiente.tpm.as_mut() {
        None => s.push_str("\n  sem TPM nesta maquina"),
        Some((tpm, _)) => {
            let estado = match tpm.try_wait() {
                Ok(None) => "vivo".to_string(),
                Ok(Some(saida)) => format!("saiu ({saida})"),
                Err(e) => format!("sem estado ({e})"),
            };
            s.push_str(&format!("\n  o swtpm: {estado}"));
            if let Some(log) = log {
                s.push_str(&fim_do_log("swtpm", &log, LINHAS_DO_TPM, "nenhum erro"));
            }
        }
    }
    if let Some(firmware) = firmware {
        s.push_str(&fim_do_log(
            "firmware",
            firmware,
            LINHAS_DO_FIRMWARE,
            "um firmware de release nao escreve no debugcon",
        ));
    }
    s
}

/// O fim de um log para o diagnóstico: as últimas `n` linhas, sem os
/// controles de terminal, cada uma com o rótulo — ou uma linha que diz que
/// ele está vazio, e o que isso quer dizer, `vazio`.
fn fim_do_log(rotulo: &str, caminho: &Path, n: usize, vazio: &str) -> String {
    let texto = std::fs::read(caminho)
        .map(|b| sem_controles(&b))
        .unwrap_or_default();
    if texto.trim().is_empty() {
        return format!(
            "\n  o log do {rotulo} esta vazio ({}): {vazio}",
            caminho.display()
        );
    }
    let linhas = ultimas_linhas(&texto, n);
    let mut s = format!(
        "\n  as ultimas {} linhas do log do {rotulo} ({}):",
        linhas.len(),
        caminho.display()
    );
    for linha in linhas {
        s.push_str(&format!("\n  [{rotulo}] {linha}"));
    }
    s
}

/// O texto de uma saída de terminal, legível numa linha de log: os
/// controles — o escape das sequências do console do firmware, o retorno
/// de carro — viram espaço, e o resto fica como veio. As sequências ficam à
/// vista de propósito: na CI 413, as do firmware depois do pânico eram a
/// prova de que ele tinha voltado, e parado antes de escrever texto.
pub(crate) fn sem_controles(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect()
}

/// As últimas `n` linhas de `texto`, sem o espaço do fim.
pub(crate) fn ultimas_linhas(texto: &str, n: usize) -> Vec<&str> {
    let linhas: Vec<&str> = texto.lines().map(str::trim_end).collect();
    linhas[linhas.len().saturating_sub(n)..].to_vec()
}

/// O maior intervalo sem sinal novo que um boot que atendeu teve nesta
/// execução, em milissegundos — ver [`relatar_a_maior_parada`].
static MAIOR_PARADA_MS: AtomicU64 = AtomicU64::new(0);

/// Guarda o intervalo sem sinal novo de um boot que atendeu.
fn registrar_a_parada(parada: Duration) {
    MAIOR_PARADA_MS.fetch_max(
        u64::try_from(parada.as_millis()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

/// Diz, no fim de uma bancada, o maior intervalo sem sinal novo que um boot
/// que atendeu teve: é o número com que a [`JANELA_SEM_ANDAR`] se refaz,
/// como a suíte faz com a dela.
pub(crate) fn relatar_a_maior_parada(bancada: &str) {
    let ms = MAIOR_PARADA_MS.load(Ordering::Relaxed);
    if ms > 0 {
        println!(
            "[xtask] {bancada}: o maior intervalo sem sinal novo num boot que atendeu foi de {}s (a janela e de {}s)",
            ms / 1000,
            JANELA_SEM_ANDAR.as_secs()
        );
    }
}

impl Drop for Ligada {
    fn drop(&mut self) {
        self.perguntar_o_motivo_se_recusou();
        let _ = self.filho.kill();
        let _ = self.filho.wait();
    }
}

// ---------------------------------------------------------------------------
// A recusa que diz o motivo (CI 439)
// ---------------------------------------------------------------------------

/// Uma resposta da máquina disse `DENY_REVOCATION` desde o último fim de
/// máquina que perguntou o porquê — ver [`notar_a_resposta`].
static RECUSA_DE_REVOGACAO: AtomicBool = AtomicBool::new(false);

/// A resposta `r` recusa porque a identidade não vale agora: revogada, ou
/// o journal recusado e as revogações sem se saber.
fn diz_revogacao(r: &str) -> bool {
    r.contains(r#""reason":"DENY_REVOCATION""#)
}

/// Olha uma resposta da máquina, da serial ou de uma porta de agente: a
/// que diz `DENY_REVOCATION` faz o fim da máquina perguntar o porquê.
///
/// # Por quê
///
/// Na CI 439, o primeiro boot de um cenário, sobre o estado zerado, teve
/// o journal recusado, e o motivo não chegou ao log: a recusa da escrita
/// do slot diz só `DENY_REVOCATION`, e, no ARM, o log do kernel fica no
/// anel dele — a serial é o canal. Com o journal recusado, o gate recusa
/// toda credencial, até a leitura do `system.info` pela porta do agente;
/// a serial da bancada, que não é credenciada, ainda lê. Então o fim da
/// máquina ([`Ligada`]) pergunta por ela, antes de matar o emulador, e
/// imprime o estado e o motivo da persistência — também nos cenários que
/// provocam a recusa de propósito, onde a linha só confirma o que eles
/// conferem. O fim é o corte de energia do cenário
/// ([`Ligada::cortar_a_energia`]), ou o `Drop`; o [`Ligada::cortar`] que a
/// bancada do enlace usa no meio do cenário não pergunta.
///
/// A marca é uma só para a bancada: com duas máquinas de pé ao mesmo
/// tempo, quem pergunta é a primeira que acabar.
pub(crate) fn notar_a_resposta(r: &str) {
    if diz_revogacao(r) {
        RECUSA_DE_REVOGACAO.store(true, Ordering::Release);
    }
}

/// Esquece a recusa que nenhum fim de máquina perguntou: cada cenário
/// começa sem ela.
pub(crate) fn esquecer_a_recusa_de_revogacao() {
    RECUSA_DE_REVOGACAO.store(false, Ordering::Release);
}

/// O estado da persistência e o motivo, numa resposta do `system.info`: o
/// motivo inteiro, com as vírgulas dele.
fn estado_e_motivo(r: &str) -> Option<(String, String)> {
    let p = protocolo::json::Json(r.as_bytes())
        .member("result")?
        .member("persistence")?;
    let estado = p.member("state")?.as_str()?;
    let motivo = p.member("reason").and_then(|m| m.as_str()).unwrap_or("");
    Some((estado.to_string(), motivo.to_string()))
}

impl Ligada {
    /// Se uma resposta disse `DENY_REVOCATION` — ver [`notar_a_resposta`]
    /// —, pergunta à máquina, pela serial, o estado da persistência e o
    /// motivo, e os imprime. Cinco segundos: a máquina que não responde não
    /// segura o fim do cenário; a que já acabou — o emulador saiu — não é
    /// perguntada.
    fn perguntar_o_motivo_se_recusou(&mut self) {
        if !RECUSA_DE_REVOGACAO.swap(false, Ordering::AcqRel) {
            return;
        }
        let dito = if matches!(self.filho.try_wait(), Ok(Some(_))) {
            "a maquina ja tinha acabado".to_string()
        } else {
            let _ = self.esperar_respostas_por(Duration::from_secs(5));
            match self.pedir("system.info", "{}") {
                Ok(r) => match estado_e_motivo(&r) {
                    Some((estado, motivo)) => format!("{estado} ({motivo})"),
                    None => "o system.info nao diz a persistencia".to_string(),
                },
                Err(e) => format!(
                    "a maquina nao respondeu ({})",
                    e.lines().next().unwrap_or("")
                ),
            }
        };
        // A pergunta não é uma recusa nova: a resposta dela não marca nada.
        esquecer_a_recusa_de_revogacao();
        println!(
            "  [persistencia]   uma resposta disse DENY_REVOCATION; a persistencia da maquina: {dito}"
        );
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
        nome: "a auditoria sob carga e leitura sobrevive ao corte: o audit.tail segue a cadeia sem pular nem repetir, o audit.verify sempre confere, e o gravado volta igual",
        rodar: a_auditoria_sob_carga_e_leitura,
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
        nome: "o TPM que demora a responder: a gravacao espera por ele, e a persistencia nao o da por morto",
        rodar: o_tpm_que_demora_a_responder,
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
        nome: "a queda em cada fronteira do registro de boot: a cadeia que o boot continuou vale exatamente quando ele esta no disco, o gravado antes volta igual, e a cadeia continua",
        rodar: as_quedas_no_registro_de_boot,
    },
    Cenario {
        nome: "a queda no meio da coleta da auditoria sob carga: o gravado volta igual, sem buraco nem repeticao, e a cadeia continua",
        rodar: as_quedas_na_coleta_sob_carga,
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
            esquecer_a_recusa_de_revogacao();
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
    relatar_a_maior_parada("persistencia");
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

/// Onde vai a saída humana das máquinas do cenário que roda — a COM1 do
/// x86; no ARM, onde a única serial é o canal, o que as esperas leem dele
/// antes de a máquina atender (ver [`Olhos::ouvir_o_canal`]): cada boot
/// acrescenta a sua, e o começo de cada cenário a esvazia. Com
/// `DUKE_BANCADA_LOG`, vai para esse arquivo, que acumula todos.
///
/// Ela existe para o cenário que reprova: na CI 335, o primeiro boot de um
/// cenário não respondeu em 90 s, e nada dizia onde a máquina parou — o
/// firmware, o iniciador, ou que passo do kernel. E o tamanho dela é um dos
/// sinais de que a máquina anda — ver [`JANELA_SEM_ANDAR`].
pub(crate) fn serial_do_cenario() -> Option<std::path::PathBuf> {
    std::env::var_os("DUKE_BANCADA_LOG")
        .map(std::path::PathBuf::from)
        .or_else(|| SERIAL_DA_BANCADA.get().cloned())
}

/// O fim da serial do cenário que reprovou, na saída: as últimas linhas,
/// sem os controles de terminal do firmware — ver [`sem_controles`].
pub(crate) fn mostrar_o_fim_da_serial() {
    const LINHAS: usize = 40;
    let Some(caminho) = serial_do_cenario() else {
        return;
    };
    let Ok(bytes) = std::fs::read(&caminho) else {
        return;
    };
    let texto = sem_controles(&bytes);
    let linhas = ultimas_linhas(&texto, LINHAS);
    println!(
        "  [persistencia]   as ultimas {} linhas da serial ({}):",
        linhas.len(),
        caminho.display()
    );
    for linha in linhas {
        println!("  [serial] {linha}");
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
    /// sozinha, e o canal da serial é o mesmo —, pelo andamento dela, até o
    /// [`TETO_DO_BOOT`]. Os pedidos feitos no meio do reinício se perdem, e
    /// são feitos de novo.
    pub(crate) fn esperar_o_boot_seguinte(&mut self, boots: u64) -> Result<Persistencia, String> {
        self.esperar_o_boot_ate(boots, TETO_DO_BOOT)
    }

    /// [`Ligada::esperar_o_boot_seguinte`], com o teto `teto`: a
    /// atualização atravessa vários boots antes de um atender.
    ///
    /// A espera é pelo andamento, como a da partida (ver
    /// [`Ligada::subir_esperando`]), com uma diferença: enquanto o boot de
    /// antes ainda responde, os sinais não contam — a serial e os discos que
    /// ele mexe para responder não são o reinício andando. A máquina que não
    /// reinicia desiste na janela, e não no teto.
    pub(crate) fn esperar_o_boot_ate(
        &mut self,
        boots: u64,
        teto: Duration,
    ) -> Result<Persistencia, String> {
        let mut andamento = AndamentoDoBoot::novo(Instant::now(), JANELA_SEM_ANDAR, teto);
        loop {
            if let Ok(Some(status)) = self.filho.try_wait() {
                return Err(format!("a maquina saiu em vez de reiniciar: {status}"));
            }
            // A última resposta — o boot de antes, ou o erro do canal — vai na
            // desistência.
            let (reiniciando, ultimo) = match persistencia_de(self) {
                Ok(p) if p.boots > boots => {
                    registrar_a_parada(andamento.maior_parada_ate(Instant::now()));
                    return Ok(p);
                }
                Ok(p) => (false, format!("ainda o boot {}", p.boots)),
                Err(e) => (true, e),
            };
            let agora = Instant::now();
            let sinais = reiniciando.then(|| self.olhos.sinais(agora));
            if let Err(d) = andamento.olhar(agora, sinais) {
                let estado =
                    estado_do_emulador(&self.olhos.qmp, self.olhos.codigo_do_firmware.as_deref());
                let tpm = tpm_e_firmware(&mut self._ambiente, self.olhos.firmware.as_deref());
                return Err(format!(
                    "o boot seguinte nao respondeu: {d}; a ultima resposta: {ultimo}\n  o emulador, pelo QMP: {estado}{tpm}"
                ));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
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

/// A cauda da auditoria: os últimos [`MAIOR_CAUDA`] registros, pela
/// serial. Um registro de antes de um boot, ou de antes de muitas leituras,
/// se procura em [`auditoria_do_anel`] ou pelo número
/// ([`registro_de_numero`]).
pub(crate) fn cauda_da_auditoria(maquina: &mut Ligada) -> Result<Vec<Rastro>, String> {
    rastros(&maquina.pedir("audit.tail", &format!(r#"{{"count":{MAIOR_CAUDA}}}"#))?)
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

/// Quantos registros o `audit.tail` dá numa leitura, no máximo — o teto do
/// kernel (`MAIOR_CAUDA_DA_AUDITORIA`, em `kernel/src/agent/commands.rs`).
pub(crate) const MAIOR_CAUDA: usize = 128;

/// Quantas leituras de [`MAIOR_CAUDA`] a [`auditoria_do_anel_por`] faz, no
/// máximo: o anel do kernel guarda 1024 registros (`CAPACIDADE_DA_AUDITORIA`),
/// oito lotes, e cada leitura põe mais um nele.
const MAIS_LOTES_DO_ANEL: usize = 16;

/// Os registros depois de `depois`, do mais velho para o mais novo, até
/// `quantos`: o `audit.tail` com `after`, que lê o anel inteiro da
/// auditoria — e não só os últimos [`MAIOR_CAUDA`]. Vazio, se nenhum.
///
/// `pedir` faz o `audit.tail` com os parâmetros que recebe, por qualquer
/// canal: a serial de uma [`Ligada`], a porta de um agente.
fn depois_de(
    pedir: &mut impl FnMut(&str) -> Result<String, String>,
    depois: u64,
    quantos: usize,
) -> Result<Vec<Rastro>, String> {
    let r = pedir(&format!(r#"{{"after":{depois},"count":{quantos}}}"#))?;
    if !r.contains(r#"{"seq":"#) {
        return Ok(Vec::new());
    }
    rastros(&r)
}

/// A auditoria inteira que o anel guarda, do mais velho ao mais novo: o
/// `audit.tail` com `after`, em lotes de [`MAIOR_CAUDA`], até um lote
/// menor. Cada leitura entra na própria auditoria, e a última traz a si
/// mesma: o laço acaba — e, se não acabar em [`MAIS_LOTES_DO_ANEL`], é
/// erro.
///
/// É onde se procura um registro de antes de um boot. Os últimos
/// [`MAIOR_CAUDA`] — [`cauda_da_auditoria`] — não bastam quando o cenário
/// leu a auditoria muitas vezes depois dele: a cadeia que voltou do journal
/// traz essas leituras, e o boot seguinte põe as dele depois. Foi o que
/// reprovou a troca da senha nas CIs 452, 458 e 459: a decisão tinha
/// voltado do journal, mais de 128 registros antes da cabeça.
///
/// Quem conclui que um registro **não** está precisa conferir também onde
/// o anel começa: um anel que já perdeu os primeiros não diz nada deles.
pub(crate) fn auditoria_do_anel_por(
    pedir: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<Vec<Rastro>, String> {
    let mut todos: Vec<Rastro> = Vec::new();
    let mut depois = 0;
    for _ in 0..MAIS_LOTES_DO_ANEL {
        let lote = depois_de(pedir, depois, MAIOR_CAUDA)?;
        let cheio = lote.len() >= MAIOR_CAUDA;
        if let Some(r) = lote.last() {
            depois = r.seq;
        }
        todos.extend(lote);
        if !cheio {
            return Ok(todos);
        }
    }
    Err(format!(
        "a auditoria do anel nao acabou em {MAIS_LOTES_DO_ANEL} leituras de {MAIOR_CAUDA}: ia em {depois}"
    ))
}

/// [`auditoria_do_anel_por`], pela serial da máquina.
pub(crate) fn auditoria_do_anel(maquina: &mut Ligada) -> Result<Vec<Rastro>, String> {
    auditoria_do_anel_por(&mut |q| maquina.pedir("audit.tail", q))
}

/// O registro de número `seq`, procurado no anel inteiro da auditoria — ver
/// [`auditoria_do_anel_por`]. `Err`, dizendo qual, se o anel já não o tem
/// ou ainda não chegou a ele: nos dois casos, nada se conclui dele.
///
/// O número sozinho não identifica um registro entre boots: o que não ficou
/// no journal tem o número reusado pelo boot seguinte — e a própria leitura
/// grava a si mesma antes de responder, com o número seguinte à cabeça.
/// Quem procura um registro de antes do corte compara o que veio com o que
/// viu antes dele, o elo da cadeia inclusive.
pub(crate) fn registro_de_numero_por(
    pedir: &mut impl FnMut(&str) -> Result<String, String>,
    seq: u64,
) -> Result<Rastro, String> {
    match depois_de(pedir, seq.saturating_sub(1), 1)?
        .into_iter()
        .next()
    {
        Some(r) if r.seq == seq => Ok(r),
        Some(r) => Err(format!(
            "o registro {seq} ja saiu do anel da auditoria: o mais velho e o {}",
            r.seq
        )),
        None => Err(format!("a auditoria ainda nao chegou ao registro {seq}")),
    }
}

/// [`registro_de_numero_por`], pela serial da máquina.
pub(crate) fn registro_de_numero(maquina: &mut Ligada, seq: u64) -> Result<Rastro, String> {
    registro_de_numero_por(&mut |q| maquina.pedir("audit.tail", q), seq)
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

/// Quanto o cenário do TPM que demora segura o `swtpm` parado, no boot e
/// numa gravação.
///
/// # Por que no boot também
///
/// O teto antigo, em voltas, não tinha duração: era o custo de cinco
/// milhões de leituras de registrador no emulador, e esse custo muda depois
/// do boot. No boot, com um núcleo só, as cinco milhões foram de 2,5 a
/// 2,7 s no x86 emulado, no kernel de depuração — e foi no boot que a CI
/// 471 reprovou. Depois do boot, com os quatro núcleos ligados, a volta
/// custa mais — a causa não foi medida —, e o teto antigo passou dos dez
/// segundos: uma parada de dez segundos antes de uma gravação não o
/// estourava, e só a do boot pega o código de antes. Doze segundos: a
/// espera do teto antigo começa uns 1,4 s depois da parada, pelo relógio
/// do log, e os até 10,6 s que sobram são perto de quatro vezes ele; e os
/// doze são menos da metade do prazo do kernel (`ESPERA_MS`, em
/// `kernel/src/tpm.rs`).
const SEGURADO_NO_TPM: Duration = Duration::from_secs(12);

/// O TPM que demora a responder: o `swtpm` parado — o `SIGSTOP` — por
/// [`SEGURADO_NO_TPM`], no boot e numa gravação. O kernel espera o prazo
/// dele, em tempo, e não dá o TPM por morto:
/// - no boot, parado desde a primeira linha do kernel — antes de a
///   persistência abrir, que é quando o kernel manda o primeiro comando a
///   ele, na imagem da bancada, cuja identidade é a chave da imagem —, a
///   máquina só atende depois que o TPM volta, e a persistência abre;
/// - parado antes de uma gravação, que o encontra parado quando o journal
///   avança o contador da âncora — o primeiro comando dela ao TPM —, nada
///   responde com o TPM parado, e a gravação confirma depois;
/// - nos dois, a persistência segue disponível, o log não tem erro do TPM —
///   nem o aviso do avanço que falhou e foi conferido pela leitura —, e a
///   gravação seguinte confirma.
///
/// Pelo TIS e, no x86, pela CRB, cada uma num boot; o boot seguinte abre
/// com a última gravação de cada interface, o journal e a âncora de
/// acordo, e a auditoria verifica. A parada do boot é só no x86: ela espera
/// a primeira linha do kernel na serial do cenário, que no x86 é a COM1
/// inteira, escrita pelo emulador, e no ARM só o que as esperas leem do
/// canal — ver [`Olhos::ouvir_o_canal`].
///
/// A parada do boot é a falha da CI 471 num ponto exato: lá, o `swtpm`
/// ficou mais que o teto antigo em voltas sem responder no primeiro boot de
/// um cenário, e a persistência abriu recusada (`o TPM nao respondeu`). A
/// parada antes da gravação não é: depois do boot, o teto antigo passava
/// dos dez segundos.
fn o_tpm_que_demora_a_responder(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    const DIR: &str = "/armazem/lento";
    let interfaces: &[&str] = if arch == Arquitetura::X86_64 {
        &["TIS", "CRB"]
    } else {
        &["TIS"]
    };
    let mut relato = Vec::new();
    let mut primeiro = None;
    for &interface in interfaces {
        let por = pela_interface(interface);
        let mut ambiente = Ambiente::ligar(arch, None)?;
        ambiente.crb = interface == "CRB";
        let (mut m, no_boot) = if arch == Arquitetura::X86_64 {
            subir_com_o_tpm_parado(arch, artefato, ambiente)?
        } else {
            (
                Ligada::subir_com(arch, artefato, ambiente)?,
                "o boot sem parar o TPM".into(),
            )
        };
        let p = persistencia_de(&mut m)?;
        if p.estado != "available" || p.interface != interface {
            return Err(format!(
                "{por}, {no_boot}: a persistencia ficou {} ({}), interface {}",
                p.estado, p.motivo, p.interface
            ));
        }
        nenhum_erro_do_tpm_no_log(&mut m, &por)?;
        primeiro.get_or_insert(p.boots);
        if primeiro == Some(p.boots) {
            no_armazem(&mut m, "fs.mkdir", &format!(r#"{{"path":"{DIR}"}}"#))?;
        }
        let na_gravacao = gravar_com_o_tpm_parado(&mut m, interface, DIR)?;
        relato.push(format!("{por}, {no_boot}; {na_gravacao}"));
        m.cortar_a_energia()?;
    }

    let mut m = Ligada::subir(arch, artefato, None)?;
    let depois = persistencia_de(&mut m)?;
    let antes = primeiro.unwrap_or_default();
    if depois.estado != "available" || depois.boots <= antes {
        return Err(format!(
            "o boot depois do TPM que demorou: {} ({}), boot {} depois de {}",
            depois.estado, depois.motivo, depois.boots, antes
        ));
    }
    // A última gravação de cada interface: a segunda, confirmada antes do
    // corte, por cima da que esperou o TPM.
    for &interface in interfaces {
        let caminho = format!("{DIR}/{interface}.txt");
        let por = pela_interface(interface);
        let lido = m.pedir("fs.read", &format!(r#"{{"path":"{caminho}"}}"#))?;
        if !lido.contains(&format!("depois do TPM, {por}, de novo")) {
            return Err(format!(
                "a ultima gravacao confirmada {por} nao voltou\n  {lido}"
            ));
        }
    }
    auditoria_verifica(&mut m)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o TPM parado por {} s: {}; o boot {} abriu com a ultima gravacao de cada interface",
        SEGURADO_NO_TPM.as_secs(),
        relato.join("; "),
        depois.boots
    ))
}

/// Liga a máquina no `ambiente` com o `swtpm` dela parado por
/// [`SEGURADO_NO_TPM`] desde a primeira linha do kernel na serial do
/// cenário — o firmware e o iniciador já não falam com o TPM, e o kernel
/// ainda não falou. Só no x86: ver [`o_tpm_que_demora_a_responder`].
///
/// A máquina tem de atender só depois que o TPM volta: o canal do agente
/// sobe depois de a persistência abrir, e ela não abre sem ele. Uma
/// máquina que atende antes não passou pelo TPM — ou o deu por morto.
fn subir_com_o_tpm_parado(
    arch: Arquitetura,
    artefato: &Artefato,
    ambiente: Ambiente,
) -> Result<(Ligada, String), String> {
    let pid = ambiente
        .tpm
        .as_ref()
        .map(|(tpm, _)| tpm.id())
        .ok_or("a maquina do cenario nao tem TPM")?;
    let serial = serial_do_cenario().ok_or("o cenario nao tem a serial onde esperar o kernel")?;
    let desde = std::fs::metadata(&serial).map_or(0, |m| m.len());
    let acabou = std::sync::Arc::new(AtomicBool::new(false));
    let vigia = {
        let acabou = acabou.clone();
        std::thread::spawn(move || parar_o_tpm_no_kernel(&serial, desde, pid, &acabou))
    };
    let ligada = Ligada::subir_com(arch, artefato, ambiente);
    let atendeu = Instant::now();
    acabou.store(true, Ordering::Release);
    let parada = vigia
        .join()
        .map_err(|_| String::from("o vigia do TPM entrou em panico"))?;
    let m = ligada?;
    let (parou, soltou) = parada?;
    if atendeu < soltou {
        return Err(format!(
            "a maquina atendeu {:.1} s depois de o TPM parar, e ele ficou parado {} s: o boot nao passou por ele",
            atendeu.duration_since(parou).as_secs_f64(),
            SEGURADO_NO_TPM.as_secs()
        ));
    }
    Ok((
        m,
        format!(
            "o boot atendeu {:.1} s depois de o TPM parar",
            atendeu.duration_since(parou).as_secs_f64()
        ),
    ))
}

/// O vigia de [`subir_com_o_tpm_parado`]: espera a primeira linha do kernel
/// na serial, depois de `desde`, e para o `swtpm` `pid` por
/// [`SEGURADO_NO_TPM`]; devolve quando parou e quando soltou. Desiste —
/// sem parar nada — quando `acabou`: a máquina subiu ou caiu antes.
fn parar_o_tpm_no_kernel(
    serial: &Path,
    desde: u64,
    pid: u32,
    acabou: &AtomicBool,
) -> Result<(Instant, Instant), String> {
    use std::io::{Read, Seek, SeekFrom};
    const PRIMEIRA_LINHA: &[u8] = b"Duke iniciado em";
    let mut lido = Vec::new();
    let mut pos = desde;
    loop {
        if acabou.load(Ordering::Acquire) {
            return Err(
                "a maquina atendeu, ou caiu, antes da primeira linha do kernel na serial".into(),
            );
        }
        if let Ok(mut arquivo) = std::fs::File::open(serial)
            && arquivo.seek(SeekFrom::Start(pos)).is_ok()
        {
            let mut novo = Vec::new();
            if arquivo.read_to_end(&mut novo).is_ok() {
                pos += novo.len() as u64;
                lido.extend_from_slice(&novo);
            }
        }
        if lido
            .windows(PRIMEIRA_LINHA.len())
            .any(|w| w == PRIMEIRA_LINHA)
        {
            break;
        }
        // Só o fim pode emendar com a leitura seguinte.
        if lido.len() > PRIMEIRA_LINHA.len() {
            lido.drain(..lido.len() - PRIMEIRA_LINHA.len());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    segurar_o_swtpm(pid, true)?;
    let parou = Instant::now();
    std::thread::sleep(SEGURADO_NO_TPM);
    let solto = segurar_o_swtpm(pid, false);
    let soltou = Instant::now();
    solto.map(|()| (parou, soltou))
}

/// Os erros do TPM no log da máquina: os de transporte
/// (`kernel/src/tpm.rs`), a persistência recusada por eles, e o aviso do
/// avanço do contador que falhou e foi conferido pela leitura
/// (`avancar_a_ancora`, em `kernel/src/persistencia.rs`).
fn nenhum_erro_do_tpm_no_log(m: &mut Ligada, por: &str) -> Result<(), String> {
    let avisos = m.pedir("log.tail", r#"{"count":256,"min_level":"warn"}"#)?;
    for sinal in [
        "o TPM nao",
        "o TPM parou",
        "a CRB nao",
        "o avanco do contador falhou",
    ] {
        if avisos.contains(sinal) {
            return Err(format!(
                "{por}, o log tem um erro do TPM que demorou (`{sinal}`)\n  {avisos}"
            ));
        }
    }
    Ok(())
}

/// Uma gravação em `dir` com o `swtpm` da máquina parado por
/// [`SEGURADO_NO_TPM`] — ver [`o_tpm_que_demora_a_responder`] —, e o que se
/// confere depois dela; o relato, com quanto ela esperou.
fn gravar_com_o_tpm_parado(m: &mut Ligada, interface: &str, dir: &str) -> Result<String, String> {
    let caminho = format!("{dir}/{interface}.txt");
    let por = pela_interface(interface);
    m.segurar_o_tpm(true)?;
    let comeco = Instant::now();
    let id = m.mandar(
        "fs.write",
        &format!(r#"{{"path":"{caminho}","content":"depois do TPM, {por}","expect_version":0}}"#),
    );
    // Com o TPM parado, nada responde: a gravação espera o contador da
    // âncora. Uma resposta antes de soltar é uma gravação que não passou
    // pelo TPM. Um kernel que desiste do avanço também pode não responder
    // antes — a leitura que confere espera de novo, e a gravação confirma
    // depois —: quem o pega é o log, abaixo.
    let parado = match m.esperar_respostas_por(SEGURADO_NO_TPM) {
        Ok(()) => m.proxima_resposta().ok(),
        Err(e) => Some((0, e)),
    };
    // Solto antes de conferir: um TPM parado para sempre deixaria a máquina
    // presa, e o cenário seguinte herdaria o `swtpm` dela.
    m.segurar_o_tpm(false)?;
    let id = id?;
    if let Some((de, r)) = parado {
        return Err(format!(
            "{por}, a resposta {de} veio em {:?}, com o TPM parado\n  {r}",
            comeco.elapsed()
        ));
    }
    m.esperar_respostas_por(Duration::from_secs(120))?;
    let r = loop {
        let (de, r) = m.proxima_resposta()?;
        if de == id {
            break r;
        }
    };
    let esperou = comeco.elapsed();
    m.esperar_respostas_por(Duration::from_secs(15))?;
    if !confirmada(&r) {
        return Err(format!(
            "{por}, com o TPM parado por {} s, a gravacao nao foi confirmada\n  {r}",
            SEGURADO_NO_TPM.as_secs()
        ));
    }
    let p = persistencia_de(m)?;
    if p.estado != "available" {
        return Err(format!(
            "{por}, depois do TPM que demorou, a persistencia ficou {} ({})",
            p.estado, p.motivo
        ));
    }
    nenhum_erro_do_tpm_no_log(m, &por)?;
    // O TPM de volta atende a gravação seguinte como sempre.
    let versao = versao_no_armazem(m, &caminho)?;
    no_armazem(
        m,
        "fs.write",
        &format!(
            r#"{{"path":"{caminho}","content":"depois do TPM, {por}, de novo","expect_version":{versao}}}"#
        ),
    )?;
    Ok(format!(
        "a gravacao confirmou em {:.1} s",
        esperou.as_secs_f64()
    ))
}

/// "pelo TIS", "pela CRB": a interface do TPM no texto do cenário.
fn pela_interface(interface: &str) -> String {
    match interface {
        "CRB" => "pela CRB".into(),
        outra => format!("pelo {outra}"),
    }
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
        ABERTURA, ARMAZEM, AUDITORIA, BASE_FIM, BOOT, MENSAGENS, OPERACAO, SELAGEM,
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
    let limite = Instant::now() + espera;
    esperar_o_aviso_com(leitor, |_| {
        if Instant::now() >= limite {
            Err(format!(
                "a maquina nao avisou a queda em {}s",
                espera.as_secs()
            ))
        } else {
            Ok(())
        }
    })
}

/// [`esperar_o_aviso`], com a espera decidida por quem chama: depois de
/// cada leitura que não trouxe o aviso, `seguir` recebe o que ela trouxe —
/// uma linha, a metade de uma num tempo sem nada, ou nada — e o erro dele
/// encerra a espera com ele.
fn esperar_o_aviso_com(
    leitor: &mut BufReader<UnixStream>,
    mut seguir: impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<u8, String> {
    use std::io::BufRead;
    let mut linha = String::new();
    loop {
        let antes = linha.len();
        match leitor.read_line(&mut linha) {
            Ok(0) => return Err("o canal fechou antes do aviso da queda".into()),
            Ok(_) => {
                if let Some(p) = aviso_de_queda(&linha) {
                    return Ok(p);
                }
                seguir(linha.as_bytes().get(antes..).unwrap_or_default())?;
                linha.clear();
            }
            // Um tempo sem nada: o que veio pela metade continua em `linha`.
            Err(_) => seguir(linha.as_bytes().get(antes..).unwrap_or_default())?,
        }
    }
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
    subir_ate_cair_em(arch, artefato, TETO_DO_BOOT)
}

/// [`subir_ate_cair`], com o teto `teto`: a queda num boot que vem depois
/// de outros — uma tentativa da atualização — demora mais.
pub(crate) fn subir_ate_cair_em(
    arch: Arquitetura,
    artefato: &Artefato,
    teto: Duration,
) -> Result<u8, String> {
    subir_ate_cair_com(arch, artefato, Ambiente::ligar(arch, None)?, teto)
}

/// [`subir_ate_cair_em`] no ambiente dado — o disco de uma imagem de
/// produção, digamos.
///
/// A espera pelo aviso é pelo andamento da máquina, como a da partida —
/// ver [`Ligada::subir_esperando`] —, e o que se lê do canal até o aviso
/// conta como andamento: no ARM é o console do firmware e o relatório do
/// iniciador. Desistindo, diz onde a máquina parou, como lá.
pub(crate) fn subir_ate_cair_com(
    arch: Arquitetura,
    artefato: &Artefato,
    mut ambiente: Ambiente,
    teto: Duration,
) -> Result<u8, String> {
    let (mut filho, socket, mut olhos) = lancar(arch, artefato, &ambiente)?;
    let mut andamento = AndamentoDoBoot::novo(Instant::now(), JANELA_SEM_ANDAR, teto);
    let mut seguir = |lidos: &[u8]| -> Result<(), String> {
        olhos.ouvir_o_canal(lidos);
        if matches!(filho.try_wait(), Ok(Some(_))) {
            return Err("o emulador saiu antes do aviso".to_string());
        }
        let agora = Instant::now();
        andamento
            .olhar(agora, Some(olhos.sinais(agora)))
            .map_err(|d| d.to_string())
    };
    let conectado = loop {
        if let Ok(f) = UnixStream::connect(&socket) {
            break Ok(f);
        }
        if let Err(e) = seguir(&[]) {
            break Err(format!("o socket da serial nao abriu: {e}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let caiu = conectado.and_then(|f| {
        f.set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| e.to_string())?;
        esperar_o_aviso_com(&mut BufReader::new(f), &mut seguir)
    });
    let caiu = caiu.map_err(|e| {
        format!(
            "a maquina nao avisou a queda: {e}\n  o emulador, pelo QMP: {}{}",
            estado_do_emulador(&olhos.qmp, olhos.codigo_do_firmware.as_deref()),
            tpm_e_firmware(&mut ambiente, olhos.firmware.as_deref())
        )
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

/// A queda em cada fronteira do registro de boot — o primeiro que um boot
/// grava, logo depois de adotar a cadeia que o journal refez: ele leva a
/// auditoria que o boot continuou nela, do `policy.load` dele em diante. É
/// a ponta da reconstrução que vai ao disco. O boot seguinte sobe com a
/// persistência de pé; a cadeia do boot que caiu está nela exatamente
/// quando o registro está no disco — o `policy.load` dele entre o do boot
/// de antes e o de agora, gravado, ou nenhum —; o que estava gravado antes
/// da queda volta com o mesmo número e o mesmo elo; a cadeia segue sem
/// buraco nem repetição, e se verifica; e a próxima operação grava a
/// decisão dela, que volta no boot seguinte.
///
/// O boot que cai é o segundo da máquina: o primeiro, sem plano, grava a
/// criação e a auditoria dele, e o que cai é um boot comum, que refaz a
/// cadeia de um journal que existe.
fn as_quedas_no_registro_de_boot(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let disco = disco_de_testes()?;
    for (i, (ponto, perder, vale, caso)) in QUEDAS_NA_GRAVACAO.into_iter().enumerate() {
        zerar_o_estado(arch)?;
        let mut m = Ligada::subir(arch, artefato, None)?;
        let gravada = esperar_a_auditoria_gravada(&mut m);
        m.cortar_a_energia()?;
        let antes = gravada.map_err(|e| format!("{caso}: o boot antes da queda: {e}"))?;
        let primeiro_boot =
            comeco_do_boot(&antes).map_err(|e| format!("{caso}: o boot antes da queda: {e}"))?;
        plano_de_queda(&disco, ponto, tipo::BOOT, 1)?;
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
        if p.estado != "available" {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: o boot seguinte deixou a persistencia {} ({})",
                p.estado, p.motivo
            ));
        }
        let cauda = cauda_da_auditoria(&mut m)?;
        let comeco = comeco_do_boot(&cauda)?;
        // A cadeia do boot que caiu, entre o `policy.load` do primeiro e o
        // de agora: inteira e gravada se o registro de boot vale, e nada
        // dela se não vale.
        let do_que_caiu: Vec<&Rastro> = cauda
            .iter()
            .filter(|r| r.metodo == "policy.load" && r.titular == "kernel")
            .filter(|r| r.seq > primeiro_boot && r.seq < comeco)
            .collect();
        if do_que_caiu.len() > 1
            || (do_que_caiu.len() == 1) != vale
            || do_que_caiu.iter().any(|r| !r.duravel)
        {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: o boot que caiu tem {} policy.load na cadeia, e o registro de boot {}",
                do_que_caiu.len(),
                if vale { "vale" } else { "nao vale" }
            ));
        }
        // O que estava gravado antes da queda volta igual: o mesmo número e
        // o mesmo elo.
        let mut iguais = 0;
        for r in antes.iter().filter(|r| r.duravel) {
            if let Some(d) = cauda.iter().find(|d| d.seq == r.seq) {
                if d.elo != r.elo || d.metodo != r.metodo {
                    m.cortar_a_energia()?;
                    return Err(format!(
                        "{caso}: o registro {} gravado antes da queda voltou outro",
                        r.seq
                    ));
                }
                iguais += 1;
            }
        }
        if iguais == 0 {
            m.cortar_a_energia()?;
            return Err(format!(
                "{caso}: a cauda nao alcanca nada do que estava gravado antes da queda"
            ));
        }
        // Sem buraco nem repetição: a cauda segue de um em um.
        if cauda.windows(2).any(|par| par[1].seq != par[0].seq + 1) {
            m.cortar_a_energia()?;
            return Err(format!("{caso}: a cadeia pula ou repete depois da queda"));
        }
        auditoria_verifica(&mut m)?;
        let nome = format!("boot-{i}");
        let r = administrar(
            &mut m,
            &chaves.administrador,
            "agent.register",
            &registro_de_agente(&[0xB0 + i as u8; 32], &nome, "observador"),
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
        "{} quedas: a cadeia que o boot continuou vale exatamente quando o registro de boot esta no disco, o gravado antes volta igual, e a cadeia continua",
        QUEDAS_NA_GRAVACAO.len()
    ))
}

/// Em que registro só de auditoria do boot a energia cai, sob carga: o
/// décimo — com a carga da serial, o coletor grava mais de um por passada,
/// e a queda cai depois de pelo menos uma passada inteira, com a carga
/// tendo visto registros gravados, e no meio de outra.
const REGISTRO_DA_QUEDA_SOB_CARGA: u32 = 10;

/// Quantos `agent.ping` a carga manda de uma vez, antes de cada leitura do
/// que ficou gravado.
const RAJADA_DA_CARGA: usize = 40;

/// O que veio da serial durante a carga.
#[derive(Debug, PartialEq, Eq)]
enum Lido {
    /// A resposta do pedido esperado.
    Resposta(String),
    /// O aviso da queda, com o ponto.
    Queda(u8),
}

/// Lê a serial até a resposta do pedido `id` — as dos outros passam — ou
/// até o aviso da queda, o que vier primeiro, e até `limite`. Um tempo sem
/// nada não perde o que veio pela metade — ver [`esperar_o_aviso_com`].
fn ate_a_resposta_ou_a_queda(
    leitor: &mut impl std::io::BufRead,
    id: u32,
    limite: Instant,
) -> Result<Lido, String> {
    let mut linha = String::new();
    loop {
        match leitor.read_line(&mut linha) {
            Ok(0) => return Err("o canal fechou no meio da carga".into()),
            Ok(_) => {
                if let Some(p) = aviso_de_queda(&linha) {
                    return Ok(Lido::Queda(p));
                }
                if super::campo_simples(&linha, "id").and_then(|v| v.parse::<u32>().ok())
                    == Some(id)
                {
                    return Ok(Lido::Resposta(linha));
                }
                linha.clear();
            }
            Err(_) => {}
        }
        if Instant::now() >= limite {
            return Err("a carga ficou sem a resposta e sem o aviso da queda".into());
        }
    }
}

/// A carga da serial até a energia cair: rajadas de `agent.ping`, cada uma
/// seguida de um `audit.tail` do que veio depois do último registro visto
/// gravado — o que ele diz gravado fica anotado, pelo número. Corta a
/// energia; devolve o ponto em que caiu e os anotados.
fn carga_ate_cair(mut m: Ligada) -> Result<(u8, std::collections::BTreeMap<u64, Rastro>), String> {
    let mut vistos = std::collections::BTreeMap::new();
    let limite = Instant::now() + ESPERA_PELA_QUEDA;
    let caiu = (|| -> Result<u8, String> {
        m.esperar_respostas_por(Duration::from_secs(2))?;
        let mut depois = 0u64;
        loop {
            for _ in 0..RAJADA_DA_CARGA {
                m.mandar("agent.ping", "{}")?;
            }
            let id = m.mandar(
                "audit.tail",
                &format!(r#"{{"after":{depois},"count":{MAIOR_CAUDA}}}"#),
            )?;
            match ate_a_resposta_ou_a_queda(&mut m.leitor, id, limite)? {
                Lido::Queda(p) => return Ok(p),
                Lido::Resposta(r) if r.contains(r#"{"seq":"#) => {
                    for rastro in rastros(&r)?.into_iter().filter(|r| r.duravel) {
                        depois = depois.max(rastro.seq);
                        vistos.insert(rastro.seq, rastro);
                    }
                }
                Lido::Resposta(_) => {}
            }
        }
    })();
    m.cortar_a_energia()?;
    Ok((caiu?, vistos))
}

/// Quantos registros o anel da auditoria do kernel guarda —
/// `CAPACIDADE_DA_AUDITORIA`, em `kernel/src/autorizacao.rs`.
const CAPACIDADE_DO_ANEL: usize = 1024;

/// O anel da auditoria de depois de um corte — `anel`, do mais velho ao
/// mais novo, lido inteiro ([`auditoria_do_anel`]) —, contra os registros
/// vistos gravados antes dele: sem buraco nem repetição; cada visto de
/// volta igual — o mesmo elo, o mesmo método, gravado — e antes de
/// `comeco`, o primeiro registro do boot de agora; e, se o registro do
/// corte `vale`, a cadeia do boot cortado passa do último visto gravado.
/// Devolve quantos vistos conferiu.
///
/// # Os vistos de antes do começo do anel
///
/// Só deixam de contar se o anel deu a volta. Um registro sai dele pela
/// ponta só com ele cheio, e então o anel lido inteiro tem pelo menos o que
/// ele guarda, [`CAPACIDADE_DO_ANEL`] — as leituras somadas. Com menos,
/// ninguém saiu pela ponta neste boot, nem da cadeia que o journal refez: o
/// anel começa no primeiro registro do journal, ou no seguinte à última
/// lacuna ou à marca de uma compactação, e um visto de antes disso não se
/// confere mais. Este cenário não pede nem uma nem outra; reprova, e diz
/// qual visto, e o anel com quantos.
///
/// # O `vale`
///
/// É uma conferência de sanidade: a carga não sabe até onde a gravada ia
/// antes do registro do corte — o último que ela viu gravado pode estar
/// atrás —, e o que passa do último visto pode ter vindo no registro de
/// antes. A exata, a de que o registro vale exatamente quando está no
/// disco, é a de [`as_quedas_na_auditoria`].
fn conferir_o_anel_do_corte(
    anel: &[Rastro],
    vistos: &std::collections::BTreeMap<u64, Rastro>,
    comeco: u64,
    vale: bool,
) -> Result<usize, String> {
    if let Some(w) = anel.windows(2).find(|w| w[1].seq != w[0].seq + 1) {
        return Err(format!(
            "o anel da auditoria pula ou repete: o {} depois do {}",
            w[1].seq, w[0].seq
        ));
    }
    let alcance = anel.first().map_or(u64::MAX, |r| r.seq);
    if anel.len() < CAPACIDADE_DO_ANEL
        && let Some((&seq, _)) = vistos.range(..alcance).next()
    {
        return Err(format!(
            "o registro {seq}, visto gravado antes do corte, ficou antes do comeco do anel do boot novo ({alcance}), e o anel nao deu a volta: {} registros, de {CAPACIDADE_DO_ANEL}",
            anel.len()
        ));
    }
    let mut conferidos = 0;
    for (&seq, visto) in vistos.range(alcance..) {
        match anel.get((seq - alcance) as usize) {
            Some(r)
                if r.seq == seq
                    && r.elo == visto.elo
                    && r.metodo == visto.metodo
                    && r.duravel
                    && seq < comeco =>
            {
                conferidos += 1;
            }
            outro => {
                return Err(format!(
                    "o registro {seq}, visto gravado antes do corte, nao voltou igual antes do boot novo ({comeco}): {visto:?} / {outro:?}"
                ));
            }
        }
    }
    let ultimo_visto = vistos.keys().next_back().copied().unwrap_or(0);
    if vale && !anel.iter().any(|r| r.seq > ultimo_visto && r.seq < comeco) {
        return Err(format!(
            "o registro do corte estava no disco, e nada do boot cortado depois do {ultimo_visto} voltou"
        ));
    }
    Ok(conferidos)
}

/// No boot de agora: a persistência de pé — um registro da auditoria
/// repetido ou fora de ordem no journal a deixaria recusada —, a cadeia
/// que se verifica, e o anel conferido contra os `vistos` gravados antes do
/// corte ([`conferir_o_anel_do_corte`]).
fn conferir_a_coleta_depois_do_corte(
    m: &mut Ligada,
    vistos: &std::collections::BTreeMap<u64, Rastro>,
    vale: bool,
) -> Result<usize, String> {
    let p = persistencia_de(m)?;
    if p.estado != "available" {
        return Err(format!(
            "o boot seguinte deixou a persistencia {} ({})",
            p.estado, p.motivo
        ));
    }
    auditoria_verifica(m)?;
    let anel = auditoria_do_anel(m)?;
    conferir_o_anel_do_corte(&anel, vistos, comeco_do_boot(&anel)?, vale)
}

/// A queda no meio da coleta da auditoria sob carga — a serial pedindo sem
/// parar, e o coletor gravando várias vezes por passada: a energia cai em
/// cada fronteira do décimo registro só de auditoria do boot
/// ([`REGISTRO_DA_QUEDA_SOB_CARGA`]) — antes da escrita, depois dela (a que
/// chegou ao disco, e a que se perdeu sem a descarga), depois da descarga e
/// antes da confirmação —, com o anel crescendo, e a carga anotando o que o
/// `audit.tail` diz gravado. No boot seguinte, nada do que se viu gravado
/// sumiu ou mudou, o journal não tem buraco nem repetição — um registro
/// repetido ou fora de ordem o faria recusado —, e, se o registro do corte
/// está no disco, o que ele levava voltou. Esse boot grava a auditoria dele
/// em cima, e mais um confere de novo: a cadeia continua.
fn as_quedas_na_coleta_sob_carga(arch: Arquitetura, artefato: &Artefato) -> Result<String, String> {
    let disco = disco_de_testes()?;
    let mut relato = Vec::new();
    for (ponto, perder, vale, caso) in QUEDAS_NA_AUDITORIA {
        zerar_o_estado(arch)?;
        plano_de_queda(&disco, ponto, tipo::AUDITORIA, REGISTRO_DA_QUEDA_SOB_CARGA)?;
        let m = Ligada::subir(arch, artefato, None)?;
        let (caiu, vistos) = carga_ate_cair(m).map_err(|e| format!("{caso}: {e}"))?;
        if caiu != ponto {
            return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        if vistos.is_empty() {
            return Err(format!(
                "{caso}: a carga nao viu nada gravado antes da queda"
            ));
        }
        sem_plano(&disco)?;
        if perder {
            perder_o_ultimo_registro(&disco, None)?;
        }

        let mut m = Ligada::subir(arch, artefato, None)?;
        let conferidos = conferir_a_coleta_depois_do_corte(&mut m, &vistos, vale);
        let gravada = conferidos
            .is_ok()
            .then(|| esperar_a_auditoria_gravada(&mut m));
        m.cortar_a_energia()?;
        let conferidos = conferidos.map_err(|e| format!("{caso}: {e}"))?;
        let gravada = gravada
            .unwrap_or_else(|| Err("nao conferido".into()))
            .map_err(|e| format!("{caso}: o boot depois da queda: {e}"))?;
        let vistos_depois: std::collections::BTreeMap<u64, Rastro> = gravada
            .into_iter()
            .filter(|r| r.duravel)
            .map(|r| (r.seq, r))
            .collect();

        let mut m = Ligada::subir(arch, artefato, None)?;
        let de_novo = conferir_a_coleta_depois_do_corte(&mut m, &vistos_depois, false);
        m.cortar_a_energia()?;
        let de_novo = de_novo.map_err(|e| format!("{caso}: o boot seguinte ao seguinte: {e}"))?;
        relato.push(format!(
            "{caso}: {} vistos gravados, {conferidos} de volta iguais; depois, {de_novo}",
            vistos.len()
        ));
    }
    Ok(relato.join("; "))
}

// ---------------------------------------------------------------------------
// A auditoria sob carga e leitura
// ---------------------------------------------------------------------------

/// Os produtores da carga sobre a auditoria: a porta, o pedido e o que a
/// resposta traz quando o gate decide o que se espera. Os dois agentes são
/// `operador`, cada um com o balde da taxa da chave dele, e cada decisão é
/// um registro da auditoria: a do `agent.ping`, concedido — o `operador`
/// tem `agent.read`, pelo `observador` —, e a do `audit.head`, recusado —
/// ele não tem `audit.read`. Pedem sem parar: passando da taxa do papel, a
/// recusa por taxa também grava — a primeira de cada sequência, e a conta
/// das outras junto com o pedido seguinte que passa.
const PRODUTORES: [(u8, &str, &str); 2] = [
    (1, "agent.ping", r#""result":"#),
    (2, "audit.head", r#""data":"DENY_PERMISSION""#),
];

/// A porta de quem acompanha a cadeia: o agente 4. Das quatro portas, só o
/// papel dele, `sistema`, tem `audit.read` — os agentes 1 a 3 são
/// `operador`, que não a tem (ver `politica::PADRAO`) —, e a política não
/// muda para a bancada. O `audit.verify` e o `security.metrics`, que também
/// pedem permissão de leitura, vão pela serial, que a política dá ao
/// `sistema` (a linha `serial sistema`).
const PORTA_DO_LEITOR: u8 = 4;

/// Quantos pedidos que gravam — dos produtores e da serial — podem estar à
/// frente dos que o leitor já alcançou: ver [`Carga`].
const FOLGA_DA_CARGA: u64 = 128;

/// Quanto a carga dura, pelo menos — e daí até a hora do corte: ver
/// [`verificar_ate_o_corte`].
const CARGA_MINIMA: Duration = Duration::from_secs(5);

/// Quanto a carga dura, no máximo: sem a hora do corte até aqui, o cenário
/// reprova, dizendo até onde ela chegou.
const TETO_DA_CARGA: Duration = Duration::from_secs(90);

/// O prazo de cada resposta nos fios da carga: o kernel de depuração, com
/// quatro conversas ao mesmo tempo, pode passar dos dez segundos que a
/// conexão tem depois do aperto.
const PRAZO_DA_CARGA: Duration = Duration::from_secs(30);

/// Quanto o leitor e o laço do `audit.verify` descansam, pelo menos, entre
/// dois pedidos: cada um faz no máximo cem por segundo, abaixo da taxa do
/// `sistema` (400 por segundo, rajada de 800). O leitor descansa só depois
/// de um lote que não encheu — com ele, já alcançou a cabeça. E a serial,
/// que numera os pedidos a partir de 70 000, não chega no teto da carga aos
/// 90 000, que a leitura dela pula como respostas do aperto (ver
/// `ler_resposta`).
const DESCANSO_DA_LEITURA: Duration = Duration::from_millis(10);

/// O que os fios da carga dividem.
///
/// # A folga: por que o leitor não pode ver um buraco
///
/// O leitor segue a cadeia com `after` no último registro que leu, e
/// confere que cada lote começa no seguinte a ele: um registro que falta é
/// do `audit.tail`, e não do ritmo da carga, porque a carga não deixa o anel
/// passar por cima do leitor. Um registro só sai do anel depois de
/// [`CAPACIDADE_DO_ANEL`] anexados depois dele, e os pedidos que gravam —
/// dos produtores e da serial — só saem com a vez
/// ([`Carga::esperar_a_vez`]): no máximo [`FOLGA_DA_CARGA`] à frente dos
/// `alcancados`, os respondidos antes de o leitor mandar uma leitura que
/// voltou com menos de um lote — e que então trouxe tudo até a cabeça.
/// Cada pedido grava dois registros, no máximo — a decisão, e a conta das
/// recusas por taxa de antes dela —, cada leitura do leitor também, e o
/// resto é do kernel: o NSF lê a auditoria no máximo oito vezes por
/// segundo. Com o leitor parado pelo prazo inteiro de uma resposta
/// ([`PRAZO_DA_CARGA`]), são uns quinhentos registros: longe do anel.
///
/// # O corte
///
/// Sem aviso: os fios pedem até a energia cair. A marca `cortando` só diz a
/// eles que o erro de E/S que vem é o corte, e não uma falha.
#[derive(Default)]
struct Carga {
    /// A energia vai cair — ver acima.
    cortando: AtomicBool,
    /// Um fio reprovou: os outros param, e o corte vem logo.
    falhou: AtomicBool,
    /// Os pedidos que gravam, mandados e respondidos.
    mandados: AtomicU64,
    respondidos: AtomicU64,
    /// Dos respondidos, quantos o leitor já alcançou — ver acima.
    alcancados: AtomicU64,
    /// O último registro que o leitor leu, e o maior `durable_seq` que ele
    /// viu numa resposta.
    lido: AtomicU64,
    gravado: AtomicU64,
}

impl Carga {
    /// A carga acabou: a energia vai cair, ou um fio reprovou.
    fn acabou(&self) -> bool {
        self.cortando.load(Ordering::SeqCst) || self.falhou.load(Ordering::SeqCst)
    }

    /// Espera a vez de mandar um pedido que grava, e a toma — ver
    /// [`Carga`]. `false` se a carga acabou, ou passou de `limite`, antes.
    fn esperar_a_vez(&self, limite: Instant) -> bool {
        loop {
            if self.acabou() || Instant::now() >= limite {
                return false;
            }
            let alcancados = self.alcancados.load(Ordering::SeqCst);
            let vez = self
                .mandados
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |m| {
                    (m < alcancados + FOLGA_DA_CARGA).then_some(m + 1)
                });
            if vez.is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Um fio reprova: os outros param.
    fn reprovar<T>(&self, erro: String) -> Result<T, String> {
        self.falhou.store(true, Ordering::SeqCst);
        Err(erro)
    }

    /// Um erro de E/S num fio: depois da marca do corte, é a energia que
    /// caiu, e o fio acaba com o que fez; antes, reprova.
    fn fim<T>(&self, feito: T, erro: String) -> Result<T, String> {
        if self.cortando.load(Ordering::SeqCst) {
            Ok(feito)
        } else {
            self.reprovar(erro)
        }
    }
}

/// A espera que uma recusa por taxa pede — o `retry_after_ms` dela, entre
/// um milissegundo e um segundo; dez, se não diz —, se a resposta `r` é uma;
/// `None`, se não é. Pelo `data` do erro, e não pelo `code`: um lote do
/// `audit.tail` traz o `code` de cada registro, e as recusas por taxa
/// gravadas estão entre eles.
fn espera_da_taxa(r: &str) -> Option<Duration> {
    if !r.contains(r#""data":"RATE_LIMIT""#) {
        return None;
    }
    let ms = super::campo_simples(r, "retry_after_ms")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    Some(Duration::from_millis(ms.clamp(1, 1000)))
}

/// Um lote do `audit.tail`, como o leitor da carga o confere.
#[derive(Debug, PartialEq)]
struct LoteDaCauda {
    /// Cada registro com o `prev` dele — o elo do registro anterior, como o
    /// kernel o pôs no elo deste —, na ordem em que vieram.
    registros: Vec<(Rastro, String)>,
    /// O `durable_seq` da resposta: até onde a cadeia estava no journal.
    gravado: u64,
}

/// O lote de uma resposta do `audit.tail` — `Err`, se ela não é de um.
fn lote_da_cauda(r: &str) -> Result<LoteDaCauda, String> {
    let gravado = super::campo_simples(r, "durable_seq")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| format!("a resposta nao e a de um audit.tail\n  {r}"))?;
    if !r.contains(r#"{"seq":"#) {
        return Ok(LoteDaCauda {
            registros: Vec::new(),
            gravado,
        });
    }
    // Os mesmos pedaços que `rastros` lê, um por registro.
    let anteriores = r
        .split(r#"{"seq":"#)
        .skip(1)
        .map(|p| super::campo_simples(p, "prev").unwrap_or_default());
    Ok(LoteDaCauda {
        registros: rastros(r)?.into_iter().zip(anteriores).collect(),
        gravado,
    })
}

/// Confere um lote do leitor da carga contra o último registro que ele já
/// tinha lido, `anterior` — nenhum, no primeiro lote —: cada registro é o
/// seguinte ao de antes dele, sem pular nem repetir — nada do que já foi
/// lido volta —, e o `prev` de cada um é o `link` do de antes. Diz o
/// primeiro que não confere, e por quê.
fn conferir_o_lote(anterior: Option<&Rastro>, lote: &[(Rastro, String)]) -> Result<(), String> {
    let mut antes = anterior.map(|r| (r.seq, r.elo.as_str()));
    for (r, prev) in lote {
        if let Some((seq, elo)) = antes {
            if r.seq <= seq {
                return Err(format!(
                    "o audit.tail trouxe o registro {}, que nao vem depois do {seq}: lido de novo, ou fora de ordem",
                    r.seq
                ));
            }
            if r.seq != seq + 1 {
                return Err(format!(
                    "o audit.tail pulou do registro {seq} para o {}",
                    r.seq
                ));
            }
            if prev != elo {
                return Err(format!(
                    "o prev do registro {} nao e o link do {seq}: {prev} / {elo}",
                    r.seq
                ));
            }
        }
        antes = Some((r.seq, r.elo.as_str()));
    }
    Ok(())
}

/// O atraso do journal, no `audit_backlog` do `security.metrics`: quantos
/// registros saíram do anel antes dele neste boot, e o maior atraso dele em
/// relação à cabeça da auditoria, em registros.
fn atraso_da_auditoria(r: &str) -> Result<(u64, u64), String> {
    let atraso = r
        .split(r#""audit_backlog":{"#)
        .nth(1)
        .and_then(|a| a.split('}').next())
        .ok_or_else(|| format!("o security.metrics nao diz o atraso da auditoria\n  {r}"))?;
    let numero = |n: &str| -> Result<u64, String> {
        super::campo_simples(atraso, n)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("o atraso da auditoria nao diz `{n}`: {atraso}"))
    };
    Ok((numero("lost")?, numero("max")?))
}

/// Os lidos que o journal tinha quando o leitor viu `gravado` como o
/// `durable_seq` de uma resposta: os de número até ele, pelo número.
///
/// O `durable` de cada registro é isto mesmo — o número até o
/// `durable_seq` da resposta —, e o leitor não relê o que leu: o registro
/// lido antes de o coletor o gravar fica gravado pelo `durable_seq` de uma
/// resposta seguinte, como o `durable` dele diria nela.
fn gravados_vistos(lidos: &[Rastro], gravado: u64) -> std::collections::BTreeMap<u64, Rastro> {
    lidos
        .iter()
        .filter(|r| r.seq <= gravado)
        .map(|r| {
            (
                r.seq,
                Rastro {
                    duravel: true,
                    ..r.clone()
                },
            )
        })
        .collect()
}

/// O que um produtor ouviu do gate: o que esperava, e a recusa por taxa.
#[derive(Default)]
struct Producao {
    esperadas: u64,
    pela_taxa: u64,
}

/// Um produtor da carga — ver [`PRODUTORES`]: o pedido dele pela conexão
/// `agente`, um depois do outro, cada um com a vez
/// ([`Carga::esperar_a_vez`]), até a carga acabar. Cada resposta é a
/// esperada ou uma recusa por taxa; outra reprova.
fn produzir(
    carga: &Carga,
    mut agente: super::AgenteNaPorta,
    (porta, metodo, esperada): (u8, &str, &str),
    limite: Instant,
) -> Result<Producao, String> {
    let mut feito = Producao::default();
    while carga.esperar_a_vez(limite) {
        let r = match agente.pedir(metodo, "{}") {
            Ok(r) => r,
            Err(e) => return carga.fim(feito, format!("o produtor da porta {porta}: {e}")),
        };
        carga.respondidos.fetch_add(1, Ordering::SeqCst);
        if r.contains(esperada) {
            feito.esperadas += 1;
        } else if espera_da_taxa(&r).is_some() {
            feito.pela_taxa += 1;
        } else {
            return carga.reprovar(format!(
                "o produtor da porta {porta} ouviu do {metodo} o que nao esperava\n  {r}"
            ));
        }
    }
    Ok(feito)
}

/// O que o leitor fez: os registros que leu, seguidos, na ordem; e as
/// leituras, e quantas vieram com o lote cheio.
#[derive(Default)]
struct Acompanhado {
    lidos: Vec<Rastro>,
    leituras: u64,
    cheias: u64,
}

/// O leitor da carga: segue a cadeia pela conexão `agente` com o
/// `audit.tail` — `after` no último registro lido, um lote de
/// [`MAIOR_CAUDA`] — e confere cada lote contra o que já leu
/// ([`conferir_o_lote`]), até a carga acabar. Para os outros fios, diz o
/// último lido, o maior `durable_seq` visto e os pedidos alcançados — ver
/// [`Carga`].
fn acompanhar(
    carga: &Carga,
    mut agente: super::AgenteNaPorta,
    limite: Instant,
) -> Result<Acompanhado, String> {
    let mut feito = Acompanhado::default();
    while !carga.acabou() && Instant::now() < limite {
        // Antes de mandar: o que já foi respondido está na auditoria antes
        // de esta leitura ser atendida.
        let respondidos = carga.respondidos.load(Ordering::SeqCst);
        let depois = feito.lidos.last().map_or(0, |r| r.seq);
        let r = match agente.pedir(
            "audit.tail",
            &format!(r#"{{"after":{depois},"count":{MAIOR_CAUDA}}}"#),
        ) {
            Ok(r) => r,
            Err(e) => {
                return carga.fim(feito, format!("o leitor da porta {PORTA_DO_LEITOR}: {e}"));
            }
        };
        if let Some(espera) = espera_da_taxa(&r) {
            std::thread::sleep(espera);
            continue;
        }
        let lote = match lote_da_cauda(&r)
            .and_then(|l| conferir_o_lote(feito.lidos.last(), &l.registros).map(|()| l))
        {
            Ok(l) => l,
            Err(e) => {
                return carga.reprovar(format!(
                    "o leitor, com {} registros lidos: {e}",
                    feito.lidos.len()
                ));
            }
        };
        feito.leituras += 1;
        let cheio = lote.registros.len() >= MAIOR_CAUDA;
        feito
            .lidos
            .extend(lote.registros.into_iter().map(|(r, _)| r));
        if let Some(r) = feito.lidos.last() {
            carga.lido.store(r.seq, Ordering::SeqCst);
        }
        carga.gravado.fetch_max(lote.gravado, Ordering::SeqCst);
        if cheio {
            feito.cheias += 1;
        } else {
            // O lote trouxe tudo até a cabeça.
            carga.alcancados.fetch_max(respondidos, Ordering::SeqCst);
            std::thread::sleep(DESCANSO_DA_LEITURA);
        }
    }
    Ok(feito)
}

/// Um pedido que grava, pela serial, com a vez ([`Carga::esperar_a_vez`]):
/// a resposta, ou `None` se a carga acabou antes. A recusa por taxa espera
/// o que ela pede, e o pedido vai de novo, com outra vez.
fn pedir_com_a_vez(
    m: &mut Ligada,
    carga: &Carga,
    limite: Instant,
    metodo: &str,
) -> Result<Option<String>, String> {
    while carga.esperar_a_vez(limite) {
        let r = m.pedir(metodo, "{}")?;
        carga.respondidos.fetch_add(1, Ordering::SeqCst);
        match espera_da_taxa(&r) {
            Some(espera) => std::thread::sleep(espera),
            None => return Ok(Some(r)),
        }
    }
    Ok(None)
}

/// O que a serial fez até a hora do corte.
#[derive(Default)]
struct Verificado {
    /// Os `audit.verify` — todos com `ok:true` —, e quantos conferiram o
    /// anel cheio.
    verificacoes: u64,
    do_anel_cheio: u64,
    /// O maior `durable_seq` que o leitor tinha visto quando a serial
    /// conferiu que nada saiu do anel antes do journal — ver
    /// [`gravados_vistos`].
    gravado: u64,
    /// O maior atraso do journal em relação à cabeça da auditoria neste
    /// boot, em registros.
    maior_atraso: u64,
    /// Quanto a carga durou, até a hora do corte.
    duracao: Duration,
}

/// O laço da serial: um `audit.verify` depois do outro, cada um com a vez
/// ([`Carga::esperar_a_vez`]), todos com `ok:true`, até a hora do corte — a
/// carga com pelo menos [`CARGA_MINIMA`]; o leitor um lote além do anel
/// inteiro, com o anel cheio empurrando o mais velho para fora a cada
/// registro novo; o journal com registros desse trecho; e um `audit.verify`
/// que conferiu o anel cheio. Na hora, o `security.metrics`: nenhum
/// registro saiu do anel antes do journal neste boot. `Ok` também quando um
/// fio reprovou: ele diz por quê.
fn verificar_ate_o_corte(
    m: &mut Ligada,
    carga: &Carga,
    inicio: Instant,
) -> Result<Verificado, String> {
    let limite = inicio + TETO_DA_CARGA;
    let mut feito = Verificado::default();
    loop {
        let lido = carga.lido.load(Ordering::SeqCst);
        let gravado = carga.gravado.load(Ordering::SeqCst);
        if inicio.elapsed() >= CARGA_MINIMA
            && lido >= (CAPACIDADE_DO_ANEL + MAIOR_CAUDA) as u64
            && gravado > CAPACIDADE_DO_ANEL as u64
            && feito.do_anel_cheio > 0
        {
            break;
        }
        let antes = Instant::now();
        let Some(r) = pedir_com_a_vez(m, carga, limite, "audit.verify")? else {
            if carga.falhou.load(Ordering::SeqCst) {
                return Ok(feito);
            }
            return Err(format!(
                "a carga nao chegou a hora do corte em {} s: o leitor no registro {lido} (de {}), o journal no {gravado} (de mais de {CAPACIDADE_DO_ANEL}), {} audit.verify do anel cheio",
                TETO_DA_CARGA.as_secs(),
                CAPACIDADE_DO_ANEL + MAIOR_CAUDA,
                feito.do_anel_cheio
            ));
        };
        if !r.contains(r#""ok":true"#) {
            return Err(format!(
                "o audit.verify falhou sob a carga, depois de {} que conferiram\n  {r}",
                feito.verificacoes
            ));
        }
        feito.verificacoes += 1;
        if super::campo_simples(&r, "checked").and_then(|v| v.parse::<usize>().ok())
            == Some(CAPACIDADE_DO_ANEL)
        {
            feito.do_anel_cheio += 1;
        }
        // Pelo menos o que o pedido levou: um `audit.verify` que segurasse
        // a trava do gate pela conta inteira ficaria com ela no máximo
        // metade do tempo, e a carga anda.
        std::thread::sleep(antes.elapsed().max(DESCANSO_DA_LEITURA));
    }
    // A hora do corte. Um `durable_seq` que passasse por cima de registros
    // que saíram do anel antes do journal diria gravados os que o journal
    // marcou como perdidos, numa lacuna. A conta deles anda antes da
    // gravada (`contar_a_lacuna`, no kernel): o que o leitor viu antes desta
    // pergunta, ela cobre.
    feito.gravado = carga.gravado.load(Ordering::SeqCst);
    let r = pedir_com_a_vez(m, carga, limite, "security.metrics")?
        .ok_or("a carga acabou antes do security.metrics")?;
    let (perdidos, maior) = atraso_da_auditoria(&r)?;
    if perdidos > 0 {
        return Err(format!(
            "a auditoria perdeu {perdidos} registros sob a carga: sairam do anel antes do journal (o maior atraso dele foi de {maior})"
        ));
    }
    feito.maior_atraso = maior;
    feito.duracao = inicio.elapsed();
    Ok(feito)
}

/// As conexões da carga, antes dela — o aperto do kernel de depuração leva
/// centenas de milissegundos, e as portas o fazem uma de cada vez —: os
/// produtores, na ordem de [`PRODUTORES`], e o leitor, cada uma com o
/// [`PRAZO_DA_CARGA`].
fn conectar_a_carga(
    arch: Arquitetura,
) -> Result<(Vec<super::AgenteNaPorta>, super::AgenteNaPorta), String> {
    let conectar = |porta: u8| -> Result<super::AgenteNaPorta, String> {
        let agente = super::AgenteNaPorta::conectar(arch, porta)?;
        agente
            .fluxo
            .set_read_timeout(Some(PRAZO_DA_CARGA))
            .map_err(|e| format!("o prazo da porta {porta}: {e}"))?;
        Ok(agente)
    };
    let produtores = PRODUTORES
        .iter()
        .map(|&(porta, _, _)| conectar(porta))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((produtores, conectar(PORTA_DO_LEITOR)?))
}

/// A auditoria sob carga e leitura sobrevive ao corte.
///
/// Por alguns segundos, ao mesmo tempo: dois produtores pedem sem parar,
/// cada pedido uma decisão gravada ([`PRODUTORES`]); um leitor segue a
/// cadeia pelo `audit.tail`, conferindo cada lote — os números seguidos,
/// sem pular nem repetir, e o `prev` de cada registro no `link` do anterior
/// ([`conferir_o_lote`]); e a serial roda o `audit.verify` em laço, todos
/// com `ok:true`. Com o anel cheio — cada registro novo empurra o mais velho
/// para fora, com o leitor e o `audit.verify` lendo — e o journal com
/// registros desse trecho, a energia cai no meio da carga, sem aviso. No
/// boot seguinte, a persistência de pé, a cadeia se verifica, o anel lido
/// inteiro não pula nem repete, e cada registro que o leitor viu gravado e
/// que o anel de agora alcança voltou igual — o mesmo número, o mesmo elo,
/// o mesmo método —, antes do primeiro registro do boot novo: a cadeia
/// continua depois do último gravado
/// ([`conferir_a_coleta_depois_do_corte`]).
///
/// # Por que a conferência não depende do ritmo
///
/// O que se exige vale em qualquer intercalação dos fios: a folga da carga
/// ([`Carga`]) não deixa o anel passar por cima do leitor, e então um
/// buraco no que ele lê é do `audit.tail`; o que ele viu gravado é o que o
/// `durable_seq` cobria quando a serial conferiu que nada saiu do anel
/// antes do journal ([`gravados_vistos`]); e a hora do corte é dada pelo
/// que a carga alcançou — o anel cheio, o journal nele, um `audit.verify`
/// dele —, e não pelo relógio ([`verificar_ate_o_corte`]).
fn a_auditoria_sob_carga_e_leitura(
    arch: Arquitetura,
    artefato: &Artefato,
) -> Result<String, String> {
    let mut m = Ligada::subir(arch, artefato, None)?;
    // Sem o journal de pé, nada fica gravado, e a carga só acabaria no teto.
    let conectados = persistencia_de(&mut m).and_then(|p| {
        if p.estado != "available" {
            return Err(format!(
                "a persistencia nao esta de pe antes da carga: {} ({})",
                p.estado, p.motivo
            ));
        }
        conectar_a_carga(arch)
    });
    let (produtores, agente_do_leitor) = match conectados {
        Ok(c) => c,
        Err(e) => {
            m.cortar_a_energia()?;
            return Err(e);
        }
    };
    let carga = Carga::default();
    let inicio = Instant::now();
    let limite = inicio + TETO_DA_CARGA;
    let (verificado, producoes, leitura, corte) = std::thread::scope(|s| {
        let carga = &carga;
        let mut fios = Vec::new();
        for (agente, p) in produtores.into_iter().zip(PRODUTORES) {
            fios.push(s.spawn(move || produzir(carga, agente, p, limite)));
        }
        let leitor = s.spawn(move || acompanhar(carga, agente_do_leitor, limite));
        let verificado = verificar_ate_o_corte(&mut m, carga, inicio);
        if verificado.is_err() {
            carga.falhou.store(true, Ordering::SeqCst);
        }
        carga.cortando.store(true, Ordering::SeqCst);
        let corte = m.cortar_a_energia();
        // Cada fio, até o último: um que entrasse em pânico e ficasse para
        // o fim do escopo derrubaria a bancada inteira.
        let mut producoes = Vec::new();
        for fio in fios {
            producoes.push(
                fio.join()
                    .unwrap_or_else(|_| Err("o fio de um produtor entrou em panico".to_string())),
            );
        }
        let leitura = leitor
            .join()
            .unwrap_or_else(|_| Err("o fio do leitor entrou em panico".to_string()));
        (verificado, producoes, leitura, corte)
    });
    // O que um fio reprovou vem antes do que a serial diz depois dele: ela
    // só para quando a carga acaba.
    let leitura = leitura?;
    let producoes = producoes.into_iter().collect::<Result<Vec<_>, _>>()?;
    let verificado = verificado?;
    corte?;
    if let Some((_, metodo, _)) = producoes
        .iter()
        .zip(PRODUTORES)
        .find_map(|(p, d)| (p.esperadas == 0).then_some(d))
    {
        return Err(format!(
            "o produtor do {metodo} nao ouviu nenhuma vez o que esperava"
        ));
    }
    let vistos = gravados_vistos(&leitura.lidos, verificado.gravado);

    let mut m = Ligada::subir(arch, artefato, None)?;
    let conferidos = conferir_a_coleta_depois_do_corte(&mut m, &vistos, false);
    m.cortar_a_energia()?;
    let conferidos = conferidos?;
    if conferidos == 0 {
        return Err(format!(
            "nenhum dos {} vistos gravados, ate o {}, ficou ao alcance do anel do boot seguinte",
            vistos.len(),
            verificado.gravado
        ));
    }
    let produzido: Vec<String> = producoes
        .iter()
        .zip(PRODUTORES)
        .map(|(p, (porta, metodo, _))| {
            format!(
                "{metodo} pela porta {porta}: {} como esperado, {} pela taxa",
                p.esperadas, p.pela_taxa
            )
        })
        .collect();
    Ok(format!(
        "{:.1} s de carga, cortada no meio: o leitor seguiu {} registros em {} leituras ({} com o lote cheio), sem pular nem repetir, cada prev no link do anterior; {} audit.verify com ok:true, {} do anel cheio; {}; nada saiu do anel antes do journal (o maior atraso: {}); dos {} vistos gravados, {conferidos} ao alcance do boot seguinte, de volta iguais, e a cadeia continua e se verifica",
        verificado.duracao.as_secs_f64(),
        leitura.lidos.len(),
        leitura.leituras,
        leitura.cheias,
        verificado.verificacoes,
        verificado.do_anel_cheio,
        produzido.join("; "),
        verificado.maior_atraso,
        vistos.len(),
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

#[cfg(test)]
mod testes {
    use super::*;

    fn s(segundos: u64) -> Duration {
        Duration::from_secs(segundos)
    }

    fn sinais(serial: u64, discos: u64, canal: u64) -> Option<Sinais> {
        Some(Sinais {
            serial,
            discos,
            canal,
        })
    }

    /// A máquina que anda passa da janela sem a espera desistir — o limite
    /// é do andamento, e não do total —, e a que para desiste exatamente na
    /// janela, contada do último sinal novo.
    #[test]
    fn a_janela_e_do_andamento_e_nao_do_total() {
        let t0 = Instant::now();
        let mut a = AndamentoDoBoot::novo(t0, s(120), s(1000));
        assert_eq!(a.olhar(t0, sinais(0, 0, 0)), Ok(()));
        // Um sinal novo a cada 100 s, por 500 s: quatro janelas no total.
        for (i, t) in [100, 200, 300, 400, 500].into_iter().enumerate() {
            assert_eq!(a.olhar(t0 + s(t), sinais(i as u64 + 1, 0, 0)), Ok(()));
        }
        // Parada desde os 500: segue até 619, e desiste nos 620.
        assert_eq!(a.olhar(t0 + s(619), sinais(5, 0, 0)), Ok(()));
        assert_eq!(
            a.olhar(t0 + s(620), sinais(5, 0, 0)),
            Err(Desistencia::Parou {
                parada: s(120),
                andou: s(500)
            })
        );
    }

    /// Nenhum sinal muda desde a partida: a janela corre desde ela, e a
    /// primeira olhada — com a serial e os discos já andados — é a base, e
    /// não conta como andar.
    #[test]
    fn a_primeira_olhada_e_a_base() {
        let t0 = Instant::now();
        let mut a = AndamentoDoBoot::novo(t0, s(120), s(1000));
        assert_eq!(a.olhar(t0 + s(30), sinais(4096, 900, 0)), Ok(()));
        assert_eq!(a.olhar(t0 + s(119), sinais(4096, 900, 0)), Ok(()));
        assert_eq!(
            a.olhar(t0 + s(120), sinais(4096, 900, 0)),
            Err(Desistencia::Parou {
                parada: s(120),
                andou: s(0)
            })
        );
    }

    /// Cada sinal sozinho é andamento: a serial, os discos — o iniciador
    /// que confere o kernel em silêncio, lendo um pedaço por vez —, e o
    /// canal.
    #[test]
    fn cada_sinal_sozinho_e_andamento() {
        let mudancas: [fn(Sinais) -> Sinais; 3] = [
            |x| Sinais {
                serial: x.serial + 1,
                ..x
            },
            |x| Sinais {
                discos: x.discos + 1_048_576,
                ..x
            },
            |x| Sinais {
                canal: x.canal + 1,
                ..x
            },
        ];
        for mudar in mudancas {
            let t0 = Instant::now();
            let mut a = AndamentoDoBoot::novo(t0, s(120), s(1000));
            let mut x = Sinais::default();
            assert_eq!(a.olhar(t0, Some(x)), Ok(()));
            for t in (100..=900).step_by(100) {
                x = mudar(x);
                assert_eq!(a.olhar(t0 + s(t), Some(x)), Ok(()), "aos {t} s: {x:?}");
            }
            assert!(a.olhar(t0 + s(1020), Some(x)).is_err());
        }
    }

    /// A olhada sem sinais só passa o tempo: o boot de antes que ainda
    /// responde não é o reinício andando.
    #[test]
    fn a_olhada_sem_sinais_nao_anda() {
        let t0 = Instant::now();
        let mut a = AndamentoDoBoot::novo(t0, s(120), s(1000));
        assert_eq!(a.olhar(t0 + s(1), sinais(1, 1, 1)), Ok(()));
        for t in (10..120).step_by(10) {
            assert_eq!(a.olhar(t0 + s(t), None), Ok(()));
        }
        assert!(matches!(
            a.olhar(t0 + s(120), None),
            Err(Desistencia::Parou { .. })
        ));
    }

    /// O teto vale com a máquina andando: a que reinicia em laço não
    /// pendura a bancada.
    #[test]
    fn o_teto_vale_andando() {
        let t0 = Instant::now();
        let mut a = AndamentoDoBoot::novo(t0, s(120), s(300));
        let mut serial = 0;
        for t in (0..300).step_by(50) {
            serial += 80;
            assert_eq!(a.olhar(t0 + s(t), sinais(serial, 0, 0)), Ok(()));
        }
        assert_eq!(
            a.olhar(t0 + s(300), sinais(serial, 0, 0)),
            Err(Desistencia::Teto {
                teto: s(300),
                parada: s(50)
            })
        );
    }

    /// O maior intervalo sem sinal novo conta da partida ao primeiro, entre
    /// dois, e do último ao atendimento.
    #[test]
    fn o_maior_intervalo_sem_sinal_novo() {
        let t0 = Instant::now();
        let mut a = AndamentoDoBoot::novo(t0, s(120), s(1000));
        for (t, serial) in [(5, 0), (30, 1), (100, 2), (110, 3)] {
            assert_eq!(a.olhar(t0 + s(t), sinais(serial, 0, 0)), Ok(()));
        }
        // Da partida ao primeiro sinal novo, 30; dos 30 aos 100, 70.
        assert_eq!(a.maior_parada_ate(t0 + s(150)), s(70));
        assert_eq!(a.maior_parada_ate(t0 + s(200)), s(90));
    }

    /// A desistência diz quanto tempo a máquina ficou sem andar, e quando
    /// foi o último sinal.
    #[test]
    fn a_desistencia_diz_os_segundos() {
        let parou = Desistencia::Parou {
            parada: s(120),
            andou: s(254),
        }
        .to_string();
        assert!(
            parou.contains("ha 120s") && parou.contains("254s depois da partida"),
            "{parou}"
        );
        let teto = Desistencia::Teto {
            teto: s(300),
            parada: s(3),
        }
        .to_string();
        assert!(
            teto.contains("teto de 300s") && teto.contains("ha 3s"),
            "{teto}"
        );
    }

    /// A resposta do `info blockstats` pelo QMP, como o QEMU a escreve — o
    /// 8.2 do Ubuntu 24.04 e o 10.2 da CI, que a CI 413 mostrou igual: os
    /// contadores de cada disco somados, e os tempos de fora — o ocioso
    /// anda com o disco parado.
    #[test]
    fn os_discos_somam_os_contadores_e_nao_os_tempos() {
        let resposta = |rd: u64, ocioso: u64| {
            format!(
                r#"{{"return": "pflash0: rd_bytes=0 wr_bytes=0 rd_operations=0 wr_operations=0 flush_operations=0 wr_total_time_ns=0 rd_total_time_ns=0 flush_total_time_ns=0 rd_merged=0 wr_merged=0 idle_time_ns=0\r\nide0-hd0: rd_bytes={rd} wr_bytes=512 rd_operations=17 wr_operations=1 flush_operations=1 wr_total_time_ns=123 rd_total_time_ns=456 flush_total_time_ns=789 rd_merged=0 wr_merged=0 idle_time_ns={ocioso}\r\n"}}"#
            )
        };
        assert_eq!(
            atividade_dos_discos(&resposta(13_312, 1_000)),
            Some(13_312 + 512 + 17 + 1 + 1)
        );
        // Só o tempo andou: nada mudou.
        assert_eq!(
            atividade_dos_discos(&resposta(13_312, 9_000_000_000)),
            atividade_dos_discos(&resposta(13_312, 1_000))
        );
        // Um pedaço do kernel lido: mudou.
        assert_ne!(
            atividade_dos_discos(&resposta(13_312 + 1_048_576, 0)),
            atividade_dos_discos(&resposta(13_312, 0))
        );
        assert_eq!(
            atividade_dos_discos(r#"{"error": {"class": "GenericError", "desc": "x"}}"#),
            None
        );
        assert_eq!(atividade_dos_discos(""), None);
    }

    /// O console do firmware como a CI 413 o viu depois do pânico: o escape
    /// vira espaço, e as sequências ficam à vista — eram a prova de que o
    /// firmware tinha voltado.
    #[test]
    fn as_sequencias_do_console_ficam_a_vista() {
        let serial = b"!!! PANICO NO KERNEL !!!\r\ntentativa da versao nova: reiniciando\r\n\
\x1b[2J\x1b[001;001H\x1b[=3h\x1b[2J\x1b[001;001H\x1b[8;056;240t\r\n\
BdsDxe: loading Boot0001 \"UEFI Misc Device\"\r\n";
        let texto = sem_controles(serial);
        assert_eq!(
            ultimas_linhas(&texto, 3),
            [
                "tentativa da versao nova: reiniciando",
                " [2J [001;001H [=3h [2J [001;001H [8;056;240t",
                "BdsDxe: loading Boot0001 \"UEFI Misc Device\"",
            ]
        );
    }

    /// As linhas do kernel passam como estão; os outros controles viram
    /// espaço; o UTF-8 inválido, o caractere de substituição; e um escape
    /// cortado no fim do arquivo não derruba nada.
    #[test]
    fn as_linhas_do_kernel_e_os_restos() {
        let texto =
            sem_controles(b"[   12]     34ms info  boot pronto\nsino\x07aqui\n\xffx\n\n\x1b[1");
        assert_eq!(
            ultimas_linhas(&texto, 40),
            [
                "[   12]     34ms info  boot pronto",
                "sino aqui",
                "\u{fffd}x",
                "",
                " [1"
            ]
        );
        assert_eq!(ultimas_linhas(&texto, 2), ["", " [1"]);
        assert!(ultimas_linhas("", 5).is_empty());
    }

    /// Um arquivo deste teste, por nome, no diretório temporário.
    fn temporario(nome: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-persistencia-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(nome)
    }

    /// Os olhos de uma máquina sem QMP: os discos ficam onde estavam.
    fn olhos(serial: &Path, canal_na_serial: bool) -> Olhos {
        Olhos {
            qmp: temporario("sem-qmp.sock"),
            serial: Some(serial.to_path_buf()),
            firmware: None,
            codigo_do_firmware: None,
            canal_na_serial,
            discos: 0,
            canal: 0,
            qmp_olhado: None,
        }
    }

    /// No ARM, o que as esperas leem do canal vai para a serial do cenário,
    /// cada amostra acabando numa linha; no x86, não. Nos dois, conta como
    /// andamento.
    #[test]
    fn o_canal_do_arm_vai_para_a_serial() {
        let serial = temporario("arm.serial");
        std::fs::write(&serial, b"").unwrap();
        let mut arm = olhos(&serial, true);
        arm.ouvir_o_canal(b"UEFI firmware (version 2024.02)\r\n");
        arm.ouvir_o_canal(b"");
        arm.ouvir_o_canal(b"BdsDxe: loading Boot0001");
        assert_eq!(
            std::fs::read(&serial).unwrap(),
            b"UEFI firmware (version 2024.02)\r\nBdsDxe: loading Boot0001\n"
        );
        let agora = Instant::now();
        let vistos = arm.sinais(agora);
        assert_eq!(vistos.canal, 33 + 24);
        assert_eq!(vistos.serial, 33 + 25);
        assert_eq!(vistos.discos, 0);

        let x86 = temporario("x86.serial");
        std::fs::write(&x86, b"").unwrap();
        let mut olhos_do_x86 = olhos(&x86, false);
        olhos_do_x86.ouvir_o_canal(b"lixo da UART\n");
        assert_eq!(std::fs::read(&x86).unwrap(), b"");
        assert_eq!(olhos_do_x86.sinais(agora).canal, 13);
        let _ = std::fs::remove_file(serial);
        let _ = std::fs::remove_file(x86);
    }

    /// O diagnóstico de uma máquina que não atendeu: sem TPM, diz; o log de
    /// depuração do firmware, o fim dele, com o rótulo — ou que está vazio.
    #[test]
    fn o_diagnostico_do_tpm_e_do_firmware() {
        let firmware = temporario("firmware.log");
        std::fs::write(&firmware, b"").unwrap();
        let mut sem_tpm = Ambiente::sem_tpm(None);
        let vazio = tpm_e_firmware(&mut sem_tpm, Some(&firmware));
        assert!(vazio.contains("sem TPM nesta maquina"), "{vazio}");
        assert!(vazio.contains("o log do firmware esta vazio"), "{vazio}");

        let linhas: String = (0..40).map(|i| format!("Loading driver {i}\r\n")).collect();
        std::fs::write(&firmware, linhas).unwrap();
        let cheio = tpm_e_firmware(&mut sem_tpm, Some(&firmware));
        assert!(
            cheio.contains(&format!(
                "as ultimas {LINHAS_DO_FIRMWARE} linhas do log do firmware"
            )),
            "{cheio}"
        );
        assert!(
            cheio.contains("\n  [firmware] Loading driver 39"),
            "{cheio}"
        );
        assert!(!cheio.contains("Loading driver 14\n"), "{cheio}");
        assert!(
            cheio.contains("\n  [firmware] Loading driver 15"),
            "{cheio}"
        );
        // Sem firmware — o ARM —, nada dele.
        assert!(!tpm_e_firmware(&mut sem_tpm, None).contains("firmware"));
        let _ = std::fs::remove_file(firmware);
    }

    /// O `swtpm` da máquina que não atendeu: se vive ou saiu, e o fim do
    /// log dele, que mora ao lado do socket de controle — ver
    /// `Ambiente::ligar`.
    #[test]
    fn o_diagnostico_diz_se_o_swtpm_vive() {
        let log = temporario("swtpm.log");
        std::fs::write(&log, b"erro um\nerro dois\n").unwrap();
        let filho = Command::new("sleep").arg("30").spawn().unwrap();
        let mut ambiente = Ambiente::sem_tpm(None);
        ambiente.tpm = Some((filho, log.with_file_name("controle.sock")));
        let vivo = tpm_e_firmware(&mut ambiente, None);
        assert!(vivo.contains("\n  o swtpm: vivo"), "{vivo}");
        assert!(
            vivo.contains("as ultimas 2 linhas do log do swtpm"),
            "{vivo}"
        );
        assert!(
            vivo.ends_with("\n  [swtpm] erro um\n  [swtpm] erro dois"),
            "{vivo}"
        );
        if let Some((tpm, _)) = ambiente.tpm.as_mut() {
            tpm.kill().unwrap();
            tpm.wait().unwrap();
        }
        let morto = tpm_e_firmware(&mut ambiente, None);
        assert!(morto.contains("\n  o swtpm: saiu ("), "{morto}");
        let _ = std::fs::remove_file(log);
    }

    /// O diagnóstico da CI 439: só a recusa por revogação marca a máquina
    /// para o fim dela perguntar o porquê — a resposta da CI 439 marca; a
    /// recusa por permissão e a resposta que deu certo, não —, e o estado e
    /// o motivo saem do `system.info` inteiros, com as vírgulas do motivo.
    #[test]
    fn a_recusa_de_revogacao_pede_o_motivo() {
        // A resposta da CI 439, como veio.
        let ci_439 = r#"{"jsonrpc":"2.0","id":400001,"error":{"code":-32010,"message":"operacao negada pela politica","data":"DENY_NOT_AUTHENTICATED","explain":{"outcome":"DENY","reason":"DENY_REVOCATION","code":"DENY_NOT_AUTHENTICATED","permission":"system.update","resource":"","role":"sistema","decision":34,"recoverable":false,"retry":"non_retryable","next_action":"CONTACT_ADMIN","message":"Esta identidade nao vale agora: foi revogada, ou nao se sabe se foi. Fale com um administrador."}}}"#;
        assert!(diz_revogacao(ci_439));
        let permissao = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32010,"message":"operacao negada pela politica","data":"DENY_PERMISSION","explain":{"outcome":"DENY","reason":"DENY_PERMISSION","code":"DENY_PERMISSION"}}}"#;
        assert!(!diz_revogacao(permissao));
        assert!(!diz_revogacao(
            r#"{"jsonrpc":"2.0","id":8,"result":{"written":65536}}"#
        ));

        let info = r#"{"jsonrpc":"2.0","id":9,"result":{"arch":"aarch64","time":{"state":"ok","reason":"outro"},"persistence":{"state":"refused","reason":"a EK do TPM nao e a fixada, nem a de antes","generation":0,"anchor":null}}}"#;
        assert_eq!(
            estado_e_motivo(info),
            Some((
                "refused".to_string(),
                "a EK do TPM nao e a fixada, nem a de antes".to_string()
            ))
        );
        let sem_motivo = r#"{"jsonrpc":"2.0","id":9,"result":{"persistence":{"state":"available","reason":"","generation":3}}}"#;
        assert_eq!(
            estado_e_motivo(sem_motivo),
            Some(("available".to_string(), String::new()))
        );
        assert_eq!(
            estado_e_motivo(r#"{"jsonrpc":"2.0","id":9,"result":{"arch":"x86_64"}}"#),
            None
        );
        assert_eq!(
            estado_e_motivo(r#"{"jsonrpc":"2.0","id":9,"error":{"code":-32010}}"#),
            None
        );
    }

    /// Um anel de auditoria de mentira, como o do kernel: cada leitura grava
    /// a si mesma antes de responder, o anel guarda os últimos
    /// `capacidade`, e o `after` dá os seguintes a um número, do mais velho
    /// ao mais novo.
    struct AnelDeMentira {
        proximo: u64,
        capacidade: u64,
        leituras: usize,
    }

    impl AnelDeMentira {
        fn com(registros: u64, capacidade: u64) -> AnelDeMentira {
            AnelDeMentira {
                proximo: registros + 1,
                capacidade,
                leituras: 0,
            }
        }

        fn pedir(&mut self, q: &str) -> Result<String, String> {
            self.leituras += 1;
            self.proximo += 1;
            let numero = |n: &str| -> Result<u64, String> {
                crate::campo_simples(q, n)
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("sem `{n}` em {q}"))
            };
            let depois = numero("after")?;
            let quantos = numero("count")? as usize;
            let primeiro = self.proximo.saturating_sub(self.capacidade).max(1);
            let registros: Vec<String> = (primeiro.max(depois + 1)..self.proximo)
                .take(quantos)
                .map(|s| {
                    format!(
                        r#"{{"seq":{s},"holder":"kernel","method":"m{s}","resource":"","code":"ALLOW","detail":"","link":"e{s}","durable":true}}"#
                    )
                })
                .collect();
            Ok(format!(
                r#"{{"durable_seq":0,"records":[{}]}}"#,
                registros.join(",")
            ))
        }
    }

    /// O anel inteiro vem em lotes de 128, do primeiro registro à leitura
    /// que acaba o laço — a que traz menos de um lote —, sem buraco.
    #[test]
    fn o_anel_inteiro_vem_em_lotes_e_acaba() {
        let mut anel = AnelDeMentira::com(300, 1024);
        let todos = auditoria_do_anel_por(&mut |q| anel.pedir(q)).unwrap();
        let numeros: Vec<u64> = todos.iter().map(|r| r.seq).collect();
        // As 300, e as três leituras que as trouxeram.
        assert_eq!(numeros, (1..=303).collect::<Vec<u64>>());
        assert_eq!(anel.leituras, 3);
    }

    /// Um anel que já perdeu os primeiros registros começa depois do 1, e
    /// o laço acaba mesmo assim — quem conclui que algo não está confere
    /// onde ele começa.
    #[test]
    fn o_anel_que_perdeu_os_primeiros_comeca_depois_do_um() {
        let mut anel = AnelDeMentira::com(2000, 1024);
        let todos = auditoria_do_anel_por(&mut |q| anel.pedir(q)).unwrap();
        assert_eq!(todos.first().map(|r| r.seq), Some(2002 - 1024));
        assert!(anel.leituras <= MAIS_LOTES_DO_ANEL);
        assert!(todos.windows(2).all(|w| w[1].seq == w[0].seq + 1));
    }

    /// Uma auditoria que nunca para de dar lotes cheios não prende a
    /// bancada: depois de [`MAIS_LOTES_DO_ANEL`] leituras, é erro.
    #[test]
    fn o_lote_cheio_sem_fim_e_erro() {
        let mut proximo = 1u64;
        let mut sem_fim = |_: &str| -> Result<String, String> {
            let registros: Vec<String> = (proximo..proximo + MAIOR_CAUDA as u64)
                .map(|s| format!(r#"{{"seq":{s},"method":"m","durable":true}}"#))
                .collect();
            proximo += MAIOR_CAUDA as u64;
            Ok(format!(r#"{{"records":[{}]}}"#, registros.join(",")))
        };
        let e = auditoria_do_anel_por(&mut sem_fim).unwrap_err();
        assert!(e.contains("nao acabou"), "{e}");
    }

    /// Pelo número: o registro, se o anel o tem; erro, dizendo qual, se o
    /// anel já o perdeu ou ainda não chegou a ele. E o número seguinte à
    /// cabeça é o da própria leitura — por isso quem procura um registro de
    /// antes do corte compara o que veio, o elo inclusive.
    #[test]
    fn um_registro_pelo_numero() {
        let mut anel = AnelDeMentira::com(300, 1024);
        let r = registro_de_numero_por(&mut |q| anel.pedir(q), 150).unwrap();
        assert_eq!(
            (r.seq, r.metodo.as_str(), r.elo.as_str()),
            (150, "m150", "e150")
        );

        let mut perdido = AnelDeMentira::com(2000, 1024);
        let e = registro_de_numero_por(&mut |q| perdido.pedir(q), 5).unwrap_err();
        assert!(
            e.contains("ja saiu do anel") && e.contains("o mais velho e o 978"),
            "{e}"
        );

        let mut cabeca = AnelDeMentira::com(300, 1024);
        let propria = registro_de_numero_por(&mut |q| cabeca.pedir(q), 301).unwrap();
        assert_eq!((propria.seq, propria.metodo.as_str()), (301, "m301"));

        let mut adiante = AnelDeMentira::com(300, 1024);
        let e = registro_de_numero_por(&mut |q| adiante.pedir(q), 400).unwrap_err();
        assert!(e.contains("ainda nao chegou ao registro 400"), "{e}");
    }

    /// Um registro do anel como o `audit.tail` o mostra, de mentira: o elo
    /// diz a sequência, e o método é sempre o mesmo.
    fn rastro(seq: u64, elo: &str) -> Rastro {
        Rastro {
            seq,
            elo: elo.to_string(),
            titular: "kernel".to_string(),
            metodo: "agent.ping".to_string(),
            recurso: String::new(),
            codigo: "ALLOW".to_string(),
            detalhe: String::new(),
            duravel: true,
        }
    }

    /// O anel de `n` registros, do 100 em diante.
    fn anel_de(n: u64) -> Vec<Rastro> {
        (100..100 + n)
            .map(|s| rastro(s, &format!("e{s}")))
            .collect()
    }

    /// O anel de 100 a 300, com o boot novo a partir do 251.
    fn anel_do_corte() -> Vec<Rastro> {
        anel_de(201)
    }

    /// O anel que deu a volta: cheio, de 100 a 1123 — o boot novo a partir
    /// do 1100.
    fn anel_cheio() -> Vec<Rastro> {
        anel_de(CAPACIDADE_DO_ANEL as u64)
    }

    /// Os vistos gravados antes do corte, de `de` a `ate`.
    fn vistos(de: u64, ate: u64) -> std::collections::BTreeMap<u64, Rastro> {
        (de..=ate)
            .map(|s| (s, rastro(s, &format!("e{s}"))))
            .collect()
    }

    /// O anel inteiro, com cada visto de volta igual antes do boot novo e
    /// a cadeia do boot cortado passando deles: confere — e, com o anel
    /// dado a volta, os vistos que ele já não alcança não contam.
    #[test]
    fn o_anel_do_corte_que_confere() {
        assert_eq!(
            conferir_o_anel_do_corte(&anel_do_corte(), &vistos(150, 200), 251, true),
            Ok(51)
        );
        assert_eq!(
            conferir_o_anel_do_corte(&anel_cheio(), &vistos(20, 120), 1100, false),
            Ok(21)
        );
    }

    /// Sem o anel do boot novo ter dado a volta — menos registros que ele
    /// guarda, até um a menos —, um visto antes do começo dele não saiu pela
    /// ponta: sumiu do que se confere. Reprova, e diz qual; com o anel
    /// cheio, o mesmo visto não conta.
    #[test]
    fn o_visto_antes_do_anel_que_nao_deu_a_volta() {
        let e =
            conferir_o_anel_do_corte(&anel_do_corte(), &vistos(20, 120), 251, false).unwrap_err();
        assert!(
            e.contains("o registro 20,") && e.contains("nao deu a volta"),
            "{e}"
        );
        let quase = anel_de(CAPACIDADE_DO_ANEL as u64 - 1);
        let e = conferir_o_anel_do_corte(&quase, &vistos(99, 120), 1100, false).unwrap_err();
        assert!(e.contains("o registro 99,"), "{e}");
        assert_eq!(
            conferir_o_anel_do_corte(&anel_cheio(), &vistos(99, 120), 1100, false),
            Ok(21)
        );
    }

    /// Um buraco ou uma repetição no anel, um visto que volta com outro elo
    /// ou outro método, ou que não volta, ou que volta depois do começo do
    /// boot novo: cada um reprova, e diz o quê.
    #[test]
    fn o_anel_do_corte_que_nao_confere() {
        let mut buraco = anel_do_corte();
        buraco.remove(60);
        let e = conferir_o_anel_do_corte(&buraco, &vistos(150, 200), 251, false).unwrap_err();
        assert!(e.contains("pula ou repete"), "{e}");

        let mut repetido = anel_do_corte();
        repetido.insert(60, rastro(160, "e160"));
        let e = conferir_o_anel_do_corte(&repetido, &vistos(150, 200), 251, false).unwrap_err();
        assert!(e.contains("pula ou repete"), "{e}");

        let mut outro_elo = vistos(150, 200);
        outro_elo.insert(170, rastro(170, "outro"));
        let e = conferir_o_anel_do_corte(&anel_do_corte(), &outro_elo, 251, false).unwrap_err();
        assert!(
            e.contains("o registro 170") && e.contains("nao voltou igual"),
            "{e}"
        );

        let mut outro_metodo = anel_do_corte();
        outro_metodo[80].metodo = "audit.tail".to_string();
        let e = conferir_o_anel_do_corte(&outro_metodo, &vistos(150, 200), 251, false).unwrap_err();
        assert!(e.contains("o registro 180"), "{e}");

        let mut nao_gravado = anel_do_corte();
        nao_gravado[90].duravel = false;
        let e = conferir_o_anel_do_corte(&nao_gravado, &vistos(150, 200), 251, false).unwrap_err();
        assert!(e.contains("o registro 190"), "{e}");

        let e =
            conferir_o_anel_do_corte(&anel_do_corte(), &vistos(150, 320), 251, false).unwrap_err();
        assert!(e.contains("o registro 251"), "{e}");

        // O boot novo começando antes de um visto: a cadeia recomeçou por
        // cima do que estava gravado.
        let e =
            conferir_o_anel_do_corte(&anel_do_corte(), &vistos(150, 200), 190, false).unwrap_err();
        assert!(e.contains("o registro 190"), "{e}");
    }

    /// Com o registro do corte no disco, a cadeia do boot cortado passa do
    /// último visto gravado; sem nada depois dele antes do boot novo,
    /// reprova — e, com o registro do corte fora do disco, confere.
    #[test]
    fn o_registro_do_corte_que_vale_traz_o_que_levava() {
        let e =
            conferir_o_anel_do_corte(&anel_do_corte(), &vistos(150, 250), 251, true).unwrap_err();
        assert!(e.contains("nada do boot cortado depois do 250"), "{e}");
        assert_eq!(
            conferir_o_anel_do_corte(&anel_do_corte(), &vistos(150, 250), 251, false),
            Ok(101)
        );
    }

    /// A carga lê até a resposta do pedido dela, passando pelas outras; o
    /// aviso da queda, mesmo cortando uma linha pela metade, encerra a
    /// leitura; e o canal que fecha é erro.
    #[test]
    fn a_carga_le_ate_a_resposta_ou_a_queda() {
        let limite = Instant::now() + Duration::from_secs(5);
        let texto = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{\"records\":[]}}\n",
        );
        let lido = ate_a_resposta_ou_a_queda(&mut texto.as_bytes(), 8, limite).unwrap();
        assert!(
            matches!(&lido, Lido::Resposta(r) if r.contains("\"id\":8")),
            "{lido:?}"
        );

        let cortado = "{\"jsonrpc\":\"2.0\",\"id\":9,\"res\n{\"queda\":012}\n";
        assert_eq!(
            ate_a_resposta_ou_a_queda(&mut cortado.as_bytes(), 10, limite),
            Ok(Lido::Queda(12))
        );

        let fechado = "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n";
        let e = ate_a_resposta_ou_a_queda(&mut fechado.as_bytes(), 10, limite).unwrap_err();
        assert!(e.contains("fechou"), "{e}");
    }

    /// Um lote do leitor da carga, de `de` a `ate`: o elo de cada registro
    /// diz a sequência, como em [`rastro`], e o `prev`, a do anterior.
    fn lote(de: u64, ate: u64) -> Vec<(Rastro, String)> {
        (de..=ate)
            .map(|s| (rastro(s, &format!("e{s}")), format!("e{}", s - 1)))
            .collect()
    }

    /// Os lotes seguidos conferem: o primeiro sozinho, de onde o anel
    /// começar, e cada um depois do último lido — o vazio também.
    #[test]
    fn os_lotes_seguidos_conferem() {
        assert_eq!(conferir_o_lote(None, &lote(1, 128)), Ok(()));
        assert_eq!(conferir_o_lote(None, &lote(977, 1100)), Ok(()));
        let ultimo = rastro(128, "e128");
        assert_eq!(conferir_o_lote(Some(&ultimo), &lote(129, 256)), Ok(()));
        assert_eq!(conferir_o_lote(Some(&ultimo), &[]), Ok(()));
    }

    /// O lote que pula, que traz de novo o que já foi lido, que vem fora de
    /// ordem, ou em que um `prev` não é o `link` do anterior — dentro dele,
    /// ou entre ele e o último lido —: cada um reprova, e diz o quê. Sem o
    /// último lido, só o primeiro registro do lote fica sem conferir.
    #[test]
    fn o_lote_que_pula_repete_ou_quebra_o_elo() {
        let ultimo = rastro(128, "e128");
        let e = conferir_o_lote(Some(&ultimo), &lote(130, 140)).unwrap_err();
        assert!(e.contains("pulou do registro 128 para o 130"), "{e}");
        let e = conferir_o_lote(Some(&ultimo), &lote(128, 140)).unwrap_err();
        assert!(
            e.contains("o registro 128, que nao vem depois do 128"),
            "{e}"
        );
        let e = conferir_o_lote(Some(&ultimo), &lote(1, 140)).unwrap_err();
        assert!(e.contains("lido de novo"), "{e}");

        let mut buraco = lote(129, 140);
        buraco.remove(5);
        let e = conferir_o_lote(Some(&ultimo), &buraco).unwrap_err();
        assert!(e.contains("pulou do registro 133 para o 135"), "{e}");
        let mut repetido = lote(129, 140);
        repetido.insert(3, repetido[2].clone());
        let e = conferir_o_lote(Some(&ultimo), &repetido).unwrap_err();
        assert!(
            e.contains("o registro 131, que nao vem depois do 131"),
            "{e}"
        );
        let mut trocado = lote(129, 140);
        trocado.swap(4, 5);
        let e = conferir_o_lote(Some(&ultimo), &trocado).unwrap_err();
        assert!(e.contains("pulou do registro 132 para o 134"), "{e}");

        let mut outro_prev = lote(129, 140);
        outro_prev[6].1 = "outro".to_string();
        let e = conferir_o_lote(Some(&ultimo), &outro_prev).unwrap_err();
        assert!(
            e.contains("o prev do registro 135 nao e o link do 134"),
            "{e}"
        );
        let e = conferir_o_lote(Some(&rastro(128, "outro")), &lote(129, 140)).unwrap_err();
        assert!(
            e.contains("o prev do registro 129 nao e o link do 128"),
            "{e}"
        );

        let mut primeiro = lote(129, 140);
        primeiro[0].1 = "qualquer".to_string();
        assert_eq!(conferir_o_lote(None, &primeiro), Ok(()));
        let e = conferir_o_lote(None, &outro_prev).unwrap_err();
        assert!(e.contains("o prev do registro 135"), "{e}");
    }

    /// Um lote do `audit.tail`, com os campos que o kernel escreve: cada
    /// registro com o `prev` dele, na ordem, e o `durable_seq`; uma recusa
    /// por taxa gravada no lote não faz dele uma recusa; o lote vazio; e a
    /// resposta que não é de um `audit.tail`, que é erro.
    #[test]
    fn o_lote_da_cauda_traz_o_prev_e_o_gravado() {
        let registro = |seq: u64, metodo: &str, duravel: bool| {
            format!(
                r#"{{"seq":{seq},"ts_ms":5,"holder":"agent","session":3,"person_session":null,"agent":"agente-1","key":"ab","role":"operador","method":"{metodo}","resource":"","result":"DENY","code":"RATE_LIMIT","params":"00","detail":"taxa do papel esgotada","prev":"e{}","link":"e{seq}","durable":{duravel}}}"#,
                seq - 1
            )
        };
        let r = format!(
            r#"{{"jsonrpc":"2.0","id":400002,"result":{{"durable_seq":41,"records":[{},{}]}}}}"#,
            registro(41, "audit.head", true),
            registro(42, "agent.ping", false)
        );
        let lote = lote_da_cauda(&r).unwrap();
        assert_eq!(lote.gravado, 41);
        let lidos: Vec<(u64, &str, &str, &str, bool)> = lote
            .registros
            .iter()
            .map(|(r, prev)| {
                (
                    r.seq,
                    r.metodo.as_str(),
                    prev.as_str(),
                    r.elo.as_str(),
                    r.duravel,
                )
            })
            .collect();
        assert_eq!(
            lidos,
            [
                (41, "audit.head", "e40", "e41", true),
                (42, "agent.ping", "e41", "e42", false)
            ]
        );
        assert_eq!(espera_da_taxa(&r), None);

        let vazio = r#"{"jsonrpc":"2.0","id":400003,"result":{"durable_seq":42,"records":[]}}"#;
        assert_eq!(
            lote_da_cauda(vazio),
            Ok(LoteDaCauda {
                registros: Vec::new(),
                gravado: 42
            })
        );
        let recusa = r#"{"jsonrpc":"2.0","id":200004,"error":{"code":-32010,"message":"operacao negada pela politica","data":"DENY_PERMISSION"}}"#;
        let e = lote_da_cauda(recusa).unwrap_err();
        assert!(e.contains("nao e a de um audit.tail"), "{e}");
    }

    /// A recusa por taxa diz quanto esperar, entre um milissegundo e um
    /// segundo — dez, se não diz —; a recusa por permissão e a resposta que
    /// deu certo não são recusa por taxa.
    #[test]
    fn a_recusa_por_taxa_diz_quanto_esperar() {
        let taxa = |espera: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":400007,"error":{{"code":-32011,"message":"taxa de pedidos do papel esgotada","data":"RATE_LIMIT","explain":{{"outcome":"DENY","reason":"RATE_LIMIT","code":"RATE_LIMIT","resource":"","role":"sistema","decision":null,"recoverable":true,"retry":"retryable"{espera},"next_action":"WAIT_AND_RETRY","message":""}}}}}}"#
            )
        };
        assert_eq!(
            espera_da_taxa(&taxa(r#","retry_after_ms":20"#)),
            Some(Duration::from_millis(20))
        );
        assert_eq!(espera_da_taxa(&taxa("")), Some(Duration::from_millis(10)));
        assert_eq!(
            espera_da_taxa(&taxa(r#","retry_after_ms":90000"#)),
            Some(Duration::from_secs(1))
        );
        let permissao = r#"{"jsonrpc":"2.0","id":200009,"error":{"code":-32010,"message":"operacao negada pela politica","data":"DENY_PERMISSION","explain":{"outcome":"DENY","code":"DENY_PERMISSION"}}}"#;
        assert_eq!(espera_da_taxa(permissao), None);
        assert_eq!(
            espera_da_taxa(r#"{"jsonrpc":"2.0","id":100003,"result":{"pong":true}}"#),
            None
        );
    }

    /// O atraso do journal sai do `audit_backlog` de um `security.metrics`
    /// — o `max` de outro objeto não conta —, e a resposta sem ele, ou sem
    /// o que saiu do anel, é erro.
    #[test]
    fn o_atraso_da_auditoria_no_security_metrics() {
        let r = r#"{"jsonrpc":"2.0","id":70012,"result":{"budget":{"control_decisions":9,"audit_waits":{"deferred":0,"ended":0,"waiting_tasks":0,"wait_ms":{"samples":3,"max":77}},"audit_backlog":{"head":3001,"now":120,"max":640,"journal":2881,"lost":0,"share_from":640,"all_wait_from":768,"capacity":1024},"throughput":{}}}}"#;
        assert_eq!(atraso_da_auditoria(r), Ok((0, 640)));
        let perdeu = r.replace(r#""lost":0"#, r#""lost":12"#);
        assert_eq!(atraso_da_auditoria(&perdeu), Ok((12, 640)));
        let e = atraso_da_auditoria(r#"{"jsonrpc":"2.0","id":70013,"result":{}}"#).unwrap_err();
        assert!(e.contains("nao diz o atraso"), "{e}");
        let sem_perdidos = r.replace(r#""lost":0,"#, "");
        let e = atraso_da_auditoria(&sem_perdidos).unwrap_err();
        assert!(e.contains("nao diz `lost`"), "{e}");
    }

    /// O que o leitor viu gravado: os lidos até o `durable_seq` da
    /// conferência — nenhum, se ele vem antes do primeiro lido —, com o
    /// `durable` que uma resposta seguinte daria a cada um.
    #[test]
    fn os_vistos_gravados_vao_ate_o_durable_seq() {
        let lidos: Vec<Rastro> = (100..=120)
            .map(|s| Rastro {
                duravel: false,
                ..rastro(s, &format!("e{s}"))
            })
            .collect();
        let vistos = gravados_vistos(&lidos, 110);
        assert_eq!(
            vistos.keys().copied().collect::<Vec<u64>>(),
            (100..=110).collect::<Vec<u64>>()
        );
        assert!(
            vistos
                .values()
                .all(|r| r.duravel && r.elo == format!("e{}", r.seq))
        );
        assert!(gravados_vistos(&lidos, 99).is_empty());
        assert_eq!(gravados_vistos(&lidos, 500).len(), 21);
    }

    /// O erro de E/S de um fio reprova antes da marca do corte — e a carga
    /// acaba para os outros —; depois dela, é o corte, e o fio acaba com o
    /// que fez.
    #[test]
    fn o_erro_de_um_fio_antes_e_depois_do_corte() {
        let carga = Carga::default();
        assert!(!carga.acabou());
        assert_eq!(carga.fim(7u64, "caiu".into()), Err("caiu".to_string()));
        assert!(carga.acabou());
        let cortada = Carga::default();
        cortada.cortando.store(true, Ordering::SeqCst);
        assert_eq!(cortada.fim(7u64, "caiu".into()), Ok(7));
        assert!(!cortada.falhou.load(Ordering::SeqCst));
    }

    /// A vez da carga, com vários fios pedindo ao mesmo tempo: nunca passa
    /// da folga sobre os alcançados — nem por um —, anda quando o leitor
    /// alcança, e acaba com a marca do corte, com um fio reprovado e com o
    /// limite.
    #[test]
    fn a_vez_da_carga_nao_passa_da_folga() {
        let carga = Carga::default();
        let limite = Instant::now() + Duration::from_secs(60);
        // Os mandados, quando chegam a `n` — e mais um pouco, para um fio a
        // mais aparecer, se passasse.
        let mandados_ate = |n: u64| {
            let ate = Instant::now() + Duration::from_secs(10);
            while carga.mandados.load(Ordering::SeqCst) < n && Instant::now() < ate {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(50));
            carga.mandados.load(Ordering::SeqCst)
        };
        let (na_folga, alcancada, vezes) = std::thread::scope(|s| {
            let mut fios = Vec::new();
            for _ in 0..4 {
                fios.push(s.spawn(|| {
                    let mut vezes = 0u64;
                    while carga.esperar_a_vez(limite) {
                        vezes += 1;
                    }
                    vezes
                }));
            }
            let na_folga = mandados_ate(FOLGA_DA_CARGA);
            carga.alcancados.store(10, Ordering::SeqCst);
            let alcancada = mandados_ate(FOLGA_DA_CARGA + 10);
            carga.cortando.store(true, Ordering::SeqCst);
            let mut vezes = 0;
            for fio in fios {
                vezes += fio.join().unwrap_or(0);
            }
            (na_folga, alcancada, vezes)
        });
        assert_eq!(na_folga, FOLGA_DA_CARGA);
        assert_eq!(alcancada, FOLGA_DA_CARGA + 10);
        assert_eq!(vezes, FOLGA_DA_CARGA + 10);

        let reprovada = Carga::default();
        assert_eq!(reprovada.reprovar::<()>("x".into()), Err("x".to_string()));
        assert!(!reprovada.esperar_a_vez(limite));
        assert!(!Carga::default().esperar_a_vez(Instant::now()));
    }
}
