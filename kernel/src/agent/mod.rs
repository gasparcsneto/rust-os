//! O canal do agente: como o Claude opera este sistema operacional.
//!
//! # O que é
//!
//! Um servidor JSON-RPC 2.0 rodando dentro do kernel, falando pela COM2. Um
//! objeto JSON por linha entra, um objeto JSON por linha sai. Do lado de fora,
//! o QEMU liga essa porta a um socket Unix, então o agente conversa com o OS
//! com um `connect()` comum — sem depurador, sem stub de GDB, sem instrumentar
//! o binário.
//!
//! # Por que serial, e não rede
//!
//! Porque funciona *agora*. Um canal sobre TCP exigiria driver de rede, pilha
//! IP e, para ser honesto sobre segurança, TLS — tudo isso é fase 3. A UART
//! já está de pé no primeiro milissegundo do boot, antes de haver paginação,
//! heap ou interrupções.
//!
//! E essa precocidade é justamente o que dá valor ao canal: ele existe para
//! nos ajudar a construir e depurar as camadas que vêm *depois* dele. Quando
//! a paginação quebrar, o canal do agente ainda vai estar respondendo.
//!
//! O transporte é um detalhe trocável: o conjunto de comandos em
//! [`commands::COMANDOS`] não sabe nada sobre serial. Na fase 3, expor o mesmo
//! conjunto sobre TCP é trocar este módulo, não os comandos.
//!
//! # Os dois modos de atendimento
//!
//! - [`atender`] é o normal: uma tarefa assíncrona que espera bytes chegarem
//!   por interrupção e cede a CPU enquanto não há nada. É o que roda em
//!   operação.
//! - [`servir`] é o de emergência: um laço síncrono que não depende do heap
//!   nem do escalonador, usado no modo post-mortem depois de uma exceção
//!   fatal. Nessa hora, o heap e o escalonador podem ser exatamente o que
//!   quebrou, e o canal precisa responder mesmo assim.
//!
//! Os dois consomem a mesma fila de bytes e compartilham todo o resto:
//! enquadramento, decodificação e despacho.

// O canal do agente inteiro — enquadramento, parser, escritor e os dezenove
// comandos — é Rust seguro, e esta linha transforma esse fato num invariante
// verificado pelo compilador em vez de uma coincidência que o próximo commit
// desfaz sem ninguém notar.
//
// A escolha de módulo não é arbitrária. Este é o código que processa entrada
// vinda de fora da máquina: se algum dia houver um estouro de buffer no Duke,
// é aqui que ele teria mais valor para quem o explorasse. Também é o único
// subsistema grande que não fala com hardware — não há motivo legítimo para
// `unsafe` aqui, e portanto nada de legítimo é bloqueado.
//
// Se um dia for preciso mexer nisto, o caminho certo é isolar o `unsafe` num
// módulo de arquitetura e chamá-lo daqui, não relaxar a regra.
#![deny(unsafe_code)]

pub mod commands;
pub mod json;
pub mod protocol;
pub mod registry;

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use json::JsonWriter;
use protocol::{Requisicao, RpcError};

/// Um comando pediu que o kernel falhasse de propósito.
///
/// A falha não pode acontecer dentro do handler: a serialização é em
/// streaming, e naquele ponto a resposta ainda está aberta no fio. Quem
/// dispara é [`processar`], depois que o quadro fechou.
static FALHA_AGENDADA: AtomicBool = AtomicBool::new(false);

/// Marca que a próxima resposta deve ser seguida de uma falha fatal.
pub(crate) fn agendar_falha_fatal() {
    FALHA_AGENDADA.store(true, Ordering::SeqCst);
}

/// Quanto um quadro pode ficar parado antes de ser dado por abandonado.
///
/// Dois segundos a 100 Hz. É folgadíssimo para o que este canal é — um socket
/// no hospedeiro, onde uma requisição inteira atravessa em microssegundos — e
/// continua folgado para uma serial de verdade: os 2048 bytes de uma
/// requisição máxima levam 180 ms a 115200 bauds.
///
/// A conta é sobre **ociosidade**, e não sobre a idade do quadro, para que um
/// cliente lento porém constante nunca seja penalizado: o relógio reinicia a
/// cada byte.
///
/// Errar para baixo custa pouco: um quadro legítimo partido ao meio vira um
/// erro de JSON explícito, que o cliente vê. Errar para cima custa a janela em
/// que o lixo de um cliente morto ainda pode colar no pedido de outro.
const TETO_DO_QUADRO_EM_TIQUES: u64 = 200;

/// Tamanho máximo de uma requisição.
///
/// Fixo porque não há heap. Requisições maiores são rejeitadas com um erro
/// explícito em vez de silenciosamente truncadas — um agente precisa saber
/// que seu pedido não coube, e não receber uma resposta a uma pergunta que
/// não fez.
const LINHA_MAX: usize = 2048;

/// Monta linhas a partir de um fluxo de bytes.
///
/// Fica separado dos dois laços de atendimento porque o enquadramento é a
/// única parte com estado, e duplicá-lo seria duplicar exatamente a lógica
/// mais fácil de errar: o que fazer com uma linha longa demais.
struct Montador {
    buffer: [u8; LINHA_MAX],
    tam: usize,
    /// Quantos bytes o canal já tinha perdido quando este quadro começou.
    ///
    /// Bytes descartados por fila cheia não deixam marca no que sobra: o
    /// quadro remontado é indistinguível de um quadro íntegro, e se calhar de
    /// ser JSON válido o kernel o **executa** — uma requisição que ninguém
    /// enviou. Comparar o contador nas duas pontas é a única forma de saber.
    ///
    /// Medido, despejando vinte mil bytes de uma vez numa fila de quatro mil:
    /// no x86 o quadro vinha truncado e o erro saía; no ARM o `\n` final era
    /// descartado junto, o pedido seguinte era engolido pelo quadro quebrado,
    /// e o erro que voltava era atribuído a ele. Em nenhum dos dois havia como
    /// o agente saber que o que chegou não era o que ele mandou.
    perdas_ao_abrir: u64,
    /// Quando chegou o último byte deste quadro, em tiques.
    ///
    /// Um quadro parado tempo demais não é um cliente lento: é um cliente que
    /// morreu no meio de uma requisição. O kernel não enxerga a desconexão —
    /// não há linha de modem entre ele e o socket —, mas enxerga o relógio.
    ///
    /// Sem isto, o fragmento do cliente morto ficava pendurado e colava na
    /// primeira requisição de quem conectasse depois. Medido: um cliente
    /// enviou `{"jsonrpc":"2.0","id":2,"method":"agent.pi` e caiu; o cliente
    /// seguinte pediu um `agent.ping` com `id` 99 e recebeu
    ///
    ///     {"id":2,"error":{"code":-32601,"message":"metodo nao encontrado"}}
    ///
    /// — o pedido dele engolido, e uma resposta com o `id` de outra pessoa
    /// para um método que ele não chamou. Com um fragmento mais infeliz, o
    /// quadro colado vira uma requisição válida que ninguém fez, e o kernel a
    /// executa.
    ultimo_byte_em: u64,
    /// Este quadro já foi dado por perdido, e o cliente já foi avisado.
    ///
    /// Separado de `estourou` porque a causa é outra e o desfecho também: ali
    /// o kernel viu a requisição inteira e ela não coube; aqui ele não viu a
    /// requisição inteira. O que os dois compartilham é o que fazer a seguir —
    /// descartar até o próximo `\n` e recomeçar de um ponto conhecido.
    danificado: bool,
    /// Ligado quando a linha atual estourou o buffer: descartamos tudo até o
    /// próximo `\n` para voltar a um ponto de sincronia conhecido do stream.
    estourou: bool,
}

impl Montador {
    const fn novo() -> Self {
        Self {
            buffer: [0; LINHA_MAX],
            tam: 0,
            perdas_ao_abrir: 0,
            ultimo_byte_em: 0,
            danificado: false,
            estourou: false,
        }
    }

    /// Consome um byte, processando a requisição quando a linha fecha.
    ///
    /// Devolve `true` quando este byte fechou uma linha — o chamador usa isso
    /// para saber que acabou de gastar um tempo indeterminado executando um
    /// comando, e que é uma boa hora de dar a vez a outra tarefa.
    fn alimentar(&mut self, byte: u8) -> bool {
        // Ociosidade primeiro: um quadro parado tempo demais é abandonado em
        // silêncio, e este byte passa a ser o primeiro de um quadro novo.
        //
        // Em silêncio de propósito. Quem deixou o fragmento não está mais
        // ouvindo, e mandar um erro só confundiria quem acabou de chegar — que
        // não fez nada de errado e cuja requisição precisa ser atendida
        // normalmente.
        let agora = crate::tempo::ticks();
        if self.tam > 0 && agora.saturating_sub(self.ultimo_byte_em) > TETO_DO_QUADRO_EM_TIQUES {
            self.tam = 0;
            self.estourou = false;
            self.danificado = false;
            self.abrir_quadro();
        }
        self.ultimo_byte_em = agora;

        // A perda é conferida a cada byte, e não ao fechar o quadro, para que
        // o cliente saiba enquanto ainda está mandando. O quadro fecha de
        // qualquer forma — o handler repõe o delimitador que não coube, ver
        // [`crate::tarefas::entrada::coletar`] —, mas esperar por ele seria
        // responder só depois de o cliente terminar de despejar.
        if !self.danificado && crate::tarefas::entrada::perdidos() != self.perdas_ao_abrir {
            responder_erro(None, RpcError::ENTRADA_PERDIDA, None);
            self.tam = 0;
            self.estourou = false;

            if byte == b'\n' {
                // Este byte **é** o fim do quadro danificado. Nada a descartar
                // depois dele: o que vier já é do quadro seguinte.
                //
                // A ordem aqui não é detalhe. Este byte saiu da fila antes de
                // tudo o que ainda está nela, então descartar a fila sem
                // olhá-lo primeiro jogaria fora o quadro **seguinte** e
                // deixaria o delimitador do danificado passar como se fosse
                // dele.
                self.abrir_quadro();
                return true;
            }

            // O resto deste quadro já está na fila e já é lixo conhecido.
            // Jogá-lo fora de uma vez, em vez de um byte por ida ao executor,
            // é o que devolve a fila ao pedido seguinte antes que ele chegue.
            // Sem isso, a requisição legítima que vem depois não cabe e se
            // perde junto — foi o que a CI pegou e a máquina daqui não.
            if crate::tarefas::entrada::descartar_ate_nova_linha() {
                self.abrir_quadro();
                return true;
            }

            // A fila esvaziou sem o delimitador aparecer: ele ainda vem, e até
            // lá tudo que chegar é do quadro perdido.
            self.danificado = true;
            return false;
        }

        match byte {
            b'\n' => {
                // O aviso de dano já saiu quando a perda foi detectada; aqui
                // só se recomeça de um ponto conhecido do fluxo.
                if self.danificado {
                    // nada a responder
                } else if self.estourou {
                    responder_erro(None, RpcError::LINHA_MUITO_LONGA, None);
                } else if self.tam > 0 {
                    processar(&self.buffer[..self.tam]);
                }

                self.danificado = false;
                self.estourou = false;
                self.tam = 0;
                self.abrir_quadro();
                true
            }
            // Clientes que mandam CRLF não deveriam quebrar o parser.
            b'\r' => false,
            _ => {
                if self.estourou || self.danificado {
                    return false;
                }
                if self.tam < LINHA_MAX {
                    self.buffer[self.tam] = byte;
                    self.tam += 1;
                } else {
                    self.estourou = true;
                    self.tam = 0;
                }
                false
            }
        }
    }

    /// Marca o ponto de partida de um quadro novo.
    ///
    /// Chamado ao fechar o anterior, e não ao receber o primeiro byte: a perda
    /// que interessa a este quadro é toda a que acontecer entre o fim do
    /// quadro passado e o fim dele, inclusive a que acontecer antes de o
    /// primeiro byte dele chegar — que é justamente onde some um `\n`.
    fn abrir_quadro(&mut self) {
        self.perdas_ao_abrir = crate::tarefas::entrada::perdidos();
    }
}

/// A tarefa que atende o canal do agente. Nunca termina.
///
/// # O que o `.await` faz aqui
///
/// Cada `.await` é um ponto em que esta tarefa devolve o controle ao
/// executor. Enquanto não há byte na fila, ela não roda: seu waker fica
/// guardado, o handler da interrupção da serial o aciona quando um byte
/// chega, e só então o executor a traz de volta exatamente deste ponto.
///
/// Comparado ao laço antigo, a diferença prática é grande. Antes, o kernel
/// ou dormia até o próximo tique do timer (10 ms de latência por byte) ou
/// girava em espera ativa para evitá-la. Agora não faz nenhum dos dois: a
/// latência é a da interrupção, e o núcleo fica parado no resto do tempo.
///
/// O `async fn` não retorna `!` porque uma tarefa precisa produzir `()`. O
/// laço infinito por dentro dá no mesmo, com a vantagem de o executor poder
/// continuar rodando outras tarefas.
///
/// Em modo de teste esta função não tem chamador: a suíte roda no lugar do
/// atendimento, e uma tarefa que nunca termina não teria como devolver o
/// controle ao relatório.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub async fn atender() {
    crate::log_info!(
        "agent",
        "canal assincrono pronto, {} comandos registrados",
        commands::COMANDOS.len()
    );

    let mut montador = Montador::novo();
    // A linha de partida do primeiro quadro é aqui, e não no `const fn`: o
    // contador de perdas não existe em tempo de compilação.
    montador.abrir_quadro();
    loop {
        let byte = crate::tarefas::entrada::proximo_byte().await;
        if montador.alimentar(byte) {
            // Acabamos de executar um comando, o que pode ter custado um
            // tempo arbitrário. Um cliente que envie várias requisições
            // emendadas manteria esta tarefa rodando sem parar, porque o
            // `.await` de cima encontraria a fila sempre cheia e nunca
            // cederia. Ceder aqui dá a vez às outras tarefas entre uma
            // requisição e a seguinte.
            crate::tarefas::ceder().await;
        }
    }
}

/// Atende o canal sem tarefas, sem heap e sem escalonador. Nunca retorna.
///
/// Este é o laço do modo post-mortem. Ele existe porque, depois de uma
/// exceção fatal, não dá para confiar em nada que o kernel construiu por
/// cima do básico — e o canal do agente é justamente o que precisa
/// sobreviver, para poder contar o que aconteceu.
///
/// Por isso ele bombeia a coleta da UART à mão em vez de esperar pela
/// interrupção: se a falha deixou as interrupções mascaradas, ou se o
/// controlador ficou num estado estranho, um laço que dependesse delas não
/// responderia nunca.
pub fn servir() -> ! {
    crate::log_info!(
        "agent",
        "canal em modo direto, {} comandos registrados",
        commands::COMANDOS.len()
    );

    let mut montador = Montador::novo();
    // A linha de partida do primeiro quadro é aqui, e não no `const fn`: o
    // contador de perdas não existe em tempo de compilação.
    montador.abrir_quadro();

    loop {
        // A coleta é idempotente e barata quando não há nada: se as
        // interrupções ainda funcionarem, ela vai quase sempre encontrar a
        // fila já preenchida pelo handler, e não há conflito entre os dois —
        // ambos passam pela mesma fila.
        crate::tarefas::entrada::coletar();

        let mut atendeu = false;
        while let Some(byte) = crate::tarefas::entrada::retirar() {
            let _ = montador.alimentar(byte);
            atendeu = true;
        }

        if !atendeu {
            // Ocioso: dormimos até a próxima interrupção em vez de queimar o
            // núcleo. `esperar_interrupcao` é seguro mesmo com elas
            // mascaradas — cada arquitetura verifica e cai em espera ativa
            // nesse caso, porque dormir de verdade pararia o núcleo para
            // sempre.
            crate::arch::esperar_interrupcao();
        }
    }
}

/// Remove ruído das bordas de um quadro.
///
/// Descarta bytes de controle e espaços no começo e no fim da linha. Isso
/// torna o canal tolerante a três coisas reais: terminadores CRLF, bytes
/// nulos que uma UART produz em transições de linha, e qualquer resíduo que
/// tenha escapado da drenagem feita na inicialização da porta.
///
/// É seguro: nenhum byte abaixo de 0x21 pode iniciar ou encerrar um valor
/// JSON, então nunca descartamos conteúdo significativo. E é preferível a
/// confiar só na drenagem — um único byte espúrio no momento errado não deve
/// custar ao agente uma requisição inteira.
pub(crate) fn limpar_quadro(linha: &[u8]) -> &[u8] {
    let inicio = linha.iter().position(|&b| b > 0x20);
    let Some(inicio) = inicio else {
        return &[];
    };
    let fim = linha
        .iter()
        .rposition(|&b| b > 0x20)
        .expect("se há um byte significativo no início, há um no fim");
    &linha[inicio..=fim]
}

/// Decodifica uma linha, despacha o comando e responde.
fn processar(linha: &[u8]) {
    let linha = limpar_quadro(linha);
    if linha.is_empty() {
        return;
    }

    let requisicao = match Requisicao::parse(linha) {
        Ok(r) => r,
        Err((id, erro)) => return responder_erro(id, erro, None),
    };

    let Some(comando) = registry::encontrar(requisicao.metodo) else {
        return responder_erro(requisicao.id, RpcError::METODO_NAO_ENCONTRADO, None);
    };

    // Validar antes de escrever qualquer coisa é obrigatório: a serialização
    // é em streaming, então depois de emitir `"result":` não há como voltar
    // atrás e transformar a resposta num erro.
    if let Err(campo) = registry::validar(comando, requisicao.params) {
        return responder_erro(requisicao.id, RpcError::PARAMS_INVALIDOS, Some(campo));
    }

    com_saida(|w| {
        protocol::envelope_ok(w, requisicao.id, |w| {
            (comando.handler)(requisicao.params, w)
        })
    });

    // Com a resposta inteira no fio, é seguro morrer. Daqui não se volta: o
    // handler da exceção entra em modo post-mortem, que reentra neste mesmo
    // módulo por [`servir`].
    if FALHA_AGENDADA.swap(false, Ordering::SeqCst) {
        crate::arch::disparar_falha_fatal();
    }
}

fn responder_erro(id: Option<json::Json>, erro: RpcError, detalhe: Option<&str>) {
    com_saida(|w| protocol::envelope_erro(w, id, erro, detalhe));
}

/// Emite uma resposta completa na COM2, seguida do delimitador de quadro.
fn com_saida(f: impl FnOnce(&mut JsonWriter) -> fmt::Result) {
    crate::arch::sem_interrupcoes(|| {
        let mut guarda = crate::serial::AGENT_LINK.lock();
        let Some(porta) = guarda.as_mut() else {
            return;
        };

        // Escopo explícito: o `JsonWriter` empresta a porta mutavelmente, e
        // precisamos que esse empréstimo termine antes de escrever o `\n`.
        {
            let mut w = JsonWriter::new(&mut *porta);
            // Um erro de escrita aqui significa que a porta sumiu no meio da
            // resposta. Não há a quem reportar — o canal de reporte *é* a
            // porta —, então seguimos em frente.
            let _ = f(&mut w);
        }

        // NDJSON: um `\n` fecha o quadro. É o que permite ao cliente ler uma
        // resposta inteira sem contar chaves para achar onde o objeto termina.
        porta.write_bytes(b"\n");
    });
}
