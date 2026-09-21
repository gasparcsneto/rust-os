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

pub mod commands;
pub mod json;
pub mod protocol;
pub mod registry;

use core::fmt;

use json::JsonWriter;
use protocol::{Requisicao, RpcError};

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
    /// Ligado quando a linha atual estourou o buffer: descartamos tudo até o
    /// próximo `\n` para voltar a um ponto de sincronia conhecido do stream.
    estourou: bool,
}

impl Montador {
    const fn novo() -> Self {
        Self {
            buffer: [0; LINHA_MAX],
            tam: 0,
            estourou: false,
        }
    }

    /// Consome um byte, processando a requisição quando a linha fecha.
    ///
    /// Devolve `true` quando este byte fechou uma linha — o chamador usa isso
    /// para saber que acabou de gastar um tempo indeterminado executando um
    /// comando, e que é uma boa hora de dar a vez a outra tarefa.
    fn alimentar(&mut self, byte: u8) -> bool {
        match byte {
            b'\n' => {
                if self.estourou {
                    responder_erro(None, RpcError::LINHA_MUITO_LONGA, None);
                    self.estourou = false;
                } else if self.tam > 0 {
                    processar(&self.buffer[..self.tam]);
                }
                self.tam = 0;
                true
            }
            // Clientes que mandam CRLF não deveriam quebrar o parser.
            b'\r' => false,
            _ => {
                if self.estourou {
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
