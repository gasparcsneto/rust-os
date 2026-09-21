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

/// Entra no laço de atendimento. Nunca retorna.
pub fn servir() -> ! {
    crate::log_info!(
        "agent",
        "canal pronto, {} comandos registrados",
        commands::COMANDOS.len()
    );

    let mut buffer = [0u8; LINHA_MAX];
    let mut tam = 0usize;
    // Ligado quando a linha atual estourou o buffer: descartamos tudo até o
    // próximo `\n` para voltar a um ponto de sincronia conhecido do stream.
    let mut estourou = false;

    loop {
        let byte = {
            let mut porta = crate::serial::AGENT_LINK.lock();
            porta.as_mut().and_then(|s| s.read_byte())
        };

        let Some(byte) = byte else {
            // ATENÇÃO: nada de `hlt` aqui. Nesta fase o kernel ainda não
            // habilitou nenhuma interrupção, e `hlt` sem interrupções pendentes
            // para a CPU *para sempre* — o sistema morreria silenciosamente no
            // primeiro instante ocioso. `spin_loop` é a primitiva correta para
            // espera ativa: ela emite a instrução `pause`, que avisa a CPU
            // sobre o laço de espera sem desligá-la.
            //
            // Quando as interrupções existirem, este laço vira orientado a
            // interrupção de recepção da UART e o `hlt` volta a ser correto.
            core::hint::spin_loop();
            continue;
        };

        match byte {
            b'\n' => {
                if estourou {
                    responder_erro(None, RpcError::LINHA_MUITO_LONGA, None);
                    estourou = false;
                } else if tam > 0 {
                    processar(&buffer[..tam]);
                }
                tam = 0;
            }
            // Clientes que mandam CRLF não deveriam quebrar o parser.
            b'\r' => {}
            _ => {
                if estourou {
                    continue;
                }
                if tam < LINHA_MAX {
                    buffer[tam] = byte;
                    tam += 1;
                } else {
                    estourou = true;
                    tam = 0;
                }
            }
        }
    }
}

/// Decodifica uma linha, despacha o comando e responde.
fn processar(linha: &[u8]) {
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
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
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
