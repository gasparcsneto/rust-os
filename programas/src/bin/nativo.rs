//! Um programa nativo do Duke: pede ao sistema pelo registro, como um agente
//! pede pelo canal — ver `programas::nativo` e `docs/INTERFACE.md`.
//!
//! A suíte o lança com a autoridade de um agente de papel `operador`, e ele
//! confere, de dentro, o que a interface nativa promete:
//!
//! - `system.info` passa, e diz a versão da interface;
//! - a prova administrativa e `debug.trigger` são de um canal: recusados
//!   com `DENY_PERMISSION`, mesmo para quem tem a permissão;
//! - JSON quebrado e método desconhecido voltam como no canal;
//! - a resposta que não cabe continua no kernel até ser buscada, e some
//!   depois de buscada;
//! - as mensagens saem da caixa de quem o lançou, com os nonces contados
//!   na janela do processo: o reenvio é duplicata, o nonce velho é replay;
//! - `ui.act` não é da interface nativa: o comando roda e diz que não.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não. Escreve uma linha por passo, para quem lê o log.

#![no_std]
#![no_main]

use programas::escreverln;
use programas::nativo::{self, Recusa};
use programas::sistema::{self, erro};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 74;

/// O primeiro nonce das mensagens. A suíte manda, pela porta do agente, com
/// um nonce maior antes de lançar o programa: se a janela fosse a mesma,
/// este seria replay.
const NONCE: u64 = 5;

fn recusa_de(r: &nativo::Resposta) -> Option<(i64, Option<&str>)> {
    r.resultado()
        .err()
        .map(|Recusa { codigo, motivo, .. }| (codigo, motivo))
}

fn campo_de_texto<'a>(r: &'a nativo::Resposta, campo: &str) -> Option<&'a str> {
    r.resultado().ok()?.member(campo)?.as_str()
}

fn campo_logico(r: &nativo::Resposta, campo: &str) -> Option<bool> {
    r.resultado().ok()?.member(campo)?.as_bool()
}

fn mandar(nonce: u64) -> Result<nativo::Resposta, i64> {
    nativo::pedir("message.send", |w| {
        w.field_str("to", "serial")?;
        w.field_str("body", "do programa nativo")?;
        w.field_u64("nonce", nonce)
    })
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // A versão da interface, pelo comando de todos.
    let Ok(info) = nativo::pedir("system.info", |_| Ok(())) else {
        return 1;
    };
    let versao = info
        .resultado()
        .ok()
        .and_then(|r| r.member("native_interface"))
        .and_then(|v| v.as_u64());
    if versao != Some(nativo::VERSAO as u64) {
        escreverln!("nativo: system.info deu {:?}", recusa_de(&info));
        return 2;
    }
    escreverln!("nativo: interface {}", nativo::VERSAO);

    // O que é de um canal: recusado pelo gate, com o código da política.
    for (metodo, falha) in [("admin.challenge", 3), ("debug.trigger", 4)] {
        let Ok(r) = nativo::pedir(metodo, |w| {
            if metodo == "debug.trigger" {
                w.field_str("kind", "fatal")?;
            }
            Ok(())
        }) else {
            return falha;
        };
        match recusa_de(&r) {
            Some((_, Some("DENY_PERMISSION"))) => {}
            outra => {
                escreverln!("nativo: {} deu {:?}", metodo, outra);
                return falha;
            }
        }
    }
    escreverln!("nativo: a prova e debug.trigger sao de um canal");

    // O mesmo envelope do canal para o que não chega a comando nenhum.
    match nativo::pedir_cru(b"isto nao e json") {
        Ok(r) if matches!(recusa_de(&r), Some((-32700, _))) => {}
        _ => return 5,
    }
    match nativo::pedir("nao.existe", |_| Ok(())) {
        Ok(r) if matches!(recusa_de(&r), Some((-32601, _))) => {}
        _ => return 6,
    }
    // Maior que a linha do canal: recusado pela chamada, antes de tudo.
    let grande = alloc::vec![b' '; nativo::MAIOR_PEDIDO + 1];
    if sistema::pedir(&grande) != erro::TAMANHO_INVALIDO {
        return 7;
    }
    escreverln!("nativo: os erros de protocolo sao os do canal");

    // A resposta que não cabe fica onde está.
    let pedido = br#"{"jsonrpc":"2.0","id":1,"method":"system.info","params":{}}"#;
    let tamanho = sistema::pedir(pedido);
    if tamanho <= 1 {
        return 8;
    }
    let mut um = [0u8; 1];
    if sistema::resposta(&mut um) != tamanho || um[0] != 0 {
        return 9;
    }
    let mut toda = alloc::vec![0u8; tamanho as usize];
    if sistema::resposta(&mut toda) != tamanho || toda[0] != b'{' {
        return 10;
    }
    // Buscada, ela sai do kernel.
    if sistema::resposta(&mut toda) != erro::NAO_ENCONTRADO {
        return 11;
    }
    escreverln!("nativo: a resposta espera ser buscada, uma vez");

    // As mensagens: da caixa de quem o lançou, com os nonces do processo.
    let Ok(primeira) = mandar(NONCE) else {
        return 12;
    };
    if campo_logico(&primeira, "ok") != Some(true)
        || campo_logico(&primeira, "duplicate") != Some(false)
    {
        escreverln!(
            "nativo: o primeiro envio deu {:?}",
            campo_de_texto(&primeira, "code")
        );
        return 12;
    }
    let Ok(reenvio) = mandar(NONCE) else {
        return 13;
    };
    if campo_logico(&reenvio, "duplicate") != Some(true)
        || campo_de_texto(&reenvio, "id") != campo_de_texto(&primeira, "id")
    {
        return 13;
    }
    let Ok(velho) = mandar(NONCE - 1) else {
        return 14;
    };
    if campo_de_texto(&velho, "code") != Some("DENY_REPLAY") {
        escreverln!(
            "nativo: o nonce velho deu {:?}",
            campo_de_texto(&velho, "code")
        );
        return 14;
    }
    escreverln!("nativo: as mensagens contam os nonces do processo");

    // Agir na interface não é da interface nativa: o comando diz que não.
    let Ok(acao) = nativo::pedir("ui.act", |w| {
        w.field_u64("id", 1)?;
        w.field_str("action", "press")
    }) else {
        return 15;
    };
    let erro_da_acao = campo_de_texto(&acao, "error").unwrap_or("");
    if campo_logico(&acao, "ok") != Some(false) || !erro_da_acao.contains("quem pediu nao e") {
        escreverln!("nativo: ui.act deu {:?}", recusa_de(&acao));
        return 15;
    }
    escreverln!("nativo: ui.act nao e de um processo");

    escreverln!("nativo conferido: o programa pede pelo mesmo gate");
    CODIGO
}

extern crate alloc;
