//! Quem recebe devagar por um fluxo da malha: o leitor lento da bancada
//! dos fluxos (`cargo xtask fluxo`), que segura quem manda pela
//! contrapressão — e deixa o fluxo vivo o bastante para a bancada mexer no
//! meio dele: revogar, suspender, esquecer, trocar a política, cortar a
//! energia.
//!
//! Lançado pela pessoa, sem argumentos, ele oferece [`INTENCAO`] e diz
//! `recebedor-lento: endpoint <endpoint>`. Aceita um fluxo e diz
//! `recebedor-lento: aceitei <id> de <quem abriu>`; lê [`PEDACO`] bytes de
//! cada vez, e entre uma leitura e outra espera [`PAUSA_MS`] pelo próprio
//! endpoint — `stream.accept` com `wait`: a pausa é uma espera decidida pelo
//! gate, como qualquer outra, e cabe na taxa do papel. Um pedido que chegue
//! nessa espera ele aceita e guarda, sem ler, e diz
//! `recebedor-lento: aceitei mais <id> de <quem abriu>`: dois fluxos
//! abertos ao mesmo tempo. Diz `recebedor-lento: lidos <n>` a cada
//! [`MARCO`] bytes e, no fim, `recebedor-lento: recebi <n> <resumo> de <quem
//! abriu>`; termina o sentido dele sem mandar nada, fecha o fluxo e os
//! guardados.
//!
//! Numa falha, como o `recebedor`: `recebedor-lento: parcial <n> <resumo>`
//! se veio no meio da leitura, `recebedor-lento: <passo> <código> <motivo>`
//! e `recebedor-lento: estado <estado> <motivo do fim>`. E, por último,
//! sempre, `recebedor-lento: fim <código de saída>`.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "recebedor-lento",
    "fabric.offer",
    "fabric.stream",
    "fabric.remote"
);

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::fluxo::{self, Fluxo, Origem, Resumo};
use programas::malha;

/// A intenção que ele oferece: a mesma do `recebedor`.
const INTENCAO: &str = "imagem.compartilhar";

/// O maior fluxo que ele lê: 4 MiB.
const TETO: usize = 4 * 1024 * 1024;

/// Quanto ele lê de cada vez.
const PEDACO: usize = 8 * 1024;

/// A pausa entre duas leituras: dez esperas por segundo, na metade da taxa
/// do papel da pessoa.
const PAUSA_MS: u64 = 100;

/// De quanto em quanto ele diz o que já leu.
const MARCO: usize = 256 * 1024;

/// Quanto cada leitura espera, no máximo.
const ESPERA_MS: u64 = 10_000;

/// Quantas esperas seguidas sem nada andar são o prazo.
const ESPERAS: usize = 12;

/// Quantas esperas pelo pedido de abertura, de [`ESPERA_MS`] cada.
const ESPERAS_PELO_PEDIDO: usize = 30;

/// O código de saída com tudo lido, e o de uma falha.
const CODIGO: i64 = 56;
const FALHOU: i64 = 57;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut guardados = Vec::new();
    let codigo = correr(&mut guardados);
    for g in &guardados {
        let _ = g.fechar();
    }
    escreverln!("recebedor-lento: fim {}", codigo);
    codigo
}

/// Diz a falha de um passo — e o estado do fluxo, se ele existe — e
/// devolve o código de saída dela.
fn falhou(passo: &str, codigo: &str, motivo: &str, f: Option<&Fluxo>) -> i64 {
    escreverln!("recebedor-lento: {} {} {}", passo, codigo, motivo);
    if let Some(e) = f.and_then(|f| f.estado().ok()) {
        escreverln!(
            "recebedor-lento: estado {} {}",
            e.estado,
            e.motivo.as_deref().unwrap_or("-")
        );
    }
    FALHOU
}

/// Quem abriu, como o kernel daqui o diz: o dispositivo, ou o programa.
fn quem(o: &Origem) -> String {
    match (&o.dispositivo, &o.programa) {
        (Some(d), _) => d.clone(),
        (None, Some((p, r))) => format!("{} {}", p, r.get(..8).unwrap_or(r)),
        (None, None) => String::from("?"),
    }
}

fn correr(guardados: &mut Vec<Fluxo>) -> i64 {
    let endpoint = match malha::oferecer(INTENCAO) {
        Ok(e) => e,
        Err(f) => return falhou("oferecer", f.codigo(), "", None),
    };
    escreverln!("recebedor-lento: endpoint {}", endpoint);
    let mut esperas = 0;
    let (f, origem) = loop {
        match fluxo::aceitar(&endpoint, ESPERA_MS) {
            Ok(Some(par)) => break par,
            Ok(None) => {
                esperas += 1;
                if esperas >= ESPERAS_PELO_PEDIDO {
                    return falhou("aceitar", "PRAZO", "ninguem abriu", None);
                }
            }
            Err(e) => return falhou("aceitar", e.codigo(), e.motivo(), None),
        }
    };
    let de = quem(&origem);
    escreverln!("recebedor-lento: aceitei {} de {}", f.id(), de);

    let (mut lido, mut resumo, mut paradas, mut marco) = (0usize, Resumo::novo(), 0usize, MARCO);
    loop {
        match f.ler(PEDACO, ESPERA_MS) {
            Ok((bytes, fim)) => {
                if bytes.is_empty() && !fim {
                    paradas += 1;
                    if paradas >= ESPERAS {
                        escreverln!("recebedor-lento: parcial {} {:016x}", lido, resumo.valor());
                        return falhou("ler", "PRAZO", "o outro lado nao manda", Some(&f));
                    }
                } else {
                    paradas = 0;
                }
                resumo.somar(&bytes);
                lido += bytes.len();
                if lido > TETO {
                    return falhou("ler", "GRANDE", "passou do teto", Some(&f));
                }
                if lido >= marco && !fim {
                    escreverln!("recebedor-lento: lidos {}", lido);
                    marco += MARCO;
                }
                if fim {
                    break;
                }
            }
            Err(e) => {
                escreverln!("recebedor-lento: parcial {} {:016x}", lido, resumo.valor());
                return falhou("ler", e.codigo(), e.motivo(), Some(&f));
            }
        }
        // A pausa, pelo próprio endpoint: um pedido que chegue nela é
        // aceito e guardado.
        match fluxo::aceitar(&endpoint, PAUSA_MS) {
            Ok(Some((outro, o))) => {
                escreverln!(
                    "recebedor-lento: aceitei mais {} de {}",
                    outro.id(),
                    quem(&o)
                );
                guardados.push(outro);
            }
            Ok(None) => {}
            Err(e) => return falhou("pausa", e.codigo(), e.motivo(), Some(&f)),
        }
    }
    escreverln!(
        "recebedor-lento: recebi {} {:016x} de {}",
        lido,
        resumo.valor(),
        de
    );
    if let Err(e) = f.terminar() {
        return falhou("terminar", e.codigo(), e.motivo(), Some(&f));
    }
    // Fecha antes de sair: o fim do sentido dele segue legível do outro
    // lado, mesmo depois de ele sair. Se o outro já viu o fim, o fluxo
    // concluiu, e não há o que fechar.
    let _ = f.fechar();
    CODIGO
}
