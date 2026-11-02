//! Quem manda bytes por um fluxo da malha: o "aplicativo A" da bancada dos
//! fluxos (`cargo xtask fluxo`).
//!
//! Lançado pela pessoa, sem argumentos, ele procura quem oferece
//! [`INTENCAO`] neste Duke e, sem ninguém aqui, em [`PAR`] — outro Duke,
//! relacionado a ela pelo registro de dispositivos desta máquina. Abre um
//! fluxo ao primeiro candidato, manda [`TAMANHO`] bytes do padrão
//! determinístico (semente 0), termina o sentido dele e lê o que volta até
//! o fim. Cada passo ele diz no log:
//!
//! - `remetente: candidato aqui <programa> <endpoint>`, ou
//!   `remetente: candidato no par <programa> <endpoint>`;
//! - `remetente: abri <id>`;
//! - `remetente: mandei <n>` a cada [`MARCO`] bytes e no fim da ida, e
//!   `remetente: esperas <k>` — as escritas que não couberam inteiras: o
//!   crédito do par, ou o buffer do sentido, segurando quem manda;
//! - `remetente: voltou <n> <resumo>` — o FNV-1a de 64 bits do que leu;
//! - numa falha, `remetente: <passo> <código> <motivo>` e, se o fluxo
//!   chegou a existir, `remetente: estado <estado> <motivo do fim>`;
//! - e, por último, sempre, `remetente: fim <código de saída>`.
//!
//! Sem candidato no par, ele ainda pede a abertura, a um endpoint que não
//! existe: a bancada vê a recusa do `stream.open` no gate daqui — o
//! dispositivo que não existe para quem pede —, sem conexão nenhuma.
//!
//! O tempo de cada passo a bancada lê do log da máquina: o programa não
//! tem relógio.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("remetente", "fabric.send", "fabric.stream", "fabric.remote");

use alloc::vec;
use programas::escreverln;
use programas::fluxo::{self, Fluxo, Resumo};
use programas::malha::{self, Par};

/// O outro dispositivo, como o registro desta máquina o chama.
const PAR: Par<'static> = Par("dispositivo:par");

/// A intenção que ele procura.
const INTENCAO: &str = "imagem.compartilhar";

/// Quanto ele manda: 4 MiB.
const TAMANHO: usize = 4 * 1024 * 1024;

/// De quanto em quanto ele diz o que já mandou.
const MARCO: usize = 256 * 1024;

/// Quanto cada pedido espera, no máximo: o teto do `wait`.
const ESPERA_MS: u64 = 10_000;

/// Quantas esperas seguidas sem nada andar são o prazo: o outro lado não
/// lê, ou não manda.
const ESPERAS: usize = 12;

/// O endpoint que ninguém oferece: a abertura sem candidato.
const NINGUEM: &str = "0000000000000000:0";

/// O código de saída com a ida e a volta inteiras, e o de uma falha.
const CODIGO: i64 = 52;
const FALHOU: i64 = 53;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let codigo = correr();
    escreverln!("remetente: fim {}", codigo);
    codigo
}

/// Diz a falha de um passo — e o estado do fluxo, se ele existiu — e
/// devolve o código de saída dela.
fn falhou(passo: &str, codigo: &str, motivo: &str, f: Option<&Fluxo>) -> i64 {
    escreverln!("remetente: {} {} {}", passo, codigo, motivo);
    if let Some(e) = f.and_then(|f| f.estado().ok()) {
        escreverln!(
            "remetente: estado {} {}",
            e.estado,
            e.motivo.as_deref().unwrap_or("-")
        );
    }
    FALHOU
}

fn correr() -> i64 {
    // Aqui primeiro; sem ninguém aqui, no par.
    let aqui = malha::descobrir(INTENCAO).unwrap_or_default();
    let (no_par, candidato) = match aqui.into_iter().next() {
        Some(c) => (false, c),
        None => match PAR.descobrir(INTENCAO) {
            Ok(v) => match v.into_iter().next() {
                Some(c) => (true, c),
                None => return falhou("procurar", "VAZIO", "ninguem oferece", None),
            },
            Err(f) => {
                let motivo = match &f {
                    malha::Falha::Recusa { motivo, .. } => motivo.as_str(),
                    _ => "",
                };
                falhou("procurar", f.codigo(), motivo, None);
                // A abertura também é recusada aqui, sem conexão.
                return match fluxo::abrir_no_par(PAR.0, NINGUEM, INTENCAO) {
                    Ok(f) => falhou("abrir", "ABERTO", f.id(), None),
                    Err(e) => falhou("abrir", e.codigo(), e.motivo(), None),
                };
            }
        },
    };
    escreverln!(
        "remetente: candidato {} {} {}",
        if no_par { "no par" } else { "aqui" },
        candidato.programa,
        candidato.endpoint
    );
    let aberto = if no_par {
        fluxo::abrir_no_par(PAR.0, &candidato.endpoint, INTENCAO)
    } else {
        fluxo::abrir(&candidato.endpoint, INTENCAO)
    };
    let f = match aberto {
        Ok(f) => f,
        Err(e) => return falhou("abrir", e.codigo(), e.motivo(), None),
    };
    escreverln!("remetente: abri {}", f.id());

    // A ida: o padrão, em pedaços do buffer do sentido.
    let mut pedaco = vec![0u8; fluxo::MAIOR_PEDACO];
    let (mut feito, mut esperas, mut paradas, mut marco) = (0usize, 0u64, 0usize, MARCO);
    while feito < TAMANHO {
        let n = (TAMANHO - feito).min(fluxo::MAIOR_PEDACO);
        for (k, b) in pedaco[..n].iter_mut().enumerate() {
            *b = fluxo::padrao(0, feito + k);
        }
        match f.escrever(&pedaco[..n], ESPERA_MS) {
            Ok(m) => {
                if m < n {
                    esperas += 1;
                }
                if m == 0 {
                    paradas += 1;
                    if paradas >= ESPERAS {
                        return falhou("mandar", "PRAZO", "o outro lado nao le", Some(&f));
                    }
                } else {
                    paradas = 0;
                }
                feito += m;
            }
            Err(e) => {
                escreverln!("remetente: mandei {}", feito);
                return falhou("mandar", e.codigo(), e.motivo(), Some(&f));
            }
        }
        if feito >= marco && feito < TAMANHO {
            escreverln!("remetente: mandei {}", feito);
            marco += MARCO;
        }
    }
    escreverln!("remetente: mandei {}", feito);
    escreverln!("remetente: esperas {}", esperas);
    if let Err(e) = f.terminar() {
        return falhou("terminar", e.codigo(), e.motivo(), Some(&f));
    }

    // A volta, até o fim.
    let (mut lido, mut resumo, mut paradas) = (0usize, Resumo::novo(), 0usize);
    loop {
        match f.ler(fluxo::MAIOR_PEDACO, ESPERA_MS) {
            Ok((bytes, fim)) => {
                if bytes.is_empty() && !fim {
                    paradas += 1;
                    if paradas >= ESPERAS {
                        return falhou("ler", "PRAZO", "o outro lado nao manda", Some(&f));
                    }
                } else {
                    paradas = 0;
                }
                resumo.somar(&bytes);
                lido += bytes.len();
                if lido > TAMANHO {
                    return falhou("ler", "GRANDE", "a volta passou do tamanho", Some(&f));
                }
                if fim {
                    break;
                }
            }
            Err(e) => return falhou("ler", e.codigo(), e.motivo(), Some(&f)),
        }
    }
    escreverln!("remetente: voltou {} {:016x}", lido, resumo.valor());
    CODIGO
}
