//! Quem recebe bytes por um fluxo da malha e os devolve: o "aplicativo B"
//! da bancada dos fluxos (`cargo xtask fluxo`).
//!
//! Lançado pela pessoa, sem argumentos, ele oferece [`INTENCAO`] e diz
//! `recebedor: endpoint <endpoint>`. Aceita um fluxo — daqui ou de outro
//! Duke — e diz `recebedor: aceitei <id> de <quem abriu>`; lê tudo, dizendo
//! `recebedor: lidos <n>` a cada [`MARCO`] bytes, e diz
//! `recebedor: recebi <n> <resumo> de <quem abriu>` — o FNV-1a de 64 bits do
//! que leu. Grava o resumo pelo `fs.write` **dele**, no armazém
//! compartilhado, e diz `recebedor: gravar <código>`: gravar é decisão dele,
//! pelo papel dele — o fluxo não deu escrita nenhuma. Depois devolve `n`
//! bytes do padrão determinístico com a semente 1, termina o sentido dele,
//! fecha — o que escreveu segue legível do outro lado até o fim, mesmo
//! depois de ele sair — e diz `recebedor: devolvi <n>`.
//!
//! Numa falha ele diz `recebedor: <passo> <código> <motivo>` e o estado do
//! fluxo, `recebedor: estado <estado> <motivo do fim>`; se a falha veio no
//! meio da leitura, antes `recebedor: parcial <n> <resumo>` — o que chegou
//! até ali, que a bancada confere contra o padrão: nada que alguém tenha
//! trocado no caminho chega ao programa. E, por último, sempre,
//! `recebedor: fim <código de saída>`.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "recebedor",
    "fabric.offer",
    "fabric.stream",
    "fabric.remote",
    "fs.write"
);

use alloc::format;
use alloc::string::String;
use alloc::vec;
use programas::escreverln;
use programas::fluxo::{self, Fluxo, Origem, Resumo};
use programas::malha;
use programas::nativo;
use programas::sistema;

/// A intenção que ele oferece.
const INTENCAO: &str = "imagem.compartilhar";

/// O maior fluxo que ele lê: 4 MiB.
const TETO: usize = 4 * 1024 * 1024;

/// De quanto em quanto ele diz o que já leu.
const MARCO: usize = 256 * 1024;

/// Quanto cada pedido espera, no máximo: o teto do `wait`.
const ESPERA_MS: u64 = 10_000;

/// Quantas esperas seguidas sem nada andar são o prazo.
const ESPERAS: usize = 12;

/// Quantas esperas pelo pedido de abertura, de [`ESPERA_MS`] cada.
const ESPERAS_PELO_PEDIDO: usize = 30;

/// O código de saída com tudo lido e devolvido, e o de uma falha.
const CODIGO: i64 = 54;
const FALHOU: i64 = 55;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let codigo = correr();
    escreverln!("recebedor: fim {}", codigo);
    codigo
}

/// Diz a falha de um passo — e o estado do fluxo, se ele existe — e
/// devolve o código de saída dela.
fn falhou(passo: &str, codigo: &str, motivo: &str, f: Option<&Fluxo>) -> i64 {
    escreverln!("recebedor: {} {} {}", passo, codigo, motivo);
    if let Some(e) = f.and_then(|f| f.estado().ok()) {
        escreverln!(
            "recebedor: estado {} {}",
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

/// Grava `texto` no armazém compartilhado, pelo `fs.write` deste programa:
/// o código da decisão.
fn gravar(texto: &str) -> String {
    let caminho = format!("/armazem/compartilhado/recebido-{}", sistema::id());
    match nativo::pedir_com_anexo(
        "fs.write",
        |w| {
            w.field_str("path", &caminho)?;
            w.field_u64("expect_version", 0)
        },
        texto.as_bytes(),
    ) {
        Ok(r) => match r.resultado() {
            Ok(j) if j.member("ok").and_then(|v| v.as_bool()) != Some(false) => {
                String::from("ALLOW")
            }
            Ok(j) => j
                .member("code")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| String::from("ERROR")),
            Err(recusa) => String::from(recusa.motivo.unwrap_or("ERROR")),
        },
        Err(e) => format!("CHAMADA {e}"),
    }
}

fn correr() -> i64 {
    let endpoint = match malha::oferecer(INTENCAO) {
        Ok(e) => e,
        Err(f) => return falhou("oferecer", f.codigo(), "", None),
    };
    escreverln!("recebedor: endpoint {}", endpoint);
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
    escreverln!("recebedor: aceitei {} de {}", f.id(), de);

    // Tudo, na ordem.
    let (mut lido, mut resumo, mut paradas, mut marco) = (0usize, Resumo::novo(), 0usize, MARCO);
    loop {
        match f.ler(fluxo::MAIOR_PEDACO, ESPERA_MS) {
            Ok((bytes, fim)) => {
                if bytes.is_empty() && !fim {
                    paradas += 1;
                    if paradas >= ESPERAS {
                        escreverln!("recebedor: parcial {} {:016x}", lido, resumo.valor());
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
                    escreverln!("recebedor: lidos {}", lido);
                    marco += MARCO;
                }
                if fim {
                    break;
                }
            }
            Err(e) => {
                escreverln!("recebedor: parcial {} {:016x}", lido, resumo.valor());
                return falhou("ler", e.codigo(), e.motivo(), Some(&f));
            }
        }
    }
    escreverln!(
        "recebedor: recebi {} {:016x} de {}",
        lido,
        resumo.valor(),
        de
    );
    escreverln!(
        "recebedor: gravar {}",
        gravar(&format!("{:016x}", resumo.valor()))
    );

    // A volta: o mesmo tanto, com a semente 1.
    let mut pedaco = vec![0u8; fluxo::MAIOR_PEDACO];
    let (mut feito, mut paradas) = (0usize, 0usize);
    while feito < lido {
        let n = (lido - feito).min(fluxo::MAIOR_PEDACO);
        for (k, b) in pedaco[..n].iter_mut().enumerate() {
            *b = fluxo::padrao(1, feito + k);
        }
        match f.escrever(&pedaco[..n], ESPERA_MS) {
            Ok(0) => {
                paradas += 1;
                if paradas >= ESPERAS {
                    return falhou("devolver", "PRAZO", "o outro lado nao le", Some(&f));
                }
            }
            Ok(m) => {
                paradas = 0;
                feito += m;
            }
            Err(e) => return falhou("devolver", e.codigo(), e.motivo(), Some(&f)),
        }
    }
    if let Err(e) = f.terminar() {
        return falhou("terminar", e.codigo(), e.motivo(), Some(&f));
    }
    // E fecha, antes de sair: o que ele escreveu segue legível do outro
    // lado até o fim. Sem o fecho, a morte dele — ele ainda seria ponta —
    // levaria o que o outro não leu. Se o outro já leu tudo, o fluxo
    // concluiu, e não há o que fechar: a recusa diz só isso.
    let _ = f.fechar();
    escreverln!("recebedor: devolvi {}", feito);
    CODIGO
}
