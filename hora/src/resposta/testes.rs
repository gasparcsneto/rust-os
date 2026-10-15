//! Os casos da conferência: a resposta honesta, os dois vetores externos, e
//! uma resposta torta para cada conferência — torta só naquilo.

use std::vec::Vec;

use super::*;
use crate::mensagem::{self, Mensagem};
use crate::pedido::Pedido;
use crate::servidor_de_teste::{self as st, Servidor};

const NONCE: [u8; 32] = [0x6e; 32];
const TETO: u32 = 10;

/// A chave pública do vetor da RFC 10049 (`GX9rI+Fsh…` no README dele).
const CHAVE_DO_VETOR_RFC: &str = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";
/// A chave pública da captura da época dos rascunhos (`AW5uAoTS…`).
const CHAVE_DO_VETOR_RASCUNHO: &str =
    "016e6e0284d24c37c6e4d7d8d5b4e1d3c1949ceaa545bf875616c9dce0c9bec1";

fn hex32(texto: &str) -> [u8; 32] {
    let mut saida = [0u8; 32];
    for (i, par) in texto.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(par).unwrap();
        saida[i] = u8::from_str_radix(s, 16).unwrap();
    }
    saida
}

fn conferir_contra(pedido: &Pedido, chave: &[u8; 32], resposta: &[u8]) -> Result<Prova, Recusa> {
    conferir(
        resposta,
        &Esperado {
            nonce: pedido.nonce(),
            folha: pedido.folha(),
            chave_longa: chave,
            teto_do_raio: TETO,
        },
    )
}

/// O pedido, o servidor e a resposta honesta dele.
fn honesta() -> (Pedido, Servidor, Vec<u8>) {
    let servidor = Servidor::novo();
    let pedido = Pedido::novo(&NONCE, &servidor.chave_longa());
    let resposta = servidor.responder(pedido.bytes());
    (pedido, servidor, resposta)
}

fn com(servidor: Servidor) -> Result<Prova, Recusa> {
    let pedido = Pedido::novo(&NONCE, &Servidor::novo().chave_longa());
    let resposta = servidor.responder(pedido.bytes());
    conferir_contra(&pedido, &Servidor::novo().chave_longa(), &resposta)
}

/// Os campos de uma mensagem, como dados.
fn campos(bytes: &[u8]) -> Vec<(mensagem::Etiqueta, Vec<u8>)> {
    let m = Mensagem::ler(bytes).unwrap();
    (0..m.quantas())
        .map(|i| (m.etiqueta(i), m.valor_em(i).to_vec()))
        .collect()
}

fn como_referencias(c: &[(mensagem::Etiqueta, Vec<u8>)]) -> Vec<(mensagem::Etiqueta, &[u8])> {
    c.iter().map(|(e, v)| (*e, &v[..])).collect()
}

/// A resposta honesta com o topo mexido por `mexer`, sem reassinar nada.
fn com_o_topo(mexer: impl FnOnce(&mut Vec<(mensagem::Etiqueta, Vec<u8>)>)) -> Vec<u8> {
    let (_, _, resposta) = honesta();
    let mut c = campos(moldura::mensagem(&resposta).unwrap());
    mexer(&mut c);
    st::emoldurado(&st::crua(&como_referencias(&c)))
}

/// A resposta honesta com uma mensagem aninhada do topo mexida, sem
/// reassinar nada.
fn com_a_aninhada(
    fora: mensagem::Etiqueta,
    mexer: impl FnOnce(&mut Vec<(mensagem::Etiqueta, Vec<u8>)>),
) -> Vec<u8> {
    com_o_topo(|topo| {
        let alvo = topo.iter_mut().find(|(e, _)| *e == fora).unwrap();
        let mut c = campos(&alvo.1);
        mexer(&mut c);
        alvo.1 = st::crua(&como_referencias(&c));
    })
}

fn conferir_honesto(resposta: &[u8]) -> Result<Prova, Recusa> {
    let (pedido, servidor, _) = honesta();
    conferir_contra(&pedido, &servidor.chave_longa(), resposta)
}

// --- O que passa -----------------------------------------------------------

#[test]
fn a_resposta_honesta_e_aceita() {
    let (pedido, servidor, resposta) = honesta();
    let prova = conferir_contra(&pedido, &servidor.chave_longa(), &resposta).unwrap();
    assert_eq!(prova.midp, st::MIDP_PADRAO);
    assert_eq!(prova.radi, 5);
    assert_eq!(prova.mint, st::MIDP_PADRAO - 3600);
    assert_eq!(prova.maxt, st::MIDP_PADRAO + 86_400);
    assert_eq!(prova.delegada, servidor.delegada.verifying_key().to_bytes());
    assert_eq!(
        prova.resumo,
        merkle::h(&[&resposta]),
        "o resumo é do pacote inteiro"
    );
}

#[test]
fn o_vetor_da_rfc_10049_e_aceito() {
    // O par gerado pela implementação de referência para a versão 1: a
    // única conferência externa possível sem rede. Se o escritor e o leitor
    // deste pacote errassem juntos, é aqui que apareceria.
    let pedido = include_bytes!("../../testdata/rfc10049-pedido.104172a3");
    let resposta = include_bytes!("../../testdata/rfc10049-resposta.104172a3");
    let nonce = st::nonce_do_pedido(pedido);
    let folha = merkle::folha(pedido);
    let prova = conferir(
        resposta,
        &Esperado {
            nonce: &nonce,
            folha: &folha,
            chave_longa: &hex32(CHAVE_DO_VETOR_RFC),
            teto_do_raio: TETO,
        },
    )
    .unwrap();
    assert_eq!(prova.midp, 1_791_158_400, "2026-10-05T00:00:00Z");
    assert_eq!(prova.radi, 5);
    assert_eq!(prova.mint, 1_791_158_400);
    assert_eq!(prova.maxt, 0x6b3c_fa80);
    // A folha é do pacote inteiro: a mensagem sem a moldura não fecha.
    let sem_moldura = merkle::folha(&pedido[moldura::CABECALHO..]);
    let errado = conferir(
        resposta,
        &Esperado {
            nonce: &nonce,
            folha: &sem_moldura,
            chave_longa: &hex32(CHAVE_DO_VETOR_RFC),
            teto_do_raio: TETO,
        },
    );
    assert_eq!(errado, Err(Recusa::OutroPedido));
}

#[test]
fn o_vetor_da_epoca_dos_rascunhos_e_recusado() {
    // Uma captura real da versão 0x8000000c: este lado só fala a 1.
    let pedido = include_bytes!("../../testdata/rascunho-pedido.071039e5");
    let resposta = include_bytes!("../../testdata/rascunho-resposta.071039e5");
    let nonce = st::nonce_do_pedido(pedido);
    let folha = merkle::folha(pedido);
    let r = conferir(
        resposta,
        &Esperado {
            nonce: &nonce,
            folha: &folha,
            chave_longa: &hex32(CHAVE_DO_VETOR_RASCUNHO),
            teto_do_raio: TETO,
        },
    );
    assert_eq!(r, Err(Recusa::Versao));
}

#[test]
fn em_lote_cada_pedido_fecha_a_sua_folha() {
    let servidor = Servidor::novo();
    let chave = servidor.chave_longa();
    let pedidos: Vec<Pedido> = (0..5u8).map(|i| Pedido::novo(&[i; 32], &chave)).collect();
    let bytes: Vec<&[u8]> = pedidos.iter().map(|p| &p.bytes()[..]).collect();
    for i in 0..5 {
        let resposta = servidor.responder_lote(&bytes, i);
        let prova = conferir_contra(&pedidos[i], &chave, &resposta);
        assert!(prova.is_ok(), "o pedido {i}: {prova:?}");
        let alheio = conferir_contra(&pedidos[(i + 1) % 5], &chave, &resposta);
        assert_eq!(alheio, Err(Recusa::Nonce), "a resposta de outro pedido");
    }
}

#[test]
fn etiquetas_desconhecidas_sao_ignoradas_e_assinadas_como_chegaram() {
    // Etiquetas novas no topo, dentro do SREP e dentro da DELE: as
    // assinaturas cobrem os bytes como chegaram, e uma reescrita que
    // largasse as desconhecidas não fecharia.
    let mut s = Servidor::novo();
    s.extra_no_topo.push((*b"ZZZY", std::vec![1; 8]));
    s.extra_no_srep.push((*b"ZZZY", std::vec![2; 12]));
    s.extra_na_dele.push((*b"ZZZY", std::vec![3; 4]));
    let prova = com(s).unwrap();
    assert_eq!(prova.midp, st::MIDP_PADRAO);
}

#[test]
fn a_delegacao_sem_prazo_passa_e_fica_na_prova() {
    let mut s = Servidor::novo();
    s.mint = 0;
    s.maxt = u64::MAX;
    let prova = com(s).unwrap();
    assert_eq!((prova.mint, prova.maxt), (0, u64::MAX));
}

#[test]
fn as_bordas_da_delegacao_e_do_raio_passam() {
    let mut s = Servidor::novo();
    s.mint = st::MIDP_PADRAO;
    assert!(com(s).is_ok(), "MIDP == MINT");
    let mut s = Servidor::novo();
    s.maxt = st::MIDP_PADRAO;
    assert!(com(s).is_ok(), "MIDP == MAXT");
    let mut s = Servidor::novo();
    s.radi = TETO;
    assert!(com(s).is_ok(), "o raio no teto");
    let mut s = Servidor::novo();
    s.radi = 1;
    assert!(com(s).is_ok());
}

#[test]
fn versoes_a_mais_no_vers_passam() {
    for vers in [
        std::vec![0, 1],
        std::vec![1, 0x8000_000c],
        std::vec![0, 1, 7, 0x8000_000c],
    ] {
        let mut s = Servidor::novo();
        s.vers = vers.clone();
        assert!(com(s).is_ok(), "{vers:?}");
    }
}

// --- A forma -----------------------------------------------------------------

#[test]
fn moldura() {
    let (_, _, resposta) = honesta();
    let mut magico = resposta.clone();
    magico[0] = b'X';
    assert_eq!(conferir_honesto(&magico), Err(Recusa::Moldura));
    let mut a_mais = resposta.clone();
    a_mais.push(0);
    assert_eq!(conferir_honesto(&a_mais), Err(Recusa::Moldura));
    // O formato legado do Google: a mensagem sem moldura nenhuma.
    let legado = &resposta[moldura::CABECALHO..];
    assert_eq!(conferir_honesto(legado), Err(Recusa::Moldura));
    let grande = st::emoldurado(&std::vec![0u8; moldura::MAIOR_PACOTE]);
    assert_eq!(conferir_honesto(&grande), Err(Recusa::Moldura));
}

#[test]
fn cada_etiqueta_do_topo_e_obrigatoria() {
    for falta in [SIG, NONC, TYPE, PATH, SREP, CERT, INDX] {
        let r = com_o_topo(|c| c.retain(|(e, _)| *e != falta));
        assert_eq!(
            conferir_honesto(&r),
            Err(Recusa::Estrutura),
            "sem {falta:?}"
        );
    }
}

#[test]
fn tamanhos_errados_no_topo() {
    for (etiqueta, tamanho) in [
        (SIG, 60),
        (SIG, 68),
        (NONC, 28),
        (NONC, 36),
        (TYPE, 8),
        (INDX, 8),
        (PATH, 36),
    ] {
        let r = com_o_topo(|c| {
            let alvo = c.iter_mut().find(|(e, _)| *e == etiqueta).unwrap();
            alvo.1 = std::vec![0; tamanho];
        });
        assert_eq!(
            conferir_honesto(&r),
            Err(Recusa::Estrutura),
            "{etiqueta:?} com {tamanho}"
        );
    }
    // O caminho com 33 resumos.
    let r = com_o_topo(|c| {
        let alvo = c.iter_mut().find(|(e, _)| *e == PATH).unwrap();
        alvo.1 = std::vec![0; 32 * 33];
    });
    // Passa do pacote máximo antes de chegar ao caminho: ou moldura, ou
    // estrutura — as duas recusam.
    assert!(matches!(
        conferir_honesto(&r),
        Err(Recusa::Moldura | Recusa::Estrutura)
    ));
}

#[test]
fn o_caminho_de_33_resumos_e_estrutura() {
    // Com o caminho cabendo no pacote: 33 resumos, os outros valores mínimos.
    let servidor = Servidor::novo();
    let pedido = Pedido::novo(&NONCE, &servidor.chave_longa());
    let caminho = std::vec![0u8; 32 * 33];
    let resposta = servidor.montar(&NONCE, &[0; 32], &caminho, 0);
    if resposta.len() <= moldura::MAIOR_PACOTE {
        assert_eq!(
            conferir_contra(&pedido, &servidor.chave_longa(), &resposta),
            Err(Recusa::Estrutura)
        );
    } else {
        assert_eq!(
            conferir_contra(&pedido, &servidor.chave_longa(), &resposta),
            Err(Recusa::Moldura)
        );
    }
    let caminho = std::vec![0u8; 32 * 32];
    let resposta = servidor.montar(&NONCE, &[0; 32], &caminho, 0);
    assert!(
        resposta.len() <= moldura::MAIOR_PACOTE,
        "32 resumos cabem num pacote"
    );
    assert_eq!(
        conferir_contra(&pedido, &servidor.chave_longa(), &resposta),
        Err(Recusa::OutroPedido),
        "32 resumos são estrutura válida; a raiz não fecha"
    );
}

#[test]
fn topo_fora_de_ordem_ou_repetido() {
    let r = com_o_topo(|c| c.swap(0, 1));
    assert_eq!(conferir_honesto(&r), Err(Recusa::Estrutura));
    let r = com_o_topo(|c| {
        let primeiro = c[0].clone();
        c.insert(1, primeiro);
    });
    assert_eq!(conferir_honesto(&r), Err(Recusa::Estrutura));
}

#[test]
fn o_srep_torto() {
    for falta in [VER, RADI, MIDP, VERS, ROOT] {
        let r = com_a_aninhada(SREP, |c| c.retain(|(e, _)| *e != falta));
        assert_eq!(
            conferir_honesto(&r),
            Err(Recusa::Estrutura),
            "SREP sem {falta:?}"
        );
    }
    for (etiqueta, tamanho) in [(VER, 8), (RADI, 8), (MIDP, 4), (ROOT, 28), (ROOT, 36)] {
        let r = com_a_aninhada(SREP, |c| {
            let alvo = c.iter_mut().find(|(e, _)| *e == etiqueta).unwrap();
            alvo.1 = std::vec![0; tamanho];
        });
        assert_eq!(
            conferir_honesto(&r),
            Err(Recusa::Estrutura),
            "{etiqueta:?} com {tamanho}"
        );
    }
    let r = com_o_topo(|c| {
        let alvo = c.iter_mut().find(|(e, _)| *e == SREP).unwrap();
        alvo.1 = 0u32.to_le_bytes().to_vec();
    });
    assert_eq!(
        conferir_honesto(&r),
        Err(Recusa::Estrutura),
        "SREP sem etiquetas"
    );
}

#[test]
fn o_vers_torto() {
    let tortos: [Vec<u8>; 5] = [
        Vec::new(),
        std::vec![1, 0, 0, 0, 0],
        [1u32, 1].iter().flat_map(|v| v.to_le_bytes()).collect(),
        [7u32, 1].iter().flat_map(|v| v.to_le_bytes()).collect(),
        (0u32..33).flat_map(|v| v.to_le_bytes()).collect(),
    ];
    for torto in tortos {
        let r = com_a_aninhada(SREP, |c| {
            c.iter_mut().find(|(e, _)| *e == VERS).unwrap().1 = torto.clone();
        });
        assert_eq!(
            conferir_honesto(&r),
            Err(Recusa::Estrutura),
            "VERS {torto:?}"
        );
    }
    let r = com_a_aninhada(SREP, |c| {
        c.iter_mut().find(|(e, _)| *e == VERS).unwrap().1 =
            (0u32..32).flat_map(|v| v.to_le_bytes()).collect();
    });
    assert_ne!(
        conferir_honesto(&r),
        Err(Recusa::Estrutura),
        "32 versões são forma válida"
    );
}

#[test]
fn o_cert_e_a_dele_tortos() {
    let r = com_a_aninhada(CERT, |c| c.retain(|(e, _)| *e != DELE));
    assert_eq!(
        conferir_honesto(&r),
        Err(Recusa::Estrutura),
        "CERT sem DELE"
    );
    let r = com_a_aninhada(CERT, |c| c.retain(|(e, _)| *e != SIG));
    assert_eq!(conferir_honesto(&r), Err(Recusa::Estrutura), "CERT sem SIG");
    let r = com_a_aninhada(CERT, |c| {
        c.iter_mut().find(|(e, _)| *e == SIG).unwrap().1 = std::vec![0; 60];
    });
    assert_eq!(
        conferir_honesto(&r),
        Err(Recusa::Estrutura),
        "SIG da delegação curta"
    );
    for falta in [PUBK, MINT, MAXT] {
        let r = com_a_aninhada(CERT, |c| {
            let dele = c.iter_mut().find(|(e, _)| *e == DELE).unwrap();
            let mut d = campos(&dele.1);
            d.retain(|(e, _)| *e != falta);
            dele.1 = st::crua(&como_referencias(&d));
        });
        assert_eq!(
            conferir_honesto(&r),
            Err(Recusa::Estrutura),
            "DELE sem {falta:?}"
        );
    }
    let r = com_a_aninhada(CERT, |c| {
        let dele = c.iter_mut().find(|(e, _)| *e == DELE).unwrap();
        let mut d = campos(&dele.1);
        d.iter_mut().find(|(e, _)| *e == PUBK).unwrap().1 = std::vec![0; 28];
        dele.1 = st::crua(&como_referencias(&d));
    });
    assert_eq!(conferir_honesto(&r), Err(Recusa::Estrutura), "PUBK curta");
}

#[test]
fn tipo() {
    for tipo in [0, 2, u32::MAX] {
        let mut s = Servidor::novo();
        s.tipo = tipo;
        assert_eq!(com(s), Err(Recusa::Tipo), "TYPE {tipo}");
    }
}

#[test]
fn nonce() {
    let mut s = Servidor::novo();
    s.nonce = Some([0x99; 32]);
    assert_eq!(com(s), Err(Recusa::Nonce));
}

#[test]
fn versao() {
    for (versao, vers) in [
        (0x8000_000c, std::vec![0x8000_000c]),
        (0, std::vec![0]),
        (2, std::vec![1, 2]),
        (1, std::vec![0, 2]),
        (1, std::vec![0x8000_000c]),
    ] {
        let mut s = Servidor::novo();
        s.versao = versao;
        s.vers = vers.clone();
        assert_eq!(
            com(s),
            Err(Recusa::Versao),
            "VER {versao:#x}, VERS {vers:?}"
        );
    }
}

// --- As assinaturas ------------------------------------------------------------

/// Uma assinatura que vale para qualquer mensagem contra a chave identidade
/// — de ordem pequena —, e a própria chave. A conferência estrita recusa.
fn forjada_para_a_chave_fraca() -> ([u8; 64], [u8; 32]) {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    let r = Scalar::from_bytes_mod_order([7u8; 32]);
    let ponto = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let mut assinatura = [0u8; 64];
    assinatura[..32].copy_from_slice(&ponto);
    assinatura[32..].copy_from_slice(&r.to_bytes());
    let mut identidade = [0u8; 32];
    identidade[0] = 1;
    (assinatura, identidade)
}

#[test]
fn a_forjada_valeria_na_conferencia_frouxa() {
    // O caso de cima só prova algo se a assinatura forjada passasse numa
    // conferência que não fosse a estrita.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (assinatura, identidade) = forjada_para_a_chave_fraca();
    let chave = VerifyingKey::from_bytes(&identidade).unwrap();
    assert!(chave.is_weak());
    assert!(
        chave
            .verify(b"qualquer coisa", &Signature::from_bytes(&assinatura))
            .is_ok()
    );
    assert!(
        chave
            .verify_strict(b"qualquer coisa", &Signature::from_bytes(&assinatura))
            .is_err()
    );
}

#[test]
fn assinatura_da_delegacao() {
    let (pedido, servidor, resposta) = honesta();
    // Outra chave fixada para a fonte.
    let outra = Servidor {
        longa: ed25519_dalek::SigningKey::from_bytes(&[0x4d; 32]),
        ..Servidor::novo()
    };
    assert_eq!(
        conferir_contra(&pedido, &outra.chave_longa(), &resposta),
        Err(Recusa::AssinaturaDaDelegacao)
    );
    // Um bit da assinatura da delegação.
    let r = com_a_aninhada(CERT, |c| {
        c.iter_mut().find(|(e, _)| *e == SIG).unwrap().1[5] ^= 1;
    });
    assert_eq!(conferir_honesto(&r), Err(Recusa::AssinaturaDaDelegacao));
    // A DELE mexida depois de assinada: o MINT.
    let (comeco, _) = {
        let corpo = moldura::mensagem(&resposta).unwrap();
        let topo = Mensagem::ler(corpo).unwrap();
        let cert = Mensagem::ler(topo.valor(CERT).unwrap()).unwrap();
        let dele = Mensagem::ler(cert.valor(DELE).unwrap()).unwrap();
        let mint = dele.valor(MINT).unwrap();
        (
            mint.as_ptr() as usize - resposta.as_ptr() as usize,
            mint.len(),
        )
    };
    let mut mexida = resposta.clone();
    mexida[comeco] ^= 1;
    assert_eq!(
        conferir_contra(&pedido, &servidor.chave_longa(), &mexida),
        Err(Recusa::AssinaturaDaDelegacao)
    );
    // O contexto dos rascunhos, na versão 1.
    let mut s = Servidor::novo();
    s.contexto_de_delegacao = b"RoughTime v1 delegation signature\0".to_vec();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaDelegacao));
    // O contexto sem o zero do fim.
    let mut s = Servidor::novo();
    s.contexto_de_delegacao = b"Roughtime v1 delegation signature".to_vec();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaDelegacao));
}

#[test]
fn a_chave_fixada_fraca_nao_vale() {
    let (assinatura, identidade) = forjada_para_a_chave_fraca();
    let (pedido, _, resposta) = honesta();
    let r = {
        let corpo = moldura::mensagem(&resposta).unwrap();
        let topo = Mensagem::ler(corpo).unwrap();
        let cert = Mensagem::ler(topo.valor(CERT).unwrap()).unwrap();
        let sig = cert.valor(SIG).unwrap();
        let comeco = sig.as_ptr() as usize - resposta.as_ptr() as usize;
        let mut r = resposta.clone();
        r[comeco..comeco + 64].copy_from_slice(&assinatura);
        r
    };
    assert_eq!(
        conferir_contra(&pedido, &identidade, &r),
        Err(Recusa::AssinaturaDaDelegacao)
    );
}

#[test]
fn assinatura_da_resposta() {
    let (pedido, servidor, resposta) = honesta();
    let chave = servidor.chave_longa();
    // Um bit da assinatura do topo.
    let mut sig = [0u8; 64];
    let corpo = moldura::mensagem(&resposta).unwrap();
    sig.copy_from_slice(Mensagem::ler(corpo).unwrap().valor(SIG).unwrap());
    sig[9] ^= 0x40;
    let r = st::trocar_no_topo(&resposta, SIG, &sig);
    assert_eq!(
        conferir_contra(&pedido, &chave, &r),
        Err(Recusa::AssinaturaDaResposta)
    );
    // O SREP mexido depois de assinado: o MIDP.
    let (comeco, _) = st::posicao_aninhada(&resposta, SREP, MIDP);
    let mut mexida = resposta.clone();
    mexida[comeco] ^= 1;
    assert_eq!(
        conferir_contra(&pedido, &chave, &mexida),
        Err(Recusa::AssinaturaDaResposta)
    );
    // Assinado pela chave longa, e não pela delegada.
    let mut s = Servidor::novo();
    s.assina_o_srep = Some(s.longa.clone());
    assert_eq!(com(s), Err(Recusa::AssinaturaDaResposta));
    // A PUBK de outra chave, que não assinou.
    let mut s = Servidor::novo();
    s.pubk = ed25519_dalek::SigningKey::from_bytes(&[0x45; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaResposta));
    // O contexto dos rascunhos, na versão 1.
    let mut s = Servidor::novo();
    s.contexto_de_resposta = b"RoughTime v1 response signature\0".to_vec();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaResposta));
    // O contexto sem o zero do fim.
    let mut s = Servidor::novo();
    s.contexto_de_resposta = b"Roughtime v1 response signature".to_vec();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaResposta));
    // O contexto da delegação no lugar do da resposta.
    let mut s = Servidor::novo();
    s.contexto_de_resposta = CONTEXTO_DE_DELEGACAO.to_vec();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaResposta));
}

#[test]
fn a_chave_delegada_fraca_nao_vale() {
    // A fonte delega, com a chave longa de verdade, para a chave identidade;
    // a assinatura do SREP é a forjada que valeria contra ela.
    let (assinatura, identidade) = forjada_para_a_chave_fraca();
    let mut s = Servidor::novo();
    s.pubk = identidade;
    let pedido = Pedido::novo(&NONCE, &s.chave_longa());
    let resposta = s.responder(pedido.bytes());
    let r = st::trocar_no_topo(&resposta, SIG, &assinatura);
    assert_eq!(
        conferir_contra(&pedido, &s.chave_longa(), &r),
        Err(Recusa::AssinaturaDaResposta)
    );
}

/// Uma assinatura de quem tem a chave, com o R de ordem pequena — a
/// identidade: S = k·a, com k = H(R ‖ A ‖ mensagem). Ela fecha a conta da
/// conferência frouxa, [S]B = R + [k]A; a estrita a recusa pelo R.
fn com_o_r_de_ordem_pequena(chave: &ed25519_dalek::SigningKey, mensagem: &[u8]) -> [u8; 64] {
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};
    let mut r = [0u8; 32];
    r[0] = 1;
    let resumo = Sha512::new()
        .chain_update(r)
        .chain_update(chave.verifying_key().to_bytes())
        .chain_update(mensagem)
        .finalize();
    let mut largo = [0u8; 64];
    largo.copy_from_slice(&resumo);
    let s = Scalar::from_bytes_mod_order_wide(&largo) * chave.to_scalar();
    let mut assinatura = [0u8; 64];
    assinatura[..32].copy_from_slice(&r);
    assinatura[32..].copy_from_slice(&s.to_bytes());
    assinatura
}

#[test]
fn o_r_de_ordem_pequena_nao_vale() {
    // A chave não é fraca, e quem assinou tem a chave privada; o que torna
    // a assinatura maleável é o R. A conferência frouxa a aceitaria — é por
    // isso que o caso prova algo.
    use ed25519_dalek::{Signature, Verifier};
    let (pedido, servidor, resposta) = honesta();
    let chave = servidor.chave_longa();
    let corpo = moldura::mensagem(&resposta).unwrap();
    let topo = Mensagem::ler(corpo).unwrap();
    // O SREP, como chegou, assinado pela delegada.
    let assinado = [CONTEXTO_DE_RESPOSTA, topo.valor(SREP).unwrap()].concat();
    let assinatura = com_o_r_de_ordem_pequena(&servidor.delegada, &assinado);
    assert!(
        servidor
            .delegada
            .verifying_key()
            .verify(&assinado, &Signature::from_bytes(&assinatura))
            .is_ok()
    );
    let r = st::trocar_no_topo(&resposta, SIG, &assinatura);
    assert_eq!(
        conferir_contra(&pedido, &chave, &r),
        Err(Recusa::AssinaturaDaResposta)
    );
    // A DELE, como chegou, assinada pela longa.
    let cert = Mensagem::ler(topo.valor(CERT).unwrap()).unwrap();
    let assinado = [CONTEXTO_DE_DELEGACAO, cert.valor(DELE).unwrap()].concat();
    let assinatura = com_o_r_de_ordem_pequena(&servidor.longa, &assinado);
    assert!(
        servidor
            .longa
            .verifying_key()
            .verify(&assinado, &Signature::from_bytes(&assinatura))
            .is_ok()
    );
    let sig = cert.valor(SIG).unwrap();
    let comeco = sig.as_ptr() as usize - resposta.as_ptr() as usize;
    let mut r = resposta.clone();
    r[comeco..comeco + 64].copy_from_slice(&assinatura);
    assert_eq!(
        conferir_contra(&pedido, &chave, &r),
        Err(Recusa::AssinaturaDaDelegacao)
    );
}

// --- O que a resposta autêntica afirma ------------------------------------------

#[test]
fn outro_pedido() {
    let servidor = Servidor::novo();
    let chave = servidor.chave_longa();
    // O mesmo nonce, outro pacote (o SRV de outra chave): a folha é do
    // pacote inteiro, e não do nonce.
    let nosso = Pedido::novo(&NONCE, &chave);
    let outro = Pedido::novo(&NONCE, &[0x77; 32]);
    let resposta = servidor.responder(outro.bytes());
    assert_eq!(
        conferir_contra(&nosso, &chave, &resposta),
        Err(Recusa::OutroPedido)
    );
    // Um byte do pedido mudado no caminho: o servidor assinou o que viu.
    let mut mudado = *nosso.bytes();
    mudado[1000] = 1;
    let resposta = servidor.responder(&mudado);
    assert_eq!(
        conferir_contra(&nosso, &chave, &resposta),
        Err(Recusa::OutroPedido)
    );
}

#[test]
fn o_caminho_e_o_indice_mexidos() {
    let servidor = Servidor::novo();
    let chave = servidor.chave_longa();
    let pedidos: Vec<Pedido> = (0..4u8).map(|i| Pedido::novo(&[i; 32], &chave)).collect();
    let bytes: Vec<&[u8]> = pedidos.iter().map(|p| &p.bytes()[..]).collect();
    let resposta = servidor.responder_lote(&bytes, 2);
    assert!(conferir_contra(&pedidos[2], &chave, &resposta).is_ok());
    // Um bit do caminho.
    let corpo = moldura::mensagem(&resposta).unwrap();
    let mut caminho = Mensagem::ler(corpo).unwrap().valor(PATH).unwrap().to_vec();
    caminho[40] ^= 1;
    let r = st::trocar_no_topo(&resposta, PATH, &caminho);
    assert_eq!(
        conferir_contra(&pedidos[2], &chave, &r),
        Err(Recusa::OutroPedido)
    );
    // O índice de outra posição, e o índice com um bit além do caminho.
    for indice in [3u32, 0, 2 | 4, 2 | 0x8000_0000] {
        let r = st::trocar_no_topo(&resposta, INDX, &indice.to_le_bytes());
        assert_eq!(
            conferir_contra(&pedidos[2], &chave, &r),
            Err(Recusa::OutroPedido),
            "INDX {indice}"
        );
    }
}

#[test]
fn fora_da_delegacao() {
    let mut s = Servidor::novo();
    s.mint = st::MIDP_PADRAO + 1;
    assert_eq!(com(s), Err(Recusa::ForaDaDelegacao), "antes da delegação");
    let mut s = Servidor::novo();
    s.maxt = st::MIDP_PADRAO - 1;
    assert_eq!(com(s), Err(Recusa::ForaDaDelegacao), "depois da delegação");
    let mut s = Servidor::novo();
    s.mint = u64::MAX;
    s.maxt = 0;
    assert_eq!(com(s), Err(Recusa::ForaDaDelegacao), "janela invertida");
}

#[test]
fn raio() {
    let mut s = Servidor::novo();
    s.radi = 0;
    assert_eq!(com(s), Err(Recusa::Raio), "raio zero");
    let mut s = Servidor::novo();
    s.radi = TETO + 1;
    assert_eq!(com(s), Err(Recusa::Raio), "acima do teto");
    let mut s = Servidor::novo();
    s.radi = u32::MAX;
    assert_eq!(com(s), Err(Recusa::Raio));
}

// --- A ordem e os nomes -----------------------------------------------------------

#[test]
fn o_que_a_resposta_afirma_so_se_le_depois_das_assinaturas() {
    // Forjada e fora da delegação: a recusa é a da assinatura.
    let mut s = Servidor::novo();
    s.mint = st::MIDP_PADRAO + 1;
    s.contexto_de_delegacao = b"outra coisa\0".to_vec();
    assert_eq!(com(s), Err(Recusa::AssinaturaDaDelegacao));
    // Forjada e com raio zero.
    let mut s = Servidor::novo();
    s.radi = 0;
    s.assina_o_srep = Some(s.longa.clone());
    assert_eq!(com(s), Err(Recusa::AssinaturaDaResposta));
    // A resposta de outro pedido, forjada: assinatura, e não outro pedido.
    let servidor = Servidor::novo();
    let nosso = Pedido::novo(&NONCE, &servidor.chave_longa());
    let outro = Pedido::novo(&NONCE, &[0x77; 32]);
    let mut s = Servidor::novo();
    s.contexto_de_resposta = b"x\0".to_vec();
    let r = s.responder(outro.bytes());
    assert_eq!(
        conferir_contra(&nosso, &servidor.chave_longa(), &r),
        Err(Recusa::AssinaturaDaResposta)
    );
}

#[test]
fn a_forma_se_confere_antes_das_assinaturas() {
    // Contra outra chave fixada, nenhuma assinatura fecha. Mesmo assim, o
    // veredito de uma resposta torta na forma é o da forma: ela se confere
    // sem conta de curva, e quem manda lixo não faz este lado conferir
    // assinatura.
    let contra_outra_chave = |servidor: Servidor| {
        let pedido = Pedido::novo(&NONCE, &servidor.chave_longa());
        let resposta = servidor.responder(pedido.bytes());
        let outra = ed25519_dalek::SigningKey::from_bytes(&[0x4d; 32])
            .verifying_key()
            .to_bytes();
        conferir_contra(&pedido, &outra, &resposta)
    };
    assert_eq!(
        contra_outra_chave(Servidor::novo()),
        Err(Recusa::AssinaturaDaDelegacao)
    );
    let mut s = Servidor::novo();
    s.tipo = 0;
    assert_eq!(contra_outra_chave(s), Err(Recusa::Tipo));
    let mut s = Servidor::novo();
    s.nonce = Some([0x99; 32]);
    assert_eq!(contra_outra_chave(s), Err(Recusa::Nonce));
    let mut s = Servidor::novo();
    s.versao = 0x8000_000c;
    s.vers = std::vec![0x8000_000c];
    assert_eq!(contra_outra_chave(s), Err(Recusa::Versao));
}

#[test]
fn nomes_estaveis_e_autenticidade() {
    let todas = [
        (Recusa::Moldura, "moldura", false),
        (Recusa::Estrutura, "estrutura", false),
        (Recusa::Tipo, "tipo", false),
        (Recusa::Nonce, "nonce", false),
        (Recusa::Versao, "versao", false),
        (
            Recusa::AssinaturaDaDelegacao,
            "assinatura_da_delegacao",
            false,
        ),
        (
            Recusa::AssinaturaDaResposta,
            "assinatura_da_resposta",
            false,
        ),
        (Recusa::OutroPedido, "outro_pedido", true),
        (Recusa::ForaDaDelegacao, "fora_da_delegacao", true),
        (Recusa::Raio, "raio", true),
    ];
    for (recusa, nome, autentica) in todas {
        assert_eq!(recusa.nome(), nome);
        assert_eq!(recusa.autentica(), autentica, "{nome}");
    }
}

// --- O custo -------------------------------------------------------------------------

/// O custo de conferir, no hospedeiro. Fica fora do CI:
/// `cargo test -p hora --release -- --ignored --nocapture custo`.
#[test]
#[ignore]
fn custo_da_conferencia() {
    let (pedido, servidor, resposta) = honesta();
    let chave = servidor.chave_longa();
    let medir = |nome: &str, pacote: &[u8], esperado: Result<(), Recusa>| {
        let n = 2_000u32;
        let inicio = std::time::Instant::now();
        for _ in 0..n {
            assert_eq!(
                conferir_contra(&pedido, &chave, pacote).map(|_| ()),
                esperado
            );
        }
        std::println!("{nome}: {:?} por resposta", inicio.elapsed() / n);
    };
    medir("válida (duas assinaturas)", &resposta, Ok(()));
    let mut forjada = resposta.clone();
    let corpo = moldura::mensagem(&resposta).unwrap();
    let topo = Mensagem::ler(corpo).unwrap();
    let cert = Mensagem::ler(topo.valor(CERT).unwrap()).unwrap();
    let sig = cert.valor(SIG).unwrap();
    let comeco = sig.as_ptr() as usize - resposta.as_ptr() as usize;
    forjada[comeco] ^= 1;
    medir(
        "delegação forjada (uma assinatura)",
        &forjada,
        Err(Recusa::AssinaturaDaDelegacao),
    );
    let mut torta = resposta.clone();
    torta[0] = b'X';
    medir(
        "sem moldura (nenhuma assinatura)",
        &torta,
        Err(Recusa::Moldura),
    );
}
