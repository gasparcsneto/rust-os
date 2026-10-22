//! A rede principal do IC, de verdade, no hospedeiro: corpos de
//! `read_state` que a rede principal respondeu, gravados pelo `ic-agent`
//! 0.49.2 nos testes dele (`src/agent/agent_test/`, Apache-2.0 — o pacote
//! conferido pelo `cksum` do índice do crates.io) e guardados em
//! `web3/dados/rede_principal/`. Cada um é conferido pela chave da raiz da
//! rede principal — a de `raiz.hex`, ao lado deles, a mesma que o `xtask`
//! escreve na linha `mainnet` de `/dados/icp/redes` —, na hora em que foi
//! assinado.
//!
//! Nenhum byte daqui veio pela rede desta máquina. A prova de que são da
//! rede principal é a verificação: a assinatura BLS da raiz sobre a
//! delegação, e a da sub-rede sobre a árvore — que nenhum caminho entre o
//! IC e quem gravou poderia forjar.
//!
//! - `ivg37_time.bin`: o `read_state` de `/time` do canister
//!   `ivg37-qiaaa-aaaab-aaaga-cai`, pela `/api/v3`, delegado à sub-rede
//!   [`SUB_REDE_DO_IVG37`];
//! - `ivg37_time_pruned_ranges.bin`: o mesmo, com as faixas podadas à mão;
//! - `ivg37_delegated_v2.bin`: o do mesmo canister pela `/api/v2`, com as
//!   faixas na forma antiga;
//! - `224od_subnet.bin`: o `read_state` de `/subnet` do canister
//!   `224od-giaaa-aaaao-ae5vq-cai` — a leitura que a consulta faz antes do
//!   `query` ([`crate::icp::agente::consultar`]) —, delegado à sub-rede
//!   [`SUB_REDE_DO_224OD`], com as chaves dos nós dela.

use std::vec::Vec;

use ic_certificate_verification::VerifyCertificate;

use super::*;
use crate::icp::bancada::{chave_bls, raiz};

/// A chave da raiz da rede principal, em DER, como `/dados/icp/redes` a
/// diz.
const RAIZ_DA_REDE_PRINCIPAL: &str = include_str!("../../../dados/rede_principal/raiz.hex");

const IVG37: &[u8] = include_bytes!("../../../dados/rede_principal/ivg37_time.bin");
const IVG37_PODADO: &[u8] =
    include_bytes!("../../../dados/rede_principal/ivg37_time_pruned_ranges.bin");
const IVG37_V2: &[u8] = include_bytes!("../../../dados/rede_principal/ivg37_delegated_v2.bin");
const SUB_REDE_224OD: &[u8] = include_bytes!("../../../dados/rede_principal/224od_subnet.bin");

const CANISTER_IVG37: &str = "ivg37-qiaaa-aaaab-aaaga-cai";
const CANISTER_224OD: &str = "224od-giaaa-aaaao-ae5vq-cai";

/// O livro-razão do ICP, na sub-rede do NNS: de nenhuma das duas sub-redes
/// abaixo.
const LIVRO_RAZAO: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";

const SUB_REDE_DO_IVG37: &str = "qxesv-zoxpm-vc64m-zxguk-5sj74-35vrb-tbgwg-pcird-5gr26-62oxl-cae";
const SUB_REDE_DO_224OD: &str = "o3ow2-2ipam-6fcjo-3j5vt-fzbge-2g7my-5fz2m-p4o2t-dwlc4-gt2q7-5ae";

/// Quando cada um foi assinado: o `/time` deles.
const TEMPO_DO_IVG37: u64 = 1_763_796_896_688_941_908;
const TEMPO_DO_224OD: u64 = 1_765_214_062_097_800_265;

fn raiz_da_rede_principal() -> Raiz {
    let hex = RAIZ_DA_REDE_PRINCIPAL.trim().as_bytes();
    assert_eq!(hex.len(), 2 * CHAVE_BLS_DER);
    let der: Vec<u8> = hex
        .chunks(2)
        .map(|par| u8::from_str_radix(core::str::from_utf8(par).unwrap(), 16).unwrap())
        .collect();
    Raiz::de_der(&der).unwrap()
}

/// O certificado de um corpo de `read_state`: `{certificate: bytes}`.
fn doc(corpo: &[u8]) -> Vec<u8> {
    let v = cbor::ler(corpo).unwrap();
    Vec::from(v.campo("certificate").and_then(Valor::bytes).unwrap())
}

fn principal(texto: &str) -> Principal {
    Principal::de_texto(texto).unwrap()
}

fn conferir(doc: &[u8], canister: &str, agora_ns: u64) -> Result<Autoridade, Erro> {
    let cert = Certificado::ler(doc)?;
    verificar(
        &cert,
        &raiz_da_rede_principal(),
        &principal(canister),
        agora_ns,
    )
}

/// O oráculo: o `ic-certificate-verification`, com a mesma tolerância.
fn oraculo(doc: &[u8], canister: &str, raiz: &Raiz, agora_ns: u64) -> bool {
    let Ok(cert) = serde_cbor::from_slice::<ic_certification::Certificate>(doc) else {
        return false;
    };
    cert.verify(
        principal(canister).bytes(),
        raiz.der(),
        &u128::from(agora_ns),
        &u128::from(TOLERANCIA_NS),
    )
    .is_ok()
}

/// Onde `parte`, uma fatia de `todo`, começa nele.
fn posicao(todo: &[u8], parte: &[u8]) -> usize {
    let inicio = parte.as_ptr() as usize - todo.as_ptr() as usize;
    assert!(inicio + parte.len() <= todo.len());
    inicio
}

/// `doc` com o bit de baixo do byte `i` trocado.
fn trocado(doc: &[u8], i: usize) -> Vec<u8> {
    let mut d = Vec::from(doc);
    d[i] ^= 1;
    d
}

#[test]
fn a_rede_principal_verifica_pela_raiz_dela() {
    let raiz = raiz_da_rede_principal();
    // A chave é a da rede principal, e não a de outra: a sub-rede raiz que
    // ela diz é a do NNS.
    assert_eq!(
        raiz.sub_rede().texto(),
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    );

    let ivg37 = doc(IVG37);
    assert_eq!(
        conferir(&ivg37, CANISTER_IVG37, TEMPO_DO_IVG37),
        Ok(Autoridade {
            sub_rede: principal(SUB_REDE_DO_IVG37),
            delegada: true,
            tempo_ns: TEMPO_DO_IVG37,
        })
    );
    assert!(oraculo(&ivg37, CANISTER_IVG37, &raiz, TEMPO_DO_IVG37));

    let sub_rede = doc(SUB_REDE_224OD);
    assert_eq!(
        conferir(&sub_rede, CANISTER_224OD, TEMPO_DO_224OD),
        Ok(Autoridade {
            sub_rede: principal(SUB_REDE_DO_224OD),
            delegada: true,
            tempo_ns: TEMPO_DO_224OD,
        })
    );
    assert!(oraculo(&sub_rede, CANISTER_224OD, &raiz, TEMPO_DO_224OD));
}

/// A leitura que a consulta faz antes do `query` traz os nós da sub-rede,
/// cada um com a chave Ed25519 em DER: é contra eles que a resposta da
/// consulta é conferida.
#[test]
fn a_leitura_da_sub_rede_traz_os_nos_dela() {
    let d = doc(SUB_REDE_224OD);
    let cert = Certificado::ler(&d).unwrap();
    let sub_rede = principal(SUB_REDE_DO_224OD);
    assert_eq!(nos_com_chave(&cert, &sub_rede), 13);
    let Sub::Achou(nos) = cert
        .arvore
        .subarvore(&[b"subnet", sub_rede.bytes(), b"node"])
    else {
        panic!("sem os nos");
    };
    let mut com_chave = 0;
    for no in nos.floresta() {
        if let Arvore::Rotulada(id, _) = no {
            let no = Principal::de_bytes(id).unwrap();
            if chave_do_no(&cert, &sub_rede, &no).unwrap().is_some() {
                com_chave += 1;
            }
        }
    }
    assert_eq!(com_chave, 13);
    // Os nós de outra sub-rede não estão nela.
    assert_eq!(nos_com_chave(&cert, &principal(SUB_REDE_DO_IVG37)), 0);
}

#[test]
fn a_raiz_de_outra_rede_recusa_a_rede_principal() {
    let outra = raiz(&chave_bls(1));
    for (corpo, canister, tempo) in [
        (IVG37, CANISTER_IVG37, TEMPO_DO_IVG37),
        (SUB_REDE_224OD, CANISTER_224OD, TEMPO_DO_224OD),
    ] {
        let d = doc(corpo);
        let cert = Certificado::ler(&d).unwrap();
        assert_eq!(
            verificar(&cert, &outra, &principal(canister), tempo),
            Err(Erro::AssinaturaDaDelegacao)
        );
        assert!(!oraculo(&d, canister, &outra, tempo));
    }
}

/// Um bit trocado em qualquer parte que se assina: na assinatura da
/// sub-rede, na da raiz sobre a delegação, no tempo, e na chave de um nó.
#[test]
fn um_bit_trocado_na_rede_principal_e_recusado() {
    let raiz = raiz_da_rede_principal();
    let d = doc(SUB_REDE_224OD);
    let cert = Certificado::ler(&d).unwrap();
    let delegacao = cert.delegacao.unwrap();
    let da_delegacao = Certificado::ler(delegacao.certificado).unwrap();
    let Procura::Achou(tempo) = cert.arvore.procurar(&[b"time"]) else {
        panic!("sem o tempo");
    };
    let sub_rede = principal(SUB_REDE_DO_224OD);
    let Sub::Achou(nos) = cert
        .arvore
        .subarvore(&[b"subnet", sub_rede.bytes(), b"node"])
    else {
        panic!("sem os nos");
    };
    let Some(Arvore::Rotulada(primeiro, _)) = nos.floresta().into_iter().next() else {
        panic!("sem um no");
    };
    let no = Principal::de_bytes(primeiro).unwrap();
    let Procura::Achou(chave_do_no) = cert.arvore.procurar(&[
        b"subnet",
        sub_rede.bytes(),
        b"node",
        no.bytes(),
        b"public_key",
    ]) else {
        panic!("sem a chave do no");
    };

    let casos = [
        (posicao(&d, cert.assinatura) + 10, Erro::Assinatura),
        (
            posicao(&d, da_delegacao.assinatura) + 10,
            Erro::AssinaturaDaDelegacao,
        ),
        // O bit de baixo do primeiro byte do LEB128: o tempo anda 1 ns, e a
        // árvore muda.
        (posicao(&d, tempo), Erro::Assinatura),
        (posicao(&d, chave_do_no) + 20, Erro::Assinatura),
    ];
    for (i, esperado) in casos {
        let mexido = trocado(&d, i);
        assert_eq!(
            conferir(&mexido, CANISTER_224OD, TEMPO_DO_224OD),
            Err(esperado),
            "byte {i}"
        );
        assert!(!oraculo(&mexido, CANISTER_224OD, &raiz, TEMPO_DO_224OD));
    }
}

/// O certificado de um canister não vale para outro: a sub-rede que
/// assinou só fala pelos canisters das faixas dela — o lado de quem
/// serviria a resposta certa para o canister errado.
#[test]
fn o_canister_de_outra_sub_rede_e_recusado() {
    let raiz = raiz_da_rede_principal();
    for (corpo, outro, tempo) in [
        (IVG37, LIVRO_RAZAO, TEMPO_DO_IVG37),
        (IVG37, CANISTER_224OD, TEMPO_DO_IVG37),
        (SUB_REDE_224OD, CANISTER_IVG37, TEMPO_DO_224OD),
        (SUB_REDE_224OD, LIVRO_RAZAO, TEMPO_DO_224OD),
    ] {
        let d = doc(corpo);
        assert_eq!(conferir(&d, outro, tempo), Err(Erro::ForaDasFaixas));
        assert!(!oraculo(&d, outro, &raiz, tempo));
    }
}

/// A janela de [`TOLERANCIA_NS`] em volta da hora de quem confere: dentro
/// vale, fora não — para trás e para a frente.
#[test]
fn a_rede_principal_fora_da_hora_e_recusada() {
    let d = doc(IVG37);
    let t = TEMPO_DO_IVG37;
    assert!(conferir(&d, CANISTER_IVG37, t + TOLERANCIA_NS).is_ok());
    assert!(conferir(&d, CANISTER_IVG37, t - TOLERANCIA_NS).is_ok());
    assert_eq!(
        conferir(&d, CANISTER_IVG37, t + TOLERANCIA_NS + 1),
        Err(Erro::Velho {
            tempo_ns: t,
            agora_ns: t + TOLERANCIA_NS + 1
        })
    );
    assert_eq!(
        conferir(&d, CANISTER_IVG37, t - TOLERANCIA_NS - 1),
        Err(Erro::Futuro {
            tempo_ns: t,
            agora_ns: t - TOLERANCIA_NS - 1
        })
    );
}

/// As faixas: as podadas não provam o canister, e a forma antiga da
/// `/api/v2`, que as implementações oficiais ainda aceitam, não vale aqui
/// — ver o cabeçalho do módulo.
#[test]
fn as_faixas_podadas_e_a_forma_antiga_sao_recusadas() {
    let podado = doc(IVG37_PODADO);
    assert_eq!(
        conferir(&podado, CANISTER_IVG37, TEMPO_DO_IVG37),
        Err(Erro::FaixasAusentes)
    );

    let antiga = doc(IVG37_V2);
    let tempo = Certificado::ler(&antiga).unwrap().tempo_ns().unwrap();
    assert_eq!(
        conferir(&antiga, CANISTER_IVG37, tempo),
        Err(Erro::FaixasAusentes)
    );
    // O oráculo aceita a forma antiga: o lado que recusa é este.
    assert!(oraculo(
        &antiga,
        CANISTER_IVG37,
        &raiz_da_rede_principal(),
        tempo
    ));
}

/// O certificado real usado como a própria delegação: a delegação passa a
/// ter outra dentro, e um nível só é o que se aceita — como no teste
/// `too_many_delegations` do `ic-agent`, que faz o mesmo com a rede
/// principal.
#[test]
fn a_delegacao_aninhada_na_rede_principal_e_recusada() {
    let d = doc(IVG37);
    let real: ic_certification::Certificate = serde_cbor::from_slice(&d).unwrap();
    let aninhado = ic_certification::Certificate {
        tree: real.tree.clone(),
        signature: real.signature.clone(),
        delegation: Some(ic_certification::Delegation {
            subnet_id: principal(SUB_REDE_DO_IVG37).bytes().to_vec(),
            certificate: serde_cbor::to_vec(&real).unwrap(),
        }),
    };
    let mexido = serde_cbor::to_vec(&aninhado).unwrap();
    assert_eq!(
        conferir(&mexido, CANISTER_IVG37, TEMPO_DO_IVG37),
        Err(Erro::DelegacaoAninhada)
    );
    assert!(!oraculo(
        &mexido,
        CANISTER_IVG37,
        &raiz_da_rede_principal(),
        TEMPO_DO_IVG37
    ));
}

/// Quanto custa, no hospedeiro, verificar um certificado de verdade da rede
/// principal: o da leitura da sub-rede do `224od`, delegado — duas
/// assinaturas BLS, a da raiz sobre a delegação e a da sub-rede sobre a
/// árvore —, com as chaves das 47 sub-redes e os 13 nós dela; e o do
/// `ivg37`, menor. Só sob demanda, sem depuração:
/// `cargo test -p web3 --release -- --ignored --nocapture medida`.
#[test]
#[ignore = "medida: --ignored --nocapture, em --release"]
fn medida_da_rede_principal_no_hospedeiro() {
    const VOLTAS: usize = 50;
    for (nome, corpo, canister, tempo) in [
        ("224od", SUB_REDE_224OD, CANISTER_224OD, TEMPO_DO_224OD),
        ("ivg37", IVG37, CANISTER_IVG37, TEMPO_DO_IVG37),
    ] {
        let d = doc(corpo);
        let mut tempos: Vec<std::time::Duration> = (0..VOLTAS)
            .map(|_| {
                let inicio = std::time::Instant::now();
                let r = conferir(&d, canister, tempo);
                let gasto = inicio.elapsed();
                assert!(r.is_ok(), "a volta nao verificou");
                gasto
            })
            .collect();
        tempos.sort_unstable();
        std::println!(
            "medida: {VOLTAS} certificados do {nome} ({} bytes) verificados no hospedeiro: mediana {:?}, de {:?} a {:?}",
            d.len(),
            tempos[VOLTAS / 2],
            tempos[0],
            tempos[VOLTAS - 1]
        );
    }
}
