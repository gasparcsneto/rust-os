//! O certificado contra a bancada e contra o `ic-certificate-verification`.

use std::string::ToString;
use std::vec;
use std::vec::Vec;

use ic_certificate_verification::VerifyCertificate;

use super::*;
use crate::icp::MINUTO_NS;
use crate::icp::bancada::{
    self, AGORA_NS, Folha, Ic, arvore, caminho, certificado_assinado, chave_bls, der_bls, faixas,
    nat,
};

/// O oráculo: o `ic-certificate-verification`, com a mesma tolerância.
fn oraculo(doc: &[u8], canister: &Principal, raiz: &Raiz, agora_ns: u64) -> bool {
    let Ok(cert) = serde_cbor::from_slice::<ic_certification::Certificate>(doc) else {
        return false;
    };
    cert.verify(
        canister.bytes(),
        raiz.der(),
        &u128::from(agora_ns),
        &u128::from(TOLERANCIA_NS),
    )
    .is_ok()
}

fn verificar_doc(doc: &[u8], ic: &Ic, agora_ns: u64) -> Result<Autoridade, Erro> {
    let cert = Certificado::ler(doc)?;
    verificar(&cert, &ic.raiz_de_confianca(), &ic.canister, agora_ns)
}

/// O certificado da bancada com as folhas de fora e as da delegação
/// trocadas.
fn com(
    ic: &Ic,
    fora: Vec<Folha>,
    chave_de_fora: &ic_verify_bls_signature::PrivateKey,
    delegacao: Option<(Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    certificado_assinado(
        arvore(&fora),
        chave_de_fora,
        delegacao.or_else(|| Some((ic.id_da_sub_rede.bytes().to_vec(), ic.delegacao(AGORA_NS)))),
    )
}

#[test]
fn o_certificado_delegado_vale() {
    let ic = Ic::novo();
    let doc = ic.certificado(AGORA_NS);
    let autoridade = verificar_doc(&doc, &ic, AGORA_NS).unwrap();
    assert_eq!(
        autoridade,
        Autoridade {
            sub_rede: ic.id_da_sub_rede,
            delegada: true,
            tempo_ns: AGORA_NS,
        }
    );
    assert!(oraculo(
        &doc,
        &ic.canister,
        &ic.raiz_de_confianca(),
        AGORA_NS
    ));
    // Sem a tag na frente, também: as implementações oficiais a aceitam
    // ausente.
    assert_eq!(&doc[..3], &[0xd9, 0xd9, 0xf7]);
    assert!(verificar_doc(&doc[3..], &ic, AGORA_NS).is_ok());
}

#[test]
fn o_certificado_da_raiz_vale_com_as_faixas_da_raiz() {
    let ic = Ic::novo();
    let id_raiz = ic.raiz_de_confianca().sub_rede();
    assert_eq!(id_raiz, Principal::auto_autenticado(&der_bls(&ic.raiz)));
    let canister = Principal::de_bytes(&[0, 0, 0, 0, 0, 0, 0, 7, 1, 1]).unwrap();
    let baixo = Principal::de_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]).unwrap();
    let alto = Principal::de_bytes(&[0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1]).unwrap();
    let folhas = vec![
        (
            caminho(&[b"subnet", id_raiz.bytes(), b"canister_ranges"]),
            faixas(&[(baixo, alto)]),
        ),
        (
            caminho(&[b"subnet", id_raiz.bytes(), b"public_key"]),
            der_bls(&ic.raiz),
        ),
        (caminho(&[b"time"]), nat(AGORA_NS)),
    ];
    let doc = certificado_assinado(arvore(&folhas), &ic.raiz, None);
    let cert = Certificado::ler(&doc).unwrap();
    let raiz = ic.raiz_de_confianca();
    let autoridade = verificar(&cert, &raiz, &canister, AGORA_NS).unwrap();
    assert_eq!(autoridade.sub_rede, id_raiz);
    assert!(!autoridade.delegada);
    assert!(oraculo(&doc, &canister, &raiz, AGORA_NS));
    // Um canister fora das faixas da raiz: recusado aqui. O oráculo não
    // confere faixa sem delegação — a especificação confere
    // (`verify_response`), e este lado segue a especificação.
    let fora = Principal::de_bytes(&[0, 0, 0, 0, 0, 1, 0, 0, 1, 1]).unwrap();
    assert_eq!(
        verificar(&cert, &raiz, &fora, AGORA_NS),
        Err(Erro::ForaDasFaixas)
    );
    assert!(oraculo(&doc, &fora, &raiz, AGORA_NS));
    // Sem as faixas da raiz no certificado: recusado.
    let sem_faixas = certificado_assinado(arvore(&folhas[1..]), &ic.raiz, None);
    let cert = Certificado::ler(&sem_faixas).unwrap();
    assert_eq!(
        verificar(&cert, &raiz, &canister, AGORA_NS),
        Err(Erro::FaixasAusentes)
    );
}

#[test]
fn a_assinatura_errada_e_recusada() {
    let ic = Ic::novo();
    // Assinado por outra chave que não a da sub-rede.
    let doc = com(&ic, ic.folhas_da_sub_rede(AGORA_NS), &chave_bls(9), None);
    assert_eq!(verificar_doc(&doc, &ic, AGORA_NS), Err(Erro::Assinatura));
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &ic.raiz_de_confianca(),
        AGORA_NS
    ));
    // A árvore mexida depois de assinada: a raiz é outra.
    let mut folhas = ic.folhas_da_sub_rede(AGORA_NS);
    let assinatura = bancada::assinar(&ic.sub_rede, &arvore(&folhas));
    folhas[0].1.push(0);
    let doc = bancada::certificado(
        arvore(&folhas),
        assinatura,
        Some((ic.id_da_sub_rede.bytes().to_vec(), ic.delegacao(AGORA_NS))),
    );
    assert_eq!(verificar_doc(&doc, &ic, AGORA_NS), Err(Erro::Assinatura));
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &ic.raiz_de_confianca(),
        AGORA_NS
    ));
    // Uma assinatura que nem é um ponto, ou do tamanho errado.
    for assinatura in [vec![0u8; 48], vec![0xffu8; 48], vec![1u8; 47], vec![]] {
        let doc = bancada::certificado(
            arvore(&ic.folhas_da_sub_rede(AGORA_NS)),
            assinatura,
            Some((ic.id_da_sub_rede.bytes().to_vec(), ic.delegacao(AGORA_NS))),
        );
        assert_eq!(verificar_doc(&doc, &ic, AGORA_NS), Err(Erro::Assinatura));
    }
}

#[test]
fn outra_raiz_e_recusada() {
    let ic = Ic::novo();
    let doc = ic.certificado(AGORA_NS);
    let cert = Certificado::ler(&doc).unwrap();
    let outra = bancada::raiz(&chave_bls(7));
    assert_eq!(
        verificar(&cert, &outra, &ic.canister, AGORA_NS),
        Err(Erro::AssinaturaDaDelegacao)
    );
    assert!(!oraculo(&doc, &ic.canister, &outra, AGORA_NS));
    // Uma delegação assinada por outra raiz.
    let delegacao = certificado_assinado(
        arvore(&ic.folhas_da_delegacao(AGORA_NS)),
        &chave_bls(7),
        None,
    );
    let doc = com(
        &ic,
        ic.folhas_da_sub_rede(AGORA_NS),
        &ic.sub_rede,
        Some((ic.id_da_sub_rede.bytes().to_vec(), delegacao)),
    );
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS),
        Err(Erro::AssinaturaDaDelegacao)
    );
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &ic.raiz_de_confianca(),
        AGORA_NS
    ));
}

#[test]
fn a_delegacao_aninhada_e_recusada() {
    let ic = Ic::novo();
    // A delegação traz, ela mesma, uma delegação — tudo assinado como se
    // valesse.
    let aninhada = certificado_assinado(
        arvore(&ic.folhas_da_delegacao(AGORA_NS)),
        &ic.raiz,
        Some((ic.id_da_sub_rede.bytes().to_vec(), ic.delegacao(AGORA_NS))),
    );
    let doc = com(
        &ic,
        ic.folhas_da_sub_rede(AGORA_NS),
        &ic.sub_rede,
        Some((ic.id_da_sub_rede.bytes().to_vec(), aninhada)),
    );
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS),
        Err(Erro::DelegacaoAninhada)
    );
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &ic.raiz_de_confianca(),
        AGORA_NS
    ));
}

#[test]
fn as_faixas_da_delegacao() {
    let ic = Ic::novo();
    let raiz = ic.raiz_de_confianca();
    let doc = ic.certificado(AGORA_NS);
    let cert = Certificado::ler(&doc).unwrap();
    // As bordas da faixa valem; um a mais, não.
    let (baixo, alto) = ic.faixas[0];
    assert!(verificar(&cert, &raiz, &baixo, AGORA_NS).is_ok());
    assert!(verificar(&cert, &raiz, &alto, AGORA_NS).is_ok());
    let depois = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x20, 0, 0, 1, 1]).unwrap();
    assert_eq!(
        verificar(&cert, &raiz, &depois, AGORA_NS),
        Err(Erro::ForaDasFaixas)
    );
    assert!(!oraculo(&doc, &depois, &raiz, AGORA_NS));
    let antes = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x0f, 0xff, 0xff, 1, 1]).unwrap();
    assert_eq!(
        verificar(&cert, &raiz, &antes, AGORA_NS),
        Err(Erro::ForaDasFaixas)
    );
}

fn delegacao_com(ic: &Ic, folhas: Vec<Folha>) -> Vec<u8> {
    com(
        ic,
        ic.folhas_da_sub_rede(AGORA_NS),
        &ic.sub_rede,
        Some((
            ic.id_da_sub_rede.bytes().to_vec(),
            certificado_assinado(arvore(&folhas), &ic.raiz, None),
        )),
    )
}

#[test]
fn a_delegacao_sem_faixas_ou_so_na_forma_antiga() {
    let ic = Ic::novo();
    let raiz = ic.raiz_de_confianca();
    let mut folhas = ic.folhas_da_delegacao(AGORA_NS);
    let fragmentos = folhas.remove(0);
    // Sem faixas: recusado.
    let doc = delegacao_com(&ic, folhas.clone());
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS),
        Err(Erro::FaixasAusentes)
    );
    assert!(!oraculo(&doc, &ic.canister, &raiz, AGORA_NS));
    // Só a forma antiga, `/subnet/<id>/canister_ranges`, que a v3 não
    // usa: recusada aqui. O oráculo ainda aceita, por compatibilidade.
    let mut antigas = folhas.clone();
    antigas.push((
        caminho(&[b"subnet", ic.id_da_sub_rede.bytes(), b"canister_ranges"]),
        fragmentos.1.clone(),
    ));
    let doc = delegacao_com(&ic, antigas);
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS),
        Err(Erro::FaixasAusentes)
    );
    assert!(oraculo(&doc, &ic.canister, &raiz, AGORA_NS));
    // Várias faixas em vários fragmentos: o canister está num deles.
    let id = ic.id_da_sub_rede.bytes();
    let p = |b: u8| Principal::de_bytes(&[0, 0, 0, 0, 0, b, 0, 0, 1, 1]).unwrap();
    let mut varias = folhas.clone();
    varias.push((
        caminho(&[b"canister_ranges", id, p(0x01).bytes()]),
        faixas(&[(p(0x01), p(0x02)), (p(0x05), p(0x06))]),
    ));
    varias.push((
        caminho(&[b"canister_ranges", id, p(0x10).bytes()]),
        faixas(&[(p(0x10), p(0x1f))]),
    ));
    let doc = delegacao_com(&ic, varias);
    assert!(verificar_doc(&doc, &ic, AGORA_NS).is_ok());
    assert!(oraculo(&doc, &ic.canister, &raiz, AGORA_NS));
    // Faixas fora da forma.
    for ruim in [
        bancada::cbor(&5u8),
        bancada::cbor(&vec![vec![serde_bytes::ByteBuf::from(vec![1u8])]]),
        bancada::cbor(&vec![(
            serde_bytes::ByteBuf::from(vec![0u8; 30]),
            serde_bytes::ByteBuf::from(vec![1u8]),
        )]),
        vec![0xff],
    ] {
        let mut f = folhas.clone();
        f.push((
            caminho(&[b"canister_ranges", id, ic.faixas[0].0.bytes()]),
            ruim,
        ));
        let doc = delegacao_com(&ic, f);
        assert_eq!(
            verificar_doc(&doc, &ic, AGORA_NS),
            Err(Erro::FaixasForaDaForma)
        );
    }
}

#[test]
fn as_faixas_exigem_as_duas_ordens() {
    // Um canister de 11 bytes, dentro da faixa de 10 pela ordem
    // lexicográfica (a da especificação) e fora dela pela do
    // `ic_principal` (o tamanho primeiro): recusado.
    let baixo = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x10, 0, 0, 1, 1]).unwrap();
    let alto = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x1f, 0xff, 0xff, 1, 1]).unwrap();
    let longo = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x11, 0, 0, 1, 1, 0]).unwrap();
    assert!(baixo < longo && longo < alto);
    assert!(longo.ordem_oficial(&alto).is_gt());
    let lista = faixas(&[(baixo, alto)]);
    assert_eq!(faixas_contem(&lista, &longo), Ok(false));
    // E um curto que a ordem oficial põe dentro e a lexicográfica fora.
    let b2 = Principal::de_bytes(&[5]).unwrap();
    let a2 = Principal::de_bytes(&[1, 0]).unwrap();
    let curto = Principal::de_bytes(&[9]).unwrap();
    assert!(b2.ordem_oficial(&curto).is_le() && curto.ordem_oficial(&a2).is_le());
    assert!(curto > a2);
    assert_eq!(faixas_contem(&faixas(&[(b2, a2)]), &curto), Ok(false));
    // Do mesmo tamanho, as duas concordam.
    let meio = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x11, 0, 0, 1, 1]).unwrap();
    assert_eq!(faixas_contem(&lista, &meio), Ok(true));
}

#[test]
fn a_delegacao_sem_a_chave_da_sub_rede() {
    let ic = Ic::novo();
    let mut folhas = ic.folhas_da_delegacao(AGORA_NS);
    folhas.retain(|(c, _)| c.last().map(|r| &r[..]) != Some(b"public_key"));
    let doc = delegacao_com(&ic, folhas);
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS),
        Err(Erro::ChaveDaSubRedeAusente)
    );
    // A delegação para uma sub-rede que não é a do certificado dela.
    let doc = com(
        &ic,
        ic.folhas_da_sub_rede(AGORA_NS),
        &ic.sub_rede,
        Some((vec![1, 2, 3], ic.delegacao(AGORA_NS))),
    );
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS),
        Err(Erro::ChaveDaSubRedeAusente)
    );
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &ic.raiz_de_confianca(),
        AGORA_NS
    ));
    // A chave da sub-rede fora da forma DER.
    let mut folhas = ic.folhas_da_delegacao(AGORA_NS);
    for (c, v) in &mut folhas {
        if c.last().map(|r| &r[..]) == Some(b"public_key") {
            v[0] ^= 1;
        }
    }
    let doc = delegacao_com(&ic, folhas);
    assert_eq!(verificar_doc(&doc, &ic, AGORA_NS), Err(Erro::ChaveDer));
}

#[test]
fn o_tempo() {
    let ic = Ic::novo();
    // Na borda da tolerância, vale; um nanossegundo além, não.
    let doc = ic.certificado(AGORA_NS);
    assert!(verificar_doc(&doc, &ic, AGORA_NS + TOLERANCIA_NS).is_ok());
    assert!(verificar_doc(&doc, &ic, AGORA_NS - TOLERANCIA_NS).is_ok());
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS + TOLERANCIA_NS + 1),
        Err(Erro::Velho {
            tempo_ns: AGORA_NS,
            agora_ns: AGORA_NS + TOLERANCIA_NS + 1
        })
    );
    assert_eq!(
        verificar_doc(&doc, &ic, AGORA_NS - TOLERANCIA_NS - 1),
        Err(Erro::Futuro {
            tempo_ns: AGORA_NS,
            agora_ns: AGORA_NS - TOLERANCIA_NS - 1
        })
    );
    let raiz = ic.raiz_de_confianca();
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &raiz,
        AGORA_NS + 6 * MINUTO_NS
    ));
    assert!(!oraculo(
        &doc,
        &ic.canister,
        &raiz,
        AGORA_NS - 6 * MINUTO_NS
    ));
    // O tempo da delegação não conta: a de um mês atrás vale, como nas
    // implementações oficiais.
    let mes = 30 * 24 * 60 * MINUTO_NS;
    let doc = com(
        &ic,
        ic.folhas_da_sub_rede(AGORA_NS),
        &ic.sub_rede,
        Some((
            ic.id_da_sub_rede.bytes().to_vec(),
            ic.delegacao(AGORA_NS - mes),
        )),
    );
    assert!(verificar_doc(&doc, &ic, AGORA_NS).is_ok());
    assert!(oraculo(&doc, &ic.canister, &raiz, AGORA_NS));
    // Sem /time, e com um /time fora da forma.
    let mut sem = ic.folhas_da_sub_rede(AGORA_NS);
    sem.retain(|(c, _)| c[0] != b"time");
    let doc = com(&ic, sem.clone(), &ic.sub_rede, None);
    assert_eq!(verificar_doc(&doc, &ic, AGORA_NS), Err(Erro::SemTempo));
    for ruim in [vec![], vec![0x80], vec![0xff; 11], vec![0x00, 0x00]] {
        let mut f = sem.clone();
        f.push((caminho(&[b"time"]), ruim));
        let doc = com(&ic, f, &ic.sub_rede, None);
        assert_eq!(
            verificar_doc(&doc, &ic, AGORA_NS),
            Err(Erro::TempoForaDaForma)
        );
    }
}

#[test]
fn o_certificado_fora_da_forma() {
    let ic = Ic::novo();
    assert!(matches!(Certificado::ler(&[0xff]), Err(Erro::Cbor(_))));
    assert_eq!(Certificado::ler(&bancada::cbor(&5u8)), Err(Erro::Forma));
    #[derive(serde::Serialize)]
    struct SoArvore {
        tree: ic_certification::hash_tree::HashTree<Vec<u8>>,
    }
    let doc = bancada::cbor(&SoArvore {
        tree: arvore(&ic.folhas_da_sub_rede(AGORA_NS)),
    });
    assert_eq!(Certificado::ler(&doc), Err(Erro::Forma));
    #[derive(serde::Serialize)]
    struct SoAssinatura {
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    }
    let doc = bancada::cbor(&SoAssinatura {
        signature: vec![0; 48],
    });
    assert_eq!(Certificado::ler(&doc), Err(Erro::Forma));
    // Uma delegação sem o certificado, ou com um sub-rede longo demais.
    #[derive(serde::Serialize)]
    struct Delegacao {
        #[serde(with = "serde_bytes")]
        subnet_id: Vec<u8>,
    }
    #[derive(serde::Serialize)]
    struct ComDelegacao {
        tree: ic_certification::hash_tree::HashTree<Vec<u8>>,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
        delegation: Delegacao,
    }
    let doc = bancada::cbor(&ComDelegacao {
        tree: arvore(&ic.folhas_da_sub_rede(AGORA_NS)),
        signature: vec![0; 48],
        delegation: Delegacao { subnet_id: vec![1] },
    });
    assert_eq!(Certificado::ler(&doc), Err(Erro::Forma));
}

#[test]
fn as_chaves_dos_nos() {
    let ic = Ic::novo();
    let doc = ic.certificado(AGORA_NS);
    let cert = Certificado::ler(&doc).unwrap();
    assert_eq!(nos_com_chave(&cert, &ic.id_da_sub_rede), ic.nos.len());
    for (no, chave) in &ic.nos {
        assert_eq!(
            chave_do_no(&cert, &ic.id_da_sub_rede, no),
            Ok(Some(*chave.verifying_key().as_bytes()))
        );
    }
    // Um nó que o certificado não mostra, ou o mesmo nó noutra sub-rede.
    let estranho = Principal::de_bytes(&[9; 29]).unwrap();
    assert_eq!(chave_do_no(&cert, &ic.id_da_sub_rede, &estranho), Ok(None));
    let raiz = ic.raiz_de_confianca().sub_rede();
    assert_eq!(chave_do_no(&cert, &raiz, &ic.nos[0].0), Ok(None));
    assert_eq!(nos_com_chave(&cert, &raiz), 0);
    // A chave de um nó fora da forma DER.
    let mut folhas = ic.folhas_da_sub_rede(AGORA_NS);
    for (c, v) in &mut folhas {
        if c.len() == 5 {
            v.pop();
        }
    }
    let doc = com(&ic, folhas, &ic.sub_rede, None);
    let cert = Certificado::ler(&doc).unwrap();
    assert_eq!(
        chave_do_no(&cert, &ic.id_da_sub_rede, &ic.nos[0].0),
        Err(Erro::ChaveDoNo)
    );
}

#[test]
fn a_chave_no_infinito_e_o_ponto_invalido() {
    // O infinito comprimido: 0xc0 e zeros. Com ele, a assinatura no
    // infinito conferiria tudo — a conta da `ic-verify-bls-signature`
    // aceita, e por isso a chave é recusada antes.
    let mut der = Vec::from(PREFIXO_DER_BLS);
    let mut infinito = [0u8; CHAVE_BLS];
    infinito[0] = 0xc0;
    der.extend_from_slice(&infinito);
    let mut assinatura_no_infinito = [0u8; 48];
    assinatura_no_infinito[0] = 0xc0;
    assert!(
        ic_verify_bls_signature::verify_bls_signature(
            &assinatura_no_infinito,
            b"qualquer",
            &infinito
        )
        .is_ok()
    );
    assert_eq!(extrair_der(&der), Err(Erro::ChaveDer));
    assert_eq!(Raiz::de_der(&der), Err(Erro::ChaveDer));
    // Uma chave que não é ponto da curva.
    let mut der = Vec::from(PREFIXO_DER_BLS);
    let mut torta = [0x8au8; CHAVE_BLS];
    torta[0] = 0x9f;
    der.extend_from_slice(&torta);
    assert!(extrair_der(&der).is_ok());
    assert_eq!(Raiz::de_der(&der), Err(Erro::ChaveDer));
    // Uma delegação que traz a chave da sub-rede no infinito.
    let ic = Ic::novo();
    let mut folhas = ic.folhas_da_delegacao(AGORA_NS);
    for (c, v) in &mut folhas {
        if c.last().map(|r| &r[..]) == Some(b"public_key") {
            let mut der = Vec::from(PREFIXO_DER_BLS);
            der.extend_from_slice(&infinito);
            *v = der;
        }
    }
    let doc = delegacao_com(&ic, folhas);
    assert_eq!(verificar_doc(&doc, &ic, AGORA_NS), Err(Erro::ChaveDer));
}

#[test]
fn o_leb128_do_tempo() {
    assert_eq!(ler_leb128(&[0x00]), Some(0));
    assert_eq!(ler_leb128(&[0x80, 0x01]), Some(128));
    assert_eq!(ler_leb128(&nat(AGORA_NS)), Some(AGORA_NS));
    assert_eq!(ler_leb128(&nat(u64::MAX)), Some(u64::MAX));
    assert_eq!(ler_leb128(&[]), None);
    assert_eq!(ler_leb128(&[0x80]), None);
    assert_eq!(ler_leb128(&[0x00, 0x00]), None);
    // Onze bytes, ou o décimo com mais que o bit que cabe.
    assert_eq!(
        ler_leb128(&[0x80; 10].iter().copied().chain([0x01]).collect::<Vec<_>>()),
        None
    );
    let mut dez = vec![0xffu8; 9];
    dez.push(0x02);
    assert_eq!(ler_leb128(&dez), None);
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::Forma,
        Erro::DelegacaoAninhada,
        Erro::AssinaturaDaDelegacao,
        Erro::ChaveDaSubRedeAusente,
        Erro::ChaveDer,
        Erro::Assinatura,
        Erro::SemTempo,
        Erro::TempoForaDaForma,
        Erro::Velho {
            tempo_ns: 0,
            agora_ns: TOLERANCIA_NS * 2,
        },
        Erro::Futuro {
            tempo_ns: TOLERANCIA_NS * 2,
            agora_ns: 0,
        },
        Erro::FaixasAusentes,
        Erro::FaixasForaDaForma,
        Erro::ForaDasFaixas,
        Erro::ChaveDoNo,
        Erro::Cbor(cbor::Erro::Sobra),
        Erro::Arvore(arvore::Erro::Forma),
    ] {
        assert!(e.to_string().is_ascii(), "{e}");
    }
    assert!(
        Erro::Velho {
            tempo_ns: 0,
            agora_ns: 10 * MINUTO_NS
        }
        .to_string()
        .contains("600 s")
    );
}
