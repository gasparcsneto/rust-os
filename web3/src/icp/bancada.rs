//! A bancada dos testes: chaves, árvores, certificados e respostas de um
//! IC de mentira, montados com as bibliotecas oficiais — a árvore pelo
//! `ic-certification`, a assinatura BLS pela `ic-verify-bls-signature`, o
//! que um nó assina pelo `ic-transport-types` e a assinatura do nó pelo
//! `ed25519-dalek`. O que este pacote lê, a bancada escreve com o código
//! de lá.

use std::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use ic_certification::hash_tree::{HashTree, empty, fork, label, leaf};
use ic_certification::{Certificate, Delegation};
use ic_verify_bls_signature::PrivateKey;
use serde::Serialize;

use super::certificado::{PREFIXO_DER_BLS, PREFIXO_DER_ED25519, Raiz, SEPARADOR_DA_RAIZ};
use super::principal::Principal;

/// 2026-10-19T00:00:00Z, em nanossegundos.
pub const AGORA_NS: u64 = 1_792_368_000 * 1_000_000_000;

/// Uma chave BLS de teste, de uma semente.
pub fn chave_bls(semente: u8) -> PrivateKey {
    let mut b = [0x5au8; 32];
    b[0] = 0;
    b[1] = semente;
    PrivateKey::deserialize(&b).unwrap()
}

/// A chave pública BLS em DER.
pub fn der_bls(chave: &PrivateKey) -> Vec<u8> {
    let mut der = Vec::from(PREFIXO_DER_BLS);
    der.extend_from_slice(&chave.public_key().serialize());
    der
}

/// A raiz de confiança de uma chave.
pub fn raiz(chave: &PrivateKey) -> Raiz {
    Raiz::de_der(&der_bls(chave)).unwrap()
}

/// Uma chave Ed25519 de nó, de uma semente.
pub fn chave_de_no(semente: u8) -> SigningKey {
    SigningKey::from_bytes(&[semente; 32])
}

/// A chave pública Ed25519 em DER, como o IC a guarda.
pub fn der_ed25519(chave: &SigningKey) -> Vec<u8> {
    let mut der = Vec::from(PREFIXO_DER_ED25519);
    der.extend_from_slice(chave.verifying_key().as_bytes());
    der
}

/// Um número natural como o IC o põe numa folha: LEB128.
pub fn nat(mut n: u64) -> Vec<u8> {
    let mut saida = Vec::new();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            saida.push(b);
            return saida;
        }
        saida.push(b | 0x80);
    }
}

/// CBOR com a tag 55799 na frente, como o IC escreve.
pub fn cbor<T: Serialize>(valor: &T) -> Vec<u8> {
    let mut s = serde_cbor::Serializer::new(Vec::new());
    s.self_describe().unwrap();
    valor.serialize(&mut s).unwrap();
    s.into_inner()
}

/// Faixas de canister: `55799([[baixo, alto], …])`.
pub fn faixas(f: &[(Principal, Principal)]) -> Vec<u8> {
    let pares: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf)> = f
        .iter()
        .map(|(a, b)| {
            (
                serde_bytes::ByteBuf::from(a.bytes().to_vec()),
                serde_bytes::ByteBuf::from(b.bytes().to_vec()),
            )
        })
        .collect();
    cbor(&pares)
}

/// Uma folha: o caminho e o valor.
pub type Folha = (Vec<Vec<u8>>, Vec<u8>);

/// Um caminho de rótulos.
pub fn caminho(rotulos: &[&[u8]]) -> Vec<Vec<u8>> {
    rotulos.iter().map(|r| r.to_vec()).collect()
}

/// A árvore de hash de um conjunto de folhas, bem formada e com as
/// bifurcações equilibradas, como o IC monta.
pub fn arvore(folhas: &[Folha]) -> HashTree<Vec<u8>> {
    construir(folhas.to_vec())
}

fn construir(mut itens: Vec<Folha>) -> HashTree<Vec<u8>> {
    if itens.len() == 1 && itens[0].0.is_empty() {
        return leaf(itens.pop().unwrap().1);
    }
    itens.sort_by(|a, b| a.0[0].cmp(&b.0[0]));
    let mut filhos = Vec::new();
    let mut i = 0;
    while i < itens.len() {
        let rotulo = itens[i].0[0].clone();
        let mut grupo = Vec::new();
        while i < itens.len() && itens[i].0[0] == rotulo {
            grupo.push((itens[i].0[1..].to_vec(), itens[i].1.clone()));
            i += 1;
        }
        filhos.push(label(rotulo, construir(grupo)));
    }
    bifurcar(filhos)
}

/// As árvores, unidas por bifurcações equilibradas.
pub fn bifurcar(mut filhos: Vec<HashTree<Vec<u8>>>) -> HashTree<Vec<u8>> {
    match filhos.len() {
        0 => empty(),
        1 => filhos.pop().unwrap(),
        n => {
            let direita = filhos.split_off(n / 2);
            fork(bifurcar(filhos), bifurcar(direita))
        }
    }
}

/// A assinatura BLS da raiz de uma árvore.
pub fn assinar(chave: &PrivateKey, arvore: &HashTree<Vec<u8>>) -> Vec<u8> {
    let mut mensagem = Vec::from(&SEPARADOR_DA_RAIZ[..]);
    mensagem.extend_from_slice(&arvore.digest());
    chave.sign(&mensagem).serialize().to_vec()
}

/// Um certificado em CBOR.
pub fn certificado(
    arvore: HashTree<Vec<u8>>,
    assinatura: Vec<u8>,
    delegacao: Option<(Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    cbor(&Certificate {
        tree: arvore,
        signature: assinatura,
        delegation: delegacao.map(|(subnet_id, certificate)| Delegation {
            subnet_id,
            certificate,
        }),
    })
}

/// Um certificado assinado com a chave.
pub fn certificado_assinado(
    arvore: HashTree<Vec<u8>>,
    chave: &PrivateKey,
    delegacao: Option<(Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    let assinatura = assinar(chave, &arvore);
    certificado(arvore, assinatura, delegacao)
}

/// Um IC de mentira: a raiz, uma sub-rede de aplicação com delegação, os
/// nós dela e um canister nas faixas dela.
pub struct Ic {
    /// A chave da sub-rede raiz.
    pub raiz: PrivateKey,
    /// A chave da sub-rede de aplicação.
    pub sub_rede: PrivateKey,
    /// O id da sub-rede de aplicação.
    pub id_da_sub_rede: Principal,
    /// Os nós da sub-rede, com as chaves.
    pub nos: Vec<(Principal, SigningKey)>,
    /// As faixas da sub-rede, num fragmento só.
    pub faixas: Vec<(Principal, Principal)>,
    /// Um canister nas faixas.
    pub canister: Principal,
}

impl Ic {
    /// Um IC com quatro nós e um canister.
    pub fn novo() -> Ic {
        let raiz = chave_bls(1);
        let sub_rede = chave_bls(2);
        let id_da_sub_rede = Principal::auto_autenticado(&der_bls(&sub_rede));
        let nos = (10..14)
            .map(|s| {
                let chave = chave_de_no(s);
                (Principal::auto_autenticado(&der_ed25519(&chave)), chave)
            })
            .collect();
        let faixas = std::vec![(
            Principal::de_bytes(&[0, 0, 0, 0, 0, 0x10, 0, 0, 1, 1]).unwrap(),
            Principal::de_bytes(&[0, 0, 0, 0, 0, 0x1f, 0xff, 0xff, 1, 1]).unwrap(),
        )];
        let canister = Principal::de_bytes(&[0, 0, 0, 0, 0, 0x10, 0, 1, 1, 1]).unwrap();
        Ic {
            raiz,
            sub_rede,
            id_da_sub_rede,
            nos,
            faixas,
            canister,
        }
    }

    /// A raiz de confiança.
    pub fn raiz_de_confianca(&self) -> Raiz {
        raiz(&self.raiz)
    }

    /// As folhas do certificado da delegação: a chave e as faixas da
    /// sub-rede, e o tempo.
    pub fn folhas_da_delegacao(&self, tempo_ns: u64) -> Vec<Folha> {
        let id = self.id_da_sub_rede.bytes();
        std::vec![
            (
                caminho(&[b"canister_ranges", id, self.faixas[0].0.bytes()]),
                faixas(&self.faixas),
            ),
            (
                caminho(&[b"subnet", id, b"public_key"]),
                der_bls(&self.sub_rede),
            ),
            (caminho(&[b"subnet", id, b"type"]), b"application".to_vec()),
            (caminho(&[b"time"]), nat(tempo_ns)),
        ]
    }

    /// O certificado da delegação, assinado pela raiz.
    pub fn delegacao(&self, tempo_ns: u64) -> Vec<u8> {
        certificado_assinado(
            arvore(&self.folhas_da_delegacao(tempo_ns)),
            &self.raiz,
            None,
        )
    }

    /// As folhas do certificado de um `read_state` de `["subnet"]`: as
    /// chaves das duas sub-redes, as faixas da raiz, os nós da de
    /// aplicação, e o tempo.
    pub fn folhas_da_sub_rede(&self, tempo_ns: u64) -> Vec<Folha> {
        let id = self.id_da_sub_rede.bytes();
        let id_raiz = Principal::auto_autenticado(&der_bls(&self.raiz));
        let raiz_faixa = Principal::de_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]).unwrap();
        let mut folhas = std::vec![
            (
                caminho(&[b"subnet", id_raiz.bytes(), b"canister_ranges"]),
                faixas(&[(raiz_faixa, raiz_faixa)]),
            ),
            (
                caminho(&[b"subnet", id_raiz.bytes(), b"public_key"]),
                der_bls(&self.raiz),
            ),
            (
                caminho(&[b"subnet", id, b"public_key"]),
                der_bls(&self.sub_rede),
            ),
            (caminho(&[b"time"]), nat(tempo_ns)),
        ];
        for (no, chave) in &self.nos {
            folhas.push((
                caminho(&[b"subnet", id, b"node", no.bytes(), b"public_key"]),
                der_ed25519(chave),
            ));
        }
        folhas
    }

    /// O certificado de um `read_state` de `["subnet"]`, assinado pela
    /// sub-rede, com a delegação.
    pub fn certificado(&self, tempo_ns: u64) -> Vec<u8> {
        certificado_assinado(
            arvore(&self.folhas_da_sub_rede(tempo_ns)),
            &self.sub_rede,
            Some((
                self.id_da_sub_rede.bytes().to_vec(),
                self.delegacao(tempo_ns),
            )),
        )
    }

    /// O corpo da resposta de um `read_state`.
    pub fn resposta_de_leitura(&self, certificado: Vec<u8>) -> Vec<u8> {
        #[derive(Serialize)]
        struct Corpo {
            #[serde(with = "serde_bytes")]
            certificate: Vec<u8>,
        }
        cbor(&Corpo {
            certificate: certificado,
        })
    }

    /// O corpo de uma resposta de consulta respondida, assinada pelos
    /// nós de índice `quem`, com o carimbo `tempo_ns` — o que se assina,
    /// pelo `ic-transport-types`.
    pub fn resposta_de_consulta(
        &self,
        id_do_pedido: [u8; 32],
        arg: &[u8],
        tempo_ns: u64,
        quem: &[usize],
    ) -> Vec<u8> {
        use ic_transport_types::{NodeSignature, QueryResponse, ReplyResponse};
        let mut resposta = QueryResponse::Replied {
            reply: ReplyResponse { arg: arg.to_vec() },
            signatures: Vec::new(),
        };
        self.assinar_resposta(&mut resposta, id_do_pedido, tempo_ns, quem);
        let _: &[NodeSignature] = resposta.signatures();
        cbor(&resposta)
    }

    /// Assina uma resposta pelos nós de índice `quem`.
    pub fn assinar_resposta(
        &self,
        resposta: &mut ic_transport_types::QueryResponse,
        id_do_pedido: [u8; 32],
        tempo_ns: u64,
        quem: &[usize],
    ) {
        use ic_transport_types::{NodeSignature, QueryResponse, RequestId};
        let assinavel = resposta.signable(RequestId::new(&id_do_pedido), tempo_ns);
        let assinaturas: Vec<NodeSignature> = quem
            .iter()
            .map(|&i| NodeSignature {
                timestamp: tempo_ns,
                signature: self.nos[i].1.sign(&assinavel).to_bytes().to_vec(),
                identity: candid::Principal::from_slice(self.nos[i].0.bytes()),
            })
            .collect();
        match resposta {
            QueryResponse::Replied { signatures, .. }
            | QueryResponse::Rejected { signatures, .. } => *signatures = assinaturas,
        }
    }
}

/// Um sorteio determinístico (xorshift64*), para as entradas geradas: o
/// mesmo caso falha do mesmo jeito em toda máquina.
pub struct Sorteio(u64);

impl Sorteio {
    /// Um sorteio desta semente.
    pub fn novo(semente: u64) -> Sorteio {
        Sorteio(semente.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    /// O próximo número.
    pub fn proximo(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Um número abaixo de `n`.
    pub fn ate(&mut self, n: u64) -> u64 {
        self.proximo() % n
    }

    /// `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.proximo() as u8).collect()
    }

    /// De zero a `n` bytes.
    pub fn bytes_ate(&mut self, n: usize) -> Vec<u8> {
        let tamanho = self.ate(n as u64 + 1) as usize;
        self.bytes(tamanho)
    }
}
