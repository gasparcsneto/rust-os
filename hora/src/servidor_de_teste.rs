//! Só nos testes: um servidor de Roughtime que responde como a versão 1 —
//! ou, de propósito, de outro jeito.
//!
//! Dos casos deste pacote, e da suíte do kernel, que o compila com a
//! `feature` `servidor` para os servidores de dentro da máquina — ver
//! `kernel/src/rede/bancada_hora.rs`. Nenhuma outra compilação o tem.
//!
//! As chaves são sementes fixas de teste, como as do `sigilo`; não guardam
//! nada. O servidor monta a resposta com o mesmo escritor de mensagens que o
//! pedido usa; o que o escritor recusaria é montado à mão pelos casos.
//! Escritor e leitor errando juntos é o que o vetor externo da RFC 10049
//! pega (ver `resposta::testes`).

use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};

use crate::mensagem::{
    self, CERT, DELE, Etiqueta, INDX, MAXT, MIDP, MINT, Mensagem, NONC, PATH, PUBK, RADI, ROOT,
    SIG, SREP, TYPE, VER, VERS,
};
use crate::merkle::{self, Resumo};
use crate::moldura;
use crate::resposta::{CONTEXTO_DE_DELEGACAO, CONTEXTO_DE_RESPOSTA};

/// A semente da chave longa do servidor de teste.
pub const LONGA: [u8; 32] = [0x4c; 32];
/// A semente da chave delegada.
pub const DELEGADA: [u8; 32] = [0x44; 32];
/// 2026-10-05T00:00:00Z.
pub const MIDP_PADRAO: u64 = 1_791_158_400;

/// O que o servidor põe na resposta. Cada campo pode ser torcido.
#[derive(Clone)]
pub struct Servidor {
    pub longa: SigningKey,
    pub delegada: SigningKey,
    /// A chave pública que vai em `PUBK` — a da delegada, salvo nos casos
    /// que põem outra.
    pub pubk: [u8; 32],
    pub midp: u64,
    pub radi: u32,
    pub mint: u64,
    pub maxt: u64,
    pub versao: u32,
    pub vers: Vec<u32>,
    pub tipo: u32,
    pub contexto_de_delegacao: Vec<u8>,
    pub contexto_de_resposta: Vec<u8>,
    /// Quem assina o `SREP`: a delegada, salvo nos casos que trocam.
    pub assina_o_srep: Option<SigningKey>,
    /// Etiquetas a mais, que este lado não conhece.
    pub extra_no_topo: Vec<(Etiqueta, Vec<u8>)>,
    pub extra_no_srep: Vec<(Etiqueta, Vec<u8>)>,
    pub extra_na_dele: Vec<(Etiqueta, Vec<u8>)>,
    /// O nonce que vai em `NONC`, se não o do pedido.
    pub nonce: Option<[u8; 32]>,
}

impl Servidor {
    pub fn novo() -> Servidor {
        let longa = SigningKey::from_bytes(&LONGA);
        let delegada = SigningKey::from_bytes(&DELEGADA);
        let pubk = delegada.verifying_key().to_bytes();
        Servidor {
            longa,
            delegada,
            pubk,
            midp: MIDP_PADRAO,
            radi: 5,
            mint: MIDP_PADRAO - 3600,
            maxt: MIDP_PADRAO + 86_400,
            versao: 1,
            vers: alloc::vec![1],
            tipo: 1,
            contexto_de_delegacao: CONTEXTO_DE_DELEGACAO.to_vec(),
            contexto_de_resposta: CONTEXTO_DE_RESPOSTA.to_vec(),
            assina_o_srep: None,
            extra_no_topo: Vec::new(),
            extra_no_srep: Vec::new(),
            extra_na_dele: Vec::new(),
            nonce: None,
        }
    }

    /// Um servidor com estas sementes — a longa e a delegada —, e o resto
    /// como o de [`Servidor::novo`]. A suíte do kernel sorteia as dela.
    pub fn com_sementes(longa: &[u8; 32], delegada: &[u8; 32]) -> Servidor {
        let longa = SigningKey::from_bytes(longa);
        let delegada = SigningKey::from_bytes(delegada);
        let pubk = delegada.verifying_key().to_bytes();
        Servidor {
            longa,
            delegada,
            pubk,
            ..Servidor::novo()
        }
    }

    /// O mesmo servidor, com o `SREP` assinado pela chave desta semente, e
    /// não pela delegada.
    pub fn com_srep_assinado_por(mut self, semente: &[u8; 32]) -> Servidor {
        self.assina_o_srep = Some(SigningKey::from_bytes(semente));
        self
    }

    /// A chave pública longa: a que o kernel fixaria.
    pub fn chave_longa(&self) -> [u8; 32] {
        self.longa.verifying_key().to_bytes()
    }

    /// Responde a um pedido sozinho numa árvore de uma folha.
    pub fn responder(&self, pedido: &[u8]) -> Vec<u8> {
        self.responder_lote(&[pedido], 0)
    }

    /// Responde ao pedido `qual` de um lote, numa árvore com todos.
    pub fn responder_lote(&self, pedidos: &[&[u8]], qual: usize) -> Vec<u8> {
        let folhas: Vec<Resumo> = pedidos.iter().map(|p| merkle::folha(p)).collect();
        let (raiz, caminhos) = arvore(&folhas);
        let nonce = self.nonce.unwrap_or_else(|| nonce_do_pedido(pedidos[qual]));
        self.montar(&nonce, &raiz, &caminhos[qual], qual as u32)
    }

    /// Monta a resposta com esta raiz, este caminho e este índice.
    pub fn montar(&self, nonce: &[u8; 32], raiz: &Resumo, caminho: &[u8], indice: u32) -> Vec<u8> {
        let mint = self.mint.to_le_bytes();
        let maxt = self.maxt.to_le_bytes();
        let mut campos_dele: Vec<(Etiqueta, &[u8])> =
            alloc::vec![(PUBK, &self.pubk[..]), (MINT, &mint[..]), (MAXT, &maxt[..])];
        for (e, v) in &self.extra_na_dele {
            campos_dele.push((*e, v));
        }
        let dele = escrita(&campos_dele);
        let sig_dele = self
            .longa
            .sign(&[&self.contexto_de_delegacao[..], &dele[..]].concat())
            .to_bytes();
        let cert = escrita(&[(SIG, &sig_dele[..]), (DELE, &dele[..])]);

        let versao = self.versao.to_le_bytes();
        let radi = self.radi.to_le_bytes();
        let midp = self.midp.to_le_bytes();
        let vers: Vec<u8> = self.vers.iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut campos_srep: Vec<(Etiqueta, &[u8])> = alloc::vec![
            (VER, &versao[..]),
            (RADI, &radi[..]),
            (MIDP, &midp[..]),
            (VERS, &vers[..]),
            (ROOT, &raiz[..]),
        ];
        for (e, v) in &self.extra_no_srep {
            campos_srep.push((*e, v));
        }
        let srep = escrita(&campos_srep);
        let quem = self.assina_o_srep.as_ref().unwrap_or(&self.delegada);
        let sig = quem
            .sign(&[&self.contexto_de_resposta[..], &srep[..]].concat())
            .to_bytes();

        let tipo = self.tipo.to_le_bytes();
        let indx = indice.to_le_bytes();
        let mut campos: Vec<(Etiqueta, &[u8])> = alloc::vec![
            (SIG, &sig[..]),
            (NONC, &nonce[..]),
            (TYPE, &tipo[..]),
            (PATH, caminho),
            (SREP, &srep[..]),
            (CERT, &cert[..]),
            (INDX, &indx[..]),
        ];
        for (e, v) in &self.extra_no_topo {
            campos.push((*e, v));
        }
        emoldurado(&escrita(&campos))
    }
}

/// Uma mensagem escrita pelo escritor do pacote.
pub fn escrita(campos: &[(Etiqueta, &[u8])]) -> Vec<u8> {
    let mut destino = alloc::vec![0u8; 4096];
    let n = mensagem::escrever(campos, &mut destino).expect("o servidor de teste escreve certo");
    destino.truncate(n);
    destino
}

/// Uma mensagem escrita na ordem dada, sem conferir nada — para montar
/// o que o escritor recusaria.
pub fn crua(campos: &[(Etiqueta, &[u8])]) -> Vec<u8> {
    let n = campos.len();
    let mut m = Vec::new();
    m.extend_from_slice(&(n as u32).to_le_bytes());
    let mut deslocamento = 0u32;
    for (i, (_, valor)) in campos.iter().enumerate() {
        deslocamento += valor.len() as u32;
        if i + 1 < n {
            m.extend_from_slice(&deslocamento.to_le_bytes());
        }
    }
    for (etiqueta, _) in campos {
        m.extend_from_slice(etiqueta);
    }
    for (_, valor) in campos {
        m.extend_from_slice(valor);
    }
    m
}

/// A mensagem com a moldura.
pub fn emoldurado(mensagem: &[u8]) -> Vec<u8> {
    let mut pacote = alloc::vec![0u8; moldura::CABECALHO];
    moldura::escrever(&mut pacote, mensagem.len() as u32);
    pacote.extend_from_slice(mensagem);
    pacote
}

/// O nonce de um pedido emoldurado.
pub fn nonce_do_pedido(pedido: &[u8]) -> [u8; 32] {
    let m = Mensagem::ler(moldura::mensagem(pedido).unwrap()).unwrap();
    m.valor(NONC).unwrap().try_into().unwrap()
}

/// Uma árvore completa sobre as folhas (completadas até uma potência de
/// dois) e o caminho de cada uma.
pub fn arvore(folhas: &[Resumo]) -> (Resumo, Vec<Vec<u8>>) {
    let mut tamanho = 1;
    while tamanho < folhas.len() {
        tamanho *= 2;
    }
    let mut nivel: Vec<Resumo> = folhas.to_vec();
    while nivel.len() < tamanho {
        nivel.push(merkle::h(&[&[0xee], &(nivel.len() as u32).to_le_bytes()]));
    }
    let mut caminhos: Vec<Vec<u8>> = alloc::vec![Vec::new(); folhas.len()];
    let mut posicao: Vec<usize> = (0..folhas.len()).collect();
    while nivel.len() > 1 {
        for (i, p) in posicao.iter_mut().enumerate() {
            caminhos[i].extend_from_slice(&nivel[*p ^ 1]);
            *p /= 2;
        }
        nivel = nivel
            .chunks(2)
            .map(|par| merkle::no(&par[0], &par[1]))
            .collect();
    }
    (nivel[0], caminhos)
}

/// Troca o valor de uma etiqueta do topo de um pacote por outro do mesmo
/// tamanho, sem reassinar nada.
pub fn trocar_no_topo(pacote: &[u8], etiqueta: Etiqueta, novo: &[u8]) -> Vec<u8> {
    let corpo = moldura::mensagem(pacote).unwrap();
    let m = Mensagem::ler(corpo).unwrap();
    let valor = m.valor(etiqueta).unwrap();
    assert_eq!(valor.len(), novo.len(), "o mesmo tamanho");
    let comeco = valor.as_ptr() as usize - pacote.as_ptr() as usize;
    let mut outro = pacote.to_vec();
    outro[comeco..comeco + novo.len()].copy_from_slice(novo);
    outro
}

/// A posição, no pacote, do valor de uma etiqueta de uma mensagem aninhada
/// no topo (por exemplo, o `MIDP` dentro do `SREP`).
pub fn posicao_aninhada(pacote: &[u8], fora: Etiqueta, dentro: Etiqueta) -> (usize, usize) {
    let corpo = moldura::mensagem(pacote).unwrap();
    let topo = Mensagem::ler(corpo).unwrap();
    let interna = Mensagem::ler(topo.valor(fora).unwrap()).unwrap();
    let valor = interna.valor(dentro).unwrap();
    let comeco = valor.as_ptr() as usize - pacote.as_ptr() as usize;
    (comeco, valor.len())
}
