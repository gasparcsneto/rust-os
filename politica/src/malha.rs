//! A malha do Duke como conta pura: as intenções que os programas oferecem,
//! as entregas entre eles, os estados, os nonces e as cotas.
//!
//! # O que é
//!
//! Um programa não precisa conhecer outro para cooperar com ele. Ele diz o
//! que quer fazer — uma **intenção**, `imagem.compartilhar` —, a malha
//! acha quem a oferece, e quem pede escolhe a quem entregar. Do outro lado,
//! um programa **oferece** a intenção: abre um endpoint, recebe o que chega
//! por ele e responde. A malha só leva: não decide nada.
//!
//! # O que ela não é
//!
//! - **Uma autoridade.** Quem pode oferecer ou mandar é o gate, pela
//!   política, com as permissões `fabric.offer` e `fabric.send` e a
//!   intenção como recurso enumerado ([`crate::permissao`]). A malha
//!   confere só a forma — quem é dono de que endpoint, de que entrega.
//! - **Uma transferência de autoridade.** O que se entrega é um texto que
//!   quem manda já tinha; quem recebe não ganha acesso a nada por isso — o
//!   que ele faz depois continua decidido pelo papel dele.
//! - **Um caminho entre titulares.** Uma entrega só vai de um programa a
//!   outro do **mesmo** titular: a mesma pessoa, o mesmo agente, o
//!   sistema. Entre titulares, a ferramenta é a mensagem
//!   ([`crate::mensagens`]), com o papel do destinatário como recurso.
//! - **Persistente.** Como um canal de eventos, a malha vive na memória: um
//!   boot a perde, e um id de outro boot não é de entrega nenhuma.
//!
//! # A identidade de um endpoint
//!
//! É a do processo que o abriu, conferida pelo kernel — e não a que o
//! programa diz ter: o nome do manifesto, o resumo da imagem e, para o
//! código de fora da imagem, o editor que o selou ([`Programa`]). Dois
//! programas que dizem o mesmo nome são dois endpoints diferentes, com
//! resumos e origens diferentes, e quem procura vê os dois como são. O
//! endpoint é do processo: some com ele, e um processo de outro titular
//! não o enxerga.
//!
//! # Os estados
//!
//! Os das mensagens ([`Estado`]): `pending` ao entrar; `delivered` na
//! primeira leitura de quem recebe — ler não consome —; `acked` quando ele
//! confirma, com uma resposta opcional; `canceled` se quem mandou desiste
//! antes da leitura; `voided` quando o endpoint acaba, o processo dele
//! morre ou o titular é revogado; `expired` pelo prazo. Cada transição tem
//! versão. A entrega que sai deixa uma lápide curta: o estado, a versão e a
//! resposta, para quem mandou consultar.
//!
//! # Replay e duplicata
//!
//! Como nas mensagens: cada envio traz um `nonce` que só cresce no canal de
//! quem manda — o processo, a sessão. O mesmo nonce com o mesmo conteúdo é
//! o reenvio, e devolve o mesmo id sem criar nada; um nonce velho, ou o
//! mesmo com outro conteúdo, é recusado.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use blake2::{Blake2s256, Digest};

use crate::codigo::Codigo;
pub use crate::mensagens::{Canal, Estado};
use crate::sigiloso::Corpo;

/// A maior intenção, em bytes.
pub const MAIOR_INTENCAO: usize = 48;
/// O maior corpo de uma entrega, em bytes — o de uma mensagem.
pub const MAIOR_CORPO: usize = crate::mensagens::MAIOR_CORPO;
/// A maior resposta de quem recebe, em bytes.
pub const MAIOR_RESPOSTA: usize = 512;
/// Quantos endpoints um processo abre.
pub const ENDPOINTS_POR_PROCESSO: usize = 4;
/// Quantos endpoints um titular tem, somando os processos dele.
pub const ENDPOINTS_POR_TITULAR: usize = 16;
/// Quantos endpoints a malha guarda.
pub const ENDPOINTS: usize = 64;
/// Quantas entregas vivas um canal de quem manda tem.
pub const VIVAS_POR_CANAL: usize = 32;
/// Quantas entregas vivas esperam num endpoint.
pub const VIVAS_POR_ENDPOINT: usize = 32;
/// Quantas entregas vivas a malha guarda.
pub const VIVAS: usize = 128;
/// O prazo de uma entrega sem prazo pedido.
pub const PRAZO_PADRAO_MS: u64 = 60 * 1000;
/// O maior prazo de uma entrega.
pub const MAIOR_PRAZO_MS: u64 = 10 * 60 * 1000;
/// Quantas lápides a malha lembra.
pub const LAPIDES: usize = 64;
/// Quantos nonces recentes cada canal lembra.
pub const JANELA_DE_NONCES: usize = 32;
/// Quantas entregas uma leitura devolve.
pub const MAIOR_LEITURA: usize = 16;

/// Se `texto` é uma intenção: `<espaço>.<nome>[.<nome>…]` — duas partes
/// ou mais, cada uma de minúsculas, dígitos e `_`, começando por letra —,
/// até [`MAIOR_INTENCAO`] bytes. Sem curinga, sem maiúscula, sem parte
/// vazia: `imagem.*`, `Imagem.ver` e `imagem..ver` não são intenções.
pub fn intencao_valida(texto: &str) -> bool {
    if texto.is_empty() || texto.len() > MAIOR_INTENCAO {
        return false;
    }
    let mut partes = 0usize;
    for parte in texto.split('.') {
        let mut bytes = parte.bytes();
        if !bytes.next().is_some_and(|b| b.is_ascii_lowercase()) {
            return false;
        }
        if !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return false;
        }
        partes += 1;
    }
    partes >= 2
}

/// Por quem um programa age — o titular de quem o lançou. Uma entrega só
/// vai de um a outro do mesmo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Titular {
    /// A autoridade local: os processos do sistema.
    Sistema,
    /// A serial.
    Serial,
    /// Um agente, pela chave que provou o aperto.
    Agente([u8; 32]),
    /// Uma pessoa, pelo identificador do registro — e não pela sessão: os
    /// programas que ela lança de dois consoles são dela.
    Pessoa([u8; 8]),
}

/// O programa de um processo, como o kernel o conferiu: o nome que o
/// manifesto diz, o resumo BLAKE2s da imagem — o que ele é — e, se veio de
/// fora da imagem, a chave do editor que o selou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Programa {
    pub nome: String,
    pub resumo: [u8; 32],
    pub editor: Option<[u8; 32]>,
}

/// Um endpoint: um processo oferecendo uma intenção.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub id: u64,
    pub titular: Titular,
    /// O fio do processo que o abriu: o endpoint é dele, e some com ele.
    pub processo: u64,
    pub intencao: String,
    pub programa: Programa,
    pub desde_ms: u64,
}

/// Quem mandou uma entrega: o canal dos nonces e, se foi um processo, ele
/// e o programa dele.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origem {
    pub canal: Canal,
    pub processo: Option<(u64, Programa)>,
}

/// Uma entrega viva.
#[derive(Debug)]
struct Entrega {
    id: u64,
    titular: Titular,
    de: Origem,
    /// O endpoint a que vai.
    para: u64,
    intencao: String,
    /// O texto, opaco: guardado e devolvido, nunca interpretado. Sai da
    /// memória zerado.
    corpo: Corpo,
    criada_ms: u64,
    vence_ms: u64,
    estado: Estado,
    versao: u64,
}

/// O que sobra de uma entrega que saiu: de quem, para onde, onde parou, em
/// que versão, e a resposta de quem a confirmou.
#[derive(Debug)]
struct Lapide {
    id: u64,
    titular: Titular,
    canal: Canal,
    intencao: String,
    estado: Estado,
    versao: u64,
    resposta: Option<Corpo>,
}

/// O que quem recebe lê de uma entrega: uma cópia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lida {
    pub id: u64,
    pub intencao: String,
    /// O programa que mandou, se foi um processo — conferido pelo kernel.
    pub de: Option<Programa>,
    /// O canal de quem mandou: um processo, uma sessão, ou outro
    /// dispositivo pelo enlace — o que o kernel diz a quem recebe.
    pub canal: Canal,
    pub corpo: Corpo,
    pub criada_ms: u64,
    pub vence_ms: u64,
    pub estado: Estado,
    pub versao: u64,
}

/// O que quem mandou vê de uma entrega: onde ela está, em que versão, e a
/// resposta, se foi confirmada com uma.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vista {
    pub intencao: String,
    pub estado: Estado,
    pub versao: u64,
    pub resposta: Option<Corpo>,
}

/// Um envio aceito: o id, e se era o reenvio de um anterior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enviada {
    pub id: u64,
    pub versao: u64,
    pub duplicata: bool,
}

/// Uma mudança de estado, para a auditoria.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transicao {
    pub id: u64,
    pub titular: Titular,
    /// O endpoint de destino.
    pub para: u64,
    pub estado: Estado,
    pub versao: u64,
}

/// Por que uma operação foi recusada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Não há, **para quem pede**, o endpoint ou a entrega: o de outro
    /// titular, de outro processo, um endpoint que não oferece a intenção,
    /// um que acabou ou que nunca existiu — todos respondem igual: o pedido
    /// não descobre o que é dos outros.
    NaoExiste,
    /// A intenção não tem a forma.
    Intencao,
    /// O corpo passa de [`MAIOR_CORPO`].
    CorpoGrande,
    /// A resposta passa de [`MAIOR_RESPOSTA`].
    RespostaGrande,
    /// Prazo zero, ou além de [`MAIOR_PRAZO_MS`].
    Prazo,
    /// O nonce não é novo neste canal.
    Replay,
    /// Uma cota cheia: o motivo diz qual.
    Cota(&'static str),
    /// A entrega não está num estado que aceite a operação.
    Estado(Estado),
    /// A versão esperada não é a de agora.
    Versao { esperada: u64, atual: u64 },
}

impl Recusa {
    /// O código da auditoria e da resposta.
    pub const fn codigo(self) -> Codigo {
        match self {
            Recusa::Intencao | Recusa::CorpoGrande | Recusa::RespostaGrande | Recusa::Prazo => {
                Codigo::InvalidArgument
            }
            Recusa::Replay => Codigo::DenyReplay,
            Recusa::Cota(_) => Codigo::DenyPolicy,
            Recusa::NaoExiste => Codigo::DenyResource,
            Recusa::Estado(_) | Recusa::Versao { .. } => Codigo::Conflict,
        }
    }

    /// O motivo, para quem pediu e para a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::NaoExiste => "nao existe para quem pede",
            Recusa::Intencao => "a intencao nao tem a forma",
            Recusa::CorpoGrande => "o corpo passa de 512 bytes",
            Recusa::RespostaGrande => "a resposta passa de 512 bytes",
            Recusa::Prazo => "prazo zero, ou maior que dez minutos",
            Recusa::Replay => "o nonce nao e novo neste canal",
            Recusa::Cota(m) => m,
            Recusa::Estado(_) => "o estado da entrega nao aceita isto",
            Recusa::Versao { .. } => "a versao esperada nao e a de agora",
        }
    }
}

/// Os nonces recentes de um canal.
#[derive(Default)]
struct Janela {
    /// O maior nonce aceito.
    ultimo: u64,
    /// Os últimos aceitos: nonce, id e o resumo do conteúdo.
    recentes: VecDeque<(u64, u64, [u8; 32])>,
}

/// O resumo do conteúdo de um envio: o destino, a intenção e o corpo.
fn resumir(para: u64, intencao: &str, corpo: &str) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(para.to_le_bytes());
    h.update((intencao.len() as u64).to_le_bytes());
    h.update(intencao.as_bytes());
    h.update((corpo.len() as u64).to_le_bytes());
    h.update(corpo.as_bytes());
    h.finalize().into()
}

/// A malha: os endpoints, as entregas vivas, os nonces e as lápides.
#[derive(Default)]
pub struct Malha {
    endpoints: Vec<Endpoint>,
    /// As vivas, em ordem de id.
    vivas: Vec<Entrega>,
    proximo_endpoint: u64,
    proxima_entrega: u64,
    janelas: BTreeMap<Canal, Janela>,
    lapides: VecDeque<Lapide>,
}

impl Malha {
    pub fn nova() -> Malha {
        Malha {
            proximo_endpoint: 1,
            proxima_entrega: 1,
            ..Malha::default()
        }
    }

    /// Abre o endpoint do `processo` para `intencao`. O mesmo processo
    /// oferecendo a mesma intenção de novo recebe o mesmo endpoint — e
    /// `false`: nada foi criado.
    pub fn oferecer(
        &mut self,
        titular: Titular,
        processo: u64,
        programa: Programa,
        intencao: &str,
        agora_ms: u64,
    ) -> Result<(u64, bool), Recusa> {
        if !intencao_valida(intencao) {
            return Err(Recusa::Intencao);
        }
        if let Some(e) = self
            .endpoints
            .iter()
            .find(|e| e.processo == processo && e.intencao == intencao)
        {
            // O processo é de um titular só: o endpoint dele com outro
            // titular não é deste pedido.
            return if e.titular == titular {
                Ok((e.id, false))
            } else {
                Err(Recusa::NaoExiste)
            };
        }
        if self
            .endpoints
            .iter()
            .filter(|e| e.processo == processo)
            .count()
            >= ENDPOINTS_POR_PROCESSO
        {
            return Err(Recusa::Cota("o processo ja oferece 4 intencoes"));
        }
        if self
            .endpoints
            .iter()
            .filter(|e| e.titular == titular)
            .count()
            >= ENDPOINTS_POR_TITULAR
        {
            return Err(Recusa::Cota("o titular ja tem 16 endpoints"));
        }
        if self.endpoints.len() >= ENDPOINTS {
            return Err(Recusa::Cota("ja ha 64 endpoints na malha"));
        }
        let id = self.proximo_endpoint;
        self.proximo_endpoint += 1;
        self.endpoints.push(Endpoint {
            id,
            titular,
            processo,
            intencao: String::from(intencao),
            programa,
            desde_ms: agora_ms,
        });
        Ok((id, true))
    }

    /// Fecha o endpoint `id` do `processo`: o que esperava nele é anulado.
    pub fn retirar(
        &mut self,
        titular: Titular,
        processo: u64,
        id: u64,
    ) -> Result<Vec<Transicao>, Recusa> {
        let i = self
            .endpoints
            .iter()
            .position(|e| e.id == id && e.titular == titular && e.processo == processo)
            .ok_or(Recusa::NaoExiste)?;
        self.endpoints.remove(i);
        Ok(self.anular_onde(|e| e.para == id))
    }

    /// Os endpoints de `titular` que oferecem `intencao`, em ordem de id. Só
    /// os dele: os de outro titular não existem para ele.
    pub fn descobrir(&self, titular: Titular, intencao: &str) -> Vec<Endpoint> {
        self.endpoints
            .iter()
            .filter(|e| e.titular == titular && e.intencao == intencao)
            .cloned()
            .collect()
    }

    /// A intenção do endpoint `id`, se ele é do `processo` de `titular`.
    pub fn intencao_do_endpoint(&self, titular: Titular, processo: u64, id: u64) -> Option<&str> {
        self.endpoints
            .iter()
            .find(|e| e.id == id && e.titular == titular && e.processo == processo)
            .map(|e| e.intencao.as_str())
    }

    /// A intenção de uma entrega viva que vai a um endpoint do `processo`
    /// de `titular` — o lado de quem recebe.
    pub fn intencao_recebida(&self, titular: Titular, processo: u64, id: u64) -> Option<&str> {
        let entrega = self
            .vivas
            .iter()
            .find(|m| m.id == id && m.titular == titular)?;
        self.endpoints
            .iter()
            .any(|e| e.id == entrega.para && e.processo == processo)
            .then_some(entrega.intencao.as_str())
    }

    /// A intenção de uma entrega — viva ou lembrada — que o `canal` de
    /// `titular` mandou — o lado de quem manda.
    pub fn intencao_mandada(&self, titular: Titular, canal: Canal, id: u64) -> Option<&str> {
        self.vivas
            .iter()
            .find(|m| m.id == id && m.titular == titular && m.de.canal == canal)
            .map(|m| m.intencao.as_str())
            .or_else(|| {
                self.lapides
                    .iter()
                    .find(|l| l.id == id && l.titular == titular && l.canal == canal)
                    .map(|l| l.intencao.as_str())
            })
    }

    /// Entrega `corpo` ao endpoint `para`, que tem de ser de `titular` e
    /// oferecer `intencao`. O `nonce` é o do canal de quem manda. Também
    /// devolve as que venceram até agora, para a auditoria.
    #[allow(clippy::too_many_arguments)]
    pub fn enviar(
        &mut self,
        titular: Titular,
        de: Origem,
        para: u64,
        intencao: &str,
        corpo: &str,
        nonce: u64,
        prazo_ms: Option<u64>,
        agora_ms: u64,
    ) -> (Result<Enviada, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        (
            self.enviar_sem_vencer(
                titular, de, para, intencao, corpo, nonce, prazo_ms, agora_ms,
            ),
            vencidas,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enviar_sem_vencer(
        &mut self,
        titular: Titular,
        de: Origem,
        para: u64,
        intencao: &str,
        corpo: &str,
        nonce: u64,
        prazo_ms: Option<u64>,
        agora_ms: u64,
    ) -> Result<Enviada, Recusa> {
        if !intencao_valida(intencao) {
            return Err(Recusa::Intencao);
        }
        // O destino antes do nonce: um endpoint que não existe para quem
        // pede não gasta nonce, e o reenvio para um endpoint que acabou
        // ouve que ele não existe.
        if !self
            .endpoints
            .iter()
            .any(|e| e.id == para && e.titular == titular && e.intencao == intencao)
        {
            return Err(Recusa::NaoExiste);
        }
        let resumo = resumir(para, intencao, corpo);
        // O reenvio de um pedido que passou devolve o que ele criou, mesmo
        // que agora a fila esteja cheia.
        if let Some(j) = self.janelas.get(&de.canal) {
            if let Some(&(_, id, r)) = j.recentes.iter().find(|(n, _, _)| *n == nonce) {
                if r != resumo {
                    return Err(Recusa::Replay);
                }
                let versao = self.versao_de(id).unwrap_or(0);
                return Ok(Enviada {
                    id,
                    versao,
                    duplicata: true,
                });
            }
            if nonce <= j.ultimo {
                return Err(Recusa::Replay);
            }
        } else if nonce == 0 {
            return Err(Recusa::Replay);
        }
        if corpo.len() > MAIOR_CORPO {
            return Err(Recusa::CorpoGrande);
        }
        let prazo = match prazo_ms {
            None => PRAZO_PADRAO_MS,
            Some(p) if p == 0 || p > MAIOR_PRAZO_MS => return Err(Recusa::Prazo),
            Some(p) => p,
        };
        if self.vivas.iter().filter(|m| m.de.canal == de.canal).count() >= VIVAS_POR_CANAL {
            return Err(Recusa::Cota("quem manda ja tem 32 entregas vivas"));
        }
        if self.vivas.iter().filter(|m| m.para == para).count() >= VIVAS_POR_ENDPOINT {
            return Err(Recusa::Cota("o endpoint ja tem 32 esperando"));
        }
        if self.vivas.len() >= VIVAS {
            return Err(Recusa::Cota("ja ha 128 entregas vivas na malha"));
        }
        let id = self.proxima_entrega;
        self.proxima_entrega += 1;
        let canal = de.canal;
        self.vivas.push(Entrega {
            id,
            titular,
            de,
            para,
            intencao: String::from(intencao),
            corpo: Corpo::from(corpo),
            criada_ms: agora_ms,
            vence_ms: agora_ms.saturating_add(prazo),
            estado: Estado::Pendente,
            versao: 1,
        });
        let j = self.janelas.entry(canal).or_default();
        j.ultimo = nonce;
        if j.recentes.len() >= JANELA_DE_NONCES {
            j.recentes.pop_front();
        }
        j.recentes.push_back((nonce, id, resumo));
        Ok(Enviada {
            id,
            versao: 1,
            duplicata: false,
        })
    }

    /// A versão de agora de uma entrega, viva ou lembrada.
    fn versao_de(&self, id: u64) -> Option<u64> {
        self.vivas
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.versao)
            .or_else(|| self.lapides.iter().find(|l| l.id == id).map(|l| l.versao))
    }

    /// Até `max` entregas — no máximo [`MAIOR_LEITURA`] — que esperam no
    /// endpoint `endpoint` do `processo`, com id maior que `apos`, em ordem.
    /// Ler não consome: a pendente passa a entregue, e continua até a
    /// confirmação.
    pub fn receber(
        &mut self,
        titular: Titular,
        processo: u64,
        endpoint: u64,
        apos: u64,
        max: usize,
        agora_ms: u64,
    ) -> (Result<Vec<Lida>, Recusa>, Vec<Transicao>) {
        let mut transicoes = self.vencer(agora_ms);
        if self
            .intencao_do_endpoint(titular, processo, endpoint)
            .is_none()
        {
            return (Err(Recusa::NaoExiste), transicoes);
        }
        let mut lidas = Vec::new();
        for m in self
            .vivas
            .iter_mut()
            .filter(|m| m.para == endpoint && m.id > apos)
            .take(max.min(MAIOR_LEITURA))
        {
            if m.estado == Estado::Pendente {
                m.estado = Estado::Entregue;
                m.versao += 1;
                transicoes.push(Transicao {
                    id: m.id,
                    titular: m.titular,
                    para: m.para,
                    estado: m.estado,
                    versao: m.versao,
                });
            }
            lidas.push(Lida {
                id: m.id,
                intencao: m.intencao.clone(),
                de: m.de.processo.as_ref().map(|(_, p)| p.clone()),
                canal: m.de.canal,
                corpo: m.corpo.clone(),
                criada_ms: m.criada_ms,
                vence_ms: m.vence_ms,
                estado: m.estado,
                versao: m.versao,
            });
        }
        (Ok(lidas), transicoes)
    }

    /// Confirma uma entrega lida, que chegou a um endpoint do `processo`,
    /// com uma resposta opcional para quem mandou: ela sai da fila.
    #[allow(clippy::too_many_arguments)]
    pub fn confirmar(
        &mut self,
        titular: Titular,
        processo: u64,
        id: u64,
        resposta: Option<&str>,
        versao_esperada: Option<u64>,
        agora_ms: u64,
    ) -> (Result<Transicao, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        if self.intencao_recebida(titular, processo, id).is_none() {
            return (Err(Recusa::NaoExiste), vencidas);
        }
        if resposta.is_some_and(|r| r.len() > MAIOR_RESPOSTA) {
            return (Err(Recusa::RespostaGrande), vencidas);
        }
        let i = self
            .vivas
            .iter()
            .position(|m| m.id == id)
            .expect("a entrega acabou de ser achada");
        let m = &self.vivas[i];
        if m.estado != Estado::Entregue {
            return (Err(Recusa::Estado(m.estado)), vencidas);
        }
        if let Some(v) = versao_esperada
            && v != m.versao
        {
            return (
                Err(Recusa::Versao {
                    esperada: v,
                    atual: m.versao,
                }),
                vencidas,
            );
        }
        let t = self.sair(i, Estado::Confirmada, resposta.map(Corpo::from));
        (Ok(t), vencidas)
    }

    /// Cancela uma entrega que o `canal` mandou, enquanto ninguém a leu.
    pub fn cancelar(
        &mut self,
        titular: Titular,
        canal: Canal,
        id: u64,
        versao_esperada: Option<u64>,
        agora_ms: u64,
    ) -> (Result<Transicao, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        let Some(i) = self
            .vivas
            .iter()
            .position(|m| m.id == id && m.titular == titular && m.de.canal == canal)
        else {
            // A que já saiu responde pelo estado em que parou.
            let r = match self
                .lapides
                .iter()
                .find(|l| l.id == id && l.titular == titular && l.canal == canal)
            {
                Some(l) => Recusa::Estado(l.estado),
                None => Recusa::NaoExiste,
            };
            return (Err(r), vencidas);
        };
        let m = &self.vivas[i];
        if m.estado != Estado::Pendente {
            return (Err(Recusa::Estado(m.estado)), vencidas);
        }
        if let Some(v) = versao_esperada
            && v != m.versao
        {
            return (
                Err(Recusa::Versao {
                    esperada: v,
                    atual: m.versao,
                }),
                vencidas,
            );
        }
        let t = self.sair(i, Estado::Cancelada, None);
        (Ok(t), vencidas)
    }

    /// Onde está uma entrega que o `canal` mandou: viva ou lembrada.
    pub fn estado(
        &mut self,
        titular: Titular,
        canal: Canal,
        id: u64,
        agora_ms: u64,
    ) -> (Result<Vista, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        let viva = self
            .vivas
            .iter()
            .find(|m| m.id == id && m.titular == titular && m.de.canal == canal)
            .map(|m| Vista {
                intencao: m.intencao.clone(),
                estado: m.estado,
                versao: m.versao,
                resposta: None,
            });
        let vista = viva.or_else(|| {
            self.lapides
                .iter()
                .find(|l| l.id == id && l.titular == titular && l.canal == canal)
                .map(|l| Vista {
                    intencao: l.intencao.clone(),
                    estado: l.estado,
                    versao: l.versao,
                    resposta: l.resposta.clone(),
                })
        });
        (vista.ok_or(Recusa::NaoExiste), vencidas)
    }

    /// Se há o que ler no endpoint `endpoint`: uma pendente — ou ele não
    /// existe mais, que também acaba a espera de quem lia.
    pub fn tem_o_que_ler(&self, endpoint: u64) -> bool {
        !self.endpoints.iter().any(|e| e.id == endpoint)
            || self
                .vivas
                .iter()
                .any(|m| m.para == endpoint && m.estado == Estado::Pendente)
    }

    /// O titular foi revogado: os endpoints dele fecham, e as entregas
    /// vivas dele — as que mandou e as que esperavam — são anuladas.
    pub fn anular_titular(&mut self, titular: Titular) -> Vec<Transicao> {
        self.endpoints.retain(|e| e.titular != titular);
        self.anular_onde(|m| m.titular == titular)
    }

    /// Fecha os endpoints de processos que não vivem mais — `vivo` diz
    /// quais —, e anula o que esperava neles. O que esses processos
    /// mandaram continua: quem recebe ainda pode ler e confirmar.
    pub fn podar(&mut self, vivo: impl Fn(u64) -> bool) -> Vec<Transicao> {
        let mortos: Vec<u64> = self
            .endpoints
            .iter()
            .filter(|e| !vivo(e.processo))
            .map(|e| e.id)
            .collect();
        if mortos.is_empty() {
            return Vec::new();
        }
        self.endpoints.retain(|e| !mortos.contains(&e.id));
        self.anular_onde(|m| mortos.contains(&m.para))
    }

    /// Anula as entregas vivas mandadas pelos canais que `de` escolhe, e as
    /// janelas deles saem — o dispositivo revogado ou suspenso: o que ele
    /// mandou e ninguém confirmou não chega mais a quem recebe.
    pub fn anular_de(&mut self, de: impl Fn(&Canal) -> bool) -> Vec<Transicao> {
        self.janelas.retain(|c, _| !de(c));
        self.anular_onde(|m| de(&m.de.canal))
    }

    /// O canal acabou — a sessão fechou, o processo morreu —: a janela de
    /// nonces dele sai. Um canal novo conta do zero.
    pub fn canal_acabou(&mut self, canal: Canal) {
        self.janelas.remove(&canal);
    }

    /// Todas as janelas de nonces saem, como sairiam com o fim de todos os
    /// canais.
    pub fn esquecer_janelas(&mut self) {
        self.janelas.clear();
    }

    /// Vence o que passou do prazo.
    pub fn vencer(&mut self, agora_ms: u64) -> Vec<Transicao> {
        let mut ts = Vec::new();
        while let Some(i) = self.vivas.iter().position(|m| m.vence_ms <= agora_ms) {
            ts.push(self.sair(i, Estado::Expirada, None));
        }
        ts
    }

    fn anular_onde(&mut self, f: impl Fn(&Entrega) -> bool) -> Vec<Transicao> {
        let mut ts = Vec::new();
        while let Some(i) = self.vivas.iter().position(&f) {
            ts.push(self.sair(i, Estado::Anulada, None));
        }
        ts
    }

    /// Tira a entrega `i` das vivas no `estado` final, com a resposta, e a
    /// lembra numa lápide. O corpo sai da memória zerado.
    fn sair(&mut self, i: usize, estado: Estado, resposta: Option<Corpo>) -> Transicao {
        let m = self.vivas.remove(i);
        let versao = m.versao + 1;
        if self.lapides.len() >= LAPIDES {
            self.lapides.pop_front();
        }
        self.lapides.push_back(Lapide {
            id: m.id,
            titular: m.titular,
            canal: m.de.canal,
            intencao: m.intencao.clone(),
            estado,
            versao,
            resposta,
        });
        Transicao {
            id: m.id,
            titular: m.titular,
            para: m.para,
            estado,
            versao,
        }
    }

    /// Os endpoints, para os relatórios e a suíte.
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// Quantas entregas vivas.
    pub fn quantas_vivas(&self) -> usize {
        self.vivas.len()
    }

    /// As regras que a tabela nunca quebra: ids únicos, toda viva num
    /// estado vivo e indo a um endpoint do mesmo titular que oferece a
    /// mesma intenção, os tetos.
    pub fn coerente(&self) -> bool {
        let ids_unicos = self
            .vivas
            .iter()
            .enumerate()
            .all(|(i, m)| self.vivas[..i].iter().all(|o| o.id != m.id));
        let endpoints_unicos = self
            .endpoints
            .iter()
            .enumerate()
            .all(|(i, e)| self.endpoints[..i].iter().all(|o| o.id != e.id));
        let vivas_certas = self.vivas.iter().all(|m| {
            !m.estado.final_()
                && self
                    .endpoints
                    .iter()
                    .any(|e| e.id == m.para && e.titular == m.titular && e.intencao == m.intencao)
        });
        ids_unicos
            && endpoints_unicos
            && vivas_certas
            && self.vivas.len() <= VIVAS
            && self.endpoints.len() <= ENDPOINTS
            && self.lapides.len() <= LAPIDES
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    const P1: Titular = Titular::Pessoa([1; 8]);
    const P2: Titular = Titular::Pessoa([2; 8]);
    const A1: Titular = Titular::Agente([7; 32]);

    fn programa(nome: &str, b: u8) -> Programa {
        Programa {
            nome: String::from(nome),
            resumo: [b; 32],
            editor: None,
        }
    }

    fn de_processo(fio: u64, nome: &str) -> Origem {
        Origem {
            canal: Canal::Processo(fio),
            processo: Some((fio, programa(nome, fio as u8))),
        }
    }

    /// Uma malha com o `correio` (fio 20) de P1 oferecendo
    /// `imagem.compartilhar`: devolve o endpoint.
    fn com_correio() -> (Malha, u64) {
        let mut m = Malha::nova();
        let (e, novo) = m
            .oferecer(P1, 20, programa("correio", 20), "imagem.compartilhar", 0)
            .unwrap();
        assert!(novo);
        (m, e)
    }

    #[test]
    fn a_forma_da_intencao() {
        for boa in [
            "imagem.compartilhar",
            "pdf.anotar",
            "a.b",
            "foto_3.ver_em_tela.agora",
        ] {
            assert!(intencao_valida(boa), "{boa}");
        }
        let longa = "a.".repeat(30);
        for ruim in [
            "",
            "imagem",
            "imagem.*",
            "*",
            "Imagem.ver",
            "imagem..ver",
            ".imagem",
            "imagem.",
            "3d.ver",
            "imagem.ver agora",
            "imagem/ver",
            "intencao:imagem.ver",
            longa.as_str(),
        ] {
            assert!(!intencao_valida(ruim), "{ruim}");
        }
        assert!(!intencao_valida(&"a.b".repeat(17)));
    }

    /// O canal de outro dispositivo: a janela é da (chave, relação, época),
    /// quem recebe vê de onde veio, e a revogação dele anula o que ele
    /// mandou — e só o que ele mandou —, com a janela.
    #[test]
    fn o_canal_de_outro_dispositivo() {
        let remoto = |epoca: u8| Canal::Remoto {
            dispositivo: [0xD1; 32],
            relacao: [0x5A; 16],
            epoca: [epoca; 8],
        };
        let de = |c: Canal| Origem {
            canal: c,
            processo: None,
        };
        let (mut m, e) = com_correio();
        let a = m
            .enviar(P1, de(remoto(1)), e, "imagem.compartilhar", "x", 1, None, 0)
            .0
            .unwrap();
        // O mesmo nonce, o mesmo conteúdo: o mesmo id. Outro conteúdo:
        // replay.
        let b = m
            .enviar(P1, de(remoto(1)), e, "imagem.compartilhar", "x", 1, None, 0)
            .0
            .unwrap();
        assert!(b.duplicata && b.id == a.id);
        assert_eq!(
            m.enviar(P1, de(remoto(1)), e, "imagem.compartilhar", "y", 1, None, 0)
                .0,
            Err(Recusa::Replay)
        );
        // Outra época — o boot seguinte da origem — é outro canal: o nonce
        // 1 é novo nele.
        let c = m
            .enviar(P1, de(remoto(2)), e, "imagem.compartilhar", "y", 1, None, 0)
            .0
            .unwrap();
        assert!(!c.duplicata);
        // Um processo local manda também.
        let d = m
            .enviar(
                P1,
                de_processo(30, "fotos"),
                e,
                "imagem.compartilhar",
                "z",
                1,
                None,
                0,
            )
            .0
            .unwrap();
        // Quem recebe vê o canal de cada uma, e nenhum programa local nas
        // remotas.
        let lidas = m.receber(P1, 20, e, 0, 8, 0).0.unwrap();
        assert_eq!(lidas.len(), 3);
        assert_eq!((lidas[0].canal, lidas[0].de.is_none()), (remoto(1), true));
        assert_eq!(lidas[2].canal, Canal::Processo(30));
        // A revogação do dispositivo anula as duas dele, e não a local.
        let anuladas = m.anular_de(
            |c| matches!(c, Canal::Remoto { dispositivo, .. } if *dispositivo == [0xD1; 32]),
        );
        let ids: Vec<u64> = anuladas.iter().map(|t| t.id).collect();
        assert_eq!(ids, alloc::vec![a.id, c.id]);
        assert!(anuladas.iter().all(|t| t.estado == Estado::Anulada));
        assert_eq!(m.quantas_vivas(), 1);
        assert!(m.vivas.iter().any(|v| v.id == d.id));
        // A janela dele saiu com elas: o mesmo nonce, depois, é novo.
        let e2 = m
            .enviar(P1, de(remoto(1)), e, "imagem.compartilhar", "w", 1, None, 0)
            .0
            .unwrap();
        assert!(!e2.duplicata);
        assert!(m.coerente());
    }

    #[test]
    fn oferecer_e_descobrir() {
        let (mut m, e) = com_correio();
        // De novo: o mesmo endpoint, nada criado.
        assert_eq!(
            m.oferecer(P1, 20, programa("correio", 20), "imagem.compartilhar", 5),
            Ok((e, false))
        );
        // Outro processo do mesmo titular, a mesma intenção: outro endpoint,
        // com a identidade dele.
        let (e2, _) = m
            .oferecer(P1, 21, programa("correio", 99), "imagem.compartilhar", 6)
            .unwrap();
        assert_ne!(e, e2);
        let vistos = m.descobrir(P1, "imagem.compartilhar");
        assert_eq!(vistos.len(), 2);
        assert_eq!(vistos[0].programa.resumo, [20; 32]);
        assert_eq!(vistos[1].programa.resumo, [99; 32]);
        // Outro titular não vê nada; outra intenção também não.
        assert!(m.descobrir(P2, "imagem.compartilhar").is_empty());
        assert!(m.descobrir(P1, "pdf.anotar").is_empty());
        assert_eq!(
            m.oferecer(P1, 22, programa("x", 1), "imagem", 0),
            Err(Recusa::Intencao)
        );
        assert!(m.coerente());
    }

    #[test]
    fn as_cotas_dos_endpoints() {
        let mut m = Malha::nova();
        for (i, intencao) in ["a.a", "a.b", "a.c", "a.d"].into_iter().enumerate() {
            assert_eq!(
                m.oferecer(P1, 1, programa("p", 1), intencao, 0),
                Ok((i as u64 + 1, true))
            );
        }
        assert!(matches!(
            m.oferecer(P1, 1, programa("p", 1), "a.e", 0),
            Err(Recusa::Cota(_))
        ));
        // O teto do titular: 16, somando os processos.
        let mut fio = 2;
        while m.endpoints().iter().filter(|e| e.titular == P1).count() < ENDPOINTS_POR_TITULAR {
            m.oferecer(P1, fio, programa("p", 1), "a.a", 0).unwrap();
            fio += 1;
        }
        assert!(matches!(
            m.oferecer(P1, fio, programa("p", 1), "a.a", 0),
            Err(Recusa::Cota(_))
        ));
        assert!(m.oferecer(P2, fio, programa("p", 1), "a.a", 0).is_ok());
        assert!(m.coerente());
    }

    #[test]
    fn mandar_receber_confirmar() {
        let (mut m, e) = com_correio();
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "/armazem/compartilhado/foto.png",
            1,
            None,
            100,
        );
        let enviada = r.unwrap();
        assert!(!enviada.duplicata && enviada.versao == 1);
        // Quem recebe lê, em ordem, sem consumir: a pendente vira entregue.
        let (lidas, ts) = m.receber(P1, 20, e, 0, 8, 110);
        let lidas = lidas.unwrap();
        assert_eq!(lidas.len(), 1);
        assert_eq!(lidas[0].estado, Estado::Entregue);
        assert_eq!(lidas[0].versao, 2);
        assert_eq!(lidas[0].de.as_ref().unwrap().nome, "fotos");
        assert_eq!(
            lidas[0].corpo.como_texto(),
            "/armazem/compartilhado/foto.png"
        );
        assert_eq!(ts.len(), 1);
        // De novo: a mesma, sem transição.
        let (lidas, ts) = m.receber(P1, 20, e, 0, 8, 120);
        assert_eq!(lidas.unwrap().len(), 1);
        assert!(ts.is_empty());
        // Confirmar com a versão velha: conflito; com a de agora, sai.
        let (r, _) = m.confirmar(P1, 20, enviada.id, Some("ok"), Some(1), 130);
        assert_eq!(
            r,
            Err(Recusa::Versao {
                esperada: 1,
                atual: 2
            })
        );
        let (r, _) = m.confirmar(P1, 20, enviada.id, Some("guardada"), Some(2), 130);
        assert_eq!(r.unwrap().estado, Estado::Confirmada);
        assert_eq!(m.quantas_vivas(), 0);
        // Quem mandou vê a resposta; quem não mandou, nada.
        let (v, _) = m.estado(P1, Canal::Processo(10), enviada.id, 140);
        let v = v.unwrap();
        assert_eq!(v.estado, Estado::Confirmada);
        assert_eq!(v.versao, 3);
        assert_eq!(v.resposta.as_deref(), Some("guardada"));
        let (v, _) = m.estado(P1, Canal::Processo(11), enviada.id, 140);
        assert_eq!(v, Err(Recusa::NaoExiste));
        let (v, _) = m.estado(P2, Canal::Processo(10), enviada.id, 140);
        assert_eq!(v, Err(Recusa::NaoExiste));
        assert!(m.coerente());
    }

    #[test]
    fn so_o_mesmo_titular_e_so_a_intencao_oferecida() {
        let (mut m, e) = com_correio();
        // Outro titular manda ao endpoint de P1: não existe para ele.
        let (r, _) = m.enviar(
            P2,
            de_processo(30, "fotos"),
            e,
            "imagem.compartilhar",
            "x",
            1,
            None,
            0,
        );
        assert_eq!(r, Err(Recusa::NaoExiste));
        // A mesma pessoa, outra intenção: o endpoint não a oferece — e a
        // resposta é a mesma de um que não existe.
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "pdf.anotar",
            "x",
            1,
            None,
            0,
        );
        assert_eq!(r, Err(Recusa::NaoExiste));
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            999,
            "imagem.compartilhar",
            "x",
            1,
            None,
            0,
        );
        assert_eq!(r, Err(Recusa::NaoExiste));
        // Nada disso gastou o nonce.
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "x",
            1,
            None,
            0,
        );
        assert!(r.is_ok());
        // Outro processo de P1 não lê o endpoint do correio, e outro
        // titular não confirma a entrega dele.
        let (r, _) = m.receber(P1, 21, e, 0, 8, 0);
        assert_eq!(r, Err(Recusa::NaoExiste));
        let (r, _) = m.receber(P2, 20, e, 0, 8, 0);
        assert_eq!(r, Err(Recusa::NaoExiste));
        assert!(m.coerente());
    }

    #[test]
    fn replay_e_duplicata() {
        let (mut m, e) = com_correio();
        let manda = |m: &mut Malha, nonce: u64, corpo: &str| {
            m.enviar(
                P1,
                de_processo(10, "fotos"),
                e,
                "imagem.compartilhar",
                corpo,
                nonce,
                None,
                0,
            )
            .0
        };
        assert_eq!(manda(&mut m, 0, "a"), Err(Recusa::Replay));
        let primeira = manda(&mut m, 5, "a").unwrap();
        // O mesmo nonce, o mesmo conteúdo: o reenvio — o mesmo id.
        let de_novo = manda(&mut m, 5, "a").unwrap();
        assert_eq!(de_novo.id, primeira.id);
        assert!(de_novo.duplicata);
        // O mesmo nonce com outro conteúdo, ou um nonce velho: replay.
        assert_eq!(manda(&mut m, 5, "b"), Err(Recusa::Replay));
        assert_eq!(manda(&mut m, 4, "c"), Err(Recusa::Replay));
        assert_eq!(m.quantas_vivas(), 1);
        // Outro canal conta do zero.
        let (r, _) = m.enviar(
            P1,
            de_processo(11, "fotos"),
            e,
            "imagem.compartilhar",
            "a",
            1,
            None,
            0,
        );
        assert!(r.is_ok());
        // O canal que acabou também.
        m.canal_acabou(Canal::Processo(10));
        assert!(manda(&mut m, 1, "z").is_ok());
        assert!(m.coerente());
    }

    #[test]
    fn os_tetos_das_entregas() {
        let (mut m, e) = com_correio();
        let manda = |m: &mut Malha, fio: u64, nonce: u64, corpo: &str, prazo: Option<u64>| {
            m.enviar(
                P1,
                de_processo(fio, "fotos"),
                e,
                "imagem.compartilhar",
                corpo,
                nonce,
                prazo,
                0,
            )
            .0
        };
        let grande = "x".repeat(MAIOR_CORPO + 1);
        assert_eq!(
            manda(&mut m, 10, 1, &grande, None),
            Err(Recusa::CorpoGrande)
        );
        assert!(manda(&mut m, 10, 1, &grande[1..], None).is_ok());
        assert_eq!(manda(&mut m, 10, 2, "a", Some(0)), Err(Recusa::Prazo));
        assert_eq!(
            manda(&mut m, 10, 2, "a", Some(MAIOR_PRAZO_MS + 1)),
            Err(Recusa::Prazo)
        );
        for n in 2..=VIVAS_POR_CANAL as u64 {
            assert!(manda(&mut m, 10, n, "a", None).is_ok());
        }
        assert!(matches!(
            manda(&mut m, 10, 100, "a", None),
            Err(Recusa::Cota(_))
        ));
        // O endpoint enche com o segundo remetente? Não: o teto dele também
        // é 32, e já tem 32.
        assert!(matches!(
            manda(&mut m, 11, 1, "a", None),
            Err(Recusa::Cota(_))
        ));
        assert!(m.coerente());
    }

    #[test]
    fn cancelar_so_quem_mandou_e_antes_da_leitura() {
        let (mut m, e) = com_correio();
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "a",
            1,
            None,
            0,
        );
        let id = r.unwrap().id;
        let (r, _) = m.cancelar(P1, Canal::Processo(11), id, None, 0);
        assert_eq!(r, Err(Recusa::NaoExiste));
        let (r, _) = m.cancelar(P1, Canal::Processo(10), id, Some(9), 0);
        assert_eq!(
            r,
            Err(Recusa::Versao {
                esperada: 9,
                atual: 1
            })
        );
        let (r, _) = m.cancelar(P1, Canal::Processo(10), id, Some(1), 0);
        assert_eq!(r.unwrap().estado, Estado::Cancelada);
        // De novo: já saiu, e diz como.
        let (r, _) = m.cancelar(P1, Canal::Processo(10), id, None, 0);
        assert_eq!(r, Err(Recusa::Estado(Estado::Cancelada)));
        // Uma lida não se cancela.
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "b",
            2,
            None,
            0,
        );
        let id = r.unwrap().id;
        let _ = m.receber(P1, 20, e, 0, 8, 0);
        let (r, _) = m.cancelar(P1, Canal::Processo(10), id, None, 0);
        assert_eq!(r, Err(Recusa::Estado(Estado::Entregue)));
        // E uma pendente não se confirma: tem de ser lida antes.
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "c",
            3,
            None,
            0,
        );
        let id = r.unwrap().id;
        let (r, _) = m.confirmar(P1, 20, id, None, None, 0);
        assert_eq!(r, Err(Recusa::Estado(Estado::Pendente)));
        assert!(m.coerente());
    }

    #[test]
    fn o_prazo_vence() {
        let (mut m, e) = com_correio();
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "a",
            1,
            Some(50),
            100,
        );
        let id = r.unwrap().id;
        assert!(m.tem_o_que_ler(e));
        let (lidas, ts) = m.receber(P1, 20, e, 0, 8, 150);
        assert!(lidas.unwrap().is_empty());
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].estado, Estado::Expirada);
        let (v, _) = m.estado(P1, Canal::Processo(10), id, 160);
        assert_eq!(v.unwrap().estado, Estado::Expirada);
        assert!(!m.tem_o_que_ler(e));
        assert!(m.coerente());
    }

    #[test]
    fn a_revogacao_e_a_morte_anulam() {
        let (mut m, e) = com_correio();
        let (e2, _) = m
            .oferecer(P2, 40, programa("correio", 40), "imagem.compartilhar", 0)
            .unwrap();
        for (t, para, fio) in [(P1, e, 10), (P2, e2, 41)] {
            let (r, _) = m.enviar(
                t,
                de_processo(fio, "fotos"),
                para,
                "imagem.compartilhar",
                "a",
                1,
                None,
                0,
            );
            assert!(r.is_ok());
        }
        // P1 revogado: o endpoint dele fecha, a entrega dele é anulada; a
        // de P2 continua.
        let ts = m.anular_titular(P1);
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].estado, Estado::Anulada);
        assert!(m.descobrir(P1, "imagem.compartilhar").is_empty());
        assert_eq!(m.descobrir(P2, "imagem.compartilhar").len(), 1);
        assert_eq!(m.quantas_vivas(), 1);
        // O processo do correio de P2 morre: o endpoint fecha, e o que
        // esperava nele é anulado.
        let ts = m.podar(|fio| fio != 40);
        assert_eq!(ts.len(), 1);
        assert!(m.descobrir(P2, "imagem.compartilhar").is_empty());
        assert_eq!(m.quantas_vivas(), 0);
        assert!(m.tem_o_que_ler(e2), "um endpoint que acabou acaba a espera");
        assert!(m.coerente());
    }

    #[test]
    fn retirar_so_o_dono() {
        let (mut m, e) = com_correio();
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "a",
            1,
            None,
            0,
        );
        let id = r.unwrap().id;
        assert_eq!(m.retirar(P1, 21, e), Err(Recusa::NaoExiste));
        assert_eq!(m.retirar(P2, 20, e), Err(Recusa::NaoExiste));
        let ts = m.retirar(P1, 20, e).unwrap();
        assert_eq!(ts.len(), 1);
        let (v, _) = m.estado(P1, Canal::Processo(10), id, 0);
        assert_eq!(v.unwrap().estado, Estado::Anulada);
        // O reenvio para o endpoint que acabou ouve que ele não existe.
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "a",
            1,
            None,
            0,
        );
        assert_eq!(r, Err(Recusa::NaoExiste));
        assert!(m.coerente());
    }

    #[test]
    fn as_intencoes_para_o_gate() {
        let (mut m, e) = com_correio();
        assert_eq!(
            m.intencao_do_endpoint(P1, 20, e),
            Some("imagem.compartilhar")
        );
        assert_eq!(m.intencao_do_endpoint(P1, 21, e), None);
        assert_eq!(m.intencao_do_endpoint(A1, 20, e), None);
        let (r, _) = m.enviar(
            P1,
            de_processo(10, "fotos"),
            e,
            "imagem.compartilhar",
            "a",
            1,
            None,
            0,
        );
        let id = r.unwrap().id;
        assert_eq!(m.intencao_recebida(P1, 20, id), Some("imagem.compartilhar"));
        assert_eq!(m.intencao_recebida(P1, 10, id), None);
        assert_eq!(
            m.intencao_mandada(P1, Canal::Processo(10), id),
            Some("imagem.compartilhar")
        );
        assert_eq!(m.intencao_mandada(P1, Canal::Processo(20), id), None);
        assert_eq!(m.intencao_mandada(P2, Canal::Processo(10), id), None);
    }

    /// Sorteio: oferecer, mandar, ler, confirmar, cancelar, revogar e
    /// matar, em qualquer ordem — a tabela continua coerente.
    #[test]
    fn coerente_por_sorteio() {
        let mut m = Malha::nova();
        let mut semente = 0x9E37_79B9_7F4A_7C15u64;
        let mut proximo = || {
            semente ^= semente << 13;
            semente ^= semente >> 7;
            semente ^= semente << 17;
            semente
        };
        let titulares = [P1, P2, A1];
        let intencoes = ["a.a", "a.b"];
        let mut nonces = [0u64; 8];
        for passo in 0..4000u64 {
            let t = titulares[(proximo() % 3) as usize];
            let fio = proximo() % 8;
            let intencao = intencoes[(proximo() % 2) as usize];
            match proximo() % 8 {
                0 => {
                    let _ = m.oferecer(t, fio, programa("p", fio as u8), intencao, passo);
                }
                1 | 2 => {
                    let para = proximo() % 20;
                    nonces[fio as usize] += 1;
                    let _ = m.enviar(
                        t,
                        de_processo(fio, "q"),
                        para,
                        intencao,
                        "corpo",
                        nonces[fio as usize],
                        Some(1 + proximo() % 500),
                        passo,
                    );
                }
                3 => {
                    let e = proximo() % 20;
                    let _ = m.receber(t, fio, e, 0, 4, passo);
                }
                4 => {
                    let id = proximo() % 200;
                    let _ = m.confirmar(t, fio, id, Some("r"), None, passo);
                }
                5 => {
                    let id = proximo() % 200;
                    let _ = m.cancelar(t, Canal::Processo(fio), id, None, passo);
                }
                6 => {
                    if proximo() % 50 == 0 {
                        m.anular_titular(t);
                    } else {
                        let morto = proximo() % 8;
                        m.podar(|f| f != morto);
                    }
                }
                _ => {
                    let e = proximo() % 20;
                    let _ = m.retirar(t, fio, e);
                }
            }
            assert!(m.coerente(), "passo {passo}");
        }
    }
}
