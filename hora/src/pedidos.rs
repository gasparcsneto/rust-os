//! Os pedidos em aberto: cada id ligado ao principal que o pediu, à fonte,
//! à chave fixada dela e à folha do pacote.
//!
//! Quem entrega uma resposta diz só o id e mostra os bytes. O resto — o
//! nonce, a folha, a chave contra a qual se confere, a fonte da amostra —
//! vem do registro feito na emissão, e nunca de quem entrega. Um principal
//! não entrega para o id de outro: para ele, o id não existe.
//!
//! # O ciclo de um id
//!
//! - **Emitido** com um nonce, para uma fonte, num instante do contador. Um
//!   pedido novo do mesmo principal para a mesma fonte substitui o anterior.
//! - Uma entrega **recusada** não consome o id: quem está no caminho não
//!   queima o pedido mandando lixo antes da resposta verdadeira. Cada recusa
//!   conta uma tentativa, e na [`MAIS_TENTATIVAS`]-ésima o id se fecha — o
//!   custo de conferir lixo tem teto.
//! - A **primeira resposta válida consome** o id: a mesma resposta entregue
//!   de novo não acha mais nada.
//! - Passado o **prazo**, o id vence, e a entrega é recusada mesmo com uma
//!   resposta válida: o RTT seria maior que o aceito.
//! - **Revogado** o principal, os pedidos dele somem
//!   ([`Pedidos::esquecer_principal`]).
//!
//! Um principal tem no máximo [`MAIS_POR_PRINCIPAL`] pedidos abertos: quem
//! pede demais não toma a tabela dos outros. Que o serviço de hora tenha a
//! vaga dele garantida, mesmo com outros principais pedindo, é escolha do
//! kernel — uma tabela só dele.
//!
//! Os ids não se repetem: um contador que só sobe.

use crate::intervalo::Amostra;
use crate::merkle::Resumo;
use crate::pedido::Pedido;
use crate::resposta::{self, Esperado, Prova, Recusa};

/// Quantos pedidos ficam abertos ao mesmo tempo, de todos os principais.
pub const MAIS_PEDIDOS: usize = 16;

/// Quantos pedidos um principal tem abertos ao mesmo tempo: um por fonte,
/// no máximo tantas quantas fontes cabem numa rodada.
pub const MAIS_POR_PRINCIPAL: usize = crate::quorum::MAIS_AMOSTRAS;

/// Quantas entregas recusadas um id aguenta antes de se fechar.
pub const MAIS_TENTATIVAS: u8 = 4;

/// As regras de uma entrega.
#[derive(Debug, Clone, Copy)]
pub struct Regras {
    /// Quanto tempo, no contador local, a resposta tem para chegar: o maior
    /// RTT aceito.
    pub prazo_ms: u64,
    /// O maior raio aceito, em segundos.
    pub teto_do_raio: u32,
}

#[derive(Debug, Clone, Copy)]
struct Aberto<P> {
    id: u64,
    principal: P,
    fonte: usize,
    chave_longa: [u8; 32],
    nonce: [u8; 32],
    folha: Resumo,
    emitido_ms: u64,
    tentativas: u8,
}

/// Por que um pedido não foi emitido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecusaDaEmissao {
    /// A tabela está cheia.
    Cheia,
    /// Este principal já tem [`MAIS_POR_PRINCIPAL`] pedidos abertos.
    DemaisDoPrincipal,
}

/// Um pedido emitido: o id e os bytes a mandar.
pub struct Emitido {
    pub id: u64,
    pub pedido: Pedido,
}

/// Por que uma entrega não deu uma amostra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalhaDaEntrega {
    /// Nenhum pedido aberto com esse id para esse principal.
    Desconhecido,
    /// O prazo passou: o id se fechou.
    Vencido,
    /// O instante da entrega é anterior ao da emissão: o contador de quem
    /// chama voltou. O id se fecha.
    InstanteInvalido,
    /// A resposta foi recusada; `fechou` diz se esta foi a última tentativa.
    Recusada { recusa: Recusa, fechou: bool },
}

/// Uma entrega aceita: a fonte do registro, a prova, o RTT e a amostra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entrega {
    pub fonte: usize,
    pub prova: Prova,
    pub rtt_ms: u64,
    pub amostra: Amostra,
}

/// Os pedidos em aberto, de qualquer principal `P`.
pub struct Pedidos<P> {
    vagas: [Option<Aberto<P>>; MAIS_PEDIDOS],
    proximo: u64,
}

impl<P: Copy + Eq> Default for Pedidos<P> {
    fn default() -> Self {
        Self::novo()
    }
}

impl<P: Copy + Eq> Pedidos<P> {
    pub const fn novo() -> Pedidos<P> {
        Pedidos {
            vagas: [const { None }; MAIS_PEDIDOS],
            proximo: 1,
        }
    }

    /// Emite um pedido para a fonte `fonte`, cuja chave longa fixada é
    /// `chave_longa`, com este nonce. Um pedido aberto do mesmo principal
    /// para a mesma fonte é substituído.
    pub fn emitir(
        &mut self,
        principal: P,
        fonte: usize,
        chave_longa: &[u8; 32],
        nonce: &[u8; 32],
        agora_ms: u64,
    ) -> Result<Emitido, RecusaDaEmissao> {
        for vaga in self.vagas.iter_mut() {
            if vaga.is_some_and(|a| a.principal == principal && a.fonte == fonte) {
                *vaga = None;
            }
        }
        let do_principal = self
            .vagas
            .iter()
            .filter(|v| v.is_some_and(|a| a.principal == principal))
            .count();
        if do_principal >= MAIS_POR_PRINCIPAL {
            return Err(RecusaDaEmissao::DemaisDoPrincipal);
        }
        let vaga = self
            .vagas
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or(RecusaDaEmissao::Cheia)?;
        let pedido = Pedido::novo(nonce, chave_longa);
        let id = self.proximo;
        self.proximo += 1;
        *vaga = Some(Aberto {
            id,
            principal,
            fonte,
            chave_longa: *chave_longa,
            nonce: *nonce,
            folha: *pedido.folha(),
            emitido_ms: agora_ms,
            tentativas: 0,
        });
        Ok(Emitido { id, pedido })
    }

    /// Entrega a resposta, como chegou, ao pedido `id` deste principal.
    pub fn entregar(
        &mut self,
        principal: P,
        id: u64,
        pacote: &[u8],
        agora_ms: u64,
        regras: &Regras,
    ) -> Result<Entrega, FalhaDaEntrega> {
        let vaga = self
            .vagas
            .iter_mut()
            .find(|v| v.is_some_and(|a| a.id == id && a.principal == principal))
            .ok_or(FalhaDaEntrega::Desconhecido)?;
        let Some(aberto) = vaga.as_mut() else {
            return Err(FalhaDaEntrega::Desconhecido);
        };
        if agora_ms < aberto.emitido_ms {
            *vaga = None;
            return Err(FalhaDaEntrega::InstanteInvalido);
        }
        let rtt_ms = agora_ms - aberto.emitido_ms;
        if rtt_ms > regras.prazo_ms {
            *vaga = None;
            return Err(FalhaDaEntrega::Vencido);
        }
        let esperado = Esperado {
            nonce: &aberto.nonce,
            folha: &aberto.folha,
            chave_longa: &aberto.chave_longa,
            teto_do_raio: regras.teto_do_raio,
        };
        match resposta::conferir(pacote, &esperado) {
            Ok(prova) => {
                let entrega = Entrega {
                    fonte: aberto.fonte,
                    prova,
                    rtt_ms,
                    amostra: Amostra::de(
                        aberto.chave_longa,
                        prova.midp,
                        prova.radi,
                        rtt_ms,
                        agora_ms,
                    ),
                };
                *vaga = None;
                Ok(entrega)
            }
            Err(recusa) => {
                aberto.tentativas += 1;
                let fechou = aberto.tentativas >= MAIS_TENTATIVAS;
                if fechou {
                    *vaga = None;
                }
                Err(FalhaDaEntrega::Recusada { recusa, fechou })
            }
        }
    }

    /// Fecha os ids vencidos; devolve quantos.
    pub fn vencer(&mut self, agora_ms: u64, prazo_ms: u64) -> usize {
        let mut fechados = 0;
        for vaga in self.vagas.iter_mut() {
            if vaga.is_some_and(|a| agora_ms.saturating_sub(a.emitido_ms) > prazo_ms) {
                *vaga = None;
                fechados += 1;
            }
        }
        fechados
    }

    /// Fecha os ids de um principal — o principal foi revogado; devolve
    /// quantos.
    pub fn esquecer_principal(&mut self, principal: P) -> usize {
        let mut fechados = 0;
        for vaga in self.vagas.iter_mut() {
            if vaga.is_some_and(|a| a.principal == principal) {
                *vaga = None;
                fechados += 1;
            }
        }
        fechados
    }

    /// Quantos pedidos estão abertos.
    pub fn abertos(&self) -> usize {
        self.vagas.iter().filter(|v| v.is_some()).count()
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::servidor_de_teste::Servidor;
    use std::vec::Vec;

    const REGRAS: Regras = Regras {
        prazo_ms: 2_000,
        teto_do_raio: 10,
    };
    const NONCE: [u8; 32] = [0x6e; 32];
    const DONO: u32 = 7;
    const OUTRO: u32 = 8;

    fn tabela_com_um() -> (Pedidos<u32>, Servidor, u64, Vec<u8>) {
        let servidor = Servidor::novo();
        let mut t = Pedidos::novo();
        let e = t
            .emitir(DONO, 3, &servidor.chave_longa(), &NONCE, 1_000)
            .unwrap();
        let resposta = servidor.responder(e.pedido.bytes());
        (t, servidor, e.id, resposta)
    }

    #[test]
    fn a_resposta_valida_da_a_amostra_e_consome_o_id() {
        let (mut t, servidor, id, resposta) = tabela_com_um();
        let entrega = t.entregar(DONO, id, &resposta, 1_250, &REGRAS).unwrap();
        assert_eq!(entrega.fonte, 3, "a fonte vem do registro");
        assert_eq!(entrega.rtt_ms, 250);
        assert_eq!(entrega.amostra.chave, servidor.chave_longa());
        assert_eq!(entrega.amostra.instante_ms, 1_250);
        let midp = entrega.prova.midp;
        assert_eq!(entrega.amostra.cedo_ms, (midp - 5) * 1000);
        assert_eq!(
            entrega.amostra.tarde_ms,
            (midp + 5) * 1000 + 250,
            "o RTT no fim"
        );
        assert_eq!(t.abertos(), 0);
        assert_eq!(
            t.entregar(DONO, id, &resposta, 1_300, &REGRAS),
            Err(FalhaDaEntrega::Desconhecido),
            "a mesma resposta de novo não acha o id"
        );
    }

    #[test]
    fn a_recusa_nao_consome_o_id() {
        let (mut t, _, id, resposta) = tabela_com_um();
        let lixo = [0u8; 100];
        assert_eq!(
            t.entregar(DONO, id, &lixo, 1_100, &REGRAS),
            Err(FalhaDaEntrega::Recusada {
                recusa: Recusa::Moldura,
                fechou: false
            })
        );
        assert!(
            t.entregar(DONO, id, &resposta, 1_200, &REGRAS).is_ok(),
            "a verdadeira ainda entra"
        );
    }

    #[test]
    fn as_tentativas_tem_teto() {
        let (mut t, _, id, resposta) = tabela_com_um();
        let mut torta = resposta.clone();
        let fim = torta.len() - 1;
        torta[fim] ^= 1;
        for i in 1..=MAIS_TENTATIVAS {
            let r = t.entregar(DONO, id, &torta, 1_100, &REGRAS);
            let fechou = i == MAIS_TENTATIVAS;
            assert!(
                matches!(r, Err(FalhaDaEntrega::Recusada { fechou: f, .. }) if f == fechou),
                "tentativa {i}: {r:?}"
            );
        }
        assert_eq!(
            t.entregar(DONO, id, &resposta, 1_200, &REGRAS),
            Err(FalhaDaEntrega::Desconhecido),
            "depois do teto, nem a verdadeira"
        );
        assert_eq!(t.abertos(), 0);
    }

    #[test]
    fn o_prazo() {
        let (mut t, _, id, resposta) = tabela_com_um();
        assert!(
            t.entregar(DONO, id, &resposta, 3_000, &REGRAS).is_ok(),
            "no prazo exato"
        );
        let (mut t, _, id, resposta) = tabela_com_um();
        assert_eq!(
            t.entregar(DONO, id, &resposta, 3_001, &REGRAS),
            Err(FalhaDaEntrega::Vencido)
        );
        assert_eq!(t.abertos(), 0, "vencido, fechado");
    }

    #[test]
    fn o_instante_que_volta() {
        let (mut t, _, id, resposta) = tabela_com_um();
        assert_eq!(
            t.entregar(DONO, id, &resposta, 999, &REGRAS),
            Err(FalhaDaEntrega::InstanteInvalido)
        );
        assert_eq!(t.abertos(), 0);
    }

    #[test]
    fn outro_principal_nao_ve_nem_gasta_o_id() {
        let (mut t, _, id, resposta) = tabela_com_um();
        for _ in 0..(2 * MAIS_TENTATIVAS) {
            assert_eq!(
                t.entregar(OUTRO, id, &resposta, 1_100, &REGRAS),
                Err(FalhaDaEntrega::Desconhecido)
            );
            assert_eq!(
                t.entregar(OUTRO, id, &[0u8; 10], 1_100, &REGRAS),
                Err(FalhaDaEntrega::Desconhecido)
            );
        }
        assert!(
            t.entregar(DONO, id, &resposta, 1_200, &REGRAS).is_ok(),
            "o dono continua"
        );
    }

    #[test]
    fn a_chave_e_a_do_registro() {
        // A resposta de outra fonte, válida para a chave dela, entregue ao
        // pedido feito para esta: a conferência usa a chave registrada.
        let servidor = Servidor::novo();
        let outra_fonte = Servidor {
            longa: ed25519_dalek::SigningKey::from_bytes(&[0x4d; 32]),
            ..Servidor::novo()
        };
        let mut t = Pedidos::novo();
        let e = t
            .emitir(DONO, 0, &servidor.chave_longa(), &NONCE, 1_000)
            .unwrap();
        let resposta = outra_fonte.responder(e.pedido.bytes());
        assert_eq!(
            t.entregar(DONO, e.id, &resposta, 1_100, &REGRAS),
            Err(FalhaDaEntrega::Recusada {
                recusa: Recusa::AssinaturaDaDelegacao,
                fechou: false
            })
        );
    }

    #[test]
    fn o_pedido_e_o_registrado() {
        // A resposta a um pedido montado por fora, com o mesmo nonce, mas
        // outro pacote: não é a folha do registro.
        let servidor = Servidor::novo();
        let mut t = Pedidos::novo();
        let e = t
            .emitir(DONO, 0, &servidor.chave_longa(), &NONCE, 1_000)
            .unwrap();
        let por_fora = Pedido::novo(&NONCE, &[0x33; 32]);
        let resposta = servidor.responder(por_fora.bytes());
        assert_eq!(
            t.entregar(DONO, e.id, &resposta, 1_100, &REGRAS),
            Err(FalhaDaEntrega::Recusada {
                recusa: Recusa::OutroPedido,
                fechou: false
            })
        );
    }

    #[test]
    fn um_pedido_novo_para_a_mesma_fonte_substitui() {
        let servidor = Servidor::novo();
        let mut t = Pedidos::novo();
        let velho = t
            .emitir(DONO, 0, &servidor.chave_longa(), &[1; 32], 1_000)
            .unwrap();
        let novo = t
            .emitir(DONO, 0, &servidor.chave_longa(), &[2; 32], 1_010)
            .unwrap();
        assert_ne!(velho.id, novo.id);
        assert_eq!(t.abertos(), 1);
        let r = servidor.responder(velho.pedido.bytes());
        assert_eq!(
            t.entregar(DONO, velho.id, &r, 1_100, &REGRAS),
            Err(FalhaDaEntrega::Desconhecido)
        );
        // Outra fonte, ou outro principal, não substitui.
        t.emitir(DONO, 1, &servidor.chave_longa(), &[3; 32], 1_020)
            .unwrap();
        t.emitir(OUTRO, 0, &servidor.chave_longa(), &[4; 32], 1_030)
            .unwrap();
        assert_eq!(t.abertos(), 3);
    }

    #[test]
    fn a_tabela_tem_teto_e_os_ids_nao_se_repetem() {
        let servidor = Servidor::novo();
        let chave = servidor.chave_longa();
        let mut t = Pedidos::novo();
        let mut ids = Vec::new();
        for principal in [DONO, OUTRO] {
            for fonte in 0..MAIS_POR_PRINCIPAL {
                ids.push(t.emitir(principal, fonte, &chave, &NONCE, 0).unwrap().id);
            }
        }
        assert_eq!(t.abertos(), MAIS_PEDIDOS);
        assert_eq!(
            t.emitir(9, 0, &chave, &NONCE, 0).err(),
            Some(RecusaDaEmissao::Cheia)
        );
        assert_eq!(t.esquecer_principal(DONO), MAIS_POR_PRINCIPAL);
        assert_eq!(t.esquecer_principal(OUTRO), MAIS_POR_PRINCIPAL);
        let depois = t.emitir(DONO, 0, &chave, &NONCE, 0).unwrap().id;
        assert!(ids.iter().all(|&i| i < depois), "o contador só sobe");
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), MAIS_PEDIDOS);
    }

    #[test]
    fn um_principal_nao_ocupa_a_tabela_inteira() {
        let servidor = Servidor::novo();
        let chave = servidor.chave_longa();
        let mut t = Pedidos::novo();
        for fonte in 0..MAIS_POR_PRINCIPAL {
            t.emitir(DONO, fonte, &chave, &NONCE, 0).unwrap();
        }
        assert_eq!(
            t.emitir(DONO, MAIS_POR_PRINCIPAL, &chave, &NONCE, 0).err(),
            Some(RecusaDaEmissao::DemaisDoPrincipal)
        );
        // Para uma fonte que já tem pedido, substitui: não conta a mais.
        assert!(t.emitir(DONO, 0, &chave, &[9; 32], 0).is_ok());
        // Os outros continuam tendo lugar.
        assert!(t.emitir(OUTRO, 0, &chave, &NONCE, 0).is_ok());
        assert_eq!(t.abertos(), MAIS_POR_PRINCIPAL + 1);
    }

    #[test]
    fn revogar_o_principal_fecha_os_pedidos_dele() {
        let (mut t, servidor, id, resposta) = tabela_com_um();
        t.emitir(OUTRO, 3, &servidor.chave_longa(), &NONCE, 1_000)
            .unwrap();
        assert_eq!(t.esquecer_principal(DONO), 1);
        assert_eq!(
            t.entregar(DONO, id, &resposta, 1_100, &REGRAS),
            Err(FalhaDaEntrega::Desconhecido)
        );
        assert_eq!(t.abertos(), 1, "o do outro fica");
    }

    #[test]
    fn vencer_fecha_so_os_vencidos() {
        let servidor = Servidor::novo();
        let mut t = Pedidos::novo();
        t.emitir(DONO, 0, &servidor.chave_longa(), &NONCE, 1_000)
            .unwrap();
        t.emitir(DONO, 1, &servidor.chave_longa(), &NONCE, 2_000)
            .unwrap();
        assert_eq!(t.vencer(3_000, 2_000), 0, "no prazo exato");
        assert_eq!(t.vencer(3_001, 2_000), 1);
        assert_eq!(t.abertos(), 1);
    }
}
