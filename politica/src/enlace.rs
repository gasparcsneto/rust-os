//! O enlace entre dois Dukes relacionados, na origem: os pedidos que
//! esperam a resposta do par.
//!
//! # O que é
//!
//! Um programa de uma pessoa daqui pede à malha de outro dispositivo —
//! `fabric.send`, `fabric.discover`, `fabric.status` ou `fabric.cancel`
//! com `device` — e o gate daqui decide o pedido, com as duas permissões:
//! a da malha sobre a intenção, e `fabric.remote` sobre o dispositivo. O
//! que passou entra nesta tabela, e o serviço de enlace o leva ao par, que
//! decide de novo, pelo gate dele. A resposta do par volta para cá, e quem
//! pediu a lê quando o pedido é executado de novo — ver
//! `kernel/src/enlace.rs`.
//!
//! Nada aqui decide: a tabela guarda o que o gate já decidiu e o que o par
//! respondeu. A conta é esta:
//!
//! - **Um pedido por pergunta.** O pedido é o canal de quem pede — o
//!   processo, a sessão da pessoa — e o resumo do que ele pediu. A mesma
//!   pergunta de novo, enquanto a primeira espera, espera com ela; a
//!   resposta sai da tabela quando quem perguntou a lê.
//! - **Os nonces do enlace são da relação.** Do outro lado, a janela é a do
//!   canal remoto (dispositivo, relação, época desta origem), uma só para
//!   todos os processos daqui que pedem pela mesma relação. Por isso o nonce
//!   de um processo não viaja: cada envio ganha aqui um nonce do enlace,
//!   crescente na relação, e a janela do processo guarda qual — o reenvio
//!   do mesmo pedido, com o mesmo nonce do processo, leva o mesmo nonce do
//!   enlace, e o par devolve o mesmo id. O mesmo nonce com outro conteúdo,
//!   ou um nonce velho, é replay aqui mesmo, como na malha local.
//! - **Só o que se mandou se pergunta.** O id de uma entrega remota só
//!   resolve, para `fabric.status` e `fabric.cancel`, no canal que a mandou
//!   — como na malha local.
//! - **Volátil.** Um boot perde a tabela; a época, que vai no aperto, faz o
//!   par abrir uma janela nova.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use crate::codigo::Codigo;
use crate::mensagens::Canal;

/// Os métodos que chegam pelo enlace: o conjunto fechado. Oferecer,
/// retirar, ler, confirmar e qualquer comando fora da malha não existem
/// para quem pede de outro dispositivo.
pub const METODOS: [&str; 4] = [
    "fabric.send",
    "fabric.discover",
    "fabric.status",
    "fabric.cancel",
];

/// Se `metodo` é do conjunto fechado do enlace.
pub fn metodo_do_enlace(metodo: &str) -> bool {
    METODOS.contains(&metodo)
}

/// O parâmetro que leva um pedido da malha a outro dispositivo, na origem:
/// `dispositivo:<nome>`.
pub const PARAMETRO: &str = "device";

/// Quantos pedidos um canal de origem tem na tabela.
pub const PEDIDOS_POR_CANAL: usize = 4;
/// Quantos pedidos a tabela guarda.
pub const PEDIDOS: usize = 32;
/// Quantos nonces recentes cada canal de origem lembra: os da malha.
pub const JANELA_DE_NONCES: usize = crate::malha::JANELA_DE_NONCES;
/// Quanto um pedido espera o par. Mais que a espera de quem pede, que é
/// executado de novo ao fim dela e ainda acha o pedido; e o mesmo tempo,
/// depois de respondido, para quem pediu vir buscar a resposta.
pub const PRAZO_MS: u64 = 15_000;
/// A maior resposta do par que se guarda, em bytes.
pub const MAIOR_RESPOSTA: usize = 4096;
/// Quantas entregas remotas cada canal de origem lembra, para perguntar
/// por elas.
pub const LEMBRADAS_POR_CANAL: usize = 32;

/// Onde está um pedido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Decidido aqui, esperando o serviço de enlace.
    NaFila,
    /// O serviço de enlace o levou ao par.
    EmCurso,
    /// O par respondeu: o envelope dele, inteiro — uma recusa do gate de lá
    /// também é resposta.
    Respondido(String),
    /// Não chegou ao par, ou o par não respondeu: o código e o motivo.
    Falhou(Codigo, &'static str),
}

impl Estado {
    /// Se o pedido terminou: há o que quem pediu ler.
    pub fn terminado(&self) -> bool {
        matches!(self, Estado::Respondido(_) | Estado::Falhou(..))
    }
}

/// Um pedido na tabela.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedido {
    pub id: u64,
    /// O canal de quem pediu: o processo, a sessão da pessoa.
    pub canal: Canal,
    /// O resumo do que foi pedido: o método e os parâmetros.
    pub resumo: [u8; 32],
    pub dispositivo: [u8; 32],
    pub relacao: [u8; 16],
    /// O que vai ao par: a linha do pedido, já com o nonce do enlace.
    pub linha: String,
    /// O resumo da imagem do programa que pediu, que a origem atesta e o par
    /// grava — e que não é critério de nada lá.
    pub programa: [u8; 32],
    pub estado: Estado,
    pub vence_ms: u64,
}

/// O que o serviço de enlace leva ao par.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tomado {
    pub id: u64,
    pub dispositivo: [u8; 32],
    pub relacao: [u8; 16],
    pub linha: String,
    pub programa: [u8; 32],
}

/// O que um pedido deu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Andamento {
    /// Entrou na fila, com este número.
    Novo(u64),
    /// A mesma pergunta já esperava: este número.
    Esperando(u64),
    /// Terminou: o envelope do par, ou a falha.
    Pronto(Result<String, (Codigo, &'static str)>),
}

/// Por que um pedido não entrou na tabela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O nonce do processo não é novo no canal dele.
    Replay,
    /// Uma cota cheia: o motivo diz qual.
    Cota(&'static str),
}

impl Recusa {
    /// O código da resposta e da auditoria.
    pub const fn codigo(self) -> Codigo {
        match self {
            Recusa::Replay => Codigo::DenyReplay,
            Recusa::Cota(_) => Codigo::DenyPolicy,
        }
    }

    /// O motivo, para quem pediu e para a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Replay => "o nonce nao e novo neste canal",
            Recusa::Cota(m) => m,
        }
    }
}

/// Os nonces recentes de um canal de origem: o do processo, o resumo do
/// pedido e o nonce do enlace que ele ganhou.
#[derive(Clone, Debug, Default)]
struct Janela {
    ultimo: u64,
    recentes: VecDeque<(u64, [u8; 32], u64)>,
}

/// Uma entrega remota que um canal daqui mandou: no dispositivo, o id que
/// o par deu, e a intenção dela.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lembrada {
    dispositivo: [u8; 32],
    id: String,
    intencao: String,
}

/// A tabela do enlace, na origem.
#[derive(Default)]
pub struct Enlace {
    /// Em ordem de id.
    pedidos: Vec<Pedido>,
    proximo_id: u64,
    /// O próximo nonce do enlace, por relação.
    nonces: BTreeMap<([u8; 32], [u8; 16]), u64>,
    janelas: BTreeMap<Canal, Janela>,
    lembradas: BTreeMap<Canal, VecDeque<Lembrada>>,
}

impl Enlace {
    pub fn nova() -> Enlace {
        Enlace {
            proximo_id: 1,
            ..Enlace::default()
        }
    }

    /// Pede ao dispositivo `dispositivo`, pela relação `relacao`, o que o
    /// canal `canal` pediu — `resumo` é o do método e dos parâmetros.
    /// `nonce` é o do processo, num envio; `montar` escreve a linha que vai
    /// ao par com o nonce do enlace, se há um.
    ///
    /// A mesma pergunta que já espera espera com ela; a que terminou sai
    /// da tabela com a resposta. Uma pergunta nova entra na fila.
    #[allow(clippy::too_many_arguments)]
    pub fn pedir(
        &mut self,
        canal: Canal,
        resumo: [u8; 32],
        dispositivo: [u8; 32],
        relacao: [u8; 16],
        nonce: Option<u64>,
        programa: [u8; 32],
        montar: impl FnOnce(Option<u64>) -> String,
        agora_ms: u64,
    ) -> Result<Andamento, Recusa> {
        if let Some(i) = self
            .pedidos
            .iter()
            .position(|p| p.canal == canal && p.resumo == resumo)
        {
            if !self.pedidos[i].estado.terminado() {
                return Ok(Andamento::Esperando(self.pedidos[i].id));
            }
            let p = self.pedidos.remove(i);
            return Ok(Andamento::Pronto(match p.estado {
                Estado::Respondido(texto) => Ok(texto),
                Estado::Falhou(c, m) => Err((c, m)),
                // Terminado é um dos dois.
                _ => Err((Codigo::Error, "pedido sem desfecho")),
            }));
        }
        // O nonce do enlace: o mesmo do pedido igual que passou, ou um novo
        // na relação. A janela só anda se o pedido entrar.
        let (nonce_do_enlace, novo) = match nonce {
            None => (None, None),
            Some(n) => {
                let janela = self.janelas.get(&canal);
                match janela.and_then(|j| j.recentes.iter().find(|(m, _, _)| *m == n)) {
                    Some(&(_, r, _)) if r != resumo => return Err(Recusa::Replay),
                    Some(&(_, _, l)) => (Some(l), None),
                    None if n == 0 || janela.is_some_and(|j| n <= j.ultimo) => {
                        return Err(Recusa::Replay);
                    }
                    None => {
                        let l = self
                            .nonces
                            .get(&(dispositivo, relacao))
                            .copied()
                            .unwrap_or(1);
                        (Some(l), Some((n, l)))
                    }
                }
            }
        };
        if self.pedidos.iter().filter(|p| p.canal == canal).count() >= PEDIDOS_POR_CANAL {
            return Err(Recusa::Cota(
                "quem pede ja tem 4 pedidos a outros dispositivos",
            ));
        }
        if self.pedidos.len() >= PEDIDOS {
            return Err(Recusa::Cota("ja ha 32 pedidos a outros dispositivos"));
        }
        if let Some((n, l)) = novo {
            self.nonces.insert((dispositivo, relacao), l + 1);
            let j = self.janelas.entry(canal).or_default();
            j.ultimo = n;
            if j.recentes.len() >= JANELA_DE_NONCES {
                j.recentes.pop_front();
            }
            j.recentes.push_back((n, resumo, l));
        }
        let id = self.proximo_id;
        self.proximo_id += 1;
        self.pedidos.push(Pedido {
            id,
            canal,
            resumo,
            dispositivo,
            relacao,
            linha: montar(nonce_do_enlace),
            programa,
            estado: Estado::NaFila,
            vence_ms: agora_ms.saturating_add(PRAZO_MS),
        });
        Ok(Andamento::Novo(id))
    }

    /// O próximo pedido na fila, para o serviço de enlace levar ao par: o
    /// mais antigo. Ele passa a estar a caminho.
    pub fn tomar(&mut self) -> Option<Tomado> {
        let p = self
            .pedidos
            .iter_mut()
            .find(|p| p.estado == Estado::NaFila)?;
        p.estado = Estado::EmCurso;
        Some(Tomado {
            id: p.id,
            dispositivo: p.dispositivo,
            relacao: p.relacao,
            linha: p.linha.clone(),
            programa: p.programa,
        })
    }

    /// Se o pedido `id` ainda está a caminho: o serviço de enlace confere
    /// entre um passo e outro — a revogação, a suspensão, o prazo e o fim
    /// de quem pediu o tiram do caminho.
    pub fn a_caminho(&self, id: u64) -> bool {
        self.pedido(id).is_some_and(|p| p.estado == Estado::EmCurso)
    }

    /// O par respondeu o pedido `id`, que estava a caminho. Falso se ele
    /// não estava mais.
    pub fn responder(&mut self, id: u64, texto: String) -> bool {
        let Some(p) = self.pedidos.iter_mut().find(|p| p.id == id) else {
            return false;
        };
        if p.estado != Estado::EmCurso {
            return false;
        }
        p.estado = if texto.len() > MAIOR_RESPOSTA {
            Estado::Falhou(Codigo::Error, "a resposta do par passa do teto")
        } else {
            Estado::Respondido(texto)
        };
        true
    }

    /// O pedido `id` não chegou ao par, ou o par não respondeu. Falso se
    /// ele já tinha terminado.
    pub fn falhar(&mut self, id: u64, codigo: Codigo, motivo: &'static str) -> bool {
        match self.pedidos.iter_mut().find(|p| p.id == id) {
            Some(p) if !p.estado.terminado() => {
                p.estado = Estado::Falhou(codigo, motivo);
                true
            }
            _ => false,
        }
    }

    /// O pedido `id`, se está na tabela.
    pub fn pedido(&self, id: u64) -> Option<&Pedido> {
        self.pedidos.iter().find(|p| p.id == id)
    }

    /// O prazo: o que esperava e venceu falha, e o que terminou e ninguém
    /// veio buscar sai. Devolve os que falharam agora — para acordar quem
    /// espera por eles.
    pub fn vencer(&mut self, agora_ms: u64) -> Vec<u64> {
        let mut falharam = Vec::new();
        for p in &mut self.pedidos {
            if !p.estado.terminado() && p.vence_ms <= agora_ms {
                p.estado = Estado::Falhou(Codigo::Error, "o par nao respondeu no prazo");
                p.vence_ms = agora_ms.saturating_add(PRAZO_MS);
                falharam.push(p.id);
            }
        }
        self.pedidos
            .retain(|p| !(p.estado.terminado() && p.vence_ms <= agora_ms));
        falharam
    }

    /// O dispositivo saiu — revogado, suspenso —: o que esperava por ele
    /// falha com o motivo, e o que se lembrava dele sai. Devolve os que
    /// falharam, para acordar quem espera.
    pub fn anular_dispositivo(
        &mut self,
        dispositivo: &[u8; 32],
        codigo: Codigo,
        motivo: &'static str,
    ) -> Vec<u64> {
        let mut falharam = Vec::new();
        for p in &mut self.pedidos {
            if p.dispositivo == *dispositivo && !p.estado.terminado() {
                p.estado = Estado::Falhou(codigo, motivo);
                falharam.push(p.id);
            }
        }
        for l in self.lembradas.values_mut() {
            l.retain(|e| e.dispositivo != *dispositivo);
        }
        self.lembradas.retain(|_, l| !l.is_empty());
        falharam
    }

    /// O dispositivo foi revogado: a contagem dos nonces dele sai também —
    /// a chave não volta.
    pub fn esquecer_dispositivo(&mut self, dispositivo: &[u8; 32]) {
        self.nonces.retain(|(d, _), _| d != dispositivo);
    }

    /// O canal acabou — o processo, a sessão —: os pedidos dele, a janela
    /// e o que ele lembrava saem. Devolve os ids que saíram.
    pub fn canal_acabou(&mut self, canal: Canal) -> Vec<u64> {
        let saem = self
            .pedidos
            .iter()
            .filter(|p| p.canal == canal)
            .map(|p| p.id)
            .collect();
        self.pedidos.retain(|p| p.canal != canal);
        self.janelas.remove(&canal);
        self.lembradas.remove(&canal);
        saem
    }

    /// Lembra que o canal `canal` mandou ao dispositivo a entrega `id`, com
    /// a intenção `intencao`: é o que `fabric.status` e `fabric.cancel`
    /// resolvem depois.
    pub fn lembrar(&mut self, canal: Canal, dispositivo: [u8; 32], id: &str, intencao: &str) {
        let l = self.lembradas.entry(canal).or_default();
        if l.iter().any(|e| e.dispositivo == dispositivo && e.id == id) {
            return;
        }
        if l.len() >= LEMBRADAS_POR_CANAL {
            l.pop_front();
        }
        l.push_back(Lembrada {
            dispositivo,
            id: String::from(id),
            intencao: String::from(intencao),
        });
    }

    /// A intenção da entrega `id` que o canal `canal` mandou ao
    /// dispositivo, se ele a mandou — de outro canal, ou que ele nunca
    /// mandou, não resolve.
    pub fn intencao_lembrada(
        &self,
        canal: Canal,
        dispositivo: &[u8; 32],
        id: &str,
    ) -> Option<&str> {
        self.lembradas
            .get(&canal)?
            .iter()
            .find(|e| e.dispositivo == *dispositivo && e.id == id)
            .map(|e| e.intencao.as_str())
    }

    /// Quantos pedidos a tabela tem.
    pub fn quantos(&self) -> usize {
        self.pedidos.len()
    }

    /// Os pedidos, para o relatório.
    pub fn pedidos(&self) -> &[Pedido] {
        &self.pedidos
    }

    /// As regras da tabela, para a suíte: as cotas, um pedido por pergunta,
    /// os ids crescentes, as janelas no tamanho e abaixo do último, e os
    /// nonces do enlace já dados abaixo do próximo da relação.
    pub fn coerente(&self) -> bool {
        let cotas = self.pedidos.len() <= PEDIDOS
            && self.pedidos.iter().all(|p| {
                self.pedidos.iter().filter(|q| q.canal == p.canal).count() <= PEDIDOS_POR_CANAL
            });
        let unicos = self.pedidos.iter().enumerate().all(|(i, p)| {
            self.pedidos[i + 1..]
                .iter()
                .all(|q| q.id > p.id && !(q.canal == p.canal && q.resumo == p.resumo))
        });
        let ids = self.pedidos.iter().all(|p| p.id < self.proximo_id);
        let janelas = self.janelas.values().all(|j| {
            j.recentes.len() <= JANELA_DE_NONCES
                && j.recentes.iter().all(|(n, _, _)| *n <= j.ultimo)
        });
        let lembradas = self
            .lembradas
            .values()
            .all(|l| l.len() <= LEMBRADAS_POR_CANAL);
        cotas && unicos && ids && janelas && lembradas
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::format;

    const P: Canal = Canal::Processo(20);
    const Q: Canal = Canal::Processo(21);
    const B: [u8; 32] = [0xB0; 32];
    const C: [u8; 32] = [0xC0; 32];
    const R: [u8; 16] = [0x5A; 16];

    fn resumo(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// A linha que o serviço leva, com o nonce do enlace.
    fn linha(n: Option<u64>) -> String {
        format!("{n:?}")
    }

    fn pedir(e: &mut Enlace, c: Canal, r: u8, nonce: Option<u64>) -> Result<Andamento, Recusa> {
        e.pedir(c, resumo(r), B, R, nonce, [0; 32], linha, 0)
    }

    #[test]
    fn o_conjunto_fechado() {
        for m in METODOS {
            assert!(metodo_do_enlace(m));
        }
        for m in [
            "fabric.offer",
            "fabric.recv",
            "fabric.ack",
            "fabric.withdraw",
            "fs.read",
            "admin.execute",
            "fabric.*",
            "",
        ] {
            assert!(!metodo_do_enlace(m), "{m}");
        }
    }

    #[test]
    fn a_pergunta_espera_e_a_resposta_sai_uma_vez() {
        let mut e = Enlace::nova();
        assert_eq!(pedir(&mut e, P, 1, None), Ok(Andamento::Novo(1)));
        // A mesma pergunta espera com a primeira.
        assert_eq!(pedir(&mut e, P, 1, None), Ok(Andamento::Esperando(1)));
        let t = e.tomar().unwrap();
        assert_eq!((t.id, t.dispositivo, t.relacao), (1, B, R));
        assert!(e.tomar().is_none());
        assert!(e.a_caminho(1));
        assert!(e.responder(1, String::from("{\"ok\":true}")));
        // Respondido não se responde de novo, nem falha.
        assert!(!e.responder(1, String::from("outra")));
        assert!(!e.falhar(1, Codigo::Error, "x"));
        assert_eq!(
            pedir(&mut e, P, 1, None),
            Ok(Andamento::Pronto(Ok(String::from("{\"ok\":true}"))))
        );
        // Lida, saiu: a mesma pergunta depois é outra.
        assert_eq!(e.quantos(), 0);
        assert_eq!(pedir(&mut e, P, 1, None), Ok(Andamento::Novo(2)));
        assert!(e.coerente());
    }

    #[test]
    fn o_nonce_do_enlace_e_da_relacao() {
        let mut e = Enlace::nova();
        // Dois processos pela mesma relação: nonces do enlace seguidos.
        assert_eq!(pedir(&mut e, P, 1, Some(5)), Ok(Andamento::Novo(1)));
        assert_eq!(pedir(&mut e, Q, 2, Some(5)), Ok(Andamento::Novo(2)));
        assert_eq!(e.tomar().unwrap().linha, "Some(1)");
        assert_eq!(e.tomar().unwrap().linha, "Some(2)");
        // Outra relação, ou outro dispositivo: outra contagem.
        let r2 = e.pedir(P, resumo(3), B, [1; 16], Some(6), [0; 32], linha, 0);
        assert_eq!(r2, Ok(Andamento::Novo(3)));
        let r3 = e.pedir(P, resumo(4), C, R, Some(7), [0; 32], linha, 0);
        assert_eq!(r3, Ok(Andamento::Novo(4)));
        assert_eq!(e.tomar().unwrap().linha, "Some(1)");
        assert_eq!(e.tomar().unwrap().linha, "Some(1)");
        assert!(e.coerente());
    }

    #[test]
    fn o_reenvio_leva_o_mesmo_nonce_e_o_replay_para_aqui() {
        let mut e = Enlace::nova();
        assert_eq!(pedir(&mut e, P, 1, Some(5)), Ok(Andamento::Novo(1)));
        let t = e.tomar().unwrap();
        assert!(e.falhar(t.id, Codigo::Error, "o enlace caiu"));
        assert_eq!(
            pedir(&mut e, P, 1, Some(5)),
            Ok(Andamento::Pronto(Err((Codigo::Error, "o enlace caiu"))))
        );
        // O reenvio — o mesmo pedido, o mesmo nonce do processo — leva o
        // mesmo nonce do enlace: o par devolve o mesmo id.
        assert_eq!(pedir(&mut e, P, 1, Some(5)), Ok(Andamento::Novo(2)));
        assert_eq!(e.tomar().unwrap().linha, "Some(1)");
        // O mesmo nonce com outro conteúdo, um nonce velho e o zero: replay,
        // sem gastar nonce do enlace.
        assert_eq!(pedir(&mut e, P, 9, Some(5)), Err(Recusa::Replay));
        assert_eq!(pedir(&mut e, P, 9, Some(4)), Err(Recusa::Replay));
        assert_eq!(pedir(&mut e, Q, 9, Some(0)), Err(Recusa::Replay));
        assert_eq!(pedir(&mut e, P, 3, Some(6)), Ok(Andamento::Novo(3)));
        assert_eq!(e.tomar().unwrap().linha, "Some(2)");
        assert_eq!(Recusa::Replay.codigo(), Codigo::DenyReplay);
        assert!(e.coerente());
    }

    #[test]
    fn a_janela_esquece_os_mais_velhos() {
        let mut e = Enlace::nova();
        for n in 1..=(JANELA_DE_NONCES as u64 + 1) {
            assert!(matches!(
                pedir(&mut e, P, n as u8, Some(n)),
                Ok(Andamento::Novo(_))
            ));
            let t = e.tomar().unwrap();
            e.responder(t.id, String::from("ok"));
            assert!(matches!(
                pedir(&mut e, P, n as u8, Some(n)),
                Ok(Andamento::Pronto(Ok(_)))
            ));
        }
        // O primeiro saiu da janela: o reenvio dele é replay agora.
        assert_eq!(pedir(&mut e, P, 1, Some(1)), Err(Recusa::Replay));
        // O segundo ainda está: o mesmo nonce do enlace.
        assert_eq!(pedir(&mut e, P, 2, Some(2)), Ok(Andamento::Novo(34)));
        assert_eq!(e.tomar().unwrap().linha, "Some(2)");
        assert!(e.coerente());
    }

    #[test]
    fn as_cotas() {
        let mut e = Enlace::nova();
        for r in 0..PEDIDOS_POR_CANAL as u8 {
            assert!(matches!(pedir(&mut e, P, r, None), Ok(Andamento::Novo(_))));
        }
        assert!(matches!(
            pedir(&mut e, P, 99, Some(1)),
            Err(Recusa::Cota(_))
        ));
        // A recusa por cota não gastou o nonce do processo nem o do enlace.
        let mut f = 0u64;
        for c in 30..60u64 {
            if e.quantos() >= PEDIDOS {
                break;
            }
            assert!(matches!(
                pedir(&mut e, Canal::Processo(c), 1, None),
                Ok(Andamento::Novo(_))
            ));
            f = c;
        }
        assert_eq!(e.quantos(), PEDIDOS);
        assert!(matches!(
            pedir(&mut e, Canal::Processo(f + 1), 1, None),
            Err(Recusa::Cota(_))
        ));
        e.canal_acabou(P);
        assert_eq!(pedir(&mut e, Q, 7, Some(1)), Ok(Andamento::Novo(33)));
        let mut achou = None;
        while let Some(t) = e.tomar() {
            achou = Some(t);
        }
        assert_eq!(achou.unwrap().linha, "Some(1)");
        assert!(e.coerente());
    }

    #[test]
    fn o_prazo_falha_e_depois_esquece() {
        let mut e = Enlace::nova();
        e.pedir(P, resumo(1), B, R, None, [0; 32], linha, 100)
            .unwrap();
        e.pedir(Q, resumo(1), B, R, None, [0; 32], linha, 100)
            .unwrap();
        let t = e.tomar().unwrap();
        assert_eq!(e.vencer(100 + PRAZO_MS - 1), Vec::<u64>::new());
        // Os dois vencem: o que estava a caminho e o que estava na fila.
        assert_eq!(e.vencer(100 + PRAZO_MS), alloc::vec![1, 2]);
        assert!(!e.a_caminho(t.id));
        assert!(!e.responder(t.id, String::from("tarde")));
        // Ninguém veio buscar: sai depois de outro prazo.
        assert_eq!(e.quantos(), 2);
        e.vencer(100 + 2 * PRAZO_MS);
        assert_eq!(e.quantos(), 0);
    }

    #[test]
    fn a_revogacao_do_dispositivo() {
        let mut e = Enlace::nova();
        assert_eq!(pedir(&mut e, P, 1, Some(1)), Ok(Andamento::Novo(1)));
        let c = e.pedir(Q, resumo(2), C, R, Some(1), [0; 32], linha, 0);
        assert_eq!(c, Ok(Andamento::Novo(2)));
        e.lembrar(P, B, "e1:1", "imagem.ver");
        e.lembrar(P, C, "e2:1", "imagem.ver");
        let t = e.tomar().unwrap();
        assert_eq!(
            e.anular_dispositivo(&B, Codigo::DenyCredential, "dispositivo revogado"),
            alloc::vec![1]
        );
        assert!(!e.a_caminho(t.id));
        assert!(!e.responder(t.id, String::from("tarde")));
        assert_eq!(
            pedir(&mut e, P, 1, Some(1)),
            Ok(Andamento::Pronto(Err((
                Codigo::DenyCredential,
                "dispositivo revogado"
            ))))
        );
        // O do outro dispositivo segue; o que se lembrava do revogado, não.
        assert_eq!(e.pedido(2).map(|p| &p.estado), Some(&Estado::NaFila));
        assert_eq!(e.intencao_lembrada(P, &B, "e1:1"), None);
        assert_eq!(e.intencao_lembrada(P, &C, "e2:1"), Some("imagem.ver"));
        e.esquecer_dispositivo(&B);
        assert!(e.coerente());
    }

    #[test]
    fn so_o_canal_que_mandou_pergunta() {
        let mut e = Enlace::nova();
        e.lembrar(P, B, "e1:1", "imagem.ver");
        e.lembrar(P, B, "e1:1", "imagem.ver");
        assert_eq!(e.intencao_lembrada(P, &B, "e1:1"), Some("imagem.ver"));
        assert_eq!(e.intencao_lembrada(Q, &B, "e1:1"), None);
        assert_eq!(e.intencao_lembrada(P, &C, "e1:1"), None);
        assert_eq!(e.intencao_lembrada(P, &B, "e1:2"), None);
        for n in 0..LEMBRADAS_POR_CANAL {
            e.lembrar(P, B, &format!("e1:{}", n + 10), "imagem.ver");
        }
        // A mais velha saiu.
        assert_eq!(e.intencao_lembrada(P, &B, "e1:1"), None);
        e.canal_acabou(P);
        assert_eq!(e.intencao_lembrada(P, &B, "e1:10"), None);
        assert!(e.coerente());
    }

    #[test]
    fn a_resposta_grande_demais_falha() {
        let mut e = Enlace::nova();
        pedir(&mut e, P, 1, None).unwrap();
        let t = e.tomar().unwrap();
        assert!(e.responder(t.id, "x".repeat(MAIOR_RESPOSTA + 1)));
        assert!(matches!(
            pedir(&mut e, P, 1, None),
            Ok(Andamento::Pronto(Err((Codigo::Error, _))))
        ));
    }
}
