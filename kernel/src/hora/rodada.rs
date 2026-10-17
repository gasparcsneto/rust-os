//! Os pedidos de hora em aberto e as rodadas: o que `time.request` e
//! `time.sync` fazem, sem trava nenhuma — quem chama tem a vez da hora
//! (ver `super::Vez`).
//!
//! # A rodada
//!
//! Uma rodada é de **um principal** — a autoridade decidida pelo gate, e
//! não o fio nem um PID — e consulta as fontes do registro uma depois da
//! outra, na ordem do registro:
//!
//! - `time.request` da primeira fonte abre uma rodada nova, e a de antes
//!   do mesmo principal, se havia, é largada com os pedidos dela;
//! - a fonte seguinte só é pedida depois de a anterior ter sido entregue —
//!   aceita, recusada de vez, sem resposta ou vencida —: o nonce dela é
//!   H(o pacote inteiro da última resposta aceita da rodada ‖ 32 bytes
//!   aleatórios), e a primeira resposta ainda não chegou quando a segunda
//!   é pedida fora de ordem (desenho §5, D0-9). Sem resposta aceita ainda,
//!   o nonce é o próprio aleatório, do gerador;
//! - pedir de novo a fonte em curso substitui o pedido dela, se ela ainda
//!   não foi aceita: uma resposta autêntica não se troca por outra;
//! - a entrega da última fonte fecha a rodada: as amostras aceitas, levadas
//!   ao mesmo instante pela régua, vão ao quórum de pelo menos `k` chaves
//!   do registro (`hora::quorum`), e o desfecho vai ao civil.
//!
//! Uma rodada aberta sob uma política vale só sob ela: uma troca da
//! política em vigor — um `policy.write`, o papel da serial num
//! `policy.assign` — larga as rodadas em curso e os pedidos delas, e nada
//! delas chega ao civil. O gate decide cada pedido de novo; isto só impede
//! que a evidência juntada antes da troca seja aplicada depois dela. O que
//! muda sem trocar a política — o papel de um agente, a chave revogada, a
//! sessão de pessoa que acabou — não larga nada aqui: o pedido seguinte é
//! recusado pelo gate, e o fechamento refaz a decisão antes do civil (ver
//! `super::aplicar`).
//!
//! # As tabelas
//!
//! Duas `hora::pedidos::Pedidos`: a do serviço de hora, só dele, e a de
//! todos os outros principais com `time.sync` — quem pede demais não toma
//! a vaga do serviço (desenho §6.4). Cada uma com os tetos do pacote: 16
//! abertos, 8 por principal, 4 entregas recusadas por id.
//!
//! # A pilha
//!
//! A conferência de uma resposta — duas assinaturas Ed25519 — roda no fio
//! de quem entrega, no fundo do despacho do gate; o do serviço de hora tem
//! a pilha de um fio qualquer (`crate::fios::pilha`). Por isso o que é
//! grande anda em caixa, e não por valor: uma rodada tem o registro e o
//! veredito de cada fonte, alguns KiB, e cada movimento de um valor desses
//! é uma cópia na pilha — no perfil de depuração, uma por temporário. A
//! rodada mora numa caixa do começo ao fim, o fechamento a leva consigo, e
//! uma entrega devolve só a fonte dela.

use alloc::boxed::Box;
use alloc::vec::Vec;

use hora::intervalo::Amostra;
use hora::pedido::Pedido;
use hora::pedidos::{FalhaDaEntrega, Pedidos, RecusaDaEmissao, Regras};
use hora::quorum::{self, Desfecho, MAIS_AMOSTRAS};
use hora::registro::{Fonte, MAIS_FONTES, Registro};
use hora::resposta::{Prova, Recusa};

use crate::autorizacao::{Principal, Servico};

/// O prazo de um pedido, e o maior RTT aceito (desenho §7.6).
pub const PRAZO_MS: u64 = 2_000;

/// O maior raio aceito de uma resposta, em segundos (desenho §7.6).
pub const TETO_DO_RAIO: u32 = 10;

const REGRAS: Regras = Regras {
    prazo_ms: PRAZO_MS,
    teto_do_raio: TETO_DO_RAIO,
};

/// Quantas rodadas de outros principais ficam abertas ao mesmo tempo. A do
/// serviço de hora tem lugar só dela.
const MAIS_RODADAS_DOS_OUTROS: usize = 4;

const _: () = assert!(MAIS_FONTES <= MAIS_AMOSTRAS);

/// O principal do serviço de hora.
pub const SERVICO: Principal = Principal::Servico(Servico::Hora);

/// O que aconteceu com uma fonte numa rodada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Veredito {
    /// Pedida: espera a entrega até o prazo.
    Aberta { id: u64, emitido_ms: u64 },
    /// A resposta valeu: uma amostra.
    Aceita {
        prova: Prova,
        rtt_ms: u64,
        amostra: Amostra,
    },
    /// Recusada na última tentativa: o id se fechou.
    Recusada(Recusa),
    /// Quem entrega avisou que a resposta não veio.
    SemResposta,
    /// O prazo passou antes da entrega.
    Vencida,
}

impl Veredito {
    /// O nome estável, para a auditoria e o `system.info`.
    pub fn nome(&self) -> &'static str {
        match self {
            Veredito::Aberta { .. } => "aberta",
            Veredito::Aceita { .. } => "aceita",
            Veredito::Recusada(r) => r.nome(),
            Veredito::SemResposta => "sem_resposta",
            Veredito::Vencida => "vencida",
        }
    }

    /// A fonte já foi entregue — ou o prazo dela passou.
    fn resolvida(&self, agora_ms: u64) -> bool {
        match self {
            Veredito::Aberta { emitido_ms, .. } => agora_ms.saturating_sub(*emitido_ms) > PRAZO_MS,
            _ => true,
        }
    }
}

struct Rodada {
    principal: Principal,
    numero: u64,
    /// A política sob a qual a rodada foi aberta.
    versao_da_politica: u64,
    /// O registro de quando ela foi aberta: as fontes pela posição.
    registro: Registro,
    fontes: [Option<Veredito>; MAIS_FONTES],
    /// Entregas recusadas de cada fonte, nesta rodada.
    tentativas: [u8; MAIS_FONTES],
    /// A última fonte pedida.
    atual: usize,
    /// O pacote inteiro da última resposta aceita: de onde sai o nonce da
    /// fonte seguinte.
    ultima_aceita: Option<Vec<u8>>,
}

/// Os pedidos e as rodadas.
pub struct Tabelas {
    do_servico: Pedidos<Principal>,
    dos_outros: Pedidos<Principal>,
    /// Cada rodada na caixa dela, e não no vetor: ela sai dele inteira, no
    /// fechamento, e uma caixa sai sem passar pela pilha — ver a pilha no
    /// topo do módulo.
    #[allow(clippy::vec_box)]
    rodadas: Vec<Box<Rodada>>,
    proxima: u64,
    /// Só na suíte: os 32 bytes do gerador do último pedido — o aleatório
    /// não sai do kernel, e é com ele que a suíte confere o encadeamento.
    #[cfg(feature = "modo-teste")]
    pub ultimo_aleatorio: [u8; 32],
}

/// Um pedido emitido: o id, os bytes a mandar e a rodada.
pub struct Emissao {
    pub id: u64,
    pub pedido: Box<Pedido>,
    pub rodada: u64,
}

/// Por que um pedido ou uma entrega não foi feito.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusado {
    /// A rodada começa pela primeira fonte do registro, e segue a ordem.
    ForaDaOrdem,
    /// A fonte anterior da rodada ainda espera a entrega.
    AnteriorAberta,
    /// A fonte já foi aceita nesta rodada: a resposta não se troca.
    JaAceita,
    /// A tabela de pedidos — `Cheia`, ou o principal no teto dele.
    Tabela(RecusaDaEmissao),
    /// Nenhum pedido aberto com este id para este principal.
    Desconhecido,
}

/// O que uma entrega fez com a fonte dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resultado {
    Aceita {
        prova: Prova,
        rtt_ms: u64,
    },
    /// Recusada: a tentativa desta entrega, e se o id se fechou nela.
    Recusada {
        recusa: Recusa,
        tentativa: u8,
        fechou: bool,
    },
    SemResposta,
    Vencida,
}

impl Resultado {
    /// O nome estável do veredito, para a auditoria e a resposta.
    pub fn nome(&self) -> &'static str {
        match self {
            Resultado::Aceita { .. } => "aceita",
            Resultado::Recusada { recusa, .. } => recusa.nome(),
            Resultado::SemResposta => "sem_resposta",
            Resultado::Vencida => "vencida",
        }
    }
}

/// Uma rodada que fechou: o desfecho do quórum, e a rodada inteira — o
/// registro dela e o que cada fonte deu.
pub struct Fechamento {
    rodada: Box<Rodada>,
    pub desfecho: Desfecho,
    /// Quantas fontes deram amostra.
    pub aceitas: usize,
}

impl Fechamento {
    pub fn numero(&self) -> u64 {
        self.rodada.numero
    }

    pub fn principal(&self) -> Principal {
        self.rodada.principal
    }

    /// A política sob a qual a rodada foi aberta.
    pub fn versao_da_politica(&self) -> u64 {
        self.rodada.versao_da_politica
    }

    /// O registro de quando a rodada foi aberta.
    pub fn registro(&self) -> &Registro {
        &self.rodada.registro
    }

    /// O que cada fonte deu, pela posição no registro.
    pub fn fontes(&self) -> &[Option<Veredito>; MAIS_FONTES] {
        &self.rodada.fontes
    }

    /// Larga o pacote da última resposta aceita: o nonce da fonte seguinte
    /// não existe mais, e o resumo não o guarda.
    pub fn sem_o_pacote(mut self: Box<Self>) -> Box<Self> {
        self.rodada.ultima_aceita = None;
        self
    }
}

/// Uma entrega: a fonte, a rodada, o que a fonte deu, e o fechamento se
/// esta foi a última fonte.
pub struct Entrega {
    pub fonte: Fonte,
    pub rodada: u64,
    pub resultado: Resultado,
    pub fechamento: Option<Box<Fechamento>>,
}

impl Rodada {
    fn nova(principal: Principal, numero: u64, versao: u64, registro: Registro) -> Rodada {
        Rodada {
            principal,
            numero,
            versao_da_politica: versao,
            registro,
            fontes: [None; MAIS_FONTES],
            tentativas: [0; MAIS_FONTES],
            atual: 0,
            ultima_aceita: None,
        }
    }

    fn fechar(self: Box<Self>, agora_ms: u64, deriva_ppm: u64) -> Box<Fechamento> {
        let lidas: Vec<Amostra> = self
            .fontes
            .iter()
            .flatten()
            .filter_map(|v| match v {
                Veredito::Aceita { amostra, .. } => Some(amostra.em(agora_ms, deriva_ppm)),
                _ => None,
            })
            .collect();
        // O `k` do registro da rodada: pelo menos dois sempre — o registro
        // não se lê com menos —, e uma conta que recebesse menos nunca
        // daria acordo (`hora::quorum`).
        let k = usize::try_from(self.registro.quorum()).unwrap_or(usize::MAX);
        let desfecho = quorum::acordo(&lidas, k);
        Box::new(Fechamento {
            aceitas: lidas.len(),
            desfecho,
            rodada: self,
        })
    }
}

impl Tabelas {
    pub const fn novas() -> Tabelas {
        Tabelas {
            do_servico: Pedidos::novo(),
            dos_outros: Pedidos::novo(),
            rodadas: Vec::new(),
            proxima: 1,
            #[cfg(feature = "modo-teste")]
            ultimo_aleatorio: [0; 32],
        }
    }

    fn tabela(&mut self, principal: Principal) -> &mut Pedidos<Principal> {
        if principal == SERVICO {
            &mut self.do_servico
        } else {
            &mut self.dos_outros
        }
    }

    /// Larga a rodada da posição `i` e os pedidos do principal dela.
    fn largar(&mut self, i: usize) {
        let r = self.rodadas.swap_remove(i);
        self.tabela(r.principal).esquecer_principal(r.principal);
    }

    /// Larga as rodadas abertas sob outra política. `versao` é a em vigor,
    /// lida por quem chama com a vez na mão: uma lida antes podia ser de
    /// antes de uma troca que outro fio já viu, e largaria as rodadas
    /// abertas sob a nova.
    fn largar_as_de_outra_politica(&mut self, versao: u64) {
        let mut i = 0;
        while i < self.rodadas.len() {
            if self.rodadas[i].versao_da_politica != versao {
                self.largar(i);
            } else {
                i += 1;
            }
        }
    }

    /// A primeira fonte abre uma rodada nova de `principal`: a de antes
    /// dele, na posição `posicao`, é largada com os pedidos dela, e, se os
    /// outros principais já têm rodadas demais, a mais velha deles. Devolve
    /// a posição da nova.
    ///
    /// Fora de [`Tabelas::pedir`], e nunca embutida nele: a rodada nova
    /// passa pela pilha antes da caixa, e não deve ocupar o quadro de quem
    /// emite o pedido — ver a pilha no topo do módulo.
    #[inline(never)]
    fn abrir(
        &mut self,
        principal: Principal,
        posicao: Option<usize>,
        registro: &Registro,
        versao: u64,
    ) -> usize {
        if let Some(i) = posicao {
            self.largar(i);
        }
        self.tabela(principal).esquecer_principal(principal);
        if principal != SERVICO
            && self
                .rodadas
                .iter()
                .filter(|r| r.principal != SERVICO)
                .count()
                >= MAIS_RODADAS_DOS_OUTROS
            && let Some(velha) = self
                .rodadas
                .iter()
                .enumerate()
                .filter(|(_, r)| r.principal != SERVICO)
                .min_by_key(|(_, r)| r.numero)
                .map(|(i, _)| i)
        {
            self.largar(velha);
        }
        let numero = self.proxima;
        self.proxima += 1;
        self.rodadas
            .push(Box::new(Rodada::nova(principal, numero, versao, *registro)));
        self.rodadas.len() - 1
    }

    /// `time.request`: o pedido para a fonte `indice` do registro, com
    /// estes 32 bytes do gerador, para `principal`.
    pub fn pedir(
        &mut self,
        principal: Principal,
        registro: &Registro,
        indice: usize,
        aleatorio: &[u8; 32],
        agora_ms: u64,
        versao: u64,
    ) -> Result<Emissao, Recusado> {
        self.largar_as_de_outra_politica(versao);
        self.do_servico.vencer(agora_ms, PRAZO_MS);
        self.dos_outros.vencer(agora_ms, PRAZO_MS);
        let fonte = registro
            .fontes()
            .get(indice)
            .copied()
            .ok_or(Recusado::ForaDaOrdem)?;
        let posicao = self.rodadas.iter().position(|r| r.principal == principal);
        let i = if indice == 0 {
            self.abrir(principal, posicao, registro, versao)
        } else {
            let i = posicao.ok_or(Recusado::ForaDaOrdem)?;
            let r = &self.rodadas[i];
            // O registro mudou desde a abertura: a rodada recomeça.
            if r.registro != *registro {
                return Err(Recusado::ForaDaOrdem);
            }
            if indice == r.atual {
                if matches!(r.fontes[indice], Some(Veredito::Aceita { .. })) {
                    return Err(Recusado::JaAceita);
                }
            } else if indice == r.atual + 1 {
                if !r.fontes[r.atual].is_some_and(|v| v.resolvida(agora_ms)) {
                    return Err(Recusado::AnteriorAberta);
                }
            } else {
                return Err(Recusado::ForaDaOrdem);
            }
            i
        };
        #[cfg(feature = "modo-teste")]
        {
            self.ultimo_aleatorio = *aleatorio;
        }
        let nonce = match &self.rodadas[i].ultima_aceita {
            Some(resposta) => hora::encadeamento::nonce(resposta, aleatorio),
            None => *aleatorio,
        };
        // O pedido vai para a caixa direto: são mais de 1 KiB. Um pedido
        // aberto deste principal para a mesma fonte — ela pedida de novo —
        // é substituído pela tabela.
        let (id, pedido) =
            match self
                .tabela(principal)
                .emitir(principal, indice, fonte.chave(), &nonce, agora_ms)
            {
                Ok(e) => (e.id, Box::new(e.pedido)),
                Err(r) => return Err(Recusado::Tabela(r)),
            };
        let r = &mut self.rodadas[i];
        r.fontes[indice] = Some(Veredito::Aberta {
            id,
            emitido_ms: agora_ms,
        });
        r.tentativas[indice] = 0;
        r.atual = indice;
        Ok(Emissao {
            id,
            pedido,
            rodada: r.numero,
        })
    }

    /// `time.sync`: a resposta ao pedido `id` de `principal`, como chegou —
    /// ou `None`, o aviso de que ela não veio.
    pub fn entregar(
        &mut self,
        principal: Principal,
        id: u64,
        pacote: Option<&[u8]>,
        agora_ms: u64,
        versao: u64,
        deriva_ppm: u64,
    ) -> Result<Entrega, Recusado> {
        self.largar_as_de_outra_politica(versao);
        let (i, indice) = self
            .rodadas
            .iter()
            .enumerate()
            .find_map(|(i, r)| {
                (r.principal == principal)
                    .then(|| {
                        r.fontes.iter().position(
                            |v| matches!(v, Some(Veredito::Aberta { id: aberto, .. }) if *aberto == id),
                        )
                    })
                    .flatten()
                    .map(|f| (i, f))
            })
            .ok_or(Recusado::Desconhecido)?;
        let resultado = match pacote {
            None => match self.tabela(principal).desistir(principal, id) {
                Some(_) => Resultado::SemResposta,
                // O prazo passou e a tabela já o fechou.
                None => Resultado::Vencida,
            },
            Some(p) => match self
                .tabela(principal)
                .entregar(principal, id, p, agora_ms, &REGRAS)
            {
                Ok(e) => {
                    let r = &mut self.rodadas[i];
                    r.ultima_aceita = Some(p.to_vec());
                    r.fontes[indice] = Some(Veredito::Aceita {
                        prova: e.prova,
                        rtt_ms: e.rtt_ms,
                        amostra: e.amostra,
                    });
                    Resultado::Aceita {
                        prova: e.prova,
                        rtt_ms: e.rtt_ms,
                    }
                }
                Err(FalhaDaEntrega::Recusada { recusa, fechou }) => {
                    let r = &mut self.rodadas[i];
                    r.tentativas[indice] = r.tentativas[indice].saturating_add(1);
                    Resultado::Recusada {
                        recusa,
                        tentativa: r.tentativas[indice],
                        fechou,
                    }
                }
                // Vencido, um instante que voltou, ou a tabela já o tinha
                // vencido: o prazo passou.
                Err(_) => Resultado::Vencida,
            },
        };
        let r = &mut self.rodadas[i];
        match resultado {
            Resultado::Aceita { .. } => {}
            Resultado::Recusada { fechou: false, .. } => {}
            Resultado::Recusada {
                recusa,
                fechou: true,
                ..
            } => r.fontes[indice] = Some(Veredito::Recusada(recusa)),
            Resultado::SemResposta => r.fontes[indice] = Some(Veredito::SemResposta),
            Resultado::Vencida => r.fontes[indice] = Some(Veredito::Vencida),
        }
        let numero = r.numero;
        let fonte = r.registro.fontes()[indice];
        let resolvida = r.fontes[indice].is_some_and(|v| v.resolvida(agora_ms));
        let ultima = indice + 1 == r.registro.fontes().len();
        let fechamento = if resolvida && ultima {
            Some(self.rodadas.swap_remove(i).fechar(agora_ms, deriva_ppm))
        } else {
            None
        };
        Ok(Entrega {
            fonte,
            rodada: numero,
            resultado,
            fechamento,
        })
    }

    /// Quantos pedidos estão abertos: os do serviço e os dos outros.
    pub fn abertos(&self) -> (usize, usize) {
        (self.do_servico.abertos(), self.dos_outros.abertos())
    }

    /// Quantas rodadas estão abertas.
    pub fn rodadas_abertas(&self) -> usize {
        self.rodadas.len()
    }

    /// Larga tudo: as rodadas e os pedidos. Só a suíte, entre casos.
    #[cfg(feature = "modo-teste")]
    pub fn esvaziar(&mut self) {
        while !self.rodadas.is_empty() {
            self.largar(0);
        }
        self.do_servico = Pedidos::novo();
        self.dos_outros = Pedidos::novo();
    }
}
