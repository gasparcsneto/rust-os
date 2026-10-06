//! As mensagens entre titulares: as caixas, os estados, as cotas e os
//! nonces — sem relógio nem kernel.
//!
//! A conta mora aqui pelo mesmo motivo da do arrendamento: é a parte que se
//! testa inteira no hospedeiro. O kernel põe o relógio, deriva o remetente
//! da sessão autenticada, resolve o destinatário — o papel dele é o recurso
//! da decisão — e grava cada transição na auditoria.
//!
//! # O que esta tabela garante
//!
//! - **O remetente é argumento de quem chama, e nunca do pedido**: a tabela
//!   não lê parâmetro nenhum. Quem a chama — o kernel — passa o titular da
//!   sessão que pediu.
//! - **Uma mensagem é um recurso**, com id dado aqui, monotônico, e versão
//!   que sobe a cada transição. Um id não se repete, nem depois que a
//!   mensagem sai.
//! - **Ler não consome.** A mensagem sai da caixa só com a confirmação
//!   (`ack`) de quem a recebeu: uma resposta perdida no caminho se relê, com
//!   os mesmos ids — entrega pelo menos uma vez, com id para descartar a
//!   duplicata.
//! - **Ordem**: a leitura devolve a caixa em ordem crescente de id, que é a
//!   ordem de aceitação.
//! - **Replay**: cada canal — a sessão de onde os pedidos vêm — tem um
//!   `nonce` que só cresce. O mesmo nonce com o mesmo conteúdo é o reenvio
//!   de um pedido que já passou: devolve o mesmo id e não cria nada. Um
//!   nonce velho, ou o mesmo com outro conteúdo, é recusado.
//! - **Cotas**: corpo, caixa, remetente e total. A recusa não gasta id nem
//!   nonce.
//! - **Revogação**: anular um titular tira todas as mensagens vivas que ele
//!   mandou e todas as que ele tinha para receber.
//! - **Vazamento**: tudo o que se consulta por id confere a posse — quem
//!   mandou ou quem recebe —, e o id alheio responde como o inexistente.
//! - **O corpo não é interpretado.** É texto opaco, guardado e devolvido; ao
//!   sair da tabela, é zerado.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use blake2::{Blake2s256, Digest};

use crate::codigo::Codigo;

/// O maior corpo, em bytes.
pub const MAIOR_CORPO: usize = 512;
/// Quantas mensagens vivas há, no total — a memória que as mensagens podem
/// ocupar. Da imagem, e não da política: não depende de papel.
pub const MAIS_NO_TOTAL: usize = 128;
/// O teto da cota de um remetente que a política aceita: um quarto do
/// total, para que um papel não tome a tabela inteira.
pub const TETO_POR_REMETENTE: usize = 32;
/// O teto da cota de uma caixa que a política aceita: metade do total.
pub const TETO_POR_CAIXA: usize = 64;

/// As cotas de mensagens de um papel: quantas vivas um titular dele tem
/// como remetente, somando todas as caixas, e quantas a caixa dele guarda.
///
/// Vêm da política — a linha `mensagens <papel> <por remetente> <por
/// caixa>` —, de 1 até os tetos [`TETO_POR_REMETENTE`] e
/// [`TETO_POR_CAIXA`]; sem a linha, [`COTAS_PADRAO`]. O total
/// ([`MAIS_NO_TOTAL`]) vale por cima de qualquer cota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cotas {
    pub por_remetente: usize,
    pub por_caixa: usize,
}

/// As cotas de um papel que não declara as suas.
pub const COTAS_PADRAO: Cotas = Cotas {
    por_remetente: 8,
    por_caixa: 32,
};

/// As cotas de quem não tem papel: nenhuma. Quem não tem papel não chega a
/// mandar — a decisão o recusa antes —, e se chegasse, não guardaria nada.
pub const SEM_COTA: Cotas = Cotas {
    por_remetente: 0,
    por_caixa: 0,
};
/// O prazo de uma mensagem que não diz o seu: dez minutos.
pub const PRAZO_PADRAO_MS: u64 = 10 * 60 * 1000;
/// O maior prazo: uma hora.
pub const MAIOR_PRAZO_MS: u64 = 60 * 60 * 1000;
/// Quantos nonces recentes de cada canal ficam lembrados, para o reenvio.
pub const JANELA_DE_NONCES: usize = 32;
/// Quantas mensagens que saíram ficam lembradas, para a consulta do estado.
pub const LAPIDES: usize = 64;

/// De quem é uma caixa: a identidade, e não a sessão. Duas sessões do mesmo
/// titular veem a mesma caixa; dois titulares, nunca.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dono {
    /// A serial: o canal de controle, sem chave.
    Serial,
    /// Um agente, pela chave que provou o aperto.
    Agente([u8; 32]),
    /// Uma pessoa, pelo identificador do registro.
    Pessoa([u8; 8]),
    /// Um administrador, pela chave — que nunca abre sessão: age só por
    /// operação administrativa, com prova.
    Administrador([u8; 32]),
}

/// Por onde os pedidos chegam: a janela de nonces é de cada canal. Uma
/// sessão nova começa a contar de novo — os quadros de uma sessão não se
/// repetem em outra, que tem outras chaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Canal {
    /// A sessão de um canal do agente: a serial (0) ou uma porta.
    Sessao(u8),
    /// Uma sessão de pessoa.
    Pessoa([u8; 8]),
    /// As operações administrativas de um administrador.
    Administrador([u8; 32]),
    /// Um processo, pelo identificador do fio — que nunca se repete. Os
    /// pedidos de um programa não contam na janela do agente que o lançou:
    /// um processo que gastasse nonces da porta do agente recusaria os
    /// envios dele, ou os do agente que entrasse depois naquela porta.
    Processo(u64),
}

/// Onde uma mensagem está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Aceita, na caixa, e ninguém a leu ainda.
    Pendente,
    /// Lida ao menos uma vez; continua na caixa até o `ack`.
    Entregue,
    /// O destinatário confirmou: saiu da caixa.
    Confirmada,
    /// O remetente cancelou antes da primeira leitura.
    Cancelada,
    /// Um dos titulares foi revogado.
    Anulada,
    /// O prazo venceu.
    Expirada,
    /// Um administrador a tirou, com prova.
    Purgada,
}

impl Estado {
    /// O nome, como o relatório e a auditoria o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Estado::Pendente => "pending",
            Estado::Entregue => "delivered",
            Estado::Confirmada => "acked",
            Estado::Cancelada => "canceled",
            Estado::Anulada => "voided",
            Estado::Expirada => "expired",
            Estado::Purgada => "purged",
        }
    }

    /// Um estado de onde não se sai: o corpo já foi apagado.
    pub const fn final_(self) -> bool {
        !matches!(self, Estado::Pendente | Estado::Entregue)
    }
}

/// Uma mensagem viva.
#[derive(Debug)]
pub struct Mensagem {
    pub id: u64,
    pub de: Dono,
    pub para: Dono,
    /// O texto, opaco: guardado e devolvido, nunca interpretado.
    corpo: Vec<u8>,
    pub criada_ms: u64,
    pub expira_ms: u64,
    pub estado: Estado,
    pub versao: u64,
}

impl Mensagem {
    /// O corpo, como texto. Só entra texto: [`Caixas::enviar`] recebe
    /// `&str`.
    pub fn corpo(&self) -> &str {
        core::str::from_utf8(&self.corpo).unwrap_or("")
    }
}

impl Drop for Mensagem {
    /// O corpo sai da memória zerado: uma mensagem que acabou não deixa o
    /// texto no heap para o próximo dono do bloco.
    fn drop(&mut self) {
        crate::sigiloso::zerar_bloco(&mut self.corpo);
    }
}

/// O que se lê de uma mensagem: uma cópia, para a resposta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lida {
    pub id: u64,
    pub de: Dono,
    /// A cópia do corpo, que se apaga ao sair — ver [`crate::sigiloso`].
    pub corpo: crate::sigiloso::Corpo,
    pub criada_ms: u64,
    pub expira_ms: u64,
    pub estado: Estado,
    pub versao: u64,
}

/// O que sobra de uma mensagem que saiu: quem, onde parou, em que versão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lapide {
    pub id: u64,
    pub de: Dono,
    pub para: Dono,
    pub estado: Estado,
    pub versao: u64,
}

/// Uma mudança de estado, para a auditoria.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transicao {
    pub id: u64,
    pub de: Dono,
    pub para: Dono,
    pub estado: Estado,
    pub versao: u64,
}

/// Uma mensagem como o journal a guarda ao ser criada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gravada<'a> {
    pub id: u64,
    pub de: Dono,
    pub para: Dono,
    pub corpo: &'a [u8],
    pub criada_ms: u64,
    pub expira_ms: u64,
}

impl Mensagem {
    /// Como o journal a guarda.
    pub fn gravada(&self) -> Gravada<'_> {
        Gravada {
            id: self.id,
            de: self.de,
            para: self.para,
            corpo: &self.corpo,
            criada_ms: self.criada_ms,
            expira_ms: self.expira_ms,
        }
    }
}

impl Dono {
    /// Os bytes do titular no journal: um byte de tipo e a chave ou o
    /// identificador.
    pub fn bytes(&self) -> Vec<u8> {
        let (tipo, resto): (u8, &[u8]) = match self {
            Dono::Serial => (0, &[]),
            Dono::Agente(k) => (1, k),
            Dono::Pessoa(p) => (2, p),
            Dono::Administrador(k) => (3, k),
        };
        let mut v = Vec::with_capacity(1 + resto.len());
        v.push(tipo);
        v.extend_from_slice(resto);
        v
    }

    /// O titular de volta, dos bytes de [`Dono::bytes`].
    pub fn de_bytes(b: &[u8]) -> Option<Dono> {
        match b {
            [0] => Some(Dono::Serial),
            [1, k @ ..] => Some(Dono::Agente(k.try_into().ok()?)),
            [2, p @ ..] => Some(Dono::Pessoa(p.try_into().ok()?)),
            [3, k @ ..] => Some(Dono::Administrador(k.try_into().ok()?)),
            _ => None,
        }
    }
}

impl Estado {
    /// O número do estado no journal.
    pub const fn codigo(self) -> u8 {
        match self {
            Estado::Pendente => 0,
            Estado::Entregue => 1,
            Estado::Confirmada => 2,
            Estado::Cancelada => 3,
            Estado::Anulada => 4,
            Estado::Expirada => 5,
            Estado::Purgada => 6,
        }
    }

    /// O estado de volta, do número de [`Estado::codigo`].
    pub const fn de_codigo(c: u8) -> Option<Estado> {
        Some(match c {
            0 => Estado::Pendente,
            1 => Estado::Entregue,
            2 => Estado::Confirmada,
            3 => Estado::Cancelada,
            4 => Estado::Anulada,
            5 => Estado::Expirada,
            6 => Estado::Purgada,
            _ => return None,
        })
    }
}

/// O desfecho de um envio aceito.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enviada {
    pub id: u64,
    pub versao: u64,
    /// O mesmo pedido de novo, pelo mesmo nonce: nada foi criado.
    pub duplicata: bool,
}

/// Por que um pedido foi recusado. Em toda recusa, nada mudou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O corpo passa de [`MAIOR_CORPO`].
    CorpoGrande,
    /// Prazo zero, ou além de [`MAIOR_PRAZO_MS`].
    Prazo,
    /// O nonce não é novo neste canal.
    Replay,
    /// O remetente já tem as vivas que a cota do papel dele deixa.
    RemetenteCheio,
    /// A caixa do destinatário já tem as que a cota do papel dele deixa.
    CaixaCheia,
    /// Já há [`MAIS_NO_TOTAL`] vivas.
    TotalCheio,
    /// Não há mensagem com este id para quem pergunta — também a de outro.
    Desconhecida,
    /// A mensagem não está num estado que aceite a operação.
    Estado(Estado),
    /// A versão esperada não é a de agora.
    Versao { esperada: u64, atual: u64 },
    /// A autoridade que o gate decidiu não vale mais no ponto de commit —
    /// uma revogação, uma política nova chegou no meio —: o código e o
    /// motivo da decisão de agora.
    Reconfirmacao(Codigo, &'static str),
}

impl Recusa {
    /// O código da auditoria.
    pub const fn codigo(self) -> Codigo {
        match self {
            Recusa::CorpoGrande | Recusa::Prazo => Codigo::InvalidArgument,
            Recusa::Replay => Codigo::DenyReplay,
            Recusa::RemetenteCheio | Recusa::CaixaCheia | Recusa::TotalCheio => Codigo::DenyPolicy,
            Recusa::Desconhecida => Codigo::DenyResource,
            Recusa::Estado(_) | Recusa::Versao { .. } => Codigo::Conflict,
            Recusa::Reconfirmacao(c, _) => c,
        }
    }

    /// O motivo, para quem pediu e para a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::CorpoGrande => "o corpo passa de 512 bytes",
            Recusa::Prazo => "prazo zero, ou maior que uma hora",
            Recusa::Replay => "o nonce nao e novo nesta sessao",
            Recusa::RemetenteCheio => "o remetente ja tem as pendentes que a cota do papel deixa",
            Recusa::CaixaCheia => "a caixa do destinatario ja tem as que a cota do papel deixa",
            Recusa::TotalCheio => "ja ha 128 mensagens pendentes",
            Recusa::Desconhecida => "nao ha mensagem com este id para quem pede",
            Recusa::Estado(_) => "a mensagem nao esta num estado que aceite isto",
            Recusa::Versao { .. } => "a versao esperada nao e a de agora",
            Recusa::Reconfirmacao(_, m) => m,
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

/// As caixas.
#[derive(Default)]
pub struct Caixas {
    /// As vivas, em ordem de id.
    vivas: Vec<Mensagem>,
    /// O id da próxima. Começa em 1 e só cresce.
    proximo: u64,
    janelas: BTreeMap<Canal, Janela>,
    lapides: VecDeque<Lapide>,
}

/// O resumo do conteúdo de um envio: destinatário e corpo.
fn resumir(para: Dono, corpo: &str) -> [u8; 32] {
    let mut h = Blake2s256::new();
    let (tipo, bytes): (u8, &[u8]) = match &para {
        Dono::Serial => (0, &[]),
        Dono::Agente(k) => (1, k),
        Dono::Pessoa(p) => (2, p),
        Dono::Administrador(k) => (3, k),
    };
    h.update([tipo]);
    h.update(bytes);
    h.update((corpo.len() as u64).to_le_bytes());
    h.update(corpo.as_bytes());
    h.finalize().into()
}

impl Caixas {
    pub fn nova() -> Caixas {
        Caixas {
            proximo: 1,
            ..Caixas::default()
        }
    }

    /// Manda `corpo` de `de` para `para`, pelo `canal`, com o `nonce` do
    /// pedido. `prazo_ms` `None` é o padrão. As `cotas` são as da política:
    /// a de remetente do papel de `de`, a de caixa do papel de `para` — ver
    /// [`crate::Politica::cotas_de_mensagens`]. Também devolve as que
    /// venceram até agora, para a auditoria.
    ///
    /// Vence antes de contar: uma vencida não ocupa a vaga de ninguém.
    #[allow(clippy::too_many_arguments)]
    pub fn enviar(
        &mut self,
        canal: Canal,
        de: Dono,
        para: Dono,
        corpo: &str,
        nonce: u64,
        prazo_ms: Option<u64>,
        agora_ms: u64,
        cotas: Cotas,
    ) -> (Result<Enviada, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        (
            self.enviar_sem_vencer(canal, de, para, corpo, nonce, prazo_ms, agora_ms, cotas),
            vencidas,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enviar_sem_vencer(
        &mut self,
        canal: Canal,
        de: Dono,
        para: Dono,
        corpo: &str,
        nonce: u64,
        prazo_ms: Option<u64>,
        agora_ms: u64,
        cotas: Cotas,
    ) -> Result<Enviada, Recusa> {
        let resumo = resumir(para, corpo);
        // O nonce antes de tudo: o reenvio de um pedido que passou devolve
        // o que ele criou, mesmo que agora a caixa esteja cheia.
        if let Some(j) = self.janelas.get(&canal) {
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
        // As cotas nunca passam dos tetos, nem se quem chama as passasse:
        // o teto é da tabela, e não de quem a usa.
        let por_remetente = cotas.por_remetente.min(TETO_POR_REMETENTE);
        let por_caixa = cotas.por_caixa.min(TETO_POR_CAIXA);
        if self.vivas.iter().filter(|m| m.de == de).count() >= por_remetente {
            return Err(Recusa::RemetenteCheio);
        }
        if self.vivas.iter().filter(|m| m.para == para).count() >= por_caixa {
            return Err(Recusa::CaixaCheia);
        }
        if self.vivas.len() >= MAIS_NO_TOTAL {
            return Err(Recusa::TotalCheio);
        }
        let id = self.proximo;
        self.proximo += 1;
        self.vivas.push(Mensagem {
            id,
            de,
            para,
            corpo: corpo.as_bytes().to_vec(),
            criada_ms: agora_ms,
            expira_ms: agora_ms.saturating_add(prazo),
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

    /// A versão de agora de uma mensagem, viva ou lembrada.
    fn versao_de(&self, id: u64) -> Option<u64> {
        self.vivas
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.versao)
            .or_else(|| self.lapides.iter().find(|l| l.id == id).map(|l| l.versao))
    }

    /// Até `max` mensagens da caixa de `dono`, com id maior que `apos`, em
    /// ordem. Ler **não consome**: a que estava pendente passa a entregue —
    /// e essa transição volta para a auditoria —, e continua na caixa.
    pub fn ler(
        &mut self,
        dono: Dono,
        apos: u64,
        max: usize,
        agora_ms: u64,
    ) -> (Vec<Lida>, Vec<Transicao>) {
        let mut transicoes = self.vencer(agora_ms);
        let mut lidas = Vec::new();
        for m in self
            .vivas
            .iter_mut()
            .filter(|m| m.para == dono && m.id > apos)
            .take(max)
        {
            if m.estado == Estado::Pendente {
                m.estado = Estado::Entregue;
                m.versao += 1;
                transicoes.push(Transicao {
                    id: m.id,
                    de: m.de,
                    para: m.para,
                    estado: m.estado,
                    versao: m.versao,
                });
            }
            lidas.push(Lida {
                id: m.id,
                de: m.de,
                corpo: crate::sigiloso::Corpo::from(m.corpo()),
                criada_ms: m.criada_ms,
                expira_ms: m.expira_ms,
                estado: m.estado,
                versao: m.versao,
            });
        }
        (lidas, transicoes)
    }

    /// A confirmação de quem recebeu: a mensagem entregue sai da caixa.
    pub fn confirmar(
        &mut self,
        dono: Dono,
        id: u64,
        esperada: Option<u64>,
        agora_ms: u64,
    ) -> (Result<Transicao, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        let r = self.transicionar(id, esperada, Estado::Confirmada, |m| {
            if m.para != dono {
                return Err(Recusa::Desconhecida);
            }
            if m.estado != Estado::Entregue {
                return Err(Recusa::Estado(m.estado));
            }
            Ok(())
        });
        let r = r.map_err(|e| self.recusa_lembrada(e, id, |l| l.para == dono));
        (r, vencidas)
    }

    /// O cancelamento de quem mandou, antes da primeira leitura.
    pub fn cancelar(
        &mut self,
        dono: Dono,
        id: u64,
        esperada: Option<u64>,
        agora_ms: u64,
    ) -> (Result<Transicao, Recusa>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        let r = self.transicionar(id, esperada, Estado::Cancelada, |m| {
            if m.de != dono {
                return Err(Recusa::Desconhecida);
            }
            if m.estado != Estado::Pendente {
                return Err(Recusa::Estado(m.estado));
            }
            Ok(())
        });
        let r = r.map_err(|e| self.recusa_lembrada(e, id, |l| l.de == dono));
        (r, vencidas)
    }

    /// Uma mensagem que já saiu, consultada por quem tinha parte nela: o
    /// conflito diz onde ela parou. Para qualquer outro, desconhecida.
    fn recusa_lembrada(&self, recusa: Recusa, id: u64, dele: impl Fn(&Lapide) -> bool) -> Recusa {
        if recusa != Recusa::Desconhecida {
            return recusa;
        }
        match self.lapides.iter().find(|l| l.id == id) {
            Some(l) if dele(l) => Recusa::Estado(l.estado),
            _ => Recusa::Desconhecida,
        }
    }

    /// Leva a mensagem viva `id` a um estado final, se `pode` deixar e a
    /// versão conferir.
    fn transicionar(
        &mut self,
        id: u64,
        esperada: Option<u64>,
        para: Estado,
        pode: impl Fn(&Mensagem) -> Result<(), Recusa>,
    ) -> Result<Transicao, Recusa> {
        let i = self
            .vivas
            .iter()
            .position(|m| m.id == id)
            .ok_or(Recusa::Desconhecida)?;
        pode(&self.vivas[i])?;
        if let Some(v) = esperada
            && v != self.vivas[i].versao
        {
            return Err(Recusa::Versao {
                esperada: v,
                atual: self.vivas[i].versao,
            });
        }
        Ok(self.tirar(i, para))
    }

    /// Tira a viva da posição `i` para o estado final `estado`: o corpo
    /// vai embora zerado, e fica a lápide.
    fn tirar(&mut self, i: usize, estado: Estado) -> Transicao {
        let m = self.vivas.remove(i);
        let t = Transicao {
            id: m.id,
            de: m.de,
            para: m.para,
            estado,
            versao: m.versao + 1,
        };
        if self.lapides.len() >= LAPIDES {
            self.lapides.pop_front();
        }
        self.lapides.push_back(Lapide {
            id: t.id,
            de: t.de,
            para: t.para,
            estado,
            versao: t.versao,
        });
        t
    }

    /// Tira todas as vivas que `sai` aponta, para `estado`.
    fn tirar_se(&mut self, estado: Estado, sai: impl Fn(&Mensagem) -> bool) -> Vec<Transicao> {
        let mut saidas = Vec::new();
        let mut i = 0;
        while i < self.vivas.len() {
            if sai(&self.vivas[i]) {
                saidas.push(self.tirar(i, estado));
            } else {
                i += 1;
            }
        }
        saidas
    }

    /// O estado de uma mensagem agora: vence os prazos antes de responder.
    ///
    /// É o que `message.status` usa. [`Caixas::estado`] só olha a tabela, e
    /// uma mensagem vencida apareceria como pendente até o coletor passar;
    /// a leitura, a confirmação e o cancelamento já vencem antes, e a
    /// consulta faz o mesmo. Devolve também as que venceram, para a
    /// auditoria.
    pub fn consultar(
        &mut self,
        dono: Dono,
        id: u64,
        agora_ms: u64,
    ) -> (Option<(Estado, u64)>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        (self.estado(dono, id), vencidas)
    }

    /// O estado de uma mensagem, para quem tem parte nela. Para qualquer
    /// outro, nada — como a inexistente.
    pub fn estado(&self, dono: Dono, id: u64) -> Option<(Estado, u64)> {
        if let Some(m) = self.vivas.iter().find(|m| m.id == id) {
            return (m.de == dono || m.para == dono).then_some((m.estado, m.versao));
        }
        self.lapides
            .iter()
            .find(|l| l.id == id && (l.de == dono || l.para == dono))
            .map(|l| (l.estado, l.versao))
    }

    /// O titular revogado: as que ele mandou e as que ele ia receber são
    /// anuladas. Nenhuma delas é entregue depois — nem a uma chave que volte
    /// ao registro.
    pub fn anular(&mut self, dono: Dono) -> Vec<Transicao> {
        self.tirar_se(Estado::Anulada, |m| m.de == dono || m.para == dono)
    }

    /// A operação administrativa: uma mensagem, de quem for.
    pub fn purgar(&mut self, id: u64) -> Option<Transicao> {
        let i = self.vivas.iter().position(|m| m.id == id)?;
        Some(self.tirar(i, Estado::Purgada))
    }

    /// A operação administrativa: a caixa inteira de um titular — as vivas
    /// que ele ia receber; as que ele mandou ficam nas caixas dos outros.
    ///
    /// Vence antes: uma mensagem cujo prazo passou é `Expirada`, e não
    /// entra na conta do que o administrador tirou. Devolve as tiradas e as
    /// que venceram, cada lista para a sua auditoria.
    pub fn purgar_caixa(&mut self, dono: Dono, agora_ms: u64) -> (Vec<Transicao>, Vec<Transicao>) {
        let vencidas = self.vencer(agora_ms);
        (self.tirar_se(Estado::Purgada, |m| m.para == dono), vencidas)
    }

    /// As que venceram até `agora_ms`.
    pub fn vencer(&mut self, agora_ms: u64) -> Vec<Transicao> {
        self.tirar_se(Estado::Expirada, |m| m.expira_ms <= agora_ms)
    }

    /// Se o canal tem uma janela de nonces — se já mandou e ainda não foi
    /// esquecido.
    pub fn tem_janela(&self, canal: Canal) -> bool {
        self.janelas.contains_key(&canal)
    }

    /// A sessão do canal acabou: a janela de nonces dela também. A próxima
    /// sessão nesse canal começa a contar do zero.
    pub fn esquecer_canal(&mut self, canal: Canal) {
        self.janelas.remove(&canal);
    }

    /// Todas as sessões acabaram: nenhuma janela de nonces fica.
    pub fn esquecer_janelas(&mut self) {
        self.janelas.clear();
    }

    /// As vivas, em ordem de id.
    pub fn todas(&self) -> impl Iterator<Item = &Mensagem> {
        self.vivas.iter()
    }

    /// A viva `id`, se há — para quem grava o que acabou de ser criado.
    pub fn mensagem(&self, id: u64) -> Option<&Mensagem> {
        self.vivas.iter().find(|m| m.id == id)
    }

    /// Põe de volta uma mensagem criada, como o journal a gravou: pendente,
    /// na versão 1. Os ids só crescem — um id que não passa do último já
    /// visto é um registro fora de ordem, e é recusado.
    ///
    /// As cotas não se conferem de novo: valeram quando ela foi aceita, e
    /// a política em vigor no boot pode ser outra.
    pub fn restaurar(&mut self, gravada: Gravada<'_>) -> Result<(), &'static str> {
        if gravada.id < self.proximo || gravada.id == u64::MAX {
            return Err("id de mensagem fora de ordem");
        }
        if gravada.corpo.len() > MAIOR_CORPO || core::str::from_utf8(gravada.corpo).is_err() {
            return Err("corpo de mensagem gravada invalido");
        }
        self.proximo = gravada.id + 1;
        self.vivas.push(Mensagem {
            id: gravada.id,
            de: gravada.de,
            para: gravada.para,
            corpo: gravada.corpo.to_vec(),
            criada_ms: gravada.criada_ms,
            expira_ms: gravada.expira_ms,
            estado: Estado::Pendente,
            versao: 1,
        });
        Ok(())
    }

    /// Aplica uma transição como o journal a gravou: a viva `id` vai para
    /// `estado` na `versao`, que tem de ser exatamente a seguinte.
    ///
    /// Uma transição para um estado final de uma mensagem que já não está
    /// viva não muda nada e não é erro: a revogação de um titular, reposta
    /// do mesmo journal antes, já a anulou — e o registro dela traz a
    /// mesma anulação. Qualquer outra coisa sobre uma mensagem ausente é
    /// um registro que não confere.
    pub fn aplicar(&mut self, id: u64, estado: Estado, versao: u64) -> Result<(), &'static str> {
        let Some(i) = self.vivas.iter().position(|m| m.id == id) else {
            return if estado.final_() {
                Ok(())
            } else {
                Err("transicao de mensagem que nao existe")
            };
        };
        if versao != self.vivas[i].versao + 1 {
            return Err("versao de mensagem fora de ordem");
        }
        match estado {
            Estado::Pendente => Err("transicao de volta a pendente"),
            Estado::Entregue if self.vivas[i].estado == Estado::Pendente => {
                self.vivas[i].estado = Estado::Entregue;
                self.vivas[i].versao = versao;
                Ok(())
            }
            Estado::Entregue => Err("entrega de mensagem ja entregue"),
            final_ => {
                self.tirar(i, final_);
                Ok(())
            }
        }
    }

    /// As lápides que a tabela guarda, da mais velha à mais nova: o que
    /// uma compactação leva para o `message.status` continuar respondendo.
    pub fn lapides(&self) -> impl Iterator<Item = &Lapide> {
        self.lapides.iter()
    }

    /// O id da próxima mensagem.
    pub fn proximo(&self) -> u64 {
        self.proximo
    }

    /// Repõe uma lápide gravada pela compactação. Ela não pode ser de uma
    /// viva, nem estar num estado que não é final; o anel continua com o
    /// teto.
    pub fn restaurar_lapide(&mut self, l: Lapide) -> Result<(), &'static str> {
        if !l.estado.final_() {
            return Err("lapide de mensagem que nao saiu");
        }
        if self.vivas.iter().any(|m| m.id == l.id) || self.lapides.iter().any(|x| x.id == l.id) {
            return Err("lapide de mensagem repetida");
        }
        if self.lapides.len() >= LAPIDES {
            self.lapides.pop_front();
        }
        self.lapides.push_back(l);
        Ok(())
    }

    /// Fixa o próximo id, gravado pela compactação. Ele nunca volta: um
    /// próximo menor que o de agora é recusado — e o de agora já está acima
    /// de toda viva, porque enviar e restaurar o sobem, então o fixado
    /// também fica.
    pub fn fixar_proximo(&mut self, proximo: u64) -> Result<(), &'static str> {
        if proximo < self.proximo {
            return Err("proximo id de mensagem voltando");
        }
        self.proximo = proximo;
        Ok(())
    }

    /// Quantas vivas há.
    pub fn vivas(&self) -> usize {
        self.vivas.len()
    }

    /// Quantas vivas há para `dono`.
    pub fn na_caixa(&self, dono: Dono) -> usize {
        self.vivas.iter().filter(|m| m.para == dono).count()
    }

    /// Para o invariante da suíte: ids em ordem estrita, nenhum repetido,
    /// todos abaixo do próximo, e nenhuma viva num estado final.
    pub fn coerente(&self) -> bool {
        self.vivas.windows(2).all(|w| w[0].id < w[1].id)
            && self
                .vivas
                .iter()
                .all(|m| m.id < self.proximo && !m.estado.final_())
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::string::String;

    const A: Dono = Dono::Agente([1; 32]);
    const B: Dono = Dono::Agente([2; 32]);
    const C: Dono = Dono::Agente([3; 32]);
    const PA: Canal = Canal::Sessao(1);
    const PC: Canal = Canal::Sessao(3);

    fn manda(
        t: &mut Caixas,
        canal: Canal,
        de: Dono,
        para: Dono,
        nonce: u64,
    ) -> Result<Enviada, Recusa> {
        t.enviar(canal, de, para, "oi", nonce, None, 0, COTAS_PADRAO)
            .0
    }

    fn ids(lidas: &[Lida]) -> Vec<u64> {
        lidas.iter().map(|l| l.id).collect()
    }

    /// Reordenação: a leitura devolve em ordem de aceitação, o cursor
    /// respeita a ordem, e os ids crescem.
    #[test]
    fn a_ordem_e_a_da_aceitacao() {
        let mut t = Caixas::nova();
        let a = manda(&mut t, PA, A, B, 1).unwrap().id;
        let c = manda(&mut t, PC, C, B, 1).unwrap().id;
        let b = manda(&mut t, PA, A, B, 2).unwrap().id;
        assert!(a < c && c < b);
        let (lidas, _) = t.ler(B, 0, 10, 0);
        assert_eq!(ids(&lidas), [a, c, b]);
        let (depois, _) = t.ler(B, a, 10, 0);
        assert_eq!(ids(&depois), [c, b]);
        let (uma, _) = t.ler(B, 0, 1, 0);
        assert_eq!(ids(&uma), [a]);
    }

    /// Duplicação: ler não consome — a releitura devolve os mesmos ids, e
    /// só a primeira leitura é uma transição —; o `ack` tira; o segundo
    /// `ack` é conflito, e não some com outra.
    #[test]
    fn ler_nao_consome_e_o_ack_tira() {
        let mut t = Caixas::nova();
        let id = manda(&mut t, PA, A, B, 1).unwrap().id;
        let (l1, tr1) = t.ler(B, 0, 10, 0);
        assert_eq!(tr1.len(), 1);
        assert_eq!(tr1[0].estado, Estado::Entregue);
        let (l2, tr2) = t.ler(B, 0, 10, 0);
        assert!(tr2.is_empty());
        assert_eq!(l1, l2);
        assert_eq!(&*l1[0].corpo, "oi");
        assert_eq!(l1[0].de, A);
        let v = l1[0].versao;
        assert_eq!(
            t.confirmar(B, id, Some(v + 5), 0).0,
            Err(Recusa::Versao {
                esperada: v + 5,
                atual: v
            })
        );
        let ack = t.confirmar(B, id, Some(v), 0).0.unwrap();
        assert_eq!(ack.estado, Estado::Confirmada);
        assert!(t.ler(B, 0, 10, 0).0.is_empty());
        assert_eq!(
            t.confirmar(B, id, None, 0).0,
            Err(Recusa::Estado(Estado::Confirmada))
        );
        assert_eq!(t.estado(B, id), Some((Estado::Confirmada, v + 1)));
        // Confirmar sem ter lido: conflito, e a mensagem fica.
        let outra = manda(&mut t, PA, A, B, 2).unwrap().id;
        assert_eq!(
            t.confirmar(B, outra, None, 0).0,
            Err(Recusa::Estado(Estado::Pendente))
        );
        assert_eq!(t.na_caixa(B), 1);
    }

    /// Replay: o mesmo nonce com o mesmo pedido é o reenvio — o mesmo id,
    /// nada criado —; com outro conteúdo, ou um nonce velho, recusa. Outro
    /// canal conta à parte; um canal esquecido começa de novo.
    #[test]
    fn o_nonce_impede_o_replay() {
        let mut t = Caixas::nova();
        let e = manda(&mut t, PA, A, B, 5).unwrap();
        assert!(!e.duplicata);
        let de_novo = manda(&mut t, PA, A, B, 5).unwrap();
        assert_eq!((de_novo.id, de_novo.duplicata), (e.id, true));
        assert_eq!(t.vivas(), 1);
        assert_eq!(
            t.enviar(PA, A, B, "outro", 5, None, 0, COTAS_PADRAO).0,
            Err(Recusa::Replay)
        );
        assert_eq!(
            t.enviar(PA, A, C, "oi", 5, None, 0, COTAS_PADRAO).0,
            Err(Recusa::Replay)
        );
        assert_eq!(manda(&mut t, PA, A, B, 4), Err(Recusa::Replay));
        assert_eq!(manda(&mut t, PA, A, B, 0), Err(Recusa::Replay));
        assert_eq!(t.vivas(), 1);
        // O reenvio de um que já saiu continua sendo ele, e não cria outro.
        let (lidas, _) = t.ler(B, 0, 1, 0);
        t.confirmar(B, lidas[0].id, None, 0).0.unwrap();
        assert!(manda(&mut t, PA, A, B, 5).unwrap().duplicata);
        assert_eq!(t.vivas(), 0);
        // Outro canal conta à parte.
        assert!(!manda(&mut t, PC, C, B, 1).unwrap().duplicata);
        // Nonce zero nunca vale, nem no primeiro pedido de um canal.
        assert_eq!(
            manda(&mut t, Canal::Sessao(4), C, B, 0),
            Err(Recusa::Replay)
        );
        // A sessão acabou: a próxima conta do zero.
        t.esquecer_canal(PA);
        assert!(!manda(&mut t, PA, A, B, 1).unwrap().duplicata);
    }

    /// Estouro de cota: corpo, prazo, remetente, caixa e total. A recusa
    /// não gasta id nem nonce.
    #[test]
    fn as_cotas() {
        let mut t = Caixas::nova();
        let grande = "x".repeat(MAIOR_CORPO + 1);
        assert_eq!(
            t.enviar(PA, A, B, &grande, 1, None, 0, COTAS_PADRAO).0,
            Err(Recusa::CorpoGrande)
        );
        let cabe = "x".repeat(MAIOR_CORPO);
        let primeira = t
            .enviar(PA, A, B, &cabe, 1, None, 0, COTAS_PADRAO)
            .0
            .unwrap()
            .id;
        assert_eq!(primeira, 1, "a recusa gastou um id");
        for prazo in [0, MAIOR_PRAZO_MS + 1] {
            assert_eq!(
                t.enviar(PA, A, B, "oi", 2, Some(prazo), 0, COTAS_PADRAO).0,
                Err(Recusa::Prazo)
            );
        }
        assert!(
            t.enviar(PA, A, B, "oi", 2, Some(MAIOR_PRAZO_MS), 0, COTAS_PADRAO)
                .0
                .is_ok()
        );
        // O remetente: 8 vivas, somando caixas.
        for n in 3..=8 {
            let para = if n % 2 == 0 { B } else { C };
            manda(&mut t, PA, A, para, n).unwrap();
        }
        assert_eq!(manda(&mut t, PA, A, C, 9), Err(Recusa::RemetenteCheio));
        // A recusa não gastou o nonce: o 9 ainda vale quando houver vaga.
        let (lidas, _) = t.ler(B, 0, 1, 0);
        t.confirmar(B, lidas[0].id, None, 0).0.unwrap();
        assert!(!manda(&mut t, PA, A, C, 9).unwrap().duplicata);

        // A caixa: 32, de quatro remetentes.
        let mut t = Caixas::nova();
        let alvo = Dono::Pessoa([9; 8]);
        for r in 0..4u8 {
            for n in 1..=8 {
                t.enviar(
                    Canal::Sessao(r),
                    Dono::Agente([r + 10; 32]),
                    alvo,
                    "oi",
                    n,
                    None,
                    0,
                    COTAS_PADRAO,
                )
                .0
                .unwrap();
            }
        }
        assert_eq!(t.na_caixa(alvo), COTAS_PADRAO.por_caixa);
        assert_eq!(
            t.enviar(
                Canal::Sessao(9),
                Dono::Serial,
                alvo,
                "oi",
                1,
                None,
                0,
                COTAS_PADRAO
            )
            .0,
            Err(Recusa::CaixaCheia)
        );

        // O total: 128, de dezesseis remetentes em quatro caixas.
        let mut t = Caixas::nova();
        for r in 0..16u8 {
            let para = Dono::Pessoa([r % 4; 8]);
            for n in 1..=8 {
                t.enviar(
                    Canal::Pessoa([r; 8]),
                    Dono::Agente([r; 32]),
                    para,
                    "oi",
                    n,
                    None,
                    0,
                    COTAS_PADRAO,
                )
                .0
                .unwrap();
            }
        }
        assert_eq!(t.vivas(), MAIS_NO_TOTAL);
        assert_eq!(
            t.enviar(
                Canal::Sessao(9),
                Dono::Serial,
                Dono::Pessoa([99; 8]),
                "oi",
                1,
                None,
                0,
                COTAS_PADRAO
            )
            .0,
            Err(Recusa::TotalCheio)
        );
        assert!(t.coerente());
    }

    /// Entrega após revogação: anular o titular tira o que ele mandou e o
    /// que ele ia receber; a mesma chave de volta encontra a caixa vazia, e
    /// quem ia receber dele não recebe.
    #[test]
    fn a_revogacao_anula() {
        let mut t = Caixas::nova();
        let de_a = manda(&mut t, PA, A, B, 1).unwrap().id;
        let para_a = manda(&mut t, PC, C, A, 1).unwrap().id;
        let de_c = manda(&mut t, PC, C, B, 2).unwrap().id;
        let anuladas = t.anular(A);
        let mut quais: Vec<u64> = anuladas.iter().map(|x| x.id).collect();
        quais.sort();
        assert_eq!(quais, [de_a, para_a]);
        assert!(anuladas.iter().all(|x| x.estado == Estado::Anulada));
        assert!(t.ler(A, 0, 10, 0).0.is_empty());
        assert_eq!(ids(&t.ler(B, 0, 10, 0).0), [de_c]);
        assert_eq!(t.estado(B, de_a), Some((Estado::Anulada, 2)));
    }

    /// Vazamento: um terceiro não lê, não consulta, não confirma e não
    /// cancela — e a resposta é a da mensagem que não existe. Titulares de
    /// tipos diferentes com os mesmos bytes são donos diferentes.
    #[test]
    fn ninguem_alcanca_a_caixa_de_outro() {
        let mut t = Caixas::nova();
        let id = manda(&mut t, PA, A, B, 1).unwrap().id;
        let nenhuma = 999;
        assert!(t.ler(C, 0, 10, 0).0.is_empty());
        assert_eq!(t.estado(C, id), None);
        assert_eq!(t.estado(C, nenhuma), None);
        assert_eq!(t.cancelar(C, id, None, 0).0, Err(Recusa::Desconhecida));
        assert_eq!(t.cancelar(C, nenhuma, None, 0).0, Err(Recusa::Desconhecida));
        t.ler(B, 0, 10, 0);
        assert_eq!(t.confirmar(C, id, None, 0).0, Err(Recusa::Desconhecida));
        assert_eq!(t.confirmar(A, id, None, 0).0, Err(Recusa::Desconhecida));
        // O remetente não confirma pelo destinatário, e o destinatário não
        // cancela pelo remetente.
        assert_eq!(t.cancelar(B, id, None, 0).0, Err(Recusa::Desconhecida));
        let mesma_chave = Dono::Administrador([2; 32]);
        assert!(t.ler(mesma_chave, 0, 10, 0).0.is_empty());
        assert_eq!(t.estado(mesma_chave, id), None);
        // Depois que sai, a lápide também só responde a quem tinha parte.
        t.confirmar(B, id, None, 0).0.unwrap();
        assert_eq!(t.estado(C, id), None);
        assert_eq!(t.confirmar(C, id, None, 0).0, Err(Recusa::Desconhecida));
        assert!(t.estado(A, id).is_some());
    }

    /// Cancelar: só quem mandou, e só antes da primeira leitura.
    #[test]
    fn cancelar_antes_de_ler() {
        let mut t = Caixas::nova();
        let id = manda(&mut t, PA, A, B, 1).unwrap().id;
        let c = t.cancelar(A, id, Some(1), 0).0.unwrap();
        assert_eq!(c.estado, Estado::Cancelada);
        assert!(t.ler(B, 0, 10, 0).0.is_empty());
        let id = manda(&mut t, PA, A, B, 2).unwrap().id;
        t.ler(B, 0, 10, 0);
        assert_eq!(
            t.cancelar(A, id, None, 0).0,
            Err(Recusa::Estado(Estado::Entregue))
        );
        assert_eq!(t.na_caixa(B), 1);
    }

    /// O prazo vence sozinho, e a vencida não é entregue.
    #[test]
    fn o_prazo_vence() {
        let mut t = Caixas::nova();
        let id = t
            .enviar(PA, A, B, "oi", 1, Some(1_000), 0, COTAS_PADRAO)
            .0
            .unwrap()
            .id;
        assert_eq!(t.ler(B, 0, 10, 999).0.len(), 1);
        let (lidas, transicoes) = t.ler(B, 0, 10, 1_000);
        assert!(lidas.is_empty());
        assert_eq!(transicoes[0].estado, Estado::Expirada);
        assert_eq!(transicoes[0].id, id);
        // A padrão: dez minutos.
        let id = manda(&mut t, PA, A, B, 2).unwrap().id;
        assert_eq!(t.vencer(PRAZO_PADRAO_MS - 1).len(), 0);
        // A consulta vence antes de responder: no instante do prazo, a
        // mensagem já é `Expirada`, e a transição volta para a auditoria.
        let (agora, vencidas) = t.consultar(A, id, PRAZO_PADRAO_MS);
        assert_eq!(agora.map(|(e, _)| e), Some(Estado::Expirada));
        assert_eq!(vencidas.len(), 1);
        assert_eq!((vencidas[0].id, vencidas[0].estado), (id, Estado::Expirada));
        // E uma vez: o coletor depois não acha mais nada.
        assert!(t.vencer(PRAZO_PADRAO_MS).is_empty());
    }

    /// A operação administrativa tira uma mensagem, ou uma caixa, de quem
    /// for.
    #[test]
    fn purgar() {
        let mut t = Caixas::nova();
        let um = manda(&mut t, PA, A, B, 1).unwrap().id;
        manda(&mut t, PA, A, B, 2).unwrap();
        manda(&mut t, PC, C, A, 1).unwrap();
        assert_eq!(t.purgar(um).unwrap().estado, Estado::Purgada);
        assert!(t.purgar(um).is_none());
        let dois = manda(&mut t, PA, A, B, 3).unwrap().id;
        // O que B mandou não é da caixa dele: fica na de quem vai ler.
        manda(&mut t, Canal::Sessao(2), B, A, 1).unwrap();
        let (tiradas, vencidas) = t.purgar_caixa(B, 0);
        assert!(vencidas.is_empty());
        assert_eq!(tiradas.len(), 2);
        assert!(tiradas.iter().all(|x| x.estado == Estado::Purgada));
        assert_eq!(tiradas[1].id, dois);
        assert_eq!(t.na_caixa(B), 0);
        // A caixa de outro fica, e a lápide diz o que aconteceu.
        assert_eq!(t.na_caixa(A), 2);
        assert_eq!(t.estado(A, dois).map(|(e, _)| e), Some(Estado::Purgada));
        // Esvaziar uma caixa vazia não tira nada.
        assert!(t.purgar_caixa(B, 0).0.is_empty());
    }

    /// O corpo guardado sai da memória zerado quando a mensagem sai da
    /// tabela — pelo vigia do alocador de [`crate::sigiloso`], que olha o
    /// bloco ao ser devolvido.
    #[test]
    fn o_corpo_guardado_sai_zerado() {
        let _vez = crate::sigiloso::testes::UM_DE_CADA_VEZ
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut t = Caixas::nova();
        let id = t
            .enviar(PA, A, B, "segredo guardado", 1, None, 0, COTAS_PADRAO)
            .0
            .unwrap()
            .id;
        let p = t.vivas[0].corpo.as_ptr();
        let veredito = crate::sigiloso::testes::ao_sair(p, || {
            t.purgar(id).unwrap();
        });
        assert_eq!(veredito, 1);
    }

    /// Esvaziar vence antes: a vencida sai como vencida, e não como tirada
    /// pelo administrador.
    #[test]
    fn esvaziar_vence_antes() {
        let mut t = Caixas::nova();
        let velha = manda(&mut t, PA, A, B, 1).unwrap().id;
        let (tiradas, vencidas) = t.purgar_caixa(B, PRAZO_PADRAO_MS);
        assert!(tiradas.is_empty());
        assert_eq!(
            (vencidas[0].id, vencidas[0].estado),
            (velha, Estado::Expirada)
        );
    }

    /// As cotas vêm de quem chama — da política —, e o teto da tabela vale
    /// por cima delas.
    #[test]
    fn as_cotas_de_quem_chama() {
        let duas = Cotas {
            por_remetente: 2,
            por_caixa: 3,
        };
        let mut t = Caixas::nova();
        let envia = |t: &mut Caixas, canal, de, para, nonce, cotas| {
            t.enviar(canal, de, para, "oi", nonce, None, 0, cotas).0
        };
        // O remetente: duas, e a terceira não.
        envia(&mut t, PA, A, B, 1, duas).unwrap();
        envia(&mut t, PA, A, B, 2, duas).unwrap();
        assert_eq!(
            envia(&mut t, PA, A, C, 3, duas),
            Err(Recusa::RemetenteCheio)
        );
        // A caixa: três, de remetentes diferentes, e a quarta não.
        envia(&mut t, PC, C, B, 1, duas).unwrap();
        assert_eq!(
            envia(&mut t, Canal::Sessao(4), Dono::Serial, B, 1, duas),
            Err(Recusa::CaixaCheia)
        );
        // Sem cota, nada.
        assert_eq!(
            envia(
                &mut t,
                Canal::Sessao(5),
                Dono::Agente([5; 32]),
                C,
                1,
                SEM_COTA
            ),
            Err(Recusa::RemetenteCheio)
        );
        // Uma cota além do teto vale o teto.
        let demais = Cotas {
            por_remetente: 1000,
            por_caixa: 1000,
        };
        let mut t = Caixas::nova();
        for n in 1..=TETO_POR_REMETENTE as u64 {
            envia(&mut t, PA, A, B, n, demais).unwrap();
        }
        assert_eq!(
            envia(&mut t, PA, A, C, 100, demais),
            Err(Recusa::RemetenteCheio)
        );
    }

    /// Mandar vence antes de contar: a vencida não ocupa a vaga de ninguém.
    #[test]
    fn a_vencida_nao_ocupa_a_cota() {
        let uma = Cotas {
            por_remetente: 1,
            por_caixa: 1,
        };
        let mut t = Caixas::nova();
        t.enviar(PA, A, B, "oi", 1, Some(10), 0, uma).0.unwrap();
        assert_eq!(
            t.enviar(PA, A, B, "oi", 2, None, 9, uma).0,
            Err(Recusa::RemetenteCheio)
        );
        let (r, vencidas) = t.enviar(PA, A, B, "oi", 2, None, 10, uma);
        assert!(r.is_ok());
        assert_eq!(vencidas.len(), 1);
    }

    /// Os ids não voltam: o que saiu não é reusado.
    #[test]
    fn os_ids_so_crescem() {
        let mut t = Caixas::nova();
        let um = manda(&mut t, PA, A, B, 1).unwrap().id;
        t.cancelar(A, um, None, 0).0.unwrap();
        let dois = manda(&mut t, PA, A, B, 2).unwrap().id;
        assert!(dois > um);
        assert!(t.coerente());
    }

    /// O que o journal guarda de uma tabela: as criadas e as transições, na
    /// ordem em que aconteceram — como o kernel as grava.
    #[derive(Default)]
    struct Gravacao {
        eventos: Vec<Evento>,
    }

    enum Evento {
        Criada {
            id: u64,
            de: Dono,
            para: Dono,
            corpo: Vec<u8>,
            criada_ms: u64,
            expira_ms: u64,
        },
        Transicao(u64, Estado, u64),
    }

    impl Gravacao {
        fn criada(&mut self, t: &Caixas, id: u64) {
            let g = t.mensagem(id).unwrap().gravada();
            self.eventos.push(Evento::Criada {
                id: g.id,
                de: g.de,
                para: g.para,
                corpo: g.corpo.to_vec(),
                criada_ms: g.criada_ms,
                expira_ms: g.expira_ms,
            });
        }
        fn transicoes(&mut self, ts: &[Transicao]) {
            for t in ts {
                self.eventos
                    .push(Evento::Transicao(t.id, t.estado, t.versao));
            }
        }
        fn repor(&self) -> Result<Caixas, &'static str> {
            let mut t = Caixas::nova();
            for e in &self.eventos {
                match e {
                    Evento::Criada {
                        id,
                        de,
                        para,
                        corpo,
                        criada_ms,
                        expira_ms,
                    } => t.restaurar(Gravada {
                        id: *id,
                        de: *de,
                        para: *para,
                        corpo,
                        criada_ms: *criada_ms,
                        expira_ms: *expira_ms,
                    })?,
                    Evento::Transicao(id, estado, versao) => t.aplicar(*id, *estado, *versao)?,
                }
            }
            Ok(t)
        }
    }

    /// Uma viva, campo a campo.
    type Linha = (u64, Dono, Dono, String, u64, u64, Estado, u64);

    /// O retrato de uma tabela, para comparar duas.
    fn retrato(t: &Caixas) -> Vec<Linha> {
        t.vivas
            .iter()
            .map(|m| {
                (
                    m.id,
                    m.de,
                    m.para,
                    String::from(m.corpo()),
                    m.criada_ms,
                    m.expira_ms,
                    m.estado,
                    m.versao,
                )
            })
            .collect()
    }

    /// Repor as criadas e as transições, na ordem, dá a mesma tabela: as
    /// mesmas vivas, nos mesmos estados e versões, os mesmos prazos — e o
    /// A base de uma compactação repõe a mesma tabela: as lápides, as
    /// vivas — pendentes ou entregues — e o próximo id. O `message.status`
    /// de uma que saiu continua dizendo onde ela parou, e nenhum id se
    /// repete depois.
    #[test]
    fn a_base_repoe_a_mesma_tabela() {
        let mut t = Caixas::nova();
        let mut ids = Vec::new();
        for n in 1..=6 {
            let e = t
                .enviar(PA, A, B, "corpo", n, Some(5_000 * n), 1_000, COTAS_PADRAO)
                .0
                .unwrap();
            ids.push(e.id);
        }
        t.ler(B, 0, 3, 1_000);
        t.confirmar(B, ids[0], None, 1_000).0.unwrap();
        t.cancelar(A, ids[4], None, 1_000).0.unwrap();
        t.purgar(ids[5]).unwrap();

        let mut base = Caixas::nova();
        for l in t.lapides() {
            base.restaurar_lapide(*l).unwrap();
        }
        for m in t.todas() {
            base.restaurar(m.gravada()).unwrap();
            if m.estado == Estado::Entregue {
                base.aplicar(m.id, Estado::Entregue, m.versao).unwrap();
            }
        }
        base.fixar_proximo(t.proximo()).unwrap();
        assert_eq!(retrato(&base), retrato(&t));
        assert!(base.coerente());
        for &id in &ids {
            assert_eq!(base.estado(A, id), t.estado(A, id), "{id}");
        }
        assert_eq!(base.proximo(), t.proximo());

        // O que a base não aceita: uma lápide de estado que não é final,
        // uma repetida, o próximo voltando, ou abaixo de uma viva.
        let l = *t.lapides().next().unwrap();
        assert!(base.restaurar_lapide(l).is_err(), "repetida");
        let mut outra = l;
        outra.id = 999;
        outra.estado = Estado::Entregue;
        assert!(base.restaurar_lapide(outra).is_err(), "nao final");
        assert!(base.fixar_proximo(t.proximo() - 1).is_err(), "voltando");
        let mut c = Caixas::nova();
        c.restaurar(t.mensagem(ids[1]).unwrap().gravada()).unwrap();
        assert!(c.fixar_proximo(ids[1]).is_err(), "abaixo de uma viva");
        assert!(c.fixar_proximo(ids[1] + 1).is_ok());

        // As lápides repostas guardam o mesmo teto do anel: passando dele,
        // as mais antigas saem.
        let mut anel = Caixas::nova();
        for id in 1..=(LAPIDES as u64 + 3) {
            anel.restaurar_lapide(Lapide {
                id,
                de: A,
                para: B,
                estado: Estado::Confirmada,
                versao: 2,
            })
            .unwrap();
        }
        let ids: Vec<u64> = anel.lapides().map(|l| l.id).collect();
        assert_eq!(ids.len(), LAPIDES);
        assert_eq!(ids.first(), Some(&4));
        assert_eq!(ids.last(), Some(&(LAPIDES as u64 + 3)));
    }

    /// próximo id continua de onde parou.
    #[test]
    fn repor_o_que_foi_gravado_da_a_mesma_tabela() {
        let mut t = Caixas::nova();
        let mut g = Gravacao::default();
        let mut agora = 1_000;
        let mut ids = Vec::new();
        for n in 1..=6 {
            let (r, venc) = t.enviar(PA, A, B, "corpo", n, Some(5_000 * n), agora, COTAS_PADRAO);
            g.transicoes(&venc);
            let e = r.unwrap();
            g.criada(&t, e.id);
            ids.push(e.id);
            agora += 100;
        }
        let (r, venc) = t.enviar(PC, C, A, "para A", 1, None, agora, COTAS_PADRAO);
        g.transicoes(&venc);
        g.criada(&t, r.unwrap().id);
        // B lê: as pendentes viram entregues.
        let (_, ts) = t.ler(B, 0, 3, agora);
        g.transicoes(&ts);
        // Confirma uma, cancela outra que ainda está pendente.
        let (r, venc) = t.confirmar(B, ids[0], None, agora);
        g.transicoes(&venc);
        g.transicoes(&[r.unwrap()]);
        let (r, venc) = t.cancelar(A, ids[4], None, agora);
        g.transicoes(&venc);
        g.transicoes(&[r.unwrap()]);
        // Vence uma pelo prazo, purga outra, anula o que C mandou.
        agora = 1_000 + 5_000 * 2 + 50;
        g.transicoes(&t.vencer(agora));
        g.transicoes(&[t.purgar(ids[2]).unwrap()]);
        g.transicoes(&t.anular(C));

        let reposta = g.repor().unwrap();
        assert_eq!(retrato(&reposta), retrato(&t));
        assert!(reposta.coerente());
        for &id in &ids {
            assert_eq!(reposta.estado(A, id), t.estado(A, id), "{id}");
        }
        let mut t2 = reposta;
        let novo = t2
            .enviar(PA, A, B, "depois", 99, None, agora, COTAS_PADRAO)
            .0
            .unwrap();
        assert!(novo.id > *ids.iter().max().unwrap());
    }

    /// O que não confere com a ordem gravada é recusado: um id que volta,
    /// uma versão pulada, uma entrega dupla, uma volta a pendente.
    #[test]
    fn repor_fora_de_ordem_e_recusado() {
        let gravada = |id| Gravada {
            id,
            de: A,
            para: B,
            corpo: b"x",
            criada_ms: 0,
            expira_ms: 10,
        };
        let mut t = Caixas::nova();
        t.restaurar(gravada(5)).unwrap();
        assert!(t.restaurar(gravada(5)).is_err());
        assert!(t.restaurar(gravada(3)).is_err());
        assert!(t.aplicar(5, Estado::Entregue, 3).is_err());
        assert!(t.aplicar(5, Estado::Pendente, 2).is_err());
        t.aplicar(5, Estado::Entregue, 2).unwrap();
        assert!(t.aplicar(5, Estado::Entregue, 3).is_err());
        t.aplicar(5, Estado::Confirmada, 3).unwrap();
        // Já final: a mesma anulação de novo, reposta por uma revogação, não
        // é erro; uma entrega de quem não existe, é.
        t.aplicar(5, Estado::Anulada, 4).unwrap();
        assert!(t.aplicar(9, Estado::Entregue, 2).is_err());
        let mut corpo_ruim = gravada(10);
        corpo_ruim.corpo = &[0xFF, 0xFE];
        assert!(t.restaurar(corpo_ruim).is_err());
    }

    /// Os bytes do journal vão e voltam: titulares e estados.
    #[test]
    fn titulares_e_estados_vao_e_voltam() {
        for d in [
            Dono::Serial,
            A,
            Dono::Pessoa([7; 8]),
            Dono::Administrador([9; 32]),
        ] {
            assert_eq!(Dono::de_bytes(&d.bytes()), Some(d));
        }
        // Curto, comprido, ou de um tipo que não existe: nenhum titular.
        assert_eq!(Dono::de_bytes(&[]), None);
        assert_eq!(Dono::de_bytes(&[1, 2, 3]), None);
        assert_eq!(Dono::de_bytes(&[4]), None);
        assert_eq!(Dono::de_bytes(&[0, 0]), None);
        for tipo in 1u8..=3 {
            let tamanho = if tipo == 2 { 8 } else { 32 };
            let mut b = alloc::vec![tipo];
            b.resize(1 + tamanho + 1, 7);
            assert_eq!(Dono::de_bytes(&b), None, "tipo {tipo} com um byte a mais");
            b.truncate(tamanho);
            assert_eq!(Dono::de_bytes(&b), None, "tipo {tipo} com um byte a menos");
        }
        for c in 0..=6 {
            assert_eq!(Estado::de_codigo(c).map(Estado::codigo), Some(c));
        }
        assert_eq!(Estado::de_codigo(7), None);
    }
}
