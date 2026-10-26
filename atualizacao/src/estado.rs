//! O estado da atualização, que o journal guarda; as transições dele; e a
//! reconciliação do boot, que decide o que o kernel faz com o que achou.
//!
//! # O estado
//!
//! Duas coisas: a imagem **ativa** — a que a máquina boota — e, se há, a
//! **candidata** — a versão nova, armada por uma operação de quórum, no
//! outro slot, à espera de bootar e se confirmar.
//!
//! O **piso** de geração é a geração da ativa. Nenhuma imagem abaixo dele
//! ganha autoridade, e uma candidata tem de estar acima dele. O piso mora
//! no journal, e é a âncora do journal no contador do TPM que o protege:
//! voltar o disco a um journal de antes da confirmação é voltar o journal
//! atrás da âncora, que a persistência recusa. Não há um índice de NV para
//! a versão mínima, nem uma segunda custódia: o piso e a troca da ativa
//! entram no **mesmo** registro, que avança o contador uma vez — não há
//! uma janela em que o TPM diga uma coisa e o journal outra.
//!
//! # As transições
//!
//! - [`Estado::linha_de_base`]: o primeiro boot de um slot numa máquina sem
//!   estado de atualização — a imagem que bootou vira a ativa;
//! - [`Estado::armar`]: a operação de quórum que instala uma versão nova;
//! - [`Estado::cancelar`]: a operação de quórum que desiste dela antes do
//!   boot;
//! - [`Estado::confirmar`]: a versão nova bootou numa tentativa e se
//!   validou — vira a ativa, e o piso sobe para ela. **É o ponto de
//!   irreversibilidade**: dali em diante a versão velha está abaixo do piso
//!   e não boota mais;
//! - [`Estado::desfazer`]: a tentativa acabou sem confirmação — a versão
//!   velha continua a ativa, e a nova sai.
//!
//! # A reconciliação
//!
//! [`reconciliar`]: a cada boot, o kernel confere o que o iniciador bootou
//! — o slot, o modo, o manifesto — contra o journal e o controle, e decide.
//! A tabela inteira está na documentação da função.

use crate::controle::{Controle, Falha, Modo, TENTATIVAS};
use crate::manifesto::{MAIOR_VERSAO, versao_valida};
use crate::{Slot, TAM_RESUMO};

/// Uma imagem, como o journal a nomeia: onde está, a geração, o resumo do
/// manifesto e o rótulo da versão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imagem {
    pub slot: Slot,
    pub geracao: u64,
    pub manifesto: [u8; TAM_RESUMO],
    versao: [u8; MAIOR_VERSAO],
    tamanho_da_versao: u8,
}

/// O maior tamanho de uma imagem codificada.
pub const MAIOR_IMAGEM: usize = 1 + 8 + TAM_RESUMO + MAIOR_VERSAO;

impl Imagem {
    /// Uma imagem. `None` com geração zero ou um rótulo fora da regra do
    /// manifesto.
    pub fn nova(
        slot: Slot,
        geracao: u64,
        manifesto: [u8; TAM_RESUMO],
        versao: &str,
    ) -> Option<Imagem> {
        if geracao == 0 || !versao_valida(versao) {
            return None;
        }
        let mut v = [0u8; MAIOR_VERSAO];
        v[..versao.len()].copy_from_slice(versao.as_bytes());
        Some(Imagem {
            slot,
            geracao,
            manifesto,
            versao: v,
            tamanho_da_versao: versao.len() as u8,
        })
    }

    /// O rótulo da versão.
    pub fn versao(&self) -> &str {
        // Só `nova` e `decodificar` fazem uma imagem, e as duas conferem a
        // regra: o rótulo é ASCII.
        core::str::from_utf8(&self.versao[..usize::from(self.tamanho_da_versao)]).unwrap_or("")
    }

    /// Se é a mesma imagem no mesmo slot: o resumo do manifesto nomeia a
    /// imagem inteira — a geração e a versão estão nele.
    pub fn mesma(&self, slot: Slot, manifesto: &[u8; TAM_RESUMO]) -> bool {
        self.slot == slot && self.manifesto == *manifesto
    }

    /// Codifica: `[slot (1), geração (8, LE), manifesto (32), versão]`.
    pub fn codificar(&self) -> ([u8; MAIOR_IMAGEM], usize) {
        let mut b = [0u8; MAIOR_IMAGEM];
        b[0] = self.slot.byte();
        b[1..9].copy_from_slice(&self.geracao.to_le_bytes());
        b[9..41].copy_from_slice(&self.manifesto);
        let n = usize::from(self.tamanho_da_versao);
        b[41..41 + n].copy_from_slice(&self.versao[..n]);
        (b, 41 + n)
    }

    /// Decodifica o que [`Imagem::codificar`] escreveu.
    pub fn decodificar(b: &[u8]) -> Option<Imagem> {
        if b.len() < 42 || b.len() > MAIOR_IMAGEM {
            return None;
        }
        let slot = Slot::do_byte(b[0])?;
        let geracao = u64::from_le_bytes(b[1..9].try_into().ok()?);
        let mut manifesto = [0u8; TAM_RESUMO];
        manifesto.copy_from_slice(&b[9..41]);
        let versao = core::str::from_utf8(&b[41..]).ok()?;
        Imagem::nova(slot, geracao, manifesto, versao)
    }
}

/// O estado da atualização.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estado {
    pub ativo: Imagem,
    pub candidato: Option<Imagem>,
}

impl Estado {
    /// Um estado do journal, conferido: a candidata, se há, no outro slot e
    /// acima do piso. Um registro que diz outra coisa não é um estado.
    pub fn novo(ativo: Imagem, candidato: Option<Imagem>) -> Option<Estado> {
        match candidato {
            Some(c) if c.slot == ativo.slot || c.geracao <= ativo.geracao => None,
            _ => Some(Estado { ativo, candidato }),
        }
    }

    /// Decodifica os dois campos do journal: a ativa, e a candidata ou
    /// nada.
    pub fn dos_campos(ativo: &[u8], candidato: &[u8]) -> Option<Estado> {
        let ativo = Imagem::decodificar(ativo)?;
        let candidato = match candidato {
            [] => None,
            c => Some(Imagem::decodificar(c)?),
        };
        Estado::novo(ativo, candidato)
    }

    /// A máquina sem estado de atualização: a imagem que bootou vira a
    /// ativa.
    pub fn linha_de_base(ativo: Imagem) -> Estado {
        Estado {
            ativo,
            candidato: None,
        }
    }

    /// O piso de geração: a geração da ativa.
    pub const fn piso(&self) -> u64 {
        self.ativo.geracao
    }

    /// O slot que não é o da ativa: o único que recebe uma versão nova.
    pub const fn inativo(&self) -> Slot {
        self.ativo.slot.outro()
    }

    /// Arma `c` como a versão nova.
    pub fn armar(&self, c: Imagem) -> Result<Estado, &'static str> {
        if self.candidato.is_some() {
            return Err("ja ha uma versao nova armada");
        }
        if c.slot == self.ativo.slot {
            return Err("a versao nova tem de estar no slot inativo");
        }
        if c.geracao <= self.piso() {
            return Err("a geracao da versao nova nao e maior que a da ativa");
        }
        Ok(Estado {
            ativo: self.ativo,
            candidato: Some(c),
        })
    }

    /// Desiste da versão nova antes de ela bootar.
    pub fn cancelar(&self) -> Result<Estado, &'static str> {
        self.candidato.ok_or("nao ha versao nova armada")?;
        Ok(Estado::linha_de_base(self.ativo))
    }

    /// A versão nova bootou e se validou: vira a ativa.
    pub fn confirmar(&self) -> Result<Estado, &'static str> {
        let c = self.candidato.ok_or("nao ha versao nova armada")?;
        if c.geracao <= self.piso() {
            return Err("a geracao da versao nova nao e maior que a da ativa");
        }
        Ok(Estado::linha_de_base(c))
    }

    /// A tentativa acabou sem confirmação: a versão nova sai.
    pub fn desfazer(&self) -> Result<Estado, &'static str> {
        self.cancelar()
    }

    /// O controle de boot que diz o mesmo que este estado: o bom é a ativa;
    /// a candidata, se há, em tentativa; o slot de nenhuma das duas, sem
    /// manifesto — não boota.
    ///
    /// A conta de tentativas e a falha vêm de `atual` quando ele já tem a
    /// mesma tentativa armada — regravar o controle não devolve tentativas
    /// gastas —; senão, a conta é cheia. A sequência é de quem grava.
    pub fn controle(&self, atual: Option<&Controle>) -> Controle {
        let mut manifestos = [[0u8; TAM_RESUMO]; 2];
        manifestos[self.ativo.slot.indice()] = self.ativo.manifesto;
        let (tentativa, restantes, falha) = match self.candidato {
            Some(c) => {
                manifestos[c.slot.indice()] = c.manifesto;
                match atual {
                    Some(k)
                        if !k.sintetizado
                            && k.bom == self.ativo.slot
                            && k.tentativa == Some(c.slot)
                            && k.manifestos[c.slot.indice()] == c.manifesto =>
                    {
                        (Some(c.slot), k.restantes, k.falha)
                    }
                    _ => (Some(c.slot), TENTATIVAS, Falha::Nenhuma),
                }
            }
            None => (None, 0, Falha::Nenhuma),
        };
        Controle {
            sequencia: atual.map_or(0, |k| k.sequencia),
            bom: self.ativo.slot,
            tentativa,
            restantes,
            falha,
            manifestos,
            sintetizado: false,
        }
    }
}

/// O que o iniciador contou ao kernel na entrega.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arranque {
    pub slot: Slot,
    pub modo: Modo,
    /// O resumo do manifesto do cabeçalho que o iniciador leu.
    pub manifesto: [u8; TAM_RESUMO],
}

/// O journal, como a reconciliação o vê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Journal<'a> {
    /// A persistência não abriu: o journal não é legível, ou não é
    /// confiável — atrás da âncora, outro TPM, nenhum TPM.
    Indisponivel,
    /// O journal abriu e não tem estado de atualização.
    SemEstado,
    Com(&'a Estado),
}

/// Quando reiniciar depois de uma recusa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reinicio {
    /// Nunca: reiniciar voltaria ao mesmo lugar.
    Nao,
    /// Se o controle foi regravado: o próximo boot vai para outro lugar.
    /// Se a gravação falhou, reiniciar seria um laço.
    SeGravou,
    /// Sempre: é uma tentativa, e o iniciador já desceu a conta dela antes
    /// de bootar — reiniciar não faz laço.
    Sim,
}

/// O que o kernel faz.
///
/// `gravar` é o controle a gravar quando o atual não diz o que o journal
/// diz — `None` quando já diz. Nas decisões que mudam o journal, a ordem é
/// sempre o journal primeiro e o controle depois: o journal decide, e um
/// controle velho o boot seguinte conserta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decisao {
    /// Seguir, com autoridade.
    Seguir { gravar: Option<Controle> },
    /// Registrar a linha de base e seguir.
    LinhaDeBase {
        estado: Estado,
        gravar: Option<Controle>,
    },
    /// Esta é a versão nova, na tentativa, e se validou: registrar a
    /// confirmação e seguir.
    Confirmar {
        estado: Estado,
        gravar: Option<Controle>,
    },
    /// A tentativa acabou sem confirmação: registrar o desfazimento e
    /// seguir com a ativa.
    Desfazer {
        estado: Estado,
        gravar: Option<Controle>,
        motivo: &'static str,
    },
    /// Recusar a autoridade a este boot.
    Recusar {
        motivo: &'static str,
        gravar: Option<Controle>,
        reinicio: Reinicio,
    },
    /// A persistência não abriu, e não é uma tentativa: nada a decidir
    /// sobre a atualização — sem persistência, a autoridade já está
    /// bloqueada.
    SemPersistencia,
    /// O kernel não veio de um slot, e o journal não tem estado de
    /// atualização: nada a proteger, e nada a decidir — a atualização fica
    /// indisponível neste boot, e a autoridade é a de sempre. Com estado no
    /// journal, um kernel de fora de um slot é recusado.
    SemSlot,
}

/// O controle `alvo`, se o `atual` não diz o mesmo.
fn se_difere(alvo: Controle, atual: Option<&Controle>) -> Option<Controle> {
    match atual {
        Some(a) if a.mesmo_que(&alvo) => None,
        _ => Some(alvo),
    }
}

/// Por que a tentativa de `c` acabou, pelo que o controle diz.
fn motivo_do_desfazimento(c: &Imagem, controle: Option<&Controle>) -> &'static str {
    match controle {
        Some(k) if k.tentativa == Some(c.slot) && k.falha != Falha::Nenhuma => k.falha.motivo(),
        Some(k) if k.tentativa == Some(c.slot) && k.restantes == 0 => Falha::Nenhuma.motivo(),
        _ => "o iniciador nao tentou a versao nova",
    }
}

/// A reconciliação do boot.
///
/// - `arranque`: o que o iniciador contou; `None` quando o kernel não veio
///   de um slot (carregado direto, sem o iniciador);
/// - `imagem`: a imagem que bootou, já conferida pelo kernel — a assinatura
///   com uma chave do registro da máquina, a arquitetura, o formato do
///   estado, o pacote —, ou o motivo da recusa;
/// - `journal`: o estado de atualização do journal;
/// - `controle`: o controle que vale agora no disco, se algum.
///
/// A tabela, em ordem:
///
/// 1. fora de slot: recusa, se o journal tem estado de atualização; sem
///    estado, nada a decidir;
/// 2. a imagem não confere: numa tentativa, a tentativa acaba — o controle
///    marca a falha e o boot volta ao bom —; fora dela, se a imagem não é a
///    ativa, o controle volta a dizer o journal e o boot reinicia; se é a
///    própria ativa que não confere, recusa e para;
/// 3. sem persistência: numa tentativa, ela acaba — uma versão nova não se
///    confirma sem o journal —; fora dela, nada a decidir;
/// 4. sem estado de atualização: a linha de base — fora de uma tentativa,
///    que sem estado não tem o que tentar;
///
///    nos dois, a tentativa de um controle sintetizado não conta como
///    tentativa: é o iniciador alternando os slots, e não uma versão nova;
/// 5. a candidata, numa tentativa: confirma; fora de uma tentativa, recusa
///    e reinicia para a tentativa;
/// 6. a ativa: com a tentativa acabada — o modo desfeita, ou a conta a
///    zero —, desfaz; senão segue, com o controle consertado — a armação
///    que uma queda deixou pela metade se completa aqui;
/// 7. outra imagem — abaixo do piso, ou nem ativa nem candidata: recusa; o
///    controle volta a dizer o journal, e o boot reinicia para a ativa.
pub fn reconciliar(
    arranque: Option<&Arranque>,
    imagem: Result<&Imagem, &'static str>,
    journal: Journal<'_>,
    controle: Option<&Controle>,
) -> Decisao {
    let Some(a) = arranque else {
        return match journal {
            Journal::Indisponivel => Decisao::SemPersistencia,
            Journal::SemEstado => Decisao::SemSlot,
            Journal::Com(_) => Decisao::Recusar {
                motivo: "o kernel nao veio de um slot",
                gravar: None,
                reinicio: Reinicio::Nao,
            },
        };
    };
    let em_tentativa = a.modo == Modo::Tentativa;
    // Uma tentativa num controle sintetizado não é de uma versão nova: é o
    // iniciador alternando os slots sem saber qual é o bom.
    let tentativa_de_verdade = em_tentativa && !controle.is_some_and(|k| k.sintetizado);
    let acabar_a_tentativa = |motivo| Decisao::Recusar {
        motivo,
        gravar: controle.map(|c| c.tentativa_encerrada(Falha::ValidacaoRecusada)),
        reinicio: Reinicio::Sim,
    };
    let imagem = match imagem {
        Ok(i) if i.mesma(a.slot, &a.manifesto) => Ok(i),
        Ok(_) => Err("o slot mudou entre o iniciador e o kernel"),
        Err(m) => Err(m),
    };
    let i = match imagem {
        Ok(i) => i,
        Err(motivo) if em_tentativa => return acabar_a_tentativa(motivo),
        Err(motivo) => {
            return match journal {
                Journal::Com(e) if !e.ativo.mesma(a.slot, &a.manifesto) => Decisao::Recusar {
                    motivo,
                    gravar: se_difere(e.controle(controle), controle),
                    reinicio: Reinicio::SeGravou,
                },
                _ => Decisao::Recusar {
                    motivo,
                    gravar: None,
                    reinicio: Reinicio::Nao,
                },
            };
        }
    };
    let e = match journal {
        Journal::Indisponivel if tentativa_de_verdade => {
            return acabar_a_tentativa("a versao nova nao abriu a persistencia");
        }
        Journal::Indisponivel => return Decisao::SemPersistencia,
        Journal::SemEstado if tentativa_de_verdade => {
            return acabar_a_tentativa("o journal nao tem uma versao nova armada");
        }
        Journal::SemEstado => {
            let estado = Estado::linha_de_base(*i);
            return Decisao::LinhaDeBase {
                estado,
                gravar: se_difere(estado.controle(controle), controle),
            };
        }
        Journal::Com(e) => e,
    };
    let candidata = e.candidato.filter(|c| c.mesma(i.slot, &i.manifesto));
    if let Some(c) = candidata {
        if !em_tentativa {
            return Decisao::Recusar {
                motivo: "a versao nova so se confirma numa tentativa",
                gravar: se_difere(e.controle(controle), controle),
                reinicio: Reinicio::SeGravou,
            };
        }
        return match e.confirmar() {
            Ok(estado) if estado.ativo == c => Decisao::Confirmar {
                estado,
                gravar: se_difere(estado.controle(controle), controle),
            },
            Ok(_) => acabar_a_tentativa("a confirmacao nao e da versao nova armada"),
            // `Estado::novo` já recusa uma candidata que não está acima do
            // piso; isto é a mesma regra, de novo, no ponto sem volta.
            Err(motivo) => acabar_a_tentativa(motivo),
        };
    }
    if e.ativo.mesma(i.slot, &i.manifesto) {
        if let Some(c) = e.candidato {
            let conta_a_zero = controle.is_some_and(|k| {
                k.tentativa == Some(c.slot)
                    && k.manifestos[c.slot.indice()] == c.manifesto
                    && k.restantes == 0
            });
            if a.modo == Modo::Desfeita || conta_a_zero {
                let motivo = motivo_do_desfazimento(&c, controle);
                return match e.desfazer() {
                    Ok(estado) => Decisao::Desfazer {
                        estado,
                        gravar: se_difere(estado.controle(controle), controle),
                        motivo,
                    },
                    Err(motivo) => Decisao::Recusar {
                        motivo,
                        gravar: None,
                        reinicio: Reinicio::Nao,
                    },
                };
            }
        }
        return Decisao::Seguir {
            gravar: se_difere(e.controle(controle), controle),
        };
    }
    let motivo = if i.geracao < e.piso() {
        "a imagem e anterior ao piso"
    } else {
        "a imagem nao e a ativa nem a versao nova armada"
    };
    Decisao::Recusar {
        motivo,
        gravar: se_difere(e.controle(controle), controle),
        reinicio: if em_tentativa {
            Reinicio::Sim
        } else {
            Reinicio::SeGravou
        },
    }
}

impl Decisao {
    /// Se este boot fica com a autoridade.
    pub const fn com_autoridade(&self) -> bool {
        matches!(
            self,
            Decisao::Seguir { .. }
                | Decisao::LinhaDeBase { .. }
                | Decisao::Confirmar { .. }
                | Decisao::Desfazer { .. }
        )
    }

    /// O estado novo que esta decisão registra no journal, se registra.
    pub const fn registra(&self) -> Option<&Estado> {
        match self {
            Decisao::LinhaDeBase { estado, .. }
            | Decisao::Confirmar { estado, .. }
            | Decisao::Desfazer { estado, .. } => Some(estado),
            _ => None,
        }
    }

    /// O controle a gravar, se há.
    pub const fn gravar(&self) -> Option<&Controle> {
        match self {
            Decisao::Seguir { gravar }
            | Decisao::LinhaDeBase { gravar, .. }
            | Decisao::Confirmar { gravar, .. }
            | Decisao::Desfazer { gravar, .. }
            | Decisao::Recusar { gravar, .. } => gravar.as_ref(),
            Decisao::SemPersistencia | Decisao::SemSlot => None,
        }
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn imagem(slot: Slot, geracao: u64) -> Imagem {
        let mut m = [0u8; TAM_RESUMO];
        m[0] = slot.byte();
        m[1..9].copy_from_slice(&geracao.to_le_bytes());
        Imagem::nova(slot, geracao, m, "v1.0").unwrap()
    }

    #[test]
    fn a_imagem_vai_e_volta_codificada() {
        let i = imagem(Slot::B, 9);
        let (b, n) = i.codificar();
        assert_eq!(Imagem::decodificar(&b[..n]), Some(i));
        assert_eq!(i.versao(), "v1.0");
        assert_eq!(
            Imagem::decodificar(&b[..n - 1]).map(|x| x.versao().len()),
            Some(3)
        );
        assert_eq!(Imagem::decodificar(&b[..41]), None, "sem versao");
        let mut ruim = b;
        ruim[0] = 3;
        assert_eq!(Imagem::decodificar(&ruim[..n]), None);
        let mut zero = b;
        zero[1..9].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(Imagem::decodificar(&zero[..n]), None);
        let mut espaco = b;
        espaco[42] = b' ';
        assert_eq!(Imagem::decodificar(&espaco[..n]), None);
        assert!(Imagem::nova(Slot::A, 1, [0; 32], "").is_none());
    }

    #[test]
    fn o_estado_do_journal_e_conferido() {
        let a = imagem(Slot::A, 3);
        let (ba, na) = a.codificar();
        let b = imagem(Slot::B, 4);
        let (bb, nb) = b.codificar();
        assert_eq!(
            Estado::dos_campos(&ba[..na], &bb[..nb]),
            Some(Estado {
                ativo: a,
                candidato: Some(b)
            })
        );
        assert_eq!(
            Estado::dos_campos(&ba[..na], &[]),
            Some(Estado::linha_de_base(a))
        );
        // A candidata no slot da ativa, ou não acima do piso: não é estado.
        assert_eq!(Estado::novo(a, Some(imagem(Slot::A, 4))), None);
        assert_eq!(Estado::novo(a, Some(imagem(Slot::B, 3))), None);
        assert_eq!(Estado::novo(a, Some(imagem(Slot::B, 2))), None);
    }

    #[test]
    fn as_transicoes_guardam_o_piso() {
        let e = Estado::linha_de_base(imagem(Slot::A, 3));
        assert_eq!(e.piso(), 3);
        assert_eq!(e.inativo(), Slot::B);
        assert!(e.armar(imagem(Slot::A, 4)).is_err(), "o slot ativo");
        assert!(e.armar(imagem(Slot::B, 3)).is_err(), "a mesma geracao");
        assert!(e.armar(imagem(Slot::B, 2)).is_err(), "abaixo do piso");
        assert!(e.cancelar().is_err() && e.confirmar().is_err() && e.desfazer().is_err());
        let armado = e.armar(imagem(Slot::B, 5)).unwrap();
        assert!(armado.armar(imagem(Slot::B, 6)).is_err(), "duas armadas");
        assert_eq!(armado.cancelar(), Ok(e));
        assert_eq!(armado.desfazer(), Ok(e));
        let confirmado = armado.confirmar().unwrap();
        assert_eq!(confirmado.ativo, imagem(Slot::B, 5));
        assert_eq!(confirmado.piso(), 5);
        assert_eq!(confirmado.candidato, None);
        // Depois da confirmação, a velha está abaixo do piso.
        assert!(confirmado.armar(imagem(Slot::A, 3)).is_err());
        assert!(confirmado.armar(imagem(Slot::A, 6)).is_ok());
    }

    #[test]
    fn o_controle_do_estado_nao_devolve_tentativas() {
        let a = imagem(Slot::A, 3);
        let b = imagem(Slot::B, 4);
        let e = Estado::linha_de_base(a).armar(b).unwrap();
        let cheio = e.controle(None);
        assert_eq!(cheio.bom, Slot::A);
        assert_eq!(cheio.tentativa, Some(Slot::B));
        assert_eq!(cheio.restantes, TENTATIVAS);
        assert_eq!(cheio.manifesto(Slot::B), Some(b.manifesto));
        let gasto = Controle {
            restantes: 1,
            falha: Falha::CargaRecusada,
            sequencia: 9,
            ..cheio
        };
        let refeito = e.controle(Some(&gasto));
        assert_eq!(
            (refeito.restantes, refeito.falha),
            (1, Falha::CargaRecusada)
        );
        assert!(refeito.mesmo_que(&gasto));
        // Sem candidata, o outro slot não boota.
        let so = Estado::linha_de_base(a).controle(Some(&gasto));
        assert_eq!(so.tentativa, None);
        assert_eq!(so.manifesto(Slot::B), None);
        assert_eq!(so.manifesto(Slot::A), Some(a.manifesto));
    }

    fn arranque(i: &Imagem, modo: Modo) -> Arranque {
        Arranque {
            slot: i.slot,
            modo,
            manifesto: i.manifesto,
        }
    }

    #[test]
    fn a_tabela_da_reconciliacao() {
        let a = imagem(Slot::A, 3);
        let b = imagem(Slot::B, 4);
        let velha = imagem(Slot::B, 2);
        let base = Estado::linha_de_base(a);
        let armado = base.armar(b).unwrap();
        let k_base = base.controle(None);
        let k_armado = armado.controle(None);

        // 1. Fora de slot.
        assert!(matches!(
            reconciliar(None, Ok(&a), Journal::Com(&base), Some(&k_base)),
            Decisao::Recusar {
                reinicio: Reinicio::Nao,
                ..
            }
        ));
        assert_eq!(
            reconciliar(None, Ok(&a), Journal::Indisponivel, None),
            Decisao::SemPersistencia
        );
        assert_eq!(
            reconciliar(None, Ok(&a), Journal::SemEstado, Some(&k_base)),
            Decisao::SemSlot
        );

        // 2. A imagem não confere.
        assert!(matches!(
            reconciliar(Some(&arranque(&b, Modo::Tentativa)), Err("x"), Journal::Com(&armado), Some(&k_armado)),
            Decisao::Recusar { gravar: Some(k), reinicio: Reinicio::Sim, .. }
                if k.restantes == 0 && k.falha == Falha::ValidacaoRecusada
        ));
        assert!(matches!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Err("x"),
                Journal::Com(&base),
                Some(&k_base)
            ),
            Decisao::Recusar {
                gravar: None,
                reinicio: Reinicio::Nao,
                ..
            }
        ));
        // O slot que mudou entre o iniciador e o kernel é uma imagem que
        // não confere.
        assert!(matches!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Ok(&b),
                Journal::Com(&base),
                Some(&k_base)
            ),
            Decisao::Recusar { .. }
        ));

        // 3. Sem persistência.
        assert!(matches!(
            reconciliar(
                Some(&arranque(&b, Modo::Tentativa)),
                Ok(&b),
                Journal::Indisponivel,
                Some(&k_armado)
            ),
            Decisao::Recusar {
                reinicio: Reinicio::Sim,
                ..
            }
        ));
        assert_eq!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Ok(&a),
                Journal::Indisponivel,
                Some(&k_base)
            ),
            Decisao::SemPersistencia
        );

        // 4. Sem estado.
        assert_eq!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Ok(&a),
                Journal::SemEstado,
                Some(&k_base)
            ),
            Decisao::LinhaDeBase {
                estado: base,
                gravar: None
            }
        );
        assert!(matches!(
            reconciliar(
                Some(&arranque(&b, Modo::Tentativa)),
                Ok(&b),
                Journal::SemEstado,
                Some(&k_armado)
            ),
            Decisao::Recusar {
                reinicio: Reinicio::Sim,
                ..
            }
        ));

        // 5. A candidata.
        let tentativa = Controle {
            restantes: 2,
            ..k_armado
        };
        match reconciliar(
            Some(&arranque(&b, Modo::Tentativa)),
            Ok(&b),
            Journal::Com(&armado),
            Some(&tentativa),
        ) {
            Decisao::Confirmar {
                estado,
                gravar: Some(k),
            } => {
                assert_eq!(estado.ativo, b);
                assert_eq!((k.bom, k.tentativa), (Slot::B, None));
                assert_eq!(k.manifesto(Slot::A), None, "a velha nao boota mais");
            }
            outra => panic!("{outra:?}"),
        }
        assert!(matches!(
            reconciliar(
                Some(&arranque(&b, Modo::SemControle)),
                Ok(&b),
                Journal::Com(&armado),
                None
            ),
            Decisao::Recusar {
                gravar: Some(_),
                reinicio: Reinicio::SeGravou,
                ..
            }
        ));

        // 6. A ativa.
        match reconciliar(
            Some(&arranque(&a, Modo::Desfeita)),
            Ok(&a),
            Journal::Com(&armado),
            Some(&k_armado.tentativa_encerrada(Falha::CargaRecusada)),
        ) {
            Decisao::Desfazer {
                estado,
                gravar: Some(k),
                motivo,
            } => {
                assert_eq!(estado, base);
                assert_eq!(k.manifesto(Slot::B), None);
                assert_eq!(motivo, Falha::CargaRecusada.motivo());
            }
            outra => panic!("{outra:?}"),
        }
        // A conta a zero, mesmo sem o modo, desfaz.
        assert!(matches!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Ok(&a),
                Journal::Com(&armado),
                Some(&Controle {
                    restantes: 0,
                    ..k_armado
                })
            ),
            Decisao::Desfazer { .. }
        ));
        // A armação pela metade: o journal armou, o controle não.
        assert_eq!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Ok(&a),
                Journal::Com(&armado),
                Some(&k_base)
            ),
            Decisao::Seguir {
                gravar: Some(Controle {
                    sequencia: k_base.sequencia,
                    ..k_armado
                })
            }
        );
        // Tudo no lugar: nada a gravar.
        assert_eq!(
            reconciliar(
                Some(&arranque(&a, Modo::Normal)),
                Ok(&a),
                Journal::Com(&base),
                Some(&k_base)
            ),
            Decisao::Seguir { gravar: None }
        );
        // O desfeita sem candidata: só o controle velho a limpar.
        assert!(matches!(
            reconciliar(Some(&arranque(&a, Modo::Desfeita)), Ok(&a), Journal::Com(&base), Some(&k_armado)),
            Decisao::Seguir { gravar: Some(k) } if k.tentativa.is_none()
        ));

        // 7. Outra imagem.
        assert!(matches!(
            reconciliar(Some(&arranque(&velha, Modo::Normal)), Ok(&velha), Journal::Com(&base), Some(&Controle { bom: Slot::B, manifestos: [[0; 32], velha.manifesto], ..k_base })),
            Decisao::Recusar { motivo: "a imagem e anterior ao piso", gravar: Some(k), reinicio: Reinicio::SeGravou } if k.bom == Slot::A
        ));
        // A versão nova que o journal não armou — cancelada, e o controle
        // ainda com a tentativa.
        assert!(matches!(
            reconciliar(Some(&arranque(&b, Modo::Tentativa)), Ok(&b), Journal::Com(&base), Some(&k_armado)),
            Decisao::Recusar { gravar: Some(k), reinicio: Reinicio::Sim, .. } if k.tentativa.is_none()
        ));
    }

    #[test]
    fn so_a_candidata_numa_tentativa_e_confirmada() {
        let a = imagem(Slot::A, 3);
        let b = imagem(Slot::B, 4);
        let estados = [
            Estado::linha_de_base(a),
            Estado::linha_de_base(a).armar(b).unwrap(),
        ];
        let modos = [
            Modo::Normal,
            Modo::Tentativa,
            Modo::Desfeita,
            Modo::SemControle,
        ];
        for e in &estados {
            for &modo in &modos {
                for i in [a, b, imagem(Slot::B, 9), imagem(Slot::A, 1)] {
                    for k in [None, Some(e.controle(None))] {
                        let d = reconciliar(
                            Some(&arranque(&i, modo)),
                            Ok(&i),
                            Journal::Com(e),
                            k.as_ref(),
                        );
                        if let Decisao::Confirmar { estado, .. } = d {
                            assert_eq!(modo, Modo::Tentativa);
                            assert_eq!(Some(i), e.candidato);
                            assert_eq!(estado.ativo, i);
                        }
                        if d.com_autoridade() {
                            // Quem fica com a autoridade é a ativa do
                            // estado registrado.
                            let depois = d.registra().copied().unwrap_or(*e);
                            assert!(depois.ativo.mesma(i.slot, &i.manifesto), "{d:?}");
                            assert!(i.geracao >= e.piso());
                        }
                    }
                }
            }
        }
    }
}
