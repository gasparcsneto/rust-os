//! A atualização A/B simulada, com a energia caindo em cada escrita.
//!
//! A máquina daqui é o disco e o journal: os dois slots, as duas cópias do
//! controle, o estado de atualização do journal. O iniciador e o kernel são
//! as funções do crate — [`controle::planejar`] e [`estado::reconciliar`] —
//! executadas como o iniciador e o kernel as executam: o iniciador desce a
//! conta antes de tentar, o kernel grava o journal antes do controle.
//!
//! Cada roteiro roda primeiro inteiro, para contar as escritas; depois, uma
//! vez para cada escrita e cada jeito de cair nela — antes, rasgada no meio,
//! depois —, e a máquina tem de voltar sozinha, só reiniciando, a um boot
//! com autoridade. Em todo momento:
//!
//! - o piso de geração nunca desce;
//! - a autoridade é só da imagem ativa do journal, e nunca abaixo do piso;
//! - a confirmação é só da candidata, e só numa tentativa;
//! - a imagem ativa do journal está inteira no slot dela;
//! - a versão nova que falha nunca ganha autoridade.

use atualizacao::Slot;
use atualizacao::controle::{self, Boot, Controle, Modo, Plano};
use atualizacao::estado::{Arranque, Decisao, Estado, Imagem, Journal, Reinicio, reconciliar};

/// Uma imagem num slot, e como ela se comporta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Img {
    imagem: Imagem,
    /// O iniciador a carrega: o kernel bate com o manifesto.
    carrega: bool,
    /// O kernel a confere: a assinatura, o pacote, a arquitetura.
    valida: bool,
    /// O kernel chega à reconciliação sem entrar em pânico.
    sobe: bool,
}

fn img(slot: Slot, geracao: u64) -> Img {
    let mut m = [0u8; 32];
    m[0] = slot.byte();
    m[1..9].copy_from_slice(&geracao.to_le_bytes());
    m[31] = 0xA5;
    Img {
        imagem: Imagem::nova(slot, geracao, m, &format!("g{geracao}")).unwrap(),
        carrega: true,
        valida: true,
        sobe: true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Queda {
    Antes,
    Rasgada,
    Depois,
}

#[derive(Debug)]
struct Cortado;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fim {
    Autoridade(Imagem),
    SemPersistencia,
    Recusado(&'static str),
    Parado,
    Reinicia,
}

#[derive(Clone, Debug)]
struct Maquina {
    slots: [Option<Img>; 2],
    copias: [[u8; 512]; 2],
    journal: Option<Estado>,
    persistencia: bool,
    midia_falha: bool,
    passos: u32,
    corte: Option<(u32, Queda)>,
    /// As imagens que ganharam autoridade, em ordem.
    autoridades: Vec<Imagem>,
    /// A imagem com autoridade agora, se o último boot deu autoridade.
    viva: Option<Imagem>,
    /// Quantas confirmações, desfazimentos e recusas houve — para o roteiro
    /// sorteado mostrar que passou por eles.
    confirmacoes: u32,
    desfazimentos: u32,
    recusas: u32,
}

impl Maquina {
    /// Uma máquina recém-provisionada: a imagem no slot A, o controle
    /// apontando para ela, e o journal sem estado de atualização.
    fn provisionada(a: Img) -> Maquina {
        let mut m = Maquina {
            slots: [Some(a), None],
            copias: [[0; 512]; 2],
            journal: None,
            persistencia: true,
            midia_falha: false,
            passos: 0,
            corte: None,
            autoridades: Vec::new(),
            viva: None,
            confirmacoes: 0,
            desfazimentos: 0,
            recusas: 0,
        };
        let c = Estado::linha_de_base(a.imagem).controle(None);
        m.copias[0] = controle::escrever(&Controle { sequencia: 1, ..c });
        m
    }

    fn passo(
        &mut self,
        escrever: impl FnOnce(&mut Self),
        rasgar: impl FnOnce(&mut Self),
    ) -> Result<(), Cortado> {
        self.passos += 1;
        match self.corte {
            Some((n, q)) if n == self.passos => {
                self.corte = None;
                self.viva = None;
                match q {
                    Queda::Antes => {}
                    Queda::Rasgada => rasgar(self),
                    Queda::Depois => escrever(self),
                }
                Err(Cortado)
            }
            _ => {
                escrever(self);
                Ok(())
            }
        }
    }

    fn controle_valido(&self) -> Option<(usize, Controle)> {
        controle::escolher([
            controle::ler(&self.copias[0]),
            controle::ler(&self.copias[1]),
        ])
    }

    fn gravar_controle(&mut self, alvo: &Controle) -> Result<bool, Cortado> {
        if self.midia_falha {
            return Ok(false);
        }
        let vale = self.controle_valido();
        let (onde, novo) = controle::proxima(vale.as_ref().map(|(i, c)| (*i, c)), alvo);
        let bytes = controle::escrever(&novo);
        let mut rasgado = self.copias[onde];
        rasgado[..256].copy_from_slice(&bytes[..256]);
        self.passo(|m| m.copias[onde] = bytes, |m| m.copias[onde] = rasgado)?;
        Ok(true)
    }

    fn escrever_journal(&mut self, e: Estado) -> Result<(), Cortado> {
        if let Some(antes) = self.journal {
            assert!(
                e.piso() >= antes.piso(),
                "o piso desceu: {antes:?} -> {e:?}"
            );
        }
        assert_eq!(
            self.slots[e.ativo.slot.indice()].map(|s| s.imagem),
            Some(e.ativo),
            "a ativa do journal nao esta no slot dela"
        );
        // O registro do journal é atômico — a âncora e o fecho são do
        // `diario`, testados lá —: rasgado, ele não entra.
        self.passo(|m| m.journal = Some(e), |_| {})
    }

    fn carrega(&self, b: &Boot) -> Option<[u8; 32]> {
        let s = self.slots[b.slot.indice()]?;
        (s.carrega && b.manifesto.is_none_or(|x| x == s.imagem.manifesto))
            .then_some(s.imagem.manifesto)
    }

    fn iniciador(&mut self) -> Result<Option<(Slot, Modo, [u8; 32])>, Cortado> {
        let mut valido = self.controle_valido();
        if valido.is_none() {
            let cabecalhos =
                [0, 1].map(|i| self.slots[i].map(|s| (s.imagem.manifesto, s.imagem.geracao)));
            if let Some(c) = controle::sintetizar(cabecalhos)
                && self.gravar_controle(&c)?
            {
                valido = self.controle_valido();
            }
        }
        if let Some((_, c)) = valido {
            let bom = match controle::planejar(&c) {
                Plano::Tentar {
                    gravar,
                    tentativa,
                    bom,
                } => {
                    if self.gravar_controle(&gravar)? {
                        if let Some(m) = self.carrega(&tentativa) {
                            return Ok(Some((tentativa.slot, Modo::Tentativa, m)));
                        }
                        let (_, gravado) = self.controle_valido().expect("acabou de gravar");
                        self.gravar_controle(&controle::carga_recusada(&gravado))?;
                    }
                    bom
                }
                Plano::Bootar(bom) => bom,
            };
            if let Some(m) = self.carrega(&bom) {
                return Ok(Some((bom.slot, bom.modo, m)));
            }
        }
        let geracoes = [0, 1].map(|i| self.slots[i].map(|s| s.imagem.geracao));
        for slot in controle::ordem_sem_controle(geracoes).into_iter().flatten() {
            let b = Boot {
                slot,
                manifesto: None,
                modo: Modo::SemControle,
            };
            if let Some(m) = self.carrega(&b) {
                return Ok(Some((slot, Modo::SemControle, m)));
            }
        }
        Ok(None)
    }

    fn kernel(&mut self, slot: Slot, modo: Modo, manifesto: [u8; 32]) -> Result<Fim, Cortado> {
        let s = self.slots[slot.indice()].expect("o iniciador carregou");
        if !s.sobe {
            // O pânico: numa tentativa, o kernel reinicia; fora dela, para.
            return Ok(if modo == Modo::Tentativa {
                Fim::Reinicia
            } else {
                Fim::Parado
            });
        }
        let arranque = Arranque {
            slot,
            modo,
            manifesto,
        };
        let imagem = if s.valida {
            Ok(&s.imagem)
        } else {
            Err("a imagem nao confere")
        };
        let controle = self.controle_valido().map(|(_, c)| c);
        let antes = self.journal;
        let journal = match (self.persistencia, &antes) {
            (false, _) => Journal::Indisponivel,
            (true, None) => Journal::SemEstado,
            (true, Some(e)) => Journal::Com(e),
        };
        let d = reconciliar(Some(&arranque), imagem, journal, controle.as_ref());
        if let Decisao::Confirmar { estado, .. } = d {
            assert_eq!(modo, Modo::Tentativa, "confirmou fora de uma tentativa");
            assert_eq!(antes.and_then(|e| e.candidato), Some(s.imagem));
            assert_eq!(estado.ativo, s.imagem);
        }
        if let Some(e) = d.registra() {
            self.escrever_journal(*e)?;
        }
        match d {
            Decisao::Confirmar { .. } => self.confirmacoes += 1,
            Decisao::Desfazer { .. } => self.desfazimentos += 1,
            Decisao::Recusar { .. } => self.recusas += 1,
            _ => {}
        }
        let gravou = match d.gravar() {
            Some(k) => self.gravar_controle(k)?,
            None => false,
        };
        if d.com_autoridade() {
            let e = self.journal.expect("com autoridade, ha estado");
            assert_eq!(e.ativo, s.imagem, "autoridade fora da ativa: {d:?}");
            assert!(s.imagem.geracao >= e.piso());
            self.autoridades.push(s.imagem);
            self.viva = Some(s.imagem);
            return Ok(Fim::Autoridade(s.imagem));
        }
        Ok(match d {
            Decisao::Recusar {
                reinicio: Reinicio::Sim,
                ..
            } => Fim::Reinicia,
            Decisao::Recusar {
                reinicio: Reinicio::SeGravou,
                gravar: Some(_),
                ..
            } if gravou => Fim::Reinicia,
            Decisao::Recusar { motivo, .. } => Fim::Recusado(motivo),
            Decisao::SemPersistencia => Fim::SemPersistencia,
            outra => unreachable!("{outra:?}"),
        })
    }

    fn bootar(&mut self) -> Result<Fim, Cortado> {
        self.viva = None;
        match self.iniciador()? {
            Some((slot, modo, manifesto)) => self.kernel(slot, modo, manifesto),
            None => Ok(Fim::Parado),
        }
    }

    /// Reinicia até um boot que não peça outro reinício. Uma queda no
    /// meio é devolvida a quem chamou.
    fn reiniciar(&mut self) -> Result<Fim, Cortado> {
        for _ in 0..12 {
            match self.bootar()? {
                Fim::Reinicia => continue,
                fim => return Ok(fim),
            }
        }
        panic!("doze boots sem parar de reiniciar: {self:?}");
    }

    /// Reinicia até estabilizar, sem quedas.
    fn estabilizar(&mut self) -> Fim {
        assert!(self.corte.is_none());
        self.reiniciar().expect("sem corte armado")
    }

    /// Escreve uma versão nova no slot inativo — o `update.stage`.
    fn encenar(&mut self, nova: Img) -> Result<Result<(), &'static str>, Cortado> {
        let Some(e) = self.journal else {
            return Ok(Err("sem estado"));
        };
        if self.viva != Some(e.ativo) {
            return Ok(Err("sem autoridade"));
        }
        if e.candidato.is_some() {
            return Ok(Err("ja ha uma versao nova armada"));
        }
        let destino = e.inativo();
        assert_eq!(nova.imagem.slot, destino);
        // O controle diz o journal antes de o slot mudar: o inativo, sem
        // manifesto, não boota no meio da escrita.
        let atual = self.controle_valido().map(|(_, c)| c);
        let alvo = e.controle(atual.as_ref());
        if atual.is_none_or(|a| !a.mesmo_que(&alvo)) && !self.gravar_controle(&alvo)? {
            return Ok(Err("o controle nao gravou"));
        }
        let parcial = Img {
            carrega: false,
            valida: false,
            ..nova
        };
        let i = destino.indice();
        self.passo(
            |m| m.slots[i] = Some(parcial),
            |m| m.slots[i] = Some(parcial),
        )?;
        self.passo(|m| m.slots[i] = Some(nova), |m| m.slots[i] = Some(parcial))?;
        Ok(Ok(()))
    }

    /// A operação de quórum que instala — o `system.update` com
    /// `install`.
    fn instalar(&mut self, manifesto: [u8; 32]) -> Result<Result<(), &'static str>, Cortado> {
        let Some(e) = self.journal else {
            return Ok(Err("sem estado"));
        };
        if self.viva != Some(e.ativo) {
            return Ok(Err("sem autoridade"));
        }
        let Some(s) = self.slots[e.inativo().indice()] else {
            return Ok(Err("o slot inativo esta vazio"));
        };
        if !(s.carrega && s.valida) {
            return Ok(Err("a imagem do slot inativo nao confere"));
        }
        if s.imagem.manifesto != manifesto {
            return Ok(Err("o quorum aprovou outro manifesto"));
        }
        let novo = match e.armar(s.imagem) {
            Ok(n) => n,
            Err(m) => return Ok(Err(m)),
        };
        self.escrever_journal(novo)?;
        let atual = self.controle_valido().map(|(_, c)| c);
        self.gravar_controle(&novo.controle(atual.as_ref()))?;
        Ok(Ok(()))
    }

    /// A operação de quórum que desiste — o `system.update` com `cancel`.
    fn cancelar(&mut self) -> Result<Result<(), &'static str>, Cortado> {
        let Some(e) = self.journal else {
            return Ok(Err("sem estado"));
        };
        if self.viva != Some(e.ativo) {
            return Ok(Err("sem autoridade"));
        }
        let novo = match e.cancelar() {
            Ok(n) => n,
            Err(m) => return Ok(Err(m)),
        };
        self.escrever_journal(novo)?;
        let atual = self.controle_valido().map(|(_, c)| c);
        self.gravar_controle(&novo.controle(atual.as_ref()))?;
        Ok(Ok(()))
    }

    /// O disco e o journal dizem a mesma coisa, e a máquina está de pé na
    /// ativa.
    fn em_ordem(&self) {
        let e = self.journal.expect("estado");
        let (_, c) = self.controle_valido().expect("controle");
        assert!(
            c.mesmo_que(&e.controle(Some(&c))),
            "controle {c:?} != journal {e:?}"
        );
        assert_eq!(self.viva, Some(e.ativo));
        let s = self.slots[e.ativo.slot.indice()].expect("a ativa no slot");
        assert_eq!(s.imagem, e.ativo);
    }
}

const A1: fn() -> Img = || img(Slot::A, 1);
const B2: fn() -> Img = || img(Slot::B, 2);

/// O roteiro inteiro de uma atualização: o primeiro boot, a escrita, a
/// instalação, o boot da versão nova.
fn atualizar(m: &mut Maquina, nova: Img) -> Result<Fim, Cortado> {
    if m.viva.is_none() {
        m.reiniciar()?;
    }
    m.encenar(nova)?.expect("encenar");
    m.instalar(nova.imagem.manifesto)?.expect("instalar");
    m.reiniciar()
}

/// Roda `roteiro` com uma queda em cada escrita, de cada jeito, e devolve
/// as máquinas depois da queda, já estabilizadas.
fn com_quedas(
    roteiro: impl Fn(&mut Maquina) -> Result<Fim, Cortado>,
) -> Vec<(u32, Queda, Maquina)> {
    let mut inteira = Maquina::provisionada(A1());
    roteiro(&mut inteira).expect("sem corte");
    let total = inteira.passos;
    assert!(total > 3, "o roteiro escreve: {total}");
    let mut saidas = Vec::new();
    for n in 1..=total {
        for q in [Queda::Antes, Queda::Rasgada, Queda::Depois] {
            let mut m = Maquina::provisionada(A1());
            m.corte = Some((n, q));
            assert!(roteiro(&mut m).is_err(), "o corte {n} nao caiu");
            let fim = m.estabilizar();
            assert!(
                matches!(fim, Fim::Autoridade(_)),
                "queda {q:?} na escrita {n} de {total}: {fim:?}"
            );
            m.em_ordem();
            saidas.push((n, q, m));
        }
    }
    saidas
}

#[test]
fn a_atualizacao_sem_quedas() {
    let mut m = Maquina::provisionada(A1());
    let fim = atualizar(&mut m, B2()).unwrap();
    assert_eq!(fim, Fim::Autoridade(B2().imagem));
    m.em_ordem();
    let e = m.journal.unwrap();
    assert_eq!(e.piso(), 2);
    let (_, c) = m.controle_valido().unwrap();
    assert_eq!(c.manifesto(Slot::A), None, "a velha nao boota mais");
    // A linha de base, depois a versão nova.
    assert_eq!(m.autoridades, [A1().imagem, B2().imagem]);
    // E a seguinte, de volta ao slot A.
    let fim = atualizar(&mut m, img(Slot::A, 3)).unwrap();
    assert_eq!(fim, Fim::Autoridade(img(Slot::A, 3).imagem));
    m.em_ordem();
}

#[test]
fn a_atualizacao_com_quedas_em_cada_escrita_termina() {
    for (n, q, mut m) in com_quedas(|m| atualizar(m, B2())) {
        // Depois da queda, a máquina está de pé — na velha ou na nova. O
        // operador repete o que faltou, e a atualização termina.
        let e = m.journal.unwrap();
        if e.ativo != B2().imagem {
            assert_eq!(e.ativo, A1().imagem);
            if e.candidato.is_none() {
                let ja_escrita = m.slots[1] == Some(B2());
                if !ja_escrita {
                    m.encenar(B2()).unwrap().expect("encenar de novo");
                }
                m.instalar(B2().imagem.manifesto)
                    .unwrap()
                    .expect("instalar de novo");
            }
            let fim = m.estabilizar();
            assert_eq!(fim, Fim::Autoridade(B2().imagem), "queda {q:?} na {n}");
        }
        m.em_ordem();
        assert_eq!(m.journal.unwrap().piso(), 2);
    }
}

/// Um jeito de a versão nova falhar: o nome, e o que ele estraga.
type Falha = (&'static str, fn(&mut Img));

/// Os jeitos de a versão nova falhar depois de armada.
fn falhas() -> [Falha; 3] {
    [
        ("o iniciador nao carrega", |i| i.carrega = false),
        ("o kernel novo se recusa", |i| i.valida = false),
        ("o kernel novo entra em panico", |i| i.sobe = false),
    ]
}

/// Arma a versão nova e a estraga antes do boot.
fn armar_e_estragar(m: &mut Maquina, estraga: fn(&mut Img)) -> Result<Fim, Cortado> {
    if m.viva.is_none() {
        m.reiniciar()?;
    }
    m.encenar(B2())?.expect("encenar");
    m.instalar(B2().imagem.manifesto)?.expect("instalar");
    if let Some(s) = m.slots[1].as_mut() {
        estraga(s);
    }
    m.reiniciar()
}

#[test]
fn a_versao_nova_que_falha_volta_para_a_velha() {
    for (nome, estraga) in falhas() {
        let mut m = Maquina::provisionada(A1());
        let fim = armar_e_estragar(&mut m, estraga).unwrap();
        assert_eq!(fim, Fim::Autoridade(A1().imagem), "{nome}");
        m.em_ordem();
        let e = m.journal.unwrap();
        assert_eq!(
            (e.ativo, e.candidato, e.piso()),
            (A1().imagem, None, 1),
            "{nome}"
        );
        let (_, c) = m.controle_valido().unwrap();
        assert_eq!(c.manifesto(Slot::B), None, "{nome}");
        assert!(!m.autoridades.contains(&B2().imagem), "{nome}");
    }
}

#[test]
fn a_versao_nova_que_falha_volta_para_a_velha_com_quedas() {
    for (nome, estraga) in falhas() {
        let saidas = com_quedas(|m| armar_e_estragar(m, estraga));
        for (n, q, m) in saidas {
            // Uma queda antes de a versão nova se estragar a deixa inteira
            // e armada: ela boota e se confirma, como deve. Estragada — ou
            // escrita pela metade —, ela nunca tem autoridade.
            if m.slots[1] == Some(B2()) {
                continue;
            }
            let e = m.journal.unwrap();
            assert!(
                !m.autoridades.contains(&B2().imagem),
                "{nome}: {q:?} na {n}"
            );
            assert_eq!(e.ativo, A1().imagem, "{nome}: {q:?} na {n}");
            assert_eq!(e.candidato, None, "{nome}: {q:?} na {n}");
        }
    }
}

#[test]
fn sem_persistencia_a_tentativa_acaba_e_a_velha_espera() {
    let mut m = Maquina::provisionada(A1());
    m.reiniciar().unwrap();
    m.encenar(B2()).unwrap().unwrap();
    m.instalar(B2().imagem.manifesto).unwrap().unwrap();
    m.persistencia = false;
    // A versão nova não abre o journal: a tentativa acaba; a velha sobe
    // sem autoridade, e não decide nada.
    assert_eq!(m.estabilizar(), Fim::SemPersistencia);
    assert!(m.autoridades.iter().all(|i| *i == A1().imagem));
    let e = m.journal.unwrap();
    assert_eq!(e.candidato, Some(B2().imagem), "nada mudou no journal");
    // A persistência volta: a velha registra o desfazimento.
    m.persistencia = true;
    assert_eq!(m.estabilizar(), Fim::Autoridade(A1().imagem));
    m.em_ordem();
    assert_eq!(m.journal.unwrap().candidato, None);
}

#[test]
fn o_controle_perdido_em_cada_ponto_se_refaz_pelo_journal() {
    // O roteiro inteiro, com as duas cópias do controle apagadas depois de
    // cada escrita.
    let mut inteira = Maquina::provisionada(A1());
    atualizar(&mut inteira, B2()).unwrap();
    let total = inteira.passos;
    for n in 1..=total {
        let mut m = Maquina::provisionada(A1());
        m.corte = Some((n, Queda::Depois));
        let _ = atualizar(&mut m, B2());
        m.copias = [[0; 512]; 2];
        let fim = m.estabilizar();
        let e = m.journal.unwrap();
        assert_eq!(
            fim,
            Fim::Autoridade(e.ativo),
            "apagado depois da escrita {n}"
        );
        m.em_ordem();
    }
}

#[test]
fn a_imagem_velha_nao_volta() {
    let mut m = Maquina::provisionada(A1());
    atualizar(&mut m, B2()).unwrap();
    m.em_ordem();
    // Um controle forjado que aponta para a velha, ainda no slot A.
    let (_, c) = m.controle_valido().unwrap();
    let forjado = Controle {
        bom: Slot::A,
        tentativa: None,
        manifestos: [A1().imagem.manifesto, [0; 32]],
        sequencia: c.sequencia + 10,
        ..c
    };
    m.copias[0] = controle::escrever(&forjado);
    assert_eq!(m.estabilizar(), Fim::Autoridade(B2().imagem));
    m.em_ordem();
    // E como tentativa.
    let (_, c) = m.controle_valido().unwrap();
    let forjado = Controle {
        tentativa: Some(Slot::A),
        restantes: 3,
        manifestos: [A1().imagem.manifesto, B2().imagem.manifesto],
        sequencia: c.sequencia + 10,
        ..c
    };
    m.copias[0] = controle::escrever(&forjado);
    assert_eq!(m.estabilizar(), Fim::Autoridade(B2().imagem));
    m.em_ordem();
    assert_eq!(
        m.autoridades.iter().filter(|i| **i == A1().imagem).count(),
        1
    );
    // Instalar a velha: abaixo do piso.
    assert_eq!(
        m.instalar(A1().imagem.manifesto).unwrap(),
        Err("a geracao da versao nova nao e maior que a da ativa")
    );
    // Nem uma imagem nova da mesma geração.
    m.encenar(img(Slot::A, 2)).unwrap().unwrap();
    assert!(
        m.instalar(img(Slot::A, 2).imagem.manifesto)
            .unwrap()
            .is_err()
    );
}

#[test]
fn uma_instalacao_por_vez() {
    let mut m = Maquina::provisionada(A1());
    m.reiniciar().unwrap();
    m.encenar(B2()).unwrap().unwrap();
    m.instalar(B2().imagem.manifesto).unwrap().unwrap();
    // A segunda instalação, e a escrita por cima da armada, são recusadas.
    assert_eq!(
        m.instalar(B2().imagem.manifesto).unwrap(),
        Err("ja ha uma versao nova armada")
    );
    assert_eq!(
        m.encenar(img(Slot::B, 3)).unwrap(),
        Err("ja ha uma versao nova armada")
    );
    // O quórum aprovou um manifesto, e o slot tem outro.
    let mut outra = Maquina::provisionada(A1());
    outra.reiniciar().unwrap();
    outra.encenar(B2()).unwrap().unwrap();
    assert_eq!(
        outra.instalar(img(Slot::B, 3).imagem.manifesto).unwrap(),
        Err("o quorum aprovou outro manifesto")
    );
    // A escrita pela metade não instala.
    let mut metade = Maquina::provisionada(A1());
    metade.reiniciar().unwrap();
    metade.corte = Some((metade.passos + 2, Queda::Antes));
    assert!(metade.encenar(B2()).is_err());
    metade.estabilizar();
    assert_eq!(
        metade.instalar(B2().imagem.manifesto).unwrap(),
        Err("a imagem do slot inativo nao confere")
    );
}

#[test]
fn o_cancelamento_com_quedas_nunca_boota_a_cancelada() {
    let roteiro = |m: &mut Maquina| -> Result<Fim, Cortado> {
        if m.viva.is_none() {
            m.reiniciar()?;
        }
        m.encenar(B2())?.expect("encenar");
        m.instalar(B2().imagem.manifesto)?.expect("instalar");
        m.cancelar()?.expect("cancelar");
        m.reiniciar()
    };
    for (n, q, m) in com_quedas(roteiro) {
        let e = m.journal.unwrap();
        // A queda entre a instalação e o cancelamento deixa a versão nova
        // armada — ela pode bootar e se confirmar, como sem o
        // cancelamento. Depois do cancelamento no journal, nunca.
        if e.ativo == A1().imagem {
            assert!(!m.autoridades.contains(&B2().imagem), "{q:?} na {n}");
        }
    }
    // Sem quedas: a cancelada não boota.
    let mut m = Maquina::provisionada(A1());
    assert_eq!(roteiro(&mut m).unwrap(), Fim::Autoridade(A1().imagem));
    m.em_ordem();
    // O cancelamento entrou no journal e o controle ficou com a tentativa:
    // o iniciador boota a versão nova, que se recusa e devolve.
    let mut m = Maquina::provisionada(A1());
    m.reiniciar().unwrap();
    m.encenar(B2()).unwrap().unwrap();
    m.instalar(B2().imagem.manifesto).unwrap().unwrap();
    let e = m.journal.unwrap().cancelar().unwrap();
    m.journal = Some(e);
    assert_eq!(m.estabilizar(), Fim::Autoridade(A1().imagem));
    m.em_ordem();
    assert!(!m.autoridades.contains(&B2().imagem));
}

#[test]
fn o_disco_que_nao_grava_nao_deixa_a_versao_nova_bootar() {
    let mut m = Maquina::provisionada(A1());
    m.reiniciar().unwrap();
    m.encenar(B2()).unwrap().unwrap();
    m.instalar(B2().imagem.manifesto).unwrap().unwrap();
    m.midia_falha = true;
    // O iniciador não consegue descer a conta: não tenta. A velha desfaz
    // no journal, e não consegue limpar o controle; o próximo boot também
    // não tenta, e segue.
    for _ in 0..3 {
        assert_eq!(m.estabilizar(), Fim::Autoridade(A1().imagem));
    }
    assert_eq!(m.journal.unwrap().candidato, None);
    m.midia_falha = false;
    assert_eq!(m.estabilizar(), Fim::Autoridade(A1().imagem));
    m.em_ordem();
    assert!(!m.autoridades.contains(&B2().imagem));
}

#[test]
fn o_slot_bom_estragado_sem_versao_valida_para() {
    // A ativa estragada, e o outro slot com a velha abaixo do piso: nada
    // tem autoridade, e a máquina não fica em laço.
    let mut m = Maquina::provisionada(A1());
    atualizar(&mut m, B2()).unwrap();
    m.slots[1].as_mut().unwrap().carrega = false;
    let fim = m.estabilizar();
    assert_eq!(fim, Fim::Recusado("a imagem e anterior ao piso"));
    assert_eq!(m.autoridades.last(), Some(&B2().imagem));
    // A ativa reescrita com a mesma imagem — a recuperação — volta.
    m.slots[1] = Some(B2());
    assert_eq!(m.estabilizar(), Fim::Autoridade(B2().imagem));
    m.em_ordem();
}

/// Um gerador congruencial: os roteiros aleatórios se repetem.
struct Sorteio(u64);

impl Sorteio {
    fn ate(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

#[test]
fn roteiros_sorteados_com_quedas_falhas_e_forjas() {
    let mut s = Sorteio(0xD0CE);
    let (mut confirmacoes, mut desfazimentos, mut recusas, mut quedas) = (0, 0, 0, 0);
    for rodada in 0..3000 {
        let mut m = Maquina::provisionada(A1());
        let mut proxima = 2u64;
        // As imagens que passaram a falhar, e quantas autoridades havia
        // quando isso aconteceu.
        let mut estragadas: Vec<(Imagem, usize)> = Vec::new();
        let mut forjou = false;
        for _ in 0..25 {
            if m.corte.is_none() && s.ate(4) == 0 {
                quedas += 1;
                m.corte = Some((m.passos + 1 + s.ate(4) as u32, Queda::Antes));
                m.corte = m.corte.map(|(n, _)| {
                    (
                        n,
                        [Queda::Antes, Queda::Rasgada, Queda::Depois][s.ate(3) as usize],
                    )
                });
            }
            let acao = s.ate(13);
            // O operador só opera numa máquina de pé: sem autoridade, ele
            // reinicia antes.
            if (2..=6).contains(&acao) && m.viva.is_none() && m.reiniciar().is_err() {
                continue;
            }
            let inativo = m.journal.map(|e| e.inativo());
            let _ = match acao {
                0 | 1 => m.reiniciar().map(|_| ()),
                2 | 3 => match inativo {
                    Some(slot) => {
                        // Às vezes uma geração velha, para a instalação
                        // recusar.
                        let g = if s.ate(4) == 0 { 1 } else { proxima };
                        proxima += 1;
                        let nova = img(slot, g);
                        // E às vezes a atualização inteira, de uma vez.
                        if s.ate(2) == 0 {
                            (|| {
                                if m.encenar(nova)?.is_ok()
                                    && m.instalar(nova.imagem.manifesto)?.is_ok()
                                {
                                    m.reiniciar()?;
                                }
                                Ok(())
                            })()
                        } else {
                            m.encenar(nova).map(|_| ())
                        }
                    }
                    None => Ok(()),
                },
                4 | 5 => match inativo.and_then(|slot| m.slots[slot.indice()]) {
                    Some(i) => m.instalar(i.imagem.manifesto).map(|_| ()),
                    None => Ok(()),
                },
                6 => m.cancelar().map(|_| ()),
                7 => {
                    // Uma cópia do controle estragada.
                    let i = s.ate(2) as usize;
                    m.copias[i][s.ate(512) as usize] ^= 1;
                    Ok(())
                }
                8 => {
                    // A versão do slot inativo passa a falhar — se é a
                    // armada, ela não pode mais ganhar autoridade.
                    // O pânico fica de fora depois de uma forja: um
                    // controle forjado e íntegro que aponta o bom para um
                    // kernel em pânico para a máquina — é quem tem o disco
                    // na mão, e contra ele só o Secure Boot.
                    let n = if forjou { 2 } else { 3 };
                    let autoridades = m.autoridades.len();
                    if let Some(slot) = inativo
                        && let Some(i) = m.slots[slot.indice()].as_mut()
                    {
                        falhas()[s.ate(n) as usize].1(i);
                        estragadas.push((i.imagem, autoridades));
                    }
                    Ok(())
                }
                9 => {
                    // Um controle forjado, íntegro, que aponta o bom para o
                    // slot inativo.
                    if let (Some(slot), Some((_, c))) = (inativo, m.controle_valido())
                        && let Some(i) = m.slots[slot.indice()]
                        && i.sobe
                    {
                        forjou = true;
                        let mut manifestos = c.manifestos;
                        manifestos[slot.indice()] = i.imagem.manifesto;
                        let forjado = Controle {
                            bom: slot,
                            tentativa: None,
                            manifestos,
                            sequencia: c.sequencia + 5,
                            ..c
                        };
                        m.copias[s.ate(2) as usize] = controle::escrever(&forjado);
                    }
                    Ok(())
                }
                10 => {
                    m.persistencia = !m.persistencia;
                    Ok(())
                }
                _ => {
                    m.midia_falha = !m.midia_falha;
                    Ok(())
                }
            };
        }
        // O fim: o disco grava, a persistência abre; sem mais quedas, a
        // máquina volta sozinha à ativa do journal.
        m.corte = None;
        m.persistencia = true;
        m.midia_falha = false;
        let fim = m.estabilizar();
        match m.journal {
            Some(e) => {
                assert_eq!(
                    fim,
                    Fim::Autoridade(e.ativo),
                    "rodada {rodada}: controle {:?}, slots {:?}, journal {:?}",
                    m.controle_valido(),
                    m.slots,
                    m.journal
                );
                m.em_ordem();
                // A imagem que passou a falhar nunca mais teve autoridade.
                for (f, desde) in &estragadas {
                    assert!(!m.autoridades[*desde..].contains(f), "rodada {rodada}");
                }
            }
            None => assert!(matches!(fim, Fim::Autoridade(_)), "rodada {rodada}"),
        }
        // O piso de cada autoridade nunca desceu.
        let mut piso = 0;
        for i in &m.autoridades {
            assert!(i.geracao >= piso, "rodada {rodada}: {:?}", m.autoridades);
            piso = i.geracao;
        }
        confirmacoes += m.confirmacoes;
        desfazimentos += m.desfazimentos;
        recusas += m.recusas;
    }
    // Os roteiros passaram pelo que importa, e não só pelo caminho feliz.
    assert!(
        confirmacoes > 500 && desfazimentos > 150 && recusas > 1000 && quedas > 5000,
        "confirmacoes {confirmacoes}, desfazimentos {desfazimentos}, recusas {recusas}, quedas {quedas}"
    );
}
