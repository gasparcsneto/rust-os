//! A cerimônia de pareamento — o autosserviço da Pessoa (D8) —, como conta
//! pura: os estados, as transições, os prazos, o compromisso, os códigos de
//! conferência e o identificador da relação.
//!
//! # O que é
//!
//! Uma Pessoa, autenticada nos dois Dukes, relaciona os dois sem o
//! administrador. Num, o que **aceita**, ela abre uma janela; no outro, o
//! que **inicia** — o que sabe o endereço do primeiro —, ela pede o
//! pareamento. Os dois fazem o Noise IK de sempre, com o prólogo da
//! cerimônia, e cada um mostra à Pessoa um código de 8 dígitos: o que ela
//! tem de digitar no **outro**. Cada lado só grava a relação depois de a
//! Pessoa dele digitar o código que o outro mostra, a senha dela conferir,
//! e o `conferido` do outro chegar.
//!
//! # As contas
//!
//! ```text
//! w   = 16 bytes do aceitante, ao abrir a janela   — vai no anúncio e volta na 1ª mensagem
//! n   = 32 bytes do iniciante                      — comprometido na 1ª mensagem, aberto depois da 2ª
//! c   = BLAKE2s("Duke compromisso do pareamento v1" ‖ n)
//! b   = BLAKE2s("Duke codigo de conferencia v1" ‖ h ‖ n)
//! K_B = u40(b[0..5])  mod 10⁸                      — o aceitante mostra, o iniciante pede
//! K_A = u40(b[5..10]) mod 10⁸                      — o iniciante mostra, o aceitante pede
//! R   = BLAKE2s("Duke relacao do pareamento v1" ‖ h ‖ n)[0..16]
//! ```
//!
//! `h` é o resumo do aperto (`sigilo::Transporte::resumo_do_aperto`), igual
//! nos dois lados e único por sessão.
//!
//! - **Por que o compromisso.** Sem ele, o código seria função só de `h`, e
//!   quem está no meio — respondendo ao iniciante — escolheria a efêmera
//!   dele depois de ver a do iniciante, e testaria até o código bater com o
//!   da sessão que ele abriu com o aceitante. Com o compromisso, `n` só
//!   aparece depois da 2ª mensagem e não muda: quando quem está no meio fixa
//!   a efêmera, ainda não conhece `n`.
//! - **Por que o desafio da janela.** A 1ª mensagem do IK é repetível. Sem
//!   o desafio, uma gravada de outra cerimônia ocuparia a janela; e quem
//!   está no meio abriria várias sessões com o aceitante e levaria adiante
//!   só a que acertasse. O aceitante responde a **uma** 1ª mensagem por
//!   janela, e só à que traz o desafio dela.
//! - **Ninguém escolhe o código nem `R`.** São funções de `h` e de `n`.
//! - **O código não é segredo** — aparece nas telas —, mas não serve fora do
//!   aperto; ele e `n` nunca vão à auditoria, ao log nem ao journal.
//!
//! # O que este módulo não faz
//!
//! Não faz o Noise (o `sigilo`), não fala com a rede nem com o console, não
//! confere a senha, não grava, e não decide nada: o gate decide, antes de
//! abrir e de novo no commit, com a ordem das gravações na mão — ver
//! `kernel/src/pareamento.rs`. Aqui está a ordem da cerimônia, e o que cada
//! passo exige do anterior.

use alloc::string::String;

use blake2::{Blake2s256, Digest};

use crate::sigiloso::zerar;

/// Quanto a janela do aceitante espera o aperto, em ms.
pub const JANELA_MS: u64 = 120_000;

/// Quanto a cerimônia inteira dura, de cada lado, contada da abertura, em
/// ms. Depois disso, nenhum passo vale.
pub const PRAZO_MS: u64 = 180_000;

/// O tamanho do desafio da janela.
pub const TAM_DESAFIO: usize = 16;

/// O tamanho do nonce do iniciante.
pub const TAM_NONCE: usize = 32;

/// O tamanho do compromisso e do resumo do aperto.
pub const TAM_RESUMO: usize = 32;

/// O tamanho do identificador da relação — o de
/// [`crate::dispositivos::TAM_ID`].
pub const TAM_RELACAO: usize = crate::dispositivos::TAM_ID;

/// Os códigos têm 8 dígitos decimais.
pub const MODULO_DO_CODIGO: u64 = 100_000_000;

const ROTULO_DO_COMPROMISSO: &[u8] = b"Duke compromisso do pareamento v1";
const ROTULO_DO_CODIGO: &[u8] = b"Duke codigo de conferencia v1";
const ROTULO_DA_RELACAO: &[u8] = b"Duke relacao do pareamento v1";

fn resumir(pedacos: &[&[u8]]) -> [u8; TAM_RESUMO] {
    let mut h = Blake2s256::new();
    for p in pedacos {
        h.update(p);
    }
    h.finalize().into()
}

/// O compromisso do iniciante com o nonce `n`.
pub fn compromisso(n: &[u8; TAM_NONCE]) -> [u8; TAM_RESUMO] {
    resumir(&[ROTULO_DO_COMPROMISSO, n])
}

/// Os dois códigos de um aperto: `(K_B, K_A)` — o que o aceitante mostra e o
/// que o iniciante mostra.
pub fn codigos(h: &[u8; TAM_RESUMO], n: &[u8; TAM_NONCE]) -> (u32, u32) {
    let mut b = resumir(&[ROTULO_DO_CODIGO, h, n]);
    let u40 = |p: &[u8]| p.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let k_b = (u40(&b[0..5]) % MODULO_DO_CODIGO) as u32;
    let k_a = (u40(&b[5..10]) % MODULO_DO_CODIGO) as u32;
    zerar(&mut b);
    (k_b, k_a)
}

/// O identificador da relação que nasce de um aperto.
pub fn relacao(h: &[u8; TAM_RESUMO], n: &[u8; TAM_NONCE]) -> [u8; TAM_RELACAO] {
    let r = resumir(&[ROTULO_DA_RELACAO, h, n]);
    let mut id = [0u8; TAM_RELACAO];
    id.copy_from_slice(&r[..TAM_RELACAO]);
    id
}

/// Um código como a Pessoa o lê: `1234 5678`.
pub fn texto_do_codigo(k: u32) -> String {
    alloc::format!("{:04} {:04}", k / 10_000, k % 10_000)
}

/// O código que a Pessoa digitou: oito dígitos, com espaços onde ela
/// quiser, e nada mais.
pub fn ler_codigo(texto: &str) -> Option<u32> {
    let mut k: u32 = 0;
    let mut digitos = 0;
    for c in texto.bytes() {
        match c {
            b' ' => {}
            b'0'..=b'9' => {
                digitos += 1;
                if digitos > 8 {
                    return None;
                }
                k = k * 10 + u32::from(c - b'0');
            }
            _ => return None,
        }
    }
    (digitos == 8).then_some(k)
}

/// A comparação de dois valores sem atalho pelo primeiro byte diferente.
fn iguais(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// De que lado da cerimônia este Duke está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lado {
    /// O que abriu a janela (`aceitar`) e responde ao aperto.
    Aceita,
    /// O que conhece o endereço do outro (`parear`) e inicia o aperto.
    Inicia,
}

/// Onde a cerimônia está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// No aceitante, a janela livre, esperando a 1ª mensagem. No iniciante,
    /// a caminho do par: o anúncio, o aperto.
    Aberta,
    /// No aceitante, a 1ª mensagem desta janela respondida: a janela está
    /// ocupada, e falta o nonce. No iniciante, o anúncio recebido e a 1ª
    /// mensagem mandada: falta a 2ª.
    Ocupada,
    /// Os códigos à mostra: falta a Pessoa digitar o do outro.
    Apertada,
    /// O código do outro conferiu: falta a senha.
    CodigoCerto,
    /// O código e a senha da Pessoa daqui conferiram, e o `conferido` saiu.
    ConferidaAqui,
    /// As duas confirmações: a gravação em curso.
    Gravando,
    /// Gravada aqui; falta o `gravado` do outro.
    Gravada,
    /// Acabou.
    Fim(Desfecho),
}

/// Como a cerimônia acabou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Desfecho {
    /// Gravada nos dois: o `gravado` do outro chegou, com o mesmo `R`.
    Concluida,
    /// Gravada aqui; o outro não disse que gravou — o prazo, a conexão. Pode
    /// ter ficado uma meia relação, deste lado.
    GravadaSemAviso,
    /// Gravada aqui, e o outro desistiu depois: quem chama desfaz a relação.
    DesfazerAqui,
    /// Nada gravado.
    Desfeita(Motivo),
}

/// Por que a cerimônia acabou sem gravar — ou por que a gravada não chegou
/// ao fim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motivo {
    /// O prazo venceu.
    Prazo,
    /// O código digitado não é o que o outro mostra.
    CodigoErrado,
    /// A senha não conferiu.
    SenhaErrada,
    /// A Pessoa desistiu.
    Cancelada,
    /// O outro desistiu.
    OutroDesistiu,
    /// A conexão caiu, ou o outro fechou.
    Conexao,
    /// O nonce aberto não é o comprometido.
    CompromissoErrado,
    /// A chave do outro foi revogada aqui.
    ParRevogado,
    /// A chave do outro está suspensa aqui.
    ParSuspenso,
    /// A sessão da Pessoa acabou, ou ela foi revogada.
    FimDaSessao,
    /// A decisão recusou — a política, o papel, o nome, a chave do par —, ao
    /// conhecer a chave do outro ou de novo no commit.
    Recusada,
    /// A máquina está desligando.
    Desligamento,
    /// Um quadro fora do protocolo da cerimônia.
    ForaDoProtocolo,
    /// O `gravado` do outro diz outra relação.
    RelacaoDiferente,
    /// O aperto não fechou: quem respondeu não provou a chave que anunciou.
    ParNaoProvou,
}

impl Motivo {
    /// O motivo, para quem pediu e para a auditoria: curto e em ASCII.
    pub const fn texto(self) -> &'static str {
        match self {
            Motivo::Prazo => "a cerimonia venceu",
            Motivo::CodigoErrado => "o codigo nao conferiu",
            Motivo::SenhaErrada => "a senha nao conferiu",
            Motivo::Cancelada => "cancelada",
            Motivo::OutroDesistiu => "o outro desistiu",
            Motivo::Conexao => "a conexao caiu",
            Motivo::CompromissoErrado => "o compromisso nao conferiu",
            Motivo::ParRevogado => "o par foi revogado",
            Motivo::ParSuspenso => "o par esta suspenso",
            Motivo::FimDaSessao => "a sessao acabou",
            Motivo::Recusada => "a decisao recusou",
            Motivo::Desligamento => "a maquina esta desligando",
            Motivo::ForaDoProtocolo => "quadro fora do protocolo",
            Motivo::RelacaoDiferente => "o outro gravou outra relacao",
            Motivo::ParNaoProvou => "o par nao provou a chave",
        }
    }
}

/// Por que um passo foi recusado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O passo não é deste estado, ou deste lado.
    ForaDeOrdem,
    /// O prazo — da janela ou da cerimônia — já venceu.
    Vencida,
    /// A 1ª mensagem não traz o desafio desta janela. A janela continua.
    DesafioErrado,
    /// A janela já respondeu a uma 1ª mensagem.
    Ocupada,
    /// O nonce não abre o compromisso. A cerimônia acabou.
    CompromissoErrado,
    /// O código não confere. A cerimônia acabou.
    CodigoErrado,
    /// Este lado já digitou, ou o outro já disse `conferido`.
    Repetido,
    /// A cerimônia já acabou.
    Acabou,
    /// O `gravado` do outro diz outra relação.
    RelacaoDiferente,
}

/// Os códigos deste lado: o que ele mostra e o que ele pede.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Codigos {
    mostrar: u32,
    pedir: u32,
}

/// Uma cerimônia, de um lado.
#[derive(Debug)]
pub struct Cerimonia {
    lado: Lado,
    aberta_em: u64,
    estado: Estado,
    /// O desafio da janela: no aceitante, sorteado na abertura; no
    /// iniciante, o que veio no anúncio.
    desafio: Option<[u8; TAM_DESAFIO]>,
    /// No aceitante, o compromisso que veio na 1ª mensagem.
    compromisso: Option<[u8; TAM_RESUMO]>,
    /// No iniciante, o nonce dele; no aceitante, o aberto. Apagado no fim.
    nonce: Option<[u8; TAM_NONCE]>,
    /// A chave do outro: no iniciante, a anunciada, que o aperto prova; no
    /// aceitante, a que a 1ª mensagem provou.
    par: Option<[u8; 32]>,
    codigos: Option<Codigos>,
    relacao: Option<[u8; TAM_RELACAO]>,
    /// O aceitante respondeu a uma 1ª mensagem desta janela.
    respondida: bool,
    /// A Pessoa daqui já digitou — certo ou errado.
    digitada: bool,
    /// O `conferido` do outro chegou.
    conferida_la: bool,
    /// Gravada aqui.
    gravada_aqui: bool,
    /// O `gravado` do outro chegou, com o mesmo `R`.
    gravado_la: bool,
    /// A desistência que chegou durante a gravação: quem grava decide o
    /// desfecho com ela — ver [`Cerimonia::desistir`].
    pendente: Option<Motivo>,
}

impl Cerimonia {
    /// O aceitante abre a janela no instante `agora`, com o desafio
    /// `desafio`, sorteado por quem chama.
    pub fn aceitar(agora: u64, desafio: [u8; TAM_DESAFIO]) -> Cerimonia {
        Cerimonia::nova(Lado::Aceita, agora, Some(desafio), None)
    }

    /// O iniciante começa no instante `agora`, com o nonce `nonce`, sorteado
    /// por quem chama — e comprometido desde já.
    pub fn parear(agora: u64, nonce: [u8; TAM_NONCE]) -> Cerimonia {
        Cerimonia::nova(Lado::Inicia, agora, None, Some(nonce))
    }

    fn nova(
        lado: Lado,
        agora: u64,
        desafio: Option<[u8; TAM_DESAFIO]>,
        nonce: Option<[u8; TAM_NONCE]>,
    ) -> Cerimonia {
        Cerimonia {
            lado,
            aberta_em: agora,
            estado: Estado::Aberta,
            desafio,
            compromisso: None,
            nonce,
            par: None,
            codigos: None,
            relacao: None,
            respondida: false,
            digitada: false,
            conferida_la: false,
            gravada_aqui: false,
            gravado_la: false,
            pendente: None,
        }
    }

    pub fn lado(&self) -> Lado {
        self.lado
    }

    pub fn estado(&self) -> Estado {
        self.estado
    }

    /// Acabou?
    pub fn acabou(&self) -> bool {
        matches!(self.estado, Estado::Fim(_))
    }

    /// O instante da abertura.
    pub fn aberta_em(&self) -> u64 {
        self.aberta_em
    }

    /// Quanto falta para o prazo da cerimônia, em ms.
    pub fn restante_ms(&self, agora: u64) -> u64 {
        PRAZO_MS.saturating_sub(agora.saturating_sub(self.aberta_em))
    }

    fn no_prazo(&self, agora: u64) -> bool {
        agora.saturating_sub(self.aberta_em) < PRAZO_MS
    }

    /// A janela do aceitante ainda aceita a 1ª mensagem: aberta, livre e no
    /// prazo dela.
    pub fn janela_livre(&self, agora: u64) -> bool {
        self.lado == Lado::Aceita
            && self.estado == Estado::Aberta
            && !self.respondida
            && agora.saturating_sub(self.aberta_em) < JANELA_MS
    }

    /// O desafio da janela — no aceitante, para o anúncio.
    pub fn desafio(&self) -> Option<[u8; TAM_DESAFIO]> {
        self.desafio
    }

    /// O compromisso que o iniciante manda na 1ª mensagem.
    pub fn compromisso_a_mandar(&self) -> Option<[u8; TAM_RESUMO]> {
        match (self.lado, self.estado, &self.nonce) {
            (Lado::Inicia, Estado::Aberta | Estado::Ocupada, Some(n)) => Some(compromisso(n)),
            _ => None,
        }
    }

    /// A chave do outro, quando já se sabe.
    pub fn par(&self) -> Option<[u8; 32]> {
        self.par
    }

    /// O identificador da relação, quando já se sabe. Não é segredo: é o
    /// que a relação gravada leva.
    pub fn relacao(&self) -> Option<[u8; TAM_RELACAO]> {
        self.relacao
    }

    /// O código que este lado mostra à Pessoa — o que ela digita no outro.
    /// Só enquanto ela ainda pode precisar dele.
    pub fn codigo_a_mostrar(&self) -> Option<u32> {
        match self.estado {
            Estado::Apertada | Estado::CodigoCerto | Estado::ConferidaAqui => {
                self.codigos.map(|c| c.mostrar)
            }
            _ => None,
        }
    }

    /// Recusa o passo se a cerimônia acabou ou venceu; o vencimento leva ao
    /// fim.
    fn viva(&mut self, agora: u64) -> Result<(), Recusa> {
        if self.acabou() {
            return Err(Recusa::Acabou);
        }
        if self.vencer(agora).is_some() {
            return Err(Recusa::Vencida);
        }
        Ok(())
    }

    // ── O aceitante ──────────────────────────────────────────────────────

    /// A 1ª mensagem do IK chegou e abriu: `desafio` é o que ela trouxe,
    /// `par` a estática que ela provou, `compromisso` o do iniciante.
    ///
    /// Uma por janela. Um desafio que não é o desta janela é recusado e
    /// **não** a ocupa — é a 1ª mensagem gravada de outra cerimônia.
    pub fn primeira_mensagem(
        &mut self,
        agora: u64,
        desafio: &[u8; TAM_DESAFIO],
        par: [u8; 32],
        compromisso: [u8; TAM_RESUMO],
    ) -> Result<(), Recusa> {
        self.viva(agora)?;
        if self.lado != Lado::Aceita {
            return Err(Recusa::ForaDeOrdem);
        }
        if self.respondida || self.estado != Estado::Aberta {
            return Err(Recusa::Ocupada);
        }
        if !self.janela_livre(agora) {
            return Err(Recusa::Vencida);
        }
        let nosso = self.desafio.ok_or(Recusa::ForaDeOrdem)?;
        if !iguais(&nosso, desafio) {
            return Err(Recusa::DesafioErrado);
        }
        self.respondida = true;
        self.par = Some(par);
        self.compromisso = Some(compromisso);
        self.estado = Estado::Ocupada;
        Ok(())
    }

    /// O iniciante abriu o nonce, depois da 2ª mensagem; `h` é o resumo do
    /// aperto. O nonce tem de abrir o compromisso; os códigos e `R` saem
    /// dele e de `h`.
    pub fn nonce_aberto(
        &mut self,
        agora: u64,
        h: &[u8; TAM_RESUMO],
        n: [u8; TAM_NONCE],
    ) -> Result<(), Recusa> {
        self.viva(agora)?;
        if self.lado != Lado::Aceita || self.estado != Estado::Ocupada {
            return Err(Recusa::ForaDeOrdem);
        }
        let c = self.compromisso.ok_or(Recusa::ForaDeOrdem)?;
        if !iguais(&c, &compromisso(&n)) {
            self.terminar(Desfecho::Desfeita(Motivo::CompromissoErrado));
            return Err(Recusa::CompromissoErrado);
        }
        let (k_b, k_a) = codigos(h, &n);
        self.codigos = Some(Codigos {
            mostrar: k_b,
            pedir: k_a,
        });
        self.relacao = Some(relacao(h, &n));
        self.nonce = Some(n);
        self.estado = Estado::Apertada;
        Ok(())
    }

    // ── O iniciante ──────────────────────────────────────────────────────

    /// O anúncio do aceitante: a estática dele e o desafio da janela. O
    /// aperto que vem depois prova a chave — ou não fecha.
    pub fn anuncio(
        &mut self,
        agora: u64,
        par: [u8; 32],
        desafio: [u8; TAM_DESAFIO],
    ) -> Result<(), Recusa> {
        self.viva(agora)?;
        if self.lado != Lado::Inicia || self.estado != Estado::Aberta || self.par.is_some() {
            return Err(Recusa::ForaDeOrdem);
        }
        self.par = Some(par);
        self.desafio = Some(desafio);
        Ok(())
    }

    /// A 1ª mensagem saiu, com o compromisso.
    pub fn primeira_mandada(&mut self, agora: u64) -> Result<(), Recusa> {
        self.viva(agora)?;
        if self.lado != Lado::Inicia || self.estado != Estado::Aberta || self.par.is_none() {
            return Err(Recusa::ForaDeOrdem);
        }
        self.estado = Estado::Ocupada;
        Ok(())
    }

    /// A 2ª mensagem chegou e abriu; `h` é o resumo do aperto. Devolve o
    /// nonce, que só agora pode sair.
    pub fn segunda_mensagem(
        &mut self,
        agora: u64,
        h: &[u8; TAM_RESUMO],
    ) -> Result<[u8; TAM_NONCE], Recusa> {
        self.viva(agora)?;
        if self.lado != Lado::Inicia || self.estado != Estado::Ocupada {
            return Err(Recusa::ForaDeOrdem);
        }
        let n = self.nonce.ok_or(Recusa::ForaDeOrdem)?;
        let (k_b, k_a) = codigos(h, &n);
        self.codigos = Some(Codigos {
            mostrar: k_a,
            pedir: k_b,
        });
        self.relacao = Some(relacao(h, &n));
        self.estado = Estado::Apertada;
        Ok(n)
    }

    // ── Os dois ─────────────────────────────────────────────────────────

    /// A Pessoa daqui digitou o código do outro. Uma vez: certo, a cerimônia
    /// pede a senha; errado, acaba — não há segunda tentativa.
    pub fn digitado(&mut self, agora: u64, codigo: u32) -> Result<(), Recusa> {
        self.viva(agora)?;
        if self.digitada {
            return Err(Recusa::Repetido);
        }
        if self.estado != Estado::Apertada {
            return Err(Recusa::ForaDeOrdem);
        }
        let Some(c) = self.codigos else {
            return Err(Recusa::ForaDeOrdem);
        };
        self.digitada = true;
        if !iguais(&c.pedir.to_be_bytes(), &codigo.to_be_bytes()) {
            self.terminar(Desfecho::Desfeita(Motivo::CodigoErrado));
            return Err(Recusa::CodigoErrado);
        }
        self.estado = Estado::CodigoCerto;
        Ok(())
    }

    /// A senha da Pessoa conferiu — quem confere é o kernel. O `conferido`
    /// sai agora. Devolve se o do outro já tinha chegado: então é a hora de
    /// gravar.
    pub fn senha_conferida(&mut self, agora: u64) -> Result<bool, Recusa> {
        self.viva(agora)?;
        if self.estado != Estado::CodigoCerto {
            return Err(Recusa::ForaDeOrdem);
        }
        self.estado = Estado::ConferidaAqui;
        Ok(self.conferida_la)
    }

    /// O `conferido` do outro chegou. Uma vez. Devolve se a Pessoa daqui já
    /// tinha confirmado: então é a hora de gravar.
    pub fn conferido_do_outro(&mut self, agora: u64) -> Result<bool, Recusa> {
        self.viva(agora)?;
        if self.conferida_la {
            return Err(Recusa::Repetido);
        }
        if !matches!(
            self.estado,
            Estado::Apertada | Estado::CodigoCerto | Estado::ConferidaAqui
        ) {
            return Err(Recusa::ForaDeOrdem);
        }
        self.conferida_la = true;
        Ok(self.estado == Estado::ConferidaAqui)
    }

    /// Começa a gravar: as duas confirmações, no prazo. Uma vez.
    pub fn gravar(&mut self, agora: u64) -> Result<(), Recusa> {
        self.viva(agora)?;
        if self.estado != Estado::ConferidaAqui || !self.conferida_la {
            return Err(Recusa::ForaDeOrdem);
        }
        self.estado = Estado::Gravando;
        Ok(())
    }

    /// A gravação aqui terminou. Se o `gravado` do outro já veio, a
    /// cerimônia acabou. Se uma desistência chegou durante a gravação, é
    /// ela que acaba a cerimônia agora, com o que se gravou: o outro
    /// desistiu (ou disse outra relação) — quem chama desfaz; qualquer
    /// outra — a conexão, a sessão —, a relação fica deste lado, e o outro
    /// não confirmou.
    pub fn gravada(&mut self) -> Result<(), Recusa> {
        if self.estado != Estado::Gravando {
            return Err(Recusa::ForaDeOrdem);
        }
        self.gravada_aqui = true;
        match self.pendente.take() {
            Some(Motivo::OutroDesistiu | Motivo::RelacaoDiferente) => {
                self.terminar(Desfecho::DesfazerAqui);
            }
            _ if self.gravado_la => self.terminar(Desfecho::Concluida),
            Some(_) => self.terminar(Desfecho::GravadaSemAviso),
            None => self.estado = Estado::Gravada,
        }
        Ok(())
    }

    /// A gravação aqui não aconteceu — a decisão de novo recusou, o
    /// registro recusou, o journal falhou: nada gravado, por `motivo`.
    pub fn nao_gravada(&mut self, motivo: Motivo) -> Result<Desfecho, Recusa> {
        if self.estado != Estado::Gravando {
            return Err(Recusa::ForaDeOrdem);
        }
        let d = Desfecho::Desfeita(motivo);
        self.terminar(d);
        Ok(d)
    }

    /// A desistência que espera a gravação em curso.
    pub fn pendente(&self) -> Option<Motivo> {
        self.pendente
    }

    /// O `gravado` do outro chegou, dizendo a relação `r`. Tem de ser a
    /// mesma; uma vez.
    pub fn gravado_do_outro(&mut self, r: &[u8; TAM_RELACAO]) -> Result<(), Recusa> {
        if self.acabou() {
            return Err(Recusa::Acabou);
        }
        if self.gravado_la {
            return Err(Recusa::Repetido);
        }
        if !matches!(
            self.estado,
            Estado::ConferidaAqui | Estado::Gravando | Estado::Gravada
        ) || !self.conferida_la
        {
            return Err(Recusa::ForaDeOrdem);
        }
        if self.relacao.as_ref().is_none_or(|nossa| !iguais(nossa, r)) {
            return Err(Recusa::RelacaoDiferente);
        }
        self.gravado_la = true;
        if self.estado == Estado::Gravada {
            self.terminar(Desfecho::Concluida);
        }
        Ok(())
    }

    /// A cerimônia acaba por `motivo`. Devolve o desfecho: o que já estava
    /// gravado aqui fica — a menos que o outro tenha desistido ou dito outra
    /// relação, e então quem chama desfaz.
    ///
    /// Com a gravação em curso, não acaba ainda: só ela sabe se gravou. A
    /// desistência — a primeira — espera por ela, e `None`: o desfecho sai
    /// de [`Cerimonia::gravada`] ou de [`Cerimonia::nao_gravada`].
    pub fn desistir(&mut self, motivo: Motivo) -> Option<Desfecho> {
        if let Estado::Fim(d) = self.estado {
            return Some(d);
        }
        if self.estado == Estado::Gravando {
            if self.pendente.is_none() {
                self.pendente = Some(motivo);
            }
            return None;
        }
        let d = if self.gravada_aqui {
            match motivo {
                Motivo::OutroDesistiu | Motivo::RelacaoDiferente => Desfecho::DesfazerAqui,
                _ => Desfecho::GravadaSemAviso,
            }
        } else {
            Desfecho::Desfeita(motivo)
        };
        self.terminar(d);
        Some(d)
    }

    /// Se o prazo venceu, a cerimônia acaba — e devolve o desfecho. A
    /// gravação em curso não vence aqui: quem grava confere o prazo de novo
    /// com a ordem na mão.
    pub fn vencer(&mut self, agora: u64) -> Option<Desfecho> {
        if self.acabou() || self.estado == Estado::Gravando {
            return None;
        }
        let janela_vencida = self.lado == Lado::Aceita
            && self.estado == Estado::Aberta
            && agora.saturating_sub(self.aberta_em) >= JANELA_MS;
        if !self.no_prazo(agora) || janela_vencida {
            return self.desistir(Motivo::Prazo);
        }
        None
    }

    /// O prazo, de novo, para quem grava com a ordem na mão.
    pub fn ainda_no_prazo(&self, agora: u64) -> bool {
        self.no_prazo(agora)
    }

    fn terminar(&mut self, d: Desfecho) {
        self.estado = Estado::Fim(d);
        self.pendente = None;
        self.apagar();
    }

    /// Apaga o que não serve fora do aperto: o nonce e os códigos.
    fn apagar(&mut self) {
        if let Some(mut n) = self.nonce.take() {
            zerar(&mut n);
        }
        if let Some(mut c) = self.codigos.take() {
            c.mostrar = 0;
            c.pedir = 0;
            core::hint::black_box(&c);
        }
        if let Some(mut c) = self.compromisso.take() {
            zerar(&mut c);
        }
    }

    /// As regras que a cerimônia nunca quebra.
    pub fn coerente(&self) -> bool {
        let fim = self.acabou();
        let apertada = matches!(
            self.estado,
            Estado::Apertada
                | Estado::CodigoCerto
                | Estado::ConferidaAqui
                | Estado::Gravando
                | Estado::Gravada
        );
        // O fim apaga o que é do aperto; antes dele, os códigos existem
        // exatamente desde o aperto.
        let segredos = if fim {
            self.nonce.is_none() && self.codigos.is_none() && self.compromisso.is_none()
        } else {
            self.codigos.is_some() == apertada && (!apertada || self.relacao.is_some())
        };
        // Só o aceitante responde à 1ª mensagem; ocupado, ele tem a chave e o
        // compromisso.
        let resposta = match self.lado {
            Lado::Aceita => {
                (self.respondida || self.estado == Estado::Aberta || fim)
                    && (self.estado != Estado::Ocupada
                        || (self.par.is_some() && self.compromisso.is_some()))
            }
            Lado::Inicia => {
                !self.respondida && (self.estado != Estado::Ocupada || self.par.is_some())
            }
        };
        // A Pessoa daqui só passa do código digitando; gravar exige as duas
        // confirmações.
        let digitou = !matches!(
            self.estado,
            Estado::CodigoCerto | Estado::ConferidaAqui | Estado::Gravando | Estado::Gravada
        ) || self.digitada;
        let duas = !matches!(self.estado, Estado::Gravando | Estado::Gravada) || self.conferida_la;
        let gravada = !matches!(self.estado, Estado::Gravada) || self.gravada_aqui;
        let concluida = self.estado != Estado::Fim(Desfecho::Concluida)
            || (self.gravada_aqui && self.gravado_la);
        let nada_gravado =
            !matches!(self.estado, Estado::Fim(Desfecho::Desfeita(_))) || !self.gravada_aqui;
        // A desistência só espera a gravação em curso.
        let pendente = self.pendente.is_none() || self.estado == Estado::Gravando;
        segredos && resposta && digitou && duas && gravada && concluida && nada_gravado && pendente
    }
}

impl Drop for Cerimonia {
    fn drop(&mut self) {
        self.apagar();
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::vec::Vec;

    const W: [u8; TAM_DESAFIO] = [7; TAM_DESAFIO];
    const N: [u8; TAM_NONCE] = [9; TAM_NONCE];
    const H: [u8; TAM_RESUMO] = [3; TAM_RESUMO];
    const KA: [u8; 32] = [0xa1; 32];
    const KB: [u8; 32] = [0xb2; 32];

    /// O par honesto: os dois lados até os códigos à mostra.
    fn apertados(h: &[u8; TAM_RESUMO]) -> (Cerimonia, Cerimonia) {
        let mut b = Cerimonia::aceitar(0, W);
        let mut a = Cerimonia::parear(10, N);
        a.anuncio(20, KB, b.desafio().unwrap()).unwrap();
        let c = a.compromisso_a_mandar().unwrap();
        a.primeira_mandada(30).unwrap();
        b.primeira_mensagem(40, &W, KA, c).unwrap();
        let n = a.segunda_mensagem(50, h).unwrap();
        b.nonce_aberto(60, h, n).unwrap();
        assert!(a.coerente() && b.coerente());
        (a, b)
    }

    // H04: as contas.
    #[test]
    fn os_dois_lados_chegam_aos_mesmos_codigos_e_ao_mesmo_id() {
        let (a, b) = apertados(&H);
        assert_eq!(a.relacao(), b.relacao());
        assert!(a.relacao().is_some());
        // O que um mostra é o que o outro pede.
        assert_eq!(a.codigo_a_mostrar(), a.codigos.map(|c| c.mostrar));
        assert_eq!(a.codigos.unwrap().mostrar, b.codigos.unwrap().pedir);
        assert_eq!(b.codigos.unwrap().mostrar, a.codigos.unwrap().pedir);
        // Uma tela nunca pede o código que ela mesma mostra (a não ser por
        // coincidência de 10⁻⁸, que este vetor não tem).
        assert_ne!(a.codigos.unwrap().mostrar, a.codigos.unwrap().pedir);
        // Os dois códigos têm 8 dígitos.
        assert!(u64::from(a.codigos.unwrap().mostrar) < MODULO_DO_CODIGO);
    }

    #[test]
    fn mudar_o_aperto_ou_o_nonce_muda_tudo() {
        let base = codigos(&H, &N);
        let mut h2 = H;
        h2[31] ^= 1;
        let mut n2 = N;
        n2[0] ^= 1;
        assert_ne!(codigos(&h2, &N), base);
        assert_ne!(codigos(&H, &n2), base);
        assert_ne!(relacao(&h2, &N), relacao(&H, &N));
        assert_ne!(relacao(&H, &n2), relacao(&H, &N));
        assert_ne!(compromisso(&n2), compromisso(&N));
        // Determinístico.
        assert_eq!(codigos(&H, &N), base);
    }

    #[test]
    fn o_codigo_se_escreve_e_se_le() {
        assert_eq!(texto_do_codigo(12_345_678), "1234 5678");
        assert_eq!(texto_do_codigo(42), "0000 0042");
        assert_eq!(ler_codigo("1234 5678"), Some(12_345_678));
        assert_eq!(ler_codigo("12345678"), Some(12_345_678));
        assert_eq!(ler_codigo(" 0000 0042 "), Some(42));
        assert_eq!(ler_codigo("1234 567"), None);
        assert_eq!(ler_codigo("1234 56789"), None);
        assert_eq!(ler_codigo("1234-5678"), None);
        assert_eq!(ler_codigo(""), None);
        for k in [0u32, 1, 99_999_999, 50_000_000] {
            assert_eq!(ler_codigo(&texto_do_codigo(k)), Some(k));
        }
    }

    // H03: a ordem e o compromisso.
    #[test]
    fn o_nonce_so_sai_depois_da_segunda_mensagem() {
        let mut a = Cerimonia::parear(0, N);
        // Antes do anúncio, nada de aperto.
        assert_eq!(a.primeira_mandada(1), Err(Recusa::ForaDeOrdem));
        assert_eq!(a.segunda_mensagem(1, &H), Err(Recusa::ForaDeOrdem));
        a.anuncio(2, KB, W).unwrap();
        // O compromisso sai na 1ª; o nonce, só com a 2ª.
        assert_eq!(a.compromisso_a_mandar(), Some(compromisso(&N)));
        assert_eq!(a.segunda_mensagem(3, &H), Err(Recusa::ForaDeOrdem));
        a.primeira_mandada(4).unwrap();
        assert_eq!(a.segunda_mensagem(5, &H), Ok(N));
        // Depois do aperto, não se compromete de novo.
        assert_eq!(a.compromisso_a_mandar(), None);
        assert!(a.coerente());
    }

    #[test]
    fn o_compromisso_que_nao_confere_desfaz() {
        let mut b = Cerimonia::aceitar(0, W);
        b.primeira_mensagem(1, &W, KA, compromisso(&N)).unwrap();
        let mut outro = N;
        outro[5] ^= 0x80;
        assert_eq!(b.nonce_aberto(2, &H, outro), Err(Recusa::CompromissoErrado));
        assert_eq!(
            b.estado(),
            Estado::Fim(Desfecho::Desfeita(Motivo::CompromissoErrado))
        );
        assert!(b.codigo_a_mostrar().is_none() && b.coerente());
    }

    #[test]
    fn o_nonce_antes_da_primeira_mensagem_e_fora_de_ordem() {
        let mut b = Cerimonia::aceitar(0, W);
        assert_eq!(b.nonce_aberto(1, &H, N), Err(Recusa::ForaDeOrdem));
        assert_eq!(b.estado(), Estado::Aberta);
    }

    // A janela: uma resposta, e só à que traz o desafio dela.
    #[test]
    fn a_janela_responde_a_uma_so_e_ao_desafio_dela() {
        let mut b = Cerimonia::aceitar(0, W);
        let mut velho = W;
        velho[0] ^= 1;
        // A 1ª mensagem de outra cerimônia não ocupa a janela.
        assert_eq!(
            b.primeira_mensagem(1, &velho, KA, compromisso(&N)),
            Err(Recusa::DesafioErrado)
        );
        assert!(b.janela_livre(2));
        b.primeira_mensagem(3, &W, KA, compromisso(&N)).unwrap();
        // A segunda, mesmo com o desafio certo, encontra a janela ocupada.
        assert_eq!(
            b.primeira_mensagem(4, &W, KB, compromisso(&N)),
            Err(Recusa::Ocupada)
        );
        assert_eq!(b.par(), Some(KA));
        assert!(!b.janela_livre(5) && b.coerente());
    }

    // H02: os prazos.
    #[test]
    fn a_janela_e_a_cerimonia_vencem() {
        let mut b = Cerimonia::aceitar(1_000, W);
        assert!(b.janela_livre(1_000 + JANELA_MS - 1));
        assert_eq!(
            b.primeira_mensagem(1_000 + JANELA_MS, &W, KA, compromisso(&N)),
            Err(Recusa::Vencida)
        );
        assert_eq!(b.estado(), Estado::Fim(Desfecho::Desfeita(Motivo::Prazo)));

        let (mut a, mut b) = apertados(&H);
        // No último instante ainda vale; no prazo, não.
        assert_eq!(a.vencer(10 + PRAZO_MS - 1), None);
        let k = a.codigos.unwrap().pedir;
        assert_eq!(a.digitado(10 + PRAZO_MS, k), Err(Recusa::Vencida));
        assert_eq!(a.estado(), Estado::Fim(Desfecho::Desfeita(Motivo::Prazo)));
        assert_eq!(b.vencer(PRAZO_MS), Some(Desfecho::Desfeita(Motivo::Prazo)));
        assert!(a.coerente() && b.coerente());
    }

    #[test]
    fn a_gravacao_em_curso_nao_vence_sozinha() {
        let (mut a, _) = apertados(&H);
        let k = a.codigos.unwrap().pedir;
        a.digitado(100, k).unwrap();
        a.conferido_do_outro(110).unwrap();
        assert_eq!(a.senha_conferida(120), Ok(true));
        a.gravar(130).unwrap();
        // Quem grava confere o prazo de novo, com a ordem na mão.
        assert_eq!(a.vencer(10 + PRAZO_MS), None);
        assert!(!a.ainda_no_prazo(10 + PRAZO_MS));
        assert!(a.ainda_no_prazo(10 + PRAZO_MS - 1));
    }

    // H01: as transições.
    #[test]
    fn o_caminho_inteiro_dos_dois_lados() {
        let (mut a, mut b) = apertados(&H);
        let ka = a.codigos.unwrap().pedir;
        let kb = b.codigos.unwrap().pedir;
        // Cada Pessoa digita o código que o outro mostra.
        b.digitado(100, kb).unwrap();
        assert_eq!(b.senha_conferida(110), Ok(false));
        a.digitado(120, ka).unwrap();
        // O `conferido` de B chega a A antes da senha de A.
        assert_eq!(a.conferido_do_outro(130), Ok(false));
        assert_eq!(a.senha_conferida(140), Ok(true));
        // O de A chega a B: os dois gravam.
        assert_eq!(b.conferido_do_outro(150), Ok(true));
        a.gravar(160).unwrap();
        b.gravar(170).unwrap();
        a.gravada().unwrap();
        b.gravada().unwrap();
        let r = a.relacao().unwrap();
        b.gravado_do_outro(&r).unwrap();
        a.gravado_do_outro(&b.relacao().unwrap()).unwrap();
        assert_eq!(a.estado(), Estado::Fim(Desfecho::Concluida));
        assert_eq!(b.estado(), Estado::Fim(Desfecho::Concluida));
        // O fim apaga os códigos e o nonce, e guarda `R`.
        assert!(a.codigo_a_mostrar().is_none() && a.nonce.is_none());
        assert_eq!(a.relacao(), Some(r));
        assert!(a.coerente() && b.coerente());
    }

    #[test]
    fn sem_o_conferido_do_outro_nao_se_grava() {
        let (mut a, _) = apertados(&H);
        let k = a.codigos.unwrap().pedir;
        a.digitado(100, k).unwrap();
        assert_eq!(a.senha_conferida(110), Ok(false));
        assert_eq!(a.gravar(120), Err(Recusa::ForaDeOrdem));
        assert_eq!(a.estado(), Estado::ConferidaAqui);
    }

    #[test]
    fn sem_a_confirmacao_daqui_nao_se_grava() {
        let (mut a, _) = apertados(&H);
        assert_eq!(a.conferido_do_outro(100), Ok(false));
        assert_eq!(a.gravar(110), Err(Recusa::ForaDeOrdem));
        let k = a.codigos.unwrap().pedir;
        a.digitado(120, k).unwrap();
        // O código sem a senha também não basta.
        assert_eq!(a.gravar(130), Err(Recusa::ForaDeOrdem));
        assert_eq!(a.senha_conferida(140), Ok(true));
        assert_eq!(a.gravar(150), Ok(()));
        // Uma vez.
        assert_eq!(a.gravar(160), Err(Recusa::ForaDeOrdem));
    }

    #[test]
    fn o_codigo_errado_acaba_e_nao_ha_segunda_vez() {
        let (mut a, _) = apertados(&H);
        let k = a.codigos.unwrap().pedir;
        assert_eq!(a.digitado(100, k ^ 1), Err(Recusa::CodigoErrado));
        assert_eq!(
            a.estado(),
            Estado::Fim(Desfecho::Desfeita(Motivo::CodigoErrado))
        );
        assert_eq!(a.digitado(110, k), Err(Recusa::Acabou));
        // O código que a própria tela mostra não serve.
        let (mut a, _) = apertados(&H);
        let proprio = a.codigo_a_mostrar().unwrap();
        assert_eq!(a.digitado(100, proprio), Err(Recusa::CodigoErrado));
        assert!(a.coerente());
    }

    #[test]
    fn digitar_duas_vezes_e_repetido() {
        let (mut a, _) = apertados(&H);
        let k = a.codigos.unwrap().pedir;
        a.digitado(100, k).unwrap();
        assert_eq!(a.digitado(110, k), Err(Recusa::Repetido));
        assert_eq!(a.estado(), Estado::CodigoCerto);
    }

    #[test]
    fn o_conferido_do_outro_vale_uma_vez() {
        let (mut a, _) = apertados(&H);
        a.conferido_do_outro(100).unwrap();
        assert_eq!(a.conferido_do_outro(110), Err(Recusa::Repetido));
    }

    #[test]
    fn o_gravado_do_outro_com_outra_relacao_e_recusado() {
        let (mut a, mut b) = apertados(&H);
        let ka = a.codigos.unwrap().pedir;
        let kb = b.codigos.unwrap().pedir;
        a.digitado(100, ka).unwrap();
        a.conferido_do_outro(101).unwrap();
        a.senha_conferida(102).unwrap();
        a.gravar(103).unwrap();
        a.gravada().unwrap();
        let mut outra = a.relacao().unwrap();
        outra[0] ^= 1;
        assert_eq!(a.gravado_do_outro(&outra), Err(Recusa::RelacaoDiferente));
        // Quem chama desfaz o que gravou.
        assert_eq!(
            a.desistir(Motivo::RelacaoDiferente),
            Some(Desfecho::DesfazerAqui)
        );
        // E o `gravado` antes das duas confirmações é fora de ordem.
        b.digitado(100, kb).unwrap();
        assert_eq!(
            b.gravado_do_outro(&b.relacao().unwrap()),
            Err(Recusa::ForaDeOrdem)
        );
    }

    #[test]
    fn desistir_depois_de_gravar() {
        let grava = |m: Motivo| {
            let (mut a, _) = apertados(&H);
            let k = a.codigos.unwrap().pedir;
            a.digitado(100, k).unwrap();
            a.conferido_do_outro(101).unwrap();
            a.senha_conferida(102).unwrap();
            a.gravar(103).unwrap();
            a.gravada().unwrap();
            a.desistir(m)
        };
        assert_eq!(grava(Motivo::OutroDesistiu), Some(Desfecho::DesfazerAqui));
        assert_eq!(grava(Motivo::Conexao), Some(Desfecho::GravadaSemAviso));
        assert_eq!(grava(Motivo::Prazo), Some(Desfecho::GravadaSemAviso));
        // Antes de gravar, nada fica.
        let (mut a, _) = apertados(&H);
        assert_eq!(
            a.desistir(Motivo::OutroDesistiu),
            Some(Desfecho::Desfeita(Motivo::OutroDesistiu))
        );
        // E o fim é um só.
        assert_eq!(
            a.desistir(Motivo::Conexao),
            Some(Desfecho::Desfeita(Motivo::OutroDesistiu))
        );
    }

    /// A desistência que chega com a gravação em curso espera por ela: só
    /// quem grava sabe se gravou. Gravada, o outro que desistiu pede o
    /// desfazimento, e qualquer outra deixa a relação deste lado; não
    /// gravada, nada ficou.
    #[test]
    fn desistir_durante_a_gravacao() {
        let gravando = || {
            let (mut a, _) = apertados(&H);
            let k = a.codigos.unwrap().pedir;
            a.digitado(100, k).unwrap();
            a.conferido_do_outro(101).unwrap();
            a.senha_conferida(102).unwrap();
            a.gravar(103).unwrap();
            a
        };
        // O outro desistiu no meio: gravada, desfaz-se aqui.
        let mut a = gravando();
        assert_eq!(a.desistir(Motivo::OutroDesistiu), None);
        assert_eq!(a.estado(), Estado::Gravando);
        assert_eq!(a.pendente(), Some(Motivo::OutroDesistiu));
        // A primeira desistência é a que vale.
        assert_eq!(a.desistir(Motivo::Conexao), None);
        assert_eq!(a.pendente(), Some(Motivo::OutroDesistiu));
        assert!(a.coerente());
        a.gravada().unwrap();
        assert_eq!(a.estado(), Estado::Fim(Desfecho::DesfazerAqui));
        assert!(a.coerente() && a.pendente().is_none());
        // A conexão caiu no meio: gravada, fica aqui sem aviso.
        let mut a = gravando();
        assert_eq!(a.desistir(Motivo::Conexao), None);
        a.gravada().unwrap();
        assert_eq!(a.estado(), Estado::Fim(Desfecho::GravadaSemAviso));
        // O `gravado` do outro, e a conexão que cai depois: os dois gravaram.
        let mut a = gravando();
        let r = a.relacao().unwrap();
        a.gravado_do_outro(&r).unwrap();
        assert_eq!(a.desistir(Motivo::Conexao), None);
        a.gravada().unwrap();
        assert_eq!(a.estado(), Estado::Fim(Desfecho::Concluida));
        // Não gravada: nada ficou, seja qual for a desistência.
        let mut a = gravando();
        assert_eq!(a.desistir(Motivo::OutroDesistiu), None);
        assert_eq!(
            a.nao_gravada(Motivo::Recusada),
            Ok(Desfecho::Desfeita(Motivo::Recusada))
        );
        assert!(a.coerente() && !a.gravada_aqui);
        // Fora da gravação, os dois passos são fora de ordem.
        let (mut b, _) = apertados(&H);
        assert_eq!(b.nao_gravada(Motivo::Recusada), Err(Recusa::ForaDeOrdem));
        assert_eq!(b.gravada(), Err(Recusa::ForaDeOrdem));
        // A gravação em curso não vence, e a desistência pelo prazo também
        // espera.
        let mut a = gravando();
        assert_eq!(a.vencer(PRAZO_MS * 2), None);
        assert_eq!(a.estado(), Estado::Gravando);
    }

    #[test]
    fn os_passos_do_outro_lado_sao_recusados() {
        let mut a = Cerimonia::parear(0, N);
        assert_eq!(
            a.primeira_mensagem(1, &W, KB, compromisso(&N)),
            Err(Recusa::ForaDeOrdem)
        );
        let mut b = Cerimonia::aceitar(0, W);
        assert_eq!(b.anuncio(1, KA, W), Err(Recusa::ForaDeOrdem));
        assert_eq!(b.segunda_mensagem(1, &H), Err(Recusa::ForaDeOrdem));
        assert_eq!(b.compromisso_a_mandar(), None);
    }

    // O homem no meio: dois apertos, dois `h` diferentes. Os códigos que cada
    // Pessoa vê na tela do outro não conferem com o que este pede.
    #[test]
    fn com_alguem_no_meio_os_codigos_nao_conferem() {
        let mut h2 = H;
        h2[0] ^= 0x55;
        let (a, _b_do_meio) = apertados(&H);
        let (_a_do_meio, b) = apertados(&h2);
        assert_ne!(a.codigos.unwrap().pedir, b.codigos.unwrap().mostrar);
        assert_ne!(b.codigos.unwrap().pedir, a.codigos.unwrap().mostrar);
        assert_ne!(a.relacao(), b.relacao());
    }

    // H05: coerente sob sequências sorteadas; nunca uma gravação sem as duas
    // confirmações, nunca duas.
    #[test]
    fn coerente_sob_passos_sorteados() {
        let mut estado = 0x9E37_79B9_7F4A_7C15u64;
        let mut sorteio = move |n: u64| {
            estado ^= estado << 13;
            estado ^= estado >> 7;
            estado ^= estado << 17;
            estado % n
        };
        for rodada in 0..400 {
            let aceita = rodada % 2 == 0;
            let mut c = if aceita {
                Cerimonia::aceitar(0, W)
            } else {
                Cerimonia::parear(0, N)
            };
            let mut agora = 0u64;
            let mut gravacoes = 0;
            let mut h = H;
            h[0] = sorteio(256) as u8;
            for _ in 0..40 {
                agora += sorteio(12_000);
                let antes = (c.digitada, c.conferida_la, c.estado());
                let codigo = match sorteio(3) {
                    0 => c.codigos.map(|x| x.pedir).unwrap_or(0),
                    1 => c.codigos.map(|x| x.mostrar).unwrap_or(0),
                    _ => sorteio(MODULO_DO_CODIGO) as u32,
                };
                match sorteio(14) {
                    0 => {
                        let w = if sorteio(4) == 0 { [1; TAM_DESAFIO] } else { W };
                        let _ = c.primeira_mensagem(agora, &w, KA, compromisso(&N));
                    }
                    1 => {
                        let mut n = N;
                        if sorteio(5) == 0 {
                            n[1] ^= 1;
                        }
                        let _ = c.nonce_aberto(agora, &h, n);
                    }
                    2 => {
                        let _ = c.anuncio(agora, KB, W);
                    }
                    3 => {
                        let _ = c.primeira_mandada(agora);
                    }
                    4 => {
                        let _ = c.segunda_mensagem(agora, &h);
                    }
                    5 => {
                        let _ = c.digitado(agora, codigo);
                    }
                    6 => {
                        let _ = c.senha_conferida(agora);
                    }
                    7 => {
                        let _ = c.conferido_do_outro(agora);
                    }
                    8 => {
                        if c.gravar(agora).is_ok() {
                            gravacoes += 1;
                            // Gravar exigiu as duas confirmações.
                            assert!(antes.0 && antes.1);
                            assert_eq!(antes.2, Estado::ConferidaAqui);
                        }
                    }
                    9 => {
                        let _ = c.gravada();
                    }
                    10 => {
                        let r = c.relacao().unwrap_or([0; TAM_RELACAO]);
                        let _ = c.gravado_do_outro(&r);
                    }
                    11 => {
                        let _ = c.vencer(agora);
                    }
                    12 => {
                        let _ = c.nao_gravada(Motivo::Recusada);
                    }
                    _ => {
                        let _ = c.desistir(Motivo::Cancelada);
                    }
                }
                assert!(c.coerente(), "{:?}", c);
                assert!(gravacoes <= 1);
            }
        }
    }

    #[test]
    fn o_desfecho_tem_texto_curto() {
        let todos = [
            Motivo::Prazo,
            Motivo::CodigoErrado,
            Motivo::SenhaErrada,
            Motivo::Cancelada,
            Motivo::OutroDesistiu,
            Motivo::Conexao,
            Motivo::CompromissoErrado,
            Motivo::ParRevogado,
            Motivo::ParSuspenso,
            Motivo::FimDaSessao,
            Motivo::Recusada,
            Motivo::Desligamento,
            Motivo::ForaDoProtocolo,
            Motivo::RelacaoDiferente,
            Motivo::ParNaoProvou,
        ];
        let textos: Vec<&str> = todos.iter().map(|m| m.texto()).collect();
        for (i, t) in textos.iter().enumerate() {
            assert!(t.is_ascii() && t.len() <= 32, "{t}");
            assert!(!textos[..i].contains(t));
        }
    }

    // ── H01 e H02: a tabela da §4, estado × passo ──────────────────────

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Passo {
        Primeira,
        Nonce,
        Anuncio,
        Mandada,
        Segunda,
        Digitado,
        Senha,
        Conferido,
        Gravar,
        Gravada,
        GravadoLa,
    }

    const PASSOS: [Passo; 11] = [
        Passo::Primeira,
        Passo::Nonce,
        Passo::Anuncio,
        Passo::Mandada,
        Passo::Segunda,
        Passo::Digitado,
        Passo::Senha,
        Passo::Conferido,
        Passo::Gravar,
        Passo::Gravada,
        Passo::GravadoLa,
    ];

    /// O passo, com os valores honestos: o desafio da janela, o compromisso
    /// de `N`, o código certo do lado, o `R` do aperto.
    fn dar(c: &mut Cerimonia, p: Passo, agora: u64) -> Result<(), Recusa> {
        let (k_b, k_a) = codigos(&H, &N);
        match p {
            Passo::Primeira => c.primeira_mensagem(agora, &W, KA, compromisso(&N)),
            Passo::Nonce => c.nonce_aberto(agora, &H, N),
            Passo::Anuncio => c.anuncio(agora, KB, W),
            Passo::Mandada => c.primeira_mandada(agora),
            Passo::Segunda => c.segunda_mensagem(agora, &H).map(|_| ()),
            Passo::Digitado => c.digitado(agora, if c.lado() == Lado::Aceita { k_a } else { k_b }),
            Passo::Senha => c.senha_conferida(agora).map(|_| ()),
            Passo::Conferido => c.conferido_do_outro(agora).map(|_| ()),
            Passo::Gravar => c.gravar(agora),
            Passo::Gravada => c.gravada(),
            Passo::GravadoLa => c.gravado_do_outro(&relacao(&H, &N)),
        }
    }

    /// Uma cerimônia de `lado` aberta em 0, levada pelo caminho `caminho`,
    /// um passo por ms.
    fn levada(lado: Lado, caminho: &[Passo]) -> Cerimonia {
        let mut c = match lado {
            Lado::Aceita => Cerimonia::aceitar(0, W),
            Lado::Inicia => Cerimonia::parear(0, N),
        };
        for (i, p) in caminho.iter().enumerate() {
            dar(&mut c, *p, 1 + i as u64).unwrap_or_else(|e| panic!("{lado:?} {p:?}: {e:?}"));
            assert!(c.coerente());
        }
        c
    }

    use Passo::*;

    /// Cada estado alcançável de cada lado, o caminho até ele e os passos
    /// que ele aceita. Todo outro passo é recusado e não muda nada.
    #[allow(clippy::type_complexity)]
    fn tabela() -> Vec<(Lado, Vec<Passo>, Estado, Vec<Passo>)> {
        let aceita = [Primeira, Nonce];
        let inicia = [Anuncio, Mandada, Segunda];
        let mut t = alloc::vec![
            (
                Lado::Aceita,
                alloc::vec![],
                Estado::Aberta,
                alloc::vec![Primeira]
            ),
            (
                Lado::Aceita,
                alloc::vec![Primeira],
                Estado::Ocupada,
                alloc::vec![Nonce]
            ),
            (
                Lado::Inicia,
                alloc::vec![],
                Estado::Aberta,
                alloc::vec![Anuncio]
            ),
            (
                Lado::Inicia,
                alloc::vec![Anuncio],
                Estado::Aberta,
                alloc::vec![Mandada]
            ),
            (
                Lado::Inicia,
                alloc::vec![Anuncio, Mandada],
                Estado::Ocupada,
                alloc::vec![Segunda]
            ),
        ];
        for (lado, inicio) in [(Lado::Aceita, &aceita[..]), (Lado::Inicia, &inicia[..])] {
            let com = |resto: &[Passo]| {
                let mut v = inicio.to_vec();
                v.extend_from_slice(resto);
                v
            };
            t.push((
                lado,
                com(&[]),
                Estado::Apertada,
                alloc::vec![Digitado, Conferido],
            ));
            t.push((
                lado,
                com(&[Conferido]),
                Estado::Apertada,
                alloc::vec![Digitado],
            ));
            t.push((
                lado,
                com(&[Digitado]),
                Estado::CodigoCerto,
                alloc::vec![Senha, Conferido],
            ));
            t.push((
                lado,
                com(&[Conferido, Digitado]),
                Estado::CodigoCerto,
                alloc::vec![Senha],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha]),
                Estado::ConferidaAqui,
                alloc::vec![Conferido],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha, Conferido]),
                Estado::ConferidaAqui,
                alloc::vec![Gravar, GravadoLa],
            ));
            t.push((
                lado,
                com(&[Conferido, Digitado, Senha]),
                Estado::ConferidaAqui,
                alloc::vec![Gravar, GravadoLa],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha, Conferido, Gravar]),
                Estado::Gravando,
                alloc::vec![Gravada, GravadoLa],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha, Conferido, GravadoLa, Gravar]),
                Estado::Gravando,
                alloc::vec![Gravada],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha, Conferido, Gravar, Gravada]),
                Estado::Gravada,
                alloc::vec![GravadoLa],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha, Conferido, Gravar, Gravada, GravadoLa]),
                Estado::Fim(Desfecho::Concluida),
                alloc::vec![],
            ));
            t.push((
                lado,
                com(&[Digitado, Senha, Conferido, GravadoLa, Gravar, Gravada]),
                Estado::Fim(Desfecho::Concluida),
                alloc::vec![],
            ));
        }
        t
    }

    // H01: cada transição, as permitidas e as recusadas.
    #[test]
    fn cada_estado_aceita_so_os_passos_dele() {
        for (lado, caminho, estado, aceitos) in tabela() {
            let c = levada(lado, &caminho);
            assert_eq!(c.estado(), estado, "{lado:?} {caminho:?}");
            drop(c);
            for p in PASSOS {
                let mut c = levada(lado, &caminho);
                let antes = c.estado();
                let r = dar(&mut c, p, 50);
                assert!(c.coerente(), "{lado:?} {caminho:?} {p:?}");
                if aceitos.contains(&p) {
                    assert_eq!(r, Ok(()), "{lado:?} {caminho:?} {p:?}");
                    assert_ne!(c.estado(), Estado::Fim(Desfecho::Desfeita(Motivo::Prazo)));
                } else {
                    assert!(r.is_err(), "{lado:?} {caminho:?} {p:?} aceito");
                    // A recusa de um passo fora de ordem não mexe em nada.
                    assert_eq!(c.estado(), antes, "{lado:?} {caminho:?} {p:?}");
                }
            }
        }
    }

    // H01: o fim recusa tudo, e a desistência só vale uma vez.
    #[test]
    fn o_fim_recusa_todo_passo() {
        for (lado, caminho, _, _) in tabela() {
            let mut c = levada(lado, &caminho);
            let d = match c.desistir(Motivo::Cancelada) {
                Some(d) => d,
                // Gravando, a desistência espera a gravação.
                None => c.nao_gravada(Motivo::Cancelada).unwrap(),
            };
            assert!(c.acabou() && c.coerente());
            for p in PASSOS {
                assert!(dar(&mut c, p, 60).is_err(), "{lado:?} {caminho:?} {p:?}");
                assert_eq!(c.estado(), Estado::Fim(d));
            }
            // Desistir de novo devolve o mesmo desfecho, sem mudar nada.
            assert_eq!(c.desistir(Motivo::OutroDesistiu), Some(d));
            assert_eq!(c.vencer(u64::MAX), None);
            assert!(c.codigo_a_mostrar().is_none() && c.compromisso_a_mandar().is_none());
        }
    }

    // H02: os prazos em cada estado.
    #[test]
    fn os_prazos_em_cada_estado() {
        for (lado, caminho, estado, _) in tabela() {
            if matches!(estado, Estado::Fim(_)) {
                continue;
            }
            // Um ms antes do prazo da cerimônia, nada vence — a não ser a
            // janela livre do aceitante, que tem o dela.
            let mut c = levada(lado, &caminho);
            let janela = lado == Lado::Aceita && estado == Estado::Aberta;
            assert_eq!(c.vencer(JANELA_MS - 1), None);
            assert_eq!(c.vencer(JANELA_MS).is_some(), janela, "{caminho:?}");
            if janela {
                assert_eq!(c.estado(), Estado::Fim(Desfecho::Desfeita(Motivo::Prazo)));
                // E a janela vencida não responde mais.
                assert_eq!(dar(&mut c, Primeira, JANELA_MS), Err(Recusa::Acabou));
                continue;
            }
            assert_eq!(c.vencer(PRAZO_MS - 1), None, "{lado:?} {caminho:?}");
            assert!(c.ainda_no_prazo(PRAZO_MS - 1));
            assert!(!c.ainda_no_prazo(PRAZO_MS));
            assert_eq!(c.restante_ms(PRAZO_MS - 1), 1);
            assert_eq!(c.restante_ms(PRAZO_MS + 5), 0);
            let venceu = c.vencer(PRAZO_MS);
            match estado {
                // A gravação em curso não vence sozinha: quem grava confere
                // o prazo de novo, com a ordem na mão.
                Estado::Gravando => assert_eq!(venceu, None),
                // Gravada aqui, sem o `gravado` do outro: fica, e avisa.
                Estado::Gravada => {
                    assert_eq!(venceu, Some(Desfecho::GravadaSemAviso));
                }
                _ => assert_eq!(
                    venceu,
                    Some(Desfecho::Desfeita(Motivo::Prazo)),
                    "{lado:?} {caminho:?}"
                ),
            }
            assert!(c.coerente());
            // Vencida, nenhum passo que confere o prazo vale.
            let mut c = levada(lado, &caminho);
            for p in PASSOS {
                if matches!(p, Gravada | GravadoLa) {
                    continue;
                }
                let r = dar(&mut c, p, PRAZO_MS);
                assert!(r.is_err(), "{lado:?} {caminho:?} {p:?}");
            }
            assert!(c.coerente());
        }
    }
}
