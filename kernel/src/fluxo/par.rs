//! O fluxo entre dois Dukes: a sessão de um fluxo com o par — o domínio do
//! fluxo no enlace (DF-4), a autoridade remota decidida pelo gate de quem
//! recebe (DF-5), e as vagas divididas com o estágio 1 e a cerimônia (DF-6).
//!
//! ```text
//! A (abre)                                                    B (aceita)
//! stream.open com device ─ gate de A (fabric.stream + fabric.remote)
//!  tabela de A: pedido ─ fio do fluxo (serviço enlace) ─ net.connect ─▶ vaga 7071
//!   quadro 9: IK, prólogo do fluxo, chave do Duke ─────────────────────▶ registro de dispositivos,
//!                                                                        suspensão, teto de sessões
//!                                           ◀── resposta IK ──
//!   abrir {relação, programa, endpoint, intenção, época} ──────────────▶ gate de B: Chamador::Remoto
//!                                                                        no domínio do fluxo → pedido
//!                                           ◀── aceito ─────────────────  stream.accept do processo de B
//!   reconfirma quem abriu, dentro da ordem → aberto
//!   dados ≤ crédito / credito / fim / fechar ◀──────────────────────────▶ cada dados: gate de B
//! ```
//!
//! # A sessão
//!
//! Uma sessão Noise por fluxo, com efêmeras novas, e um conjunto fechado de
//! mensagens dentro do transporte — [`Mensagem`]: um byte de tipo e o
//! corpo, JSON curto no controle e os bytes crus nos dados. O `abrir` vai na
//! primeira mensagem de transporte, e não na carga do IK: a carga da
//! primeira mensagem do IK não tem sigilo para a frente, e repetida por um
//! atacante faria B processar o pedido de novo — no transporte, o replay não
//! passa sem as efêmeras da sessão.
//!
//! As duas pontas rodam a mesma máquina — [`Conduta`] —, cada uma sobre o
//! seu [`Canal`]:
//!
//! - **na origem (A)**, o fio do fluxo, com a autoridade do serviço de
//!   enlace e só ela: a conexão pelo gate (`net.connect`, `net.send`,
//!   `net.recv`, `net.close`, cada um decidido e gravado) — ver
//!   [`crate::enlace`]. Ele não decide nada: leva o que os gates decidiram.
//!   A abertura efetiva em A é o `aceito`, com a decisão de quem abriu
//!   reconfirmada dentro da ordem.
//! - **no destino (B)**, a vaga do enlace despacha o quadro 9 para cá
//!   ([`quadro_na_vaga`]) — acima do teto de sessões, a recusa vai antes do
//!   aperto —, e um fio por sessão a conduz: o aperto contra o registro de
//!   dispositivos, o `abrir` e cada `dados` pelo gate de B como
//!   `Chamador::Remoto` no domínio do fluxo — montado só no
//!   [`crate::enlace`] —, a saída pela vaga. O fio, e não a tarefa da vaga,
//!   porque a decisão de um `dados` pode esperar o caminho da auditoria, e
//!   a tarefa da vaga não espera.
//!
//! O que a sessão aplica sem pedir autoridade: o `fim` e o `fechar` que
//! chegam — o fecho nunca paga nem espera —, e o `credito`, que só limita o
//! que este lado manda. Em A, o `dados` que chega de B vai ao buffer sem
//! decisão: é a resposta do que A abriu, e o processo de A o lê por um
//! `stream.read` que o gate de A decide.
//!
//! # O crédito
//!
//! Cada sentido começa com 16 KiB de crédito; quem lê devolve, agrupado, a
//! partir de 4 KiB liberados. Quem manda nunca passa do crédito: passar é
//! `protocolo`, e o fluxo acaba. A memória de cada lado fica limitada pelo
//! que ele mesmo concedeu, faça o outro o que fizer.
//!
//! # O fim da sessão
//!
//! Quem aceitou fecha a conexão primeiro, e quem abriu espera: a vaga do
//! enlace larga o que chega junto com o FIN. A sessão acaba quando o fluxo
//! acaba — os dois fins ditos e lidos, um `fechar` em qualquer sentido, um
//! gancho daqui, a conexão que cai.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use politica::Codigo;
use politica::Permissao;
use politica::fluxo::{Encerramento, Endpoint, Estado, Ponta, Quem, Titular, motivo};
use protocolo::json::{Json, JsonWriter};
use sigilo::quadro::{self, Tipo};
use sigilo::{Iniciador, Respondedor, Transporte};

use super::{com_tabela, cutucar, depois, encerrados_na_tabela, id_texto, se_ha_tabela};
use crate::trava::Mutex;

/// Quanto a origem espera a resposta do aperto, e o destino o `abrir`: o
/// prazo do aperto das vagas.
const PRAZO_DO_APERTO_MS: u64 = crate::rede::canal::PRAZO_DO_APERTO_MS;

/// De quanto em quanto a sessão olha de novo, mesmo sem evento.
const PASSO_MS: u64 = 1_000;

/// O maior pedaço de dados numa mensagem: um buffer do sentido.
const MAIOR_PEDACO: usize = politica::fluxo::BUFFER_DO_SENTIDO;
const _: () = assert!(MAIOR_PEDACO < Transporte::MAIOR_CLARO);

/// A maior mensagem de controle.
const MAIOR_CONTROLE: usize = 512;

/// O maior endpoint do par, em bytes.
const MAIOR_ENDPOINT: usize = 64;

/// O que a fila de uma sessão no destino guarda, no máximo: o crédito que
/// se concedeu, e folga para o controle e o cabeçalho de cada quadro.
const MAIOR_FILA: usize = 3 * politica::fluxo::BUFFER_DO_SENTIDO;

/// Quanto o fio da sessão espera o caminho da auditoria, no `dados` que
/// chega a B: o `wait` do pedido ao gate.
const ESPERA_DA_AUDITORIA_MS: u64 = crate::rede::espera::PRAZO_MAXIMO_MS;

// ---------------------------------------------------------------------
// As mensagens: o conjunto fechado do domínio.
// ---------------------------------------------------------------------

const ABRIR: u8 = 1;
const ACEITO: u8 = 2;
const RECUSADO: u8 = 3;
const DADOS: u8 = 4;
const CREDITO: u8 = 5;
const FIM: u8 = 6;
const FECHAR: u8 = 7;

/// O `abrir`: o pedido de A, na primeira mensagem de transporte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abertura<'a> {
    /// A relação pela qual A pede.
    pub relacao: [u8; 16],
    /// O programa que A atesta — atestado, e não conferido: vai à
    /// auditoria, e não é critério de nada.
    pub programa: [u8; 32],
    /// O endpoint de B, como a descoberta o deu.
    pub endpoint: &'a str,
    pub intencao: &'a str,
    /// A época do boot de A.
    pub epoca: [u8; 8],
}

/// Uma mensagem do fluxo, dentro de uma mensagem de transporte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mensagem<'a> {
    Abrir(Abertura<'a>),
    /// B aceitou: o id do fluxo em B.
    Aceito(&'a str),
    /// B recusou o `abrir`: o código e o motivo.
    Recusado {
        codigo: &'a str,
        motivo: &'a str,
    },
    /// Bytes do sentido de quem manda, dentro do crédito.
    Dados(&'a [u8]),
    /// Bytes a mais que o outro pode mandar.
    Credito(u32),
    /// O sentido de quem manda terminou.
    Fim,
    /// O fecho, ou o aborto, com o motivo.
    Fechar(&'a str),
}

/// Um endpoint do par como o `abrir` o traz: curto, ASCII imprimível, sem
/// aspas nem barra.
pub fn endpoint_valido(e: &str) -> bool {
    !e.is_empty()
        && e.len() <= MAIOR_ENDPOINT
        && e.bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// Um texto do controle: ASCII imprimível, sem aspas nem barra — o que o
/// JSON curto leva sem escape.
fn texto_valido(t: &str) -> bool {
    t.len() <= MAIOR_CONTROLE
        && t.bytes()
            .all(|b| (b.is_ascii_graphic() || b == b' ') && b != b'"' && b != b'\\')
}

impl<'a> Mensagem<'a> {
    /// Lê uma mensagem decifrada. `None` fora do conjunto fechado: um tipo
    /// desconhecido, um corpo que não é o do tipo, um campo malformado.
    pub fn ler(claro: &'a [u8]) -> Option<Mensagem<'a>> {
        let (&t, corpo) = claro.split_first()?;
        let controle = || (corpo.len() <= MAIOR_CONTROLE).then_some(Json(corpo));
        let texto = |j: &Json<'a>, k: &str| j.member(k).and_then(|v| v.as_str());
        match t {
            ABRIR => {
                let j = controle()?;
                let endpoint = texto(&j, "endpoint").filter(|e| endpoint_valido(e))?;
                let intencao =
                    texto(&j, "intent").filter(|i| politica::malha::intencao_valida(i))?;
                Some(Mensagem::Abrir(Abertura {
                    relacao: texto(&j, "relation").and_then(politica::dispositivos::ler_id)?,
                    programa: texto(&j, "program").and_then(sigilo::de_hex)?,
                    endpoint,
                    intencao,
                    epoca: texto(&j, "epoch").and_then(sigilo::de_hex_fixo::<8>)?,
                }))
            }
            ACEITO => {
                let j = controle()?;
                texto(&j, "stream")
                    .filter(|s| endpoint_valido(s))
                    .map(Mensagem::Aceito)
            }
            RECUSADO => {
                let j = controle()?;
                Some(Mensagem::Recusado {
                    codigo: texto(&j, "code").filter(|c| texto_valido(c))?,
                    motivo: texto(&j, "reason").filter(|m| texto_valido(m))?,
                })
            }
            DADOS => {
                (!corpo.is_empty() && corpo.len() <= MAIOR_PEDACO).then_some(Mensagem::Dados(corpo))
            }
            CREDITO => <[u8; 4]>::try_from(corpo)
                .ok()
                .map(u32::from_le_bytes)
                .filter(|&n| n > 0)
                .map(Mensagem::Credito),
            FIM => corpo.is_empty().then_some(Mensagem::Fim),
            FECHAR => {
                let j = controle()?;
                texto(&j, "reason")
                    .filter(|m| texto_valido(m))
                    .map(Mensagem::Fechar)
            }
            _ => None,
        }
    }

    /// Escreve a mensagem, para cifrar: o byte do tipo e o corpo.
    pub fn escrever(&self) -> Vec<u8> {
        let json = |tipo: u8, campos: &dyn Fn(&mut JsonWriter) -> core::fmt::Result| {
            let mut s = String::new();
            {
                let mut w = JsonWriter::new(&mut s);
                let _ = w
                    .begin_object()
                    .and_then(|()| campos(&mut w))
                    .and_then(|()| w.end_object());
            }
            let mut v = Vec::with_capacity(1 + s.len());
            v.push(tipo);
            v.extend_from_slice(s.as_bytes());
            v
        };
        match self {
            Mensagem::Abrir(a) => json(ABRIR, &|w| {
                w.field_str("relation", &politica::dispositivos::id_texto(&a.relacao))?;
                w.field_str("program", &sigilo::hex(&a.programa))?;
                w.field_str("endpoint", a.endpoint)?;
                w.field_str("intent", a.intencao)?;
                w.field_str("epoch", &sigilo::hex_de(&a.epoca))
            }),
            Mensagem::Aceito(id) => json(ACEITO, &|w| w.field_str("stream", id)),
            Mensagem::Recusado { codigo, motivo } => json(RECUSADO, &|w| {
                w.field_str("code", codigo)?;
                w.field_str("reason", motivo)
            }),
            Mensagem::Dados(d) => {
                let mut v = Vec::with_capacity(1 + d.len());
                v.push(DADOS);
                v.extend_from_slice(d);
                v
            }
            Mensagem::Credito(n) => {
                let mut v = vec![CREDITO];
                v.extend_from_slice(&n.to_le_bytes());
                v
            }
            Mensagem::Fim => vec![FIM],
            Mensagem::Fechar(m) => json(FECHAR, &|w| w.field_str("reason", m)),
        }
    }
}

// ---------------------------------------------------------------------
// O canal: por onde a sessão fala com o par.
// ---------------------------------------------------------------------

/// O que espera a sessão, além do par: se há o que fazer daqui — o fluxo
/// mudou —, e onde deixar o waker para a próxima mudança.
pub type Local<'a> = &'a mut dyn FnMut(Option<&Waker>) -> bool;

/// Por onde a sessão fala com o par: a conexão pelo gate, na origem; a
/// vaga do enlace, no destino; o par de teste, na suíte.
pub trait Canal {
    /// Manda um quadro inteiro.
    fn mandar(&mut self, quadro: &[u8]) -> Result<(), &'static str>;
    /// O próximo quadro do par, esperando até o tempo de máquina `ate_ms`,
    /// em ms — ou até `local` dizer que há o que fazer daqui. `Ok(None)` sem
    /// quadro: o prazo, ou o que fazer daqui. `Err` com o motivo se a
    /// conexão acabou.
    fn proximo(
        &mut self,
        ate_ms: u64,
        local: Local,
    ) -> Result<Option<(Tipo, Vec<u8>)>, &'static str>;
}

/// A espera de um canal: acorda quando `pronto` diz que há o que fazer —
/// ele registra o waker sob a trava de quem muda o estado — ou no tique do
/// prazo.
pub struct Esperar<F: FnMut(&Waker) -> bool> {
    pronto: F,
    relogio: crate::tarefas::relogio::Dormir,
}

impl<F: FnMut(&Waker) -> bool> Esperar<F> {
    /// Até `ate_ms`, em ms de máquina, no máximo um passo.
    pub fn ate(ate_ms: u64, pronto: F) -> Esperar<F> {
        let resta = ate_ms
            .saturating_sub(crate::tempo::uptime_ms())
            .clamp(1, PASSO_MS);
        Esperar {
            pronto,
            relogio: crate::tarefas::relogio::por_ms(resta),
        }
    }
}

impl<F: FnMut(&Waker) -> bool + Unpin> Future for Esperar<F> {
    /// Se acordou pelo que há a fazer, e não pelo prazo.
    type Output = bool;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<bool> {
        let este = self.get_mut();
        if (este.pronto)(cx.waker()) {
            return Poll::Ready(true);
        }
        match Pin::new(&mut este.relogio).poll(cx) {
            Poll::Ready(()) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------
// A máquina da sessão, nos dois lados.
// ---------------------------------------------------------------------

/// O lado da sessão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lado {
    /// Quem abriu: o fio do fluxo.
    Origem,
    /// Quem aceita: o fio da sessão que chegou pela vaga.
    Destino,
}

/// Como o gate de B vê o par: o dispositivo, a relação, a época da origem e
/// o programa atestado — o que o `Chamador::Remoto` leva.
#[derive(Clone, Copy, Debug)]
struct PeloPar {
    dispositivo: [u8; 32],
    relacao: [u8; 16],
    epoca: [u8; 8],
    programa: [u8; 32],
}

/// A sessão de um fluxo com o par, de pé.
struct Conduta {
    n: u64,
    lado: Lado,
    transporte: Transporte,
    titular: Titular,
    par: PeloPar,
    /// A origem: o `aceito` chegou. O destino: o `aceito` saiu.
    aceito: bool,
    /// O fim deste lado já foi dito ao par.
    fim_dito: bool,
    /// O fim do par chegou.
    fim_recebido: bool,
    /// A sessão acabou: o `fechar` saiu ou chegou, o fluxo concluiu, a
    /// conexão caiu.
    acabou: bool,
}

/// O que a sessão manda a seguir, decidido com a tabela na mão.
enum Saida {
    Nada,
    Aceito(String),
    Recusado(String),
    Dados(politica::fluxo::Pedaco),
    Credito(u32),
    Fim,
    /// O fecho daqui, com o motivo — a última mensagem.
    Fechar(String),
}

impl Conduta {
    fn quem_par(&self) -> Quem {
        Quem::Remoto {
            dispositivo: self.par.dispositivo,
            relacao: self.par.relacao,
        }
    }

    /// Cifra `m` e a manda num quadro de dados.
    fn mandar(&mut self, c: &mut impl Canal, m: &Mensagem) -> Result<(), &'static str> {
        let mut claro = m.escrever();
        let mut cifrado = vec![0u8; claro.len() + 16];
        let r = self.transporte.cifrar(&claro, &mut cifrado);
        politica::sigiloso::zerar(&mut claro);
        let n = r.map_err(|_| "a mensagem nao se cifrou")?;
        let q = quadro::montar(Tipo::Dados, &cifrado[..n]).map_err(|_| "a mensagem nao cabe")?;
        politica::sigiloso::zerar(&mut cifrado);
        c.mandar(&q)
    }

    /// O que há a mandar agora, com a tabela na mão: o fecho de um fluxo que
    /// acabou daqui, o aceite, os dados dentro do crédito, o crédito a
    /// devolver, o fim, e o fecho de quem saiu com tudo dito. Devolve
    /// também os encerramentos e os wakers, para depois da trava.
    fn proximo_a_mandar(&mut self, agora: u64) -> (Saida, [u8; 8], Vec<Encerramento>, Vec<Waker>) {
        let n = self.n;
        let lado = self.lado;
        let aceito = self.aceito;
        let fim_dito = self.fim_dito;
        com_tabela(|t| {
            let epoca = t.epoca;
            let fim = t.sessoes.get(&n).and_then(|s| s.fim.clone());
            let Some(r) = t.fluxos.retrato(n) else {
                // Acabou daqui: o motivo vai ao par — no destino, antes do
                // aceite, como a recusa do pedido.
                let m = fim.unwrap_or_else(|| String::from(motivo::CONEXAO));
                let s = if lado == Lado::Destino && !aceito {
                    Saida::Recusado(m)
                } else {
                    Saida::Fechar(m)
                };
                return (s, epoca, Vec::new(), Vec::new());
            };
            if r.estado == Estado::Pedido {
                return (Saida::Nada, epoca, Vec::new(), Vec::new());
            }
            if lado == Lado::Destino && !aceito {
                return (
                    Saida::Aceito(id_texto(&epoca, n)),
                    epoca,
                    Vec::new(),
                    Vec::new(),
                );
            }
            let pedaco = t.fluxos.tirar_para_o_par(n, MAIOR_PEDACO, agora);
            if !pedaco.is_empty() {
                // Abriu espaço no sentido: quem escreve daqui pode seguir.
                let w = cutucar(t, n);
                return (Saida::Dados(pedaco), epoca, Vec::new(), w);
            }
            if let Some(k) = t.fluxos.credito_a_devolver(n) {
                return (
                    Saida::Credito(k.min(u64::from(u32::MAX)) as u32),
                    epoca,
                    Vec::new(),
                    Vec::new(),
                );
            }
            if !fim_dito && t.fluxos.fim_para_o_par(n) {
                // O fim vai agora; se o outro sentido também acabou, o fluxo
                // conclui aqui.
                let es: Vec<Encerramento> = t.fluxos.talvez_encerrar(n).into_iter().collect();
                let w = encerrados_na_tabela(t, &es);
                return (Saida::Fim, epoca, es, w);
            }
            if t.fluxos.saiu_e_foi(n) {
                // A ponta daqui fechou, e tudo o que ela escreveu já foi: o
                // fecho vai ao par, e o fluxo acaba daqui.
                let es: Vec<Encerramento> =
                    t.fluxos.abortar(n, motivo::FECHADO).into_iter().collect();
                let w = encerrados_na_tabela(t, &es);
                return (Saida::Fechar(String::from(motivo::FECHADO)), epoca, es, w);
            }
            (Saida::Nada, epoca, Vec::new(), Vec::new())
        })
    }

    /// Manda o que há a mandar, até não haver mais. `Err` com o motivo se a
    /// conexão não leva.
    fn mandar_o_que_ha(&mut self, c: &mut impl Canal) -> Result<(), &'static str> {
        loop {
            let (s, epoca, es, w) = self.proximo_a_mandar(crate::tempo::uptime_ms());
            depois(epoca, es.clone(), w);
            let concluiu = !es.is_empty();
            match s {
                Saida::Nada => return Ok(()),
                Saida::Aceito(id) => {
                    self.aceito = true;
                    self.mandar(c, &Mensagem::Aceito(&id))?;
                }
                Saida::Recusado(m) => {
                    self.acabou = true;
                    let r = Mensagem::Recusado {
                        codigo: Codigo::Conflict.nome(),
                        motivo: &m,
                    };
                    return self.mandar(c, &r);
                }
                Saida::Dados(p) => self.mandar(c, &Mensagem::Dados(&p))?,
                Saida::Credito(k) => self.mandar(c, &Mensagem::Credito(k))?,
                Saida::Fim => {
                    self.fim_dito = true;
                    self.mandar(c, &Mensagem::Fim)?;
                    if concluiu || self.fim_recebido {
                        return Ok(());
                    }
                }
                Saida::Fechar(m) => {
                    self.acabou = true;
                    return self.mandar(c, &Mensagem::Fechar(&m));
                }
            }
        }
    }

    /// Encerra o fluxo daqui, com `m`, se ele ainda está vivo — e grava.
    fn abortar(&self, m: &str) {
        abortar_daqui(self.n, m);
    }

    /// Fecha por um erro do protocolo: o fluxo acaba com `protocolo`, e o
    /// par ouve o `fechar`.
    fn fora_do_protocolo(&mut self, c: &mut impl Canal) {
        self.abortar(motivo::PROTOCOLO);
        let _ = self.mandar(c, &Mensagem::Fechar(motivo::PROTOCOLO));
        self.acabou = true;
    }

    /// Aplica à tabela o que chegou do par, com a ordem das gravações na mão
    /// — o fim, o fecho, o crédito, os dados na origem: o kernel aplica e
    /// grava, sem pedir autoridade. Acorda quem espera daqui.
    fn aplicar(
        &self,
        f: impl FnOnce(
            &mut politica::fluxo::Fluxos,
        ) -> Result<Option<Encerramento>, politica::fluxo::Recusa>,
    ) -> Result<bool, politica::fluxo::Recusa> {
        let n = self.n;
        let feito = crate::persistencia::em_ordem(|| {
            se_ha_tabela(|t| {
                let r = f(&mut t.fluxos);
                let es: Vec<Encerramento> = match &r {
                    Ok(Some(e)) => alloc::vec![e.clone()],
                    _ => Vec::new(),
                };
                let mut w = cutucar(t, n);
                w.extend(encerrados_na_tabela(t, &es));
                (t.epoca, r, es, w)
            })
        });
        let Some((epoca, r, es, w)) = feito else {
            return Ok(true);
        };
        let acabou = !es.is_empty();
        depois(epoca, es, w);
        r.map(|_| acabou)
    }

    /// Uma mensagem do par, já decifrada e lida.
    fn receber(&mut self, c: &mut impl Canal, m: Mensagem) {
        let agora = crate::tempo::uptime_ms();
        let n = self.n;
        let quem = self.quem_par();
        let titular = self.titular;
        match (self.lado, self.aceito, m) {
            // O fecho do par, em qualquer hora: o fluxo acaba, ou fica
            // legível até o fim do que ele mandou.
            (_, aceito, Mensagem::Fechar(motivo_do_par)) => {
                let m = politica::fluxo::motivo_do_par(motivo_do_par);
                let _ = self.aplicar(|f| {
                    Ok(if aceito {
                        f.fechar_do_par(n, &m)
                    } else {
                        f.recusar(n, &m).or_else(|| f.abortar(n, &m))
                    })
                });
                self.acabou = true;
            }
            // A origem, esperando o aceite.
            (Lado::Origem, false, Mensagem::Aceito(_)) => self.aceito_na_origem(c),
            (Lado::Origem, false, Mensagem::Recusado { codigo, motivo }) => {
                let m = politica::fluxo::motivo_do_par(&format!("{codigo} {motivo}"));
                let _ = self.aplicar(|f| Ok(f.recusar(n, &m).or_else(|| f.abortar(n, &m))));
                self.acabou = true;
            }
            // Os dados, o crédito e o fim, com o fluxo aberto.
            (Lado::Origem, true, Mensagem::Dados(d)) => {
                let r = self.aplicar(|f| f.escrever(titular, quem, n, d, agora).map(|_| None));
                match r {
                    Ok(_) => {}
                    // A ponta daqui fechou: o que chega depois é descartado,
                    // e o `fechar` já vai.
                    Err(politica::fluxo::Recusa::Encerrado(_)) => {}
                    Err(_) => self.fora_do_protocolo(c),
                }
            }
            // Em B, a conta primeiro — o crédito, o aceite, o fim: passar
            // dela é protocolo, e não decisão de ninguém —, e então o gate.
            (Lado::Destino, true, Mensagem::Dados(d)) => {
                match se_ha_tabela(|t| t.fluxos.cabe_do_par(n, d.len())) {
                    Some(Ok(())) => self.dados_pelo_gate(d),
                    // A ponta daqui fechou, ou o fluxo acabou: descartado.
                    Some(Err(politica::fluxo::Recusa::Encerrado(_)))
                    | Some(Err(politica::fluxo::Recusa::NaoExiste))
                    | None => {}
                    Some(Err(_)) => self.fora_do_protocolo(c),
                }
            }
            (_, true, Mensagem::Credito(k)) => {
                if self
                    .aplicar(|f| f.credito_do_par(n, u64::from(k)).map(|()| None))
                    .is_err()
                {
                    self.fora_do_protocolo(c);
                }
            }
            (_, true, Mensagem::Fim) => match self.aplicar(|f| f.fim_do_par(n, agora)) {
                Ok(_) => self.fim_recebido = true,
                Err(_) => self.fora_do_protocolo(c),
            },
            // Qualquer outra coisa — um `abrir` repetido, `dados` antes do
            // aceite, um `aceito` no destino — é protocolo.
            _ => self.fora_do_protocolo(c),
        }
    }

    /// O `aceito` chegou à origem: a decisão de quem abriu, de novo, dentro
    /// da ordem — ele ainda exerceria `fabric.stream` sobre a intenção e
    /// `fabric.remote` sobre o dispositivo, a relação está ativa, o
    /// dispositivo não está suspenso, a máquina não está desligando —, e o
    /// fluxo abre. Se não, ele acaba com `quem abriu nao pode mais`, e o par
    /// ouve o `fechar`.
    fn aceito_na_origem(&mut self, c: &mut impl Canal) {
        let n = self.n;
        let par = self.par;
        let agora = crate::tempo::uptime_ms();
        let feito = crate::persistencia::em_ordem(|| {
            let r = se_ha_tabela(|t| t.fluxos.retrato(n)).flatten()?;
            let Ponta::Processo { fio, .. } = r.abridor else {
                return None;
            };
            let intencao = super::recurso_da_intencao(&r.intencao);
            // A relação, agora: ativa, da Pessoa do fluxo, o dispositivo não
            // suspenso.
            let nome = crate::dispositivos::relacao(&par.dispositivo, &par.relacao)
                .filter(|(_, rel)| Titular::Pessoa(rel.pessoa) == r.titular)
                .filter(|_| !crate::contencao::dispositivo_suspenso(&par.dispositivo))
                .map(|(nome, _)| format!("{}{nome}", politica::arquivo::PREFIXO_DE_DISPOSITIVO));
            let pode = crate::energia::pedida().is_none()
                && crate::autorizacao::processo_exerceria(fio, Permissao::FabricStream, &intencao)
                && nome.as_ref().is_some_and(|d| {
                    crate::autorizacao::processo_exerceria(fio, Permissao::FabricRemote, d)
                });
            se_ha_tabela(|t| {
                let (r, es) = if pode {
                    (t.fluxos.aceito_pelo_par(n, agora).ok(), Vec::new())
                } else {
                    let es: Vec<Encerramento> =
                        t.fluxos.recusar(n, motivo::ABRIDOR).into_iter().collect();
                    (None, es)
                };
                let mut w = cutucar(t, n);
                w.extend(encerrados_na_tabela(t, &es));
                (t.epoca, r, es, w, nome.clone())
            })
        });
        let Some((epoca, versao, es, w, nome)) = feito else {
            self.acabou = true;
            return;
        };
        depois(epoca, es, w);
        match versao {
            Some(v) => {
                self.aceito = true;
                crate::autorizacao::auditar_do_kernel(
                    "stream.open",
                    &format!(
                        "{} ; {}",
                        super::recurso_do_fluxo(&epoca, n),
                        nome.unwrap_or_default()
                    ),
                    Codigo::Allow,
                    &format!("aberto pelo par; versao {v}"),
                );
            }
            None => {
                let _ = self.mandar(c, &Mensagem::Fechar(motivo::ABRIDOR));
                self.acabou = true;
            }
        }
    }

    /// Um `dados` que chegou a B: decidido pelo gate de B, como o par — o
    /// `stream.write` no domínio do fluxo, com os bytes no anexo. A recusa
    /// encerra o fluxo com o motivo do gate, e o par ouve o `fechar`.
    fn dados_pelo_gate(&mut self, d: &[u8]) {
        let epoca = se_ha_tabela(|t| t.epoca).unwrap_or([0; 8]);
        let id = id_texto(&epoca, self.n);
        let mut pedido = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"stream.write","params":{{"stream":"{id}","attachment":{},"wait":{ESPERA_DA_AUDITORIA_MS}}}}}"#,
            d.len()
        )
        .into_bytes();
        pedido.push(crate::nativo::SEPARADOR);
        pedido.extend_from_slice(d);
        let p = self.par;
        let mut envelope = crate::enlace::pedir_pelo_par_no_fluxo(
            p.dispositivo,
            p.relacao,
            p.epoca,
            p.programa,
            &pedido,
        );
        politica::sigiloso::zerar(&mut pedido);
        let r = resultado(&envelope);
        politica::sigiloso::zerar(&mut envelope);
        match r {
            Ok(j)
                if Json(&j).member("written").and_then(|v| v.as_u64()) == Some(d.len() as u64) => {}
            Ok(_) => self.abortar(motivo::PROTOCOLO),
            // O gate recusou: pela política, ele mesmo já encerrou o fluxo —
            // ver `fluxo::recusado_pelo_gate`; pelo resto, encerra aqui.
            Err((codigo, m)) => {
                let m = politica::fluxo::motivo_guardado(&format!("{codigo}: {m}"));
                self.abortar(&m);
            }
        }
    }

    /// O protocolo do fluxo acabou: os dois fins andaram, ou um `fechar`.
    /// O que sobra é só leitura daqui, sem a sessão.
    fn terminada(&self) -> bool {
        self.acabou || (self.fim_dito && self.fim_recebido)
    }

    /// A sessão, até o fim: manda o que há, espera o par ou o que mudar
    /// daqui, e aplica o que chega.
    fn conduzir(&mut self, c: &mut impl Canal) {
        let n = self.n;
        while !self.terminada() {
            if let Err(_m) = self.mandar_o_que_ha(c) {
                self.abortar(motivo::CONEXAO);
                return;
            }
            if self.terminada() {
                return;
            }
            let ate = crate::tempo::uptime_ms().saturating_add(PASSO_MS);
            let lado = self.lado;
            let aceito = self.aceito;
            let mut local = |w: Option<&Waker>| tem_o_que_fazer(n, lado, aceito, w);
            let chegou = match c.proximo(ate, &mut local) {
                Ok(q) => q,
                Err(_) => {
                    self.abortar(motivo::CONEXAO);
                    return;
                }
            };
            let Some((tipo, corpo)) = chegou else {
                continue;
            };
            if tipo != Tipo::Dados {
                // Um quadro fora do transporte: a recusa em claro de quem
                // encerrou, ou lixo — a sessão acaba.
                let m = if tipo == Tipo::Recusa {
                    politica::fluxo::motivo_do_par(core::str::from_utf8(&corpo).unwrap_or("?"))
                } else {
                    String::from(motivo::PROTOCOLO)
                };
                self.abortar(&m);
                return;
            }
            let mut claro = vec![0u8; corpo.len()];
            let Ok(k) = self.transporte.decifrar(&corpo, &mut claro) else {
                self.fora_do_protocolo(c);
                return;
            };
            match Mensagem::ler(&claro[..k]) {
                Some(m) => self.receber(c, m),
                None => self.fora_do_protocolo(c),
            }
            politica::sigiloso::zerar(&mut claro);
        }
    }
}

/// Se a sessão do fluxo `n` tem o que fazer daqui — o fluxo acabou, há o
/// que mandar, o aceite saiu —; se não, `waker` fica para a próxima
/// mudança, sob a mesma trava com que a tabela muda.
fn tem_o_que_fazer(n: u64, lado: Lado, aceito: bool, waker: Option<&Waker>) -> bool {
    se_ha_tabela(|t| {
        let Some(estado) = t.fluxos.retrato(n).map(|r| r.estado) else {
            return true;
        };
        if t.sessoes.get(&n).is_some_and(|s| s.fim.is_some()) {
            return true;
        }
        if lado == Lado::Destino && !aceito && estado == Estado::Aberto {
            return true;
        }
        if estado == Estado::Aberto && t.fluxos.par_tem_o_que_fazer(n) {
            return true;
        }
        if let (Some(w), Some(s)) = (waker, t.sessoes.get_mut(&n)) {
            s.waker = Some(w.clone());
        }
        false
    })
    .unwrap_or(true)
}

/// O resultado de um envelope do gate: o `result` de quem passou, ou o
/// código e o motivo de quem foi recusado — pelo gate ou pelo handler.
fn resultado(envelope: &[u8]) -> Result<Vec<u8>, (String, String)> {
    let raiz = Json(envelope);
    if let Some(r) = raiz.member("result") {
        if r.member("ok").and_then(|v| v.as_bool()) == Some(false) {
            let codigo = r.member("code").and_then(|v| v.as_str()).unwrap_or("ERROR");
            let m = r.member("error").and_then(|v| v.as_str()).unwrap_or("");
            return Err((String::from(codigo), String::from(m)));
        }
        return Ok(r.0.to_vec());
    }
    let erro = raiz.member("error");
    let codigo = erro
        .as_ref()
        .and_then(|e| e.member("data"))
        .and_then(|d| d.as_str())
        .unwrap_or("ERROR");
    let m = erro
        .as_ref()
        .and_then(|e| e.member("message"))
        .and_then(|d| d.as_str())
        .unwrap_or("");
    Err((String::from(codigo), String::from(m)))
}

/// Os 8 primeiros hex de `bytes`, para a auditoria.
fn hex8(bytes: &[u8]) -> String {
    let mut h = sigilo::hex_de(bytes);
    h.truncate(8);
    h
}

// ---------------------------------------------------------------------
// A origem: o fio do fluxo.
// ---------------------------------------------------------------------

/// Onde o fio do fluxo `n` conecta: o endereço da relação dele, ativa, com
/// o dispositivo não suspenso. `None` se o fluxo acabou — e então não há o
/// que levar —, ou se a relação não leva: o fluxo acaba aqui.
pub fn endereco_da_origem(n: u64) -> Option<String> {
    let r = se_ha_tabela(|t| t.fluxos.retrato(n)).flatten()?;
    let Ponta::Remota {
        dispositivo,
        relacao,
        ..
    } = r.aceitante
    else {
        return None;
    };
    let motivo_de_nao = if crate::contencao::dispositivo_suspenso(&dispositivo) {
        Some(motivo::DISPOSITIVO_SUSPENSO)
    } else {
        match crate::dispositivos::relacao(&dispositivo, &relacao) {
            None => Some(motivo::RELACAO),
            Some((_, rel)) => match rel.endereco {
                Some(e) => return Some(e),
                None => Some(motivo::CONEXAO),
            },
        }
    };
    if let Some(m) = motivo_de_nao {
        abortar_daqui(n, m);
    }
    None
}

/// O fio do fluxo `n` não conectou ao par: o fluxo acaba, com o motivo.
pub fn nao_conectou(n: u64, _codigo: Codigo, _motivo: &'static str) {
    abortar_daqui(n, motivo::CONEXAO);
}

/// O fio do fluxo `n` não subiu: o fluxo acaba.
pub fn sem_fio(n: u64) {
    abortar_daqui(n, motivo::SEM_FIO);
}

/// Encerra o fluxo `n` daqui, com `m`, e grava.
fn abortar_daqui(n: u64, m: &str) {
    let feito = crate::persistencia::em_ordem(|| {
        se_ha_tabela(|t| {
            let es: Vec<Encerramento> = t.fluxos.abortar(n, m).into_iter().collect();
            let w = encerrados_na_tabela(t, &es);
            (t.epoca, es, w)
        })
    });
    if let Some((epoca, es, w)) = feito {
        depois(epoca, es, w);
    }
}

/// A sessão de um fluxo que sai daqui, pelo canal já conectado ao par: o
/// aperto IK com a chave do Duke e o prólogo do fluxo, o `abrir` na
/// primeira mensagem de transporte, o aceite reconfirmado, e os dados.
/// Quem chama é o fio do fluxo — ou, na suíte, o caso que faz de par.
pub fn conduzir_na_origem(n: u64, c: &mut impl Canal) {
    let Some(r) = se_ha_tabela(|t| t.fluxos.retrato(n)).flatten() else {
        return fim_da_sessao(n);
    };
    let (
        Ponta::Remota {
            dispositivo,
            relacao,
            ..
        },
        Ponta::Processo { programa, .. },
        Endpoint::DoPar(endpoint),
    ) = (&r.aceitante, &r.abridor, &r.endpoint)
    else {
        return fim_da_sessao(n);
    };
    let par = PeloPar {
        dispositivo: *dispositivo,
        relacao: *relacao,
        epoca: crate::enlace::epoca(),
        programa: programa.resumo,
    };
    match apertar_na_origem(c, &par, n) {
        Ok(transporte) => {
            let mut s = Conduta {
                n,
                lado: Lado::Origem,
                transporte,
                titular: r.titular,
                par,
                aceito: false,
                fim_dito: false,
                fim_recebido: false,
                acabou: false,
            };
            let abrir = Mensagem::Abrir(Abertura {
                relacao: par.relacao,
                programa: par.programa,
                endpoint,
                intencao: &r.intencao,
                epoca: par.epoca,
            });
            if s.mandar(c, &abrir).is_err() {
                s.abortar(motivo::CONEXAO);
            } else {
                s.conduzir(c);
            }
        }
        Err(m) => abortar_daqui(n, &m),
    }
    fim_da_sessao(n);
}

/// O aperto na origem: a primeira mensagem do IK, com a chave do Duke e a
/// do par fixada pela relação, e a resposta no prazo do aperto. `Err` com o
/// motivo do fluxo.
fn apertar_na_origem(c: &mut impl Canal, par: &PeloPar, n: u64) -> Result<Transporte, String> {
    let efemera = crate::aleatorio::chave().map_err(|_| String::from(motivo::APERTO))?;
    let mut primeira = vec![0u8; 256];
    let escrito = crate::identidade::com_chave_do_duke(|k| {
        Iniciador::novo(sigilo::PROLOGO_DO_FLUXO, k, &par.dispositivo).escrever(
            efemera,
            b"",
            &mut primeira,
        )
    });
    let Some(Ok((tam, aguardando))) = escrito else {
        return Err(String::from(motivo::APERTO));
    };
    let q = quadro::montar(Tipo::InicioFluxo, &primeira[..tam])
        .map_err(|_| String::from(motivo::APERTO))?;
    c.mandar(&q).map_err(|_| String::from(motivo::CONEXAO))?;
    let limite = crate::tempo::uptime_ms().saturating_add(PRAZO_DO_APERTO_MS);
    loop {
        // Daqui, durante o aperto, só o fim do fluxo importa.
        let mut local = |w: Option<&Waker>| fim_daqui(n, w);
        match c.proximo(limite, &mut local) {
            Err(_) => return Err(String::from(motivo::CONEXAO)),
            Ok(Some((Tipo::Resposta, corpo))) => {
                let mut lixo = vec![0u8; corpo.len()];
                return aguardando
                    .ler(&corpo, &mut lixo)
                    .map(|(_, t)| t)
                    .map_err(|_| String::from(motivo::APERTO));
            }
            Ok(Some((Tipo::Recusa, corpo))) => {
                return Err(politica::fluxo::motivo_do_par(
                    core::str::from_utf8(&corpo).unwrap_or("?"),
                ));
            }
            Ok(Some(_)) => return Err(String::from(motivo::PROTOCOLO)),
            Ok(None) => {
                if fim_daqui(n, None) {
                    return Err(String::from(motivo::FECHADO));
                }
                if crate::tempo::uptime_ms() >= limite {
                    return Err(String::from(motivo::PAR_MUDO));
                }
            }
        }
    }
}

/// Se o fluxo `n` acabou daqui — ou nunca foi; se não, `waker` fica para o
/// fim.
fn fim_daqui(n: u64, waker: Option<&Waker>) -> bool {
    se_ha_tabela(|t| {
        if t.fluxos.retrato(n).is_none() || t.sessoes.get(&n).is_some_and(|s| s.fim.is_some()) {
            return true;
        }
        if let (Some(w), Some(s)) = (waker, t.sessoes.get_mut(&n)) {
            s.waker = Some(w.clone());
        }
        false
    })
    .unwrap_or(true)
}

/// A sessão do fluxo `n` acabou: ela sai da tabela, e o fluxo que ainda
/// precisasse dela acaba com ela — nenhum fluxo remoto fica esperando uma
/// sessão que não há. O que só tem leitura daqui a fazer — os dois fins
/// andaram, ou o fecho em ordem do par — fica, até quem lê acabar.
fn fim_da_sessao(n: u64) {
    let precisa = se_ha_tabela(|t| {
        t.sessoes.remove(&n);
        t.fluxos.precisa_do_par(n)
    })
    .unwrap_or(false);
    if precisa {
        abortar_daqui(n, motivo::CONEXAO);
    }
}

// ---------------------------------------------------------------------
// O destino: as sessões que chegam pelas vagas do enlace.
// ---------------------------------------------------------------------

/// Uma sessão de fluxo que chegou por uma vaga do enlace.
struct NaVaga {
    /// O número da sessão — o argumento do fio dela.
    numero: u64,
    v: u8,
    g: u64,
    /// Os quadros que a vaga remontou, para o fio.
    entrada: VecDeque<(Tipo, Vec<u8>)>,
    bytes: usize,
    waker: Option<Waker>,
    /// A conexão acabou, ou a fila passou do teto.
    acabou: bool,
    /// O fluxo, depois do `abrir`.
    fluxo: Option<u64>,
    /// A chave que provou o aperto.
    chave: Option<[u8; 32]>,
}

static NAS_VAGAS: Mutex<Vec<NaVaga>> = Mutex::new(Vec::new());

/// O número da próxima sessão.
static PROXIMA: AtomicU64 = AtomicU64::new(1);

fn com_vagas<R>(f: impl FnOnce(&mut Vec<NaVaga>) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut NAS_VAGAS.lock()))
}

/// Na suíte, o que iria às vagas fica aqui, para o caso ler — ver
/// [`saida_de_teste`].
#[cfg(feature = "modo-teste")]
static VAGAS_DE_TESTE: Mutex<Option<Vec<NaVagaDeTeste>>> = Mutex::new(None);

/// O que a sessão fez numa vaga, na suíte.
#[cfg(feature = "modo-teste")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaVagaDeTeste {
    Quadro(u8, u64, Vec<u8>),
    Identificada(u8, u64, [u8; 32]),
    Encerrada(u8, u64),
}

#[cfg(feature = "modo-teste")]
fn na_vaga_de_teste(e: NaVagaDeTeste) -> bool {
    crate::arch::sem_interrupcoes(|| match VAGAS_DE_TESTE.lock().as_mut() {
        Some(v) => {
            v.push(e);
            true
        }
        None => false,
    })
}

/// Põe um quadro na saída da vaga `v`, na conexão `g`, e faz a pilha
/// andar.
fn por_na_vaga(v: u8, g: u64, q: &[u8]) -> bool {
    #[cfg(feature = "modo-teste")]
    if na_vaga_de_teste(NaVagaDeTeste::Quadro(v, g, q.to_vec())) {
        return true;
    }
    let ok = crate::rede::canal::enfileirar_na_conexao(v, g, q);
    crate::rede::pilha::sondar();
    ok
}

fn identificar_na_vaga(v: u8, g: u64, chave: [u8; 32]) {
    #[cfg(feature = "modo-teste")]
    if na_vaga_de_teste(NaVagaDeTeste::Identificada(v, g, chave)) {
        return;
    }
    crate::rede::canal::identificar(v, g, chave);
}

fn encerrar_vaga(v: u8, g: u64) {
    #[cfg(feature = "modo-teste")]
    if na_vaga_de_teste(NaVagaDeTeste::Encerrada(v, g)) {
        return;
    }
    crate::rede::canal::encerrar(v, g);
}

/// O par da conexão, para a auditoria.
fn par_da_conexao(v: u8, g: u64) -> String {
    crate::rede::canal::remoto_da_conexao(v, g)
        .map_or_else(|| String::from("tcp"), crate::rede::canal::texto_do_par)
}

/// Recusa uma sessão que chega: grava (como `stream.session`), manda a
/// recusa em claro e fecha a vaga.
fn recusar_na_vaga(v: u8, g: u64, chave: Option<[u8; 32]>, codigo: Codigo, m: &str) {
    let mut detalhe = format!("{m} ({})", par_da_conexao(v, g));
    detalhe.truncate(politica::auditoria::MAIOR_DETALHE);
    crate::autorizacao::auditar_aperto_do_fluxo(chave, "", codigo, &detalhe);
    if let Ok(q) = quadro::montar(Tipo::Recusa, m.as_bytes()) {
        por_na_vaga(v, g, &q);
    }
    encerrar_vaga(v, g);
}

/// Um quadro numa vaga do enlace cuja sessão é — ou vira — de fluxo. É o
/// respondedor de [`crate::enlace`] quem chama, no primeiro quadro da
/// conexão (o 9) e em todos os seguintes. O primeiro passa pelo teto de
/// sessões, pela janela de apertos da vaga e pelo desligamento **antes**
/// do aperto, que não gasta DH; os outros vão à fila do fio da sessão.
/// Falso se a sessão acabou: a recusa e o fecho já saíram.
pub fn quadro_na_vaga(v: u8, g: u64, tipo: Tipo, corpo: &[u8]) -> bool {
    let na_fila = com_vagas(|vs| {
        let s = vs.iter_mut().find(|s| s.v == v && s.g == g)?;
        if s.acabou {
            return Some(false);
        }
        if s.bytes + corpo.len() > MAIOR_FILA {
            // O par mandou além do que se concedeu: a sessão acaba.
            s.acabou = true;
        } else {
            s.bytes += corpo.len();
            s.entrada.push_back((tipo, corpo.to_vec()));
        }
        if let Some(w) = s.waker.take() {
            w.wake();
        }
        Some(!s.acabou)
    });
    if let Some(continua) = na_fila {
        return continua;
    }
    if tipo != Tipo::InicioFluxo {
        return false;
    }
    if !crate::autorizacao::permitir_aperto_do_enlace(v) {
        if let Ok(q) = quadro::montar(Tipo::Recusa, b"apertos demais; espere a janela") {
            por_na_vaga(v, g, &q);
        }
        encerrar_vaga(v, g);
        return false;
    }
    if crate::energia::pedida().is_some() {
        recusar_na_vaga(v, g, None, Codigo::Conflict, "a maquina esta desligando");
        return false;
    }
    let numero = PROXIMA.fetch_add(1, Ordering::Relaxed);
    let coube = com_vagas(|vs| {
        if vs.len() >= politica::fluxo::SESSOES_QUE_CHEGAM {
            return false;
        }
        let mut entrada = VecDeque::new();
        entrada.push_back((tipo, corpo.to_vec()));
        vs.push(NaVaga {
            numero,
            v,
            g,
            entrada,
            bytes: corpo.len(),
            waker: None,
            acabou: false,
            fluxo: None,
            chave: None,
        });
        true
    });
    if !coube {
        recusar_na_vaga(
            v,
            g,
            None,
            Codigo::Conflict,
            "sessoes de fluxo demais; tente depois",
        );
        return false;
    }
    if let Err(m) = crate::enlace::lancar_a_sessao_do_fluxo(numero) {
        com_vagas(|vs| vs.retain(|s| s.numero != numero));
        recusar_na_vaga(v, g, None, Codigo::Error, m);
        return false;
    }
    true
}

/// A conexão `g` da vaga `v` acabou: a sessão dela, se é de fluxo, acaba —
/// o fio acorda, e o fluxo acaba com `a conexao caiu`. Chamada pelo
/// coletor das vagas, fora das travas.
pub fn vaga_acabou(v: u8, g: u64) {
    com_vagas(|vs| {
        if let Some(s) = vs.iter_mut().find(|s| s.v == v && s.g == g) {
            s.acabou = true;
            if let Some(w) = s.waker.take() {
                w.wake();
            }
        }
    });
}

/// Só para a suíte: as sessões de fluxo que chegaram e estão de pé.
#[cfg(feature = "modo-teste")]
pub fn sessoes_de_teste() -> usize {
    com_vagas(|vs| vs.len())
}

/// O canal do destino: a fila que a vaga enche, e a saída da vaga.
struct CanalDaVaga {
    numero: u64,
    v: u8,
    g: u64,
}

impl Canal for CanalDaVaga {
    fn mandar(&mut self, q: &[u8]) -> Result<(), &'static str> {
        if por_na_vaga(self.v, self.g, q) {
            Ok(())
        } else {
            Err("a vaga nao leva")
        }
    }

    fn proximo(
        &mut self,
        ate_ms: u64,
        local: Local,
    ) -> Result<Option<(Tipo, Vec<u8>)>, &'static str> {
        let numero = self.numero;
        // O quadro da fila, se há; a conexão que acabou; ou nada.
        let tirar = || -> Option<Result<(Tipo, Vec<u8>), ()>> {
            com_vagas(|vs| {
                let Some(s) = vs.iter_mut().find(|s| s.numero == numero) else {
                    return Some(Err(()));
                };
                if let Some((t, c)) = s.entrada.pop_front() {
                    s.bytes -= c.len();
                    return Some(Ok((t, c)));
                }
                s.acabou.then_some(Err(()))
            })
        };
        loop {
            match tirar() {
                Some(Ok(q)) => return Ok(Some(q)),
                Some(Err(())) => return Err("a conexao caiu"),
                None => {}
            }
            if local(None) || crate::tempo::uptime_ms() >= ate_ms {
                return Ok(None);
            }
            let acordou = crate::fios::bloquear_em(Esperar::ate(ate_ms, |w: &Waker| {
                // Os dois wakers ficam, cada um sob a trava de quem muda: a
                // vaga, e a tabela do fluxo.
                let na_fila = com_vagas(|vs| {
                    vs.iter_mut().find(|s| s.numero == numero).is_none_or(|s| {
                        let pronto = !s.entrada.is_empty() || s.acabou;
                        if !pronto {
                            s.waker = Some(w.clone());
                        }
                        pronto
                    })
                });
                na_fila || local(Some(w))
            }));
            if !acordou && crate::tempo::uptime_ms() >= ate_ms {
                return Ok(None);
            }
        }
    }
}

/// A sessão `numero` no destino, no fio dela — que o enlace lança com a
/// autoridade do serviço de enlace, e só ela: o aperto contra o registro de
/// dispositivos, o `abrir` pelo gate de B como o par, e a conduta até o
/// fim. A vaga fecha no fim — quem aceitou fecha primeiro.
pub(crate) fn sessao_que_chega(numero: u64) {
    let Some((v, g)) = com_vagas(|vs| vs.iter().find(|s| s.numero == numero).map(|s| (s.v, s.g)))
    else {
        return;
    };
    let mut c = CanalDaVaga { numero, v, g };
    let fluxo = sessao_no_destino(&mut c, v, g);
    com_vagas(|vs| vs.retain(|s| s.numero != numero));
    if let Some(n) = fluxo {
        fim_da_sessao(n);
    }
    encerrar_vaga(v, g);
}

/// O aperto, o `abrir` e a conduta. Devolve o fluxo, se chegou a haver um.
fn sessao_no_destino(c: &mut CanalDaVaga, v: u8, g: u64) -> Option<u64> {
    let numero = c.numero;
    // O primeiro quadro: a primeira mensagem do IK, já na fila.
    let primeira = match c.proximo(0, &mut |_| false) {
        Ok(Some((Tipo::InicioFluxo, corpo))) => corpo,
        _ => return None,
    };
    let mut carga = vec![0u8; primeira.len()];
    let lido = crate::identidade::com_chave_do_duke(|k| {
        Respondedor::novo(sigilo::PROLOGO_DO_FLUXO, k).ler(&primeira, &mut carga)
    });
    let recebido = match lido {
        None => {
            recusar_na_vaga(v, g, None, Codigo::Error, "o Duke nao tem chave");
            return None;
        }
        Some(Err(e)) => {
            recusar_na_vaga(v, g, None, Codigo::DenyNotAuthenticated, e.motivo());
            return None;
        }
        Some(Ok((_, r))) => r,
    };
    // Autenticado não é relacionado: o registro de dispositivos diz se a
    // chave tem relação aqui — e a lápide a tirou de lá.
    let chave = recebido.remota();
    let Some(d) = crate::dispositivos::dispositivo(&chave) else {
        recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::DenyNotAuthenticated,
            "chave fora do registro de dispositivos",
        );
        return None;
    };
    if crate::contencao::dispositivo_suspenso(&chave) {
        recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::DenyCredential,
            "dispositivo suspenso",
        );
        return None;
    }
    let resposta = crate::aleatorio::chave().ok().and_then(|efemera| {
        let mut saida = vec![0u8; 128];
        let (m, t) = recebido.escrever(efemera, b"", &mut saida).ok()?;
        Some((quadro::montar(Tipo::Resposta, &saida[..m]).ok()?, t))
    });
    let Some((q, mut transporte)) = resposta else {
        recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::Error,
            "a resposta do aperto nao se escreveu",
        );
        return None;
    };
    com_vagas(|vs| {
        if let Some(s) = vs.iter_mut().find(|s| s.numero == numero) {
            s.chave = Some(chave);
        }
    });
    if c.mandar(&q).is_err() {
        return None;
    }
    // O `abrir`: a primeira mensagem de transporte, no prazo do aperto.
    let limite = crate::tempo::uptime_ms().saturating_add(PRAZO_DO_APERTO_MS);
    let corpo = loop {
        match c.proximo(limite, &mut |_| false) {
            Ok(Some((Tipo::Dados, corpo))) => break corpo,
            Ok(None) if crate::tempo::uptime_ms() < limite => continue,
            Ok(None) => {
                recusar_na_vaga(
                    v,
                    g,
                    Some(chave),
                    Codigo::DenyNotAuthenticated,
                    "o abrir nao chegou no prazo",
                );
                return None;
            }
            Ok(Some(_)) => {
                recusar_na_vaga(
                    v,
                    g,
                    Some(chave),
                    Codigo::InvalidArgument,
                    "quadro fora de ordem",
                );
                return None;
            }
            Err(_) => return None,
        }
    };
    let mut claro = vec![0u8; corpo.len()];
    let aberto = transporte.decifrar(&corpo, &mut claro).ok().and_then(|k| {
        match Mensagem::ler(&claro[..k]) {
            Some(Mensagem::Abrir(a)) => Some((
                PeloPar {
                    dispositivo: chave,
                    relacao: a.relacao,
                    epoca: a.epoca,
                    programa: a.programa,
                },
                String::from(a.endpoint),
                String::from(a.intencao),
            )),
            _ => None,
        }
    });
    politica::sigiloso::zerar(&mut claro);
    let Some((par, endpoint, intencao)) = aberto else {
        recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::InvalidArgument,
            "a primeira mensagem nao e um abrir",
        );
        return None;
    };
    // A chave provou o aperto e a sessão abriu: a vaga sai do prazo do
    // aperto, e a sessão vai à auditoria.
    identificar_na_vaga(v, g, chave);
    let mut detalhe = format!(
        "{} ; relacao {} ; atestado {} ({})",
        crate::identidade::impressao(&chave),
        &politica::dispositivos::id_texto(&par.relacao)[..8],
        hex8(&par.programa),
        par_da_conexao(v, g)
    );
    detalhe.truncate(politica::auditoria::MAIOR_DETALHE);
    crate::autorizacao::auditar_aperto_do_fluxo(Some(chave), &d.nome, Codigo::Allow, &detalhe);
    // O `abrir` pelo gate de B, como o par, no domínio do fluxo.
    let mut params = String::new();
    {
        let mut w = JsonWriter::new(&mut params);
        let _ = w
            .begin_object()
            .and_then(|()| w.field_str("endpoint", &endpoint))
            .and_then(|()| w.field_str("intent", &intencao))
            .and_then(|()| w.end_object());
    }
    let pedido = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"stream.open","params":{params}}}"#);
    let envelope = crate::enlace::pedir_pelo_par_no_fluxo(
        par.dispositivo,
        par.relacao,
        par.epoca,
        par.programa,
        pedido.as_bytes(),
    );
    let mut s = Conduta {
        n: 0,
        lado: Lado::Destino,
        transporte,
        titular: Titular::Sistema,
        par,
        aceito: false,
        fim_dito: false,
        fim_recebido: false,
        acabou: false,
    };
    let id = match resultado(&envelope) {
        Ok(r) => Json(&r)
            .member(super::PARAMETRO)
            .and_then(|v| v.as_str())
            .and_then(super::ler_id_global),
        Err((codigo, m)) => {
            let m = politica::fluxo::motivo_guardado(&m);
            let _ = s.mandar(
                c,
                &Mensagem::Recusado {
                    codigo: &codigo,
                    motivo: &m,
                },
            );
            return None;
        }
    };
    let Some(n) = id else {
        let _ = s.mandar(
            c,
            &Mensagem::Recusado {
                codigo: Codigo::Error.nome(),
                motivo: motivo::PROTOCOLO,
            },
        );
        return None;
    };
    // O fluxo é da sessão: a vaga que acabou no meio o leva.
    let vaga_viva = com_vagas(|vs| {
        vs.iter_mut().find(|s| s.numero == numero).is_some_and(|s| {
            s.fluxo = Some(n);
            !s.acabou
        })
    });
    let Some(titular) = se_ha_tabela(|t| t.fluxos.retrato(n).map(|r| r.titular)).flatten() else {
        return Some(n);
    };
    if !vaga_viva {
        abortar_daqui(n, motivo::CONEXAO);
        return Some(n);
    }
    s.n = n;
    s.titular = titular;
    s.conduzir(c);
    Some(n)
}

/// Os dispositivos com sessão de fluxo que chegou, para a revogação: a
/// vaga de cada uma, que [`crate::enlace::dispositivo_saiu`] não acha nas
/// sessões do enlace. O fluxo delas acaba pelo gancho do fluxo; a sessão
/// sem fluxo ainda — no aperto — acaba aqui.
pub fn dispositivo_saiu(chave: &[u8; 32]) {
    com_vagas(|vs| {
        for s in vs
            .iter_mut()
            .filter(|s| s.chave == Some(*chave) && s.fluxo.is_none())
        {
            s.acabou = true;
            if let Some(w) = s.waker.take() {
                w.wake();
            }
        }
    });
}

// ---------------------------------------------------------------------
// A suíte.
// ---------------------------------------------------------------------

/// Só para a suíte: guarda o que iria às vagas — `true` — ou volta a
/// mandar de verdade.
#[cfg(feature = "modo-teste")]
pub fn saida_de_teste(guardar: bool) {
    crate::arch::sem_interrupcoes(|| *VAGAS_DE_TESTE.lock() = guardar.then(Vec::new));
}

/// Só para a suíte: o que a sessão fez nas vagas desde a última vez.
#[cfg(feature = "modo-teste")]
pub fn tirar_das_vagas_de_teste() -> Vec<NaVagaDeTeste> {
    crate::arch::sem_interrupcoes(|| {
        VAGAS_DE_TESTE
            .lock()
            .as_mut()
            .map(core::mem::take)
            .unwrap_or_default()
    })
}

/// Só para a suíte: as sessões que chegaram saem — os fios delas acordam e
/// acabam.
#[cfg(feature = "modo-teste")]
pub fn esvaziar_de_teste() {
    com_vagas(|vs| {
        for s in vs.iter_mut() {
            s.acabou = true;
            if let Some(w) = s.waker.take() {
                w.wake();
            }
        }
    });
}

/// Destrava a tabela das sessões à força, para uso exclusivo do caminho de
/// falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        NAS_VAGAS.force_unlock();
        #[cfg(feature = "modo-teste")]
        VAGAS_DE_TESTE.force_unlock();
    }
}
