//! Os casos do fluxo entre dois Dukes — o DN-2 entre dispositivos
//! (FS19–FS26) — e o fim que a sessão com o par conclui, gravado dentro da
//! ordem das gravações (FS27).
//!
//! A suíte faz o outro Duke, com a chave de teste de um dispositivo
//! relacionado, como nos casos do enlace e do pareamento:
//!
//! - **chegando** — [`DeLa`]: o Duke de lá abre um fluxo para este pela vaga
//!   do enlace de verdade — o `Lado` que despacha o quadro 9 —, e a sessão
//!   daqui, no fio dela, responde pela saída de teste das vagas;
//! - **saindo** — [`ParQueAceita`]: um processo daqui abre um fluxo para o
//!   Duke de lá, um fio de teste conduz a sessão daqui pelo [`CanalDeTeste`],
//!   e a suíte responde do outro lado dele.

use super::*;
use crate::fluxo::par::{Abertura, Canal, Esperar, Local, Mensagem, NaVagaDeTeste};

pub(in crate::testes) mod aviso;
use crate::testes::enlace::{
    Par, PontaDeTeste, VAGA, admin, chave_de_dispositivo, com_o_enlace, pessoa_com_sessao,
    politica_com, privada_de_dispositivo, relacionar,
};
use crate::trava::Mutex;
use alloc::collections::VecDeque;
use alloc::vec;
use core::task::Waker;
use sigilo::Transporte;
use sigilo::quadro::{self, Leitor, Tipo};

/// A relação dos casos: o mesmo identificador nos dois lados.
const RELACAO: &str = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1";

/// A relação de outro dispositivo, de outra pessoa.
const RELACAO_DE_OUTRO: &str = "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2";

/// O dispositivo de teste que faz o outro Duke, e o nome dele aqui — no
/// alcance de `fabric.remote` do operador.
const DO_PAR: u8 = 7;
const NOME_DO_PAR: &str = "par";

/// Outro dispositivo, de outra pessoa.
const DO_OUTRO: u8 = 8;

/// O programa que o Duke de lá atesta, e a época do boot dele.
const PROGRAMA_DE_LA: [u8; 32] = [0xab; 32];
const EPOCA_DE_LA: [u8; 8] = [0x0e; 8];

/// O crédito de cada sentido no começo.
const CREDITO: u64 = politica::fluxo::BUFFER_DO_SENTIDO as u64;

/// O teto das esperas do par.
const TETO: u64 = TETO_DA_MALHA;

fn relacao(texto: &str) -> [u8; 16] {
    politica::dispositivos::ler_id(texto).unwrap_or([0; 16])
}

/// Espera `condicao`, atendendo os pedidos dos processos e cedendo a CPU
/// aos fios das sessões.
fn esperar_no_par(mut condicao: impl FnMut() -> bool, teto: u64) -> Resultado {
    let limite = crate::tempo::ticks().saturating_add(teto);
    loop {
        if condicao() {
            return Ok(());
        }
        if crate::tempo::ticks() >= limite {
            return Err("o par nao respondeu dentro do teto");
        }
        crate::nativo::atender_pendentes();
        crate::fios::ceder();
    }
}

// ---------------------------------------------------------------------------
// Chegando: a suíte abre, por uma vaga do enlace.
// ---------------------------------------------------------------------------

/// O que as sessões fizeram nas vagas e nenhum caso leu ainda: cada [`DeLa`]
/// tira só o da conexão dele.
static PENDENTES: Mutex<Vec<NaVagaDeTeste>> = Mutex::new(Vec::new());

fn limpar_pendentes() {
    let _ = crate::fluxo::par::tirar_das_vagas_de_teste();
    crate::arch::sem_interrupcoes(|| PENDENTES.lock().clear());
}

/// O que as sessões fizeram na conexão `g` da vaga `v`.
fn colher(v: u8, g: u64) -> Vec<NaVagaDeTeste> {
    let novos = crate::fluxo::par::tirar_das_vagas_de_teste();
    crate::arch::sem_interrupcoes(|| {
        let mut p = PENDENTES.lock();
        p.extend(novos);
        let (meus, outros): (Vec<NaVagaDeTeste>, Vec<NaVagaDeTeste>) =
            p.drain(..).partition(|e| match e {
                NaVagaDeTeste::Quadro(a, b, _)
                | NaVagaDeTeste::Identificada(a, b, _)
                | NaVagaDeTeste::Encerrada(a, b) => (*a, *b) == (v, g),
            });
        *p = outros;
        meus
    })
}

/// O que chegou de uma sessão daqui.
#[derive(Debug)]
enum Chegada {
    /// A segunda mensagem do aperto.
    Resposta(Vec<u8>),
    /// A recusa em claro.
    Recusa(String),
    /// Uma mensagem do fluxo, decifrada.
    Claro(Vec<u8>),
}

/// O outro Duke abrindo um fluxo para este: a suíte, com a chave de teste
/// do dispositivo, falando com o respondedor de verdade de uma vaga do
/// enlace.
struct DeLa {
    lado: crate::enlace::Lado,
    ponta: PontaDeTeste,
    v: u8,
    g: u64,
    privada: [u8; 32],
    leitor: Leitor,
    transporte: Option<Transporte>,
    /// O quadro da primeira mensagem do aperto, para repetir.
    primeira: Vec<u8>,
    /// Os quadros de dados mandados, para repetir.
    mandados: Vec<Vec<u8>>,
    chegou: VecDeque<Chegada>,
    encerrada: bool,
    identificada: Option<[u8; 32]>,
    /// O crédito para mandar, e o lido que ainda não se devolveu.
    credito: u64,
    a_devolver: u64,
}

impl DeLa {
    /// O dispositivo de teste `n`, na vaga `v`, na conexão `g`.
    fn novo(v: u8, g: u64, n: u8) -> DeLa {
        let mut lado = crate::enlace::Lado::nova(v, 0);
        lado.conexao(g);
        DeLa {
            lado,
            ponta: PontaDeTeste::default(),
            v,
            g,
            privada: privada_de_dispositivo(n),
            leitor: Leitor::novo(),
            transporte: None,
            primeira: Vec::new(),
            mandados: Vec::new(),
            chegou: VecDeque::new(),
            encerrada: false,
            identificada: None,
            credito: 0,
            a_devolver: 0,
        }
    }

    fn empurrar(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.lado.receber(b, &mut self.ponta);
        }
    }

    /// O que a sessão daqui fez nesta conexão, desde a última vez.
    fn colher(&mut self) -> Resultado {
        for e in colher(self.v, self.g) {
            match e {
                NaVagaDeTeste::Quadro(_, _, q) => {
                    for b in q {
                        let (tipo, corpo) = match self.leitor.empurrar(b) {
                            Ok(Some((t, c))) => (t, c.to_vec()),
                            Ok(None) => continue,
                            Err(_) => return Err("a sessao mandou um quadro que nao se le"),
                        };
                        let c = match tipo {
                            Tipo::Resposta => Chegada::Resposta(corpo),
                            Tipo::Recusa => {
                                Chegada::Recusa(String::from_utf8_lossy(&corpo).into_owned())
                            }
                            Tipo::Dados => {
                                let t = self
                                    .transporte
                                    .as_mut()
                                    .ok_or("dados da sessao antes do aperto")?;
                                let mut claro = vec![0u8; corpo.len()];
                                let n = t
                                    .decifrar(&corpo, &mut claro)
                                    .map_err(|_| "uma mensagem da sessao nao abriu")?;
                                claro.truncate(n);
                                Chegada::Claro(claro)
                            }
                            _ => return Err("a sessao mandou um quadro fora do protocolo"),
                        };
                        self.chegou.push_back(c);
                    }
                }
                NaVagaDeTeste::Identificada(_, _, k) => self.identificada = Some(k),
                NaVagaDeTeste::Encerrada(..) => self.encerrada = true,
            }
        }
        Ok(())
    }

    /// O que chegar primeiro: uma chegada, ou `None` com a conexão
    /// encerrada sem mais nada.
    fn proxima(&mut self) -> Result<Option<Chegada>, &'static str> {
        let mut erro = None;
        esperar_no_par(
            || {
                if let Err(e) = self.colher() {
                    erro = Some(e);
                    return true;
                }
                !self.chegou.is_empty() || self.encerrada
            },
            TETO,
        )?;
        if let Some(e) = erro {
            return Err(e);
        }
        Ok(self.chegou.pop_front())
    }

    /// A próxima mensagem do fluxo, decifrada.
    fn mensagem(&mut self) -> Result<Vec<u8>, &'static str> {
        match self.proxima()? {
            Some(Chegada::Claro(c)) => Ok(c),
            outra => {
                crate::log_error!("teste", "{:?} (encerrada: {})", outra, self.encerrada);
                Err("a sessao daqui nao mandou a mensagem esperada")
            }
        }
    }

    /// Espera a conexão encerrar, sem mais mensagens; devolve o `fechar`
    /// que tiver chegado antes.
    fn esperar_o_fim(&mut self) -> Result<Option<String>, &'static str> {
        let mut fechar = None;
        loop {
            match self.proxima()? {
                None => return Ok(fechar),
                Some(Chegada::Claro(c)) => match Mensagem::ler(&c) {
                    Some(Mensagem::Fechar(m)) => fechar = Some(String::from(m)),
                    // Crédito e o que estava a caminho podem vir antes.
                    Some(Mensagem::Credito(_) | Mensagem::Dados(_) | Mensagem::Fim) => {}
                    outra => {
                        crate::log_error!("teste", "{:?}", outra);
                        return Err("a sessao mandou outra coisa antes de encerrar");
                    }
                },
                Some(Chegada::Recusa(m)) => fechar = Some(m),
                Some(Chegada::Resposta(_)) => return Err("uma resposta de aperto fora de hora"),
            }
        }
    }

    /// O aperto, com o prólogo do fluxo: `Ok(Ok)` com o transporte aberto,
    /// `Ok(Err)` com a recusa em claro.
    fn apertar(&mut self) -> Result<Result<(), String>, &'static str> {
        let duke = crate::identidade::publica_do_duke().ok_or("o Duke nao tem chave")?;
        let efemera = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
        let mut buf = vec![0u8; 256];
        let (n, aguardando) =
            sigilo::Iniciador::novo(sigilo::PROLOGO_DO_FLUXO, &self.privada, &duke)
                .escrever(efemera, b"", &mut buf)
                .map_err(|_| "a 1a mensagem nao se escreveu")?;
        let q = quadro::montar(Tipo::InicioFluxo, &buf[..n]).map_err(|_| "quadro grande")?;
        self.primeira = q.clone();
        self.empurrar(&q);
        match self.proxima()? {
            Some(Chegada::Resposta(c)) => {
                let mut lixo = vec![0u8; c.len()];
                let (_, t) = aguardando
                    .ler(&c, &mut lixo)
                    .map_err(|_| "a 2a mensagem nao abriu")?;
                self.transporte = Some(t);
                Ok(Ok(()))
            }
            Some(Chegada::Recusa(m)) => {
                let _ = self.proxima();
                Ok(Err(m))
            }
            outra => {
                crate::log_error!("teste", "{:?}", outra);
                Err("o aperto nao teve resposta nem recusa")
            }
        }
    }

    /// Cifra e manda `claro` num quadro de dados.
    fn mandar_claro(&mut self, claro: &[u8]) -> Resultado {
        let t = self.transporte.as_mut().ok_or("sem transporte")?;
        let mut c = vec![0u8; claro.len() + 16];
        let n = t.cifrar(claro, &mut c).map_err(|_| "nao se cifrou")?;
        let q = quadro::montar(Tipo::Dados, &c[..n]).map_err(|_| "quadro grande")?;
        self.mandados.push(q.clone());
        self.empurrar(&q);
        Ok(())
    }

    fn mandar(&mut self, m: &Mensagem) -> Resultado {
        self.mandar_claro(&m.escrever())
    }

    /// O `abrir` ao endpoint `endpoint`, pela relação `rel`.
    fn abrir_com(&mut self, rel: &str, endpoint: &str) -> Resultado {
        self.mandar(&Mensagem::Abrir(Abertura {
            relacao: relacao(rel),
            programa: PROGRAMA_DE_LA,
            endpoint,
            intencao: INTENCAO,
            epoca: EPOCA_DE_LA,
        }))
    }

    /// O `aceito` da sessão daqui: o id do fluxo de lá.
    fn aceito(&mut self) -> Result<String, &'static str> {
        let m = self.mensagem()?;
        match Mensagem::ler(&m) {
            Some(Mensagem::Aceito(id)) => {
                self.credito = CREDITO;
                Ok(String::from(id))
            }
            outra => {
                crate::log_error!("teste", "{:?}", outra);
                Err("a sessao daqui nao mandou o aceito")
            }
        }
    }

    /// O `recusado` da sessão daqui: o código e o motivo.
    fn recusado(&mut self) -> Result<(String, String), &'static str> {
        let m = self.mensagem()?;
        match Mensagem::ler(&m) {
            Some(Mensagem::Recusado { codigo, motivo }) => {
                Ok((String::from(codigo), String::from(motivo)))
            }
            outra => {
                crate::log_error!("teste", "{:?}", outra);
                Err("a sessao daqui nao mandou o recusado")
            }
        }
    }

    /// A troca inteira: manda `ida` dentro do crédito, e o fim; lê o que
    /// volta até o fim, devolvendo crédito. Devolve o que voltou.
    fn trocar(&mut self, ida: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut enviado = 0;
        let mut fim_dito = false;
        let mut fim_ouvido = false;
        let mut volta = Vec::new();
        loop {
            while enviado < ida.len() && self.credito > 0 {
                let k = (ida.len() - enviado)
                    .min(self.credito as usize)
                    .min(politica::fluxo::BUFFER_DO_SENTIDO);
                self.mandar(&Mensagem::Dados(&ida[enviado..enviado + k]))?;
                enviado += k;
                self.credito -= k as u64;
            }
            if enviado == ida.len() && !fim_dito {
                self.mandar(&Mensagem::Fim)?;
                fim_dito = true;
            }
            if fim_dito && fim_ouvido {
                return Ok(volta);
            }
            let m = self.mensagem()?;
            match Mensagem::ler(&m) {
                Some(Mensagem::Credito(k)) => self.credito += u64::from(k),
                Some(Mensagem::Dados(d)) => {
                    volta.extend_from_slice(d);
                    self.a_devolver += d.len() as u64;
                    if self.a_devolver >= 4096 {
                        let k = self.a_devolver as u32;
                        self.a_devolver = 0;
                        self.mandar(&Mensagem::Credito(k))?;
                    }
                }
                Some(Mensagem::Fim) => fim_ouvido = true,
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("a troca com a sessao daqui saiu do protocolo");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Saindo: um processo daqui abre, e a suíte aceita do outro lado.
// ---------------------------------------------------------------------------

/// A linha entre a sessão daqui, saindo, e a suíte, fazendo o Duke de lá.
#[derive(Default)]
struct Linha {
    /// Os bytes que a sessão daqui mandou.
    para_la: VecDeque<u8>,
    /// Os quadros que a suíte mandou à sessão daqui.
    para_ca: VecDeque<(Tipo, Vec<u8>)>,
    /// Os que a suíte guardou: chegam à sessão daqui com o que mudar daqui
    /// — ver [`ParQueAceita::guardar`].
    guardados: VecDeque<(Tipo, Vec<u8>)>,
    waker: Option<Waker>,
    fechada: bool,
    /// O fio da sessão daqui acabou.
    acabou: bool,
}

static LINHA: Mutex<Option<Linha>> = Mutex::new(None);

fn com_linha<R>(f: impl FnOnce(&mut Linha) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| LINHA.lock().as_mut().map(f))
}

/// Fecha a linha: a sessão daqui ouve a conexão cair.
fn fechar_a_linha() {
    let w = com_linha(|l| {
        l.fechada = true;
        l.waker.take()
    })
    .flatten();
    if let Some(w) = w {
        w.wake();
    }
}

/// O canal da sessão daqui, saindo, na suíte.
struct CanalDeTeste;

impl Canal for CanalDeTeste {
    fn mandar(&mut self, q: &[u8]) -> Result<(), &'static str> {
        com_linha(|l| {
            if l.fechada {
                return Err("a linha fechou");
            }
            l.para_la.extend(q.iter().copied());
            Ok(())
        })
        .unwrap_or(Err("sem linha"))
    }

    fn proximo(
        &mut self,
        ate_ms: u64,
        local: Local,
    ) -> Result<Option<(Tipo, Vec<u8>)>, &'static str> {
        loop {
            let tirado = com_linha(|l| match l.para_ca.pop_front() {
                Some(q) => Some(Ok(q)),
                None if l.fechada => Some(Err(())),
                None => None,
            })
            .unwrap_or(Some(Err(())));
            match tirado {
                Some(Ok(q)) => return Ok(Some(q)),
                Some(Err(())) => return Err("a linha fechou"),
                None => {}
            }
            if local(None) {
                // O que a suíte guardou chega com o que mudou daqui, e a
                // sessão o lê antes de olhar a mudança: o par o mandou antes
                // de saber dela.
                return Ok(com_linha(|l| l.guardados.pop_front()).flatten());
            }
            if crate::tempo::uptime_ms() >= ate_ms {
                return Ok(None);
            }
            crate::fios::bloquear_em(Esperar::ate(ate_ms, |w: &Waker| {
                let pronta = com_linha(|l| {
                    if !l.para_ca.is_empty() || l.fechada {
                        return true;
                    }
                    l.waker = Some(w.clone());
                    false
                })
                .unwrap_or(true);
                pronta || local(Some(w))
            }));
        }
    }
}

/// O fio de teste da sessão daqui, saindo.
extern "C" fn sessao_saindo(n: u64) -> ! {
    crate::fluxo::par::conduzir_na_origem(n, &mut CanalDeTeste);
    com_linha(|l| l.acabou = true);
    crate::fios::terminar()
}

/// Uma linha nova, e o fio da sessão do fluxo `n` sobre ela.
fn lancar_a_sessao_saindo(n: u64) -> Resultado {
    crate::arch::sem_interrupcoes(|| *LINHA.lock() = Some(Linha::default()));
    crate::fios::criar("teste-fluxo-par", sessao_saindo, n).map(|_| ())
}

/// O Duke de lá aceitando: a suíte, com a chave de teste do dispositivo,
/// do outro lado da linha.
struct ParQueAceita {
    privada: [u8; 32],
    leitor: Leitor,
    transporte: Option<Transporte>,
    credito: u64,
    a_devolver: u64,
}

impl ParQueAceita {
    fn novo(n: u8) -> ParQueAceita {
        ParQueAceita {
            privada: privada_de_dispositivo(n),
            leitor: Leitor::novo(),
            transporte: None,
            credito: 0,
            a_devolver: 0,
        }
    }

    /// O próximo quadro que a sessão daqui mandou, esperando.
    fn quadro(&mut self) -> Result<(Tipo, Vec<u8>), &'static str> {
        let mut achado = None;
        let mut erro = None;
        esperar_no_par(
            || {
                let bytes: Vec<u8> =
                    com_linha(|l| l.para_la.drain(..).collect()).unwrap_or_default();
                let mut resto = Vec::new();
                for (i, b) in bytes.iter().enumerate() {
                    if achado.is_some() {
                        resto.extend_from_slice(&bytes[i..]);
                        break;
                    }
                    match self.leitor.empurrar(*b) {
                        Ok(Some((t, c))) => achado = Some((t, c.to_vec())),
                        Ok(None) => {}
                        Err(_) => {
                            erro = Some("a sessao daqui mandou um quadro que nao se le");
                            return true;
                        }
                    }
                }
                if !resto.is_empty() {
                    com_linha(|l| {
                        for b in resto.into_iter().rev() {
                            l.para_la.push_front(b);
                        }
                    });
                }
                achado.is_some() || com_linha(|l| l.acabou).unwrap_or(true)
            },
            TETO,
        )?;
        if let Some(e) = erro {
            return Err(e);
        }
        achado.ok_or("a sessao daqui acabou sem mandar o quadro")
    }

    /// Manda um quadro à sessão daqui.
    fn mandar_quadro(&self, tipo: Tipo, corpo: &[u8]) {
        let w = com_linha(|l| {
            l.para_ca.push_back((tipo, corpo.to_vec()));
            l.waker.take()
        })
        .flatten();
        if let Some(w) = w {
            w.wake();
        }
    }

    /// `m` cifrada no transporte, num corpo de quadro de dados.
    fn cifrada(&mut self, m: &Mensagem) -> Result<Vec<u8>, &'static str> {
        let claro = m.escrever();
        let t = self.transporte.as_mut().ok_or("sem transporte")?;
        let mut c = vec![0u8; claro.len() + 16];
        let n = t.cifrar(&claro, &mut c).map_err(|_| "nao se cifrou")?;
        c.truncate(n);
        Ok(c)
    }

    fn mandar(&mut self, m: &Mensagem) -> Resultado {
        let c = self.cifrada(m)?;
        self.mandar_quadro(Tipo::Dados, &c);
        Ok(())
    }

    /// Guarda `m` para a sessão daqui achar com o que mudar daqui, antes de
    /// olhar a mudança — sem acordá-la, e nunca antes dela: o par a mandou
    /// antes de saber do fim daqui. Uma por mudança: lida a primeira, a
    /// sessão vê o fim e manda o `fechar`. Nada vai à linha depois dela —
    /// a cifra conta as mensagens na ordem.
    fn guardar(&mut self, m: &Mensagem) -> Resultado {
        let c = self.cifrada(m)?;
        com_linha(|l| l.guardados.push_back((Tipo::Dados, c))).ok_or("sem linha")
    }

    /// Manda `ms` e fecha a linha de uma vez, antes de acordar a sessão
    /// daqui: ela acha as mensagens na fila e a linha já caída — o par que
    /// fecha, e a conexão que cai logo atrás.
    fn mandar_e_cair(&mut self, ms: &[Mensagem]) -> Resultado {
        let mut quadros = Vec::new();
        for m in ms {
            quadros.push(self.cifrada(m)?);
        }
        let w = com_linha(|l| {
            l.para_ca
                .extend(quadros.into_iter().map(|c| (Tipo::Dados, c)));
            l.fechada = true;
            l.waker.take()
        })
        .ok_or("sem linha")?;
        if let Some(w) = w {
            w.wake();
        }
        Ok(())
    }

    /// A próxima mensagem da sessão daqui, decifrada.
    fn mensagem(&mut self) -> Result<Vec<u8>, &'static str> {
        let (tipo, corpo) = self.quadro()?;
        if tipo != Tipo::Dados {
            crate::log_error!("teste", "{:?}", tipo);
            return Err("a sessao daqui mandou um quadro que nao e de dados");
        }
        let t = self.transporte.as_mut().ok_or("sem transporte")?;
        let mut claro = vec![0u8; corpo.len()];
        let n = t
            .decifrar(&corpo, &mut claro)
            .map_err(|_| "uma mensagem da sessao daqui nao abriu")?;
        claro.truncate(n);
        Ok(claro)
    }

    /// A primeira mensagem do IK, respondida: a carga dela e a chave de
    /// quem abriu.
    fn aceitar_o_aperto(&mut self) -> Result<(Vec<u8>, [u8; 32]), &'static str> {
        let (tipo, corpo) = self.quadro()?;
        if tipo != Tipo::InicioFluxo {
            return Err("a sessao daqui nao abriu com o quadro do fluxo");
        }
        let mut carga = vec![0u8; corpo.len()];
        let (n, recebido) = sigilo::Respondedor::novo(sigilo::PROLOGO_DO_FLUXO, &self.privada)
            .ler(&corpo, &mut carga)
            .map_err(|_| "a 1a mensagem da sessao daqui nao abriu com a chave do par")?;
        carga.truncate(n);
        let chave = recebido.remota();
        let efemera = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
        let mut saida = vec![0u8; 128];
        let (m, t) = recebido
            .escrever(efemera, b"", &mut saida)
            .map_err(|_| "a 2a mensagem nao se escreveu")?;
        self.mandar_quadro(Tipo::Resposta, &saida[..m]);
        self.transporte = Some(t);
        Ok((carga, chave))
    }
}

// ---------------------------------------------------------------------------
// O ambiente dos casos.
// ---------------------------------------------------------------------------

/// Roda `f` com o registro de dispositivos, a malha e os fluxos vazios, a
/// saída das vagas guardada para a suíte, e confere no fim que nenhuma
/// sessão ficou de pé e a tabela ficou coerente.
fn com_o_par(f: impl FnOnce() -> Resultado) -> Resultado {
    com_o_enlace(|| {
        crate::fluxo::esvaziar_de_teste();
        crate::fluxo::par::saida_de_teste(true);
        limpar_pendentes();
        let r = f();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        fechar_a_linha();
        crate::fluxo::esvaziar_de_teste();
        let saiu = esperar_no_par(
            || {
                crate::fluxo::par::sessoes_de_teste() == 0
                    && com_linha(|l| l.acabou).unwrap_or(true)
            },
            TETO,
        );
        let coerente = crate::fluxo::coerente();
        crate::fluxo::esvaziar_de_teste();
        crate::fluxo::par::saida_de_teste(false);
        crate::arch::sem_interrupcoes(|| *LINHA.lock() = None);
        limpar_pendentes();
        r?;
        saiu.map_err(|_| "uma sessao com o par ficou de pe depois do caso")?;
        if !coerente {
            return Err("a tabela de fluxos ficou incoerente");
        }
        Ok(())
    })
}

/// A pessoa `bia`, relacionada ao dispositivo do par com o papel `papel`:
/// a autoridade dela, a sessão e o identificador.
fn bia_relacionada(
    papel: &str,
) -> Result<
    (
        Autoridade,
        crate::pessoas::IdSessao,
        sigilo::pessoas::IdPessoa,
    ),
    &'static str,
> {
    let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
    relacionar(bia, NOME_DO_PAR, DO_PAR, papel, RELACAO)?;
    Ok((Autoridade::Pessoa { sessao }, sessao, bia))
}

/// Uma geração de conexão nova, para os casos não se cruzarem.
fn geracao() -> u64 {
    static G: AtomicU64 = AtomicU64::new(9_100_000);
    G.fetch_add(1, SeqCst)
}

/// Um registro `stream.session` depois de `antes`, com o código e o
/// começo do detalhe.
fn sessao_gravada(antes: u64, codigo: Codigo, detalhe: &str) -> Resultado {
    esperar_no_par(
        || {
            !registros_depois(antes, |e| {
                e.metodo == crate::autorizacao::APERTO_DO_FLUXO
                    && e.codigo == codigo
                    && e.detalhe.starts_with(detalhe)
            })
            .is_empty()
        },
        TETO,
    )
    .map_err(|_| {
        crate::log_error!(
            "teste",
            "esperava stream.session {:?} `{}`",
            codigo,
            detalhe
        );
        "a sessao do fluxo nao foi gravada como devia"
    })
}

/// Um fluxo chegando, aberto e aceito pela suíte como o processo `b`: a
/// sessão de lá e o id daqui.
fn aberto_de_la(b: &Ponta, v: u8) -> Result<(DeLa, String), &'static str> {
    let mut la = DeLa::novo(v, geracao(), DO_PAR);
    la.apertar()?.map_err(|m| {
        crate::log_error!("teste", "{}", m);
        "o aperto do fluxo foi recusado"
    })?;
    la.abrir_com(RELACAO, &b.endpoint)?;
    // O pedido chega à tabela daqui; o processo aceita, uma vez.
    esperar_no_par(|| crate::fluxo::contagem().1 == 1, TETO)
        .map_err(|_| "o pedido do par nao chegou a tabela daqui")?;
    let r = aceitar(b.quem(), &b.endpoint);
    let id = fs_texto(&r, "stream").ok_or_else(|| {
        crate::log_error!("teste", "{}", r);
        "o processo daqui nao aceitou o pedido do par"
    })?;
    let de_la = la.aceito()?;
    if de_la != id {
        return Err("o aceito nao disse o id do fluxo daqui");
    }
    Ok((la, id))
}

// ---------------------------------------------------------------------------
// FS19 — chegando e saindo, de ponta a ponta.
// ---------------------------------------------------------------------------

/// O Duke de lá abre um fluxo para o `fluxos` daqui: o aperto com o prólogo
/// do fluxo e a chave no registro de dispositivos; o `abrir` decidido pelo
/// gate daqui como o dispositivo — a pessoa da relação ∩ a relação ∩ o teto
/// `remoto`, no domínio do fluxo —; o aceite do processo; 40 KiB em cada
/// sentido, dentro do crédito; os dois fins. O programa daqui vê de que
/// dispositivo veio, cada `dados` foi uma decisão, a sessão foi gravada com
/// a relação e o programa atestado, e o fluxo acaba `concluido`.
pub(in crate::testes) fn fluxo_chegando_de_outro_duke() -> Resultado {
    const N: usize = 40 * 1024;
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let antes = crate::autorizacao::ultimo_registro();
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let desde = b.ditar(RECEBER, 1)?;
            let mut la = DeLa::novo(VAGA, geracao(), DO_PAR);
            la.apertar()?.map_err(|m| {
                crate::log_error!("teste", "{}", m);
                "o aperto do fluxo foi recusado"
            })?;
            la.abrir_com(RELACAO, &b.endpoint)?;
            la.aceito()?;
            if la.identificada != Some(chave_de_dispositivo(DO_PAR)) {
                return Err("a vaga nao saiu do prazo do aperto com a chave do par");
            }
            let ida: Vec<u8> = (0..N).map(padrao).collect();
            let volta = la.trocar(&ida)?;
            if volta != ida {
                return Err("o que voltou nao e o que foi");
            }
            let recebi = dito_na_malha(desde, "fluxos: recebi ")?;
            let h = resumo((0..N).map(padrao));
            if recebi != format!("{N} {h:016x} de dispositivo:{NOME_DO_PAR}") {
                crate::log_error!("teste", "{}", recebi);
                return Err("o processo daqui nao viu de que dispositivo veio");
            }
            if la.esperar_o_fim()?.is_some() {
                return Err("o fluxo concluido terminou com fechar");
            }
            sessao_gravada(
                antes,
                Codigo::Allow,
                &format!(
                    "{} ; relacao {} ; atestado abababab",
                    crate::identidade::impressao(&chave_de_dispositivo(DO_PAR)),
                    &RELACAO[..8]
                ),
            )?;
            let id = primeiro_id_aberto(antes)?;
            fim_gravado(
                antes,
                &id,
                &format!("concluido; ida {N}; volta {N}; desc 0"),
            )?;
            // Cada `dados` de lá foi decidido aqui, como o dispositivo, pela
            // relação, com o programa atestado.
            let pelo = format!("pela relacao {}, atestado abababab", &RELACAO[..8]);
            let decididos = registros_depois(antes, |e| {
                e.metodo == "stream.write"
                    && e.codigo == Codigo::Allow
                    && e.titular == politica::auditoria::Titular::Dispositivo
                    && e.detalhe.starts_with(&pelo)
            });
            if decididos.len() < N / politica::fluxo::BUFFER_DO_SENTIDO {
                crate::log_error!("teste", "{} decisoes", decididos.len());
                return Err("os dados de la nao foram decididos aqui, um a um");
            }
            nada_vivo("o fluxo do par ficou vivo")
        })();
        encerrar_todas(r, &[&b])
    })
}

/// Um processo daqui abre um fluxo para o Duke de lá: as duas permissões
/// decididas aqui; o fio da sessão faz o aperto com a chave do Duke e o
/// prólogo do fluxo — a carga da 1ª mensagem vazia: o `abrir` não vai
/// nela —; o `abrir` diz a relação, o programa e a época daqui; o
/// `aceito` de lá abre o fluxo depois da reconfirmação, gravada pelo
/// kernel; os dados vão dentro do crédito, voltam, e o fluxo acaba
/// `concluido`.
pub(in crate::testes) fn fluxo_saindo_para_outro_duke() -> Resultado {
    const IDA: usize = 20 * 1024;
    const VOLTA: usize = 5 * 1024;
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let r = fs_pedir(
                a.quem(),
                "stream.open",
                &format!(
                    r#"{{"endpoint":"e0e0e0e0e0e0e0e0:3","intent":"{INTENCAO}","device":"dispositivo:{NOME_DO_PAR}"}}"#
                ),
            );
            feito(&r, "o pedido de fluxo ao par nao passou")?;
            let id = fs_texto(&r, "stream").ok_or("sem id")?;
            let n = crate::fluxo::numero_de_teste(&id).ok_or("o id nao e deste boot")?;
            lancar_a_sessao_saindo(n)?;
            let mut la = ParQueAceita::novo(DO_PAR);
            let (carga, chave) = la.aceitar_o_aperto()?;
            if !carga.is_empty() {
                return Err("a 1a mensagem do aperto levou carga: o abrir nao vai nela");
            }
            if Some(chave) != crate::identidade::publica_do_duke() {
                return Err("o aperto nao veio com a chave do Duke");
            }
            let m = la.mensagem()?;
            match Mensagem::ler(&m) {
                Some(Mensagem::Abrir(ab))
                    if ab.relacao == relacao(RELACAO)
                        && ab.endpoint == "e0e0e0e0e0e0e0e0:3"
                        && ab.intencao == INTENCAO
                        && ab.programa == a.p.resumo()
                        && ab.epoca == crate::enlace::epoca() => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o abrir nao disse a relacao, o programa e a epoca daqui");
                }
            }
            la.mandar(&Mensagem::Aceito("e0e0e0e0e0e0e0e0:9"))?;
            la.credito = CREDITO;
            esperar_no_par(|| estado(a.quem(), &id).0.as_deref() == Some("open"), TETO)
                .map_err(|_| "o fluxo nao abriu com o aceito")?;
            // O kernel grava a abertura efetiva logo depois de abrir o fluxo
            // e acordar quem espera: o estado `open` pode ser visto antes do
            // registro.
            let abertos = || {
                registros_depois(antes, |e| {
                    e.metodo == "stream.open"
                        && e.agente == "kernel"
                        && e.recurso.ends_with(&format!("dispositivo:{NOME_DO_PAR}"))
                        && e.detalhe.starts_with("aberto pelo par; versao")
                })
                .len()
            };
            esperar_no_par(|| abertos() >= 1, TETO)
                .map_err(|_| "a abertura efetiva nao foi gravada pelo kernel")?;
            if abertos() != 1 {
                return Err("a abertura efetiva foi gravada mais de uma vez");
            }
            // A ida: escrita pelo processo daqui, levada dentro do crédito.
            // Cada escrita é lida inteira lá antes da seguinte — a sessão
            // pode juntar ou partir os pedaços —, devolvendo o crédito.
            let ida: Vec<u8> = (0..IDA).map(padrao).collect();
            let mut escrito = 0;
            let mut chegou = Vec::new();
            while escrito < IDA {
                let k = (IDA - escrito).min(4096);
                let r = escrever(a.quem(), &id, &ida[escrito..escrito + k]);
                let n = fs_numero(&r, "written").unwrap_or(0) as usize;
                if n == 0 {
                    crate::log_error!("teste", "{}", r);
                    return Err("a escrita da ida nao passou");
                }
                escrito += n;
                while chegou.len() < escrito {
                    let m = la.mensagem()?;
                    match Mensagem::ler(&m) {
                        Some(Mensagem::Dados(d)) => {
                            chegou.extend_from_slice(d);
                            la.a_devolver += d.len() as u64;
                            if la.a_devolver >= 4096 {
                                let k = la.a_devolver as u32;
                                la.a_devolver = 0;
                                la.mandar(&Mensagem::Credito(k))?;
                            }
                        }
                        outra => {
                            crate::log_error!("teste", "{:?}", outra);
                            return Err("a ida saiu do protocolo");
                        }
                    }
                }
            }
            if chegou != ida {
                return Err("o que chegou la nao e o que se escreveu aqui");
            }
            feito(
                &sobre(a.quem(), "stream.finish", &id),
                "o fim da ida nao passou",
            )?;
            match Mensagem::ler(&la.mensagem()?) {
                Some(Mensagem::Fim) => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o fim da ida nao chegou la");
                }
            }
            // A volta: de lá, dentro do crédito daqui, e o fim.
            let volta: Vec<u8> = (0..VOLTA).map(|i| padrao(i + 1)).collect();
            la.mandar(&Mensagem::Dados(&volta))?;
            la.mandar(&Mensagem::Fim)?;
            let mut lido = Vec::new();
            esperar_no_par(
                || {
                    let r = ler(a.quem(), &id, 16 * 1024);
                    match lidos(&r) {
                        Some((d, fim)) => {
                            lido.extend_from_slice(&d);
                            fim
                        }
                        None => true,
                    }
                },
                TETO,
            )?;
            if lido != volta {
                return Err("o que voltou de la nao e o que la mandou");
            }
            // Cada escrita e cada leitura do processo daqui decidiu também
            // `fabric.remote` sobre o par, na mesma decisão (DF-5): o recurso
            // gravado é a intenção e o dispositivo.
            let pelo = format!("pelo processo {} (", a.fio());
            let ao_par = format!("intencao:{INTENCAO} ; dispositivo:{NOME_DO_PAR}");
            for metodo in ["stream.write", "stream.read"] {
                let decididas = registros_depois(antes, |e| {
                    e.metodo == metodo && e.codigo == Codigo::Allow && e.detalhe.starts_with(&pelo)
                });
                if decididas.is_empty() || decididas.iter().any(|(_, e)| e.recurso != ao_par) {
                    crate::log_error!("teste", "{}: {:?}", metodo, decididas);
                    return Err("uma escrita ou leitura ao par nao decidiu o dispositivo");
                }
            }
            fim_gravado(
                antes,
                &id,
                &format!("concluido; ida {IDA}; volta {VOLTA}; desc 0"),
            )?;
            esperar_no_par(|| com_linha(|l| l.acabou).unwrap_or(true), TETO)
                .map_err(|_| "a sessao daqui nao acabou com os dois fins")
        })();
        encerrar_todas(r, &[&a])
    })
}

/// O `abrir` é decidido aqui pela D4 — a relação, a pessoa dela e o teto
/// `remoto`, todos ao mesmo tempo —, no domínio do fluxo: a relação sem
/// `fabric.stream` recusa; o endpoint de outra pessoa é o mesmo que um que
/// não existe; e a recusa vai ao par como `recusado`, com o código.
pub(in crate::testes) fn fluxo_o_abrir_pela_d4() -> Resultado {
    com_o_par(|| {
        let (bia, _, bia_id) = bia_relacionada("observador")?;
        let (_, edu) = pessoa("edu", 341);
        let b = Ponta::lancar(bia)?;
        let e = Ponta::lancar(edu)?;
        let r = (|| -> Resultado {
            // A relação com o papel `observador`: sem fabric.stream.
            let mut la = DeLa::novo(VAGA, geracao(), DO_PAR);
            la.apertar()?.map_err(|_| "o aperto foi recusado")?;
            la.abrir_com(RELACAO, &b.endpoint)?;
            let (codigo, _) = la.recusado()?;
            if !codigo.starts_with("DENY_") {
                crate::log_error!("teste", "{}", codigo);
                return Err("o abrir pela relacao sem fabric.stream nao foi recusado pelo gate");
            }
            la.esperar_o_fim()?;
            Ok(())
        })();
        let r = r.and_then(|()| {
            // Com a relação que deixa, o endpoint de outra pessoa.
            admin("device.revoke", r#"{"name":"par"}"#, None)?;
            crate::dispositivos::esquecer_de_teste();
            relacionar(bia_id, NOME_DO_PAR, DO_PAR, "dispositivo", RELACAO)?;
            let mut la = DeLa::novo(VAGA + 1, geracao(), DO_PAR);
            la.apertar()?.map_err(|_| "o aperto foi recusado")?;
            la.abrir_com(RELACAO, &e.endpoint)?;
            let (codigo, _) = la.recusado()?;
            if codigo != "DENY_RESOURCE" {
                crate::log_error!("teste", "{}", codigo);
                return Err("o endpoint de outra pessoa nao foi o mesmo que um que nao existe");
            }
            la.esperar_o_fim()?;
            nada_vivo("um pedido recusado ficou na tabela")
        });
        encerrar_todas(r, &[&b, &e])
    })
}

// ---------------------------------------------------------------------------
// FS20 — o quadro 9 só no domínio dele.
// ---------------------------------------------------------------------------

/// O quadro 9 só abre a sessão do fluxo, e a sessão do fluxo só aceita o
/// dela: o 9 numa vaga do agente é recusado e gravado; numa sessão de
/// enlace estabelecida a encerra; e o 5 e o 8 numa sessão de fluxo a
/// encerram — antes e depois do `abrir`.
pub(in crate::testes) fn fluxo_o_quadro_9_so_no_dominio_dele() -> Resultado {
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let q9 = quadro::montar(Tipo::InicioFluxo, &[0u8; 96]).map_err(|_| "quadro")?;
            // Numa vaga do agente.
            crate::autorizacao::esquecer_apertos();
            let antes = crate::autorizacao::ultimo_registro();
            let canal = crate::agent::sessao::Canal::Tcp(1);
            let g = crate::rede::canal::geracao(1);
            let mut agente = crate::agent::seguro::Cifrada::nova(canal);
            for &byte in &q9 {
                agente.receber(g, byte, |_| {});
            }
            esperar_no_par(
                || {
                    !registros_depois(antes, |e| {
                        e.codigo == Codigo::DenyNotAuthenticated
                            && e.detalhe.starts_with("quadro fora de ordem")
                    })
                    .is_empty()
                },
                TETO,
            )
            .map_err(|_| "o quadro 9 numa vaga do agente nao foi recusado e gravado")?;
            // Numa sessão de enlace estabelecida.
            let mut enlace = Par::novo(VAGA + 1, geracao());
            match enlace.apertar(&privada_de_dispositivo(DO_PAR), EPOCA_DE_LA)? {
                Ok(()) => {}
                Err(m) => {
                    crate::log_error!("teste", "{}", m);
                    return Err("o aperto do enlace foi recusado");
                }
            }
            for &byte in &q9 {
                enlace.lado.receber(byte, &mut enlace.ponta);
            }
            if !enlace.ponta.encerrou {
                return Err("o quadro 9 numa sessao de enlace nao a encerrou");
            }
            // O 5 e o 8 numa sessão de fluxo, antes do `abrir`.
            for tipo in [Tipo::InicioEnlace, Tipo::InicioPareamento] {
                let mut la = DeLa::novo(VAGA + 2, geracao(), DO_PAR);
                la.apertar()?
                    .map_err(|_| "o aperto do fluxo foi recusado")?;
                let q = quadro::montar(tipo, &[0u8; 96]).map_err(|_| "quadro")?;
                la.empurrar(&q);
                match la.esperar_o_fim()? {
                    Some(m) if m == "quadro fora de ordem" => {}
                    outro => {
                        crate::log_error!("teste", "{:?}", outro);
                        return Err("um quadro de outro dominio na sessao do fluxo nao a encerrou");
                    }
                }
            }
            // E depois do `abrir`, com o fluxo aberto: ele acaba.
            let antes = crate::autorizacao::ultimo_registro();
            let (mut la, id) = aberto_de_la(&b, VAGA + 3)?;
            let q = quadro::montar(Tipo::InicioEnlace, &[0u8; 96]).map_err(|_| "quadro")?;
            la.empurrar(&q);
            la.esperar_o_fim()?;
            fim_gravado_com(antes, &id, politica::fluxo::motivo::PROTOCOLO)
        })();
        encerrar_todas(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// FS21 — o aperto confere o registro.
// ---------------------------------------------------------------------------

/// Autenticado não é relacionado: a chave fora do registro, a revogada —
/// com lápide — e a suspensa são recusadas no aperto, em claro, e cada
/// recusa vai à auditoria como `stream.session`; e a relação de outra
/// pessoa, dita no `abrir`, é recusada pelo gate.
pub(in crate::testes) fn fluxo_o_aperto_confere_o_registro() -> Resultado {
    com_o_par(|| {
        let antes = crate::autorizacao::ultimo_registro();
        let recusado = |v: u8, n: u8, motivo: &str| -> Resultado {
            let mut la = DeLa::novo(v, geracao(), n);
            match la.apertar()? {
                Err(m) if m == motivo => Ok(()),
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    Err("o aperto nao foi recusado com o motivo do registro")
                }
            }
        };
        // Fora do registro.
        recusado(VAGA, DO_PAR, "chave fora do registro de dispositivos")?;
        sessao_gravada(
            antes,
            Codigo::DenyNotAuthenticated,
            "chave fora do registro",
        )?;
        // Suspensa.
        let (bia, _, bia_id) = bia_relacionada("dispositivo")?;
        admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
        recusado(VAGA + 1, DO_PAR, "dispositivo suspenso")?;
        sessao_gravada(antes, Codigo::DenyCredential, "dispositivo suspenso")?;
        // Revogada, com lápide.
        admin("device.revoke", r#"{"name":"par"}"#, None)?;
        recusado(VAGA + 2, DO_PAR, "chave fora do registro de dispositivos")?;
        // A relação de outra pessoa, dita no `abrir`: o gate recusa.
        crate::dispositivos::esquecer_de_teste();
        crate::contencao::esquecer_de_teste();
        relacionar(bia_id, NOME_DO_PAR, DO_PAR, "dispositivo", RELACAO)?;
        let (_, edu) = pessoa_com_sessao("edu", "operador")?;
        relacionar(edu, "outro", DO_OUTRO, "dispositivo", RELACAO_DE_OUTRO)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let mut la = DeLa::novo(VAGA + 3, geracao(), DO_PAR);
            la.apertar()?.map_err(|_| "o aperto foi recusado")?;
            la.abrir_com(RELACAO_DE_OUTRO, &b.endpoint)?;
            let (codigo, _) = la.recusado()?;
            if codigo != "DENY_NOT_AUTHENTICATED" {
                crate::log_error!("teste", "{}", codigo);
                return Err("a relacao de outro dispositivo nao foi recusada pelo gate");
            }
            la.esperar_o_fim()?;
            nada_vivo("o pedido pela relacao de outro ficou na tabela")
        })();
        encerrar_todas(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// FS22 — cada dados decidido em B.
// ---------------------------------------------------------------------------

/// O fluxo aberto não é autorização permanente para o que vem de fora:
/// cada `dados` é decidido aqui, e o teto `remoto` sem a intenção, posto no
/// meio, recusa o seguinte — o fluxo acaba com o motivo do gate, e o par
/// ouve o `fechar`; e a relação esquecida pela pessoa encerra o fluxo dela.
pub(in crate::testes) fn fluxo_cada_dados_decidido_aqui() -> Resultado {
    com_o_par(|| {
        let (bia, sessao, _) = bia_relacionada("dispositivo")?;
        let b = Ponta::lancar(bia)?;
        let politica_de_antes = crate::autorizacao::com_politica(|p| p.clone());
        let r = (|| -> Resultado {
            let antes = crate::autorizacao::ultimo_registro();
            let (mut la, id) = aberto_de_la(&b, VAGA)?;
            la.mandar(&Mensagem::Dados(b"antes"))?;
            esperar_no_par(
                || lidos(&ler(b.quem(), &id, 100)).is_some_and(|(d, _)| d == b"antes"),
                TETO,
            )
            .map_err(|_| "o primeiro dados nao chegou ao processo")?;
            politica_com(
                "recurso remoto fabric.stream intencao:imagem.compartilhar intencao:pdf.anotar",
                "recurso remoto fabric.stream intencao:pdf.anotar",
            )?;
            la.mandar(&Mensagem::Dados(b"depois"))?;
            match la.esperar_o_fim()? {
                Some(m) if m.starts_with("DENY_") => {}
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    return Err("o dados recusado pelo teto remoto nao fechou o fluxo");
                }
            }
            fim_gravado_com(antes, &id, "DENY_")?;
            crate::autorizacao::restaurar_politica(politica_de_antes.clone());
            // A relação esquecida pela pessoa.
            let antes = crate::autorizacao::ultimo_registro();
            let (mut la, id) = aberto_de_la(&b, VAGA + 1)?;
            let r = fs_pedir(
                Chamador::Pessoa(sessao),
                "device.forget",
                &format!(r#"{{"device":"dispositivo:{NOME_DO_PAR}"}}"#),
            );
            let esquecida = Json(r.as_bytes())
                .member("result")
                .and_then(|v| v.member("forgotten"))
                .and_then(|v| v.as_bool());
            if esquecida != Some(true) {
                crate::log_error!("teste", "{}", r);
                return Err("device.forget nao passou");
            }
            match la.esperar_o_fim()? {
                Some(m) if m == politica::fluxo::motivo::RELACAO => {}
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    return Err("a relacao esquecida nao encerrou o fluxo dela");
                }
            }
            fim_gravado_com(antes, &id, politica::fluxo::motivo::RELACAO)
        })();
        crate::autorizacao::restaurar_politica(politica_de_antes);
        encerrar_todas(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// FS23 — o protocolo.
// ---------------------------------------------------------------------------

/// O conjunto fechado do domínio: passar do crédito, um tipo desconhecido,
/// `dados` antes do `aceito` e um `abrir` repetido encerram o fluxo com
/// `protocolo`, e o par ouve o `fechar`.
pub(in crate::testes) fn fluxo_o_protocolo_fechado() -> Resultado {
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let protocolo = |la: &mut DeLa| -> Resultado {
                match la.esperar_o_fim()? {
                    Some(m) if m == politica::fluxo::motivo::PROTOCOLO => Ok(()),
                    outro => {
                        crate::log_error!("teste", "{:?}", outro);
                        Err("a quebra do protocolo nao fechou o fluxo com protocolo")
                    }
                }
            };
            // Além do crédito.
            let (mut la, _) = aberto_de_la(&b, VAGA)?;
            la.mandar(&Mensagem::Dados(&vec![
                1u8;
                politica::fluxo::BUFFER_DO_SENTIDO
            ]))?;
            la.mandar(&Mensagem::Dados(b"x"))?;
            protocolo(&mut la)?;
            // Um tipo desconhecido.
            let (mut la, _) = aberto_de_la(&b, VAGA + 1)?;
            la.mandar_claro(&[99, 1, 2, 3])?;
            protocolo(&mut la)?;
            // Um `abrir` repetido.
            let (mut la, _) = aberto_de_la(&b, VAGA + 2)?;
            la.abrir_com(RELACAO, &b.endpoint)?;
            protocolo(&mut la)?;
            // `dados` antes do `aceito`.
            let mut la = DeLa::novo(VAGA + 3, geracao(), DO_PAR);
            la.apertar()?.map_err(|_| "o aperto foi recusado")?;
            la.abrir_com(RELACAO, &b.endpoint)?;
            esperar_no_par(|| crate::fluxo::contagem().1 == 1, TETO)
                .map_err(|_| "o pedido do par nao chegou a tabela")?;
            la.mandar(&Mensagem::Dados(b"cedo"))?;
            protocolo(&mut la)?;
            nada_vivo("um fluxo que quebrou o protocolo ficou vivo")
        })();
        encerrar_todas(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// FS24 — os tetos das vagas.
// ---------------------------------------------------------------------------

/// As sessões de fluxo dividem as vagas da 7071 com o enlace e a cerimônia:
/// duas de pé, a terceira é recusada antes do aperto — em claro, sem
/// resposta, gravada —, e o enlace ainda acha vaga.
pub(in crate::testes) fn fluxo_os_tetos_das_vagas() -> Resultado {
    com_o_par(|| {
        bia_relacionada("dispositivo")?;
        let antes = crate::autorizacao::ultimo_registro();
        let mut um = DeLa::novo(VAGA, geracao(), DO_PAR);
        um.apertar()?.map_err(|_| "o 1o aperto foi recusado")?;
        let mut dois = DeLa::novo(VAGA + 1, geracao(), DO_PAR);
        dois.apertar()?.map_err(|_| "o 2o aperto foi recusado")?;
        let mut tres = DeLa::novo(VAGA + 2, geracao(), DO_PAR);
        match tres.apertar()? {
            Err(m) if m == "sessoes de fluxo demais; tente depois" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("a 3a sessao de fluxo nao foi recusada antes do aperto");
            }
        }
        if !tres.encerrada {
            return Err("a vaga da 3a sessao nao fechou");
        }
        sessao_gravada(antes, Codigo::Conflict, "sessoes de fluxo demais")?;
        if crate::fluxo::par::sessoes_de_teste() != 2 {
            return Err("as duas sessoes de pe nao sao duas");
        }
        // O enlace ainda acha vaga.
        let mut enlace = Par::novo(VAGA + 3, geracao());
        match enlace.apertar(&privada_de_dispositivo(DO_PAR), EPOCA_DE_LA)? {
            Ok(()) => Ok(()),
            Err(m) => {
                crate::log_error!("teste", "{}", m);
                Err("o enlace nao achou vaga com duas sessoes de fluxo de pe")
            }
        }
    })
}

// ---------------------------------------------------------------------------
// FS25 — a suspensão, a revogação e o esquecimento.
// ---------------------------------------------------------------------------

/// Com o fluxo aberto, `device.suspend` e `device.revoke` o encerram na
/// hora, com o motivo, e o par ouve o `fechar`; na origem, o mesmo — e a
/// política nova também: cada escrita ao par decide de novo `fabric.remote`
/// sobre ele. O fio da sessão daqui manda o `fechar` ao Duke de lá com o
/// motivo daqui mesmo quando o aceite, os dados, o crédito ou o fim de lá
/// chegam depois de o fluxo acabar — um por fim: a sessão lê um, e vê o
/// fim —, e também quando a ponta daqui já tinha fechado, e o fluxo acaba
/// sem lápide. E o `fechar` de lá com a conexão caindo logo atrás: o envio
/// daqui que falha não apaga o motivo do par — a sessão lê o que já tinha
/// chegado.
pub(in crate::testes) fn fluxo_a_suspensao_e_a_revogacao() -> Resultado {
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            use politica::fluxo::motivo;
            // A suspensão, chegando.
            let antes = crate::autorizacao::ultimo_registro();
            let (mut la, id) = aberto_de_la(&b, VAGA)?;
            admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
            match la.esperar_o_fim()? {
                Some(m) if m == motivo::DISPOSITIVO_SUSPENSO => {}
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    return Err("a suspensao nao encerrou o fluxo com o motivo");
                }
            }
            fim_gravado_com(antes, &id, motivo::DISPOSITIVO_SUSPENSO)?;
            crate::contencao::esquecer_de_teste();
            // Saindo: o pedido ao par, com o aperto e o `abrir` atendidos.
            let saindo = |endpoint: &str| -> Result<(String, ParQueAceita), &'static str> {
                let r = fs_pedir(
                    b.quem(),
                    "stream.open",
                    &format!(
                        r#"{{"endpoint":"{endpoint}","intent":"{INTENCAO}","device":"dispositivo:{NOME_DO_PAR}"}}"#
                    ),
                );
                feito(&r, "o pedido de fluxo ao par nao passou")?;
                let id = fs_texto(&r, "stream").ok_or("sem id")?;
                let n = crate::fluxo::numero_de_teste(&id).ok_or("o id nao e deste boot")?;
                lancar_a_sessao_saindo(n)?;
                let mut par = ParQueAceita::novo(DO_PAR);
                par.aceitar_o_aperto()?;
                let _ = par.mensagem()?;
                Ok((id, par))
            };
            // A suspensão, saindo, com o aceite de lá a caminho: o pedido
            // acaba daqui antes de o aceite chegar à sessão daqui — e o
            // `fechar` leva o motivo daqui, em vez de a conexão só cair.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, mut par) = saindo("e0e0e0e0e0e0e0e0:4")?;
            par.guardar(&Mensagem::Aceito("e0e0e0e0e0e0e0e0:8"))?;
            admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
            match Mensagem::ler(&par.mensagem()?) {
                Some(Mensagem::Fechar(m)) if m == motivo::DISPOSITIVO_SUSPENSO => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("a suspensao antes do aceite nao mandou o fechar ao par");
                }
            }
            fim_gravado_com(antes, &id, motivo::DISPOSITIVO_SUSPENSO)?;
            esperar_no_par(|| com_linha(|l| l.acabou).unwrap_or(true), TETO)
                .map_err(|_| "a sessao daqui nao acabou depois do fechar")?;
            crate::contencao::esquecer_de_teste();
            // Aberto, saindo: a ponta daqui escreveu `ida`, e o par a leu.
            let com_a_ida = |endpoint: &str| -> Result<(String, ParQueAceita), &'static str> {
                let (id, mut par) = saindo(endpoint)?;
                par.mandar(&Mensagem::Aceito("e0e0e0e0e0e0e0e0:9"))?;
                esperar_no_par(|| estado(b.quem(), &id).0.as_deref() == Some("open"), TETO)
                    .map_err(|_| "o fluxo nao abriu com o aceito")?;
                feito(
                    &super::escrever(b.quem(), &id, b"ida"),
                    "a ponta daqui nao escreveu no fluxo ao par",
                )?;
                let ida = par.mensagem()?;
                if !matches!(Mensagem::ler(&ida), Some(Mensagem::Dados(d)) if d == b"ida") {
                    return Err("o par nao recebeu o que a ponta daqui escreveu");
                }
                Ok((id, par))
            };
            // O `fechar` ao par com o motivo daqui — a mensagem guardada, lida
            // antes do fim, não é o par fora do protocolo —, e a sessão daqui
            // acaba.
            let fechado = |par: &mut ParQueAceita, motivo: &str, erro: &'static str| -> Resultado {
                match Mensagem::ler(&par.mensagem()?) {
                    Some(Mensagem::Fechar(m)) if m.starts_with(motivo) => {}
                    outra => {
                        crate::log_error!("teste", "{:?}", outra);
                        return Err(erro);
                    }
                }
                esperar_no_par(|| com_linha(|l| l.acabou).unwrap_or(true), TETO)
                    .map_err(|_| "a sessao daqui nao acabou depois do fechar")
            };
            // A ponta daqui enche o buffer do sentido — vazio: o par leu a
            // `ida` —, e o par recebe o que o crédito dele deixa, a `ida` de
            // menos: três bytes ficam aqui, esperando o crédito.
            let sem_credito = |id: &str, par: &mut ParQueAceita| -> Resultado {
                for pedaco in vec![0x5a; politica::fluxo::BUFFER_DO_SENTIDO].chunks(4096) {
                    super::escrito(
                        &super::escrever(b.quem(), id, pedaco),
                        pedaco.len() as u64,
                        "a ponta daqui nao encheu o buffer do sentido",
                    )?;
                }
                let mut chegou = 0;
                while chegou < politica::fluxo::BUFFER_DO_SENTIDO - 3 {
                    match Mensagem::ler(&par.mensagem()?) {
                        Some(Mensagem::Dados(d)) => chegou += d.len(),
                        outra => {
                            crate::log_error!("teste", "{:?}", outra);
                            return Err("o que o credito deixa nao chegou ao par");
                        }
                    }
                }
                Ok(())
            };
            // A suspensão, saindo, com o crédito do que o par leu a caminho.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, mut par) = com_a_ida("e0e0e0e0e0e0e0e0:5")?;
            par.guardar(&Mensagem::Credito(3))?;
            admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
            fechado(
                &mut par,
                motivo::DISPOSITIVO_SUSPENSO,
                "o credito a caminho mudou o fechar da suspensao",
            )?;
            fim_gravado_com(antes, &id, motivo::DISPOSITIVO_SUSPENSO)?;
            crate::contencao::esquecer_de_teste();
            // A política nova, saindo: cada escrita ao par decide de novo
            // `fabric.remote` sobre ele (DF-5) — sem a permissão no papel, a
            // escrita é recusada e o fluxo acaba —, com o fim de lá a caminho.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, mut par) = com_a_ida("e0e0e0e0e0e0e0e0:6")?;
            let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
            politica_sem("fabric.remote");
            par.guardar(&Mensagem::Fim)?;
            let r = super::escrever(b.quem(), &id, b"sem o remoto");
            crate::autorizacao::restaurar_politica(antes_da_politica);
            recusado(
                &r,
                "DENY_PERMISSION",
                "a politica sem fabric.remote nao recusou a escrita ao par",
            )?;
            fechado(
                &mut par,
                "DENY_PERMISSION",
                "a escrita recusada pela politica nova nao mandou o fechar ao par",
            )?;
            fim_gravado_com(antes, &id, "DENY_PERMISSION: ")?;
            // O fecho daqui com dados esperando o crédito de lá, e a
            // suspensão: a ponta daqui já tinha saído, e o fluxo acaba sem
            // lápide — os dados de lá, a caminho, não acham mais o fluxo, e
            // também não são o par fora do protocolo.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, mut par) = com_a_ida("e0e0e0e0e0e0e0e0:7")?;
            sem_credito(&id, &mut par)?;
            feito(
                &sobre(b.quem(), "stream.close", &id),
                "a ponta daqui nao fechou com dados esperando o credito",
            )?;
            par.guardar(&Mensagem::Dados(b"volta"))?;
            admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
            fechado(
                &mut par,
                motivo::DISPOSITIVO_SUSPENSO,
                "os dados de la depois do fecho daqui mudaram o fechar da suspensao",
            )?;
            fim_gravado_com(antes, &id, motivo::DISPOSITIVO_SUSPENSO)?;
            crate::contencao::esquecer_de_teste();
            // O `fechar` de lá, e a conexão caindo logo atrás, com o crédito
            // dele na frente: a sessão daqui manda o que o crédito novo
            // deixa, o envio falha — e ela lê o `fechar` que já tinha
            // chegado. O fluxo acaba com o motivo do par, e não `a conexao
            // caiu`.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, mut par) = com_a_ida("e0e0e0e0e0e0e0e0:2")?;
            sem_credito(&id, &mut par)?;
            par.mandar_e_cair(&[Mensagem::Credito(3), Mensagem::Fechar("fechado de la")])?;
            fim_gravado_com(antes, &id, "par: fechado de la")?;
            esperar_no_par(|| com_linha(|l| l.acabou).unwrap_or(true), TETO)
                .map_err(|_| "a sessao daqui nao acabou com a linha caida")?;
            // A revogação, saindo, com os dados de lá a caminho.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, mut par) = com_a_ida("e0e0e0e0e0e0e0e0:3")?;
            par.guardar(&Mensagem::Dados(b"volta"))?;
            admin("device.revoke", r#"{"name":"par"}"#, None)?;
            fechado(
                &mut par,
                motivo::DISPOSITIVO_REVOGADO,
                "a revogacao nao mandou o fechar ao par",
            )?;
            fim_gravado_com(antes, &id, motivo::DISPOSITIVO_REVOGADO)
        })();
        encerrar_todas(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// FS26 — o replay.
// ---------------------------------------------------------------------------

/// A 1ª mensagem do aperto, repetida noutra conexão, faz um aperto novo —
/// com efêmeras novas — e não abre nada: o `abrir` não vai nela, e o da
/// sessão antiga, repetido, não abre no transporte novo. Nenhuma decisão de
/// `stream.open` nasce do replay.
pub(in crate::testes) fn fluxo_o_replay_nao_abre() -> Resultado {
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let (mut la, _) = aberto_de_la(&b, VAGA)?;
            la.mandar(&Mensagem::Fechar("fechado pela ponta"))?;
            la.esperar_o_fim()?;
            let primeira = la.primeira.clone();
            let abrir = la.mandados[0].clone();
            let antes = crate::autorizacao::ultimo_registro();
            let mut replay = DeLa::novo(VAGA + 1, geracao(), DO_PAR);
            replay.empurrar(&primeira);
            match replay.proxima()? {
                Some(Chegada::Resposta(_)) => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("a 1a mensagem repetida nao teve so a resposta de um aperto novo");
                }
            }
            replay.empurrar(&abrir);
            match replay.proxima()? {
                Some(Chegada::Recusa(m)) if m == "a primeira mensagem nao e um abrir" => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o abrir repetido abriu no transporte novo");
                }
            }
            let abertos = registros_depois(antes, |e| e.metodo == "stream.open");
            if !abertos.is_empty() {
                crate::log_error!("teste", "{:?}", abertos);
                return Err("o replay chegou ao gate");
            }
            nada_vivo("o replay deixou um fluxo")
        })();
        encerrar_todas(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// FS27 — o fim que a sessão conclui, dentro da ordem.
// ---------------------------------------------------------------------------

/// Quanto a suíte dá à sessão, com a ordem das gravações na mão dela, para a
/// sessão concluir o fluxo se não esperasse a ordem: dez tiques.
const FOLGA_DA_ORDEM: u64 = 10;

/// Com a ordem das gravações na mão da suíte — como a teria a operação de um
/// processo daqui, ou o journal —, `gatilho` dá à sessão do fluxo `n` o fim
/// que o conclui. A sessão chega à ordem e espera por ela: enquanto a suíte
/// a tem, o fluxo segue vivo, nenhum `stream.end` dele vai à cadeia, nada
/// sai para o par (`nada_ao_par`) e o `dono`, se ainda está no fluxo, o vê
/// aberto — a operação dele, que entra na ordem nesse meio, vem antes da
/// conclusão. Solta a ordem, a sessão conclui: o fim vai à cadeia uma vez,
/// gravado com a ordem na mão e antes de acordar quem espera. Devolve o
/// número e o registro do fim.
fn concluido_na_ordem(
    n: u64,
    id: &str,
    antes: u64,
    dono: Option<Chamador>,
    gatilho: impl FnOnce() -> Resultado,
    mut nada_ao_par: impl FnMut() -> Result<bool, &'static str>,
) -> Result<(u64, politica::auditoria::Evento), &'static str> {
    let recurso = format!("fluxo:{id}");
    let fins = || registros_depois(antes, |e| e.metodo == "stream.end" && e.recurso == recurso);
    let vivos = crate::fluxo::contagem().0;
    crate::fluxo::conferir_o_fim_na_cadeia_de_teste(n);
    crate::fluxo::par::vigiar_a_ordem_de_teste(n);
    crate::persistencia::em_ordem(|| -> Resultado {
        // O que a sessão faria sem esperar a ordem: concluir o fluxo, gravar
        // o fim, mandar o quadro.
        let mut sem_a_ordem = || -> Resultado {
            if crate::fluxo::contagem().0 < vivos {
                return Err("a sessao concluiu o fluxo sem a ordem das gravacoes");
            }
            if !fins().is_empty() {
                return Err("o fim que a sessao conclui foi a cadeia sem a ordem das gravacoes");
            }
            if !nada_ao_par()? {
                return Err("o quadro do fim saiu ao par antes de a sessao ter a ordem");
            }
            Ok(())
        };
        gatilho()?;
        let mut visto: Resultado = Ok(());
        esperar_cedendo(
            || {
                visto = sem_a_ordem();
                visto.is_err() || crate::fluxo::par::a_caminho_da_ordem_de_teste()
            },
            TETO,
        )
        .map_err(|_| "a sessao nao chegou ao fim que conclui o fluxo")?;
        visto?;
        // A folga: a sessão que não esperasse a ordem concluiria aqui.
        let _ = esperar_cedendo(
            || {
                visto = sem_a_ordem();
                visto.is_err()
            },
            FOLGA_DA_ORDEM,
        );
        visto?;
        // A operação do dono que entra na ordem nesse meio vê o fluxo vivo:
        // ela vem antes da conclusão na cadeia.
        if let Some(dono) = dono
            && estado(dono, id).0.as_deref() != Some("open")
        {
            return Err("o dono viu o fluxo acabado com a ordem na mao dele");
        }
        Ok(())
    })?;
    // Solta a ordem, a sessão conclui: o fim foi à cadeia com a ordem na mão
    // dela, antes de acordar quem espera — uma vez.
    esperar_no_par(
        || crate::fluxo::fim_na_cadeia_ao_acordar_de_teste().is_some(),
        TETO,
    )
    .map_err(|_| "o fim que a sessao conclui nao acordou ninguem")?;
    if crate::fluxo::fim_na_cadeia_ao_acordar_de_teste() != Some(true) {
        return Err("o fim que a sessao conclui acordou antes de ir a cadeia");
    }
    if crate::fluxo::fim_gravado_na_ordem_de_teste() != Some(true) {
        return Err("o fim que a sessao conclui foi gravado sem a ordem das gravacoes");
    }
    let mut gravados = fins();
    if gravados.len() != 1 {
        crate::log_error!("teste", "{:?}", gravados);
        return Err("o fim que a sessao conclui nao foi gravado uma vez so");
    }
    Ok(gravados.remove(0))
}

/// O registro `fim` é o `stream.end` do kernel, permitido, com `detalhe`.
fn fim_do_kernel(fim: &politica::auditoria::Evento, detalhe: &str) -> Resultado {
    if fim.agente == "kernel" && fim.codigo == Codigo::Allow && fim.detalhe == detalhe {
        return Ok(());
    }
    crate::log_error!("teste", "esperava `{}`: {:?}", detalhe, fim);
    Err("o fim que a sessao conclui nao foi gravado com o motivo e as contas")
}

/// O fim que a própria sessão com o par conclui vai à cadeia como os fins
/// por fora — dentro da ordem das gravações, antes de acordar quem espera
/// —, nos dois casos: o fim mandado ao par com o outro sentido já acabado
/// (chegando: os dados e o fim de lá lidos até o fim, e o fim do sentido
/// daqui) e o fecho de quem saiu com tudo dito (saindo: o que a ponta daqui
/// escreveu já foi, e ela fecha). Com a ordem na mão da suíte, a sessão
/// chega à conclusão e espera: o fluxo segue vivo — o dono que ainda está
/// nele o vê aberto —, nada vai ao par e nenhum fim à cadeia. Solta a
/// ordem, o fim vai à cadeia uma vez, com a ordem na mão da sessão e antes
/// de acordar; só então o quadro sai ao par; e a operação do dono que vem
/// depois ouve o fim, depois dele na cadeia.
pub(in crate::testes) fn fluxo_o_fim_da_sessao_na_ordem() -> Resultado {
    use politica::fluxo::motivo;
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            // Chegando: o fim mandado ao par com o outro sentido já acabado.
            let antes = crate::autorizacao::ultimo_registro();
            let (mut la, id) = aberto_de_la(&b, VAGA)?;
            let n = crate::fluxo::numero_de_teste(&id).ok_or("o id nao e deste boot")?;
            la.mandar(&Mensagem::Dados(b"de la"))?;
            la.mandar(&Mensagem::Fim)?;
            let mut lido = Vec::new();
            esperar_no_par(
                || match lidos(&ler(b.quem(), &id, 100)) {
                    Some((d, fim)) => {
                        lido.extend_from_slice(&d);
                        fim
                    }
                    None => true,
                },
                TETO,
            )?;
            if lido != b"de la" {
                crate::log_error!("teste", "{:?}", lido);
                return Err("o processo daqui nao leu ate o fim o que veio de la");
            }
            let (fim_seq, fim) = concluido_na_ordem(
                n,
                &id,
                antes,
                Some(b.quem()),
                || {
                    feito(
                        &sobre(b.quem(), "stream.finish", &id),
                        "o fim do sentido daqui nao passou",
                    )
                },
                || {
                    la.colher()?;
                    Ok(la.chegou.is_empty())
                },
            )?;
            fim_do_kernel(&fim, "concluido; ida 5; volta 0; desc 0")?;
            // Só então o fim sai ao par; o fluxo concluído acaba sem fechar.
            match Mensagem::ler(&la.mensagem()?) {
                Some(Mensagem::Fim) => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o fim daqui nao chegou ao par depois de gravado");
                }
            }
            if la.esperar_o_fim()?.is_some() {
                return Err("o fluxo concluido pela sessao terminou com fechar");
            }
            // A operação do dono que vem depois ouve o fim — e vem depois
            // dele na cadeia.
            recusado_com(
                &ler(b.quem(), &id, 10),
                "CONFLICT",
                motivo::CONCLUIDO,
                "a leitura depois do fim nao ouviu o fluxo concluido",
            )?;
            let recurso = format!("fluxo:{id}");
            let lidas = registros_depois(antes, |e| {
                e.metodo == "stream.read" && e.recurso == recurso && e.codigo == Codigo::Conflict
            });
            if lidas.is_empty() || lidas.iter().any(|(s, _)| *s < fim_seq) {
                crate::log_error!("teste", "fim {}: {:?}", fim_seq, lidas);
                return Err("a operacao do dono que ouviu o fim veio antes dele na cadeia");
            }
            nada_vivo("o fluxo concluido pela sessao ficou vivo")?;
            // Saindo: o fecho de quem saiu com tudo dito.
            let antes = crate::autorizacao::ultimo_registro();
            let r = fs_pedir(
                b.quem(),
                "stream.open",
                &format!(
                    r#"{{"endpoint":"e0e0e0e0e0e0e0e0:3","intent":"{INTENCAO}","device":"dispositivo:{NOME_DO_PAR}"}}"#
                ),
            );
            feito(&r, "o pedido de fluxo ao par nao passou")?;
            let id = fs_texto(&r, "stream").ok_or("sem id")?;
            let n = crate::fluxo::numero_de_teste(&id).ok_or("o id nao e deste boot")?;
            lancar_a_sessao_saindo(n)?;
            let mut par = ParQueAceita::novo(DO_PAR);
            par.aceitar_o_aperto()?;
            let _abrir = par.mensagem()?;
            par.mandar(&Mensagem::Aceito("e0e0e0e0e0e0e0e0:9"))?;
            esperar_no_par(|| estado(b.quem(), &id).0.as_deref() == Some("open"), TETO)
                .map_err(|_| "o fluxo nao abriu com o aceito")?;
            escrito(
                &escrever(b.quem(), &id, b"tudo dito"),
                9,
                "a ponta daqui nao escreveu no fluxo ao par",
            )?;
            match Mensagem::ler(&par.mensagem()?) {
                Some(Mensagem::Dados(d)) if d == b"tudo dito" => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o par nao recebeu o que a ponta daqui escreveu");
                }
            }
            let (_, fim) = concluido_na_ordem(
                n,
                &id,
                antes,
                None,
                || {
                    feito(
                        &sobre(b.quem(), "stream.close", &id),
                        "o fecho daqui nao passou",
                    )
                },
                || com_linha(|l| l.para_la.is_empty()).ok_or("sem linha"),
            )?;
            fim_do_kernel(&fim, "fechado pela ponta; ida 9; volta 0; desc 0")?;
            // Só então o fim sai ao par, e o fecho atrás dele.
            match Mensagem::ler(&par.mensagem()?) {
                Some(Mensagem::Fim) => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o fim do fecho daqui nao chegou ao par depois de gravado");
                }
            }
            match Mensagem::ler(&par.mensagem()?) {
                Some(Mensagem::Fechar(m)) if m == motivo::FECHADO => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o fecho daqui nao chegou ao par com o motivo");
                }
            }
            esperar_no_par(|| com_linha(|l| l.acabou).unwrap_or(true), TETO)
                .map_err(|_| "a sessao daqui nao acabou depois do fecho")?;
            nada_vivo("o fluxo fechado pela ponta ficou vivo")
        })();
        crate::fluxo::desarmar_de_teste();
        encerrar_todas(r, &[&b])
    })
}
