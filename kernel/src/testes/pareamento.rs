//! Os casos da cerimônia de pareamento — D8: a Pessoa relaciona um Duke
//! dela a outro Duke dela, sem o administrador, com o código de conferência
//! digitado nos dois teclados e a senha dela.
//!
//! Um Duke só na suíte: o outro lado é a suíte, com uma chave de teste — um
//! Duke de verdade nunca solta a dele. Quando este Duke **aceita**, a suíte
//! inicia: fala com o respondedor de verdade da vaga do enlace, quadro a
//! quadro, e lê o que a cerimônia pôs na vaga ([`Iniciante`]). Quando este
//! Duke **inicia**, a suíte aceita: é a via do fio do iniciante, e a cada
//! volta da conversa o roteiro do caso anda — o que a Pessoa digita aqui, o
//! que o outro lado manda ([`Aceitante`]).
//!
//! A Pessoa digita no console dela, pelo caminho do teclado: `aceitar`,
//! `parear`, o código, a senha. O commit que o `conferido` do outro libera
//! roda na vez do console — o caso a dá, com [`crate::pareamento::no_console`],
//! como o interpretador acordado daria.

use super::Resultado;
use super::enlace::{
    VAGA, chave_de_dispositivo, codigo_do_envelope, com_o_enlace, privada_de_dispositivo,
};
use crate::pareamento::{Linha, NaVaga};
use crate::pessoas::{Console, IdSessao};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use politica::Codigo;
use politica::auditoria::Evento;
use politica::pareamento::{self as conta, Desfecho, Estado, Lado};
use protocolo::json::Json;
use sigilo::pessoas::IdPessoa;
use sigilo::quadro::{self, Leitor, Tipo};

/// O console da Pessoa dos casos: um Terminal, aberto e fechado por caso.
const CONSOLE: Console = Console::Terminal(2);

/// O console de outra Pessoa, ao mesmo tempo.
const OUTRO_CONSOLE: Console = Console::Terminal(3);

/// A senha das pessoas da suíte — ver `pessoas::sessao_de_teste`.
const SENHA: &str = "senha de teste";

/// O endereço do outro Duke, na forma normal — o que o papel do enlace
/// alcança.
const ENDERECO: &str = "tcp:10.0.2.100:7071";

/// O nome local do outro Duke nos casos — no alcance de `device.forget` do
/// operador — e o segundo.
const NOME: &str = "par";
const NOME_2: &str = "par-2";

/// O papel das relações dos casos: cabe no do operador, e não é teto.
const PAPEL: &str = "dispositivo";

/// O `conferido`, como as duas pontas o escrevem.
const CONFERIDO: &str = r#"{"estado":"conferido"}"#;

/// Quantas voltas a via de teste do iniciante dá antes de desistir: um
/// caso que não chega ao fim não prende a suíte.
const MAIS_VOLTAS: usize = 64;

// ---------------------------------------------------------------------
// O ambiente dos casos.
// ---------------------------------------------------------------------

/// Roda `f` com a cerimônia vazia — e o enlace, a malha e o registro de
/// dispositivos também —, os dois consoles dos casos abertos e o que a
/// cerimônia faria nas vagas guardado para o caso ler. No fim, confere que
/// a cerimônia nunca quebrou as regras dela, e a tira.
fn com_a_cerimonia(f: impl FnOnce() -> Resultado) -> Resultado {
    com_o_enlace(|| {
        crate::pareamento::esquecer_de_teste();
        crate::pareamento::saida_de_teste(true);
        crate::interpretador::abrir_console(CONSOLE);
        crate::interpretador::abrir_console(OUTRO_CONSOLE);
        let r = f();
        let coerente = crate::pareamento::coerente();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::interpretador::fechar_console(CONSOLE, "fim do caso");
        crate::interpretador::fechar_console(OUTRO_CONSOLE, "fim do caso");
        crate::pareamento::esquecer_de_teste();
        r?;
        if !coerente {
            return Err("a cerimonia de pareamento quebrou as regras dela");
        }
        Ok(())
    })
}

/// A Pessoa `nome`, operadora, entrada no console `console`: a sessão e o
/// identificador.
fn entrar(console: Console, nome: &str) -> Result<(IdSessao, IdPessoa), &'static str> {
    let sessao = crate::interpretador::entrar_para_teste(console, nome, "operador");
    let id = crate::pessoas::dona_da_sessao(sessao).ok_or("a sessao de teste nao tem pessoa")?;
    Ok((sessao, id))
}

/// Uma linha digitada no console, com o Enter.
fn digitar(console: Console, linha: &str) {
    super::digitar_no_console(console, &format!("{linha}\n"));
}

/// O que a linha do console pede por causa da cerimônia.
fn linha(console: Console) -> Linha {
    crate::pareamento::linha_do_console(console)
}

/// O estado da cerimônia, se há uma.
fn estado() -> Option<(Lado, Estado)> {
    crate::pareamento::estado_de_teste()
}

/// O estado tem de ser `esperado`.
fn no_estado(esperado: (Lado, Estado), erro: &'static str) -> Resultado {
    let agora = estado();
    if agora != Some(esperado) {
        crate::log_error!("teste", "{:?}, e nao {:?}", agora, esperado);
        return Err(erro);
    }
    Ok(())
}

/// A cerimônia acabou com o desfecho `d`, deste lado.
fn acabou_com(lado: Lado, d: Desfecho, erro: &'static str) -> Resultado {
    no_estado((lado, Estado::Fim(d)), erro)
}

/// Os códigos e a relação de um aperto, como os dois lados os contam.
#[derive(Clone, Copy, Debug)]
struct Contas {
    /// O que o aceitante mostra — e o iniciante digita.
    k_b: u32,
    /// O que o iniciante mostra — e o aceitante digita.
    k_a: u32,
    r: [u8; 16],
}

fn contas(h: &[u8; 32], n: &[u8; 32]) -> Contas {
    let (k_b, k_a) = conta::codigos(h, n);
    Contas {
        k_b,
        k_a,
        r: conta::relacao(h, n),
    }
}

/// Um código como a Pessoa o lê.
fn texto(k: u32) -> String {
    conta::texto_do_codigo(k)
}

/// Outro código, que não é `k`.
fn outro(k: u32) -> u32 {
    (k + 1) % 100_000_000
}

/// O `gravado` de `r`, e o `desistiu`, como as duas pontas os escrevem.
fn gravado(r: &[u8; 16]) -> String {
    format!(
        r#"{{"estado":"gravado","relation":"{}"}}"#,
        politica::dispositivos::id_texto(r)
    )
}

fn desistiu(motivo: &str) -> String {
    format!(r#"{{"estado":"desistiu","motivo":"{motivo}"}}"#)
}

/// O nonce de uma mensagem `{"nonce":"<64 hex>"}`.
fn nonce_de(m: &str) -> Option<[u8; 32]> {
    Json(m.as_bytes())
        .member("nonce")
        .and_then(|v| v.as_str())
        .and_then(sigilo::de_hex_fixo::<32>)
}

/// Os registros de `device.pair` gravados depois de `seq`.
fn do_pareamento(seq: u64) -> Vec<(u64, Evento)> {
    super::registros_depois(seq, |e| e.metodo == crate::autorizacao::PAREAMENTO)
}

/// O único desfecho sem gravar depois de `seq`: o código e o motivo no
/// detalhe — e o detalhe inteiro, dentro do teto.
fn uma_desfeita(seq: u64, codigo: Codigo, motivo: &str) -> Result<Evento, &'static str> {
    let v: Vec<Evento> = do_pareamento(seq)
        .into_iter()
        .map(|(_, e)| e)
        .filter(|e| e.detalhe.starts_with("desfeita: "))
        .collect();
    match v.as_slice() {
        [e] if e.codigo == codigo
            && e.detalhe.contains(motivo)
            && e.detalhe.len() < politica::auditoria::MAIOR_DETALHE =>
        {
            Ok(e.clone())
        }
        outros => {
            for e in outros {
                crate::log_error!("teste", "{:?} {}", e.codigo, e.detalhe);
            }
            crate::log_error!("teste", "esperado {} com `{}`", codigo.nome(), motivo);
            Err("a cerimonia nao gravou o desfecho esperado, uma vez")
        }
    }
}

/// Nada gravado desde `antes` — o tamanho do journal: nenhuma relação nova
/// no registro além de `relacoes`, e nenhum registro novo no journal.
fn nada_gravado(antes: usize, relacoes: usize) -> Resultado {
    if crate::dispositivos::relacoes().len() != relacoes {
        return Err("a cerimonia que nao gravou deixou relacao no registro");
    }
    if super::registros_do_journal()?.len() != antes {
        return Err("a cerimonia que nao gravou deixou registro no journal");
    }
    Ok(())
}

/// A relação da pessoa `pessoa` com o dispositivo de nome `nome`, como o
/// registro a tem: a chave e a relação.
fn relacao_de(
    nome: &str,
    pessoa: IdPessoa,
) -> Result<([u8; 32], crate::dispositivos::Relacao), &'static str> {
    crate::dispositivos::da_pessoa(nome, &pessoa.0).ok_or("a relacao nao esta no registro")
}

/// A relação gravada é a da cerimônia: a chave provada, o identificador
/// `r` dos dois lados, a pessoa da sessão, o papel e o endereço.
fn gravada_como(
    nome: &str,
    pessoa: IdPessoa,
    chave: &[u8; 32],
    r: &[u8; 16],
    endereco: Option<&str>,
) -> Result<crate::dispositivos::Relacao, &'static str> {
    let (k, rel) = relacao_de(nome, pessoa)?;
    if k != *chave
        || rel.id != *r
        || rel.pessoa != pessoa.0
        || rel.papel != PAPEL
        || rel.endereco.as_deref() != endereco
    {
        crate::log_error!("teste", "{:?} {:?}", k, rel);
        return Err("a relacao gravada nao e a da cerimonia");
    }
    Ok(rel)
}

/// O registro do journal que gravou a relação: um só, com o marcador da
/// operação, a linha inteira da relação e a decisão `decisao` — a da
/// gravação — no mesmo registro.
fn no_journal(
    antes: usize,
    chave: &[u8; 32],
    nome: &str,
    rel: &crate::dispositivos::Relacao,
    decisao: u64,
) -> Result<diario::Registro, &'static str> {
    use diario::estado::tipo;
    let linha = politica::dispositivos::linha(chave, nome, rel);
    let esperada =
        crate::persistencia::entrada_de_teste(tipo::DISPOSITIVO_REGISTRADO, &[linha.as_bytes()]);
    let recurso = format!("dispositivo:{nome}");
    let marcador = crate::persistencia::entrada_de_teste(
        tipo::OPERACAO,
        &[
            crate::autorizacao::PAREAMENTO.as_bytes(),
            recurso.as_bytes(),
        ],
    );
    let depois = super::registros_do_journal()?;
    let mut com_ela = Vec::new();
    for r in depois.iter().skip(antes) {
        let entradas = crate::persistencia::entradas_de_teste(r)?;
        if entradas.contains(&esperada.as_slice()) {
            if !entradas.contains(&marcador.as_slice()) {
                return Err("o registro da relacao nao traz o marcador do pareamento");
            }
            com_ela.push(r.clone());
        }
    }
    let [r] = com_ela.as_slice() else {
        return Err("a relacao pareada nao foi exatamente um registro do journal");
    };
    let decisoes = super::auditoria_do_registro(r)?;
    if !decisoes.iter().any(|(seq, e)| {
        *seq == decisao
            && e.metodo == crate::autorizacao::PAREAMENTO
            && e.codigo == Codigo::Allow
            && e.recurso == recurso
    }) {
        return Err("a decisao da gravacao nao foi no registro da relacao");
    }
    Ok(r.clone())
}

/// A decisão da gravação na auditoria, depois de `seq`: o `ALLOW` do
/// `pareado`, com a relação, a impressão do par e o console — uma só.
fn decisao_da_gravacao(
    seq: u64,
    nome: &str,
    chave: &[u8; 32],
    r: &[u8; 16],
    console: Console,
) -> Result<u64, &'static str> {
    let detalhe = format!(
        "pareado: relacao {}, par {}; {}",
        &politica::dispositivos::id_texto(r)[..8],
        crate::identidade::impressao(chave),
        console.texto()
    );
    let recurso = format!("dispositivo:{nome}");
    let v: Vec<(u64, Evento)> = do_pareamento(seq)
        .into_iter()
        .filter(|(_, e)| e.detalhe.starts_with("pareado: "))
        .collect();
    match v.as_slice() {
        [(s, e)]
            if e.codigo == Codigo::Allow
                && e.detalhe == detalhe
                && e.recurso == recurso
                && e.titular == politica::auditoria::Titular::Pessoa =>
        {
            Ok(*s)
        }
        outros => {
            for (_, e) in outros {
                crate::log_error!("teste", "{:?} {} {}", e.codigo, e.recurso, e.detalhe);
            }
            crate::log_error!("teste", "esperado `{}`", detalhe);
            Err("a gravacao da relacao nao foi decidida e gravada uma vez")
        }
    }
}

// ---------------------------------------------------------------------
// Este Duke aceita: a suíte inicia, pela vaga do enlace.
// ---------------------------------------------------------------------

/// O anúncio do Duke que aceita: a chave dele e o desafio da janela.
type Anuncio = ([u8; 32], [u8; 16]);

/// Um gancho do ponto de commit, nos casos da reconfirmação: o que ele faz,
/// o dispositivo de teste do par, e o fim que ele causa — o motivo da
/// cerimônia, o código e um pedaço do motivo da auditoria.
type Gancho = (fn(), u8, conta::Motivo, Codigo, &'static str);

/// O que a cerimônia fez na conexão do iniciante desde a última leitura.
#[derive(Debug, Default)]
struct Ouvido {
    /// As mensagens da cerimônia, abertas.
    mensagens: Vec<String>,
    /// A recusa em claro, se veio.
    recusa: Option<String>,
    /// O anúncio, se veio: a chave do Duke e o desafio da janela.
    anuncio: Option<Anuncio>,
    /// A 2ª mensagem do IK, se veio.
    resposta: Option<Vec<u8>>,
    /// A chave que a conexão provou, para o prazo do aperto parar.
    identificada: Option<[u8; 32]>,
    encerrada: bool,
}

/// O outro Duke, iniciando contra o respondedor de verdade da vaga `v`, na
/// conexão `g`: o pedido da chave, a 1ª mensagem do IK com o compromisso e o
/// desafio, e o nonce depois da 2ª — o que o fio do iniciante faria, com a
/// chave de teste dele.
struct Iniciante {
    lado: crate::enlace::Lado,
    ponta: super::enlace::PontaDeTeste,
    v: u8,
    g: u64,
    privada: [u8; 32],
    nonce: [u8; 32],
    leitor: Leitor,
    transporte: Option<sigilo::Transporte>,
    h: Option<[u8; 32]>,
    /// O quadro da 1ª mensagem, para repetir.
    primeira: Vec<u8>,
    /// Os quadros de dados mandados, para repetir.
    mandados: Vec<Vec<u8>>,
}

impl Iniciante {
    /// O dispositivo de teste `n`, na vaga `v` e na conexão `g`.
    fn novo(v: u8, g: u64, n: u8) -> Iniciante {
        Iniciante::com_privada(v, g, privada_de_dispositivo(n))
    }

    fn com_privada(v: u8, g: u64, privada: [u8; 32]) -> Iniciante {
        let mut lado = crate::enlace::Lado::nova(v, 0);
        lado.conexao(g);
        let mut nonce = [0u8; 32];
        let _ = crate::aleatorio::preencher(&mut nonce);
        Iniciante {
            lado,
            ponta: super::enlace::PontaDeTeste::default(),
            v,
            g,
            privada,
            nonce,
            leitor: Leitor::novo(),
            transporte: None,
            h: None,
            primeira: Vec::new(),
            mandados: Vec::new(),
        }
    }

    fn chave(&self) -> [u8; 32] {
        sigilo::publica_de(&self.privada)
    }

    fn empurrar(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.lado.receber(b, &mut self.ponta);
        }
    }

    /// O que a cerimônia fez nesta conexão. Uma escrita noutra conexão é um
    /// erro: a cerimônia só fala com a que ocupou a janela.
    fn ouvir(&mut self) -> Result<Ouvido, &'static str> {
        let mut o = Ouvido::default();
        for e in crate::pareamento::tirar_das_vagas_de_teste() {
            match e {
                NaVaga::Quadro(v, g, q) if (v, g) == (self.v, self.g) => {
                    for b in q {
                        let (tipo, corpo) = match self.leitor.empurrar(b) {
                            Ok(Some((t, c))) => (t, c.to_vec()),
                            Ok(None) => continue,
                            Err(_) => return Err("a cerimonia mandou um quadro que nao se le"),
                        };
                        match tipo {
                            Tipo::ChaveDoDuke if corpo.len() == 48 => {
                                let mut pk = [0u8; 32];
                                pk.copy_from_slice(&corpo[..32]);
                                let mut w = [0u8; 16];
                                w.copy_from_slice(&corpo[32..]);
                                o.anuncio = Some((pk, w));
                            }
                            Tipo::Resposta => o.resposta = Some(corpo),
                            Tipo::Recusa => {
                                o.recusa = Some(String::from_utf8_lossy(&corpo).into_owned());
                            }
                            Tipo::Dados => {
                                let t = self
                                    .transporte
                                    .as_mut()
                                    .ok_or("dados da cerimonia antes do aperto")?;
                                let mut claro = vec![0u8; corpo.len()];
                                let n = t
                                    .decifrar(&corpo, &mut claro)
                                    .map_err(|_| "a mensagem da cerimonia nao abriu")?;
                                let m = String::from_utf8(claro[..n].to_vec())
                                    .map_err(|_| "a mensagem da cerimonia nao e texto")?;
                                o.mensagens.push(m);
                            }
                            _ => return Err("a cerimonia mandou um quadro fora do protocolo"),
                        }
                    }
                }
                NaVaga::Identificada(v, g, k) if (v, g) == (self.v, self.g) => {
                    o.identificada = Some(k);
                }
                NaVaga::Encerrada(v, g) if (v, g) == (self.v, self.g) => o.encerrada = true,
                outra => {
                    crate::log_error!("teste", "{:?} (a conexao e {} {})", outra, self.v, self.g);
                    return Err("a cerimonia mexeu numa conexao que nao e a dela");
                }
            }
        }
        Ok(o)
    }

    /// O pedido da chave: `Ok(Ok)` com o anúncio — a chave do Duke e o
    /// desafio da janela —, `Ok(Err)` com a recusa em claro, e a conexão
    /// fechada.
    fn pedir_a_chave(&mut self) -> Result<Result<Anuncio, String>, &'static str> {
        let q = quadro::montar(Tipo::PedidoDaChave, &[]).map_err(|_| "o pedido nao se montou")?;
        self.empurrar(&q);
        let o = self.ouvir()?;
        match o {
            Ouvido {
                anuncio: Some(a),
                recusa: None,
                encerrada: false,
                ..
            } => Ok(Ok(a)),
            Ouvido {
                anuncio: None,
                recusa: Some(m),
                encerrada: true,
                ..
            } => Ok(Err(m)),
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                Err("o pedido da chave nao teve um anuncio, nem uma recusa")
            }
        }
    }

    /// A 1ª mensagem do IK para a chave `pk`, com o compromisso do nonce e o
    /// desafio `w`: `Ok(Ok)` com o transporte aberto pela 2ª, `Ok(Err)` com
    /// a recusa em claro.
    fn apertar(&mut self, pk: &[u8; 32], w: &[u8; 16]) -> Result<Result<(), String>, &'static str> {
        let c = conta::compromisso(&self.nonce);
        self.apertar_com(pk, &c, w)
    }

    fn apertar_com(
        &mut self,
        pk: &[u8; 32],
        compromisso: &[u8; 32],
        w: &[u8; 16],
    ) -> Result<Result<(), String>, &'static str> {
        let carga = format!(
            r#"{{"commit":"{}","janela":"{}"}}"#,
            sigilo::hex_de(compromisso),
            sigilo::hex_de(w)
        );
        let mut buf = vec![0u8; 512];
        let efemera = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
        let (n, aguardando) =
            sigilo::Iniciador::novo(sigilo::PROLOGO_DO_PAREAMENTO, &self.privada, pk)
                .escrever(efemera, carga.as_bytes(), &mut buf)
                .map_err(|_| "a 1a mensagem nao se escreveu")?;
        let q = quadro::montar(Tipo::InicioPareamento, &buf[..n]).map_err(|_| "quadro grande")?;
        self.primeira = q.clone();
        self.empurrar(&q);
        match self.ouvir()? {
            Ouvido {
                resposta: Some(corpo),
                recusa: None,
                encerrada: false,
                ..
            } => {
                let mut lixo = vec![0u8; corpo.len()];
                let (_, t) = aguardando
                    .ler(&corpo, &mut lixo)
                    .map_err(|_| "a 2a mensagem nao abriu")?;
                self.h = Some(t.resumo_do_aperto());
                self.transporte = Some(t);
                Ok(Ok(()))
            }
            Ouvido {
                resposta: None,
                recusa: Some(m),
                encerrada: true,
                ..
            } => Ok(Err(m)),
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                Err("a 1a mensagem nao teve a 2a, nem uma recusa")
            }
        }
    }

    /// Cifra e manda `claro`, num quadro de dados.
    fn mandar(&mut self, claro: &str) -> Result<(), &'static str> {
        let t = self
            .transporte
            .as_mut()
            .ok_or("o iniciante nao tem transporte")?;
        let mut c = vec![0u8; claro.len() + 16];
        let n = t
            .cifrar(claro.as_bytes(), &mut c)
            .map_err(|_| "a mensagem nao se cifrou")?;
        let q = quadro::montar(Tipo::Dados, &c[..n]).map_err(|_| "quadro grande")?;
        self.mandados.push(q.clone());
        self.empurrar(&q);
        Ok(())
    }

    fn mandar_o_nonce(&mut self) -> Result<(), &'static str> {
        let m = format!(r#"{{"nonce":"{}"}}"#, sigilo::hex_de(&self.nonce));
        self.mandar(&m)
    }

    fn contas(&self) -> Result<Contas, &'static str> {
        Ok(contas(
            &self.h.ok_or("o iniciante nao fez o aperto")?,
            &self.nonce,
        ))
    }
}

/// A Pessoa abre a janela: `aceitar <nome> <papel>`, no console.
fn aceitar(console: Console, nome: &str) -> Resultado {
    digitar(console, &format!("aceitar {nome} {PAPEL}"));
    no_estado((Lado::Aceita, Estado::Aberta), "aceitar nao abriu a janela")?;
    if linha(console) != Linha::Esperando || !crate::pareamento::escutando() {
        return Err("a janela aberta nao pos o console a esperar e a porta a escutar");
    }
    Ok(())
}

/// Do anúncio aos códigos: o pedido da chave, o aperto e o nonce. Os
/// códigos à mostra, a conexão identificada pela chave provada, e o
/// console pedindo o código do outro.
fn ate_os_codigos(console: Console, ini: &mut Iniciante) -> Result<Contas, &'static str> {
    let (pk, w) = ini.pedir_a_chave()?.map_err(|m| {
        crate::log_error!("teste", "{}", m);
        "o pedido da chave foi recusado com a janela aberta"
    })?;
    if Some(pk) != crate::identidade::publica_do_duke() {
        return Err("o anuncio nao trouxe a chave do Duke");
    }
    ini.apertar(&pk, &w)?.map_err(|m| {
        crate::log_error!("teste", "{}", m);
        "a 1a mensagem foi recusada com a janela aberta"
    })?;
    no_estado(
        (Lado::Aceita, Estado::Ocupada),
        "a 1a mensagem nao ocupou a janela",
    )?;
    ini.mandar_o_nonce()?;
    let o = ini.ouvir()?;
    if o.identificada != Some(ini.chave()) || !o.mensagens.is_empty() || o.encerrada {
        crate::log_error!("teste", "{:?}", o);
        return Err("o nonce nao identificou a conexao pela chave provada");
    }
    no_estado(
        (Lado::Aceita, Estado::Apertada),
        "o nonce nao pos os codigos a mostra",
    )?;
    if linha(console) != Linha::Codigo {
        return Err("os codigos a mostra nao pediram o codigo do outro no console");
    }
    ini.contas()
}

/// A Pessoa digita o código `codigo` — o que o outro mostra — e a senha.
fn conferir_aqui(console: Console, codigo: u32) -> Resultado {
    digitar(console, &texto(codigo));
    if linha(console) != Linha::Senha {
        return Err("o codigo certo nao pediu a senha");
    }
    digitar(console, SENHA);
    Ok(())
}

/// A cerimônia inteira com este Duke aceitando: o código e a senha aqui, o
/// `conferido` de lá, a gravação na vez do console, os dois `gravado`.
fn parear_aceitando(
    console: Console,
    nome: &str,
    ini: &mut Iniciante,
) -> Result<Contas, &'static str> {
    aceitar(console, nome)?;
    let k = ate_os_codigos(console, ini)?;
    conferir_aqui(console, k.k_a)?;
    if ini.ouvir()?.mensagens != [CONFERIDO] {
        return Err("a confirmacao daqui nao mandou o conferido");
    }
    no_estado(
        (Lado::Aceita, Estado::ConferidaAqui),
        "a confirmacao daqui gravou sem o conferido do outro",
    )?;
    ini.mandar(CONFERIDO)?;
    if !crate::pareamento::deve_ao_console() {
        return Err("o conferido do outro nao pediu a gravacao ao console");
    }
    crate::pareamento::no_console();
    let o = ini.ouvir()?;
    if o.mensagens != [gravado(&k.r)] || o.encerrada {
        crate::log_error!("teste", "{:?}", o);
        return Err("a gravacao nao mandou o gravado da relacao");
    }
    no_estado(
        (Lado::Aceita, Estado::Gravada),
        "a gravacao nao ficou esperando o outro",
    )?;
    ini.mandar(&gravado(&k.r))?;
    if !ini.ouvir()?.encerrada {
        return Err("a cerimonia concluida nao fechou a conexao");
    }
    acabou_com(
        Lado::Aceita,
        Desfecho::Concluida,
        "o gravado do outro nao concluiu a cerimonia",
    )?;
    Ok(k)
}

// ---------------------------------------------------------------------
// Este Duke inicia: a suíte aceita, pela via do fio do iniciante.
// ---------------------------------------------------------------------

/// O outro Duke aceitando, do lado de lá da via do fio do iniciante: o
/// anúncio, a 2ª mensagem do IK e as mensagens da cerimônia, com a chave de
/// teste dele.
struct Aceitante {
    /// A privada com que ele faz o aperto, e a chave que ele anuncia.
    privada: [u8; 32],
    anunciada: [u8; 32],
    desafio: [u8; 16],
    leitor: Leitor,
    saida: Vec<u8>,
    transporte: Option<sigilo::Transporte>,
    h: Option<[u8; 32]>,
    compromisso: Option<[u8; 32]>,
    janela: Option<[u8; 16]>,
    /// O nonce que abriu o compromisso.
    nonce: Option<[u8; 32]>,
    /// A chave que o iniciante provou no aperto.
    viu_chave: Option<[u8; 32]>,
    /// As mensagens que chegaram, abertas, e quantos quadros não abriram.
    mensagens: Vec<String>,
    estranhos: usize,
    /// Recusa o pedido da chave, em claro, com este motivo.
    recusar: Option<&'static str>,
    /// Responde a 1ª mensagem com lixo: quem anuncia uma chave que não tem.
    falsa: bool,
    voltas: usize,
}

impl Aceitante {
    /// O dispositivo de teste `n`, com o desafio `w`.
    fn novo(n: u8) -> Aceitante {
        Aceitante::com_privada(privada_de_dispositivo(n))
    }

    fn com_privada(privada: [u8; 32]) -> Aceitante {
        let mut desafio = [0u8; 16];
        let _ = crate::aleatorio::preencher(&mut desafio);
        Aceitante {
            privada,
            anunciada: sigilo::publica_de(&privada),
            desafio,
            leitor: Leitor::novo(),
            saida: Vec::new(),
            transporte: None,
            h: None,
            compromisso: None,
            janela: None,
            nonce: None,
            viu_chave: None,
            mensagens: Vec::new(),
            estranhos: 0,
            recusar: None,
            falsa: false,
            voltas: 0,
        }
    }

    fn por(&mut self, tipo: Tipo, corpo: &[u8]) {
        if let Ok(q) = quadro::montar(tipo, corpo) {
            self.saida.extend(q);
        }
    }

    /// Cifra e põe na saída uma mensagem da cerimônia.
    fn mandar(&mut self, claro: &str) {
        let Some(t) = self.transporte.as_mut() else {
            return;
        };
        let mut c = vec![0u8; claro.len() + 16];
        if let Ok(n) = t.cifrar(claro.as_bytes(), &mut c)
            && let Ok(q) = quadro::montar(Tipo::Dados, &c[..n])
        {
            self.saida.extend(q);
        }
    }

    /// Os códigos e a relação, depois do nonce.
    fn contas(&self) -> Option<Contas> {
        Some(contas(&self.h?, &self.nonce?))
    }

    /// Se a mensagem `m` chegou do iniciante.
    fn recebeu(&self, m: &str) -> bool {
        self.mensagens.iter().any(|x| x == m)
    }

    /// O que o fio do iniciante mandou.
    fn do_iniciante(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let (tipo, corpo) = match self.leitor.empurrar(b) {
                Ok(Some((t, c))) => (t, c.to_vec()),
                Ok(None) => continue,
                Err(_) => {
                    self.estranhos += 1;
                    continue;
                }
            };
            match tipo {
                Tipo::PedidoDaChave => match self.recusar {
                    Some(m) => self.por(Tipo::Recusa, m.as_bytes()),
                    None => {
                        let mut a = [0u8; 48];
                        a[..32].copy_from_slice(&self.anunciada);
                        a[32..].copy_from_slice(&self.desafio);
                        self.por(Tipo::ChaveDoDuke, &a);
                    }
                },
                Tipo::InicioPareamento if self.falsa => {
                    // Quem não tem a privada da chave anunciada não abre a 1ª
                    // mensagem: responde o que puder.
                    self.por(Tipo::Resposta, &[0x5a; 50]);
                }
                Tipo::InicioPareamento => self.responder(&corpo),
                Tipo::Dados => {
                    let aberta = self.transporte.as_mut().and_then(|t| {
                        let mut claro = vec![0u8; corpo.len()];
                        let n = t.decifrar(&corpo, &mut claro).ok()?;
                        String::from_utf8(claro[..n].to_vec()).ok()
                    });
                    match aberta {
                        Some(m) => {
                            if let Some(n) = nonce_de(&m)
                                && Some(conta::compromisso(&n)) == self.compromisso
                            {
                                self.nonce = Some(n);
                            }
                            self.mensagens.push(m);
                        }
                        None => self.estranhos += 1,
                    }
                }
                _ => self.estranhos += 1,
            }
        }
    }

    /// A 1ª mensagem: abre com a privada dele, guarda o compromisso e o
    /// desafio, e responde com a 2ª.
    fn responder(&mut self, corpo: &[u8]) {
        let mut carga = vec![0u8; corpo.len()];
        let Ok((n, recebido)) =
            sigilo::Respondedor::novo(sigilo::PROLOGO_DO_PAREAMENTO, &self.privada)
                .ler(corpo, &mut carga)
        else {
            self.por(Tipo::Recusa, b"a primeira mensagem nao abriu");
            return;
        };
        self.viu_chave = Some(recebido.remota());
        let j = Json(&carga[..n]);
        self.compromisso = j
            .member("commit")
            .and_then(|v| v.as_str())
            .and_then(sigilo::de_hex_fixo::<32>);
        self.janela = j
            .member("janela")
            .and_then(|v| v.as_str())
            .and_then(sigilo::de_hex_fixo::<16>);
        let mut r = vec![0u8; 128];
        let efemera = crate::aleatorio::chave().unwrap_or([0x44; 32]);
        match recebido.escrever(efemera, b"{}", &mut r) {
            Ok((m, t)) => {
                self.h = Some(t.resumo_do_aperto());
                self.transporte = Some(t);
                self.por(Tipo::Resposta, &r[..m]);
            }
            Err(_) => self.por(Tipo::Recusa, b"a segunda mensagem nao se escreveu"),
        }
    }
}

/// O que o roteiro do caso diz, a cada volta da conversa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Passo {
    /// A conversa segue: o que o aceitante pôs na saída chega ao fio.
    Segue,
    /// A conexão cai.
    Cai,
}

/// O aceitante de teste com o roteiro do caso: a cada `receber` do fio, o
/// roteiro anda — com o aceitante na mão.
struct ComRoteiro<F: FnMut(&mut Aceitante) -> Passo> {
    b: Aceitante,
    roteiro: F,
}

impl<F: FnMut(&mut Aceitante) -> Passo> crate::enlace::Via for ComRoteiro<F> {
    fn mandar(&mut self, bytes: &[u8]) -> Result<(), (Codigo, &'static str)> {
        self.b.do_iniciante(bytes);
        Ok(())
    }

    fn receber(&mut self, _prazo_ms: u64) -> Result<Vec<u8>, (Codigo, &'static str)> {
        self.b.voltas += 1;
        if self.b.voltas > MAIS_VOLTAS {
            return Err((Codigo::Error, "a via de teste cansou"));
        }
        match (self.roteiro)(&mut self.b) {
            Passo::Segue => Ok(core::mem::take(&mut self.b.saida)),
            Passo::Cai => Err((Codigo::Error, "o par de teste fechou a conexao")),
        }
    }
}

/// A Pessoa inicia: `parear <nome> <endereço> <papel>`, no console. Na
/// suíte não há fio: o caso conduz, com a via dele.
fn parear(console: Console, nome: &str) -> Resultado {
    digitar(console, &format!("parear {nome} {ENDERECO} {PAPEL}"));
    no_estado(
        (Lado::Inicia, Estado::Aberta),
        "parear nao abriu a cerimonia",
    )?;
    if linha(console) != Linha::Esperando || crate::pareamento::escutando() {
        return Err("parear nao pos o console a esperar, ou abriu a porta");
    }
    Ok(())
}

/// Conduz a cerimônia do iniciante com o aceitante `b` e o roteiro do caso,
/// como o fio conduziria, até o fim; devolve o aceitante.
fn conduzir(b: Aceitante, roteiro: impl FnMut(&mut Aceitante) -> Passo) -> Aceitante {
    let mut via = ComRoteiro { b, roteiro };
    crate::pareamento::conduzir_de_teste(&mut via);
    via.b
}

/// O roteiro de uma cerimônia inteira, iniciando: com os códigos à mostra, a
/// Pessoa digita o código do outro; o `conferido` de lá chega antes — ou
/// depois — da senha daqui; e o `gravado` de lá responde ao daqui.
fn roteiro_inteiro(console: Console, conferido_antes: bool) -> impl FnMut(&mut Aceitante) -> Passo {
    let mut feito = 0;
    move |b: &mut Aceitante| {
        let Some(k) = b.contas() else {
            return Passo::Segue;
        };
        match feito {
            0 => {
                digitar(console, &texto(k.k_b));
                if conferido_antes {
                    b.mandar(CONFERIDO);
                }
                feito = 1;
            }
            1 => {
                digitar(console, SENHA);
                if !conferido_antes {
                    b.mandar(CONFERIDO);
                }
                feito = 2;
            }
            2 if b.recebeu(&gravado(&k.r)) => {
                b.mandar(&gravado(&k.r));
                feito = 3;
            }
            _ => {}
        }
        Passo::Segue
    }
}

// ---------------------------------------------------------------------
// S01 — os dois lados gravam a mesma relação.
// ---------------------------------------------------------------------

/// Este Duke aceita, e a cerimônia vai até o fim: a janela abre e a porta
/// escuta; o anúncio traz a chave do Duke; o aperto ocupa a janela; o nonce
/// abre o compromisso e mostra os códigos; o código do outro e a senha
/// daqui; o `conferido` dos dois; a gravação na vez do console — a chave que
/// o IK provou, o mesmo `R` que o outro conta, a Pessoa da sessão, o papel —,
/// o `gravado` dos dois, e a conexão fecha. O journal leva a relação num
/// registro só, com a decisão; a auditoria, a abertura, o aperto e a
/// gravação; a porta segue escutando pela relação, e não mais pela janela.
pub(super) fn pareamento_aceitando_os_dois_gravam() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        if crate::pareamento::escutando() || crate::dispositivos::ha_relacao() {
            return Err("a porta do enlace escutava antes de qualquer janela ou relacao");
        }
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        let mut ini = Iniciante::novo(VAGA, 2_000_001, 1);
        let k = parear_aceitando(CONSOLE, NOME, &mut ini)?;
        let rel = gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        let decisao = decisao_da_gravacao(seq, NOME, &ini.chave(), &k.r, CONSOLE)?;
        no_journal(antes, &ini.chave(), NOME, &rel, decisao)?;
        // A abertura e o aperto, na auditoria.
        let aberta = do_pareamento(seq).iter().any(|(_, e)| {
            e.codigo == Codigo::Allow
                && e.recurso == "dispositivo:par"
                && e.detalhe == format!("janela aberta; papel {PAPEL}; {}", CONSOLE.texto())
        });
        let aperto = super::registros_depois(seq, |e| {
            e.metodo == crate::autorizacao::APERTO_DO_PAREAMENTO
                && e.codigo == Codigo::Allow
                && e.chave == Some(ini.chave())
                && e.detalhe
                    .contains(&crate::identidade::impressao(&ini.chave()))
        });
        if !aberta || aperto.len() != 1 {
            return Err("a abertura da janela ou o aperto nao foram gravados");
        }
        if crate::pareamento::escutando() || !crate::dispositivos::ha_relacao() {
            return Err("depois da cerimonia, a porta escuta pela janela, e nao pela relacao");
        }
        if linha(CONSOLE) != Linha::Comando {
            return Err("o console nao voltou aos comandos depois da cerimonia");
        }
        Ok(())
    })
}

/// Este Duke inicia, e a cerimônia vai até o fim — das duas ordens: o
/// `conferido` do outro antes da senha daqui (a gravação no Enter da
/// senha) e depois dela (na vez do console). O aperto prova a chave do
/// Duke ao outro, a relação gravada leva o endereço digitado, e o `R` é o
/// que o outro conta. A porta do enlace nunca escuta por causa de quem
/// inicia.
pub(super) fn pareamento_iniciando_os_dois_gravam() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        for (n, nome, conferido_antes) in [(1u8, NOME, true), (2u8, NOME_2, false)] {
            let seq = crate::autorizacao::ultimo_registro();
            let antes = super::registros_do_journal()?.len();
            parear(CONSOLE, nome)?;
            let b = if conferido_antes {
                conduzir(Aceitante::novo(n), roteiro_inteiro(CONSOLE, true))
            } else {
                // A senha daqui antes do `conferido` de lá: a gravação fica
                // para a vez do console, que o caso dá quando ele chega.
                let mut feito = 0;
                conduzir(Aceitante::novo(n), move |b: &mut Aceitante| {
                    let Some(k) = b.contas() else {
                        return Passo::Segue;
                    };
                    match feito {
                        0 => {
                            digitar(CONSOLE, &texto(k.k_b));
                            digitar(CONSOLE, SENHA);
                            feito = 1;
                        }
                        1 if b.recebeu(CONFERIDO) => {
                            b.mandar(CONFERIDO);
                            feito = 2;
                        }
                        2 => {
                            if crate::pareamento::deve_ao_console() {
                                crate::pareamento::no_console();
                                feito = 3;
                            }
                        }
                        3 if b.recebeu(&gravado(&k.r)) => {
                            b.mandar(&gravado(&k.r));
                            feito = 4;
                        }
                        _ => {}
                    }
                    Passo::Segue
                })
            };
            let k = b
                .contas()
                .ok_or("o aceitante de teste nao chegou aos codigos")?;
            if b.viu_chave != crate::identidade::publica_do_duke() || b.estranhos != 0 {
                return Err("o aperto do iniciante nao provou a chave do Duke ao outro");
            }
            if b.janela != Some(b.desafio) {
                return Err("a 1a mensagem nao levou o desafio do anuncio");
            }
            let esperadas = [
                format!(
                    r#"{{"nonce":"{}"}}"#,
                    sigilo::hex_de(&b.nonce.unwrap_or([0; 32]))
                ),
                String::from(CONFERIDO),
                gravado(&k.r),
            ];
            if b.mensagens != esperadas {
                crate::log_error!("teste", "{:?}", b.mensagens);
                return Err("o iniciante nao mandou o nonce, o conferido e o gravado, nessa ordem");
            }
            acabou_com(
                Lado::Inicia,
                Desfecho::Concluida,
                "o gravado do outro nao concluiu a cerimonia do iniciante",
            )?;
            let rel = gravada_como(nome, bia, &b.anunciada, &k.r, Some(ENDERECO))?;
            let decisao = decisao_da_gravacao(seq, nome, &b.anunciada, &k.r, CONSOLE)?;
            no_journal(antes, &b.anunciada, nome, &rel, decisao)?;
            let iniciada = do_pareamento(seq).iter().any(|(_, e)| {
                e.codigo == Codigo::Allow
                    && e.detalhe == format!("para {ENDERECO}; papel {PAPEL}; {}", CONSOLE.texto())
            });
            if !iniciada {
                return Err("a cerimonia iniciada nao foi gravada");
            }
            if crate::pareamento::escutando() {
                return Err("a porta do enlace escutou por causa de quem inicia");
            }
        }
        Ok(())
    })
}

/// Recomeça do zero no meio de um caso: nenhuma cerimônia, o relógio dela
/// de volta, e a janela de apertos das vagas vazia.
fn recomecar() {
    crate::pareamento::esquecer_de_teste();
    crate::pareamento::saida_de_teste(true);
    crate::autorizacao::esquecer_apertos_do_enlace_de_teste();
    // A cerimônia saiu por fora: a linha de um console que esperava por ela
    // volta aos comandos no Enter seguinte — uma linha vazia, que não faz
    // nada mais.
    for console in [CONSOLE, OUTRO_CONSOLE] {
        if crate::interpretador::abertura_de_teste(console) > 0 {
            digitar(console, "");
        }
    }
}

/// A cerimônia deste lado acabou sem gravar, por `motivo`: o fim gravado,
/// o `desistiu` com o motivo ao outro — se `avisado` — e a conexão
/// fechada; e nada gravado.
fn desfeita_aceitando(
    ini: &mut Iniciante,
    seq: u64,
    antes: usize,
    motivo: conta::Motivo,
    codigo: Codigo,
    avisado: bool,
) -> Resultado {
    desfeita_aceitando_por(ini, seq, antes, motivo, codigo, motivo.texto(), avisado)
}

/// [`desfeita_aceitando`], com o motivo da auditoria dito: o da recusa que
/// acabou a cerimônia — a decisão de novo, a chave do par —, quando não é
/// o motivo da cerimônia.
fn desfeita_aceitando_por(
    ini: &mut Iniciante,
    seq: u64,
    antes: usize,
    motivo: conta::Motivo,
    codigo: Codigo,
    trecho: &str,
    avisado: bool,
) -> Resultado {
    let o = ini.ouvir()?;
    let esperadas: Vec<String> = if avisado {
        vec![desistiu(motivo.texto())]
    } else {
        Vec::new()
    };
    if o.mensagens != esperadas || !o.encerrada {
        crate::log_error!("teste", "{:?}", o);
        return Err("o outro lado nao soube que a cerimonia acabou, ou a conexao ficou");
    }
    acabou_com(
        Lado::Aceita,
        Desfecho::Desfeita(motivo),
        "a cerimonia nao acabou pelo motivo dela",
    )?;
    uma_desfeita(seq, codigo, trecho)?;
    nada_gravado(antes, 0)?;
    if linha(CONSOLE) != Linha::Comando || crate::pareamento::escutando() {
        return Err("a cerimonia acabada deixou o console nela, ou a porta escutando");
    }
    Ok(())
}

// ---------------------------------------------------------------------
// S02 — o código incorreto.
// ---------------------------------------------------------------------

/// O código errado — um outro, ou um pedaço do certo — acaba a cerimônia
/// nos dois lados, na primeira vez: o `desistiu` vai ao outro, nada é
/// gravado, o fim vai à auditoria. Não há segunda tentativa: o certo,
/// digitado depois, é um comando qualquer. E o mesmo deste Duke iniciando.
pub(super) fn pareamento_o_codigo_errado_desfaz() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let errados: [fn(u32) -> String; 3] = [
            |k| texto(outro(k)),
            // Um pedaço do certo: sete dos oito dígitos.
            |k| String::from(&texto(k)[..8]),
            |k| format!("{} 0", texto(k)),
        ];
        for (i, errado) in errados.iter().enumerate() {
            recomecar();
            let seq = crate::autorizacao::ultimo_registro();
            let antes = super::registros_do_journal()?.len();
            let mut ini = Iniciante::novo(VAGA, 2_000_100 + i as u64, 1);
            aceitar(CONSOLE, NOME)?;
            let k = ate_os_codigos(CONSOLE, &mut ini)?;
            digitar(CONSOLE, &errado(k.k_a));
            desfeita_aceitando(
                &mut ini,
                seq,
                antes,
                conta::Motivo::CodigoErrado,
                Codigo::DenyNotAuthenticated,
                true,
            )?;
            // O certo, depois: a cerimônia acabou, e ele é só uma linha.
            digitar(CONSOLE, &texto(k.k_a));
            acabou_com(
                Lado::Aceita,
                Desfecho::Desfeita(conta::Motivo::CodigoErrado),
                "o codigo certo depois do errado mudou a cerimonia",
            )?;
            nada_gravado(antes, 0)?;
        }
        // Iniciando: o código errado aqui, e o `desistiu` vai ao outro.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        parear(CONSOLE, NOME)?;
        let mut digitado = false;
        let b = conduzir(Aceitante::novo(1), |b: &mut Aceitante| {
            if let Some(k) = b.contas()
                && !digitado
            {
                digitar(CONSOLE, &texto(outro(k.k_b)));
                digitado = true;
            }
            Passo::Segue
        });
        if !digitado || !b.recebeu(&desistiu(conta::Motivo::CodigoErrado.texto())) {
            return Err("o codigo errado no iniciante nao avisou o outro");
        }
        if b.recebeu(CONFERIDO) {
            return Err("o codigo errado no iniciante mandou o conferido");
        }
        acabou_com(
            Lado::Inicia,
            Desfecho::Desfeita(conta::Motivo::CodigoErrado),
            "o codigo errado nao desfez a cerimonia do iniciante",
        )?;
        uma_desfeita(seq, Codigo::DenyNotAuthenticated, "o codigo nao conferiu")?;
        nada_gravado(antes, 0)
    })
}

// ---------------------------------------------------------------------
// S03 — o código expirado.
// ---------------------------------------------------------------------

/// O prazo: a janela vencida não anuncia nada, e o coletor a fecha; o
/// código certo, digitado depois dos 180 s, é recusado — e o outro sabe.
/// Nada gravado.
pub(super) fn pareamento_o_prazo_desfaz() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        // A janela: 120 s para o aperto chegar.
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        aceitar(CONSOLE, NOME)?;
        crate::pareamento::adiantar_de_teste(conta::JANELA_MS);
        let mut ini = Iniciante::novo(VAGA, 2_000_200, 1);
        match ini.pedir_a_chave()? {
            Err(m) if m == "sem janela de pareamento aberta" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("a janela vencida ainda anunciou a chave");
            }
        }
        crate::pareamento::vencer();
        acabou_com(
            Lado::Aceita,
            Desfecho::Desfeita(conta::Motivo::Prazo),
            "o coletor nao fechou a janela vencida",
        )?;
        if crate::pareamento::escutando() {
            return Err("a porta continuou escutando pela janela vencida");
        }
        uma_desfeita(seq, Codigo::Error, "a cerimonia venceu")?;
        nada_gravado(antes, 0)?;
        // O código: o certo, um instante depois do prazo da cerimônia.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_000_201, 1);
        aceitar(CONSOLE, NOME)?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        crate::pareamento::adiantar_de_teste(conta::PRAZO_MS);
        digitar(CONSOLE, &texto(k.k_a));
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Prazo,
            Codigo::Error,
            true,
        )
    })
}

// ---------------------------------------------------------------------
// S04 — o código reutilizado; confirm × confirm.
// ---------------------------------------------------------------------

/// O código de uma cerimônia anterior não confere na seguinte: é outro
/// aperto. E, na mesma cerimônia, a segunda entrada de um passo já dado — o
/// código, a senha — é `CONFLICT`, e não muda nada.
pub(super) fn pareamento_o_codigo_reutilizado() -> Resultado {
    com_a_cerimonia(|| {
        let (sessao, _) = entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        // A primeira cerimônia: até os códigos, e a Pessoa desiste.
        let mut ini = Iniciante::novo(VAGA, 2_000_300, 1);
        aceitar(CONSOLE, NOME)?;
        let velhas = ate_os_codigos(CONSOLE, &mut ini)?;
        digitar(CONSOLE, "");
        acabou_com(
            Lado::Aceita,
            Desfecho::Desfeita(conta::Motivo::Cancelada),
            "a linha vazia nao desistiu",
        )?;
        if ini.ouvir()?.mensagens != [desistiu("cancelada")] {
            return Err("a desistencia da Pessoa nao avisou o outro");
        }
        // A segunda: o código da primeira não confere.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_000_301, 1);
        aceitar(CONSOLE, NOME)?;
        let novas = ate_os_codigos(CONSOLE, &mut ini)?;
        if novas.k_a == velhas.k_a || novas.r == velhas.r {
            return Err("dois apertos deram o mesmo codigo ou a mesma relacao");
        }
        digitar(CONSOLE, &texto(velhas.k_a));
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::CodigoErrado,
            Codigo::DenyNotAuthenticated,
            true,
        )?;
        // A terceira: cada passo duas vezes.
        recomecar();
        let mut ini = Iniciante::novo(VAGA, 2_000_302, 1);
        aceitar(CONSOLE, NOME)?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        let abertura = crate::interpretador::abertura_de_teste(CONSOLE);
        let entrar_linha = |l: Linha, t: &str| {
            crate::pareamento::linha_digitada(CONSOLE, abertura, Some(sessao), l, t.as_bytes())
        };
        let conflito = |t: &str| t.contains("CONFLICT");
        if conflito(&entrar_linha(Linha::Codigo, &texto(k.k_a))) {
            return Err("a primeira entrada do codigo foi conflito");
        }
        let segunda = entrar_linha(Linha::Codigo, &texto(k.k_a));
        no_estado(
            (Lado::Aceita, Estado::CodigoCerto),
            "a segunda entrada do codigo mudou a cerimonia",
        )?;
        if !conflito(&segunda) {
            crate::log_error!("teste", "{}", segunda);
            return Err("a segunda entrada do codigo nao foi CONFLICT");
        }
        entrar_linha(Linha::Senha, SENHA);
        let segunda = entrar_linha(Linha::Senha, SENHA);
        no_estado(
            (Lado::Aceita, Estado::ConferidaAqui),
            "a segunda entrada da senha mudou a cerimonia",
        )?;
        if !conflito(&segunda) {
            crate::log_error!("teste", "{}", segunda);
            return Err("a segunda entrada da senha nao foi CONFLICT");
        }
        if ini.ouvir()?.mensagens != [CONFERIDO] {
            return Err("as duas entradas da senha nao mandaram um conferido so");
        }
        entrar_linha(Linha::Esperando, "");
        acabou_com(
            Lado::Aceita,
            Desfecho::Desfeita(conta::Motivo::Cancelada),
            "a desistencia depois do conferido nao desfez",
        )?;
        nada_gravado(antes, 0)
    })
}

// ---------------------------------------------------------------------
// S05 — o replay.
// ---------------------------------------------------------------------

/// A 1ª mensagem de uma cerimônia anterior, repetida noutra conexão numa
/// janela nova, abre — é para a chave deste Duke — mas traz o desafio
/// velho: recusada, e a janela continua livre para o iniciante de verdade.
/// E um quadro repetido de uma cerimônia já gravada não abre — o contador
/// do transporte —: a conexão fecha, e a relação gravada fica, sem o
/// `desistiu` que a desfaria do outro lado.
pub(super) fn pareamento_o_replay() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        // A primeira cerimônia: o aperto, e a Pessoa desiste.
        let mut velho = Iniciante::novo(VAGA, 2_000_400, 1);
        aceitar(CONSOLE, NOME)?;
        ate_os_codigos(CONSOLE, &mut velho)?;
        digitar(CONSOLE, "");
        velho.ouvir()?;
        // A janela nova: a 1ª mensagem velha, repetida.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        aceitar(CONSOLE, NOME)?;
        let mut repetidor = Iniciante::novo(VAGA + 1, 2_000_401, 1);
        let primeira = velho.primeira.clone();
        repetidor.empurrar(&primeira);
        let o = repetidor.ouvir()?;
        if o.recusa.as_deref() != Some("o desafio nao e o desta janela") || !o.encerrada {
            crate::log_error!("teste", "{:?}", o);
            return Err("a 1a mensagem repetida nao foi recusada pelo desafio velho");
        }
        no_estado(
            (Lado::Aceita, Estado::Aberta),
            "a 1a mensagem repetida ocupou a janela",
        )?;
        let recusado = super::registros_depois(seq, |e| {
            e.metodo == crate::autorizacao::APERTO_DO_PAREAMENTO
                && e.codigo == Codigo::DenyNotAuthenticated
                && e.detalhe.starts_with("o desafio nao e o desta janela")
        });
        if recusado.len() != 1 {
            return Err("a 1a mensagem repetida nao foi gravada como recusa");
        }
        // O iniciante de verdade, na mesma janela: grava.
        let mut ini = Iniciante::novo(VAGA, 2_000_402, 1);
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        conferir_aqui(CONSOLE, k.k_a)?;
        ini.ouvir()?;
        ini.mandar(CONFERIDO)?;
        crate::pareamento::no_console();
        if ini.ouvir()?.mensagens != [gravado(&k.r)] {
            return Err("a gravacao nao mandou o gravado");
        }
        // O `conferido` dele, repetido: não abre.
        let repetido = ini
            .mandados
            .last()
            .cloned()
            .ok_or("o iniciante nao mandou nada")?;
        ini.empurrar(&repetido);
        let o = ini.ouvir()?;
        if !o.mensagens.is_empty() || !o.encerrada {
            crate::log_error!("teste", "{:?}", o);
            return Err("o quadro repetido nao encerrou, ou levou um desistiu");
        }
        acabou_com(
            Lado::Aceita,
            Desfecho::GravadaSemAviso,
            "o quadro repetido depois da gravacao nao deixou a relacao deste lado",
        )?;
        gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S28 — a senha errada.
// ---------------------------------------------------------------------

/// A senha errada, depois do código certo, acaba a cerimônia — o outro
/// sabe, nada é gravado — e conta na janela de tentativas do console, a
/// mesma do login: quatro logins depois, o quinto, certo, é recusado.
pub(super) fn pareamento_a_senha_errada() -> Resultado {
    use crate::pessoas::{RecusaDeLogin, autenticar};
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        let mut ini = Iniciante::novo(VAGA, 2_000_500, 1);
        aceitar(CONSOLE, NOME)?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        digitar(CONSOLE, &texto(k.k_a));
        digitar(CONSOLE, "nao e a senha dela");
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::SenhaErrada,
            Codigo::DenyNotAuthenticated,
            true,
        )?;
        for _ in 1..crate::pessoas::TENTATIVAS.quantos {
            if autenticar(CONSOLE, "bia", b"tambem nao e") != Err(RecusaDeLogin::NaoConfere) {
                return Err("um login errado nao foi recusado como tal");
            }
        }
        if autenticar(CONSOLE, "bia", SENHA.as_bytes()) != Err(RecusaDeLogin::Tentativas) {
            return Err("a senha errada da cerimonia nao contou na janela de tentativas");
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S30 — o commit duplicado.
// ---------------------------------------------------------------------

/// O commit pedido de novo — gravando, gravada, concluída — devolve a
/// resposta guardada: a relação e a decisão. Uma relação no registro, um
/// registro no journal, uma decisão na auditoria.
pub(super) fn pareamento_o_commit_duplicado() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        let mut ini = Iniciante::novo(VAGA, 2_000_600, 1);
        aceitar(CONSOLE, NOME)?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        conferir_aqui(CONSOLE, k.k_a)?;
        ini.ouvir()?;
        ini.mandar(CONFERIDO)?;
        crate::pareamento::no_console();
        let decisao = decisao_da_gravacao(seq, NOME, &ini.chave(), &k.r, CONSOLE)?;
        let guardada = format!(
            "ja gravada: relacao {}, decisao {decisao}",
            &politica::dispositivos::id_texto(&k.r)[..8]
        );
        for vez in 0..2 {
            let r = crate::pareamento::gravar_de_novo_de_teste();
            if r != guardada {
                crate::log_error!("teste", "{}", r);
                return Err("o commit pedido de novo nao devolveu a resposta guardada");
            }
            if vez == 0 {
                // Concluída, ainda a mesma resposta.
                ini.ouvir()?;
                ini.mandar(&gravado(&k.r))?;
                acabou_com(Lado::Aceita, Desfecho::Concluida, "o gravado nao concluiu")?;
            }
        }
        if ini.ouvir()?.mensagens.iter().any(|m| m.contains("gravado")) {
            return Err("o commit pedido de novo mandou outro gravado");
        }
        let rel = gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        if crate::dispositivos::relacoes().len() != 1 {
            return Err("o commit pedido de novo pos outra relacao no registro");
        }
        decisao_da_gravacao(seq, NOME, &ini.chave(), &k.r, CONSOLE)?;
        no_journal(antes, &ini.chave(), NOME, &rel, decisao)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S06, S07 — o par no meio; outro Duke no endereço.
// ---------------------------------------------------------------------

/// Um aperto do IK da cerimônia entre duas chaves de teste, inteiro na
/// suíte: o resumo que os dois lados dele contam.
fn aperto_avulso(privada_i: &[u8; 32], privada_r: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let pk_r = sigilo::publica_de(privada_r);
    let mut m1 = vec![0u8; 256];
    let e_i = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
    let (n1, aguardando) = sigilo::Iniciador::novo(sigilo::PROLOGO_DO_PAREAMENTO, privada_i, &pk_r)
        .escrever(e_i, b"{}", &mut m1)
        .map_err(|_| "o aperto avulso nao se escreveu")?;
    let mut carga = vec![0u8; n1];
    let (_, recebido) = sigilo::Respondedor::novo(sigilo::PROLOGO_DO_PAREAMENTO, privada_r)
        .ler(&m1[..n1], &mut carga)
        .map_err(|_| "o aperto avulso nao abriu")?;
    let mut m2 = vec![0u8; 256];
    let e_r = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
    let (n2, t_r) = recebido
        .escrever(e_r, b"{}", &mut m2)
        .map_err(|_| "a 2a mensagem avulsa nao se escreveu")?;
    let mut lixo = vec![0u8; n2];
    let (_, t_i) = aguardando
        .ler(&m2[..n2], &mut lixo)
        .map_err(|_| "a 2a mensagem avulsa nao abriu")?;
    if t_i.resumo_do_aperto() != t_r.resumo_do_aperto() {
        return Err("os dois lados de um aperto contam resumos diferentes");
    }
    Ok(t_i.resumo_do_aperto())
}

/// Um nonce sorteado.
fn sorteado() -> [u8; 32] {
    let mut n = [0u8; 32];
    let _ = crate::aleatorio::preencher(&mut n);
    n
}

/// O par no meio, com uma chave dele, entre os dois Dukes da Pessoa: um
/// aperto com cada lado, e cada lado mostra os códigos do aperto dele. O
/// que a Pessoa lê numa tela não é o que a outra pede: nada é gravado em
/// lado nenhum, dos dois jeitos — este Duke aceitando, ou iniciando.
pub(super) fn pareamento_o_par_no_meio() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let (a, m, b) = (
            privada_de_dispositivo(1),
            privada_de_dispositivo(3),
            privada_de_dispositivo(2),
        );
        // Este Duke aceita; o par no meio inicia com ele, e responde ao Duke
        // A da Pessoa — que mostra os códigos do aperto A–M.
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        let mut meio = Iniciante::com_privada(VAGA, 2_000_700, m);
        aceitar(CONSOLE, NOME)?;
        let aqui = ate_os_codigos(CONSOLE, &mut meio)?;
        let em_a = contas(&aperto_avulso(&a, &m)?, &sorteado());
        if em_a.k_a == aqui.k_a || em_a.k_b == aqui.k_b {
            return Err("dois apertos deram o mesmo codigo");
        }
        digitar(CONSOLE, &texto(em_a.k_a));
        desfeita_aceitando(
            &mut meio,
            seq,
            antes,
            conta::Motivo::CodigoErrado,
            Codigo::DenyNotAuthenticated,
            true,
        )?;
        // Este Duke inicia; o par no meio aceita, e inicia com o Duke B da
        // Pessoa — que mostra os códigos do aperto M–B.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        parear(CONSOLE, NOME)?;
        let em_b = contas(&aperto_avulso(&m, &b)?, &sorteado());
        let mut digitado = None;
        let fim = conduzir(Aceitante::com_privada(m), |x: &mut Aceitante| {
            if let Some(k) = x.contas()
                && digitado.is_none()
            {
                digitar(CONSOLE, &texto(em_b.k_b));
                digitado = Some(k);
            }
            Passo::Segue
        });
        let k = digitado.ok_or("o iniciante nao chegou aos codigos")?;
        if k.k_b == em_b.k_b {
            return Err("dois apertos deram o mesmo codigo");
        }
        if !fim.recebeu(&desistiu(conta::Motivo::CodigoErrado.texto())) || fim.recebeu(CONFERIDO) {
            return Err("o iniciante com o par no meio nao desistiu, ou conferiu");
        }
        acabou_com(
            Lado::Inicia,
            Desfecho::Desfeita(conta::Motivo::CodigoErrado),
            "o par no meio nao desfez a cerimonia do iniciante",
        )?;
        uma_desfeita(seq, Codigo::DenyNotAuthenticated, "o codigo nao conferiu")?;
        nada_gravado(antes, 0)
    })
}

/// Outro Duke atende no endereço que a Pessoa digitou. Com o nome já de um
/// dispositivo do registro — de outra chave —, a cerimônia acaba no
/// anúncio. Sem isso, os códigos aparecem, mas o que a Pessoa lê no
/// dispositivo dela não é o deste aperto: não confere. Nada gravado.
pub(super) fn pareamento_outro_duke_no_endereco() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let (_, caio) = entrar(OUTRO_CONSOLE, "caio")?;
        super::enlace::relacionar(caio, NOME, 1, PAPEL, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")?;
        let seq = crate::autorizacao::ultimo_registro();
        let antes = super::registros_do_journal()?.len();
        parear(CONSOLE, NOME)?;
        let fim = conduzir(Aceitante::novo(4), |_| Passo::Segue);
        if fim.nonce.is_some() || fim.viu_chave.is_some() {
            return Err("o iniciante apertou com a chave que nao e a do nome");
        }
        acabou_com(
            Lado::Inicia,
            Desfecho::Desfeita(conta::Motivo::Recusada),
            "o nome de outra chave nao desfez a cerimonia",
        )?;
        uma_desfeita(
            seq,
            Codigo::InvalidArgument,
            "o nome ja e de outro dispositivo",
        )?;
        nada_gravado(antes, 1)?;
        // Um nome livre: o código que a Pessoa lê no dispositivo dela não é
        // o do Duke que atendeu.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        parear(CONSOLE, NOME_2)?;
        let do_dela = contas(
            &aperto_avulso(&privada_de_dispositivo(1), &privada_de_dispositivo(2))?,
            &sorteado(),
        );
        let mut digitou = false;
        let fim = conduzir(Aceitante::novo(4), |x: &mut Aceitante| {
            if x.contas().is_some() && !digitou {
                digitar(CONSOLE, &texto(do_dela.k_b));
                digitou = true;
            }
            Passo::Segue
        });
        if fim.contas().is_some_and(|k| k.k_b == do_dela.k_b) {
            return Err("dois apertos deram o mesmo codigo");
        }
        acabou_com(
            Lado::Inicia,
            Desfecho::Desfeita(conta::Motivo::CodigoErrado),
            "o codigo de outro dispositivo nao desfez a cerimonia",
        )?;
        uma_desfeita(seq, Codigo::DenyNotAuthenticated, "o codigo nao conferiu")?;
        nada_gravado(antes, 1)
    })
}

// ---------------------------------------------------------------------
// S08, S09 — o dispositivo falso; a mensagem adulterada.
// ---------------------------------------------------------------------

/// Quem anuncia a chave de outro dispositivo não tem a privada dela: não
/// abre a 1ª mensagem, e o que ele responder não fecha o aperto — os
/// códigos nunca aparecem, nada é gravado, e o fim diz que o par não
/// provou a chave.
pub(super) fn pareamento_o_dispositivo_falso() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        for (falsa, motivo, codigo, trecho) in [
            (
                true,
                conta::Motivo::ParNaoProvou,
                Codigo::DenyNotAuthenticated,
                "o par nao provou a chave",
            ),
            (
                false,
                conta::Motivo::OutroDesistiu,
                Codigo::DenyNotAuthenticated,
                "o outro recusou: a primeira mensagem nao abriu",
            ),
        ] {
            recomecar();
            let seq = crate::autorizacao::ultimo_registro();
            parear(CONSOLE, NOME)?;
            let mut falso = Aceitante::novo(4);
            falso.anunciada = chave_de_dispositivo(1);
            falso.falsa = falsa;
            let mut codigos_a_mostra = false;
            let fim = conduzir(falso, |_| {
                codigos_a_mostra |= linha(CONSOLE) == Linha::Codigo;
                Passo::Segue
            });
            if codigos_a_mostra || fim.nonce.is_some() || !fim.mensagens.is_empty() {
                return Err("o dispositivo falso chegou aos codigos, ou ao nonce");
            }
            acabou_com(
                Lado::Inicia,
                Desfecho::Desfeita(motivo),
                "o dispositivo falso nao desfez a cerimonia",
            )?;
            let e = uma_desfeita(seq, codigo, trecho)?;
            if !e
                .detalhe
                .contains(&crate::identidade::impressao(&chave_de_dispositivo(1)))
            {
                return Err("o fim nao diz a chave que o falso anunciou");
            }
            nada_gravado(antes, 0)?;
        }
        Ok(())
    })
}

impl Iniciante {
    /// A 1ª mensagem com um byte trocado no meio: a recusa em claro.
    fn apertar_adulterado(&mut self, pk: &[u8; 32], w: &[u8; 16]) -> Result<Ouvido, &'static str> {
        let carga = format!(
            r#"{{"commit":"{}","janela":"{}"}}"#,
            sigilo::hex_de(&conta::compromisso(&self.nonce)),
            sigilo::hex_de(w)
        );
        let mut buf = vec![0u8; 512];
        let efemera = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
        let (n, _) = sigilo::Iniciador::novo(sigilo::PROLOGO_DO_PAREAMENTO, &self.privada, pk)
            .escrever(efemera, carga.as_bytes(), &mut buf)
            .map_err(|_| "a 1a mensagem nao se escreveu")?;
        buf[n / 2] ^= 0x01;
        let q = quadro::montar(Tipo::InicioPareamento, &buf[..n]).map_err(|_| "quadro grande")?;
        self.empurrar(&q);
        self.ouvir()
    }

    /// Cifra `claro`, troca um byte do cifrado e manda.
    fn mandar_adulterado(&mut self, claro: &str) -> Result<(), &'static str> {
        let t = self
            .transporte
            .as_mut()
            .ok_or("o iniciante nao tem transporte")?;
        let mut c = vec![0u8; claro.len() + 16];
        let n = t
            .cifrar(claro.as_bytes(), &mut c)
            .map_err(|_| "a mensagem nao se cifrou")?;
        c[n / 2] ^= 0x01;
        let q = quadro::montar(Tipo::Dados, &c[..n]).map_err(|_| "quadro grande")?;
        self.empurrar(&q);
        Ok(())
    }
}

impl Aceitante {
    /// Cifra `claro`, troca um byte do cifrado e põe na saída.
    fn mandar_adulterado(&mut self, claro: &str) {
        let Some(t) = self.transporte.as_mut() else {
            return;
        };
        let mut c = vec![0u8; claro.len() + 16];
        if let Ok(n) = t.cifrar(claro.as_bytes(), &mut c) {
            c[n / 2] ^= 0x01;
            if let Ok(q) = quadro::montar(Tipo::Dados, &c[..n]) {
                self.saida.extend(q);
            }
        }
    }
}

/// Um byte trocado em cada passo: a 1ª mensagem não abre — recusada, e a
/// janela continua livre —; o nonce cifrado não abre — a sessão cai —; o
/// nonce que não abre o compromisso desfaz; e, iniciando, o `conferido`
/// adulterado do outro encerra. Nada gravado em nenhum.
pub(super) fn pareamento_a_mensagem_adulterada() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        // A 1ª mensagem.
        aceitar(CONSOLE, NOME)?;
        let mut ini = Iniciante::novo(VAGA, 2_000_800, 1);
        let (pk, w) = ini.pedir_a_chave()?.map_err(|_| "o anuncio foi recusado")?;
        let o = ini.apertar_adulterado(&pk, &w)?;
        if o.recusa.is_none() || !o.encerrada || o.resposta.is_some() {
            crate::log_error!("teste", "{:?}", o);
            return Err("a 1a mensagem adulterada nao foi recusada");
        }
        no_estado(
            (Lado::Aceita, Estado::Aberta),
            "a 1a mensagem adulterada ocupou a janela",
        )?;
        // O nonce cifrado, com um byte trocado.
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA + 1, 2_000_801, 1);
        let (pk, w) = ini.pedir_a_chave()?.map_err(|_| "o anuncio foi recusado")?;
        ini.apertar(&pk, &w)?
            .map_err(|_| "a 1a mensagem foi recusada")?;
        let m = format!(r#"{{"nonce":"{}"}}"#, sigilo::hex_de(&ini.nonce));
        ini.mandar_adulterado(&m)?;
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::ForaDoProtocolo,
            Codigo::InvalidArgument,
            true,
        )?;
        // O compromisso de um nonce, e outro nonce aberto.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        aceitar(CONSOLE, NOME)?;
        let mut ini = Iniciante::novo(VAGA, 2_000_802, 1);
        let (pk, w) = ini.pedir_a_chave()?.map_err(|_| "o anuncio foi recusado")?;
        let outro_nonce = sorteado();
        ini.apertar_com(&pk, &conta::compromisso(&outro_nonce), &w)?
            .map_err(|_| "a 1a mensagem foi recusada")?;
        ini.mandar_o_nonce()?;
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::CompromissoErrado,
            Codigo::DenyNotAuthenticated,
            true,
        )?;
        // Iniciando: o `conferido` do outro, adulterado.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        parear(CONSOLE, NOME)?;
        let mut feito = false;
        let fim = conduzir(Aceitante::novo(1), |x: &mut Aceitante| {
            if let Some(k) = x.contas()
                && !feito
            {
                digitar(CONSOLE, &texto(k.k_b));
                x.mandar_adulterado(CONFERIDO);
                feito = true;
            }
            Passo::Segue
        });
        if !fim.recebeu(&desistiu(conta::Motivo::ForaDoProtocolo.texto())) {
            return Err("o conferido adulterado nao encerrou o iniciante");
        }
        acabou_com(
            Lado::Inicia,
            Desfecho::Desfeita(conta::Motivo::ForaDoProtocolo),
            "o conferido adulterado nao desfez a cerimonia do iniciante",
        )?;
        uma_desfeita(seq, Codigo::InvalidArgument, "quadro fora do protocolo")?;
        nada_gravado(antes, 0)
    })
}

// ---------------------------------------------------------------------
// S10, S11, S15 — quem pode abrir, e com que papel.
// ---------------------------------------------------------------------

/// A abertura recusada: nada aberto — nenhuma cerimônia, o console nos
/// comandos — e a recusa gravada uma vez, com o código, o recurso e o
/// motivo.
fn abertura_recusada(
    console: Console,
    linha_digitada: &str,
    recurso: &str,
    codigo: Codigo,
    motivo: &str,
) -> Resultado {
    let seq = crate::autorizacao::ultimo_registro();
    let antes = estado();
    digitar(console, linha_digitada);
    if estado() != antes || linha(console) != Linha::Comando {
        return Err("uma abertura recusada abriu ou mudou uma cerimonia");
    }
    let v = do_pareamento(seq);
    match v.as_slice() {
        [(_, e)] if e.codigo == codigo && e.recurso == recurso && e.detalhe.contains(motivo) => {
            Ok(())
        }
        outros => {
            for (_, e) in outros {
                crate::log_error!("teste", "{:?} {} {}", e.codigo, e.recurso, e.detalhe);
            }
            crate::log_error!(
                "teste",
                "{}: esperado {} `{}`",
                linha_digitada,
                codigo.nome(),
                motivo
            );
            Err("a abertura recusada nao foi gravada com o codigo e o motivo dela")
        }
    }
}

/// Sem `device.pair`, `DENY_PERMISSION`; sem `device.forget` — a relação
/// não se desfaria —, também; com o nome fora do alcance de `device.forget`
/// do papel, `DENY_RESOURCE`. Nada se abre, nem aceitando nem iniciando. E
/// `device.forget`, pelo gate, recusa do mesmo jeito.
pub(super) fn pareamento_a_pessoa_sem_permissao() -> Resultado {
    com_a_cerimonia(|| {
        let (bia_sessao, _) = entrar(CONSOLE, "bia")?;
        let aceitar_par = format!("aceitar {NOME} {PAPEL}");
        let parear_par = format!("parear {NOME} {ENDERECO} {PAPEL}");
        // O nome fora do alcance.
        abertura_recusada(
            CONSOLE,
            &format!("aceitar outro {PAPEL}"),
            "dispositivo:outro",
            Codigo::DenyResource,
            "o nome nao esta no alcance de device.forget do papel",
        )?;
        // Sem `device.pair`.
        crate::autorizacao::trocar_politica(super::politica_trocada(&[(
            "fabric.remote device.pair device.forget\n",
            "fabric.remote device.forget\n",
        )])?);
        for l in [&aceitar_par, &parear_par] {
            abertura_recusada(CONSOLE, l, "dispositivo:par", Codigo::DenyPermission, "")?;
        }
        // Sem `device.forget`: quem não desfaz não cria.
        crate::autorizacao::trocar_politica(super::politica_trocada(&[
            (
                "fabric.remote device.pair device.forget\n",
                "fabric.remote device.pair\n",
            ),
            (
                "recurso operador device.forget dispositivo:par dispositivo:par-2\n",
                "",
            ),
        ])?);
        for l in [&aceitar_par, &parear_par] {
            abertura_recusada(
                CONSOLE,
                l,
                "dispositivo:par",
                Codigo::DenyPermission,
                "o papel nao tem device.forget: a relacao nao se desfaria",
            )?;
        }
        crate::autorizacao::carregar();
        // Um papel sem as duas: o observador.
        let caio = crate::interpretador::entrar_para_teste(OUTRO_CONSOLE, "caio", "observador");
        abertura_recusada(
            OUTRO_CONSOLE,
            &aceitar_par,
            "dispositivo:par",
            Codigo::DenyPermission,
            "",
        )?;
        // `device.forget` pelo gate: a permissão e o alcance.
        let forget = |sessao, alvo: &str| {
            super::fs_pedir(
                crate::autorizacao::Chamador::Pessoa(sessao),
                "device.forget",
                &format!(r#"{{"device":"{alvo}"}}"#),
            )
        };
        if codigo_do_envelope(&forget(caio, "dispositivo:par")) != "DENY_PERMISSION" {
            return Err("device.forget sem a permissao nao foi DENY_PERMISSION");
        }
        if codigo_do_envelope(&forget(bia_sessao, "dispositivo:outro")) != "DENY_RESOURCE" {
            return Err("device.forget fora do alcance nao foi DENY_RESOURCE");
        }
        Ok(())
    })
}

/// Sem ninguém entrado no console, `aceitar` e `parear` são
/// `DENY_NOT_AUTHENTICATED`, gravados sem titular. E a chave fraca — de
/// ordem baixa — que o outro anuncie não chega ao aperto.
pub(super) fn pareamento_sem_identidade() -> Resultado {
    com_a_cerimonia(|| {
        for l in [
            format!("aceitar {NOME} {PAPEL}"),
            format!("parear {NOME} {ENDERECO} {PAPEL}"),
        ] {
            let seq = crate::autorizacao::ultimo_registro();
            digitar(CONSOLE, &l);
            if estado().is_some() {
                return Err("sem login, uma cerimonia abriu");
            }
            let recusa = super::registros_depois(seq, |e| {
                e.metodo == crate::autorizacao::PAREAMENTO
                    && e.codigo == Codigo::DenyNotAuthenticated
                    && e.titular == politica::auditoria::Titular::Anonimo
            });
            if recusa.len() != 1 {
                return Err("sem login, a recusa nao foi gravada");
            }
        }
        entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        let mut fraca = [0u8; 32];
        for primeiro in [0u8, 1] {
            fraca[0] = primeiro;
            recomecar();
            let seq = crate::autorizacao::ultimo_registro();
            parear(CONSOLE, NOME)?;
            let mut b = Aceitante::novo(4);
            b.anunciada = fraca;
            let fim = conduzir(b, |_| Passo::Segue);
            if fim.viu_chave.is_some() || fim.nonce.is_some() {
                return Err("a chave fraca chegou ao aperto");
            }
            acabou_com(
                Lado::Inicia,
                Desfecho::Desfeita(conta::Motivo::Recusada),
                "a chave fraca nao desfez a cerimonia",
            )?;
            uma_desfeita(
                seq,
                Codigo::DenyNotAuthenticated,
                "chave publica de ordem baixa",
            )?;
            nada_gravado(antes, 0)?;
        }
        Ok(())
    })
}

/// O papel da relação: o teto de um administrador não se dá; o que não
/// cabe no da Pessoa, nem o que não existe; o nome e o papel fora da regra
/// também não. Recusados antes de abrir.
pub(super) fn pareamento_o_papel() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        for (l, codigo, motivo) in [
            (
                "aceitar par administrador",
                Codigo::DenyPolicy,
                "e o teto de um administrador",
            ),
            ("aceitar par sistema", Codigo::DenyPolicy, "`sistema`"),
            ("aceitar par nao-existe", Codigo::DenyPolicy, "nao existe"),
            (
                "aceitar Par! dispositivo",
                Codigo::InvalidArgument,
                "nome de dispositivo fora da regra",
            ),
            (
                "aceitar par Papel!",
                Codigo::InvalidArgument,
                "papel fora da regra",
            ),
        ] {
            let recurso = if l.contains("Par!") {
                "dispositivo:Par!"
            } else {
                "dispositivo:par"
            };
            abertura_recusada(CONSOLE, l, recurso, codigo, motivo)?;
        }
        // O mesmo papel do operador, que cabe nele: abre.
        aceitar(CONSOLE, NOME)?;
        digitar(CONSOLE, "");
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S12, S13, S14, S21 — a lápide, a suspensão, a espécie da chave.
// ---------------------------------------------------------------------

/// A relação de teste de outra Pessoa, `caio`, com o dispositivo `n` de
/// nome `nome`: o dispositivo fica no registro — para a lápide e a
/// suspensão terem a quem se aplicar.
const RELACAO_DE_CAIO: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";

fn caio_relacionado(n: u8, nome: &str) -> Result<IdSessao, &'static str> {
    let (sessao, caio) = entrar(OUTRO_CONSOLE, "caio")?;
    super::enlace::relacionar(caio, nome, n, PAPEL, RELACAO_DE_CAIO)?;
    Ok(sessao)
}

/// Uma aceitante que recusa a chave do iniciante pelo aperto: a recusa em
/// claro, com o motivo — e a janela continua livre.
fn aperto_recusado(ini: &mut Iniciante, motivo: &str, codigo: Codigo) -> Resultado {
    let seq = crate::autorizacao::ultimo_registro();
    let (pk, w) = ini.pedir_a_chave()?.map_err(|_| "o anuncio foi recusado")?;
    match ini.apertar(&pk, &w)? {
        Err(m) if m == motivo => {}
        outro => {
            crate::log_error!("teste", "{:?} (esperado `{}`)", outro, motivo);
            return Err("o aperto nao foi recusado pelo motivo dele");
        }
    }
    no_estado(
        (Lado::Aceita, Estado::Aberta),
        "o aperto recusado ocupou a janela",
    )?;
    let gravado = super::registros_depois(seq, |e| {
        e.metodo == crate::autorizacao::APERTO_DO_PAREAMENTO
            && e.codigo == codigo
            && e.chave == Some(ini.chave())
            && e.detalhe.starts_with(motivo)
    });
    if gravado.len() != 1 {
        return Err("o aperto recusado nao foi gravado com a chave alegada");
    }
    Ok(())
}

/// Iniciando, a chave anunciada é recusada antes do aperto: o fim, com o
/// motivo, e nada gravado.
fn anuncio_recusado(
    b: Aceitante,
    motivo: conta::Motivo,
    codigo: Codigo,
    trecho: &str,
    antes: usize,
    relacoes: usize,
) -> Resultado {
    recomecar();
    let seq = crate::autorizacao::ultimo_registro();
    parear(CONSOLE, NOME)?;
    let fim = conduzir(b, |_| Passo::Segue);
    if fim.viu_chave.is_some() {
        return Err("a chave recusada no anuncio recebeu a 1a mensagem");
    }
    acabou_com(
        Lado::Inicia,
        Desfecho::Desfeita(motivo),
        "a chave recusada no anuncio nao desfez a cerimonia",
    )?;
    uma_desfeita(seq, codigo, trecho)?;
    nada_gravado(antes, relacoes)
}

/// Até o commit, aceitando: o código e a senha aqui, o `conferido` de lá;
/// o commit fica para o console.
fn ate_o_commit(console: Console, nome: &str, ini: &mut Iniciante) -> Result<Contas, &'static str> {
    aceitar(console, nome)?;
    let k = ate_os_codigos(console, ini)?;
    conferir_aqui(console, k.k_a)?;
    if ini.ouvir()?.mensagens != [CONFERIDO] {
        return Err("a confirmacao daqui nao mandou o conferido");
    }
    ini.mandar(CONFERIDO)?;
    if !crate::pareamento::deve_ao_console() {
        return Err("o conferido do outro nao pediu a gravacao ao console");
    }
    Ok(k)
}

/// A chave com lápide: recusada no anúncio — iniciando —, no aperto —
/// aceitando — e no commit, se a lápide chega entre a confirmação e a
/// gravação sem que ninguém avise a cerimônia: a conferência dentro de
/// `em_ordem` a vê.
pub(super) fn pareamento_a_lapide() -> Resultado {
    fn lapide_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let _ = crate::dispositivos::revogar(&chave_de_dispositivo(1));
    }
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        caio_relacionado(1, NOME)?;
        // No commit: a lápide entra pela porta dos fundos, no meio.
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_000_900, 1);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(lapide_no_meio));
        crate::pareamento::no_console();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        if crate::dispositivos::lapides() != [chave_de_dispositivo(1)] {
            return Err("a lapide do caso nao entrou");
        }
        desfeita_aceitando_por(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Recusada,
            Codigo::DenyPolicy,
            "a chave foi revogada: a lapide nao se desfaz",
            true,
        )?;
        // No aperto, aceitando.
        recomecar();
        aceitar(CONSOLE, NOME)?;
        aperto_recusado(
            &mut Iniciante::novo(VAGA, 2_000_901, 1),
            "a chave foi revogada: a lapide nao se desfaz",
            Codigo::DenyPolicy,
        )?;
        digitar(CONSOLE, "");
        // No anúncio, iniciando.
        anuncio_recusado(
            Aceitante::novo(1),
            conta::Motivo::ParRevogado,
            Codigo::DenyPolicy,
            "a lapide nao se desfaz",
            antes,
            0,
        )
    })
}

/// O par suspenso: recusado no aperto e no anúncio; a suspensão no meio da
/// cerimônia a desfaz — e o outro sabe —; e a que chega no ponto do commit,
/// pelo gate, também. Nada gravado; a relação de quem já tinha fica.
pub(super) fn pareamento_o_par_suspenso() -> Resultado {
    fn suspender() -> alloc::string::String {
        super::fs_pedir(
            super::sistema_aqui(),
            "device.suspend",
            r#"{"device":"dispositivo:par"}"#,
        )
    }
    fn suspender_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let _ = suspender();
    }
    fn retomar() -> alloc::string::String {
        super::fs_pedir(
            super::sistema_aqui(),
            "device.resume",
            r#"{"device":"dispositivo:par"}"#,
        )
    }
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        caio_relacionado(1, NOME)?;
        let antes = super::registros_do_journal()?.len();
        if !suspender().contains(r#""contained":true"#) {
            return Err("o sistema nao suspendeu o dispositivo");
        }
        aceitar(CONSOLE, NOME)?;
        aperto_recusado(
            &mut Iniciante::novo(VAGA, 2_001_000, 1),
            "dispositivo suspenso",
            Codigo::DenyCredential,
        )?;
        digitar(CONSOLE, "");
        anuncio_recusado(
            Aceitante::novo(1),
            conta::Motivo::ParSuspenso,
            Codigo::DenyCredential,
            "dispositivo suspenso",
            antes,
            1,
        )?;
        if !retomar().contains(r#""contained":false"#) {
            return Err("o sistema nao retomou o dispositivo");
        }
        // No meio: a cerimônia com a chave suspensa acaba.
        recomecar();
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_001, 1);
        aceitar(CONSOLE, NOME)?;
        ate_os_codigos(CONSOLE, &mut ini)?;
        suspender();
        let o = ini.ouvir()?;
        if o.mensagens != [desistiu(conta::Motivo::ParSuspenso.texto())] || !o.encerrada {
            crate::log_error!("teste", "{:?}", o);
            return Err("a suspensao no meio nao desfez a cerimonia, avisando o outro");
        }
        acabou_com(
            Lado::Aceita,
            Desfecho::Desfeita(conta::Motivo::ParSuspenso),
            "a suspensao no meio nao desfez a cerimonia",
        )?;
        uma_desfeita(seq, Codigo::DenyCredential, "o par esta suspenso")?;
        retomar();
        // No ponto do commit.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_002, 1);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(suspender_no_meio));
        crate::pareamento::no_console();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let o = ini.ouvir()?;
        if o.mensagens != [desistiu(conta::Motivo::ParSuspenso.texto())] || !o.encerrada {
            crate::log_error!("teste", "{:?}", o);
            return Err("a suspensao no commit nao desfez a cerimonia, avisando o outro");
        }
        acabou_com(
            Lado::Aceita,
            Desfecho::Desfeita(conta::Motivo::ParSuspenso),
            "a suspensao no commit nao desfez a cerimonia",
        )?;
        uma_desfeita(seq, Codigo::DenyCredential, "o par esta suspenso")?;
        retomar();
        if crate::dispositivos::relacoes().len() != 1 {
            return Err("a suspensao mexeu nas relacoes");
        }
        let r = super::registros_do_journal()?;
        if r.iter().skip(antes).any(|x| {
            crate::persistencia::entradas_de_teste(x).is_ok_and(|e| {
                e.iter().any(|c| {
                    c.starts_with(&diario::estado::tipo::DISPOSITIVO_REGISTRADO.to_le_bytes())
                })
            })
        }) {
            return Err("com o par suspenso, uma relacao foi ao journal");
        }
        Ok(())
    })
}

/// Uma chave, uma espécie: a deste Duke, a de um agente e a de um
/// administrador não são par de cerimônia — recusadas no anúncio, no
/// aperto e, se a espécie muda no meio, no commit.
pub(super) fn pareamento_uma_chave_uma_especie() -> Resultado {
    fn agente_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::identidade::registrar_agente_de_teste(
            chave_de_dispositivo(6),
            "agente-x",
            "observador",
        );
    }
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        let admin = super::ADMIN_DE_TESTE;
        crate::identidade::registrar_agente_de_teste(
            chave_de_dispositivo(5),
            "agente-y",
            "observador",
        );
        // Aceitando: a chave de um agente e a de um administrador.
        aceitar(CONSOLE, NOME)?;
        aperto_recusado(
            &mut Iniciante::novo(VAGA, 2_001_100, 5),
            "a chave e de um agente: um dispositivo nao e um agente",
            Codigo::DenyPolicy,
        )?;
        aperto_recusado(
            &mut Iniciante::com_privada(VAGA + 1, 2_001_101, admin),
            "a chave e de um administrador: um dispositivo nao e um administrador",
            Codigo::DenyPolicy,
        )?;
        digitar(CONSOLE, "");
        // Iniciando: a deste Duke, a de um agente, a de um administrador.
        let mut proprio = Aceitante::novo(4);
        proprio.anunciada = crate::identidade::publica_do_duke().ok_or("o Duke nao tem chave")?;
        for (b, trecho) in [
            (proprio, "ninguem e par de si mesmo"),
            (Aceitante::novo(5), "a chave e de um agente"),
            (
                Aceitante::com_privada(admin),
                "a chave e de um administrador",
            ),
        ] {
            anuncio_recusado(
                b,
                conta::Motivo::Recusada,
                Codigo::DenyPolicy,
                trecho,
                antes,
                0,
            )?;
        }
        // No commit: a chave do par vira a de um agente no meio.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_102, 6);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(agente_no_meio));
        crate::pareamento::no_console();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        desfeita_aceitando_por(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Recusada,
            Codigo::DenyPolicy,
            "a chave e de um agente",
            true,
        )
    })
}

// ---------------------------------------------------------------------
// S16, S17 — a sessão da cerimônia não é autoridade; parear não autoriza.
// ---------------------------------------------------------------------

/// Um quadro do enlace na sessão de uma cerimônia a encerra: a sessão é de
/// cerimônia até o fim, e nunca vira enlace. E, com o aperto da cerimônia
/// feito e nada gravado, a mesma chave pelo enlace é `fora do registro`.
pub(super) fn pareamento_a_sessao_da_cerimonia_nao_e_enlace() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_200, 1);
        aceitar(CONSOLE, NOME)?;
        ate_os_codigos(CONSOLE, &mut ini)?;
        // A mesma chave, pelo enlace, noutra vaga: fora do registro.
        let mut enlace = super::enlace::Par::novo(VAGA + 1, 2_001_201);
        match enlace.apertar(&privada_de_dispositivo(1), [9; 8])? {
            Err(m) if m == "chave fora do registro de dispositivos" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("a chave da cerimonia entrou pelo enlace antes do commit");
            }
        }
        // Um quadro do enlace na sessão da cerimônia.
        let q = quadro::montar(Tipo::InicioEnlace, &[0u8; 96]).map_err(|_| "quadro")?;
        ini.empurrar(&q);
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::ForaDoProtocolo,
            Codigo::InvalidArgument,
            true,
        )?;
        if !ini.lado.encerrada() {
            return Err("a sessao da cerimonia nao encerrou com o quadro do enlace");
        }
        Ok(())
    })
}

/// Depois de pareado, o par pede pelo enlace só o conjunto fechado, e
/// decidido pela interseção — a Pessoa, a relação e o teto `remoto`, a
/// cada vez: a relação com o papel `observador` não manda nada; `device.pair`
/// e `device.forget` não chegam de outro dispositivo; e o `R` de uma relação
/// não fala por outra.
pub(super) fn pareamento_parear_nao_autoriza() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        let mut ini = Iniciante::novo(VAGA, 2_001_300, 1);
        let k = parear_aceitando(CONSOLE, NOME, &mut ini)?;
        // Um segundo, com o papel `observador`.
        recomecar();
        digitar(CONSOLE, &format!("aceitar {NOME_2} observador"));
        let mut ini2 = Iniciante::novo(VAGA, 2_001_301, 2);
        let k2 = ate_os_codigos(CONSOLE, &mut ini2)?;
        conferir_aqui(CONSOLE, k2.k_a)?;
        ini2.ouvir()?;
        ini2.mandar(CONFERIDO)?;
        crate::pareamento::no_console();
        ini2.ouvir()?;
        ini2.mandar(&gravado(&k2.r))?;
        acabou_com(
            Lado::Aceita,
            Desfecho::Concluida,
            "o segundo pareamento nao concluiu",
        )?;
        let r1 = politica::dispositivos::id_texto(&k.r);
        let r2 = politica::dispositivos::id_texto(&k2.r);
        let intent = format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA);
        let mut par = super::enlace::Par::novo(VAGA + 1, 2_001_302);
        par.apertar(&privada_de_dispositivo(1), [3; 8])?
            .map_err(|_| "o par pareado nao entrou pelo enlace")?;
        let pedir = |par: &mut super::enlace::Par, r: &str, metodo: &str, params: &str| {
            par.pedir(r, metodo, params)
                .and_then(|x| x.map_err(|_| "o enlace caiu num pedido"))
                .map(|e| codigo_do_envelope(&e))
        };
        if pedir(&mut par, &r1, "fabric.discover", &intent)? != "ALLOW" {
            return Err("o par pareado nao pediu o que a relacao deixa");
        }
        for (metodo, params) in [
            ("device.forget", r#"{"device":"dispositivo:par"}"#),
            ("device.registry", "{}"),
            ("system.info", "{}"),
        ] {
            if pedir(&mut par, &r1, metodo, params)? != "DENY_PERMISSION" {
                return Err("o par pareado pediu fora do conjunto fechado");
            }
        }
        if pedir(&mut par, &r1, "device.pair", "{}")? == "ALLOW" {
            return Err("device.pair chegou de outro dispositivo");
        }
        // O `R` do outro dispositivo, por este: não autentica.
        if pedir(&mut par, &r2, "fabric.discover", &intent)? != "DENY_NOT_AUTHENTICATED" {
            return Err("o par falou pela relacao de outro dispositivo");
        }
        // A relação `observador`: a interseção não deixa.
        let mut par2 = super::enlace::Par::novo(VAGA + 2, 2_001_303);
        par2.apertar(&privada_de_dispositivo(2), [4; 8])?
            .map_err(|_| "o segundo par nao entrou pelo enlace")?;
        if pedir(&mut par2, &r2, "fabric.discover", &intent)? != "DENY_PERMISSION" {
            return Err("a relacao observador mandou: a intersecao nao valeu");
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S18 — só pelo teclado.
// ---------------------------------------------------------------------

/// `aceitar` e `parear` são da Pessoa no console: um agente que os
/// confirme pela árvore semântica é recusado, e nada abre. Aberta a
/// cerimônia, a linha do código e a da senha não se editam nem se
/// confirmam pela árvore. E não há comando do registro que pareie.
pub(super) fn pareamento_so_pelo_teclado() -> Resultado {
    use crate::ui::Origem;
    com_a_cerimonia(|| {
        crate::interpretador::abrir_console(Console::Fisico);
        let r = (|| -> Resultado {
            crate::interpretador::entrar_para_teste(Console::Fisico, "bia", "operador");
            for l in [
                format!("aceitar {NOME} {PAPEL}"),
                format!("parear {NOME} {ENDERECO} {PAPEL}"),
            ] {
                crate::interpretador::definir(&l)
                    .map_err(|_| "a arvore nao editou a linha de comando")?;
                crate::interpretador::confirmar(Origem::Agente(0));
                if estado().is_some() {
                    return Err("um agente abriu uma cerimonia pela arvore");
                }
            }
            for nome in ["device.pair", "aceitar", "parear"] {
                if crate::agent::registry::encontrar(nome).is_some() {
                    return Err("ha um comando do registro que pareia");
                }
            }
            // A Pessoa abre, pelo teclado.
            let mut ini = Iniciante::novo(VAGA, 2_001_400, 1);
            aceitar(Console::Fisico, NOME)?;
            let k = ate_os_codigos(Console::Fisico, &mut ini)?;
            if crate::interpretador::definir(&texto(k.k_a)).is_ok()
                || crate::interpretador::pode_confirmar(Origem::Agente(0)).is_ok()
            {
                return Err("a arvore editou ou confirmaria a linha do codigo");
            }
            super::digitar_no_console(Console::Fisico, &texto(k.k_a));
            crate::interpretador::confirmar(Origem::Agente(0));
            no_estado(
                (Lado::Aceita, Estado::Apertada),
                "um agente confirmou a linha do codigo",
            )?;
            super::digitar_no_console(Console::Fisico, "\n");
            no_estado(
                (Lado::Aceita, Estado::CodigoCerto),
                "o Enter do teclado nao levou o codigo",
            )?;
            if crate::interpretador::definir(SENHA).is_ok() {
                return Err("a arvore editou a linha da senha");
            }
            super::digitar_no_console(Console::Fisico, SENHA);
            crate::interpretador::confirmar(Origem::Agente(0));
            no_estado(
                (Lado::Aceita, Estado::CodigoCerto),
                "um agente confirmou a linha da senha",
            )?;
            super::digitar_no_console(Console::Fisico, "\n");
            no_estado(
                (Lado::Aceita, Estado::ConferidaAqui),
                "o Enter do teclado nao levou a senha",
            )?;
            digitar(Console::Fisico, "");
            Ok(())
        })();
        crate::interpretador::desativar_para_teste();
        r
    })
}

// ---------------------------------------------------------------------
// S19, S20, S22, S23, S24 — a concorrência.
// ---------------------------------------------------------------------

/// pair × pair: uma cerimônia por Duke — a segunda Pessoa recebe
/// `CONFLICT`, aceitando ou iniciando, e a primeira não muda. E dois
/// iniciantes na mesma janela: os dois veem o anúncio, a 1ª mensagem do
/// primeiro a ocupa, e a do segundo é `ocupado` — gravada, com a chave
/// dele.
pub(super) fn pareamento_pair_x_pair() -> Resultado {
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        entrar(OUTRO_CONSOLE, "caio")?;
        aceitar(CONSOLE, NOME)?;
        for l in [
            format!("aceitar {NOME_2} {PAPEL}"),
            format!("parear {NOME_2} {ENDERECO} {PAPEL}"),
        ] {
            abertura_recusada(
                OUTRO_CONSOLE,
                &l,
                "dispositivo:par-2",
                Codigo::Conflict,
                "outra cerimonia de pareamento em curso neste Duke",
            )?;
            no_estado(
                (Lado::Aceita, Estado::Aberta),
                "a segunda cerimonia mexeu na primeira",
            )?;
        }
        let mut a = Iniciante::novo(VAGA, 2_001_500, 1);
        let mut b = Iniciante::novo(VAGA + 1, 2_001_501, 2);
        let (pk, wa) = a.pedir_a_chave()?.map_err(|_| "o anuncio foi recusado")?;
        let (_, wb) = b
            .pedir_a_chave()?
            .map_err(|_| "o segundo anuncio foi recusado")?;
        if wa != wb {
            return Err("a mesma janela anunciou dois desafios");
        }
        a.apertar(&pk, &wa)?
            .map_err(|_| "a 1a mensagem do primeiro foi recusada")?;
        let seq = crate::autorizacao::ultimo_registro();
        match b.apertar(&pk, &wb)? {
            Err(m) if m == "ocupado: a janela ja respondeu a outro dispositivo" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("o segundo iniciante na mesma janela nao recebeu `ocupado`");
            }
        }
        let ocupado = super::registros_depois(seq, |e| {
            e.metodo == crate::autorizacao::APERTO_DO_PAREAMENTO
                && e.codigo == Codigo::Conflict
                && e.chave == Some(b.chave())
        });
        if ocupado.len() != 1 {
            return Err("o `ocupado` nao foi gravado com a chave do segundo");
        }
        // O primeiro segue.
        a.mandar_o_nonce()?;
        if a.ouvir()?.identificada != Some(a.chave()) {
            return Err("o primeiro iniciante nao seguiu depois do segundo");
        }
        no_estado(
            (Lado::Aceita, Estado::Apertada),
            "o primeiro iniciante nao chegou aos codigos",
        )?;
        digitar(CONSOLE, "");
        Ok(())
    })
}

/// A sessão e a pessoa dos ganchos do commit.
static NO_MEIO: crate::trava::Mutex<Option<(IdSessao, IdPessoa)>> = crate::trava::Mutex::new(None);

fn quem_no_meio() -> Option<(IdSessao, IdPessoa)> {
    crate::arch::sem_interrupcoes(|| *NO_MEIO.lock())
}

/// confirm × revoke, pair × revoke, pair × política nova: com as duas
/// confirmações feitas, o que muda no ponto do commit — dentro de
/// `em_ordem`, antes da reconfirmação — é visto por ela: a chave do par
/// revogada, a Pessoa revogada, a sessão encerrada, `device.pair` tirado,
/// o nome tirado do alcance, o papel da relação que não cabe mais. Nada
/// gravado, o fim com o motivo, e o outro sabe.
pub(super) fn pareamento_a_reconfirmacao_no_commit() -> Resultado {
    fn revogar_a_chave() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let _ = crate::dispositivos::revogar(&chave_de_dispositivo(1));
        crate::enlace::dispositivo_revogado(&chave_de_dispositivo(1));
    }
    fn revogar_a_pessoa() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        if let Some((_, p)) = quem_no_meio() {
            let _ = crate::pessoas::revogar_pessoa(p);
        }
    }
    fn encerrar_a_sessao() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        if let Some((s, _)) = quem_no_meio() {
            crate::pessoas::sair(s);
        }
    }
    fn trocar(de: &str, para: &str) {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        if let Ok(p) = super::politica_trocada(&[(de, para)]) {
            crate::autorizacao::trocar_politica(p);
        }
    }
    fn tirar_a_permissao() {
        trocar(
            "fabric.remote device.pair device.forget\n",
            "fabric.remote device.forget\n",
        );
    }
    fn tirar_o_nome() {
        trocar(
            "recurso operador device.forget dispositivo:par dispositivo:par-2\n",
            "recurso operador device.forget dispositivo:par-2\n",
        );
    }
    fn tirar_o_papel() {
        trocar(
            "papel dispositivo fabric.send\n",
            "papel dispositivo fabric.send system.power\n",
        );
    }
    com_a_cerimonia(|| {
        caio_relacionado(1, NOME)?;
        let ganchos: [Gancho; 6] = [
            (
                revogar_a_chave,
                1,
                conta::Motivo::ParRevogado,
                Codigo::DenyNotAuthenticated,
                "o par foi revogado",
            ),
            (
                revogar_a_pessoa,
                2,
                conta::Motivo::Recusada,
                Codigo::DenyNotAuthenticated,
                "",
            ),
            (
                encerrar_a_sessao,
                3,
                conta::Motivo::Recusada,
                Codigo::DenyNotAuthenticated,
                "",
            ),
            (
                tirar_a_permissao,
                4,
                conta::Motivo::Recusada,
                Codigo::DenyPermission,
                "",
            ),
            (
                tirar_o_nome,
                5,
                conta::Motivo::Recusada,
                Codigo::DenyResource,
                "o nome nao esta no alcance de device.forget do papel",
            ),
            (
                tirar_o_papel,
                6,
                conta::Motivo::Recusada,
                Codigo::DenyPolicy,
                "system.power",
            ),
        ];
        for (i, (gancho, n, motivo, codigo, trecho)) in ganchos.into_iter().enumerate() {
            recomecar();
            // Uma Pessoa nova a cada volta — a revogada não volta —, e a
            // janela de tentativas do console vazia: cada volta confere uma
            // senha.
            crate::pessoas::esquecer_registradas();
            crate::interpretador::abrir_console(CONSOLE);
            let quem = entrar(CONSOLE, &format!("bia{i}"))?;
            crate::arch::sem_interrupcoes(|| *NO_MEIO.lock() = Some(quem));
            let antes = super::registros_do_journal()?.len();
            let seq = crate::autorizacao::ultimo_registro();
            let mut ini = Iniciante::novo(VAGA, 2_001_600 + i as u64, n);
            ate_o_commit(CONSOLE, NOME, &mut ini)?;
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(gancho));
            crate::pareamento::no_console();
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            crate::autorizacao::carregar();
            let r = desfeita_aceitando_por(&mut ini, seq, antes, motivo, codigo, trecho, true);
            if r.is_err() {
                crate::log_error!("teste", "o gancho {} do commit", i);
            }
            r?;
            if !super::registros_depois(seq, |e| e.detalhe.starts_with("pareado: ")).is_empty() {
                return Err("a reconfirmacao recusou depois de a gravacao ser decidida");
            }
        }
        crate::arch::sem_interrupcoes(|| *NO_MEIO.lock() = None);
        // A sessão que acaba no meio da cerimônia, fora do commit: o
        // coletor a desfaz.
        recomecar();
        crate::pessoas::esquecer_registradas();
        crate::interpretador::abrir_console(CONSOLE);
        let (sessao, _) = entrar(CONSOLE, "bia-fim")?;
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_699, 2);
        aceitar(CONSOLE, NOME)?;
        ate_os_codigos(CONSOLE, &mut ini)?;
        crate::pessoas::sair(sessao);
        crate::pareamento::vencer();
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::FimDaSessao,
            Codigo::DenyNotAuthenticated,
            true,
        )
    })
}

/// pair × poweroff: com o desligamento pedido, o coletor desfaz a
/// cerimônia viva — e o outro sabe —, nada novo abre, a 1ª mensagem que
/// chegar é recusada; e o pedido que chega no ponto do commit é visto
/// nele. Nada gravado.
pub(super) fn pareamento_o_desligamento() -> Resultado {
    fn reiniciar() -> alloc::string::String {
        super::fs_pedir(super::sistema_aqui(), "system.reboot", "{}")
    }
    fn reiniciar_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let _ = reiniciar();
    }
    fn pedido() -> Resultado {
        let _ = crate::energia::executada_de_teste();
        if super::fs_texto(&reiniciar(), "state").as_deref() != Some("rebooting") {
            return Err("o reinicio nao foi pedido");
        }
        Ok(())
    }
    com_a_cerimonia(|| {
        entrar(CONSOLE, "bia")?;
        entrar(OUTRO_CONSOLE, "caio")?;
        let antes = super::registros_do_journal()?.len();
        // No meio: o coletor a desfaz, e nada novo abre.
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_700, 1);
        aceitar(CONSOLE, NOME)?;
        ate_os_codigos(CONSOLE, &mut ini)?;
        pedido()?;
        crate::pareamento::vencer();
        let r = desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Desligamento,
            Codigo::Conflict,
            true,
        )
        .and_then(|()| {
            abertura_recusada(
                OUTRO_CONSOLE,
                &format!("aceitar {NOME_2} {PAPEL}"),
                "dispositivo:par-2",
                Codigo::Conflict,
                "a maquina esta desligando",
            )
        });
        if super::energia_entregue() != Some(crate::energia::Acao::Reiniciar) {
            return Err("o reinicio nao chegou ao fim");
        }
        r?;
        // A janela aberta antes do pedido: a 1ª mensagem depois dele.
        recomecar();
        aceitar(CONSOLE, NOME)?;
        pedido()?;
        let r = aperto_recusado(
            &mut Iniciante::novo(VAGA, 2_001_701, 1),
            "a maquina esta desligando",
            Codigo::Conflict,
        );
        crate::pareamento::vencer();
        if super::energia_entregue() != Some(crate::energia::Acao::Reiniciar) {
            return Err("o reinicio nao chegou ao fim");
        }
        r?;
        // No ponto do commit.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_702, 1);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        let _ = crate::energia::executada_de_teste();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(reiniciar_no_meio));
        crate::pareamento::no_console();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let entregue = super::energia_entregue();
        desfeita_aceitando_por(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Recusada,
            Codigo::Conflict,
            "a maquina esta desligando",
            true,
        )?;
        if entregue != Some(crate::energia::Acao::Reiniciar) {
            return Err("o reinicio pedido no commit nao chegou ao fim");
        }
        Ok(())
    })
}

/// confirm × expiry: o prazo vale o relógio do instante, conferido na
/// entrada e de novo no commit, dentro de `em_ordem`. Por pouco antes, a
/// relação se grava; depois, a entrada é recusada; o prazo que vence entre
/// a confirmação e a gravação é visto no commit; e o coletor que vence a
/// cerimônia antes de o console gravar deixa um desfecho só.
pub(super) fn pareamento_o_prazo_no_commit() -> Resultado {
    /// A folga do "por pouco": a senha do Argon2id, na suíte, cabe nela.
    const FOLGA_MS: u64 = 30_000;
    fn vencer_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::pareamento::adiantar_de_teste(conta::PRAZO_MS);
    }
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        // Por pouco antes: grava.
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_800, 1);
        aceitar(CONSOLE, NOME)?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        crate::pareamento::adiantar_de_teste(conta::PRAZO_MS - FOLGA_MS);
        conferir_aqui(CONSOLE, k.k_a)?;
        ini.ouvir()?;
        ini.mandar(CONFERIDO)?;
        crate::pareamento::no_console();
        decisao_da_gravacao(seq, NOME, &ini.chave(), &k.r, CONSOLE)?;
        gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        if !do_pareamento(seq)
            .iter()
            .all(|(_, e)| !e.detalhe.starts_with("desfeita: "))
        {
            return Err("a gravacao por pouco antes do prazo tambem desfez");
        }
        crate::dispositivos::esquecer_de_teste();
        // A entrada depois do prazo: recusada.
        recomecar();
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_801, 1);
        aceitar(CONSOLE, NOME)?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        digitar(CONSOLE, &texto(k.k_a));
        crate::pareamento::adiantar_de_teste(conta::PRAZO_MS);
        digitar(CONSOLE, SENHA);
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Prazo,
            Codigo::Error,
            true,
        )?;
        // O prazo vence no ponto do commit.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_802, 1);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(vencer_no_meio));
        crate::pareamento::no_console();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        desfeita_aceitando_por(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Prazo,
            Codigo::Error,
            "a cerimonia acabou ou venceu antes da gravacao",
            true,
        )?;
        // O coletor vence antes de o console gravar: um desfecho só.
        recomecar();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_001_803, 1);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::pareamento::adiantar_de_teste(conta::PRAZO_MS);
        crate::pareamento::vencer();
        crate::pareamento::no_console();
        desfeita_aceitando(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Prazo,
            Codigo::Error,
            true,
        )?;
        if crate::pareamento::deve_ao_console() {
            return Err("o console ficou devendo a gravacao de uma cerimonia vencida");
        }
        Ok(())
    })
}

/// Duas Pessoas, o mesmo dispositivo: em sequência, duas relações — cada
/// uma da sua Pessoa, cada uma com o seu `R` —; ao mesmo tempo, a segunda
/// espera a vez (`CONFLICT`). A mesma Pessoa não tem duas relações com o
/// mesmo dispositivo, e um dispositivo tem um nome só.
pub(super) fn pareamento_duas_pessoas_o_mesmo_dispositivo() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        let (_, caio) = entrar(OUTRO_CONSOLE, "caio")?;
        let mut a = Iniciante::novo(VAGA, 2_001_900, 1);
        let ka = parear_aceitando(CONSOLE, NOME, &mut a)?;
        recomecar();
        let mut b = Iniciante::novo(VAGA, 2_001_901, 1);
        let kb = parear_aceitando(OUTRO_CONSOLE, NOME, &mut b)?;
        if ka.r == kb.r {
            return Err("duas cerimonias deram a mesma relacao");
        }
        gravada_como(NOME, bia, &a.chave(), &ka.r, None)?;
        gravada_como(NOME, caio, &b.chave(), &kb.r, None)?;
        let d = crate::dispositivos::dispositivo(&a.chave()).ok_or("o dispositivo saiu")?;
        if d.relacoes.len() != 2 {
            return Err("o dispositivo nao ficou com as duas relacoes");
        }
        // Ao mesmo tempo: a segunda espera a vez.
        recomecar();
        aceitar(CONSOLE, NOME_2)?;
        abertura_recusada(
            OUTRO_CONSOLE,
            &format!("aceitar {NOME_2} {PAPEL}"),
            "dispositivo:par-2",
            Codigo::Conflict,
            "outra cerimonia de pareamento em curso neste Duke",
        )?;
        digitar(CONSOLE, "");
        // A mesma Pessoa, o mesmo nome: recusada antes de abrir.
        recomecar();
        abertura_recusada(
            CONSOLE,
            &format!("aceitar {NOME} {PAPEL}"),
            "dispositivo:par",
            Codigo::InvalidArgument,
            "a pessoa ja tem uma relacao com este nome",
        )?;
        // A mesma Pessoa, o mesmo dispositivo por outro nome: no aperto.
        aceitar(CONSOLE, NOME_2)?;
        aperto_recusado(
            &mut Iniciante::novo(VAGA, 2_001_902, 1),
            "a pessoa ja tem uma relacao com este dispositivo",
            Codigo::InvalidArgument,
        )?;
        digitar(CONSOLE, "");
        // Outra Pessoa, outro nome para o mesmo dispositivo: no aperto.
        recomecar();
        crate::interpretador::abrir_console(CONSOLE);
        entrar(CONSOLE, "dani")?;
        aceitar(CONSOLE, NOME_2)?;
        aperto_recusado(
            &mut Iniciante::novo(VAGA, 2_001_903, 1),
            "o dispositivo ja esta no registro com outro nome: use o que ele ja tem",
            Codigo::InvalidArgument,
        )?;
        digitar(CONSOLE, "");
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S25, S26, S27 — device.forget.
// ---------------------------------------------------------------------

/// A relação de teste de `bia`, pelo administrador.
const RELACAO_DE_BIA: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

/// `device.forget dispositivo:<nome>`, como a Pessoa da sessão.
fn esquecer(sessao: IdSessao, nome: &str) -> String {
    super::fs_pedir(
        crate::autorizacao::Chamador::Pessoa(sessao),
        "device.forget",
        &format!(r#"{{"device":"dispositivo:{nome}"}}"#),
    )
}

/// Um campo verdadeiro-ou-falso do resultado de um envelope.
fn fs_bool(envelope: &str, campo: &str) -> Option<bool> {
    Json(envelope.as_bytes())
        .member("result")?
        .member(campo)?
        .as_bool()
}

/// O registro do journal que desfez a relação `r` do dispositivo `chave`:
/// um só, com o marcador de `device.forget`, a desfeita pela chave e pelo
/// identificador — sem lápide — e a decisão `decisao` dentro.
fn desfeita_no_journal(
    antes: usize,
    chave: &[u8; 32],
    r: &[u8; 16],
    nome: &str,
    decisao: u64,
) -> Result<diario::Registro, &'static str> {
    use diario::estado::tipo;
    let esperada = crate::persistencia::entrada_de_teste(tipo::RELACAO_DESFEITA, &[chave, r]);
    let lapide = crate::persistencia::entrada_de_teste(tipo::DISPOSITIVO_REVOGADO, &[chave]);
    let recurso = format!("dispositivo:{nome}");
    let marcador = crate::persistencia::entrada_de_teste(
        tipo::OPERACAO,
        &[
            crate::autorizacao::ESQUECIMENTO.as_bytes(),
            recurso.as_bytes(),
        ],
    );
    let mut com_ela = Vec::new();
    for x in super::registros_do_journal()?.iter().skip(antes) {
        let entradas = crate::persistencia::entradas_de_teste(x)?;
        if entradas.contains(&lapide.as_slice()) {
            return Err("a desfeita foi ao journal como lapide");
        }
        if entradas.contains(&esperada.as_slice()) {
            if !entradas.contains(&marcador.as_slice()) {
                return Err("o registro da desfeita nao traz o marcador de device.forget");
            }
            com_ela.push(x.clone());
        }
    }
    let [x] = com_ela.as_slice() else {
        return Err("a desfeita nao foi exatamente um registro do journal");
    };
    if !super::auditoria_do_registro(x)?.iter().any(|(seq, e)| {
        *seq == decisao && e.metodo == crate::autorizacao::ESQUECIMENTO && e.codigo == Codigo::Allow
    }) {
        return Err("a decisao da desfeita nao foi no registro dela");
    }
    Ok(x.clone())
}

/// A Pessoa esquece a relação dela com um dispositivo que tem outra, de
/// outra Pessoa: só a dela sai — gravada antes da resposta, como o 44 com
/// a decisão, sem lápide —; a entrega viva que chegou por ela é anulada; o
/// pedido dela ao dispositivo, que esperava, falha; o enlace do dispositivo
/// fica, pela outra relação, que continua pedindo — e a desfeita não fala
/// mais. A reposição do journal a tira de novo. E a última relação que
/// sai leva o dispositivo, e os enlaces dele caem.
pub(super) fn pareamento_esquecer_a_propria_relacao() -> Resultado {
    use crate::autorizacao::{Autoridade, Chamador};
    com_a_cerimonia(|| {
        let (bia_sessao, bia) = entrar(CONSOLE, "bia")?;
        let caio_sessao = caio_relacionado(1, NOME)?;
        super::enlace::relacionar(bia, NOME, 1, PAPEL, RELACAO_DE_BIA)?;
        let de_bia = politica::dispositivos::ler_id(RELACAO_DE_BIA).ok_or("id")?;
        let endpoint =
            super::enlace::endpoint_que_nao_le(Autoridade::Pessoa { sessao: bia_sessao })?;
        let r = (|| -> Resultado {
            let intent = format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA);
            let mut par = super::enlace::Par::novo(VAGA, 2_002_000);
            par.apertar(&privada_de_dispositivo(1), [5; 8])?
                .map_err(|_| "o dispositivo relacionado nao entrou pelo enlace")?;
            let mandada = par
                .pedir(
                    RELACAO_DE_BIA,
                    "fabric.send",
                    &format!(
                        r#"{{"endpoint":"{endpoint}","intent":"{}","body":"viva","nonce":1}}"#,
                        super::INTENCAO_DA_MALHA
                    ),
                )?
                .map_err(|_| "o enlace caiu na entrega")?;
            let id =
                super::fs_texto(&mandada, "id").ok_or("a entrega pela relacao nao foi aceita")?;
            if crate::malha::contagem().1 != 1 {
                return Err("a entrega pela relacao nao ficou viva");
            }
            // O pedido dela ao dispositivo, esperando.
            let linha_rpc = super::pedido_rpc(
                "fabric.discover",
                &format!(
                    r#"{{"device":"dispositivo:par","intent":"{}"}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            );
            let quem = Chamador::Pessoa(bia_sessao);
            let espera = crate::nativo::responder_suspensivel_de_teste(quem, &linha_rpc)
                .err()
                .ok_or("o pedido ao dispositivo nao suspendeu")?;
            let antes = super::registros_do_journal()?.len();
            let seq = crate::autorizacao::ultimo_registro();
            let r = esquecer(bia_sessao, NOME);
            if fs_bool(&r, "forgotten") != Some(true)
                || super::fs_texto(&r, "relation").as_deref() != Some(RELACAO_DE_BIA)
                || fs_bool(&r, "device_left") != Some(false)
                || super::fs_numero(&r, "annulled") != Some(1)
            {
                crate::log_error!("teste", "{}", r);
                return Err("device.forget nao desfez so a relacao dela, anulando a entrega");
            }
            let decisao = super::fs_numero(&r, "decision").ok_or("device.forget sem a decisao")?;
            desfeita_no_journal(antes, &chave_de_dispositivo(1), &de_bia, NOME, decisao)?;
            if crate::dispositivos::da_pessoa(NOME, &bia.0).is_some()
                || !crate::dispositivos::lapides().is_empty()
            {
                return Err("a relacao esquecida ficou, ou virou lapide");
            }
            if crate::malha::contagem().1 != 0
                || !super::gravado_na_malha(
                    seq,
                    "fabric.void",
                    &format!("entrega:{id}"),
                    Codigo::Allow,
                    "relacao desfeita",
                )
            {
                return Err("a entrega pela relacao esquecida nao foi anulada e gravada");
            }
            if espera.conferir(None) != Some(crate::rede::espera::Desfecho::Chegou) {
                return Err("o pedido que esperava pela relacao esquecida nao acordou");
            }
            drop(espera);
            let de_novo = crate::nativo::responder_de_teste(quem, &linha_rpc);
            if codigo_do_envelope(&de_novo) != "DENY_RESOURCE" {
                crate::log_error!("teste", "{}", de_novo);
                return Err("o pedido pela relacao esquecida, executado de novo, nao foi recusado");
            }
            // O enlace fica, pela relação de caio — e a desfeita não fala.
            if !crate::enlace::sessoes()
                .iter()
                .any(|(_, k, _)| *k == chave_de_dispositivo(1))
            {
                return Err("esquecer uma relacao derrubou o enlace da outra");
            }
            let pedir = |par: &mut super::enlace::Par, r: &str| {
                par.pedir(r, "fabric.discover", &intent)
                    .and_then(|x| x.map_err(|_| "o enlace caiu"))
                    .map(|e| codigo_do_envelope(&e))
            };
            if pedir(&mut par, RELACAO_DE_CAIO)? != "ALLOW" {
                return Err("a outra relacao do dispositivo parou de pedir");
            }
            if pedir(&mut par, RELACAO_DE_BIA)? != "DENY_NOT_AUTHENTICATED" {
                return Err("a relacao esquecida ainda pediu");
            }
            // A reposição: a relação de volta, como numa imagem que a
            // tivesse, e o registro da desfeita a tira de novo.
            let linha = politica::dispositivos::linha(
                &chave_de_dispositivo(1),
                NOME,
                &crate::dispositivos::Relacao {
                    id: de_bia,
                    pessoa: bia.0,
                    papel: String::from(PAPEL),
                    endereco: Some(String::from(ENDERECO)),
                },
            );
            crate::dispositivos::restaurar_linha(&linha)?;
            let r44 = desfeita_no_journal(antes, &chave_de_dispositivo(1), &de_bia, NOME, decisao)?;
            crate::persistencia::em_ordem(|| crate::persistencia::reaplicar_de_teste(&r44))?;
            if crate::dispositivos::da_pessoa(NOME, &bia.0).is_some()
                || crate::dispositivos::relacoes().len() != 1
                || !crate::dispositivos::lapides().is_empty()
            {
                return Err("a reposicao do 44 nao tirou so a relacao esquecida");
            }
            // A última: o dispositivo sai, e o enlace cai.
            let r = esquecer(caio_sessao, NOME);
            if fs_bool(&r, "device_left") != Some(true) {
                crate::log_error!("teste", "{}", r);
                return Err("a ultima relacao esquecida nao levou o dispositivo");
            }
            let depois = par.pedir(RELACAO_DE_CAIO, "fabric.discover", &intent)?;
            if depois.is_ok() || !par.lado.encerrada() {
                return Err("o enlace do dispositivo sem relacao ficou de pe");
            }
            if crate::dispositivos::ha_relacao() || !crate::dispositivos::lapides().is_empty() {
                return Err("sem relacao, a porta ficou, ou a chave ganhou lapide");
            }
            Ok(())
        })();
        super::encerrar_na_malha(super::CANAL_DO_IMPOSTOR, super::SAIDA_DO_IMPOSTOR)?;
        r
    })
}

/// A relação de outra Pessoa responde o mesmo que a que não existe:
/// `DENY_RESOURCE`, o mesmo motivo — e fica.
pub(super) fn pareamento_esquecer_a_de_outra_pessoa() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        let (caio_sessao, _) = entrar(OUTRO_CONSOLE, "caio")?;
        super::enlace::relacionar(bia, NOME, 1, PAPEL, RELACAO_DE_BIA)?;
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let de_outra = esquecer(caio_sessao, NOME);
        let inexistente = esquecer(caio_sessao, NOME_2);
        for r in [&de_outra, &inexistente] {
            if codigo_do_envelope(r) != "DENY_RESOURCE" || fs_bool(r, "forgotten") != Some(false) {
                crate::log_error!("teste", "{}", r);
                return Err("esquecer a relacao de outra pessoa nao foi DENY_RESOURCE");
            }
        }
        if super::fs_texto(&de_outra, "error") != super::fs_texto(&inexistente, "error") {
            return Err("a relacao de outra pessoa respondeu diferente da que nao existe");
        }
        relacao_de(NOME, bia)?;
        if super::registros_do_journal()?.len() != antes {
            return Err("a recusa de device.forget gravou no journal");
        }
        let recusas = super::registros_depois(seq, |e| {
            e.metodo == crate::autorizacao::ESQUECIMENTO && e.codigo == Codigo::DenyResource
        });
        // Iguais a menos do número da decisão, que cada uma tem o seu.
        let sem_a_decisao = |d: &str| String::from(d.split("; decisao ").next().unwrap_or(d));
        if recusas.len() != 2
            || sem_a_decisao(&recusas[0].1.detalhe) != sem_a_decisao(&recusas[1].1.detalhe)
        {
            for (_, e) in &recusas {
                crate::log_error!("teste", "{}", e.detalhe);
            }
            return Err("as duas recusas nao foram gravadas iguais");
        }
        Ok(())
    })
}

/// Esquecer e parear de novo: sem lápide, a mesma chave pareia outra vez,
/// com outro `R`; os pedidos pelo `R` velho são recusados, e pelo novo
/// passam. A reposição do journal inteiro — a relação, a desfeita, a nova
/// — deixa só a nova.
pub(super) fn pareamento_esquecer_e_parear_de_novo() -> Resultado {
    com_a_cerimonia(|| {
        let (sessao, bia) = entrar(CONSOLE, "bia")?;
        let intent = format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA);
        let pedir = |par: &mut super::enlace::Par, r: &[u8; 16]| {
            par.pedir(
                &politica::dispositivos::id_texto(r),
                "fabric.discover",
                &intent,
            )
            .and_then(|x| x.map_err(|_| "o enlace caiu"))
            .map(|e| codigo_do_envelope(&e))
        };
        let k1 = chave_de_dispositivo(1);
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_002_100, 1);
        let velha = parear_aceitando(CONSOLE, NOME, &mut ini)?;
        let rel = gravada_como(NOME, bia, &k1, &velha.r, None)?;
        let decisao = decisao_da_gravacao(seq, NOME, &k1, &velha.r, CONSOLE)?;
        let r42 = no_journal(antes, &k1, NOME, &rel, decisao)?;
        let mut par = super::enlace::Par::novo(VAGA + 1, 2_002_101);
        par.apertar(&privada_de_dispositivo(1), [6; 8])?
            .map_err(|_| "o pareado nao entrou pelo enlace")?;
        if pedir(&mut par, &velha.r)? != "ALLOW" {
            return Err("o pareado nao pediu pela relacao");
        }
        let antes = super::registros_do_journal()?.len();
        let r = esquecer(sessao, NOME);
        let esquecida = super::fs_numero(&r, "decision").ok_or("device.forget sem a decisao")?;
        if fs_bool(&r, "device_left") != Some(true) {
            crate::log_error!("teste", "{}", r);
            return Err("a unica relacao esquecida nao levou o dispositivo");
        }
        let r44 = desfeita_no_journal(antes, &k1, &velha.r, NOME, esquecida)?;
        if par
            .pedir(
                &politica::dispositivos::id_texto(&velha.r),
                "fabric.discover",
                &intent,
            )?
            .is_ok()
        {
            return Err("o enlace da relacao esquecida ficou");
        }
        // De novo.
        recomecar();
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_002_102, 1);
        let nova = parear_aceitando(CONSOLE, NOME, &mut ini)?;
        if nova.r == velha.r {
            return Err("parear de novo deu o mesmo R");
        }
        let rel_nova = gravada_como(NOME, bia, &k1, &nova.r, None)?;
        let decisao = decisao_da_gravacao(seq, NOME, &k1, &nova.r, CONSOLE)?;
        let r42_nova = no_journal(antes, &k1, NOME, &rel_nova, decisao)?;
        let mut par = super::enlace::Par::novo(VAGA + 2, 2_002_103);
        par.apertar(&privada_de_dispositivo(1), [7; 8])?
            .map_err(|_| "o pareado de novo nao entrou pelo enlace")?;
        if pedir(&mut par, &velha.r)? != "DENY_NOT_AUTHENTICATED" {
            return Err("o R velho ainda pediu");
        }
        if pedir(&mut par, &nova.r)? != "ALLOW" {
            return Err("o R novo nao pediu");
        }
        // A reposição, na ordem do journal.
        crate::dispositivos::esquecer_de_teste();
        crate::persistencia::em_ordem(|| -> Resultado {
            for x in [&r42, &r44, &r42_nova] {
                crate::persistencia::reaplicar_de_teste(x)?;
            }
            Ok(())
        })?;
        let todas = crate::dispositivos::relacoes();
        if todas.len() != 1 || todas[0].2 != rel_nova || !crate::dispositivos::lapides().is_empty()
        {
            crate::log_error!("teste", "{:?}", todas);
            return Err("a reposicao nao deixou so a relacao nova, sem lapide");
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------
// S29 — a auditoria e a proveniência.
// ---------------------------------------------------------------------

/// Se `palheiro` tem `agulha` em algum lugar.
fn contem(palheiro: &[u8], agulha: &[u8]) -> bool {
    !agulha.is_empty() && palheiro.windows(agulha.len()).any(|w| w == agulha)
}

/// O que nunca sai da cerimônia: os códigos, nas duas formas, o nonce, o
/// resumo do aperto e o desafio da janela — em texto e em binário — e a
/// senha.
fn segredos(ini: &Iniciante, k: &Contas, w: &[u8; 16]) -> Vec<Vec<u8>> {
    let h = ini.h.unwrap_or([0; 32]);
    let mut v: Vec<Vec<u8>> = Vec::new();
    for c in [k.k_a, k.k_b] {
        v.push(texto(c).into_bytes());
        v.push(format!("{c:08}").into_bytes());
    }
    v.push(sigilo::hex_de(&ini.nonce).into_bytes());
    v.push(sigilo::hex_de(&h).into_bytes());
    v.push(sigilo::hex_de(w).into_bytes());
    v.push(ini.nonce.to_vec());
    v.push(h.to_vec());
    v.push(w.to_vec());
    v.push(SENHA.as_bytes().to_vec());
    v
}

/// Os registros da cerimônia, de cada lado: a abertura, o aperto, a
/// gravação — cada um com o titular, o recurso, o detalhe inteiro, dentro
/// do teto —; a gravação liga a Pessoa, o console, o dispositivo pela
/// impressão e a relação pelo `R`, e a decisão vai no registro do journal.
/// Nenhum leva o código, o nonce, o resumo, o desafio ou a senha: nem a
/// auditoria, nem o log, nem os relatórios, nem o journal. O
/// `device.registry` mostra a cerimônia em curso — o lado, o passo, o
/// nome, o par, o tempo — e nada disso.
pub(super) fn pareamento_a_auditoria_e_a_proveniencia() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_002_200, 1);
        aceitar(CONSOLE, NOME)?;
        let w = crate::pareamento::desafio_de_teste().ok_or("a janela nao tem desafio")?;
        let k = ate_os_codigos(CONSOLE, &mut ini)?;
        let s = segredos(&ini, &k, &w);
        let leva = |t: &[u8]| s.iter().any(|x| contem(t, x));
        // O `device.registry` no meio.
        let registro = super::chamar("device.registry", "{}")?;
        let j = Json(registro.as_bytes());
        let p = j
            .member("pairing")
            .ok_or("o device.registry nao mostra a cerimonia")?;
        let txt = |c: &str| p.member(c).and_then(|v| v.as_str()).map(String::from);
        if txt("side").as_deref() != Some("accept")
            || txt("step").as_deref() != Some("code")
            || txt("device").as_deref() != Some(NOME)
            || txt("peer") != Some(crate::identidade::impressao(&ini.chave()))
            || txt("console") != Some(CONSOLE.texto())
            || !p
                .member("remaining_ms")
                .and_then(|v| v.as_u64())
                .is_some_and(|ms| ms > 0 && ms <= conta::PRAZO_MS)
            || j.member("listening").and_then(|v| v.as_bool()) != Some(true)
        {
            crate::log_error!("teste", "{}", registro);
            return Err("o device.registry nao mostra a cerimonia em curso como ela esta");
        }
        if leva(registro.as_bytes()) {
            return Err("o device.registry mostrou um segredo da cerimonia");
        }
        conferir_aqui(CONSOLE, k.k_a)?;
        ini.ouvir()?;
        ini.mandar(CONFERIDO)?;
        crate::pareamento::no_console();
        ini.ouvir()?;
        ini.mandar(&gravado(&k.r))?;
        acabou_com(
            Lado::Aceita,
            Desfecho::Concluida,
            "a cerimonia nao concluiu",
        )?;
        // A auditoria.
        let todos = super::registros_depois(seq, |e| {
            e.metodo == crate::autorizacao::PAREAMENTO
                || e.metodo == crate::autorizacao::APERTO_DO_PAREAMENTO
        });
        if todos.len() != 3 {
            for (_, e) in &todos {
                crate::log_error!("teste", "{} {:?} {}", e.metodo, e.codigo, e.detalhe);
            }
            return Err("a cerimonia nao gravou a abertura, o aperto e a gravacao");
        }
        for (_, e) in &todos {
            if e.detalhe.len() >= politica::auditoria::MAIOR_DETALHE
                || leva(e.detalhe.as_bytes())
                || leva(e.recurso.as_bytes())
                || leva(e.agente.as_bytes())
            {
                crate::log_error!("teste", "{}", e.detalhe);
                return Err("um registro da cerimonia passou do teto ou levou um segredo");
            }
            let da_pessoa = e.metodo == crate::autorizacao::PAREAMENTO;
            let titular_certo = if da_pessoa {
                e.titular == politica::auditoria::Titular::Pessoa
                    && e.agente == bia.texto()
                    && e.recurso == "dispositivo:par"
                    && e.papel == "operador"
            } else {
                e.titular == politica::auditoria::Titular::Anonimo && e.chave == Some(ini.chave())
            };
            if !titular_certo {
                crate::log_error!(
                    "teste",
                    "{:?} {} {} {}",
                    e.titular,
                    e.agente,
                    e.recurso,
                    e.papel
                );
                return Err("um registro da cerimonia nao diz quem, ou sobre o que");
            }
        }
        let decisao = decisao_da_gravacao(seq, NOME, &ini.chave(), &k.r, CONSOLE)?;
        let rel = gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        no_journal(antes, &ini.chave(), NOME, &rel, decisao)?;
        // Os relatórios e o log.
        for (comando, params) in [
            ("log.tail", r#"{"count":64}"#),
            ("system.info", "{}"),
            ("device.registry", "{}"),
        ] {
            if leva(super::chamar(comando, params)?.as_bytes()) {
                return Err("um relatorio levou um segredo da cerimonia");
            }
        }
        // O journal, decifrado.
        for x in super::registros_do_journal()?.iter().skip(antes) {
            if leva(&x.conteudo) {
                return Err("o journal levou um segredo da cerimonia");
            }
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------
// A meia relação, a desfeita do que se gravou, o journal que recusa.
// ---------------------------------------------------------------------

/// A meia relação, sem transação distribuída: este lado grava e a conexão
/// cai antes do `gravado` do outro — a relação fica, a que a Pessoa
/// conferiu, visível no `device.registry`, e sai com `device.forget`. O
/// outro grava e este não — a conexão cai antes do `conferido` dele —: a
/// chave dele é inerte aqui, fora do registro. E o journal que recusa no
/// commit: a concessão volta, e o outro recebe o `desistiu` que desfaz o
/// dele.
pub(super) fn pareamento_a_meia_relacao() -> Resultado {
    com_a_cerimonia(|| {
        let (sessao, bia) = entrar(CONSOLE, "bia")?;
        // Este lado grava; a conexão cai.
        let mut ini = Iniciante::novo(VAGA, 2_002_300, 1);
        let k = ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::pareamento::no_console();
        if ini.ouvir()?.mensagens != [gravado(&k.r)] {
            return Err("a gravacao nao mandou o gravado");
        }
        crate::pareamento::vaga_acabou(ini.v, ini.g);
        acabou_com(
            Lado::Aceita,
            Desfecho::GravadaSemAviso,
            "a conexao que caiu depois da gravacao nao deixou a meia relacao",
        )?;
        gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        let registro = super::chamar("device.registry", "{}")?;
        if !registro.contains(&politica::dispositivos::id_texto(&k.r)) {
            return Err("a meia relacao nao aparece no device.registry");
        }
        let r = esquecer(sessao, NOME);
        if fs_bool(&r, "forgotten") != Some(true) || relacao_de(NOME, bia).is_ok() {
            crate::log_error!("teste", "{}", r);
            return Err("a meia relacao nao saiu com device.forget");
        }
        // O outro grava; a conexão cai antes do `conferido` dele chegar.
        recomecar();
        let antes = super::registros_do_journal()?.len();
        parear(CONSOLE, NOME_2)?;
        let mut digitado = false;
        conduzir(Aceitante::novo(2), |b: &mut Aceitante| {
            if let Some(k) = b.contas()
                && !digitado
            {
                digitar(CONSOLE, &texto(k.k_b));
                digitar(CONSOLE, SENHA);
                digitado = true;
            }
            if b.recebeu(CONFERIDO) {
                Passo::Cai
            } else {
                Passo::Segue
            }
        });
        acabou_com(
            Lado::Inicia,
            Desfecho::Desfeita(conta::Motivo::Conexao),
            "a conexao que caiu antes do conferido do outro nao desfez aqui",
        )?;
        nada_gravado(antes, 0)?;
        let mut par = super::enlace::Par::novo(VAGA + 1, 2_002_301);
        match par.apertar(&privada_de_dispositivo(2), [8; 8])? {
            Err(m) if m == "chave fora do registro de dispositivos" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("a meia relacao do outro lado teve efeito aqui");
            }
        }
        // O journal recusa no commit.
        recomecar();
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        let mut ini = Iniciante::novo(VAGA, 2_002_302, 3);
        ate_o_commit(CONSOLE, NOME, &mut ini)?;
        let anterior = crate::persistencia::estado();
        crate::persistencia::falhar_a_proxima_gravacao_de_teste(true);
        crate::pareamento::no_console();
        crate::persistencia::falhar_a_proxima_gravacao_de_teste(false);
        let depois = crate::persistencia::estado();
        crate::persistencia::forcar_estado_de_teste(anterior);
        if depois == crate::persistencia::Estado::Disponivel {
            return Err("a persistencia continuou disponivel depois de a gravacao falhar");
        }
        desfeita_aceitando_por(
            &mut ini,
            seq,
            antes,
            conta::Motivo::Recusada,
            Codigo::Error,
            "a gravacao falhou",
            true,
        )
    })
}

/// O outro desiste depois de este lado gravar — a reconfirmação ou o
/// journal dele recusou —: este lado desfaz o que gravou, na vez do
/// console, como `device.forget` — o 44 com a decisão, sem lápide.
pub(super) fn pareamento_o_outro_desiste_depois_de_gravar() -> Resultado {
    com_a_cerimonia(|| {
        let (_, bia) = entrar(CONSOLE, "bia")?;
        let mut ini = Iniciante::novo(VAGA, 2_002_400, 1);
        let k = ate_o_commit(CONSOLE, NOME, &mut ini)?;
        crate::pareamento::no_console();
        if ini.ouvir()?.mensagens != [gravado(&k.r)] {
            return Err("a gravacao nao mandou o gravado");
        }
        gravada_como(NOME, bia, &ini.chave(), &k.r, None)?;
        let antes = super::registros_do_journal()?.len();
        let seq = crate::autorizacao::ultimo_registro();
        ini.mandar(&desistiu(conta::Motivo::Recusada.texto()))?;
        acabou_com(
            Lado::Aceita,
            Desfecho::DesfazerAqui,
            "o desistiu depois da gravacao nao pediu a desfeita",
        )?;
        if !ini.ouvir()?.encerrada || !crate::pareamento::deve_ao_console() {
            return Err("o desistiu depois da gravacao nao fechou e pediu a desfeita ao console");
        }
        crate::pareamento::no_console();
        if relacao_de(NOME, bia).is_ok() || !crate::dispositivos::lapides().is_empty() {
            return Err("a relacao que o outro desistiu ficou, ou virou lapide");
        }
        let desfeita = super::registros_depois(seq, |e| {
            e.metodo == crate::autorizacao::ESQUECIMENTO
                && e.codigo == Codigo::Allow
                && e.detalhe.contains("o outro desistiu")
        });
        let [(decisao, _)] = desfeita.as_slice() else {
            return Err("a desfeita do que se gravou nao foi gravada uma vez");
        };
        desfeita_no_journal(antes, &ini.chave(), &k.r, NOME, *decisao)?;
        if crate::pareamento::deve_ao_console() {
            return Err("o console ficou devendo depois da desfeita");
        }
        Ok(())
    })
}
