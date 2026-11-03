//! O copiador: um arquivo do armazém mandado por um fluxo a outro
//! copiador — deste Duke ou de outro, da mesma Pessoa —, que o grava pelo
//! `fs.write` **dele**. O exemplo do SDK das mensagens sobre um fluxo.
//!
//! Um programa não tem argumentos. O copiador sabe o que fazer pelo
//! armazém:
//!
//! - **sempre recebe**: escuta um canal só dele, oferece a intenção
//!   [`INTENCAO`] com o aviso e diz `copiador: pronto <endpoint> <canal>`.
//!   Cada fluxo aceito traz duas mensagens — o nome e o conteúdo — e o fim;
//!   o copiador grava o conteúdo em [`RECEBIDOS`]`/<nome>`, pelo gate, como
//!   ele mesmo, e diz `copiador: recebi <nome> <bytes> <resumo>`;
//! - **manda**, se ao começar acha [`PEDIDO`]: a primeira linha é o caminho
//!   do arquivo; a segunda, se há, o dispositivo do outro Duke
//!   (`dispositivo:<nome>`). Lê o arquivo pelo gate, abre um fluxo ao
//!   primeiro outro copiador que a descoberta acha — lá, ou aqui —, manda o
//!   nome e o conteúdo e termina; diz `copiador: mandei <nome> <bytes>
//!   <resumo>`.
//!
//! O fluxo não dá escrita nenhuma: quem grava é o copiador que recebe, com
//! a autoridade dele, e o gate decide o `fs.write` como decidiria qualquer
//! outro. O conteúdo é entrada não confiável: o nome é conferido — só
//! letras, dígitos, ponto, hífen e sublinhado —, e o tamanho tem o teto de
//! uma gravação de uma vez, [`MAIOR_ARQUIVO`] (acima disso, o `fs.draft`, em
//! pedaços — fora deste exemplo).
//!
//! A intenção é uma das de exemplo da política padrão: um programa de
//! verdade usa a dele, que o administrador enumera na política.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "copiador",
    "fabric.offer",
    "fabric.send",
    "fabric.stream",
    "fabric.remote",
    "fs.read",
    "fs.write"
);

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::fluxo::{self, EscritaPendente, Fluxo};
use programas::laco::{Acontecimento, Laco};
use programas::nativo;
use programas::quadro::{self, Entrada, Lido};
use programas::{malha, sistema};
use protocolo::usuario::evento::{Evento, tipo};

/// A intenção que o copiador oferece e procura.
const INTENCAO: &str = "pdf.anotar";

/// O nome do manifesto: entre os que oferecem a intenção, a descoberta
/// mostra o programa de cada um, e o copiador só manda a outro copiador.
const NOME: &str = "copiador";

/// Onde o copiador mora no armazém, o pedido de envio e o que ele recebe.
const BASE: &str = "/armazem/compartilhado/copiador";
const PEDIDO: &str = "/armazem/compartilhado/copiador/enviar";
const RECEBIDOS: &str = "/armazem/compartilhado/copiador/recebidos";

/// O maior arquivo: o que uma gravação leva no anexo de uma vez.
const MAIOR_ARQUIVO: usize = protocolo::usuario::nativo::MAIOR_ANEXO;

/// O maior nome.
const MAIOR_NOME: usize = 64;

/// O código de saída no fim pedido.
const CODIGO: i64 = 53;

/// O FNV-1a de 64 bits, que a suíte e a bancada conferem.
fn resumo(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Um nome de arquivo que se pode gravar: sem barra, sem `..`, curto.
fn nome_valido(nome: &str) -> bool {
    !nome.is_empty()
        && nome.len() <= MAIOR_NOME
        && nome != "."
        && nome != ".."
        && nome
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

/// Um arquivo inteiro pelo descritor de sempre, até o teto.
fn ler_arquivo(caminho: &str) -> Result<Vec<u8>, String> {
    let d = sistema::abrir(caminho);
    if d < 0 {
        return Err(format!("abrir {d}"));
    }
    let mut tudo = Vec::new();
    let mut pedaco = [0u8; 4096];
    loop {
        let n = sistema::ler(d as u64, &mut pedaco);
        if n < 0 {
            sistema::fechar(d as u64);
            return Err(format!("ler {n}"));
        }
        if n == 0 {
            break;
        }
        tudo.extend_from_slice(&pedaco[..n as usize]);
        if tudo.len() > MAIOR_ARQUIVO {
            sistema::fechar(d as u64);
            return Err(String::from("o arquivo passa do teto"));
        }
    }
    sistema::fechar(d as u64);
    Ok(tudo)
}

/// O código e o motivo de uma resposta que não fez, ou `None` se fez.
fn falha(r: &nativo::Resposta) -> Option<String> {
    match r.resultado() {
        Ok(res) if res.member("ok").and_then(|v| v.as_bool()) == Some(true) => None,
        Ok(res) => Some(String::from(
            res.member("code")
                .and_then(|v| v.as_str())
                .unwrap_or("ERROR"),
        )),
        Err(recusa) => Some(String::from(recusa.motivo.unwrap_or("ERROR"))),
    }
}

/// Se há um diretório em `caminho`, pelo `fs.stat`.
fn eh_diretorio(caminho: &str) -> Result<bool, String> {
    let r = nativo::pedir("fs.stat", |w| w.field_str("path", caminho))
        .map_err(|e| format!("stat {e}"))?;
    if let Some(c) = falha(&r) {
        return Err(format!("stat {caminho} {c}"));
    }
    Ok(r.resultado()
        .ok()
        .and_then(|res| res.member("type"))
        .and_then(|v| v.as_str())
        == Some("dir"))
}

/// Cria `caminho` se ainda não existe. O `fs.mkdir` recusa o caminho que
/// já tem alguma coisa — com `INVALID_ARGUMENT`, o mesmo código do pai que
/// falta —, e o código não diz qual dos dois: o copiador pergunta antes, e
/// de novo depois de uma recusa, porque outro processo pode tê-lo criado
/// no meio.
fn diretorio(caminho: &str) -> Result<(), String> {
    if eh_diretorio(caminho)? {
        return Ok(());
    }
    let r = nativo::pedir("fs.mkdir", |w| w.field_str("path", caminho))
        .map_err(|e| format!("mkdir {e}"))?;
    match falha(&r) {
        None => Ok(()),
        Some(c) => {
            if eh_diretorio(caminho)? {
                Ok(())
            } else {
                Err(format!("mkdir {caminho} {c}"))
            }
        }
    }
}

/// Grava `conteudo` em `caminho`, pelo gate, como este processo — contra a
/// versão de agora, para não passar por cima de outra gravação.
fn gravar(caminho: &str, conteudo: &[u8]) -> Result<(), String> {
    diretorio(BASE)?;
    diretorio(RECEBIDOS)?;
    let estado = nativo::pedir("fs.stat", |w| w.field_str("path", caminho))
        .map_err(|e| format!("stat {e}"))?;
    let versao = estado
        .resultado()
        .ok()
        .and_then(|r| r.member("version"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let r = nativo::pedir_com_anexo(
        "fs.write",
        |w| {
            w.field_str("path", caminho)?;
            w.field_u64("expect_version", versao)
        },
        conteudo,
    )
    .map_err(|e| format!("write {e}"))?;
    match falha(&r) {
        None => Ok(()),
        Some(c) => Err(format!("write {c}")),
    }
}

/// Um fluxo que chega: o que já se leu, e para onde vai.
struct Chegando {
    f: Fluxo,
    entrada: Entrada,
    nome: Option<String>,
    conteudo: Option<Vec<u8>>,
}

impl Chegando {
    /// Lê o que já chegou. `Some` com o desfecho quando o fluxo acabou.
    fn andar(&mut self) -> Option<Result<String, String>> {
        loop {
            match self.entrada.ler(&self.f) {
                Ok(Lido::Mensagem(m)) => {
                    if self.nome.is_none() {
                        let Ok(nome) = String::from_utf8(m) else {
                            return Some(Err(String::from("o nome nao e texto")));
                        };
                        if !nome_valido(&nome) {
                            return Some(Err(String::from("o nome nao e nome de arquivo")));
                        }
                        self.nome = Some(nome);
                    } else if self.conteudo.is_none() {
                        self.conteudo = Some(m);
                    } else {
                        return Some(Err(String::from("mensagem demais")));
                    }
                }
                Ok(Lido::Falta) => return None,
                Ok(Lido::Fim) => {
                    let (Some(nome), Some(conteudo)) = (self.nome.take(), self.conteudo.take())
                    else {
                        return Some(Err(String::from("o fluxo acabou antes do arquivo")));
                    };
                    let caminho = format!("{RECEBIDOS}/{nome}");
                    return Some(gravar(&caminho, &conteudo).map(|()| {
                        format!("{} {} {:016x}", nome, conteudo.len(), resumo(&conteudo))
                    }));
                }
                Err(e) => return Some(Err(format!("{e:?}"))),
            }
        }
    }
}

/// Um envio: o fluxo, o que espera espaço, e o que se diz no fim.
struct Saindo {
    f: Fluxo,
    saida: EscritaPendente,
    dito: String,
}

impl Saindo {
    /// Escreve o que couber; no fim, termina. `Some` quando acabou.
    fn andar(&mut self) -> Option<Result<String, String>> {
        match self.saida.escoar(&self.f) {
            Ok(false) => None,
            Ok(true) => Some(
                self.f
                    .terminar()
                    .map(|()| self.dito.clone())
                    .map_err(|e| format!("terminar {}", e.motivo())),
            ),
            Err(e) => Some(Err(format!("escrever {}", e.motivo()))),
        }
    }
}

/// O pedido de envio, se há: o caminho e o dispositivo.
fn pedido() -> Option<(String, Option<String>)> {
    let texto = String::from_utf8(ler_arquivo(PEDIDO).ok()?).ok()?;
    let mut linhas = texto.lines().map(str::trim).filter(|l| !l.is_empty());
    let caminho = String::from(linhas.next()?);
    let dispositivo = linhas.next().map(String::from);
    Some((caminho, dispositivo))
}

/// Começa o envio do `pedido`: lê o arquivo, acha o outro copiador, abre o
/// fluxo com o aviso e junta as duas mensagens.
fn comecar_envio(
    caminho: &str,
    dispositivo: Option<&str>,
    meu: &str,
    laco: &Laco,
) -> Result<Saindo, String> {
    let conteudo = ler_arquivo(caminho)?;
    let nome = caminho.rsplit('/').next().unwrap_or(caminho);
    if !nome_valido(nome) {
        return Err(String::from("o nome nao e nome de arquivo"));
    }
    let candidatos = match dispositivo {
        Some(d) => malha::Par(d).descobrir(INTENCAO),
        None => malha::descobrir(INTENCAO),
    }
    .map_err(|f| format!("descobrir {}", f.codigo()))?;
    let outro = candidatos
        .into_iter()
        .filter(|c| c.programa == NOME)
        .map(|c| c.endpoint)
        .find(|e| e != meu)
        .ok_or_else(|| String::from("nenhum outro copiador"))?;
    let f = match dispositivo {
        Some(d) => fluxo::abrir_no_par_avisando(d, &outro, INTENCAO, laco),
        None => fluxo::abrir_avisando(&outro, INTENCAO, laco),
    }
    .map_err(|e| format!("abrir {} {}", e.codigo(), e.motivo()))?;
    let mut saida = EscritaPendente::nova();
    quadro::juntar(&mut saida, nome.as_bytes()).map_err(|e| format!("{e:?}"))?;
    quadro::juntar(&mut saida, &conteudo).map_err(|e| format!("{e:?}"))?;
    Ok(Saindo {
        f,
        saida,
        dito: format!("{} {} {:016x}", nome, conteudo.len(), resumo(&conteudo)),
    })
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut laco = match Laco::novo() {
        Ok(l) => l,
        Err(e) => {
            let _ = escreverln!("copiador: escutar devolveu {}", e);
            return 1;
        }
    };
    let endpoint = match malha::oferecer_avisando(INTENCAO, &laco) {
        Ok(e) => e,
        Err(f) => {
            let _ = escreverln!("copiador: oferecer {}", f.codigo());
            return 2;
        }
    };
    let _ = escreverln!("copiador: pronto {} {}", endpoint, laco.nome());
    let mut chegando: BTreeMap<u64, Chegando> = BTreeMap::new();
    let mut saindo: BTreeMap<u64, Saindo> = BTreeMap::new();
    if let Some((caminho, dispositivo)) = pedido() {
        match comecar_envio(&caminho, dispositivo.as_deref(), &endpoint, &laco) {
            Ok(s) => {
                if let Some(n) = s.f.numero() {
                    saindo.insert(n, s);
                }
            }
            Err(e) => {
                let _ = escreverln!("copiador: nao mandei: {}", e);
            }
        }
    }
    loop {
        let acontecimentos = match laco.esperar() {
            Ok(v) => v,
            Err(e) => {
                let _ = escreverln!("copiador: o laco falhou: {}", e);
                return 3;
            }
        };
        for a in acontecimentos {
            match a {
                Acontecimento::Endpoint { prontidao, .. } => {
                    if prontidao.entrega() {
                        let _ = malha::descartar_entregas(&endpoint);
                    }
                    while let Ok(Some((f, origem))) = fluxo::aceitar_avisando(&endpoint, &laco) {
                        let Some(n) = f.numero() else { continue };
                        let _ = escreverln!("copiador: chegando de {}", origem.descrever());
                        let mut c = Chegando {
                            f,
                            entrada: Entrada::nova(quadro::MAIOR_CORPO),
                            nome: None,
                            conteudo: None,
                        };
                        match c.andar() {
                            None => {
                                chegando.insert(n, c);
                            }
                            // Acabou logo no aceite: fecha também.
                            Some(r) => {
                                let _ = c.f.fechar();
                                dizer_recebido(r);
                            }
                        }
                    }
                }
                Acontecimento::Fluxo { numero, .. } => {
                    if let Some(c) = chegando.get_mut(&numero) {
                        if let Some(r) = c.andar() {
                            // Acabou, bem ou mal: fecha, e a vaga da cota
                            // volta na hora.
                            let _ = c.f.fechar();
                            chegando.remove(&numero);
                            dizer_recebido(r);
                        }
                    } else if let Some(s) = saindo.get_mut(&numero) {
                        match s.andar() {
                            None => {}
                            Some(Ok(dito)) => {
                                let _ = escreverln!("copiador: mandei {}", dito);
                                // O que foi escrito segue legível para o
                                // outro até o fim do sentido; fechar libera
                                // a cota daqui na hora, sem esperar a
                                // inatividade.
                                let _ = s.f.fechar();
                                saindo.remove(&numero);
                            }
                            Some(Err(e)) => {
                                let _ = escreverln!("copiador: nao mandei: {}", e);
                                let _ = s.f.fechar();
                                saindo.remove(&numero);
                            }
                        }
                    }
                }
                Acontecimento::Evento(Evento {
                    tipo: tipo::ENCERRAR,
                    ..
                }) => {
                    let _ = escreverln!("copiador: encerrado");
                    return CODIGO;
                }
                Acontecimento::Evento(_) => {}
            }
        }
    }
}

fn dizer_recebido(r: Result<String, String>) {
    let _ = match r {
        Ok(dito) => escreverln!("copiador: recebi {}", dito),
        Err(e) => escreverln!("copiador: nao recebi: {}", e),
    };
}
