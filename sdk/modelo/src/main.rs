//! O modelo de um programa do Duke feito fora do repositório: copie esta
//! pasta e comece daqui — ver `docs/SDK.md`.
//!
//! O programa é o padrão do servidor de vários clientes, com o laço, e um
//! cliente opcional:
//!
//! - escuta um canal só dele ([`Laco::novo`]), oferece [`INTENCAO`] com o
//!   aviso nesse canal e diz `modelo: pronto <endpoint> <canal>`;
//! - cada fluxo que chega é aceito, também com o aviso, e **ecoado**: o
//!   que chega volta, e o fim também; diz `modelo: ecoei <fluxo> <bytes>`;
//! - se o armazém tem [`PAR`], é também cliente: abre um fluxo, com o
//!   aviso, ao primeiro outro programa que oferece a intenção e que a
//!   descoberta acha — no dispositivo da primeira linha do arquivo, se ela
//!   não está vazia, ou neste Duke; o programa é o da terceira linha, ou
//!   outro `modelo` —, diz `modelo: perguntei <fluxo> a <programa>`, manda
//!   os bytes do padrão — quantos a segunda linha diz, ou [`TAMANHO`] —,
//!   termina o sentido dele, lê o eco até o fim e o confere: diz `modelo:
//!   eco <bytes> <resumo> confere` e sai com [`CODIGO_DO_ECO`].
//!
//! O evento `ENCERRAR` no canal encerra o programa com [`CODIGO`].
//!
//! # O que o aviso é, e o que não é
//!
//! O aviso só diz que vale a pena pedir: cada aceite, leitura e escrita
//! continua sendo um pedido ao gate, com a autoridade de quem lançou o
//! programa, e pode não achar nada ou ser recusado. Um objeto tem no
//! máximo um aviso não consumido; a próxima operação do programa sobre ele
//! o rearma. Por isso, a cada aviso, o programa **opera** sobre o objeto
//! até não haver mais nada a fazer agora — e dorme de novo no laço, a
//! única espera dele.
//!
//! # Para fazer o seu
//!
//! Troque o nome (aqui, no `Cargo.toml` e no `manifesto!`), a intenção — a
//! sua, que quem administra enumera na política, com `fabric.offer` e
//! `fabric.stream` para o papel de quem roda — e o que cada fluxo faz.
//! Compile em release para o alvo do Duke, confira com `cargo xtask
//! sdk-conferir`, sele com `cargo xtask selar` e instale no armazém.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "modelo",
    "fabric.offer",
    "fabric.send",
    "fabric.stream",
    "fabric.remote",
    "fs.read"
);

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use programas::fluxo::{self, EscritaPendente, Falha, Fluxo, Resumo};
use programas::laco::{Acontecimento, Laco};
use programas::{escreverln, malha, sistema};
use protocolo::usuario::evento::{Evento, tipo};

/// A intenção que o modelo oferece e procura. Uma das de exemplo da
/// política padrão: a de um programa de verdade é a dele.
const INTENCAO: &str = "imagem.compartilhar";

/// O nome do manifesto — o que a descoberta mostra de cada candidato.
const NOME: &str = "modelo";

/// O pedido do cliente: se existe, o modelo também pergunta. A primeira
/// linha, se não está vazia, é o dispositivo do outro Duke
/// (`dispositivo:<nome>`); a segunda, se há, quantos bytes mandar; a
/// terceira, se há, o programa a quem perguntar — um que ecoe.
const PAR: &str = "/armazem/compartilhado/modelo/par";

/// Quantos bytes o cliente manda, se o pedido não diz: mais que dois
/// buffers de um sentido, para a escrita esbarrar no cheio e seguir pelo
/// aviso.
const TAMANHO: usize = 40 * 1024;

/// O mais que o pedido pode pedir: o eco inteiro fica na memória do
/// cliente, para a conferência.
const MAIOR_TAMANHO: usize = 4 * 1024 * 1024;

/// O código de saída no fim pedido.
const CODIGO: i64 = 57;

/// O código de saída do cliente com o eco conferido.
const CODIGO_DO_ECO: i64 = 58;

/// Um fluxo aceito: o que chegou e espera para voltar.
struct Eco {
    f: Fluxo,
    saida: EscritaPendente,
    fim_lido: bool,
    bytes: u64,
}

impl Eco {
    /// Faz o que dá para fazer agora: escreve o que espera; com isso
    /// vazio, lê e junta; com o fim lido e tudo escrito, termina. `true`
    /// quando acabou.
    fn andar(&mut self) -> Result<bool, Falha> {
        loop {
            if !self.saida.escoar(&self.f)? {
                // O outro lado não leu o eco ainda: o `GRAVAVEL` diz quando.
                return Ok(false);
            }
            if self.fim_lido {
                self.f.terminar()?;
                return Ok(true);
            }
            let (bytes, fim) = self.f.ler_agora(fluxo::MAIOR_PEDACO)?;
            self.bytes += bytes.len() as u64;
            self.saida.juntar(&bytes);
            self.fim_lido = fim;
            if bytes.is_empty() && !fim {
                // Nada mais agora: o `LEGIVEL` diz quando.
                return Ok(false);
            }
        }
    }
}

/// O fluxo que este modelo abriu: o que falta mandar e o eco que volta.
struct Pergunta {
    f: Fluxo,
    saida: EscritaPendente,
    terminado: bool,
    /// Quantos bytes foram, e o resumo deles: o que o eco tem de trazer.
    tamanho: usize,
    esperado: u64,
    recebidos: usize,
    resumo: Resumo,
}

impl Pergunta {
    /// Escreve o que couber, termina quando tudo foi, e lê o que voltou —
    /// os dois sentidos andando juntos, sem dormir numa escrita. `true`
    /// com o fim do eco lido.
    fn andar(&mut self) -> Result<bool, Falha> {
        loop {
            let antes = self.saida.tamanho();
            self.saida.escoar(&self.f)?;
            let mut andou = self.saida.tamanho() < antes;
            if self.saida.vazia() && !self.terminado {
                self.f.terminar()?;
                self.terminado = true;
            }
            let (bytes, fim) = self.f.ler_agora(fluxo::MAIOR_PEDACO)?;
            andou |= !bytes.is_empty();
            self.recebidos += bytes.len();
            self.resumo.somar(&bytes);
            if fim {
                return Ok(true);
            }
            if !andou {
                return Ok(false);
            }
        }
    }
}

/// O que o pedido do cliente diz: o dispositivo, quantos bytes, e a quem.
struct Pedido {
    dispositivo: Option<String>,
    tamanho: usize,
    programa: String,
}

/// O pedido do cliente: `None` sem o arquivo. O arquivo é entrada como
/// outra qualquer: o tamanho que não se lê, ou que passa do teto, é o
/// padrão, e o programa que não é um nome de manifesto também.
fn pedido() -> Option<Pedido> {
    let d = sistema::abrir(PAR);
    if d < 0 {
        return None;
    }
    let mut texto = [0u8; 128];
    let n = sistema::ler(d as u64, &mut texto);
    sistema::fechar(d as u64);
    let n = usize::try_from(n).unwrap_or(0);
    let mut linhas = core::str::from_utf8(&texto[..n]).unwrap_or("").lines();
    let dispositivo = linhas.next().unwrap_or("").trim();
    let tamanho = linhas
        .next()
        .and_then(|l| l.trim().parse::<usize>().ok())
        .filter(|t| (1..=MAIOR_TAMANHO).contains(t))
        .unwrap_or(TAMANHO);
    let programa = linhas
        .next()
        .map(str::trim)
        .filter(|p| {
            !p.is_empty()
                && p.len() <= 32
                && p.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
        .unwrap_or(NOME);
    Some(Pedido {
        dispositivo: (!dispositivo.is_empty()).then(|| String::from(dispositivo)),
        tamanho,
        programa: String::from(programa),
    })
}

/// Abre a pergunta ao primeiro outro programa do `pedido` que a descoberta
/// acha, com os bytes do padrão para mandar.
fn perguntar(pedido: &Pedido, meu: &str, laco: &Laco) -> Result<Pergunta, String> {
    let dispositivo = pedido.dispositivo.as_deref();
    let tamanho = pedido.tamanho;
    let candidatos = match dispositivo {
        Some(d) => malha::Par(d).descobrir(INTENCAO),
        None => malha::descobrir(INTENCAO),
    }
    .map_err(|f| alloc::format!("descobrir {}", f.codigo()))?;
    let outro = candidatos
        .into_iter()
        .find(|c| c.programa == pedido.programa && c.endpoint != meu)
        .ok_or_else(|| alloc::format!("nenhum outro {} oferece", pedido.programa))?;
    let f = match dispositivo {
        Some(d) => fluxo::abrir_no_par_avisando(d, &outro.endpoint, INTENCAO, laco),
        None => fluxo::abrir_avisando(&outro.endpoint, INTENCAO, laco),
    }
    .map_err(|f| alloc::format!("abrir {} {}", f.codigo(), f.motivo()))?;
    let mut saida = EscritaPendente::nova();
    let dados: Vec<u8> = (0..tamanho).map(|i| fluxo::padrao(0, i)).collect();
    let mut esperado = Resumo::novo();
    esperado.somar(&dados);
    saida.juntar(&dados);
    Ok(Pergunta {
        f,
        saida,
        terminado: false,
        tamanho,
        esperado: esperado.valor(),
        recebidos: 0,
        resumo: Resumo::novo(),
    })
}

/// Aceita, com o aviso, os pedidos que esperam no endpoint.
fn aceitar_todos(endpoint: &str, laco: &Laco, ecos: &mut BTreeMap<u64, Eco>) {
    loop {
        match fluxo::aceitar_avisando(endpoint, laco) {
            Ok(Some((f, origem))) => {
                let Some(n) = f.numero() else { continue };
                escreverln!("modelo: aceitei {} de {}", n, origem.descrever());
                // O aviso da ponta aceita vem quando houver o que ler; não
                // há nada a fazer antes dele.
                ecos.insert(
                    n,
                    Eco {
                        f,
                        saida: EscritaPendente::nova(),
                        fim_lido: false,
                        bytes: 0,
                    },
                );
            }
            Ok(None) => return,
            Err(e) => {
                escreverln!("modelo: aceitar {} {}", e.codigo(), e.motivo());
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut laco = match Laco::novo() {
        Ok(l) => l,
        Err(e) => {
            escreverln!("modelo: escutar devolveu {}", e);
            return 1;
        }
    };
    let endpoint = match malha::oferecer_avisando(INTENCAO, &laco) {
        Ok(e) => e,
        Err(f) => {
            escreverln!("modelo: oferecer {}", f.codigo());
            return 2;
        }
    };
    escreverln!("modelo: pronto {} {}", endpoint, laco.nome());

    let mut pergunta = match pedido() {
        None => None,
        Some(pedido) => match perguntar(&pedido, &endpoint, &laco) {
            Ok(p) => {
                escreverln!(
                    "modelo: perguntei {} a {}",
                    p.f.numero().unwrap_or(0),
                    pedido.programa
                );
                Some(p)
            }
            Err(e) => {
                escreverln!("modelo: a pergunta nao abriu: {}", e);
                return 3;
            }
        },
    };
    let mut ecos: BTreeMap<u64, Eco> = BTreeMap::new();
    loop {
        let acontecimentos = match laco.esperar() {
            Ok(v) => v,
            Err(e) => {
                escreverln!("modelo: o laco falhou: {}", e);
                return 4;
            }
        };
        for a in acontecimentos {
            match a {
                Acontecimento::Endpoint { prontidao, .. } => {
                    if prontidao.fim() {
                        escreverln!("modelo: o endpoint fechou");
                        return 5;
                    }
                    if prontidao.entrega() {
                        // O modelo não usa entregas, mas o aviso só se cala
                        // quando elas saem da pendência: recebe e confirma.
                        let _ = malha::descartar_entregas(&endpoint);
                    }
                    aceitar_todos(&endpoint, &laco, &mut ecos);
                }
                Acontecimento::Fluxo { numero, .. } => {
                    if let Some(p) = pergunta.as_mut().filter(|p| p.f.numero() == Some(numero)) {
                        match p.andar() {
                            Ok(false) => {}
                            Ok(true) => {
                                let confere =
                                    p.recebidos == p.tamanho && p.resumo.valor() == p.esperado;
                                escreverln!(
                                    "modelo: eco {} {:016x} {}",
                                    p.recebidos,
                                    p.resumo.valor(),
                                    if confere { "confere" } else { "nao confere" }
                                );
                                let _ = p.f.fechar();
                                return if confere { CODIGO_DO_ECO } else { 6 };
                            }
                            Err(e) => {
                                escreverln!(
                                    "modelo: a pergunta acabou: {} {}",
                                    e.codigo(),
                                    e.motivo()
                                );
                                return 7;
                            }
                        }
                        continue;
                    }
                    let Some(eco) = ecos.get_mut(&numero) else {
                        continue;
                    };
                    match eco.andar() {
                        Ok(false) => {}
                        Ok(true) => {
                            escreverln!("modelo: ecoei {} {}", numero, eco.bytes);
                            let _ = eco.f.fechar();
                            ecos.remove(&numero);
                        }
                        Err(e) => {
                            escreverln!("modelo: {} acabou: {}", numero, e.motivo());
                            // Fecha antes de largar: senão o fluxo fica
                            // vivo, na cota, até vencer a inatividade.
                            if let Some(eco) = ecos.remove(&numero) {
                                let _ = eco.f.fechar();
                            }
                        }
                    }
                }
                Acontecimento::Evento(Evento {
                    tipo: tipo::ENCERRAR,
                    ..
                }) => {
                    escreverln!("modelo: encerrado");
                    return CODIGO;
                }
                Acontecimento::Evento(_) => {}
            }
        }
    }
}
