//! A implantação na bancada do Internet Computer (ICP-4e): uma identidade
//! do Duke cria e gerencia um canister com a própria chave — cria pelo
//! ledger de cycles, instala um módulo do armazém, lê o estado, troca o
//! módulo em pedaços guardando o estado do canister e carrega cycles nele
//! —, cada resposta verificada antes de chegar aqui.
//!
//! Como a `carteira`: lê as âncoras do TLS da bancada e as redes em que
//! confia, diz `implantacao: pronto` e espera um evento no canal [`CANAL`]
//! — ou, com outra implantação escutando, diz `implantacao: pronto pelo
//! segundo canal` e espera no [`SEGUNDO_CANAL`]. A cada evento
//! [`tipo::ACAO`], o `a` diz o passo, o `b` a rede — o índice em [`REDES`]
//! — e o `c` a chave: 1 e 2, as de [`CHAVES`], que o kernel guarda para
//! quem lançou o processo; zero é o anônimo, que só conta. Cada pedido vai
//! por uma conexão nova, pelo caminho inteiro: o DNS, o destino no gate, o
//! TLS, os `POST` e a verificação.
//!
//! O canister desta execução fica na memória do programa: o que a criação
//! criou, ou o que a repetição dela disse. Nada se guarda.
//!
//! - [`CRIAR`]: a chave `c` cria um canister pelo ledger de cycles
//!   ([`LEDGER_DE_CICLOS`]), com [`QUANTIA_DA_CRIACAO`] dos cycles dela e o
//!   `created_at_time` da hora do Duke — o que faz desta criação uma só. O
//!   controlador é quem cria;
//! - [`REPETIR_CRIACAO`]: a última criação de novo, pela rede `b`: os
//!   mesmos argumentos, assinados de novo pela mesma chave. O ledger
//!   responde `Duplicate` com o canister da primeira, e não cria outro;
//! - [`FIXAR_HORA`] e [`CRIAR_EM`]: a hora que o `b` diz, em segundos, fica
//!   para as criações seguintes; e a chave `c` cria com o
//!   `created_at_time` dessa hora: duas implantações com a mesma hora fazem
//!   a mesma criação;
//! - [`INSTALAR`]: a chave `c` instala no canister o módulo [`MODULO_A`],
//!   lido do armazém pelo `fs.read` — o `install_code` em modo `install`,
//!   pelo canister de gerenciamento;
//! - [`FIXAR_PEDACO`] e [`ATUALIZAR`]: o tamanho dos pedaços que o `b` diz,
//!   em bytes, fica para os upgrades seguintes; e a chave `c` troca o
//!   módulo do canister pelo [`MODULO_B`]: um `upload_chunk` por pedaço, e
//!   o `install_chunked_code` em modo `upgrade`, com os hashes dos pedaços
//!   em ordem e o do módulo inteiro. O upgrade guarda a memória estável do
//!   canister. Um pedaço que não subiu — ou que voltou com o hash de outros
//!   bytes — para o upgrade antes da instalação;
//! - [`ESTADO`]: a chave `c` lê o estado do canister (`canister_status`):
//!   a situação, o hash do módulo, os controladores, os cycles e a memória;
//! - [`CARREGAR`]: a chave `c` carrega [`QUANTIA_DA_CARGA`] cycles da conta
//!   dela no canister (`withdraw`), com o `created_at_time` da hora do
//!   Duke, e guarda a carga;
//! - [`REPETIR_CARGA`]: a última carga de novo, pela rede `b`. O ledger
//!   responde `Duplicate` com o bloco da primeira, e não carrega;
//! - [`VERSAO`]: a versão do módulo que o canister roda, pela consulta do
//!   anônimo, verificada pelas assinaturas dos nós;
//! - [`CONTAR`]: o contador do módulo, na memória estável do canister —
//!   uma chamada da chave `c`, ou do anônimo.
//!
//! Antes de cada pedido, diz `implantacao: <passo> pede <etapa>` —
//! `read_state`, `query` ou `call`. Antes de mandar um módulo, diz o
//! SHA-256 dos bytes lidos: `implantacao: <passo> modulo <hash> <n> bytes`,
//! e no upgrade `implantacao: <passo> em <n> pedacos`. Numa chamada que
//! chegou ao fim, diz quem chamou — `implantacao: <passo> remetente
//! <principal>` — e o que voltou — `implantacao: <passo> resposta
//! <resposta>`: `canister <id> bloco <n>`, `bloco <n>`, `instalado`, `hash
//! <hash>`, `<situação> cycles <n> memoria <n>`, `contador <n>`, `erro
//! <nome do padrão>`, ou `recusa <código>`; o estado diz ainda, cada coisa
//! na sua linha — uma linha do log do kernel tem 160 bytes —, `implantacao:
//! <passo> modulo <hash|nenhum>` e `implantacao: <passo> controlador
//! <principal>`, uma por controlador. Depois, a linha do desfecho, como a
//! da `carteira`: `implantacao: <passo>: <desfecho>; declarada <registro>;
//! hora <estado>; assinaturas <n>; <detalhe>` — na consulta, sem as
//! assinaturas, e com a versão no detalhe. O upgrade são N + 1 passos,
//! `atualizar <rede> <chave> pedaco <i>` e `... instalacao`. O canister que
//! a criação deu, ou que a repetição disse, vai numa linha à parte:
//! `implantacao: alvo <canister>`. Sai com [`CODIGO`] quando a suíte pede o
//! fim.
//!
//! O módulo que não se lê para o passo antes de qualquer pedido ao IC, e
//! não há o que declarar: `implantacao: <passo>: failed_module; <caminho>:
//! <código>` — a recusa do `fs.read` fica na auditoria, pelo gate.
//!
//! # A declaração
//!
//! Cada chamada é declarada como a do ICP-3, `icp.update`, ancorada na
//! decisão da assinatura dela. A do gerenciamento diz o canister alvo —
//! `aaaaa-aa/<método>@<canister>` —: com `aaaaa-aa/<método>` só, a
//! auditoria não diria qual canister foi mexido.
//!
//! # O que o programa não é
//!
//! O canister, o módulo, os cycles e os controladores não dão nada a este
//! processo, nem são recurso do Duke: o kernel não sabe o que assina, e
//! quem controla um canister é um fato do IC. O que o programa pode é o que
//! o gate decide para os pedidos dele — `fs.read`, `random.read`,
//! `system.info`, `net.connect`, `audit.declare`, `key.read` e `key.sign`
//! —, com a autoridade de quem o lançou. Não há `reinstall`, que apaga o
//! estado do canister, nem troca de controladores, que pode trancar o dono
//! fora. Os passos só andam nas redes da bancada: a rede principal não está
//! em [`REDES`].

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "implantacao",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read",
    "audit.declare",
    "key.read",
    "key.sign"
);

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::icp::{
    self, Ancora, Andamento, ChaveDoKernel, Desfecho, Falha, Final, Principal, Rede, Valor,
    Verificada,
};
use programas::sistema;
use programas::tls::{self, Ancoras, Hora};
use protocolo::usuario::evento::{Evento, tipo};
use web3::icp::ciclos::{self, Carga, Criacao, RecusaDaCriacao};
use web3::icp::gerenciamento::{self, MAIOR_PEDACO, Modo};
use web3::icp::resumo::{self, Hash};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 82;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-implantacao";

/// O canal de uma segunda implantação, com a primeira viva.
const SEGUNDO_CANAL: &str = "teste-implantacao-2";

/// Os passos — a suíte tem as mesmas constantes.
const CRIAR: i64 = 1;
const REPETIR_CRIACAO: i64 = 2;
const CRIAR_EM: i64 = 3;
const INSTALAR: i64 = 4;
const ATUALIZAR: i64 = 5;
const ESTADO: i64 = 6;
const CARREGAR: i64 = 7;
const REPETIR_CARGA: i64 = 8;
const FIXAR_HORA: i64 = 9;
const VERSAO: i64 = 10;
const CONTAR: i64 = 11;
const FIXAR_PEDACO: i64 = 12;

/// As chaves, pelo `c` de um evento — `c` zero é o anônimo. Os nomes que a
/// política padrão dá ao operador.
const CHAVES: [&str; 2] = ["chave:bancada", "chave:bancada-2"];

/// As redes da bancada, pelo índice que o `b` de um evento diz — os nomes
/// de `/dados/icp/redes`, na ordem do `icp`: a honesta, a lenta, as que
/// adulteram a prova, a de raiz errada, a sem DNS e a que responde 202. A
/// rede principal não está aqui.
const REDES: [&str; 13] = [
    "bancada",
    "lenta",
    "raiz-errada",
    "bls-invalida",
    "sem-assinatura",
    "no-de-fora",
    "assinatura-errada",
    "pedido-trocado",
    "aninhada",
    "faixa-errada",
    "velho",
    "direta",
    "assincrona",
];

/// O ledger de cycles: o id da rede principal, em que a PocketIC da
/// bancada o sobe — a bancada confere (`xtask/src/icp.rs`).
const LEDGER_DE_CICLOS: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";

/// O DNS da bancada da suíte.
const DNS: &str = "udp:10.0.2.53:53";

/// A raiz do TLS da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// Os módulos do armazém: o que se instala, e o que vem no upgrade — a
/// bancada os põe na imagem (`xtask/src/icp.rs`).
const MODULO_A: &str = "/dados/icp/modulos/implantavel-a.wasm";
const MODULO_B: &str = "/dados/icp/modulos/implantavel-b.wasm";

/// O maior módulo que se lê: 64 pedaços do `fs.read`, cada um uma decisão
/// do gate e uma ficha do papel.
const MAIOR_MODULO: usize = 256 * 1024;

/// Os cycles de uma criação: 1 T. A criação custa uma parte, e o canister
/// novo fica com o resto.
const QUANTIA_DA_CRIACAO: u128 = 1_000_000_000_000;

/// Os cycles de uma carga: 0,5 T.
const QUANTIA_DA_CARGA: u128 = 500_000_000_000;

/// O [`icp::Gateway`] de um passo, que diz cada pedido antes de mandá-lo.
struct Narrado<'a> {
    gateway: &'a mut icp::Gateway,
    passo: &'a str,
}

impl icp::agente::Transporte for Narrado<'_> {
    type Erro = icp::Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), icp::Transporte> {
        let etapa = caminho.rsplit('/').next().unwrap_or(caminho);
        escreverln!("implantacao: {} pede {}", self.passo, etapa);
        self.gateway.post(caminho, corpo)
    }
}

/// Para onde vai uma chamada.
#[derive(Clone, Copy)]
enum Destino {
    /// Um canister: o ledger de cycles, ou o implantado.
    Canister(Principal),
    /// O canister de gerenciamento (`aaaaa-aa`), pelo canister efetivo — o
    /// que o método gerencia.
    Gerenciamento(Principal),
}

impl Destino {
    /// O assunto da declaração: o canister e o método — no gerenciamento,
    /// `aaaaa-aa/<método>@<canister>`.
    fn assunto(&self, metodo: &str) -> String {
        match self {
            Destino::Canister(c) => icp::assunto(c, metodo),
            Destino::Gerenciamento(alvo) => icp::assunto(
                &Principal::GERENCIAMENTO,
                &format!("{metodo}@{}", alvo.texto()),
            ),
        }
    }
}

/// O registro de uma declaração, ou o código de quem a recusou.
fn declarada(d: &icp::Declarada) -> String {
    match d {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    }
}

/// O primeiro grupo do texto de uma sub-rede, e se ela assinou por
/// delegação.
fn sub_rede(p: &Principal, delegada: bool) -> String {
    let texto = p.texto();
    format!(
        "{} {}",
        texto.split('-').next().unwrap_or(""),
        if delegada { "delegada" } else { "da raiz" }
    )
}

/// Bytes em hexadecimal minúsculo.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// O `created_at_time` da hora do Duke: a mesma com que se conferem os
/// certificados.
fn criada_em_ns(hora: &Hora) -> u64 {
    hora.validade_s().saturating_mul(1_000_000_000)
}

/// O canister desta execução, ou a linha que diz que não há nenhum.
fn alvo_de(alvo: Option<Principal>) -> Option<Principal> {
    if alvo.is_none() {
        escreverln!("implantacao: nenhum canister");
    }
    alvo
}

/// O argumento vazio, `()`.
fn vazio() -> Vec<u8> {
    icp::candid::codificar(&[]).expect("o vazio se codifica")
}

/// O módulo `caminho`, lido do armazém pelo `fs.read`, até
/// [`MAIOR_MODULO`] — e dito pelo SHA-256 dele —, ou a linha do passo que
/// diz por que não se leu.
fn modulo(passo: &str, caminho: &str) -> Option<Vec<u8>> {
    match icp::ler(caminho, MAIOR_MODULO) {
        Ok(bytes) => {
            escreverln!(
                "implantacao: {} modulo {} {} bytes",
                passo,
                hex(&resumo::sha256(&bytes)),
                bytes.len()
            );
            Some(bytes)
        }
        Err(f) => {
            let motivo = match f {
                Falha::Arquivo(Some(codigo)) => codigo,
                _ => String::from("nao se le"),
            };
            escreverln!(
                "implantacao: {}: failed_module; {}: {}",
                passo,
                caminho,
                motivo
            );
            None
        }
    }
}

/// O que monta o argumento de uma chamada, com a hora.
type Preparo<'a> = dyn FnMut(&Hora) -> Result<Vec<u8>, Falha> + 'a;

/// Uma chamada de `metodo` ao `destino` pelo caminho inteiro — a chave
/// lida, a hora, o argumento que `preparar` monta, a conexão, a chamada
/// assinada e as leituras da situação enquanto pendente —, declarada antes
/// do fecho, ancorada na decisão da assinatura da chamada; do anônimo, na
/// conexão. Diz quem chamou e o que voltou — lido por `ler`; o que não se
/// lê é `verified_malformed` —, e devolve a resposta verificada.
#[allow(clippy::too_many_arguments)]
fn chamar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    destino: Destino,
    metodo: &str,
    preparar: &mut Preparo<'_>,
    ler: &dyn Fn(&[u8]) -> Result<String, String>,
) -> Option<Vec<u8>> {
    let assunto = destino.assunto(metodo);
    let mut kernel = None;
    let mut gateway = None;
    let mut hora_dita = None;
    let mut leituras = 0u32;
    let r: Result<(icp::Atualizacao, Andamento), Falha> = (|| {
        if let Some(nome) = chave {
            kernel = Some(ChaveDoKernel::ler(nome)?);
        }
        let hora = icp::hora()?;
        hora_dita = Some(hora.estado.nome());
        let arg = preparar(&hora)?;
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        let mut a = match destino {
            Destino::Canister(canister) => icp::chamar(
                &mut narrado,
                rede,
                kernel.as_mut(),
                &canister,
                metodo,
                &arg,
                &hora,
                &nonce,
            )?,
            Destino::Gerenciamento(efetivo) => icp::chamar_ao_gerenciamento(
                &mut narrado,
                rede,
                kernel.as_mut(),
                &efetivo,
                metodo,
                &arg,
                &hora,
                &nonce,
            )?,
        };
        let mut andamento = a.andamento.clone();
        while let Andamento::Pendente(situacao) = andamento
            && leituras < icp::MAIS_LEITURAS
        {
            escreverln!("implantacao: {} pendente {}", passo, situacao);
            narrado.gateway.esperar(icp::ESPERA_ENTRE_LEITURAS_MS)?;
            let hora = icp::hora()?;
            leituras += 1;
            andamento = icp::acompanhar(&mut narrado, rede, kernel.as_mut(), &mut a, &hora)?;
        }
        Ok((a, andamento))
    })();
    let resposta = match &r {
        Ok((
            _,
            Andamento::Certificado {
                desfecho: Final::Respondida(bytes),
                ..
            },
        )) => Some((bytes.clone(), ler(bytes))),
        _ => None,
    };
    let desfecho = match &resposta {
        Some((_, Err(_))) => "verified_malformed",
        _ => icp::desfecho_da_chamada(r.as_ref().map(|(_, andamento)| andamento)),
    };
    let decisao = kernel.as_ref().and_then(|k| k.decisoes().first().copied());
    let ancora = match (decisao, gateway.as_ref()) {
        (Some(d), _) => Ancora::Decisao(d),
        (None, Some(g)) => Ancora::Conexao(g.conexao()),
        (None, None) => Ancora::Nenhuma,
    };
    let d = icp::declarar_chamada(&assunto, desfecho, ancora);
    let detalhe = match &r {
        Ok((a, andamento)) => {
            escreverln!("implantacao: {} remetente {}", passo, a.remetente.texto());
            let dito = match (&resposta, andamento) {
                (Some((_, Ok(t))), _) => t.clone(),
                (Some((_, Err(e))), _) => format!("recusado: {e}"),
                (None, Andamento::Certificado { desfecho, .. }) => match desfecho {
                    Final::Recusada { codigo, erro, .. } => {
                        format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-"))
                    }
                    Final::Concluida => String::from("concluida"),
                    Final::Respondida(_) => String::new(),
                },
                (None, Andamento::RecusaNaoReplicada { codigo, erro, .. }) => format!(
                    "recusa sem prova {codigo} {}",
                    erro.as_deref().unwrap_or("-")
                ),
                (None, Andamento::Pendente(s)) => format!("pendente {s}"),
            };
            // Uma linha do log do kernel tem 160 bytes: a resposta que não
            // cabe numa — a do estado — vai em várias, uma por linha dela.
            let mut linhas = dito.split('\n');
            escreverln!(
                "implantacao: {} resposta {}",
                passo,
                linhas.next().unwrap_or_default()
            );
            for linha in linhas {
                escreverln!("implantacao: {} {}", passo, linha);
            }
            format!(
                "prova {} leituras {}",
                sub_rede(&a.faixas.sub_rede, a.faixas.delegada),
                leituras
            )
        }
        Err(f) => format!("{f}"),
    };
    let assinaturas = kernel.as_ref().map_or(0, |k| k.decisoes().len());
    escreverln!(
        "implantacao: {}: {}; declarada {}; hora {}; assinaturas {}; {}",
        passo,
        desfecho,
        declarada(&d),
        hora_dita.unwrap_or("nenhuma"),
        assinaturas,
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
    match (desfecho, resposta) {
        ("verified", Some((bytes, _))) => Some(bytes),
        _ => None,
    }
}

/// O que uma criação respondeu, dito: o canister e o bloco, ou o erro do
/// ledger pelo nome do padrão.
fn ler_criacao(bytes: &[u8]) -> Result<String, String> {
    match ciclos::ler_criacao(bytes) {
        Ok(Ok(c)) => Ok(format!("canister {} bloco {}", c.canister.texto(), c.bloco)),
        Ok(Err(recusa)) => Ok(format!("erro {recusa}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// O que uma carga respondeu, dito: o bloco, ou o erro do ledger pelo nome
/// do padrão.
fn ler_carga(bytes: &[u8]) -> Result<String, String> {
    match ciclos::ler_carga(bytes) {
        Ok(Ok(bloco)) => Ok(format!("bloco {bloco}")),
        Ok(Err(recusa)) => Ok(format!("erro {recusa}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// O que uma instalação respondeu: `()`.
fn ler_instalacao(bytes: &[u8]) -> Result<String, String> {
    gerenciamento::ler_vazio(bytes)
        .map(|()| String::from("instalado"))
        .map_err(|e| format!("{e}"))
}

/// O estado de um canister, dito: a situação, os cycles e a memória; e, em
/// linhas à parte, o hash do módulo — ou `nenhum` — e cada controlador.
fn ler_estado(bytes: &[u8]) -> Result<String, String> {
    let e = gerenciamento::ler_estado(bytes).map_err(|e| format!("{e}"))?;
    let mut dito = format!(
        "{} cycles {} memoria {}\nmodulo {}",
        e.situacao.nome(),
        e.cycles,
        e.memoria,
        e.modulo.map_or(String::from("nenhum"), |h| hex(&h))
    );
    for c in &e.controladores {
        dito.push_str(&format!("\ncontrolador {}", c.texto()));
    }
    Ok(dito)
}

/// O contador do módulo: `(nat64)`.
fn ler_contador(bytes: &[u8]) -> Result<String, String> {
    match icp::candid::decodificar(bytes).map_err(|e| format!("{e}"))?[..] {
        [Valor::Nat64(n)] => Ok(format!("contador {n}")),
        _ => Err(String::from("resposta fora da forma do contador")),
    }
}

/// A versão do módulo: `(text)`, dita em ASCII.
fn ler_versao(bytes: &[u8]) -> Result<String, String> {
    match icp::candid::decodificar(bytes).map_err(|e| format!("{e}"))?[..] {
        [ref t @ Valor::Texto(_)] => Ok(format!("versao {t}")),
        _ => Err(String::from("resposta fora da forma da versao")),
    }
}

/// Uma criação de canister pela `chave`, com o argumento que `montar` faz
/// da hora; devolve o canister, se o ledger criou — ou se já tinha criado:
/// o `Duplicate` diz o canister da primeira.
fn criar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    ledger: &Principal,
    montar: &mut dyn FnMut(&Hora) -> Criacao,
) -> Option<Principal> {
    let mut preparar = |hora: &Hora| {
        Ok(ciclos::argumento_da_criacao(&montar(hora))
            .expect("a criacao daqui nao tem controladores"))
    };
    let bytes = chamar(
        passo,
        rede,
        ancoras,
        chave,
        Destino::Canister(*ledger),
        "create_canister",
        &mut preparar,
        &ler_criacao,
    )?;
    match ciclos::ler_criacao(&bytes) {
        Ok(Ok(c)) => Some(c.canister),
        Ok(Err(RecusaDaCriacao::Duplicada { canister, .. })) => canister,
        _ => None,
    }
}

/// Uma carga de cycles pela `chave`, com o argumento que `montar` faz da
/// hora.
fn carregar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    ledger: &Principal,
    montar: &mut dyn FnMut(&Hora) -> Carga,
) {
    let mut preparar = |hora: &Hora| Ok(ciclos::argumento_da_carga(&montar(hora)));
    chamar(
        passo,
        rede,
        ancoras,
        chave,
        Destino::Canister(*ledger),
        "withdraw",
        &mut preparar,
        &ler_carga,
    );
}

/// O upgrade do `canister` para o módulo `modulo`, pela `chave`, em pedaços
/// de até `tamanho` bytes: um `upload_chunk` por pedaço, e o
/// `install_chunked_code` com os hashes deles — os dos bytes daqui — e o do
/// módulo inteiro. Um pedaço que não subiu, ou que voltou com o hash de
/// outros bytes, para tudo antes da instalação.
fn atualizar(
    base: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    canister: &Principal,
    modulo: &[u8],
    tamanho: usize,
) {
    let pedacos: Vec<&[u8]> = gerenciamento::pedacos(modulo, tamanho).collect();
    let hashes: Vec<Hash> = pedacos.iter().map(|p| resumo::sha256(p)).collect();
    let instalacao = match gerenciamento::argumento_da_instalacao_em_pedacos(
        Modo::Atualizar,
        canister,
        &hashes,
        &resumo::sha256(modulo),
        &[],
    ) {
        Ok(arg) => arg,
        Err(e) => {
            escreverln!("implantacao: {}: failed_argument; {}", base, e);
            return;
        }
    };
    escreverln!("implantacao: {} em {} pedacos", base, pedacos.len());
    let destino = Destino::Gerenciamento(*canister);
    for (i, (pedaco, hash)) in pedacos.iter().zip(&hashes).enumerate() {
        let passo = format!("{base} pedaco {}", i + 1);
        let arg = gerenciamento::argumento_do_pedaco(canister, pedaco).expect("o pedaco cabe");
        let ler = |bytes: &[u8]| match gerenciamento::ler_pedaco(bytes) {
            Ok(h) if h == *hash => Ok(format!("hash {}", hex(&h))),
            Ok(h) => Err(format!("hash {} de outros bytes", hex(&h))),
            Err(e) => Err(format!("{e}")),
        };
        let subiu = chamar(
            &passo,
            rede,
            ancoras,
            chave,
            destino,
            "upload_chunk",
            &mut |_| Ok(arg.clone()),
            &ler,
        );
        if subiu.is_none() {
            escreverln!("implantacao: {} parou no pedaco {}", base, i + 1);
            return;
        }
    }
    chamar(
        &format!("{base} instalacao"),
        rede,
        ancoras,
        chave,
        destino,
        "install_chunked_code",
        &mut |_| Ok(instalacao.clone()),
        &ler_instalacao,
    );
}

/// A versão do módulo do `canister`, pela consulta do anônimo, verificada e
/// declarada antes do fecho, ancorada na conexão.
fn versao(passo: &str, rede: &Rede, ancoras: &Ancoras, canister: &Principal) {
    const METODO: &str = "versao";
    let assunto = icp::assunto(canister, METODO);
    let mut gateway = None;
    let mut hora_dita = None;
    let r: Result<Verificada, Falha> = (|| {
        let hora = icp::hora()?;
        hora_dita = Some(hora.estado.nome());
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        icp::consultar(
            &mut narrado,
            rede,
            canister,
            METODO,
            &vazio(),
            &hora,
            &nonce,
        )
    })();
    let lido = match &r {
        Ok(v) => match &v.desfecho {
            Desfecho::Respondida(bytes) => Some(ler_versao(bytes)),
            Desfecho::Recusada { .. } => None,
        },
        Err(_) => None,
    };
    let desfecho = match &lido {
        Some(Err(_)) => "verified_malformed",
        _ => icp::desfecho(&r),
    };
    let d = icp::declarar(
        &assunto,
        desfecho,
        gateway.as_ref().map(icp::Gateway::conexao),
    );
    let detalhe = match (&r, &lido) {
        (Ok(v), lido) => {
            let prova = format!(
                "prova {} {}/{}",
                sub_rede(&v.sub_rede, v.delegada),
                v.assinaturas,
                v.nos
            );
            match (lido, &v.desfecho) {
                (Some(Ok(t)), _) => format!("{t}; {prova}"),
                (Some(Err(e)), _) => format!("{prova}: recusado: {e}"),
                (None, Desfecho::Recusada { codigo, erro, .. }) => {
                    format!(
                        "{prova}: recusa {codigo} {}",
                        erro.as_deref().unwrap_or("-")
                    )
                }
                (None, Desfecho::Respondida(_)) => prova,
            }
        }
        (Err(f), _) => format!("{f}"),
    };
    escreverln!(
        "implantacao: {}: {}; declarada {}; hora {}; {}",
        passo,
        desfecho,
        declarada(&d),
        hora_dita.unwrap_or("nenhuma"),
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut segundo = false;
    let mut canal = sistema::escutar(CANAL);
    if canal < 0 {
        segundo = true;
        canal = sistema::escutar(SEGUNDO_CANAL);
    }
    if canal < 0 {
        escreverln!("implantacao: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("implantacao: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let redes = match icp::redes() {
        Ok(r) => r,
        Err(f) => {
            escreverln!("implantacao: as redes nao se leram: {}", f);
            return 3;
        }
    };
    let Ok(ledger) = Principal::de_texto(LEDGER_DE_CICLOS) else {
        escreverln!("implantacao: o ledger de cycles nao se le");
        return 4;
    };
    if segundo {
        escreverln!(
            "implantacao: pronto pelo segundo canal ({} redes)",
            redes.len()
        );
    } else {
        escreverln!("implantacao: pronto ({} redes)", redes.len());
    }

    // O canister desta execução, e a última criação e a última carga —
    // quem assinou e os argumentos: o que [`REPETIR_CRIACAO`] e
    // [`REPETIR_CARGA`] mandam de novo.
    let mut alvo: Option<Principal> = None;
    let mut ultima_criacao: Option<(Option<&'static str>, Criacao)> = None;
    let mut ultima_carga: Option<(Option<&'static str>, Carga)> = None;
    // A hora de [`CRIAR_EM`], em segundos, e o tamanho dos pedaços do
    // upgrade.
    let mut hora_fixada: Option<u64> = None;
    let mut tamanho_do_pedaco = MAIOR_PEDACO;
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("implantacao: a leitura do canal falhou: {}", e);
                return 5;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("implantacao: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            if e.a == FIXAR_HORA {
                hora_fixada = u64::try_from(e.b).ok();
                escreverln!("implantacao: hora fixada {}", e.b);
                continue;
            }
            if e.a == FIXAR_PEDACO {
                tamanho_do_pedaco = usize::try_from(e.b)
                    .unwrap_or(MAIOR_PEDACO)
                    .clamp(1, MAIOR_PEDACO);
                escreverln!("implantacao: pedaco fixado {}", tamanho_do_pedaco);
                continue;
            }
            let nome = usize::try_from(e.b)
                .ok()
                .and_then(|i| REDES.get(i))
                .copied()
                .unwrap_or("?");
            let Some(rede) = redes.iter().find(|r| r.nome == nome) else {
                escreverln!("implantacao: rede {} fora da bancada", nome);
                continue;
            };
            let chave = usize::try_from(e.c)
                .ok()
                .and_then(|i| i.checked_sub(1))
                .and_then(|i| CHAVES.get(i))
                .copied();
            let quem = chave.unwrap_or("anonimo");
            match e.a {
                CRIAR | CRIAR_EM if chave.is_some() => {
                    let (passo, segundos) = if e.a == CRIAR {
                        (format!("criar {nome} {quem}"), None)
                    } else {
                        let Some(s) = hora_fixada else {
                            escreverln!("implantacao: hora nao fixada");
                            continue;
                        };
                        (format!("criar_em {nome} {quem}"), Some(s))
                    };
                    let mut feita = None;
                    let criado = criar(&passo, rede, &ancoras, chave, &ledger, &mut |hora| {
                        let ns = segundos
                            .map_or(criada_em_ns(hora), |s| s.saturating_mul(1_000_000_000));
                        let c = Criacao {
                            quantia: QUANTIA_DA_CRIACAO,
                            criada_em_ns: Some(ns),
                            controladores: None,
                        };
                        feita = Some(c.clone());
                        c
                    });
                    // Guardada mesmo sem desfecho: é a resposta perdida que
                    // a repetição esclarece.
                    if let Some(c) = feita {
                        ultima_criacao = Some((chave, c));
                    }
                    if let Some(c) = criado {
                        alvo = Some(c);
                        escreverln!("implantacao: alvo {}", c.texto());
                    }
                }
                REPETIR_CRIACAO => match &ultima_criacao {
                    Some((de, c)) => {
                        let passo = format!("repetir_criacao {nome} {}", de.unwrap_or("anonimo"));
                        let c = c.clone();
                        let criado =
                            criar(&passo, rede, &ancoras, *de, &ledger, &mut |_| c.clone());
                        if let Some(c) = criado {
                            alvo = Some(c);
                            escreverln!("implantacao: alvo {}", c.texto());
                        }
                    }
                    None => {
                        escreverln!("implantacao: nada a repetir");
                    }
                },
                INSTALAR if chave.is_some() => {
                    let Some(canister) = alvo_de(alvo) else {
                        continue;
                    };
                    let passo = format!("instalar {nome} {quem}");
                    let Some(bytes) = modulo(&passo, MODULO_A) else {
                        continue;
                    };
                    let arg = gerenciamento::argumento_da_instalacao(
                        Modo::Instalar,
                        &canister,
                        &bytes,
                        &[],
                    )
                    .expect("o modulo daqui cabe");
                    chamar(
                        &passo,
                        rede,
                        &ancoras,
                        chave,
                        Destino::Gerenciamento(canister),
                        "install_code",
                        &mut |_| Ok(arg.clone()),
                        &ler_instalacao,
                    );
                }
                ATUALIZAR if chave.is_some() => {
                    let Some(canister) = alvo_de(alvo) else {
                        continue;
                    };
                    let base = format!("atualizar {nome} {quem}");
                    let Some(bytes) = modulo(&base, MODULO_B) else {
                        continue;
                    };
                    atualizar(
                        &base,
                        rede,
                        &ancoras,
                        chave,
                        &canister,
                        &bytes,
                        tamanho_do_pedaco,
                    );
                }
                ESTADO if chave.is_some() => {
                    let Some(canister) = alvo_de(alvo) else {
                        continue;
                    };
                    let passo = format!("estado {nome} {quem}");
                    let arg = gerenciamento::argumento_do_estado(&canister);
                    chamar(
                        &passo,
                        rede,
                        &ancoras,
                        chave,
                        Destino::Gerenciamento(canister),
                        "canister_status",
                        &mut |_| Ok(arg.clone()),
                        &ler_estado,
                    );
                }
                CARREGAR if chave.is_some() => {
                    let Some(canister) = alvo_de(alvo) else {
                        continue;
                    };
                    let passo = format!("carregar {nome} {quem}");
                    let mut feita = None;
                    carregar(&passo, rede, &ancoras, chave, &ledger, &mut |hora| {
                        let c = Carga {
                            para: canister,
                            quantia: QUANTIA_DA_CARGA,
                            criada_em_ns: Some(criada_em_ns(hora)),
                        };
                        feita = Some(c);
                        c
                    });
                    if let Some(c) = feita {
                        ultima_carga = Some((chave, c));
                    }
                }
                REPETIR_CARGA => match &ultima_carga {
                    Some((de, c)) => {
                        let passo = format!("repetir_carga {nome} {}", de.unwrap_or("anonimo"));
                        let c = *c;
                        carregar(&passo, rede, &ancoras, *de, &ledger, &mut |_| c);
                    }
                    None => {
                        escreverln!("implantacao: nada a repetir");
                    }
                },
                VERSAO => {
                    let Some(canister) = alvo_de(alvo) else {
                        continue;
                    };
                    let passo = format!("versao {nome}");
                    versao(&passo, rede, &ancoras, &canister);
                }
                CONTAR => {
                    let Some(canister) = alvo_de(alvo) else {
                        continue;
                    };
                    let passo = format!("contar {nome} {quem}");
                    chamar(
                        &passo,
                        rede,
                        &ancoras,
                        chave,
                        Destino::Canister(canister),
                        "contar",
                        &mut |_| Ok(vazio()),
                        &ler_contador,
                    );
                }
                outro => {
                    escreverln!(
                        "implantacao: passo {} desconhecido com a conta {}",
                        outro,
                        quem
                    );
                }
            }
        }
    }
}
