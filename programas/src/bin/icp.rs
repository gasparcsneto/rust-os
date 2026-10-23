//! Consulta o canister da bancada do Internet Computer, e confere de dentro
//! o que a consulta verificada promete — e o que ela **não** faz: dar
//! acesso.
//!
//! O programa lê as âncoras do TLS da bancada e as redes em que confia
//! (`/dados/icp/redes`), diz `icp: pronto` e espera um evento no canal
//! [`CANAL`] — ou, se outro `icp` já o escuta, diz `icp: pronto pelo
//! segundo canal` e espera no [`SEGUNDO_CANAL`]: dois processos ao mesmo
//! tempo, cada um ditado pelo seu. A cada evento [`tipo::ACAO`], o `a` diz o
//! passo, e o `b`, a rede — o índice em [`REDES`]. Cada passo é uma
//! conexão nova com o endpoint da rede, pelo caminho inteiro: o DNS, o
//! destino no gate, o TLS, os dois `POST` da consulta e a verificação.
//!
//! - [`OLA`]: o método `ola`, sem argumentos — a resposta é o texto `ola`;
//! - [`ECO`]: o método `eco`, com o texto `duke` — a resposta tem de ser
//!   ele;
//! - [`RECUSA`]: o método `recusa`, que o canister recusa: a recusa
//!   assinada pelos nós também é uma resposta verificada;
//! - [`CANDID`]: o método `candid_<c>` — `truncado`, `sobra`, `magica` —,
//!   que responde Candid fora da forma: verificado, e recusado na leitura;
//! - [`PRINCIPAL_INVALIDO`]: dois canisters que não são Principal — um
//!   texto fora da base32, e o da bancada com um caractere trocado, que se
//!   lê e tem o tamanho certo, mas a soma não confere: nada sai, e nada se
//!   declara;
//! - [`SAIR_SEM_FECHAR`]: sai sem fechar nada — o kernel recolhe as
//!   conexões de quem acabou;
//! - [`SIMBOLO`]: o símbolo do livro-razão do ICP ([`LIVRO_RAZAO`],
//!   `icrc1_symbol`) pela rede `mainnet` da imagem — a rede principal, com
//!   a raiz dela —, pelo caminho medido da fumaça real
//!   (`programas::icp::consultar_medindo`), com as âncoras públicas
//!   ([`PUBLICAS`], lidas no primeiro passo destes) e o DNS da suíte. Na
//!   suíte o nome nunca chega à rede principal: o DNS que mente, o mudo, o
//!   endereço fora da política — e o desfecho diz até onde foi. A linha diz
//!   também o destino que o nome deu e a medida da conexão;
//! - [`QUEM`], [`CONTAR`] e [`LENTO`]: as chamadas de atualização `quem`
//!   (o canister responde o Principal de quem chamou), `contar` (o
//!   contador, mais um) e `lento` (o que demora), do anônimo — com `c`
//!   zero — ou assinadas pela chave `c` de [`CHAVES`], que o kernel guarda
//!   para quem lançou o processo; com `c` de [`NA_RAIZ`] em diante, no
//!   canister [`DA_RAIZ`], o da sub-rede raiz, e a chave `c - NA_RAIZ`;
//! - [`RECUSA_NA_CHAMADA`]: o método `recusa` chamado como atualização —
//!   o canister recusa, e o certificado prova a recusa —, como as chamadas
//!   acima; e [`SEM_CANISTER`]: o `quem` de um canister que não existe na
//!   faixa provada — a recusa antes do consenso, sem prova nenhuma, que o
//!   programa diz à parte (`uncertified_reject`). A chamada pendente é
//!   acompanhada até [`icp::MAIS_LEITURAS`] vezes, cada leitura assinada de
//!   novo, com uma espera decidida pelo gate entre elas; antes de cada uma,
//!   o programa diz `icp: <passo> pendente <situação>`. Antes do desfecho
//!   de uma chamada que chegou ao fim, diz quem chamou — `icp: <passo>
//!   remetente <principal>` — e o que voltou — `icp: <passo> resposta
//!   <resposta>` —, cada um na sua linha: o Principal duas vezes não cabe
//!   numa;
//! - [`QUEM_CONSULTA`]: a consulta `quem_consulta` (o canister responde o
//!   Principal de quem consultou), do anônimo — com `c` zero — ou
//!   **assinada** pela chave `c` de [`CHAVES`] — uma assinatura, a da
//!   consulta —; com `c` de [`NA_RAIZ`] em diante, no canister
//!   [`DA_RAIZ`]. Diz quem consultou e o que voltou como a chamada, e a
//!   linha do desfecho também diz as assinaturas pedidas; a declaração é a
//!   da consulta, ancorada na decisão da assinatura — ou na conexão, do
//!   anônimo;
//! - [`QUEM_REPLICADA`]: a mesma `quem_consulta` pelo caminho da chamada —
//!   a **consulta replicada**: a resposta passa pelo consenso e vem
//!   certificada —, do anônimo ou assinada, como as chamadas acima, e
//!   declarada como uma.
//!
//! Antes de cada pedido, diz `icp: <passo> pede <etapa>` — `read_state` ou
//! `query`: a suíte sabe assim que o programa espera a resposta daquele
//! pedido, e age no meio da consulta. Depois de cada passo, diz
//! `icp: <passo>: <desfecho>; declarada
//! <registro>; hora <estado>; <detalhe>` — o desfecho numa palavra
//! (`programas::icp::desfecho`), o registro da declaração na auditoria —
//! ou o código de quem a recusou —, o estado do relógio com que conferiu,
//! e o que a verificação provou ou por que não provou. O detalhe vai por
//! último: uma linha passa de [`programas::saida::LINHA`] com o nome de um
//! nó, e o corte só come o fim. A declaração vai antes do fecho da
//! conexão: ancorada nela, o kernel escreve o destino real. Sai com
//! [`CODIGO`] quando a suíte pede o fim.
//!
//! # O que o programa não é
//!
//! O canister, o método, o Principal e o certificado não dão nada a este
//! processo: o que ele pode é o que o gate decide para os pedidos dele —
//! `fs.read`, `random.read`, `system.info`, `net.connect`,
//! `audit.declare`, `key.read` e `key.sign`, com a autoridade de quem o
//! lançou. Uma resposta verificada prova o que os nós responderam, e não
//! é `ALLOW` de nada; e a chave com que assina é de quem o lançou, no
//! espaço dele — o programa só sabe o nome.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "icp",
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
use programas::tls::{self, Ancoras};
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 93;

/// O código de saída de [`SAIR_SEM_FECHAR`].
const SEM_FECHAR: i64 = 94;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-icp";

/// O canal de um segundo `icp`, com o primeiro vivo.
const SEGUNDO_CANAL: &str = "teste-icp-2";

/// Os passos — a suíte tem as mesmas constantes.
const OLA: i64 = 1;
const ECO: i64 = 2;
const RECUSA: i64 = 3;
const CANDID: i64 = 4;
const PRINCIPAL_INVALIDO: i64 = 5;
const SAIR_SEM_FECHAR: i64 = 6;
const QUEM: i64 = 7;
const CONTAR: i64 = 8;
const LENTO: i64 = 9;
const RECUSA_NA_CHAMADA: i64 = 10;
const SEM_CANISTER: i64 = 11;
const SIMBOLO: i64 = 12;
const QUEM_CONSULTA: i64 = 13;
const QUEM_REPLICADA: i64 = 14;

/// As chaves de uma chamada assinada, pelo `c` de um evento — `c` zero é o
/// anônimo. Os nomes que a política padrão dá ao operador.
const CHAVES: [&str; 2] = ["chave:bancada", "chave:bancada-2"];

/// As redes, pelo índice que o `b` de um evento diz — os nomes de
/// `/dados/icp/redes`. As da bancada são o mesmo canister por um endpoint
/// que o proxy da bancada trata de um jeito: o honesto, o lento, e os que
/// adulteram a resposta, cada um de uma maneira; a de chave errada,
/// honesta e com outra raiz; e a honesta sem DNS. A última é a rede
/// principal.
const REDES: [&str; 14] = [
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
    "mainnet",
];

/// Os métodos que respondem Candid fora da forma, pelo `c` de um evento
/// [`CANDID`].
const FORA_DA_FORMA: [&str; 3] = ["candid_truncado", "candid_sobra", "candid_magica"];

/// O canister da bancada: o primeiro da primeira sub-rede de aplicação da
/// PocketIC — a bancada confere que é este (`xtask/src/icp.rs`).
const BANCADA: &str = "pi33i-pt777-77776-aaaaa-cai";

/// O mesmo módulo num canister da NNS, a sub-rede raiz: a prova da chamada
/// vem sem delegação, e as faixas, da leitura à parte de `["subnet"]` — a
/// bancada confere que é este (`xtask/src/icp.rs`).
const DA_RAIZ: &str = "xp3jw-ot777-77777-aaaaa-cai";

/// O `c` de uma chamada a partir do qual ela vai ao canister [`DA_RAIZ`]:
/// `c - NA_RAIZ` escolhe a chave como abaixo dele.
const NA_RAIZ: i64 = 10;

/// Os canisters que não são Principal, do passo [`PRINCIPAL_INVALIDO`]: um
/// fora da base32, e o da bancada com o vigésimo caractere trocado — um bit
/// dos bytes, e não do CRC nem da sobra da base32: a soma não confere, e é
/// só ela que o recusa.
const NAO_PRINCIPAIS: [&str; 2] = ["aaaaa-aa-nao-e-principal", "pi33i-pt777-77776-aaaab-cai"];

/// O canister seguinte ao da bancada, na faixa da mesma sub-rede, e que a
/// bancada não cria: a sub-rede é provada, e a chamada é recusada antes do
/// consenso — a recusa sem prova do passo [`SEM_CANISTER`].
const NAO_EXISTE: &str = "pp254-cl777-77776-aaaaq-cai";

/// O DNS da bancada da suíte.
const DNS: &str = "udp:10.0.2.53:53";

/// A raiz do TLS da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// As raízes públicas, na imagem: as da autoridade do endpoint da rede
/// principal.
const PUBLICAS: &str = "/dados/tls/publicas.pem";

/// O livro-razão do ICP, na sub-rede do NNS da rede principal.
const LIVRO_RAZAO: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";

/// Os argumentos de `ola`: nenhum.
fn sem_argumentos() -> Vec<u8> {
    Vec::from(*b"DIDL\x00\x00")
}

/// O que a verificação provou, curto — `prova <sub-rede> <delegada|da raiz>
/// <assinaturas>/<nós>: <resposta>`: a sub-rede pelo primeiro grupo do
/// texto dela, se assinou por delegação da raiz, as assinaturas de nó que
/// conferiram sobre os nós do certificado, e a resposta — ou por que o
/// Candid dela não se lê.
fn provado(v: &Verificada) -> String {
    let resposta = match &v.desfecho {
        Desfecho::Respondida(bytes) => match icp::candid::decodificar(bytes) {
            Ok(valores) => match valores.as_slice() {
                [Valor::Texto(t)] => format!("texto {t}"),
                outros => format!("{} valores", outros.len()),
            },
            Err(e) => format!("recusado: {e}"),
        },
        Desfecho::Recusada { codigo, erro, .. } => {
            format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-"))
        }
    };
    let texto = v.sub_rede.texto();
    format!(
        "prova {} {} {}/{}: {}",
        texto.split('-').next().unwrap_or(""),
        if v.delegada { "delegada" } else { "da raiz" },
        v.assinaturas,
        v.nos,
        resposta
    )
}

/// O [`icp::Gateway`] de um passo, que diz cada pedido antes de mandá-lo.
struct Narrado<'a> {
    gateway: &'a mut icp::Gateway,
    passo: &'a str,
}

impl icp::agente::Transporte for Narrado<'_> {
    type Erro = icp::Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), icp::Transporte> {
        let etapa = caminho.rsplit('/').next().unwrap_or(caminho);
        escreverln!("icp: {} pede {}", self.passo, etapa);
        self.gateway.post(caminho, corpo)
    }
}

/// O desfecho, com o Candid lido: uma resposta verificada que não se lê é
/// `verified_malformed` — a prova fechou, e o conteúdo não.
fn desfecho(r: &Result<Verificada, Falha>) -> &'static str {
    if let Ok(v) = r
        && let Desfecho::Respondida(bytes) = &v.desfecho
        && icp::candid::decodificar(bytes).is_err()
    {
        return "verified_malformed";
    }
    icp::desfecho(r)
}

/// Uma consulta pelo caminho inteiro, declarada antes do fecho: diz o
/// desfecho, a prova ou a falha, a hora e a declaração.
fn consultar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
) {
    let assunto = icp::assunto(canister, metodo);
    let hora = match icp::hora() {
        Ok(h) => h,
        Err(f) => {
            let r = Err(f);
            let declarada = icp::declarar(&assunto, icp::desfecho(&r), None);
            dizer(passo, &r, None, &declarada);
            return;
        }
    };
    let nonce = icp::nonce();
    let mut gateway = None;
    let r = nonce.and_then(|nonce| {
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        icp::consultar(&mut narrado, rede, canister, metodo, arg, &hora, &nonce)
    });
    let declarada = icp::declarar(
        &assunto,
        desfecho(&r),
        gateway.as_ref().map(icp::Gateway::conexao),
    );
    dizer(passo, &r, Some(hora.estado.nome()), &declarada);
    if let Some(g) = gateway {
        g.fechar();
    }
}

/// O símbolo do livro-razão pela rede `rede`, pelo caminho medido —
/// [`icp::consultar_medindo`] —, declarado antes do fecho: diz o desfecho
/// como os outros passos, e no detalhe o destino que o nome deu e a medida
/// da conexão, antes da prova ou da falha.
fn simbolo(passo: &str, rede: &Rede, ancoras: &Ancoras, livro: &Principal) {
    let c = icp::consultar_medindo(rede, ancoras, DNS, livro, "icrc1_symbol", &sem_argumentos());
    let m = &c.medida.conexao;
    let detalhe = match &c.r {
        Ok(v) => provado(v),
        Err(f) => format!("{f}"),
    };
    let declarada = match &c.declarada {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    };
    escreverln!(
        "icp: {}: {}; declarada {}; hora {}; destino {}; dns {} tcp {} tls {}; {}",
        passo,
        desfecho(&c.r),
        declarada,
        c.hora.map_or("nenhuma", |h| h.estado.nome()),
        m.destino.as_deref().unwrap_or("nenhum"),
        m.dns_ms,
        m.tcp_ms,
        m.tls_ms,
        detalhe
    );
}

/// O que uma resposta de chamada diz, curto: o Principal, o número ou o
/// texto do Candid — ou por que não se lê.
fn resposta_da_chamada(bytes: &[u8]) -> String {
    match icp::candid::decodificar(bytes) {
        Ok(valores) => match valores.as_slice() {
            [Valor::Principal(p)] => format!("principal {}", p.texto()),
            [Valor::Nat64(n)] => format!("nat64 {n}"),
            [Valor::Texto(t)] => format!("texto {t}"),
            outros => format!("{} valores", outros.len()),
        },
        Err(e) => format!("recusado: {e}"),
    }
}

/// O que o canister respondeu a uma chamada, curto: a resposta, a recusa
/// provada pelo certificado, a recusa sem prova, ou a situação em que a
/// chamada ficou.
fn resposta_do_andamento(andamento: &Andamento) -> String {
    match andamento {
        Andamento::Certificado { desfecho, .. } => match desfecho {
            Final::Respondida(bytes) => resposta_da_chamada(bytes),
            Final::Recusada { codigo, erro, .. } => {
                format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-"))
            }
            Final::Concluida => String::from("concluida"),
        },
        Andamento::RecusaNaoReplicada { codigo, erro, .. } => {
            format!(
                "recusa sem prova {codigo} {}",
                erro.as_deref().unwrap_or("-")
            )
        }
        Andamento::Pendente(s) => format!("pendente {s}"),
    }
}

/// O que uma chamada provou, curto — `prova <sub-rede> <delegada|da raiz>
/// leituras <n>`. Quem chamou e o que voltou vão antes, cada um na sua
/// linha: o Principal de quem chamou e a resposta do `quem` — o mesmo
/// Principal — não cabem juntos numa linha.
fn provado_da_chamada(a: &icp::Atualizacao, leituras: u32) -> String {
    let texto = a.faixas.sub_rede.texto();
    format!(
        "prova {} {} leituras {}",
        texto.split('-').next().unwrap_or(""),
        if a.faixas.delegada {
            "delegada"
        } else {
            "da raiz"
        },
        leituras
    )
}

/// Uma chamada de atualização pelo caminho inteiro — a chave lida, a
/// conexão, a chamada assinada, as leituras da situação enquanto
/// pendente —, declarada antes do fecho, ancorada na decisão da assinatura
/// da chamada; do anônimo, na conexão.
fn chamar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    canister: &Principal,
    metodo: &str,
    chave: Option<&str>,
) {
    let assunto = icp::assunto(canister, metodo);
    let arg = sem_argumentos();
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
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        let mut a = icp::chamar(
            &mut narrado,
            rede,
            kernel.as_mut(),
            canister,
            metodo,
            &arg,
            &hora,
            &nonce,
        )?;
        let mut andamento = a.andamento.clone();
        while let Andamento::Pendente(situacao) = andamento
            && leituras < icp::MAIS_LEITURAS
        {
            escreverln!("icp: {} pendente {}", passo, situacao);
            narrado.gateway.esperar(icp::ESPERA_ENTRE_LEITURAS_MS)?;
            let hora = icp::hora()?;
            leituras += 1;
            andamento = icp::acompanhar(&mut narrado, rede, kernel.as_mut(), &mut a, &hora)?;
        }
        Ok((a, andamento))
    })();
    let desfecho = icp::desfecho_da_chamada(r.as_ref().map(|(_, andamento)| andamento));
    let decisao = kernel.as_ref().and_then(|k| k.decisoes().first().copied());
    let ancora = match (decisao, gateway.as_ref()) {
        (Some(d), _) => Ancora::Decisao(d),
        (None, Some(g)) => Ancora::Conexao(g.conexao()),
        (None, None) => Ancora::Nenhuma,
    };
    let declarada = icp::declarar_chamada(&assunto, desfecho, ancora);
    let detalhe = match &r {
        Ok((a, andamento)) => {
            escreverln!("icp: {} remetente {}", passo, a.remetente.texto());
            escreverln!(
                "icp: {} resposta {}",
                passo,
                resposta_do_andamento(andamento)
            );
            provado_da_chamada(a, leituras)
        }
        Err(f) => format!("{f}"),
    };
    let declarada = match declarada {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    };
    let assinaturas = kernel.as_ref().map_or(0, |k| k.decisoes().len());
    escreverln!(
        "icp: {}: {}; declarada {}; hora {}; assinaturas {}; {}",
        passo,
        desfecho,
        declarada,
        hora_dita.unwrap_or("nenhuma"),
        assinaturas,
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
}

/// O que uma consulta de quem consultou provou, curto — `prova
/// <sub-rede> <delegada|da raiz> <assinaturas>/<nós>`. Quem consultou e o
/// que voltou vão antes, cada um na sua linha, como na chamada.
fn provado_da_consulta(v: &Verificada) -> String {
    let texto = v.sub_rede.texto();
    format!(
        "prova {} {} {}/{}",
        texto.split('-').next().unwrap_or(""),
        if v.delegada { "delegada" } else { "da raiz" },
        v.assinaturas,
        v.nos
    )
}

/// A consulta `quem_consulta` pelo caminho inteiro — do anônimo, ou
/// assinada pela `chave` do kernel: a pública lida por `key.read`, a
/// assinatura da consulta por `key.sign` —, declarada antes do fecho:
/// ancorada na decisão da assinatura; do anônimo, na conexão. Antes do
/// desfecho, diz quem consultou e o que voltou, cada um na sua linha, como
/// a chamada.
fn consultar_quem(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    canister: &Principal,
    chave: Option<&str>,
) {
    const METODO: &str = "quem_consulta";
    let assunto = icp::assunto(canister, METODO);
    let arg = sem_argumentos();
    let mut kernel = None;
    let mut gateway = None;
    let mut hora_dita = None;
    let r: Result<Verificada, Falha> = (|| {
        if let Some(nome) = chave {
            kernel = Some(ChaveDoKernel::ler(nome)?);
        }
        let hora = icp::hora()?;
        hora_dita = Some(hora.estado.nome());
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        match kernel.as_mut() {
            Some(k) => icp::consultar_assinada(
                &mut narrado,
                rede,
                k,
                canister,
                METODO,
                &arg,
                &hora,
                &nonce,
            ),
            None => icp::consultar(&mut narrado, rede, canister, METODO, &arg, &hora, &nonce),
        }
    })();
    let desfecho = match &r {
        Err(Falha::Chave(_) | Falha::Assinatura(_)) => icp::desfecho_da_consulta_assinada(&r),
        _ => desfecho(&r),
    };
    let decisao = kernel.as_ref().and_then(|k| k.decisoes().first().copied());
    let ancora = match (decisao, gateway.as_ref()) {
        (Some(d), _) => Ancora::Decisao(d),
        (None, Some(g)) => Ancora::Conexao(g.conexao()),
        (None, None) => Ancora::Nenhuma,
    };
    let declarada = icp::declarar_consulta(&assunto, desfecho, ancora);
    let detalhe = match &r {
        Ok(v) => {
            let remetente = kernel
                .as_ref()
                .map_or(Principal::ANONIMO, ChaveDoKernel::principal);
            escreverln!("icp: {} remetente {}", passo, remetente.texto());
            let resposta = match &v.desfecho {
                Desfecho::Respondida(bytes) => resposta_da_chamada(bytes),
                Desfecho::Recusada { codigo, erro, .. } => {
                    format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-"))
                }
            };
            escreverln!("icp: {} resposta {}", passo, resposta);
            provado_da_consulta(v)
        }
        Err(f) => format!("{f}"),
    };
    let declarada = match declarada {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    };
    let assinaturas = kernel.as_ref().map_or(0, |k| k.decisoes().len());
    escreverln!(
        "icp: {}: {}; declarada {}; hora {}; assinaturas {}; {}",
        passo,
        desfecho,
        declarada,
        hora_dita.unwrap_or("nenhuma"),
        assinaturas,
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
}

/// Diz o desfecho de um passo.
fn dizer(
    passo: &str,
    r: &Result<Verificada, Falha>,
    hora: Option<&str>,
    declarada: &icp::Declarada,
) {
    let detalhe = match r {
        Ok(v) => provado(v),
        Err(f) => format!("{f}"),
    };
    let declarada = match declarada {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    };
    escreverln!(
        "icp: {}: {}; declarada {}; hora {}; {}",
        passo,
        desfecho(r),
        declarada,
        hora.unwrap_or("nenhuma"),
        detalhe
    );
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
        escreverln!("icp: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("icp: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let redes = match icp::redes() {
        Ok(r) => r,
        Err(f) => {
            escreverln!("icp: as redes nao se leram: {}", f);
            return 3;
        }
    };
    let (Ok(bancada), Ok(da_raiz), Ok(nao_existe), Ok(livro)) = (
        Principal::de_texto(BANCADA),
        Principal::de_texto(DA_RAIZ),
        Principal::de_texto(NAO_EXISTE),
        Principal::de_texto(LIVRO_RAZAO),
    ) else {
        escreverln!("icp: o canister da bancada nao se le");
        return 4;
    };
    if segundo {
        escreverln!("icp: pronto pelo segundo canal ({} redes)", redes.len());
    } else {
        escreverln!("icp: pronto ({} redes)", redes.len());
    }

    // As públicas só no primeiro passo da rede principal: os outros não as
    // leem.
    let mut publicas: Option<Ancoras> = None;
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("icp: a leitura do canal falhou: {}", e);
                return 5;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("icp: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            let nome = usize::try_from(e.b)
                .ok()
                .and_then(|i| REDES.get(i))
                .copied()
                .unwrap_or("?");
            let rede = redes.iter().find(|r| r.nome == nome);
            match (e.a, rede) {
                (SAIR_SEM_FECHAR, _) => {
                    escreverln!("icp: saindo sem fechar");
                    return SEM_FECHAR;
                }
                (PRINCIPAL_INVALIDO, _) => {
                    // Nada sai, e nada se declara: o Principal não se lê.
                    let ditos: Vec<String> = NAO_PRINCIPAIS
                        .iter()
                        .map(|texto| match Principal::de_texto(texto) {
                            Ok(_) => String::from("aceito"),
                            Err(e) => format!("recusado: {e}"),
                        })
                        .collect();
                    escreverln!("icp: principal invalido: {}", ditos.join("; "));
                }
                (_, None) => {
                    escreverln!("icp: rede {} nao esta no arquivo", nome);
                }
                (QUEM | CONTAR | LENTO | RECUSA_NA_CHAMADA | SEM_CANISTER, Some(rede)) => {
                    let metodo = match e.a {
                        QUEM | SEM_CANISTER => "quem",
                        CONTAR => "contar",
                        LENTO => "lento",
                        _ => "recusa",
                    };
                    let (canister, c, onde) = if e.a == SEM_CANISTER {
                        (&nao_existe, e.c, " sem canister")
                    } else if e.c >= NA_RAIZ {
                        (&da_raiz, e.c - NA_RAIZ, " raiz")
                    } else {
                        (&bancada, e.c, "")
                    };
                    let chave = usize::try_from(c)
                        .ok()
                        .and_then(|i| i.checked_sub(1))
                        .and_then(|i| CHAVES.get(i))
                        .copied();
                    let passo = format!("{metodo} {nome}{onde} {}", chave.unwrap_or("anonimo"));
                    chamar(&passo, rede, &ancoras, canister, metodo, chave);
                }
                (QUEM_CONSULTA | QUEM_REPLICADA, Some(rede)) => {
                    let (canister, c, onde) = if e.c >= NA_RAIZ {
                        (&da_raiz, e.c - NA_RAIZ, " raiz")
                    } else {
                        (&bancada, e.c, "")
                    };
                    let chave = usize::try_from(c)
                        .ok()
                        .and_then(|i| i.checked_sub(1))
                        .and_then(|i| CHAVES.get(i))
                        .copied();
                    let quem = chave.unwrap_or("anonimo");
                    if e.a == QUEM_CONSULTA {
                        let passo = format!("quem_consulta {nome}{onde} {quem}");
                        consultar_quem(&passo, rede, &ancoras, canister, chave);
                    } else {
                        let passo = format!("replicada {nome}{onde} {quem}");
                        chamar(&passo, rede, &ancoras, canister, "quem_consulta", chave);
                    }
                }
                (SIMBOLO, Some(rede)) => {
                    let passo = format!("simbolo {nome}");
                    let lidas = match publicas.take() {
                        Some(a) => Ok(a),
                        None => tls::ancoras(PUBLICAS),
                    };
                    match lidas {
                        Ok(a) => {
                            simbolo(&passo, rede, &a, &livro);
                            publicas = Some(a);
                        }
                        Err(f) => {
                            escreverln!("icp: as ancoras publicas nao se leram: {}", f.codigo());
                        }
                    }
                }
                (OLA, Some(rede)) => {
                    let passo = format!("ola {nome}");
                    consultar(&passo, rede, &ancoras, &bancada, "ola", &sem_argumentos());
                }
                (ECO, Some(rede)) => {
                    let passo = format!("eco {nome}");
                    let arg = icp::candid::codificar(&[Valor::Texto(String::from("duke"))])
                        .unwrap_or_default();
                    consultar(&passo, rede, &ancoras, &bancada, "eco", &arg);
                }
                (RECUSA, Some(rede)) => {
                    let passo = format!("recusa {nome}");
                    consultar(
                        &passo,
                        rede,
                        &ancoras,
                        &bancada,
                        "recusa",
                        &sem_argumentos(),
                    );
                }
                (CANDID, Some(rede)) => {
                    let metodo = usize::try_from(e.c)
                        .ok()
                        .and_then(|i| FORA_DA_FORMA.get(i))
                        .copied()
                        .unwrap_or("candid_truncado");
                    let passo = format!("{metodo} {nome}");
                    consultar(&passo, rede, &ancoras, &bancada, metodo, &sem_argumentos());
                }
                (outro, _) => {
                    escreverln!("icp: passo {} desconhecido", outro);
                }
            }
        }
    }
}
