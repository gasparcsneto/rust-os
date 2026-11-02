//! O fluxo da malha, do lado do programa: abrir um canal ordenado de bytes
//! contra um endpoint que oferece uma intenção, aceitar o que chega a um
//! endpoint seu, escrever, ler, terminar e fechar.
//!
//! # O que é, daqui
//!
//! A entrega da malha ([`crate::malha`]) leva um texto curto, de uma vez. O
//! fluxo leva bytes, quantos forem, na ordem: quem quer mandar um arquivo
//! inteiro **abre** um fluxo contra o endpoint de quem o recebe — o mesmo
//! endpoint que `fabric.offer` abriu —, o dono o **aceita**, e os dois
//! escrevem e leem, cada um no seu sentido. Cada sentido termina sozinho
//! ([`Fluxo::terminar`]); [`Fluxo::fechar`] larga o fluxo.
//!
//! Cada passo é um comando do gate — `stream.open`, `stream.accept`,
//! `stream.write`, `stream.read`, `stream.finish`, `stream.close`,
//! `stream.status` —, com a autoridade de quem lançou o processo, o
//! manifesto dele declarando `fabric.stream` e a intenção como recurso
//! enumerado na política. Escrever e ler são o plano de dados: decididos e
//! gravados um a um, sem gastar a taxa do papel, e por isso todo pedido de
//! dados daqui leva `wait` — com a auditoria cheia, o kernel o segura em
//! vez de cobrar a taxa.
//!
//! # O que o kernel garante, e este módulo não precisa conferir
//!
//! - **Quem está do outro lado** é o processo que o kernel conferiu — o
//!   nome do manifesto, o resumo da imagem, o editor ([`Origem`]) —, ou o
//!   outro Duke, pela relação, com o programa que ele atesta.
//! - **A ordem**: os bytes saem na ordem em que entraram, sem buraco e sem
//!   repetição — ou o fluxo acaba, com o motivo.
//! - **Nenhuma autoridade viaja.** O que se lê é entrada não confiável; o
//!   que o programa faz com ela é decidido pelo papel dele.
//!
//! # Como se usa
//!
//! ```ignore
//! use programas::fluxo;
//!
//! // Quem recebe, no endpoint que ofereceu:
//! if let Some((f, de)) = fluxo::aceitar(&endpoint, 10_000)? {
//!     let (bytes, fim) = f.ler(16 * 1024, 10_000)?;
//! }
//!
//! // Quem manda:
//! let f = fluxo::abrir(&candidato.endpoint, "imagem.compartilhar")?;
//! f.escrever_tudo(&arquivo, 10_000, 3)?;
//! f.terminar()?;
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::nativo::{self, Json, Resposta};

/// O maior pedaço de uma escrita e de uma leitura: o buffer de um sentido.
pub const MAIOR_PEDACO: usize = 16 * 1024;

/// O `wait` dos pedidos "agora": um milissegundo — um tique, no máximo —,
/// só para o kernel poder segurar o pedido de dados com o caminho da
/// auditoria cheio, em vez de cobrar a taxa do papel.
const ESPERA_MINIMA_MS: u64 = 1;

/// O que não coube no fluxo, esperando espaço: quem escreve junta aqui, e
/// escoa quando o laço avisa `GRAVAVEL`. É o que desfaz o impasse dos dois
/// sentidos — cada lado escreve o que cabe e volta a ler, sem dormir numa
/// escrita.
#[derive(Clone, Debug, Default)]
pub struct EscritaPendente {
    pendente: Vec<u8>,
    /// Onde começa o que ainda não foi: o que já foi escrito fica antes,
    /// até o próximo [`EscritaPendente::juntar`] o descartar — sem mover
    /// o resto a cada escrita.
    inicio: usize,
}

impl EscritaPendente {
    /// Nada pendente.
    pub const fn nova() -> EscritaPendente {
        EscritaPendente {
            pendente: Vec::new(),
            inicio: 0,
        }
    }

    /// Junta `dados` ao que espera.
    pub fn juntar(&mut self, dados: &[u8]) {
        if self.inicio > 0 {
            self.pendente.drain(..self.inicio);
            self.inicio = 0;
        }
        self.pendente.extend_from_slice(dados);
    }

    /// Escreve no fluxo o que couber, sem esperar. `true` quando não sobrou
    /// nada; `false` quando o buffer encheu — o aviso diz quando seguir.
    pub fn escoar(&mut self, f: &Fluxo) -> Result<bool, Falha> {
        while self.inicio < self.pendente.len() {
            let n = f.escrever_agora(&self.pendente[self.inicio..])?;
            if n == 0 {
                return Ok(false);
            }
            self.inicio += n;
        }
        self.pendente.clear();
        self.inicio = 0;
        Ok(true)
    }

    /// Quantos bytes esperam.
    pub fn tamanho(&self) -> usize {
        self.pendente.len() - self.inicio
    }

    /// Se não há nada esperando.
    pub fn vazia(&self) -> bool {
        self.tamanho() == 0
    }
}

/// Por que um passo do fluxo não aconteceu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Falha {
    /// A chamada de sistema falhou: o pedido nem chegou ao gate.
    Chamada(i64),
    /// O gate, ou o fluxo, recusou: o código — `DENY_PERMISSION`,
    /// `DENY_RESOURCE`, `CONFLICT`… — e o motivo. Um fluxo que acabou
    /// responde `CONFLICT` com o motivo do fim.
    Recusa { codigo: String, motivo: String },
    /// A resposta não tem a forma esperada.
    Resposta,
    /// O outro lado não andou no prazo: nada entrou, nada chegou.
    Prazo,
}

impl Falha {
    /// O código da recusa, ou o que aconteceu, em uma palavra.
    pub fn codigo(&self) -> &str {
        match self {
            Falha::Chamada(_) => "CHAMADA",
            Falha::Recusa { codigo, .. } => codigo,
            Falha::Resposta => "RESPOSTA",
            Falha::Prazo => "PRAZO",
        }
    }

    /// O motivo, se veio um.
    pub fn motivo(&self) -> &str {
        match self {
            Falha::Recusa { motivo, .. } => motivo,
            _ => "",
        }
    }
}

/// Quem abriu um fluxo, como o kernel daqui o diz: o programa e o resumo da
/// imagem — conferidos —, ou o dispositivo, pela relação, com o programa
/// que ele atesta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origem {
    pub programa: Option<(String, String)>,
    pub dispositivo: Option<String>,
}

impl Origem {
    /// Quem abriu, numa linha: o dispositivo — `dispositivo:<nome>` — ou o
    /// programa e o começo do resumo da imagem dele.
    pub fn descrever(&self) -> String {
        match (&self.dispositivo, &self.programa) {
            (Some(d), _) => d.clone(),
            (None, Some((p, r))) => alloc::format!("{p} {}", &r[..r.len().min(8)]),
            (None, None) => String::from("?"),
        }
    }
}

/// O estado de um fluxo, como `stream.status` o diz.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Estado {
    /// `pending`, `open` ou `closed`.
    pub estado: String,
    /// O motivo do fim, se acabou.
    pub motivo: Option<String>,
    pub escritos: u64,
    pub lidos: u64,
}

/// O `result` de uma resposta, ou a recusa — a do gate, que vem como erro do
/// envelope, ou a do fluxo, que vem como `ok: false`.
fn resultado(r: &Resposta) -> Result<Json<'_>, Falha> {
    match r.resultado() {
        Ok(res) if res.member("ok").and_then(|v| v.as_bool()) == Some(true) => Ok(res),
        Ok(res) => Err(Falha::Recusa {
            codigo: texto(res, "code").unwrap_or_default(),
            motivo: texto(res, "error").unwrap_or_default(),
        }),
        Err(recusa) => Err(Falha::Recusa {
            codigo: String::from(recusa.motivo.unwrap_or("ERROR")),
            motivo: String::from(recusa.mensagem),
        }),
    }
}

/// Um campo de texto, desescapado.
fn texto(j: Json, campo: &str) -> Option<String> {
    let v = j.member(campo)?;
    let mut claro = alloc::vec![0u8; v.0.len()];
    v.desescapar_em(&mut claro).map(String::from)
}

fn pedir(
    metodo: &str,
    params: impl FnOnce(&mut nativo::JsonWriter) -> core::fmt::Result,
) -> Result<Resposta, Falha> {
    nativo::pedir(metodo, params).map_err(Falha::Chamada)
}

/// Um fluxo aberto daqui, ou aceito: o id que o kernel deu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fluxo {
    id: String,
}

/// O fluxo de uma resposta de abertura.
fn do_resultado(r: &Resposta) -> Result<Fluxo, Falha> {
    let res = resultado(r)?;
    Ok(Fluxo {
        id: texto(res, "stream").ok_or(Falha::Resposta)?,
    })
}

/// Abre um fluxo contra o `endpoint` daqui que oferece `intencao`. O fluxo
/// nasce pedido: escrever com espera aguarda o aceite.
pub fn abrir(endpoint: &str, intencao: &str) -> Result<Fluxo, Falha> {
    let r = pedir("stream.open", |w| {
        w.field_str("endpoint", endpoint)?;
        w.field_str("intent", intencao)
    })?;
    do_resultado(&r)
}

/// Abre um fluxo contra o `endpoint` de outro Duke — `dispositivo`, como o
/// registro daqui o chama —, que oferece `intencao`. Decidido aqui, com
/// `fabric.remote` sobre ele, e lá, pelo gate de lá.
pub fn abrir_no_par(dispositivo: &str, endpoint: &str, intencao: &str) -> Result<Fluxo, Falha> {
    let r = pedir("stream.open", |w| {
        w.field_str("endpoint", endpoint)?;
        w.field_str("intent", intencao)?;
        w.field_str("device", dispositivo)
    })?;
    do_resultado(&r)
}

/// [`abrir`], com o aviso da ponta no canal do `laco`: a abertura chega
/// como `GRAVAVEL`, e depois o dado, o espaço e o fim.
pub fn abrir_avisando(
    endpoint: &str,
    intencao: &str,
    laco: &crate::laco::Laco,
) -> Result<Fluxo, Falha> {
    let r = pedir("stream.open", |w| {
        w.field_str("endpoint", endpoint)?;
        w.field_str("intent", intencao)?;
        w.field_u64("notify", laco.descritor())
    })?;
    do_resultado(&r)
}

/// [`abrir_no_par`], com o aviso da ponta daqui no canal do `laco`. O aviso
/// é deste Duke: o de lá avisa o programa de lá.
pub fn abrir_no_par_avisando(
    dispositivo: &str,
    endpoint: &str,
    intencao: &str,
    laco: &crate::laco::Laco,
) -> Result<Fluxo, Falha> {
    let r = pedir("stream.open", |w| {
        w.field_str("endpoint", endpoint)?;
        w.field_str("intent", intencao)?;
        w.field_str("device", dispositivo)?;
        w.field_u64("notify", laco.descritor())
    })?;
    do_resultado(&r)
}

/// Aceita o pedido mais antigo no `endpoint` seu, esperando até `espera_ms`
/// por um. `None` se nenhum chegou.
pub fn aceitar(endpoint: &str, espera_ms: u64) -> Result<Option<(Fluxo, Origem)>, Falha> {
    aceitar_com(endpoint, espera_ms, None)
}

/// Aceita o pedido mais antigo no `endpoint` seu, sem esperar — o aviso do
/// laço disse que há um —, com o aviso da ponta aceita no canal do `laco`.
/// `None` se outro evento o levou antes.
pub fn aceitar_avisando(
    endpoint: &str,
    laco: &crate::laco::Laco,
) -> Result<Option<(Fluxo, Origem)>, Falha> {
    aceitar_com(endpoint, 0, Some(laco.descritor()))
}

fn aceitar_com(
    endpoint: &str,
    espera_ms: u64,
    aviso: Option<u64>,
) -> Result<Option<(Fluxo, Origem)>, Falha> {
    let r = pedir("stream.accept", |w| {
        w.field_str("endpoint", endpoint)?;
        if espera_ms > 0 {
            w.field_u64("wait", espera_ms)?;
        }
        if let Some(d) = aviso {
            w.field_u64("notify", d)?;
        }
        Ok(())
    })?;
    let res = resultado(&r)?;
    let Some(id) = texto(res, "stream") else {
        return Ok(None);
    };
    let de = res.member("from").ok_or(Falha::Resposta)?;
    let origem = Origem {
        programa: texto(de, "program").zip(texto(de, "digest")),
        dispositivo: texto(de, "device"),
    };
    Ok(Some((Fluxo { id }, origem)))
}

impl Fluxo {
    /// O fluxo de um id que o kernel deu.
    pub fn de(id: String) -> Fluxo {
        Fluxo { id }
    }

    /// O id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// O número do id — o que o aviso do laço leva.
    pub fn numero(&self) -> Option<u64> {
        crate::laco::numero_do_id(&self.id)
    }

    /// Lê o que já chegou, até `max`, sem esperar dado: o aviso do laço
    /// disse que há. Vazio e sem fim, se outro evento o levou antes. Leva o
    /// `wait` mínimo — o dos pedidos de dados, para o caminho da auditoria
    /// cheio segurar em vez de cobrar a taxa.
    pub fn ler_agora(&self, max: usize) -> Result<(Vec<u8>, bool), Falha> {
        self.ler(max, ESPERA_MINIMA_MS)
    }

    /// Escreve o que couber de `dados`, sem esperar espaço. Zero com o
    /// buffer cheio: o aviso `GRAVAVEL` vem quando houver espaço.
    pub fn escrever_agora(&self, dados: &[u8]) -> Result<usize, Falha> {
        self.escrever(dados, ESPERA_MINIMA_MS)
    }

    /// Escreve o que couber de `dados`, até [`MAIOR_PEDACO`], esperando
    /// até `espera_ms` por espaço — ou pelo aceite. Devolve quantos entraram.
    pub fn escrever(&self, dados: &[u8], espera_ms: u64) -> Result<usize, Falha> {
        let fim = dados.len().min(MAIOR_PEDACO);
        let r = nativo::pedir_com_anexo(
            "stream.write",
            |w| {
                w.field_str("stream", &self.id)?;
                w.field_u64("wait", espera_ms)
            },
            &dados[..fim],
        )
        .map_err(Falha::Chamada)?;
        let res = resultado(&r)?;
        res.member("written")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .ok_or(Falha::Resposta)
    }

    /// Escreve `dados` inteiros, em pedaços. `esperas` esperas seguidas sem
    /// nada entrar são o prazo: o outro lado não lê.
    pub fn escrever_tudo(&self, dados: &[u8], espera_ms: u64, esperas: usize) -> Result<(), Falha> {
        let mut feito = 0;
        let mut vazias = 0;
        while feito < dados.len() {
            let n = self.escrever(&dados[feito..], espera_ms)?;
            if n == 0 {
                vazias += 1;
                if vazias >= esperas {
                    return Err(Falha::Prazo);
                }
            } else {
                vazias = 0;
            }
            feito += n;
        }
        Ok(())
    }

    /// Lê até `max` bytes, esperando até `espera_ms` por algum. Devolve os
    /// bytes e se o sentido terminou depois deles.
    pub fn ler(&self, max: usize, espera_ms: u64) -> Result<(Vec<u8>, bool), Falha> {
        let r = pedir("stream.read", |w| {
            w.field_str("stream", &self.id)?;
            w.field_u64("max", max.min(MAIOR_PEDACO) as u64)?;
            w.field_u64("wait", espera_ms)
        })?;
        let res = resultado(&r)?;
        let fim = res.member("end").and_then(|v| v.as_bool()) == Some(true);
        let bytes = nativo::conteudo(&r).ok_or(Falha::Resposta)?;
        Ok((bytes, fim))
    }

    /// Lê até o fim, em `destino`, até `teto` bytes. `esperas` esperas
    /// seguidas sem nada chegar são o prazo.
    pub fn ler_tudo(
        &self,
        destino: &mut Vec<u8>,
        teto: usize,
        espera_ms: u64,
        esperas: usize,
    ) -> Result<(), Falha> {
        let mut vazias = 0;
        loop {
            let (bytes, fim) = self.ler(MAIOR_PEDACO, espera_ms)?;
            if bytes.is_empty() && !fim {
                vazias += 1;
                if vazias >= esperas {
                    return Err(Falha::Prazo);
                }
            } else {
                vazias = 0;
            }
            if destino.len() + bytes.len() > teto {
                return Err(Falha::Resposta);
            }
            destino.extend_from_slice(&bytes);
            if fim {
                return Ok(());
            }
        }
    }

    /// Termina o sentido daqui: quem lê recebe o resto e o fim.
    pub fn terminar(&self) -> Result<(), Falha> {
        let r = pedir("stream.finish", |w| w.field_str("stream", &self.id))?;
        resultado(&r).map(|_| ())
    }

    /// Fecha o fluxo para este programa: o que escreveu continua legível do
    /// outro lado; o que não leu sai.
    pub fn fechar(&self) -> Result<(), Falha> {
        let r = pedir("stream.close", |w| w.field_str("stream", &self.id))?;
        resultado(&r).map(|_| ())
    }

    /// O estado do fluxo.
    pub fn estado(&self) -> Result<Estado, Falha> {
        let r = pedir("stream.status", |w| w.field_str("stream", &self.id))?;
        let res = resultado(&r)?;
        Ok(Estado {
            estado: texto(res, "state").ok_or(Falha::Resposta)?,
            motivo: texto(res, "reason"),
            escritos: res.member("written").and_then(|v| v.as_u64()).unwrap_or(0),
            lidos: res.member("read").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }
}

/// O byte `i` do padrão determinístico das bancadas, com a `semente` de
/// cada sentido — a ida com 0, a volta com 1 —: quem lê confere o resumo do
/// que chegou contra o mesmo padrão, e a bancada também.
pub fn padrao(semente: u8, i: usize) -> u8 {
    (((i * 7 + 3) % 251) as u8).wrapping_add(semente)
}

/// O FNV-1a de 64 bits, somado pedaço a pedaço: o resumo do que passou
/// por um sentido, sem guardar os bytes.
#[derive(Clone, Copy, Debug)]
pub struct Resumo(u64);

impl Resumo {
    /// O resumo de nada.
    pub const fn novo() -> Resumo {
        Resumo(0xcbf2_9ce4_8422_2325)
    }

    /// Soma `bytes`, na ordem.
    pub fn somar(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    /// O valor de agora.
    pub fn valor(&self) -> u64 {
        self.0
    }
}

impl Default for Resumo {
    fn default() -> Resumo {
        Resumo::novo()
    }
}
