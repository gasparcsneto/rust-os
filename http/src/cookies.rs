//! Os cookies: o estado que um servidor pede ao cliente para guardar e
//! mandar de volta — a RFC 6265, com o que a 6265bis tornou norma: os
//! prefixos `__Secure-` e `__Host-`, o `Secure` que só uma origem cifrada
//! escreve, e o `SameSite`.
//!
//! # De quem é
//!
//! Do **programa**. O [`Pote`] é um valor do processo que conversa, na
//! memória dele: o kernel não o vê, a política não o nomeia, o gate não o
//! consulta, e ele acaba com o processo. Outro programa — e outra pessoa,
//! outro agente, outra sessão, que são sempre outro processo — não tem como
//! lê-lo: o isolamento é o da memória do processo, que o kernel já faz, e
//! não uma regra nova. Nem o mesmo programa divide: dois potes são dois
//! estados, e um pedido sem pote não leva cookie nenhum.
//!
//! Um cookie não é credencial do Duke. É um texto que um servidor deu e
//! que volta para ele: prova alguma coisa **ao servidor** — uma sessão lá —
//! e nada aqui. O que o programa pode na rede é o que o gate decide para os
//! pedidos dele, com a autoridade de quem o lançou, e um cookie não muda
//! isso nem para mais nem para menos: a revogação, a contenção e o firewall
//! valem no pedido seguinte, leve ele cookie ou não — o pedido recusado nem
//! sai. E um servidor não muda a autoridade de ninguém: o `Set-Cookie` vira
//! uma linha neste pote, e mais nada.
//!
//! # O que o pote guarda, e o que recusa
//!
//! - **O nome e o valor**: o nome não vazio, nenhum controle além da
//!   tabulação, e os dois juntos com até [`LimitesDoPote::por_cookie`]
//!   bytes. O valor volta como veio.
//! - **O domínio.** Sem `Domain`, o cookie é só do host que o deu. Com ele,
//!   do domínio e dos subdomínios — se o host está nele: `a.duke` não
//!   escreve para `b.duke`. Sem a lista de sufixos públicos, um domínio de
//!   um rótulo só (`duke`, `com`) é recusado, a menos que seja o próprio
//!   host; e um host por endereço só tem cookie dele mesmo.
//! - **O caminho**: o do `Path`, ou o diretório do pedido; o cookie vai
//!   aos pedidos dali para baixo.
//! - **`Secure`**: só uma origem `https` o escreve, e ele só vai por
//!   `https`. Uma origem clara também não sobrescreve um cookie seguro de
//!   mesmo nome — nem por um caminho de dentro do dele.
//! - **`HttpOnly`**: o valor não sai do pote para o programa. Vai ao
//!   servidor, e só: [`Pote::visiveis`] não o mostra, [`Pote::definir`] não
//!   o cria nem o sobrescreve, e a troca com o pote tira os `Set-Cookie`
//!   dos cabeçalhos da resposta, como o `fetch` de um navegador os esconde
//!   do script.
//! - **`SameSite`**: `Strict`, `Lax` ou `None` — e o cookie sem o atributo
//!   vale como `Lax`. `None` só com `Secure`. O pedido diz de onde parte
//!   ([`Contexto`]): o programa pedindo por conta dele, o caso comum, leva
//!   todos; um pedido que sai do conteúdo de outro site — um link, um
//!   formulário, um redirecionamento que o programa segue — não leva os
//!   `Strict`, e os `Lax` só numa navegação por método seguro. É a defesa
//!   de um agente que segue instruções de uma página de outro site: o
//!   pedido que ele faz por ela não carrega a sessão que o programa tem
//!   aqui.
//! - **Os prefixos**: `__Secure-` só com `Secure`; `__Host-` com `Secure`,
//!   sem `Domain` e com `Path=/`.
//! - **A validade**: `Max-Age` antes de `Expires`, e nenhuma além de 400
//!   dias. A que já passou apaga o cookie de mesmo nome, domínio e
//!   caminho. Sem validade, o cookie é da sessão — do processo.
//!
//! # O relógio
//!
//! A validade é contada no tempo do sistema, em segundos desde 1970 — no
//! programa, o mesmo `system.info` do TLS, pelo gate. O relógio só é lido
//! quando um cookie com validade está em jogo, e uma vez por troca
//! ([`Agora`]): um programa sem cookies não paga nada. Sem relógio, a
//! validade não se confere: um cookie novo com validade fica de sessão — o
//! valor novo substitui o velho, e nada sobrevive ao processo —, e um
//! guardado com validade não vai, porque não há como saber se venceu.
//!
//! # Os limites
//!
//! O pote não cresce na vontade do servidor ([`LimitesDoPote`]): um teto
//! por cookie, por domínio, de cookies e de bytes. Acima dele, saem
//! primeiro os vencidos, depois os do domínio que passou do teto, depois
//! quaisquer — sempre o usado há mais tempo primeiro.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::pedido::Metodo;
use crate::url::{Esquema, Host, Url};

/// O atributo `SameSite` de um cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MesmoSite {
    /// `Strict`: só em pedidos do próprio site.
    Estrito,
    /// `Lax` — e o cookie sem o atributo, ou com um valor desconhecido:
    /// também na navegação que parte de outro site, por método seguro.
    Frouxo,
    /// `None`: em qualquer pedido — e só com `Secure`.
    Livre,
}

/// De onde o pedido parte, para o `SameSite`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Contexto {
    /// O programa pede por conta dele: o caso comum, e o padrão.
    #[default]
    DoProprioSite,
    /// O pedido sai do conteúdo de outro site — um link, um formulário, um
    /// redirecionamento que o programa segue. `navegacao` quando é ir até
    /// lá, e não buscar um pedaço para a página de outro.
    DeOutroSite { navegacao: bool },
}

/// Por que um `Set-Cookie` não entrou no pote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Sem `=`, com o nome vazio, ou com um controle no nome ou no valor.
    Formato,
    /// O nome e o valor passam de [`LimitesDoPote::por_cookie`].
    Grande,
    /// O `Domain` não contém o host, é um rótulo só, ou não é o endereço
    /// do host.
    Dominio,
    /// `Secure` de uma origem clara, ou uma origem clara sobrescrevendo um
    /// cookie seguro.
    Seguro,
    /// `HttpOnly` pela API do programa — criar, ou sobrescrever.
    SoHttp,
    /// `SameSite=None` sem `Secure`, ou um `Strict`/`Lax` vindo de um
    /// pedido de outro site que não é navegação.
    MesmoSite,
    /// `__Secure-` sem `Secure`, ou `__Host-` sem `Secure`, com `Domain` ou
    /// sem `Path=/`.
    Prefixo,
}

/// O que um `Set-Cookie` aceito fez.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guardado {
    Novo,
    /// Tomou o lugar do de mesmo nome, domínio e caminho — e herdou dele a
    /// ordem de criação.
    Substituido,
    /// A validade já tinha passado: o de mesmo nome, domínio e caminho, se
    /// havia, saiu.
    Apagado,
}

/// As contas do pote numa troca: o que ele fez com os `Set-Cookie` da
/// resposta, e os cookies que o pedido não levou porque o relógio não se
/// leu.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Guardados {
    pub novos: u32,
    pub substituidos: u32,
    pub apagados: u32,
    pub recusados: u32,
    /// Os cookies com validade que iam no pedido e ficaram no pote: sem o
    /// relógio — recusado pelo gate, ou sem relógio no sistema —, não há
    /// como saber se venceram. O servidor só vê que eles não vieram; quem
    /// chama vê aqui por quê.
    pub retidos: u32,
}

/// Os tetos do pote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitesDoPote {
    /// O nome e o valor de um cookie, juntos, em bytes.
    pub por_cookie: usize,
    /// Quantos cookies cada domínio pode ter.
    pub por_dominio: usize,
    /// Quantos cookies o pote pode ter.
    pub total: usize,
    /// Quantos bytes — nomes, valores, domínios e caminhos — o pote pode
    /// ter.
    pub bytes: usize,
}

impl Default for LimitesDoPote {
    fn default() -> LimitesDoPote {
        LimitesDoPote {
            por_cookie: 4096,
            por_dominio: 50,
            total: 300,
            bytes: 128 * 1024,
        }
    }
}

/// O valor de um atributo além disto é ignorado (6265bis).
const MAIOR_ATRIBUTO: usize = 1024;

/// Nenhuma validade passa disto: 400 dias (6265bis).
pub const MAIOR_VALIDADE: u64 = 400 * 24 * 60 * 60;

/// O tempo de agora, em segundos desde 1970, lido de quem chama só quando
/// um cookie com validade está em jogo — e uma vez só.
pub struct Agora<'a> {
    ler: &'a mut dyn FnMut() -> Option<u64>,
    lido: Option<Option<u64>>,
}

impl<'a> Agora<'a> {
    /// O tempo que `ler` dá; `None` é a falta de relógio.
    pub fn de(ler: &'a mut dyn FnMut() -> Option<u64>) -> Agora<'a> {
        Agora { ler, lido: None }
    }

    /// O tempo de agora, lido na primeira vez.
    fn valor(&mut self) -> Option<u64> {
        if let Some(v) = self.lido {
            return v;
        }
        let v = (self.ler)();
        self.lido = Some(v);
        v
    }

    /// O tempo, se já foi lido.
    fn se_lido(&self) -> Option<u64> {
        self.lido.flatten()
    }
}

/// Um cookie no pote.
#[derive(Clone)]
struct Cookie {
    nome: String,
    valor: String,
    dominio: String,
    /// Só o host de [`Cookie::dominio`], e não os subdomínios dele.
    so_o_host: bool,
    caminho: String,
    /// Até quando vale, em segundos desde 1970: o cookie com isto em
    /// `t` venceu em qualquer tempo `>= t`. `None`: o da sessão.
    expira: Option<u64>,
    seguro: bool,
    so_http: bool,
    mesmo_site: MesmoSite,
    /// A ordem de criação e a do último uso, numa conta do pote.
    criado: u64,
    usado: u64,
}

/// O valor não aparece — nem num `{:?}` do pote: ele vai para o fio, e não
/// para o log nem para o programa.
impl core::fmt::Debug for Cookie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cookie")
            .field("nome", &self.nome)
            .field("valor", &format_args!("<{} bytes>", self.valor.len()))
            .field("dominio", &self.dominio)
            .field("so_o_host", &self.so_o_host)
            .field("caminho", &self.caminho)
            .field("expira", &self.expira)
            .field("seguro", &self.seguro)
            .field("so_http", &self.so_http)
            .field("mesmo_site", &self.mesmo_site)
            .field("criado", &self.criado)
            .field("usado", &self.usado)
            .finish()
    }
}

impl Cookie {
    fn bytes(&self) -> usize {
        self.nome.len() + self.valor.len() + self.dominio.len() + self.caminho.len()
    }

    fn vencido(&self, agora: u64) -> bool {
        self.expira.is_some_and(|t| t <= agora)
    }
}

/// A validade de um `Set-Cookie`, como veio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Validade {
    /// `Max-Age`, em segundos — zero ou menos apaga.
    Segundos(i64),
    /// `Expires`, em segundos desde 1970 — zero para antes disso.
    Data(u64),
}

/// Um `Set-Cookie` lido, antes do pote.
#[derive(Debug)]
struct Lido<'a> {
    nome: &'a str,
    valor: &'a str,
    max_age: Option<i64>,
    expires: Option<u64>,
    dominio: Option<String>,
    caminho: Option<&'a str>,
    seguro: bool,
    so_http: bool,
    /// `None` com o atributo explícito, para conferir o `Secure` dele.
    mesmo_site: MesmoSite,
    livre_explicito: bool,
}

impl Lido<'_> {
    fn validade(&self) -> Option<Validade> {
        // O `Max-Age` vence o `Expires`, em qualquer ordem.
        match (self.max_age, self.expires) {
            (Some(s), _) => Some(Validade::Segundos(s)),
            (None, Some(t)) => Some(Validade::Data(t)),
            (None, None) => None,
        }
    }
}

/// O espaço em volta de um nome, de um valor e de um atributo.
const BRANCO: [char; 2] = [' ', '\t'];

/// Um byte que pode estar num nome ou num valor de cookie: nenhum controle
/// além da tabulação.
fn permitido(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7f)
}

/// Lê um `Set-Cookie` (RFC 6265, 5.2).
fn ler(linha: &str, por_cookie: usize) -> Result<Lido<'_>, Recusa> {
    let (par, atributos) = match linha.find(';') {
        Some(i) => (&linha[..i], &linha[i + 1..]),
        None => (linha, ""),
    };
    let igual = par.find('=').ok_or(Recusa::Formato)?;
    let nome = par[..igual].trim_matches(BRANCO);
    let valor = par[igual + 1..].trim_matches(BRANCO);
    if nome.is_empty() || !nome.bytes().chain(valor.bytes()).all(permitido) {
        return Err(Recusa::Formato);
    }
    if nome.len() + valor.len() > por_cookie {
        return Err(Recusa::Grande);
    }
    let mut lido = Lido {
        nome,
        valor,
        max_age: None,
        expires: None,
        dominio: None,
        caminho: None,
        seguro: false,
        so_http: false,
        mesmo_site: MesmoSite::Frouxo,
        livre_explicito: false,
    };
    for atributo in atributos.split(';') {
        let (n, v) = match atributo.find('=') {
            Some(i) => (&atributo[..i], &atributo[i + 1..]),
            None => (atributo, ""),
        };
        let (n, v) = (n.trim_matches(BRANCO), v.trim_matches(BRANCO));
        if v.len() > MAIOR_ATRIBUTO {
            continue;
        }
        // De cada um, vale o último.
        if n.eq_ignore_ascii_case("expires") {
            if let Some(t) = data(v) {
                lido.expires = Some(t);
            }
        } else if n.eq_ignore_ascii_case("max-age") {
            if let Some(s) = max_age(v) {
                lido.max_age = Some(s);
            }
        } else if n.eq_ignore_ascii_case("domain") {
            // Vazio, o atributo não diz nada.
            if !v.is_empty() {
                lido.dominio = Some(v.strip_prefix('.').unwrap_or(v).to_ascii_lowercase());
            }
        } else if n.eq_ignore_ascii_case("path") {
            lido.caminho = v.starts_with('/').then_some(v);
        } else if n.eq_ignore_ascii_case("secure") {
            lido.seguro = true;
        } else if n.eq_ignore_ascii_case("httponly") {
            lido.so_http = true;
        } else if n.eq_ignore_ascii_case("samesite") {
            lido.livre_explicito = v.eq_ignore_ascii_case("none");
            lido.mesmo_site = if v.eq_ignore_ascii_case("strict") {
                MesmoSite::Estrito
            } else if lido.livre_explicito {
                MesmoSite::Livre
            } else {
                MesmoSite::Frouxo
            };
        }
    }
    Ok(lido)
}

/// O `Max-Age`: um inteiro, com o sinal. Fora disso, o atributo não vale.
fn max_age(v: &str) -> Option<i64> {
    let (negativo, digitos) = match v.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, v),
    };
    if digitos.is_empty() || !digitos.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = digitos.bytes().fold(0i64, |n, b| {
        n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
    });
    Some(if negativo { -n } else { n })
}

/// Um delimitador de data de cookie (RFC 6265, 5.1.1).
fn delimitador(b: u8) -> bool {
    b == 0x09
        || (0x20..=0x2f).contains(&b)
        || (0x3b..=0x40).contains(&b)
        || (0x5b..=0x60).contains(&b)
        || (0x7b..=0x7e).contains(&b)
}

/// Os dígitos do começo de `t`, se são de `min` a `max` — e o resto, que
/// então começa por um não dígito.
fn digitos(t: &[u8], min: usize, max: usize) -> Option<(u32, &[u8])> {
    let n = t.iter().take_while(|b| b.is_ascii_digit()).count();
    if n < min || n > max {
        return None;
    }
    let valor = t[..n]
        .iter()
        .fold(0u32, |v, &b| v * 10 + u32::from(b - b'0'));
    Some((valor, &t[n..]))
}

/// `hms-time`: `h:m:s`, cada um com um ou dois dígitos.
fn hora(t: &[u8]) -> Option<(u32, u32, u32)> {
    let (h, r) = digitos(t, 1, 2)?;
    let r = r.strip_prefix(b":")?;
    let (m, r) = digitos(r, 1, 2)?;
    let r = r.strip_prefix(b":")?;
    let (s, _) = digitos(r, 1, 2)?;
    Some((h, m, s))
}

/// O mês pelas três primeiras letras, sem caixa.
fn mes(t: &[u8]) -> Option<u32> {
    const MESES: [&[u8; 3]; 12] = [
        b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov",
        b"dec",
    ];
    let tres = t.get(..3)?;
    MESES
        .iter()
        .position(|m| tres.eq_ignore_ascii_case(*m))
        .map(|i| i as u32 + 1)
}

fn bissexto(ano: i64) -> bool {
    (ano % 4 == 0 && ano % 100 != 0) || ano % 400 == 0
}

fn dias_no_mes(ano: i64, mes: u32) -> u32 {
    match mes {
        2 if bissexto(ano) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Os dias de 1970-01-01 até `ano-mes-dia`, no calendário gregoriano.
fn dias_desde_1970(ano: i64, mes: u32, dia: u32) -> i64 {
    let ano = if mes <= 2 { ano - 1 } else { ano };
    let era = if ano >= 0 { ano } else { ano - 399 } / 400;
    let do_ciclo = ano - era * 400;
    let mes_de_marco = (i64::from(mes) + 9) % 12;
    let do_ano = (153 * mes_de_marco + 2) / 5 + i64::from(dia) - 1;
    let do_ciclo_em_dias = do_ciclo * 365 + do_ciclo / 4 - do_ciclo / 100 + do_ano;
    era * 146_097 + do_ciclo_em_dias - 719_468
}

/// Uma data de cookie (RFC 6265, 5.1.1), em segundos desde 1970 — zero
/// para antes disso. `None` para o que não é uma data que existe.
pub(crate) fn data(texto: &str) -> Option<u64> {
    let mut hms = None;
    let mut dia = None;
    let mut mes_ = None;
    let mut ano = None;
    for token in texto
        .as_bytes()
        .split(|&b| delimitador(b))
        .filter(|t| !t.is_empty())
    {
        if hms.is_none()
            && let Some(t) = hora(token)
        {
            hms = Some(t);
        } else if dia.is_none()
            && let Some((d, _)) = digitos(token, 1, 2)
        {
            dia = Some(d);
        } else if mes_.is_none()
            && let Some(m) = mes(token)
        {
            mes_ = Some(m);
        } else if ano.is_none()
            && let Some((a, _)) = digitos(token, 2, 4)
        {
            ano = Some(i64::from(a));
        }
    }
    let ((h, m, s), dia, mes_, mut ano) = (hms?, dia?, mes_?, ano?);
    if (70..=99).contains(&ano) {
        ano += 1900;
    } else if (0..=69).contains(&ano) {
        ano += 2000;
    }
    if !(1..=31).contains(&dia) || ano < 1601 || h > 23 || m > 59 || s > 59 {
        return None;
    }
    if dia > dias_no_mes(ano, mes_) {
        return None;
    }
    let segundos = dias_desde_1970(ano, mes_, dia) * 86_400
        + i64::from(h) * 3600
        + i64::from(m) * 60
        + i64::from(s);
    Some(u64::try_from(segundos).unwrap_or(0))
}

/// O host da URL como o cookie o guarda, e se é um endereço.
fn host_da(url: &Url) -> (String, bool) {
    match &url.host {
        Host::Nome(n) => (n.clone(), false),
        Host::Ipv4([a, b, c, d]) => (format!("{a}.{b}.{c}.{d}"), true),
    }
}

/// O caminho da URL, sem a consulta.
fn caminho_da(url: &Url) -> &str {
    url.alvo.split('?').next().unwrap_or("/")
}

/// `host` está em `dominio` (RFC 6265, 5.1.3): é ele, ou um nome abaixo
/// dele — `a.b.duke` está em `b.duke`, e `ab.duke` não.
fn domina(host: &str, dominio: &str, host_e_endereco: bool) -> bool {
    host == dominio
        || (!host_e_endereco
            && host.len() > dominio.len()
            && host.ends_with(dominio)
            && host.as_bytes()[host.len() - dominio.len() - 1] == b'.')
}

/// Sem a lista de sufixos públicos: um domínio de um rótulo só é de todo
/// mundo.
fn publico(dominio: &str) -> bool {
    !dominio.contains('.')
}

/// O caminho de um pedido está no de um cookie (RFC 6265, 5.1.4).
fn caminho_casa(pedido: &str, cookie: &str) -> bool {
    pedido == cookie
        || (pedido.starts_with(cookie)
            && (cookie.ends_with('/') || pedido.as_bytes()[cookie.len()] == b'/'))
}

/// O caminho padrão de um cookie: o diretório do caminho do pedido.
fn caminho_padrao(caminho: &str) -> String {
    match caminho.rfind('/') {
        Some(i) if i > 0 && caminho.starts_with('/') => String::from(&caminho[..i]),
        _ => String::from("/"),
    }
}

fn comeca_sem_caixa(texto: &str, prefixo: &str) -> bool {
    texto
        .get(..prefixo.len())
        .is_some_and(|c| c.eq_ignore_ascii_case(prefixo))
}

/// Um método que não muda nada no servidor.
fn seguro(metodo: Metodo) -> bool {
    matches!(metodo, Metodo::Get | Metodo::Head)
}

/// Os cookies de um programa — ver o cabeçalho do módulo.
#[derive(Clone, Debug)]
pub struct Pote {
    cookies: Vec<Cookie>,
    limites: LimitesDoPote,
    /// A conta da ordem de criação e de uso.
    conta: u64,
}

impl Default for Pote {
    fn default() -> Pote {
        Pote::novo()
    }
}

impl Pote {
    /// Um pote vazio, com os limites padrão.
    pub fn novo() -> Pote {
        Pote::com_limites(LimitesDoPote::default())
    }

    /// Um pote vazio com `limites`.
    pub fn com_limites(limites: LimitesDoPote) -> Pote {
        Pote {
            cookies: Vec::new(),
            limites,
            conta: 0,
        }
    }

    /// Quantos cookies o pote tem — vencidos inclusive, até a próxima vez
    /// que o relógio for lido.
    pub fn quantos(&self) -> usize {
        self.cookies.len()
    }

    /// Os bytes que o pote ocupa: nomes, valores, domínios e caminhos.
    pub fn bytes(&self) -> usize {
        self.cookies.iter().map(Cookie::bytes).sum()
    }

    /// Esvazia o pote.
    pub fn limpar(&mut self) {
        self.cookies.clear();
    }

    /// Os `Set-Cookie` dos `cabecalhos` da resposta a um pedido de `url`
    /// feito em `contexto`. Só a troca com o pote chama — ver
    /// [`crate::Cliente::trocar_com_pote`]: é o único caminho por onde um
    /// `HttpOnly` entra.
    pub(crate) fn guardar(
        &mut self,
        url: &Url,
        contexto: Contexto,
        cabecalhos: &[(String, String)],
        agora: &mut Agora<'_>,
    ) -> Guardados {
        let mut contas = Guardados::default();
        for (_, valor) in cabecalhos.iter().filter(|(n, _)| n == "set-cookie") {
            match self.guardar_um(url, contexto, valor, agora) {
                Ok(Guardado::Novo) => contas.novos += 1,
                Ok(Guardado::Substituido) => contas.substituidos += 1,
                Ok(Guardado::Apagado) => contas.apagados += 1,
                Err(_) => contas.recusados += 1,
            }
        }
        contas
    }

    /// Um `Set-Cookie` vindo pela rede, de `url`, em `contexto`.
    pub(crate) fn guardar_um(
        &mut self,
        url: &Url,
        contexto: Contexto,
        set_cookie: &str,
        agora: &mut Agora<'_>,
    ) -> Result<Guardado, Recusa> {
        let lido = ler(set_cookie, self.limites.por_cookie)?;
        self.armazenar(lido, url, contexto, true, agora)
    }

    /// Põe um cookie pela API do programa, como se `set_cookie` viesse de
    /// `url` — e com as regras dela: nada de `HttpOnly`, criar ou
    /// sobrescrever.
    pub fn definir(
        &mut self,
        url: &Url,
        set_cookie: &str,
        agora: &mut Agora<'_>,
    ) -> Result<Guardado, Recusa> {
        let lido = ler(set_cookie, self.limites.por_cookie)?;
        self.armazenar(lido, url, Contexto::DoProprioSite, false, agora)
    }

    /// O valor do `Cookie` de um pedido `metodo` a `url`, em `contexto` —
    /// `None` sem cookie nenhum —, e quantos ficaram de fora sem o relógio
    /// (ver [`Guardados::retidos`]). Leva os `HttpOnly`: só a troca com o
    /// pote chama, e o valor vai para o fio, e não para o programa.
    pub(crate) fn cabecalho(
        &mut self,
        url: &Url,
        metodo: Metodo,
        contexto: Contexto,
        agora: &mut Agora<'_>,
    ) -> (Option<String>, u32) {
        let (escolhidos, retidos) = self.escolher(url, metodo, contexto, true, agora);
        if escolhidos.is_empty() {
            return (None, retidos);
        }
        let mut cabecalho = String::new();
        for (n, &i) in escolhidos.iter().enumerate() {
            if n > 0 {
                cabecalho.push_str("; ");
            }
            let c = &self.cookies[i];
            cabecalho.push_str(&c.nome);
            cabecalho.push('=');
            cabecalho.push_str(&c.valor);
        }
        (Some(cabecalho), retidos)
    }

    /// Os nomes e valores que um pedido do próprio site a `url` levaria,
    /// sem os `HttpOnly`: o que o programa pode ver.
    pub fn visiveis(&mut self, url: &Url, agora: &mut Agora<'_>) -> Vec<(String, String)> {
        self.escolher(url, Metodo::Get, Contexto::DoProprioSite, false, agora)
            .0
            .into_iter()
            .map(|i| (self.cookies[i].nome.clone(), self.cookies[i].valor.clone()))
            .collect()
    }

    /// Os índices dos cookies que vão a um pedido, na ordem do cabeçalho:
    /// o caminho mais longo primeiro, e o mais antigo primeiro entre os de
    /// caminho igual (RFC 6265, 5.4). Marca o uso deles. E quantos iriam,
    /// mas têm validade e o relógio não se leu.
    fn escolher(
        &mut self,
        url: &Url,
        metodo: Metodo,
        contexto: Contexto,
        pela_rede: bool,
        agora: &mut Agora<'_>,
    ) -> (Vec<usize>, u32) {
        let (host, endereco) = host_da(url);
        let caminho = caminho_da(url);
        let cifrado = url.esquema == Esquema::Https;
        let vai = |c: &Cookie| {
            let dominio = if c.so_o_host {
                host == c.dominio
            } else {
                domina(&host, &c.dominio, endereco)
            };
            let mesmo_site = match contexto {
                Contexto::DoProprioSite => true,
                Contexto::DeOutroSite { navegacao } => match c.mesmo_site {
                    MesmoSite::Livre => true,
                    MesmoSite::Frouxo => navegacao && seguro(metodo),
                    MesmoSite::Estrito => false,
                },
            };
            dominio
                && caminho_casa(caminho, &c.caminho)
                && (cifrado || !c.seguro)
                && (pela_rede || !c.so_http)
                && mesmo_site
        };
        // O relógio só é lido se um dos que iriam tem validade.
        if self.cookies.iter().any(|c| vai(c) && c.expira.is_some())
            && let Some(a) = agora.valor()
        {
            self.cookies.retain(|c| !c.vencido(a));
        }
        let sem_relogio = agora.se_lido().is_none();
        let mut retidos = 0;
        let mut escolhidos: Vec<usize> = Vec::new();
        for (i, c) in self.cookies.iter().enumerate() {
            if !vai(c) {
                continue;
            }
            // Sem relógio, a validade não se confere: não vai.
            if sem_relogio && c.expira.is_some() {
                retidos += 1;
            } else {
                escolhidos.push(i);
            }
        }
        escolhidos.sort_by(|&a, &b| {
            let (a, b) = (&self.cookies[a], &self.cookies[b]);
            b.caminho
                .len()
                .cmp(&a.caminho.len())
                .then(a.criado.cmp(&b.criado))
        });
        for &i in &escolhidos {
            self.conta += 1;
            self.cookies[i].usado = self.conta;
        }
        (escolhidos, retidos)
    }

    /// O modelo de armazenamento (RFC 6265, 5.3; 6265bis, 5.7) para um
    /// `Set-Cookie` lido de `url`, pela rede ou pela API do programa.
    fn armazenar(
        &mut self,
        lido: Lido<'_>,
        url: &Url,
        contexto: Contexto,
        pela_rede: bool,
        agora: &mut Agora<'_>,
    ) -> Result<Guardado, Recusa> {
        let (host, endereco) = host_da(url);
        let cifrado = url.esquema == Esquema::Https;
        let (dominio, so_o_host) = match &lido.dominio {
            None => (host.clone(), true),
            Some(d) if endereco => {
                // Um endereço só tem cookie dele mesmo.
                if *d != host {
                    return Err(Recusa::Dominio);
                }
                (host.clone(), true)
            }
            Some(d) if !domina(&host, d, false) => return Err(Recusa::Dominio),
            Some(d) if publico(d) => {
                if *d != host {
                    return Err(Recusa::Dominio);
                }
                (host.clone(), true)
            }
            Some(d) => (d.clone(), false),
        };
        let caminho = match lido.caminho {
            Some(c) => String::from(c),
            None => caminho_padrao(caminho_da(url)),
        };
        if lido.seguro && !cifrado {
            return Err(Recusa::Seguro);
        }
        if lido.so_http && !pela_rede {
            return Err(Recusa::SoHttp);
        }
        if lido.livre_explicito && !lido.seguro {
            return Err(Recusa::MesmoSite);
        }
        if contexto == (Contexto::DeOutroSite { navegacao: false })
            && lido.mesmo_site != MesmoSite::Livre
        {
            return Err(Recusa::MesmoSite);
        }
        if comeca_sem_caixa(lido.nome, "__secure-") && !lido.seguro {
            return Err(Recusa::Prefixo);
        }
        if comeca_sem_caixa(lido.nome, "__host-")
            && (!lido.seguro || lido.dominio.is_some() || lido.caminho != Some("/"))
        {
            return Err(Recusa::Prefixo);
        }
        // Uma origem clara não sobrescreve um cookie seguro de mesmo nome —
        // nem por um caminho dentro do dele (6265bis, 5.7).
        if !lido.seguro
            && !cifrado
            && self.cookies.iter().any(|e| {
                e.seguro
                    && e.nome == lido.nome
                    && (domina(&e.dominio, &dominio, endereco)
                        || domina(&dominio, &e.dominio, endereco))
                    && caminho_casa(&caminho, &e.caminho)
            })
        {
            return Err(Recusa::Seguro);
        }
        // A validade: o que já passou apaga; sem relógio, o cookie fica de
        // sessão.
        let expira = match lido.validade() {
            None => None,
            Some(Validade::Segundos(s)) if s <= 0 => Some(0),
            Some(v) => agora.valor().map(|a| match v {
                Validade::Segundos(s) => a.saturating_add((s as u64).min(MAIOR_VALIDADE)),
                Validade::Data(t) => t.min(a.saturating_add(MAIOR_VALIDADE)),
            }),
        };
        let vencido = match expira {
            Some(0) => true,
            Some(t) => agora.se_lido().is_some_and(|a| t <= a),
            None => false,
        };
        let antigo = self.cookies.iter().position(|e| {
            e.nome == lido.nome
                && e.dominio == dominio
                && e.so_o_host == so_o_host
                && e.caminho == caminho
        });
        let criado = match antigo {
            Some(i) => {
                if self.cookies[i].so_http && !pela_rede {
                    return Err(Recusa::SoHttp);
                }
                Some(self.cookies.remove(i).criado)
            }
            None => None,
        };
        if vencido {
            return Ok(Guardado::Apagado);
        }
        self.conta += 1;
        self.cookies.push(Cookie {
            nome: String::from(lido.nome),
            valor: String::from(lido.valor),
            dominio,
            so_o_host,
            caminho,
            expira,
            seguro: lido.seguro,
            so_http: lido.so_http,
            mesmo_site: lido.mesmo_site,
            criado: criado.unwrap_or(self.conta),
            usado: self.conta,
        });
        self.aparar(agora.se_lido());
        Ok(if criado.is_some() {
            Guardado::Substituido
        } else {
            Guardado::Novo
        })
    }

    /// Volta aos limites: os vencidos saem, depois os do domínio que passou
    /// do teto, depois quaisquer — o usado há mais tempo primeiro.
    fn aparar(&mut self, agora: Option<u64>) {
        if let Some(a) = agora {
            self.cookies.retain(|c| !c.vencido(a));
        }
        let limites = self.limites;
        loop {
            let de_quem_passou = (0..self.cookies.len())
                .filter(|&i| {
                    let d = &self.cookies[i].dominio;
                    self.cookies.iter().filter(|c| c.dominio == *d).count() > limites.por_dominio
                })
                .min_by_key(|&i| self.cookies[i].usado);
            match de_quem_passou {
                Some(i) => {
                    self.cookies.remove(i);
                }
                None => break,
            }
        }
        while self.cookies.len() > limites.total || self.bytes() > limites.bytes {
            let Some(i) = (0..self.cookies.len()).min_by_key(|&i| self.cookies[i].usado) else {
                break;
            };
            self.cookies.remove(i);
        }
    }
}
