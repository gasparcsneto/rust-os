//! O HTTP/2 (RFC 9113): vários pedidos ao mesmo tempo numa conexão só.
//!
//! # O que é, e o que não é
//!
//! Um protocolo do programa, como o HTTP/1.1 ([`crate::Cliente`]): roda
//! dentro do processo, sobre a conexão que o gate decidiu. O kernel não sabe
//! de quadro, de corrente, de janela nem de HPACK — vê os bytes de uma
//! conexão TCP indo para um destino que a política enumera, e, com TLS, nem
//! os bytes. Nada daqui é autorização: as correntes de uma conexão são todas
//! do mesmo processo, com a autoridade de quem o lançou, e cada `net.send` e
//! cada `net.recv` da conexão continua decidido pelo gate. A recusa de um
//! deles acaba com a conexão inteira, e cada corrente que esperava ouve a
//! recusa como veio ([`Erro::Baixo`]).
//!
//! # Como se chega aqui
//!
//! Quem escolhe é quem chama: com `https`, pelo ALPN do TLS — o servidor
//! escolhe `h2` ou `http/1.1`; com `http`, só com conhecimento prévio — quem
//! chama sabe que o servidor fala HTTP/2, e começa por ele. Sem `Upgrade:
//! h2c`, que a RFC 9113 tirou. Um servidor que não fala HTTP/2 responde
//! outra coisa que não o prefácio dele, e a conexão acaba com
//! [`Motivo::Prefacio`].
//!
//! # Um fio só
//!
//! Os quadros só são lidos quando quem chama espera alguma coisa: a resposta
//! de uma corrente ([`ClienteH2::receber`]), ou a janela para mandar o corpo
//! de um pedido ([`ClienteH2::enviar`]). O que chega para as outras correntes
//! enquanto isso fica guardado com elas.
//!
//! # A contrapressão, e a memória
//!
//! Cada corrente tem a janela dela ([`AjustesH2::janela`]): o servidor manda
//! até ali e espera. A janela de uma corrente só reabre quando ela é
//! esperada — e reabre de uma vez até o limite do corpo dela —; a da
//! conexão reabre conforme chega. Uma corrente que ninguém lê segura só a
//! janela dela, e não trava as outras; a memória da conexão é a soma das
//! janelas das correntes paradas e do corpo da esperada, cada um com o teto
//! dele.
//!
//! # As falhas: da corrente, e da conexão
//!
//! - **da corrente**: o servidor a reiniciou ([`Erro::Reiniciada`]) ou não a
//!   processou ([`Erro::Recusada`]); a resposta veio malformada, ou passou
//!   de um limite — este lado manda `RST_STREAM`. Só aquela corrente falha;
//! - **da conexão**: um quadro que a RFC recusa, um bloco de cabeça que não
//!   se decodifica, o controle de fluxo violado, quadros sem progresso
//!   demais — este lado manda `GOAWAY` —; o `GOAWAY` do servidor com erro
//!   ([`Erro::Encerrada`]); o servidor que fecha ([`Erro::Fechada`]); a falha
//!   de baixo, como veio. Todas as correntes que esperavam falham com o
//!   mesmo erro, e a conexão não leva mais pedidos ([`Erro::Esgotada`]). As
//!   que já tinham a resposta inteira continuam com ela: o que chegou antes
//!   da falha chegou.
//!
//! # O que fica de fora
//!
//! O *push* — desligado no prefácio, e um `PUSH_PROMISE` acaba com a
//! conexão —, a prioridade — lida e ignorada —, o `CONNECT` estendido e o
//! `Upgrade`. E nada deste lado entra na tabela dinâmica do servidor: o
//! primeiro bloco da conexão diz que ela tem zero bytes (ver o módulo
//! `hpack`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::cliente::Fluxo;
use crate::codificacao::{self, Aceitas};
use crate::cookies::{Agora, Contexto, Guardados, Pote};
use crate::erro::{Erro, Limite, Motivo};
use crate::hpack::{Campo, Codificador, Decodificador, Representacao};
use crate::pedido::{Metodo, Pedido, tchar};
use crate::quadro::{
    self, CABECA, CodigoH2, ErroDeQuadro, JANELA_MAXIMA, JANELA_PADRAO, QUADRO_MAXIMO,
    QUADRO_PADRAO, Quadro, ajuste, bandeira, tipo,
};
use crate::resposta::{self, Enquadramento, LEITURA, Limites, MAIS_INFORMATIVAS, Resposta, Versao};
use crate::url::{Esquema, Url};

/// A tabela dinâmica que este lado decodifica: a padrão da RFC 7541, que
/// por isso não se anuncia.
const TABELA: usize = 4096;

/// A janela da conexão que este lado mantém aberta: o servidor manda até
/// isto sem esperar, e ela reabre quando passa da metade. Não é ela que
/// segura a memória — são as janelas das correntes —, então pode ser larga:
/// um `WINDOW_UPDATE` da conexão fica raro.
const JANELA_DA_CONEXAO: i64 = 1 << 24;

/// Quantos quadros seguidos sem levar resposta nenhuma adiante se aceitam:
/// `PING`, `SETTINGS`, quadros vazios, desconhecidos ou de correntes
/// largadas. Um servidor de verdade não chega perto disso.
const MAIS_PARADOS: u32 = 1024;

/// Quantos `CONTINUATION` um bloco de cabeça pode ter.
const MAIS_CONTINUACOES: usize = 64;

/// O maior número de corrente.
const MAIOR_CORRENTE: u32 = (1 << 31) - 1;

/// Os cabeçalhos da conexão, que o HTTP/2 não tem (RFC 9113, 8.2.2): uma
/// resposta com um deles é malformada.
const DA_CONEXAO: [&[u8]; 5] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// O número de cada conexão do processo: uma [`Corrente`] só é entregue à
/// conexão que a abriu.
static CONEXOES: AtomicU32 = AtomicU32::new(0);

/// O que a conexão anuncia ao servidor, e quanto ela guarda.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AjustesH2 {
    /// Quantas correntes a conexão guarda ao mesmo tempo: as abertas, e as
    /// que já acabaram e ainda não foram recebidas. O servidor pode aceitar
    /// menos (`SETTINGS_MAX_CONCURRENT_STREAMS`).
    pub correntes: usize,
    /// A janela inicial de cada corrente (`SETTINGS_INITIAL_WINDOW_SIZE`):
    /// quanto da resposta de uma corrente que ninguém está esperando o
    /// servidor manda antes de parar. É o que uma corrente parada segura de
    /// memória.
    pub janela: u32,
    /// A maior cabeça que se anuncia (`SETTINGS_MAX_HEADER_LIST_SIZE`),
    /// contada como o HPACK conta. Cada corrente tem a dos [`Limites`]
    /// dela; um bloco de cabeça que chega com mais que o dobro da maior das
    /// duas, antes de decodificado, acaba com a conexão.
    pub lista: u32,
}

impl Default for AjustesH2 {
    fn default() -> AjustesH2 {
        AjustesH2 {
            correntes: 16,
            janela: 64 * 1024,
            lista: Limites::default().cabeca as u32,
        }
    }
}

/// Uma corrente aberta por [`ClienteH2::enviar`]: o que se entrega a
/// [`ClienteH2::receber`] para ter a resposta, ou a [`ClienteH2::cancelar`]
/// para largá-la. Não se copia — cada corrente é recebida ou cancelada uma
/// vez só —, e só vale na conexão que a abriu.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "uma corrente que ninguém recebe nem cancela ocupa a conexão"]
pub struct Corrente {
    conexao: u32,
    numero: u32,
}

impl Corrente {
    /// O número da corrente na conexão: 1, 3, 5...
    pub fn numero(&self) -> u32 {
        self.numero
    }
}

/// Até onde a resposta de uma corrente chegou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fase {
    /// Esperando a cabeça final; as informativas (1xx) passam.
    Cabeca,
    /// A cabeça chegou; o corpo e talvez os *trailers* vêm.
    Corpo,
    /// O servidor acabou a corrente (`END_STREAM`).
    Fim,
}

/// Uma corrente da conexão. `E` é o erro da conexão.
struct Estado<E> {
    numero: u32,
    metodo: Metodo,
    aceitas: Aceitas,
    limites: Limites,
    /// Para o pote: de onde e em que contexto o pedido saiu, quantos
    /// cookies ficaram de fora sem o relógio, e o que o relógio deu.
    url: Url,
    contexto: Contexto,
    retidos: u32,
    relogio: Option<Option<u64>>,
    fase: Fase,
    informativas: usize,
    status: u16,
    cabecalhos: Vec<(String, String)>,
    /// O `Content-Length`, conferido contra os `DATA`.
    declarado: Option<u64>,
    corpo: Vec<u8>,
    /// A falha da corrente — dela, ou da conexão. Com ela, o que ainda
    /// chegar para a corrente é descartado.
    erro: Option<E>,
    /// Quanto o servidor ainda pode mandar nesta corrente.
    recebe: i64,
    /// Quanto deste lado ainda cabe na janela do servidor.
    envia: i64,
    /// Este lado não manda mais nada na corrente: o `END_STREAM` saiu, ou
    /// um `RST_STREAM` de qualquer um dos lados a fechou.
    mandou_tudo: bool,
    /// O servidor mandou o `END_STREAM` — mesmo que o quadro que o trouxe
    /// tenha sido recusado.
    fim_recebido: bool,
}

impl<E> Estado<E> {
    /// A corrente acabou dos dois lados: não conta no limite de correntes
    /// do servidor, e nada mais vai nela.
    fn fechada(&self) -> bool {
        self.erro.is_some() || (self.mandou_tudo && self.fase == Fase::Fim)
    }

    /// A corrente ainda espera quadros do servidor.
    fn esperando(&self) -> bool {
        self.erro.is_none() && self.fase != Fase::Fim
    }

    /// A resposta não tem conteúdo (RFC 9110, 6.4.1): a de um `HEAD`, um
    /// `204` ou um `304`.
    fn sem_conteudo(&self) -> bool {
        self.metodo == Metodo::Head || self.status == 204 || self.status == 304
    }

    /// Falha a corrente com `erro`. O que ela guardava vai embora.
    fn falhar(&mut self, erro: E) {
        self.erro = Some(erro);
        self.mandou_tudo = true;
        self.corpo = Vec::new();
        self.cabecalhos = Vec::new();
    }
}

/// Um bloco de cabeça em curso: o `HEADERS` e os `CONTINUATION` que vierem.
struct Bloco {
    corrente: u32,
    cru: Vec<u8>,
    fim_da_corrente: bool,
    continuacoes: usize,
    teto: usize,
}

/// Onde uma corrente está para a conexão.
enum Onde {
    /// Nunca aberta: um número que este lado ainda não usou, ou um par —
    /// o servidor não abre correntes.
    Ociosa,
    /// Aberta e já largada: recebida, ou cancelada. O que chega para ela é
    /// descartado.
    Largada,
    /// Na conexão, neste índice.
    Aqui(usize),
}

/// Uma conexão HTTP/2. `F::Falha` se clona: a falha de baixo vai para cada
/// corrente que esperava.
pub struct ClienteH2<F: Fluxo> {
    fluxo: F,
    serie: u32,
    ajustes: AjustesH2,
    /// O que chegou e ainda não fechou um quadro.
    entrada: Vec<u8>,
    /// O que vai na próxima ida pelo transporte.
    saida: Vec<u8>,
    /// Há na saída um reconhecimento (`SETTINGS`, `PING`) que não espera o
    /// próximo pedido.
    urgente: bool,
    correntes: Vec<Estado<Erro<F::Falha>>>,
    proxima: u32,
    decodificador: Decodificador,
    bloco: Option<Bloco>,
    /// O próximo bloco de cabeça é o primeiro da conexão.
    primeiro_bloco: bool,
    /// O prefácio do servidor — o primeiro `SETTINGS` — chegou.
    prefacio: bool,
    /// Os ajustes do servidor.
    maior_quadro: usize,
    janela_inicial: i64,
    maximo: u32,
    /// A janela da conexão: quanto o servidor ainda pode mandar, e quanto
    /// deste lado ainda cabe na dele.
    recebe: i64,
    envia: i64,
    /// O `GOAWAY` do servidor: a última corrente que ele processa, e o
    /// código.
    adeus: Option<(u32, CodigoH2)>,
    /// A conexão não abre mais correntes: o pedido pediu o fecho, ou quem
    /// chama fechou.
    encerrando: bool,
    /// A falha que acabou com a conexão.
    morta: Option<Erro<F::Falha>>,
    /// Quadros seguidos sem progresso.
    parados: u32,
    /// Quem lê agora espera uma janela para mandar um corpo: um
    /// `WINDOW_UPDATE` é progresso.
    esperando_janela: bool,
    trocas: u64,
}

impl<F: Fluxo> ClienteH2<F>
where
    F::Falha: Clone,
{
    /// Uma conexão sobre `fluxo`, com os ajustes padrão. Nada sai antes do
    /// primeiro pedido: o prefácio vai junto com ele.
    pub fn novo(fluxo: F) -> ClienteH2<F> {
        ClienteH2::com(fluxo, AjustesH2::default())
    }

    /// Uma conexão sobre `fluxo`, com `ajustes`.
    pub fn com(fluxo: F, ajustes: AjustesH2) -> ClienteH2<F> {
        let ajustes = AjustesH2 {
            correntes: ajustes.correntes.max(1),
            janela: ajustes.janela.min(JANELA_MAXIMA as u32),
            lista: ajustes.lista,
        };
        let mut saida = Vec::new();
        saida.extend_from_slice(quadro::PREFACIO);
        quadro::por_ajustes(
            &mut saida,
            &[
                (ajuste::ENABLE_PUSH, 0),
                (ajuste::INITIAL_WINDOW_SIZE, ajustes.janela),
                (ajuste::MAX_HEADER_LIST_SIZE, ajustes.lista),
            ],
        );
        quadro::por_janela(&mut saida, 0, (JANELA_DA_CONEXAO - JANELA_PADRAO) as u32);
        ClienteH2 {
            fluxo,
            serie: CONEXOES.fetch_add(1, Ordering::Relaxed),
            ajustes,
            entrada: Vec::new(),
            saida,
            urgente: false,
            correntes: Vec::new(),
            proxima: 1,
            decodificador: Decodificador::novo(TABELA),
            bloco: None,
            primeiro_bloco: true,
            prefacio: false,
            maior_quadro: QUADRO_PADRAO,
            janela_inicial: JANELA_PADRAO,
            maximo: u32::MAX,
            recebe: JANELA_DA_CONEXAO,
            envia: JANELA_PADRAO,
            adeus: None,
            encerrando: false,
            morta: None,
            parados: 0,
            esperando_janela: false,
            trocas: 0,
        }
    }

    /// A conexão abre outra corrente: viva, sem `GOAWAY` do servidor, sem
    /// pedido de fecho, com números sobrando.
    pub fn pronto(&self) -> bool {
        self.morta.is_none()
            && !self.encerrando
            && self.adeus.is_none()
            && self.proxima <= MAIOR_CORRENTE
    }

    /// Quantas correntes a conexão guarda agora.
    pub fn abertas(&self) -> usize {
        self.correntes.len()
    }

    /// Quantas trocas terminaram com uma resposta nesta conexão.
    pub fn trocas(&self) -> u64 {
        self.trocas
    }

    /// Abre uma corrente com `pedido`, a ser recebida com `limites`: manda a
    /// cabeça e o corpo inteiro — lendo o que chegar enquanto a janela do
    /// servidor não deixa —, e volta sem esperar a resposta. Sem pote: o
    /// pedido não leva cookie.
    pub fn enviar(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
    ) -> Result<Corrente, Erro<F::Falha>> {
        self.abrir(pedido, limites, None, 0, None)
    }

    /// [`ClienteH2::enviar`] com os cookies de `pote`. `relogio` dá o
    /// tempo, como em [`crate::Cliente::trocar_com_pote`]; o que ele der
    /// vale também para a resposta.
    pub fn enviar_com_pote(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
        pote: &mut Pote,
        relogio: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<Corrente, Erro<F::Falha>> {
        // Sem vaga, nem o pote nem o relógio são consultados.
        self.cabe_outra()?;
        let mut agora = Agora::de(relogio);
        let (cookie, retidos) =
            pote.cabecalho(&pedido.url, pedido.metodo, pedido.contexto, &mut agora);
        self.abrir(pedido, limites, cookie.as_deref(), retidos, agora.lido())
    }

    /// Espera a resposta de `corrente` — lendo o que chegar para as outras
    /// enquanto isso — e a entrega. Os `Set-Cookie` vêm como vieram.
    pub fn receber(&mut self, corrente: Corrente) -> Result<Resposta, Erro<F::Falha>> {
        let s = self.colher(corrente)?;
        self.montar(s)
    }

    /// [`ClienteH2::receber`] com `pote`: os `Set-Cookie` vão para ele, e
    /// saem dos cabeçalhos. A resposta que falha não grava cookie nenhum.
    pub fn receber_com_pote(
        &mut self,
        corrente: Corrente,
        pote: &mut Pote,
        relogio: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<Resposta, Erro<F::Falha>> {
        let s = self.colher(corrente)?;
        let mut agora = Agora::continuando(relogio, s.relogio);
        let (url, contexto, retidos) = (s.url.clone(), s.contexto, s.retidos);
        let mut r = self.montar(s)?;
        r.cookies = pote.guardar(&url, contexto, &r.cabecalhos, &mut agora);
        r.cookies.retidos = retidos;
        r.cabecalhos.retain(|(nome, _)| nome != "set-cookie");
        Ok(r)
    }

    /// Manda `pedido` e espera a resposta.
    pub fn trocar(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
    ) -> Result<Resposta, Erro<F::Falha>> {
        let c = self.enviar(pedido, limites)?;
        self.receber(c)
    }

    /// Manda `pedido` com os cookies de `pote` e espera a resposta; o
    /// relógio é lido no máximo uma vez para a troca inteira.
    pub fn trocar_com_pote(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
        pote: &mut Pote,
        relogio: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<Resposta, Erro<F::Falha>> {
        let c = self.enviar_com_pote(pedido, limites, pote, relogio)?;
        self.receber_com_pote(c, pote, relogio)
    }

    /// Larga `corrente`: o que já chegou dela vai embora, e o que ainda
    /// chegar é descartado. Se ela ainda está aberta, o `RST_STREAM` vai na
    /// próxima ida pelo transporte.
    pub fn cancelar(&mut self, corrente: Corrente) {
        let Ok(i) = self.indice(&corrente) else {
            return;
        };
        let s = self.correntes.remove(i);
        if !s.fechada() && self.morta.is_none() {
            quadro::por_reinicio(&mut self.saida, s.numero, CodigoH2::CANCEL);
        }
    }

    /// Avisa o servidor que a conexão acaba (`GOAWAY` com `NO_ERROR`): ela
    /// não abre mais correntes. As já abertas ainda podem ser recebidas.
    pub fn fechar(&mut self) -> Result<(), Erro<F::Falha>> {
        self.encerrando = true;
        // Uma conexão que nunca mandou nada não tem o que avisar.
        if self.morta.is_some() || self.proxima == 1 {
            return Ok(());
        }
        quadro::por_adeus(&mut self.saida, 0, CodigoH2::NO_ERROR);
        self.despachar().map_err(Erro::Baixo)
    }

    /// O transporte, para quem precisa dele entre as trocas.
    pub fn fluxo(&mut self) -> &mut F {
        &mut self.fluxo
    }

    /// Devolve o transporte, para quem chamou fechá-lo.
    pub fn devolver(self) -> F {
        self.fluxo
    }

    // --- Os pedidos ---

    /// A conexão abre mais uma corrente agora — ou o porquê de não.
    fn cabe_outra(&self) -> Result<(), Erro<F::Falha>> {
        if !self.pronto() {
            return Err(Erro::Esgotada);
        }
        let abertas = self.correntes.iter().filter(|s| !s.fechada()).count();
        if self.correntes.len() >= self.ajustes.correntes || abertas >= self.maximo as usize {
            return Err(Erro::Limite(Limite::Correntes));
        }
        Ok(())
    }

    fn abrir(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
        cookie: Option<&str>,
        retidos: u32,
        relogio: Option<Option<u64>>,
    ) -> Result<Corrente, Erro<F::Falha>> {
        self.cabe_outra()?;
        let numero = self.proxima;
        self.proxima += 2;
        let primeiro = core::mem::replace(&mut self.primeiro_bloco, false);
        let bloco = bloco_do_pedido(pedido, cookie, primeiro);
        let sem_corpo = pedido.corpo.is_empty();
        quadro::por_cabecalhos(
            &mut self.saida,
            numero,
            &bloco,
            sem_corpo,
            self.maior_quadro,
        );
        self.correntes.push(Estado {
            numero,
            metodo: pedido.metodo,
            aceitas: pedido.aceitas,
            limites: *limites,
            url: pedido.url.clone(),
            contexto: pedido.contexto,
            retidos,
            relogio,
            fase: Fase::Cabeca,
            informativas: 0,
            status: 0,
            cabecalhos: Vec::new(),
            declarado: None,
            corpo: Vec::new(),
            erro: None,
            recebe: i64::from(self.ajustes.janela),
            envia: self.janela_inicial,
            mandou_tudo: sem_corpo,
            fim_recebido: false,
        });
        if pedido.fechar {
            self.encerrando = true;
        }
        // O corpo, dentro das duas janelas do servidor e do maior quadro
        // dele; sem janela, lê o que chegar até ela abrir. Uma corrente que
        // o servidor fechou ou recusou no meio para de receber corpo.
        let mut mandado = 0;
        while self.morta.is_none() {
            let Onde::Aqui(i) = self.onde(numero) else {
                break;
            };
            let s = &mut self.correntes[i];
            if s.mandou_tudo {
                break;
            }
            let resta = pedido.corpo.len() - mandado;
            let n = (resta as i64)
                .min(self.envia)
                .min(s.envia)
                .min(self.maior_quadro as i64);
            if n > 0 {
                let n = n as usize;
                let fim = n == resta;
                quadro::por_dados(
                    &mut self.saida,
                    numero,
                    &pedido.corpo[mandado..mandado + n],
                    fim,
                );
                self.envia -= n as i64;
                s.envia -= n as i64;
                s.mandou_tudo = fim;
                mandado += n;
                continue;
            }
            self.esperando_janela = true;
            self.volta();
            self.esperando_janela = false;
        }
        if self.morta.is_none()
            && let Err(f) = self.despachar()
        {
            self.morrer(Erro::Baixo(f));
        }
        if let Some(e) = &self.morta {
            let e = e.clone();
            self.correntes.retain(|s| s.numero != numero);
            return Err(e);
        }
        Ok(Corrente {
            conexao: self.serie,
            numero,
        })
    }

    // --- As respostas ---

    fn indice(&self, c: &Corrente) -> Result<usize, Erro<F::Falha>> {
        if c.conexao != self.serie {
            return Err(Erro::Esgotada);
        }
        self.correntes
            .iter()
            .position(|s| s.numero == c.numero)
            .ok_or(Erro::Esgotada)
    }

    /// Lê até a corrente acabar, e a tira da conexão.
    fn colher(&mut self, c: Corrente) -> Result<Estado<Erro<F::Falha>>, Erro<F::Falha>> {
        let i = self.indice(&c)?;
        while self.correntes[i].esperando() {
            self.ampliar(i);
            self.volta();
        }
        let mut s = self.correntes.remove(i);
        // Os reconhecimentos não esperam o próximo pedido; o resto da fila
        // — janelas, reinícios — vai com ele.
        if self.urgente
            && self.morta.is_none()
            && let Err(f) = self.despachar()
        {
            self.morrer(Erro::Baixo(f));
        }
        match s.erro.take() {
            Some(e) => Err(e),
            None => Ok(s),
        }
    }

    /// A janela da corrente esperada, reaberta de uma vez até o limite do
    /// corpo dela — e um byte além, para o corpo que passa do limite ser
    /// visto como tal, e não ficar parado esperando janela.
    fn ampliar(&mut self, i: usize) {
        let metade = i64::from(self.ajustes.janela) / 2;
        let s = &mut self.correntes[i];
        if !s.esperando() || s.recebe > metade {
            return;
        }
        let resta = s
            .limites
            .corpo
            .saturating_sub(s.corpo.len())
            .min(JANELA_MAXIMA as usize - 1) as i64;
        let alvo = resta + 1;
        if alvo > s.recebe {
            quadro::por_janela(&mut self.saida, s.numero, (alvo - s.recebe) as u32);
            s.recebe = alvo;
        }
    }

    /// A resposta de uma corrente que acabou: o corpo decodificado, se veio
    /// comprimido.
    fn montar(&mut self, s: Estado<Erro<F::Falha>>) -> Result<Resposta, Erro<F::Falha>> {
        let enquadramento = if s.sem_conteudo() {
            Enquadramento::Nenhum
        } else {
            Enquadramento::Quadros
        };
        let codificacao = match enquadramento {
            Enquadramento::Nenhum => None,
            _ => codificacao::da_resposta(&s.cabecalhos, s.aceitas).map_err(Erro::Conteudo)?,
        };
        let no_fio = s.corpo.len();
        let corpo = match codificacao {
            Some(c) if no_fio > 0 => {
                codificacao::decodificar(c, &s.corpo, s.limites.descomprimido)?
            }
            _ => s.corpo,
        };
        self.trocas += 1;
        Ok(Resposta {
            versao: Versao::Http2,
            status: s.status,
            motivo: String::new(),
            cabecalhos: s.cabecalhos,
            corpo,
            codificacao,
            no_fio,
            cookies: Guardados::default(),
            enquadramento,
            reutilizavel: self.pronto(),
        })
    }

    // --- O transporte ---

    /// Manda a fila de saída numa ida só.
    fn despachar(&mut self) -> Result<(), F::Falha> {
        self.urgente = false;
        if self.saida.is_empty() {
            return Ok(());
        }
        let saida = core::mem::take(&mut self.saida);
        self.fluxo.mandar(&saida)
    }

    /// Uma volta: manda a fila de saída, lê o transporte uma vez e processa
    /// os quadros inteiros que chegaram. Uma falha fica em `self.morta`.
    fn volta(&mut self) {
        if self.morta.is_some() {
            return;
        }
        if let Err(f) = self.despachar() {
            return self.morrer(Erro::Baixo(f));
        }
        // Direto no fim da entrada, e não num pedaço na pilha: a pilha de um
        // programa do Duke tem 64 KiB.
        let inicio = self.entrada.len();
        self.entrada.resize(inicio + LEITURA, 0);
        match self.fluxo.receber(&mut self.entrada[inicio..]) {
            Ok(0) => {
                self.entrada.truncate(inicio);
                self.fechou();
            }
            Ok(n) => {
                self.entrada.truncate(inicio + n.min(LEITURA));
                self.processar();
            }
            Err(f) => {
                self.entrada.truncate(inicio);
                self.morrer(Erro::Baixo(f));
            }
        }
    }

    /// Processa os quadros inteiros da entrada; o que sobra fica para a
    /// próxima volta.
    fn processar(&mut self) {
        let entrada = core::mem::take(&mut self.entrada);
        let mut pos = 0;
        while self.morta.is_none() && entrada.len() - pos >= CABECA {
            let mut cabeca = [0u8; CABECA];
            cabeca.copy_from_slice(&entrada[pos..pos + CABECA]);
            let c = quadro::ler_cabeca(&cabeca);
            // O prefácio do servidor é um `SETTINGS`; um servidor que não
            // fala HTTP/2 manda outra coisa.
            if !self.prefacio && (c.tipo != tipo::SETTINGS || c.bandeiras & bandeira::ACK != 0) {
                self.falha_da_conexao(Erro::Protocolo(Motivo::Prefacio), CodigoH2::PROTOCOL_ERROR);
                break;
            }
            // Este lado não anuncia quadro maior que o padrão.
            if c.tamanho > QUADRO_PADRAO {
                self.falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::FRAME_SIZE_ERROR);
                break;
            }
            if entrada.len() - pos - CABECA < c.tamanho {
                break;
            }
            let carga = &entrada[pos + CABECA..pos + CABECA + c.tamanho];
            pos += CABECA + c.tamanho;
            self.quadro(c, carga);
        }
        if self.morta.is_none() {
            let mut entrada = entrada;
            entrada.drain(..pos);
            self.entrada = entrada;
        }
    }

    // --- Os quadros ---

    fn quadro(&mut self, c: quadro::Cabeca, carga: &[u8]) {
        // No meio de um bloco de cabeça, só o `CONTINUATION` dele.
        if let Some(b) = &self.bloco
            && (c.tipo != tipo::CONTINUATION || c.corrente != b.corrente)
        {
            return self
                .falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR);
        }
        let q = match quadro::ler(c, carga) {
            Ok(q) => q,
            Err(ErroDeQuadro {
                codigo,
                corrente: None,
            }) => return self.falha_da_conexao(Erro::Protocolo(Motivo::Quadro), codigo),
            Err(ErroDeQuadro {
                codigo,
                corrente: Some(n),
            }) => return self.falha_de_quadro(c.tipo, n, codigo),
        };
        match q {
            Quadro::Dados {
                corrente,
                dados,
                fim,
            } => self.dados(corrente, c.tamanho, dados, fim),
            Quadro::Cabecalhos {
                corrente,
                bloco,
                fim_da_corrente,
                fim_da_cabeca,
            } => self.cabecalhos(corrente, bloco, fim_da_corrente, fim_da_cabeca),
            Quadro::Continuacao {
                bloco,
                fim_da_cabeca,
                ..
            } => self.continuacao(bloco, fim_da_cabeca),
            Quadro::Reinicio { corrente, codigo } => self.reinicio(corrente, codigo),
            Quadro::Ajustes { ack: false, pares } => self.ajustes(pares),
            Quadro::Ajustes { ack: true, .. } => self.parado(),
            Quadro::Promessa => {
                self.falha_da_conexao(Erro::Protocolo(Motivo::Empurrado), CodigoH2::PROTOCOL_ERROR)
            }
            Quadro::Ping { ack: false, dados } => {
                quadro::por_ping_ack(&mut self.saida, &dados);
                self.urgente = true;
                self.parado();
            }
            Quadro::Ping { ack: true, .. } => self.parado(),
            Quadro::Adeus { ultima, codigo } => self.adeus(ultima, codigo),
            Quadro::Janela {
                corrente,
                incremento,
            } => self.janela(corrente, incremento),
            Quadro::Ignorado => self.parado(),
        }
    }

    /// Onde está a corrente `n`.
    fn onde(&self, n: u32) -> Onde {
        if n.is_multiple_of(2) || n >= self.proxima {
            return Onde::Ociosa;
        }
        match self.correntes.iter().position(|s| s.numero == n) {
            Some(i) => Onde::Aqui(i),
            None => Onde::Largada,
        }
    }

    /// O erro de um quadro que é só da corrente `n`.
    fn falha_de_quadro(&mut self, t: u8, n: u32, codigo: CodigoH2) {
        match self.onde(n) {
            // A prioridade pode chegar para uma corrente que ainda não
            // existe; a falha dela não é de ninguém.
            Onde::Ociosa if t == tipo::PRIORITY => self.parado(),
            Onde::Ociosa => {
                self.falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR)
            }
            Onde::Largada => self.parado(),
            Onde::Aqui(i) => self.falha_da_corrente(i, Erro::Protocolo(Motivo::Quadro), codigo),
        }
    }

    fn dados(&mut self, n: u32, tamanho: usize, dados: &[u8], fim: bool) {
        // A conexão conta a carga inteira, preenchimento junto, de qualquer
        // corrente — até a largada —, e reabre conforme chega.
        let tamanho = tamanho as i64;
        if tamanho > self.recebe {
            return self.falha_da_conexao(
                Erro::Protocolo(Motivo::Janela),
                CodigoH2::FLOW_CONTROL_ERROR,
            );
        }
        self.recebe -= tamanho;
        if self.recebe <= JANELA_DA_CONEXAO / 2 {
            quadro::por_janela(&mut self.saida, 0, (JANELA_DA_CONEXAO - self.recebe) as u32);
            self.recebe = JANELA_DA_CONEXAO;
        }
        let i = match self.onde(n) {
            Onde::Ociosa => {
                return self
                    .falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR);
            }
            Onde::Largada => return self.parado(),
            Onde::Aqui(i) => i,
        };
        let s = &mut self.correntes[i];
        if s.erro.is_some() {
            return self.parado();
        }
        if s.fase == Fase::Fim {
            return self
                .falha_da_conexao(Erro::Protocolo(Motivo::Corrente), CodigoH2::STREAM_CLOSED);
        }
        s.fim_recebido |= fim;
        if tamanho > s.recebe {
            return self.falha_da_corrente(
                i,
                Erro::Protocolo(Motivo::Janela),
                CodigoH2::FLOW_CONTROL_ERROR,
            );
        }
        s.recebe -= tamanho;
        // Os dados vêm depois da cabeça, e a resposta sem conteúdo não os
        // tem.
        if s.fase == Fase::Cabeca || (s.sem_conteudo() && !dados.is_empty()) {
            return self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Mensagem));
        }
        let total = s.corpo.len() + dados.len();
        if total > s.limites.corpo {
            return self.falha_da_mensagem(i, Erro::Limite(Limite::Corpo));
        }
        if s.declarado.is_some_and(|d| total as u64 > d) {
            return self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Tamanho));
        }
        s.corpo.extend_from_slice(dados);
        if fim {
            self.fim_da_corrente(i);
        }
        if fim || !dados.is_empty() {
            self.progresso();
        } else {
            self.parado();
        }
    }

    /// O servidor acabou a corrente: o corpo tem o tamanho que a cabeça
    /// prometeu.
    fn fim_da_corrente(&mut self, i: usize) {
        let s = &mut self.correntes[i];
        s.fase = Fase::Fim;
        if !s.sem_conteudo() && s.declarado.is_some_and(|d| d != s.corpo.len() as u64) {
            self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Tamanho));
        }
    }

    fn cabecalhos(&mut self, n: u32, bloco: &[u8], fim_da_corrente: bool, fim_da_cabeca: bool) {
        let lista = self.ajustes.lista as usize;
        let teto = match self.onde(n) {
            // O servidor não abre correntes.
            Onde::Ociosa => {
                return self
                    .falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR);
            }
            Onde::Largada => lista,
            Onde::Aqui(i) => lista.max(self.correntes[i].limites.cabeca),
        };
        self.bloco = Some(Bloco {
            corrente: n,
            cru: Vec::new(),
            fim_da_corrente,
            continuacoes: 0,
            teto: teto.saturating_mul(2),
        });
        self.juntar(bloco, fim_da_cabeca);
    }

    fn continuacao(&mut self, parte: &[u8], fim: bool) {
        let Some(b) = &mut self.bloco else {
            return self
                .falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR);
        };
        b.continuacoes += 1;
        if b.continuacoes > MAIS_CONTINUACOES {
            return self
                .falha_da_conexao(Erro::Limite(Limite::Quadros), CodigoH2::ENHANCE_YOUR_CALM);
        }
        self.juntar(parte, fim);
    }

    /// Junta `parte` ao bloco em curso, e o processa quando ele acaba.
    fn juntar(&mut self, parte: &[u8], fim: bool) {
        let Some(b) = &mut self.bloco else {
            return;
        };
        if b.cru.len() + parte.len() > b.teto {
            return self
                .falha_da_conexao(Erro::Limite(Limite::Cabeca), CodigoH2::ENHANCE_YOUR_CALM);
        }
        b.cru.extend_from_slice(parte);
        if fim {
            self.fim_do_bloco();
        } else {
            self.parado();
        }
    }

    /// O bloco de cabeça inteiro: decodificado sempre — a tabela dinâmica é
    /// da conexão, e o bloco seguinte depende dela —, e entregue à corrente
    /// só se ela ainda o espera.
    fn fim_do_bloco(&mut self) {
        let Some(b) = self.bloco.take() else {
            return;
        };
        let ativa = match self.onde(b.corrente) {
            Onde::Aqui(i) if self.correntes[i].erro.is_none() => Some(i),
            _ => None,
        };
        let limite = ativa.map_or(0, |i| self.correntes[i].limites.cabeca);
        let Ok((campos, passou)) = self.decodificador.decodificar(&b.cru, limite) else {
            return self.falha_da_conexao(
                Erro::Protocolo(Motivo::Compressao),
                CodigoH2::COMPRESSION_ERROR,
            );
        };
        let Some(i) = ativa else {
            return self.parado();
        };
        let fase = self.correntes[i].fase;
        if fase == Fase::Fim {
            return self
                .falha_da_conexao(Erro::Protocolo(Motivo::Corrente), CodigoH2::STREAM_CLOSED);
        }
        self.correntes[i].fim_recebido |= b.fim_da_corrente;
        self.progresso();
        if passou {
            return self.falha_da_mensagem(i, Erro::Limite(Limite::Cabeca));
        }
        match fase {
            Fase::Cabeca => self.cabeca_da_resposta(i, campos, b.fim_da_corrente),
            _ => self.trailers(i, campos, b.fim_da_corrente),
        }
    }

    fn cabeca_da_resposta(&mut self, i: usize, campos: Vec<Campo>, fim: bool) {
        let limites = self.correntes[i].limites;
        let (status, cabecalhos) = match validar(campos, &limites, false) {
            Ok(r) => r,
            Err(e) => return self.falha_da_mensagem(i, e),
        };
        if status == 101 {
            return self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Troca));
        }
        if (100..200).contains(&status) {
            // Uma informativa não acaba a corrente, e não se repete sem fim.
            let s = &mut self.correntes[i];
            s.informativas += 1;
            if fim {
                return self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Mensagem));
            }
            if s.informativas > MAIS_INFORMATIVAS {
                return self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Informativas));
            }
            return;
        }
        let s = &mut self.correntes[i];
        s.status = status;
        // Sem conteúdo, o `Content-Length` fala da representação, e não
        // desta resposta: não se confere.
        if !s.sem_conteudo() {
            match resposta::declarado(&cabecalhos, &limites) {
                Ok(d) => s.declarado = d,
                Err(e) => return self.falha_da_mensagem(i, e),
            }
        }
        let s = &mut self.correntes[i];
        s.cabecalhos = cabecalhos;
        s.fase = Fase::Corpo;
        if fim {
            self.fim_da_corrente(i);
        }
    }

    /// Os *trailers*: conferidos como cabeçalhos, com os limites da cabeça,
    /// e largados, como no HTTP/1.1. Eles acabam a corrente.
    fn trailers(&mut self, i: usize, campos: Vec<Campo>, fim: bool) {
        if !fim {
            return self.falha_da_mensagem(i, Erro::Protocolo(Motivo::Mensagem));
        }
        let limites = self.correntes[i].limites;
        if let Err(e) = validar(campos, &limites, true) {
            return self.falha_da_mensagem(i, e);
        }
        self.fim_da_corrente(i);
    }

    fn reinicio(&mut self, n: u32, codigo: CodigoH2) {
        let i = match self.onde(n) {
            Onde::Ociosa => {
                return self
                    .falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR);
            }
            Onde::Largada => return self.parado(),
            Onde::Aqui(i) => i,
        };
        let s = &mut self.correntes[i];
        s.mandou_tudo = true;
        // Depois da resposta inteira, o reinício só pede que o corpo do
        // pedido pare (RFC 9113, 8.1): a resposta fica.
        if !s.esperando() {
            return self.parado();
        }
        s.falhar(if codigo == CodigoH2::REFUSED_STREAM {
            Erro::Recusada
        } else {
            Erro::Reiniciada(codigo)
        });
        self.progresso();
    }

    fn ajustes(&mut self, pares: &[u8]) {
        self.prefacio = true;
        for par in pares.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([par[0], par[1]]);
            let valor = u32::from_be_bytes([par[2], par[3], par[4], par[5]]);
            match id {
                // O servidor não liga o *push*.
                ajuste::ENABLE_PUSH if valor != 0 => {
                    return self.falha_da_conexao(
                        Erro::Protocolo(Motivo::Quadro),
                        CodigoH2::PROTOCOL_ERROR,
                    );
                }
                ajuste::MAX_CONCURRENT_STREAMS => self.maximo = valor,
                ajuste::INITIAL_WINDOW_SIZE => {
                    let valor = i64::from(valor);
                    if valor > JANELA_MAXIMA {
                        return self.falha_da_conexao(
                            Erro::Protocolo(Motivo::Janela),
                            CodigoH2::FLOW_CONTROL_ERROR,
                        );
                    }
                    // A mudança vale para as correntes que ainda mandam.
                    let delta = valor - self.janela_inicial;
                    self.janela_inicial = valor;
                    let mut passou = false;
                    for s in self.correntes.iter_mut().filter(|s| !s.mandou_tudo) {
                        s.envia += delta;
                        passou |= s.envia > JANELA_MAXIMA;
                    }
                    if passou {
                        return self.falha_da_conexao(
                            Erro::Protocolo(Motivo::Janela),
                            CodigoH2::FLOW_CONTROL_ERROR,
                        );
                    }
                }
                ajuste::MAX_FRAME_SIZE => {
                    let valor = valor as usize;
                    if !(QUADRO_PADRAO..=QUADRO_MAXIMO).contains(&valor) {
                        return self.falha_da_conexao(
                            Erro::Protocolo(Motivo::Quadro),
                            CodigoH2::PROTOCOL_ERROR,
                        );
                    }
                    self.maior_quadro = valor;
                }
                // A tabela deste lado no servidor tem zero bytes desde o
                // primeiro bloco, e a maior cabeça do servidor só aconselha.
                ajuste::HEADER_TABLE_SIZE | ajuste::MAX_HEADER_LIST_SIZE => {}
                // O que a RFC não define se ignora.
                _ => {}
            }
        }
        quadro::por_ajustes_ack(&mut self.saida);
        self.urgente = true;
        self.parado();
    }

    fn adeus(&mut self, ultima: u32, codigo: CodigoH2) {
        let primeiro = self.adeus.is_none();
        // A última corrente só pode descer de um `GOAWAY` para o seguinte.
        let ultima = self.adeus.map_or(ultima, |(u, _)| u.min(ultima));
        self.adeus = Some((ultima, codigo));
        // O que passa da última o servidor não processou: pode ir noutra
        // conexão.
        for s in self.correntes.iter_mut() {
            if s.numero > ultima && s.esperando() {
                s.falhar(Erro::Recusada);
            }
        }
        if primeiro {
            self.progresso();
        } else {
            self.parado();
        }
    }

    fn janela(&mut self, n: u32, incremento: u32) {
        let incremento = i64::from(incremento);
        if n == 0 {
            self.envia += incremento;
            if self.envia > JANELA_MAXIMA {
                return self.falha_da_conexao(
                    Erro::Protocolo(Motivo::Janela),
                    CodigoH2::FLOW_CONTROL_ERROR,
                );
            }
            return self.progresso_se_esperando();
        }
        let i = match self.onde(n) {
            Onde::Ociosa => {
                return self
                    .falha_da_conexao(Erro::Protocolo(Motivo::Quadro), CodigoH2::PROTOCOL_ERROR);
            }
            Onde::Largada => return self.parado(),
            Onde::Aqui(i) => i,
        };
        let s = &mut self.correntes[i];
        if s.mandou_tudo {
            return self.parado();
        }
        s.envia += incremento;
        if s.envia > JANELA_MAXIMA {
            return self.falha_da_corrente(
                i,
                Erro::Protocolo(Motivo::Janela),
                CodigoH2::FLOW_CONTROL_ERROR,
            );
        }
        self.progresso_se_esperando();
    }

    // --- O progresso ---

    fn progresso(&mut self) {
        self.parados = 0;
    }

    /// Um quadro que não levou resposta nenhuma adiante.
    fn parado(&mut self) {
        self.parados += 1;
        if self.parados > MAIS_PARADOS {
            self.falha_da_conexao(Erro::Limite(Limite::Quadros), CodigoH2::ENHANCE_YOUR_CALM);
        }
    }

    fn progresso_se_esperando(&mut self) {
        if self.esperando_janela {
            self.progresso();
        } else {
            self.parado();
        }
    }

    // --- As falhas ---

    /// A resposta da corrente `i` não serve: malformada (`PROTOCOL_ERROR`),
    /// ou além de um limite deste lado (`CANCEL`).
    fn falha_da_mensagem(&mut self, i: usize, erro: Erro<F::Falha>) {
        let codigo = match erro {
            Erro::Limite(_) => CodigoH2::CANCEL,
            _ => CodigoH2::PROTOCOL_ERROR,
        };
        self.falha_da_corrente(i, erro, codigo);
    }

    /// Falha a corrente `i` e manda o `RST_STREAM` — se ela ainda não
    /// acabou dos dois lados: numa corrente fechada, nada mais vai.
    fn falha_da_corrente(&mut self, i: usize, erro: Erro<F::Falha>, codigo: CodigoH2) {
        let s = &mut self.correntes[i];
        if s.erro.is_some() {
            return;
        }
        if !(s.mandou_tudo && s.fim_recebido) {
            quadro::por_reinicio(&mut self.saida, s.numero, codigo);
        }
        s.falhar(erro);
    }

    /// Um erro da conexão: o `GOAWAY` sai — na mesma ida que o resto da
    /// fila —, e todas as correntes que esperavam falham.
    fn falha_da_conexao(&mut self, erro: Erro<F::Falha>, codigo: CodigoH2) {
        if self.morta.is_some() {
            return;
        }
        quadro::por_adeus(&mut self.saida, 0, codigo);
        // Se a ida falhar, a conexão já acabou de qualquer jeito.
        let _ = self.despachar();
        self.morrer(erro);
    }

    /// O servidor fechou: o que não acabou, acabou cedo — ou com o erro do
    /// `GOAWAY` dele.
    fn fechou(&mut self) {
        let erro = match self.adeus {
            Some((_, codigo)) if codigo != CodigoH2::NO_ERROR => Erro::Encerrada(codigo),
            _ => Erro::Fechada,
        };
        self.morrer(erro);
    }

    fn morrer(&mut self, erro: Erro<F::Falha>) {
        for s in self.correntes.iter_mut().filter(|s| s.esperando()) {
            s.falhar(erro.clone());
        }
        self.morta = Some(erro);
        self.entrada = Vec::new();
        self.saida = Vec::new();
        self.bloco = None;
    }
}

/// O bloco de cabeça de `pedido`: os pseudo-cabeçalhos, o
/// `accept-encoding`, o `cookie` do pote, os de quem chama em minúsculas e o
/// `content-length` — o que o HTTP/1.1 escreve na linha do pedido e nos
/// cabeçalhos que só este pacote escreve (ver [`crate::Pedido`]).
fn bloco_do_pedido(pedido: &Pedido, cookie: Option<&str>, primeiro: bool) -> Vec<u8> {
    use Representacao::{NuncaIndexar, SemIndexar};
    let mut bloco = Vec::new();
    if primeiro {
        // A tabela dinâmica deste lado, no servidor, tem zero bytes: nada
        // deste cliente entra nela, e assim nenhum ajuste do servidor pede
        // atualização depois.
        bloco.push(0x20);
    }
    let esquema = match pedido.url.esquema {
        Esquema::Http => "http",
        Esquema::Https => "https",
    };
    let mut campo =
        |nome: &str, valor: &[u8], como| Codificador::campo(nome, valor, como, &mut bloco);
    campo(":method", pedido.metodo.nome().as_bytes(), SemIndexar);
    campo(":scheme", esquema.as_bytes(), SemIndexar);
    campo(":authority", pedido.url.autoridade().as_bytes(), SemIndexar);
    campo(":path", pedido.url.alvo.as_bytes(), SemIndexar);
    campo(
        "accept-encoding",
        pedido.aceitas.cabecalho().as_bytes(),
        SemIndexar,
    );
    if let Some(cookie) = cookie {
        campo("cookie", cookie.as_bytes(), NuncaIndexar);
    }
    for (nome, valor) in pedido.cabecalhos() {
        let nome = nome.to_ascii_lowercase();
        // Uma credencial também não entra na tabela de ninguém no caminho.
        let como = match nome.as_str() {
            "authorization" | "proxy-authorization" => NuncaIndexar,
            _ => SemIndexar,
        };
        campo(&nome, valor.as_bytes(), como);
    }
    if pedido.metodo.leva_corpo() || !pedido.corpo.is_empty() {
        campo(
            "content-length",
            format!("{}", pedido.corpo.len()).as_bytes(),
            SemIndexar,
        );
    }
    bloco
}

/// O `:status`: três dígitos, de 100 a 599.
fn ler_status(valor: &[u8]) -> Option<u16> {
    let digitos: [u8; 3] = valor.try_into().ok()?;
    if !digitos.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = digitos
        .iter()
        .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
    (100..=599).contains(&n).then_some(n)
}

/// O `:status` e os cabeçalhos de um bloco conferido.
type Conferido = (u16, Vec<(String, String)>);

/// Confere os campos de um bloco de cabeça (RFC 9113, 8.2 e 8.3) e devolve o
/// `:status` — zero nos *trailers*, que não o têm — e os cabeçalhos.
fn validar<F>(campos: Vec<Campo>, limites: &Limites, trailers: bool) -> Result<Conferido, Erro<F>> {
    let mut status = None;
    let mut regulares = false;
    let mut cabecalhos = Vec::new();
    for Campo { nome, valor } in campos {
        if let Some(pseudo) = nome.strip_prefix(b":") {
            // Os pseudo-cabeçalhos vêm antes de todos, e a resposta só tem
            // um: o `:status`.
            if trailers || regulares || pseudo != b"status" || status.is_some() {
                return Err(Erro::Protocolo(Motivo::Mensagem));
            }
            status = Some(ler_status(&valor).ok_or(Erro::Protocolo(Motivo::Status))?);
            continue;
        }
        regulares = true;
        // O nome em minúsculas (RFC 9113, 8.2.1); o valor sem controle e
        // sem espaço nas pontas.
        if nome.is_empty() || !nome.iter().all(|&b| tchar(b) && !b.is_ascii_uppercase()) {
            return Err(Erro::Protocolo(Motivo::Cabecalho));
        }
        if !valor.iter().all(|&b| resposta::de_valor(b))
            || matches!(valor.first(), Some(b' ' | b'\t'))
            || matches!(valor.last(), Some(b' ' | b'\t'))
        {
            return Err(Erro::Protocolo(Motivo::Cabecalho));
        }
        if DA_CONEXAO.contains(&nome.as_slice()) {
            return Err(Erro::Protocolo(Motivo::Mensagem));
        }
        if nome.len() + 2 + valor.len() > limites.linha {
            return Err(Erro::Limite(Limite::Linha));
        }
        if cabecalhos.len() >= limites.cabecalhos {
            return Err(Erro::Limite(Limite::Cabecalhos));
        }
        cabecalhos.push((
            String::from_utf8_lossy(&nome).into_owned(),
            String::from_utf8_lossy(&valor).into_owned(),
        ));
    }
    match (trailers, status) {
        (true, _) => Ok((0, cabecalhos)),
        (false, Some(s)) => Ok((s, cabecalhos)),
        (false, None) => Err(Erro::Protocolo(Motivo::Mensagem)),
    }
}
