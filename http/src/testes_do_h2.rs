//! Os testes do HTTP/2: a conexão contra um servidor de mentira que
//! responde ao que o cliente manda — dentro das janelas que o cliente dá, e
//! conferindo as que ele mesmo deu —, e contra roteiros de bytes hostis,
//! cada um com o erro que a RFC 9113 manda e o alcance certo: só a
//! corrente, ou a conexão inteira.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::hpack::{Codificador, Decodificador, Representacao};
use crate::quadro::{self, CABECA, Cabeca, CodigoH2, PREFACIO, Quadro, ajuste, bandeira, tipo};
use crate::testes::{FalhaDeTeste, Roteiro};
use crate::testes_da_codificacao::OLA_GZIP;
use crate::{
    AjustesH2, ClienteH2, Codificacao, Enquadramento, Erro, Fluxo, Limite, Limites, Metodo, Motivo,
    Pedido, Pote, Resposta, Url, Versao,
};

// --- O servidor de mentira ---

/// O que o servidor responde a um pedido.
#[derive(Clone, Debug)]
struct Rota {
    status: u16,
    cabecalhos: Vec<(String, String)>,
    corpo: Vec<u8>,
    trailers: Vec<(String, String)>,
}

/// Uma resposta com `content-length`.
fn rota(status: u16, corpo: &[u8]) -> Rota {
    Rota {
        status,
        cabecalhos: vec![(String::from("content-length"), format!("{}", corpo.len()))],
        corpo: corpo.to_vec(),
        trailers: Vec::new(),
    }
}

/// Um pedido como o servidor o recebeu: os campos na ordem, os
/// pseudo-cabeçalhos junto.
#[derive(Clone, Debug, Default)]
struct Recebido {
    corrente: u32,
    campos: Vec<(String, String)>,
    corpo: Vec<u8>,
    /// O bloco de cabeça como veio, para conferir a representação.
    cru: Vec<u8>,
    reiniciado: Option<CodigoH2>,
}

impl Recebido {
    fn campo(&self, nome: &str) -> Option<&str> {
        self.campos
            .iter()
            .find(|(n, _)| n == nome)
            .map(|(_, v)| v.as_str())
    }
}

/// Uma resposta saindo: o que falta mandar dela.
struct Saindo {
    corrente: u32,
    cabeca: Option<Vec<u8>>,
    corpo: Vec<u8>,
    mandado: usize,
    trailers: Option<Vec<u8>>,
    /// Quanto o cliente deixa o servidor mandar nesta corrente.
    janela: i64,
}

impl Saindo {
    fn acabou(&self) -> bool {
        self.cabeca.is_none() && self.mandado == self.corpo.len() && self.trailers.is_none()
    }
}

/// O servidor de mentira.
struct Servidor {
    entrada: Vec<u8>,
    prefacio: bool,
    decodificador: Decodificador,
    bloco: Option<(u32, Vec<u8>, bool)>,
    recebidos: Vec<Recebido>,
    rotas: Box<dyn FnMut(&Recebido) -> Rota>,
    /// Os ajustes que o servidor anuncia.
    ajustes: Vec<(u16, u32)>,
    /// As janelas do cliente: a inicial de cada corrente, e a da conexão.
    janela_inicial: i64,
    janela: i64,
    saindo: Vec<Saindo>,
    saida: Vec<u8>,
    entregue: usize,
    pedaco: usize,
    /// O maior `DATA` que o servidor manda.
    quadro: usize,
    /// As respostas se intercalam quadro a quadro.
    intercalar: bool,
    /// As janelas do servidor, que o cliente tem de respeitar: a inicial de
    /// cada corrente — a anunciada só vale depois do reconhecimento do
    /// cliente (RFC 9113, 6.5.3) —, e o que sobra em cada uma e na conexão.
    recebe_inicial: i64,
    recebe_anunciada: i64,
    recebe_conexao: i64,
    recebe: Vec<(u32, i64)>,
    /// O maior quadro que o servidor aceita.
    maior_quadro: usize,
    /// O que o cliente mandou, quadro a quadro, e quantas idas e voltas.
    quadros: Vec<(Cabeca, Vec<u8>)>,
    idas: usize,
    voltas: usize,
    /// Sem nada para mandar: fecha (`Ok(0)`), ou falha assim.
    fim: Option<FalhaDeTeste>,
}

impl Servidor {
    fn novo(rotas: impl FnMut(&Recebido) -> Rota + 'static) -> Servidor {
        Servidor {
            entrada: Vec::new(),
            prefacio: false,
            decodificador: Decodificador::novo(4096),
            bloco: None,
            recebidos: Vec::new(),
            rotas: Box::new(rotas),
            ajustes: Vec::new(),
            janela_inicial: 65_535,
            janela: 65_535,
            saindo: Vec::new(),
            saida: Vec::new(),
            entregue: 0,
            pedaco: usize::MAX,
            quadro: 16_384,
            intercalar: false,
            recebe_inicial: 65_535,
            recebe_anunciada: 65_535,
            recebe_conexao: 65_535,
            recebe: Vec::new(),
            maior_quadro: 16_384,
            quadros: Vec::new(),
            idas: 0,
            voltas: 0,
            fim: Some(FalhaDeTeste("NETWORK_TIMEOUT")),
        }
    }

    /// Anuncia `ajustes`; a janela inicial e o maior quadro valem para o
    /// que o próprio servidor confere.
    fn com_ajustes(mut self, ajustes: &[(u16, u32)]) -> Servidor {
        for &(id, valor) in ajustes {
            match id {
                ajuste::INITIAL_WINDOW_SIZE => self.recebe_anunciada = i64::from(valor),
                ajuste::MAX_FRAME_SIZE => self.maior_quadro = valor as usize,
                _ => {}
            }
        }
        self.ajustes = ajustes.to_vec();
        self
    }

    /// Os quadros do cliente de um tipo.
    fn do_tipo(&self, t: u8) -> Vec<&(Cabeca, Vec<u8>)> {
        self.quadros.iter().filter(|(c, _)| c.tipo == t).collect()
    }

    /// Os `WINDOW_UPDATE` do cliente para a corrente `n`.
    fn janelas_para(&self, n: u32) -> Vec<u32> {
        self.do_tipo(tipo::WINDOW_UPDATE)
            .into_iter()
            .filter(|(c, _)| c.corrente == n)
            .map(|(_, p)| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
            .collect()
    }

    fn recebido(&mut self, n: u32) -> &mut Recebido {
        self.recebidos
            .iter_mut()
            .find(|r| r.corrente == n)
            .expect("um quadro para uma corrente que o cliente não abriu")
    }

    /// Lê o que o cliente mandou.
    fn ouvir(&mut self) {
        if !self.prefacio {
            if self.entrada.len() < PREFACIO.len() {
                return;
            }
            assert_eq!(&self.entrada[..PREFACIO.len()], PREFACIO);
            self.entrada.drain(..PREFACIO.len());
            self.prefacio = true;
            let ajustes = self.ajustes.clone();
            quadro::por_ajustes(&mut self.saida, &ajustes);
        }
        while self.entrada.len() >= CABECA {
            let c = quadro::ler_cabeca(self.entrada[..CABECA].try_into().unwrap());
            assert!(
                c.tamanho <= self.maior_quadro,
                "o cliente passou do maior quadro"
            );
            if self.entrada.len() < CABECA + c.tamanho {
                return;
            }
            let carga = self.entrada[CABECA..CABECA + c.tamanho].to_vec();
            self.entrada.drain(..CABECA + c.tamanho);
            self.quadros.push((c, carga.clone()));
            if let Some((n, _, _)) = &self.bloco {
                assert!(c.tipo == tipo::CONTINUATION && c.corrente == *n);
            }
            let q = quadro::ler(c, &carga).expect("o cliente mandou um quadro que a RFC recusa");
            match q {
                Quadro::Ajustes { ack: false, pares } => {
                    for par in pares.as_chunks::<6>().0 {
                        let id = u16::from_be_bytes([par[0], par[1]]);
                        let valor = i64::from(u32::from_be_bytes([par[2], par[3], par[4], par[5]]));
                        if id == ajuste::INITIAL_WINDOW_SIZE {
                            let delta = valor - self.janela_inicial;
                            self.janela_inicial = valor;
                            for s in &mut self.saindo {
                                s.janela += delta;
                            }
                        }
                    }
                    quadro::por_ajustes_ack(&mut self.saida);
                }
                Quadro::Ajustes { ack: true, .. } => {
                    let delta = self.recebe_anunciada - self.recebe_inicial;
                    self.recebe_inicial = self.recebe_anunciada;
                    for (_, j) in &mut self.recebe {
                        *j += delta;
                    }
                }
                Quadro::Janela {
                    corrente: 0,
                    incremento,
                } => self.janela += i64::from(incremento),
                Quadro::Janela {
                    corrente,
                    incremento,
                } => {
                    if let Some(s) = self.saindo.iter_mut().find(|s| s.corrente == corrente) {
                        s.janela += i64::from(incremento);
                    }
                }
                Quadro::Cabecalhos {
                    corrente,
                    bloco,
                    fim_da_corrente,
                    fim_da_cabeca,
                } => {
                    self.bloco = Some((corrente, bloco.to_vec(), fim_da_corrente));
                    if fim_da_cabeca {
                        self.fim_do_bloco();
                    }
                }
                Quadro::Continuacao {
                    bloco,
                    fim_da_cabeca,
                    ..
                } => {
                    self.bloco.as_mut().unwrap().1.extend_from_slice(bloco);
                    if fim_da_cabeca {
                        self.fim_do_bloco();
                    }
                }
                Quadro::Dados {
                    corrente,
                    dados,
                    fim,
                } => {
                    // O cliente respeita as janelas do servidor; o servidor
                    // as reabre conforme lê.
                    let n = c.tamanho as i64;
                    self.recebe_conexao -= n;
                    assert!(
                        self.recebe_conexao >= 0,
                        "o cliente passou da janela da conexão"
                    );
                    let inicial = self.recebe_inicial;
                    let j = match self.recebe.iter_mut().find(|(k, _)| *k == corrente) {
                        Some((_, j)) => j,
                        None => {
                            self.recebe.push((corrente, inicial));
                            &mut self.recebe.last_mut().unwrap().1
                        }
                    };
                    *j -= n;
                    assert!(*j >= 0, "o cliente passou da janela da corrente {corrente}");
                    if n > 0 {
                        *j += n;
                        self.recebe_conexao += n;
                        quadro::por_janela(&mut self.saida, corrente, n as u32);
                        quadro::por_janela(&mut self.saida, 0, n as u32);
                    }
                    self.recebido(corrente).corpo.extend_from_slice(dados);
                    if fim {
                        self.responder(corrente);
                    }
                }
                Quadro::Reinicio { corrente, codigo } => {
                    self.recebido(corrente).reiniciado = Some(codigo);
                    self.saindo.retain(|s| s.corrente != corrente);
                }
                Quadro::Ping { ack: false, dados } => quadro::por_ping_ack(&mut self.saida, &dados),
                _ => {}
            }
        }
    }

    fn fim_do_bloco(&mut self) {
        let (corrente, cru, fim) = self.bloco.take().unwrap();
        let (campos, passou) = self
            .decodificador
            .decodificar(&cru, usize::MAX)
            .expect("o bloco do cliente se decodifica");
        assert!(!passou);
        self.recebidos.push(Recebido {
            corrente,
            campos: campos
                .into_iter()
                .map(|c| {
                    (
                        String::from_utf8(c.nome).unwrap(),
                        String::from_utf8(c.valor).unwrap(),
                    )
                })
                .collect(),
            cru,
            ..Recebido::default()
        });
        if fim {
            self.responder(corrente);
        }
    }

    fn responder(&mut self, corrente: u32) {
        let r = self.recebido(corrente).clone();
        let rota = (self.rotas)(&r);
        let bloco_de = |campos: &[(String, String)], status: Option<u16>| {
            let mut bloco = Vec::new();
            if let Some(s) = status {
                Codificador::campo(
                    ":status",
                    format!("{s}").as_bytes(),
                    Representacao::SemIndexar,
                    &mut bloco,
                );
            }
            for (n, v) in campos {
                Codificador::campo(n, v.as_bytes(), Representacao::SemIndexar, &mut bloco);
            }
            bloco
        };
        let cabeca = bloco_de(&rota.cabecalhos, Some(rota.status));
        let trailers = (!rota.trailers.is_empty()).then(|| bloco_de(&rota.trailers, None));
        self.saindo.push(Saindo {
            corrente,
            cabeca: Some(cabeca),
            corpo: rota.corpo,
            mandado: 0,
            trailers,
            janela: self.janela_inicial,
        });
    }

    /// Manda o que as janelas do cliente deixam: a cabeça, os `DATA` e os
    /// *trailers* de cada resposta, uma corrente por vez ou intercaladas.
    fn produzir(&mut self) {
        loop {
            let mut algum = false;
            for i in 0..self.saindo.len() {
                let s = &mut self.saindo[i];
                if let Some(cabeca) = s.cabeca.take() {
                    let fim = s.corpo.is_empty() && s.trailers.is_none();
                    quadro::por_cabecalhos(&mut self.saida, s.corrente, &cabeca, fim, 16_384);
                    algum = true;
                } else if s.mandado < s.corpo.len() {
                    let n = (s.corpo.len() - s.mandado)
                        .min(self.quadro)
                        .min(self.janela.max(0) as usize)
                        .min(s.janela.max(0) as usize);
                    if n > 0 {
                        let fim = s.mandado + n == s.corpo.len() && s.trailers.is_none();
                        let pedaco = &s.corpo[s.mandado..s.mandado + n];
                        quadro::por_dados(&mut self.saida, s.corrente, pedaco, fim);
                        s.mandado += n;
                        s.janela -= n as i64;
                        self.janela -= n as i64;
                        algum = true;
                    }
                } else if let Some(t) = s.trailers.take() {
                    quadro::por_cabecalhos(&mut self.saida, s.corrente, &t, true, 16_384);
                    algum = true;
                }
                if algum && !self.intercalar {
                    break;
                }
            }
            self.saindo.retain(|s| !s.acabou());
            if !algum {
                return;
            }
        }
    }
}

impl Fluxo for Servidor {
    type Falha = FalhaDeTeste;

    fn mandar(&mut self, dados: &[u8]) -> Result<(), FalhaDeTeste> {
        self.idas += 1;
        self.entrada.extend_from_slice(dados);
        self.ouvir();
        Ok(())
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, FalhaDeTeste> {
        self.voltas += 1;
        if self.entregue == self.saida.len() {
            self.produzir();
        }
        if self.entregue == self.saida.len() {
            // Nada para mandar: numa rede de verdade, o cliente esperaria
            // até o prazo.
            return match self.fim {
                Some(f) => Err(f),
                None => Ok(0),
            };
        }
        let n = (self.saida.len() - self.entregue)
            .min(self.pedaco)
            .min(destino.len());
        destino[..n].copy_from_slice(&self.saida[self.entregue..self.entregue + n]);
        self.entregue += n;
        Ok(n)
    }
}

fn get(url: &str) -> Pedido {
    Pedido::novo(Metodo::Get, Url::ler(url).unwrap())
}

fn post(url: &str, corpo: &[u8]) -> Pedido {
    let mut p = Pedido::novo(Metodo::Post, Url::ler(url).unwrap());
    p.corpo = corpo.to_vec();
    p
}

/// O corpo que o servidor de mentira dá para o caminho `/n/<tamanho>`.
fn corpo_de(caminho: &str) -> Vec<u8> {
    let n: usize = caminho.rsplit('/').next().unwrap().parse().unwrap_or(0);
    (0..n).map(|i| b'a' + (i % 26) as u8).collect()
}

/// As rotas de sempre: `/n/<tamanho>` dá um corpo desse tamanho; `/eco`
/// devolve o corpo do pedido; o resto, `ola`.
fn rotas_padrao(r: &Recebido) -> Rota {
    let caminho = r.campo(":path").unwrap_or("/");
    if caminho.starts_with("/n/") {
        rota(200, &corpo_de(caminho))
    } else if caminho == "/eco" {
        rota(200, &r.corpo)
    } else {
        rota(200, b"ola")
    }
}

fn cliente(s: Servidor) -> ClienteH2<Servidor> {
    ClienteH2::novo(s)
}

const PEDACOS: [usize; 7] = [1, 2, 9, 13, 64, 4096, usize::MAX];

// --- O caminho de sempre ---

#[test]
fn uma_troca() {
    for pedaco in PEDACOS {
        let mut s = Servidor::novo(rotas_padrao);
        s.pedaco = pedaco;
        let mut c = cliente(s);
        let r = c
            .trocar(&get("http://bancada.duke/ola?x=1"), &Limites::default())
            .unwrap();
        assert_eq!(r.versao, Versao::Http2);
        assert_eq!(r.status, 200);
        assert_eq!(r.motivo, "");
        assert_eq!(r.corpo, b"ola");
        assert_eq!(r.cabecalho("content-length"), Some("3"));
        assert_eq!(r.enquadramento, Enquadramento::Quadros);
        assert!(r.reutilizavel);
        assert_eq!(c.trocas(), 1);
        assert_eq!(c.abertas(), 0);
        let s = c.devolver();
        // O que o cliente mandou: o prefácio e os ajustes dele, a janela da
        // conexão, o pedido — e o reconhecimento dos ajustes do servidor.
        let tipos: Vec<(u8, u8, u32)> = s
            .quadros
            .iter()
            .map(|(c, _)| (c.tipo, c.bandeiras, c.corrente))
            .collect();
        assert_eq!(
            tipos,
            [
                (tipo::SETTINGS, 0, 0),
                (tipo::WINDOW_UPDATE, 0, 0),
                (
                    tipo::HEADERS,
                    bandeira::END_STREAM | bandeira::END_HEADERS,
                    1
                ),
                (tipo::SETTINGS, bandeira::ACK, 0),
            ],
            "pedaco {pedaco}"
        );
        assert_eq!(
            s.quadros[0].1,
            [0, 2, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 6, 0, 0, 0x40, 0]
        );
        assert_eq!(
            u32::from_be_bytes(s.quadros[1].1[..4].try_into().unwrap()),
            (1 << 24) - 65_535
        );
        // Duas idas: o pedido, e o reconhecimento, que não espera o
        // próximo pedido.
        assert_eq!(s.idas, 2, "pedaco {pedaco}");
        let campos: Vec<(&str, &str)> = s.recebidos[0]
            .campos
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            campos,
            [
                (":method", "GET"),
                (":scheme", "http"),
                (":authority", "bancada.duke"),
                (":path", "/ola?x=1"),
                ("accept-encoding", "gzip, deflate"),
            ]
        );
        // O primeiro bloco começa dizendo que a tabela deste lado tem zero
        // bytes.
        assert_eq!(s.recebidos[0].cru[0], 0x20);
    }
}

#[test]
fn o_https_a_porta_e_os_cabecalhos_de_quem_chama() {
    let mut c = cliente(Servidor::novo(rotas_padrao));
    let mut p = post("https://bancada.duke:8443/eco", b"abc");
    p.cabecalho("X-Duke", "Sim").unwrap();
    p.cabecalho("Authorization", "Bearer segredo").unwrap();
    let r = c.trocar(&p, &Limites::default()).unwrap();
    assert_eq!(r.corpo, b"abc");
    let s = c.devolver();
    let pedido = &s.recebidos[0];
    assert_eq!(pedido.campo(":method"), Some("POST"));
    assert_eq!(pedido.campo(":scheme"), Some("https"));
    assert_eq!(pedido.campo(":authority"), Some("bancada.duke:8443"));
    // Os nomes em minúsculas; o tamanho, de quem escreve o pedido.
    assert_eq!(pedido.campo("x-duke"), Some("Sim"));
    assert_eq!(pedido.campo("content-length"), Some("3"));
    assert_eq!(pedido.campo("host"), None);
    // A credencial vai como nunca indexada: `0001 xxxx`, com o nome literal
    // (`authorization` está na estática, no 23: `0x1f 0x08`).
    assert!(
        pedido.cru.windows(2).any(|w| w == [0x1f, 0x08]),
        "{:x?}",
        pedido.cru
    );
}

#[test]
fn o_post_sem_corpo_diz_zero_e_acaba_na_cabeca() {
    let mut c = cliente(Servidor::novo(rotas_padrao));
    let r = c
        .trocar(&post("http://h/eco", b""), &Limites::default())
        .unwrap();
    assert_eq!(r.corpo, b"");
    let s = c.devolver();
    assert_eq!(s.recebidos[0].campo("content-length"), Some("0"));
    assert!(s.do_tipo(tipo::DATA).is_empty());
}

#[test]
fn varias_correntes_intercaladas_recebidas_fora_de_ordem() {
    for pedaco in PEDACOS {
        let mut s = Servidor::novo(rotas_padrao);
        s.intercalar = true;
        s.quadro = 1000;
        s.pedaco = pedaco;
        let mut c = cliente(s);
        let tamanhos = [0, 1, 100, 20_000, 50_000];
        let correntes: Vec<_> = tamanhos
            .iter()
            .map(|n| {
                c.enviar(&get(&format!("http://h/n/{n}")), &Limites::default())
                    .unwrap()
            })
            .collect();
        assert_eq!(c.abertas(), 5);
        let numeros: Vec<u32> = correntes.iter().map(|c| c.numero()).collect();
        assert_eq!(numeros, [1, 3, 5, 7, 9]);
        for (corrente, n) in correntes.into_iter().zip(tamanhos).rev() {
            let r = c.receber(corrente).unwrap();
            assert_eq!(r.corpo, corpo_de(&format!("/{n}")), "pedaco {pedaco}, {n}");
        }
        assert_eq!(c.abertas(), 0);
        assert_eq!(c.trocas(), 5);
    }
}

#[test]
fn a_janela_da_corrente_esperada_abre_de_uma_vez() {
    let mut c = cliente(Servidor::novo(rotas_padrao));
    let limites = Limites {
        corpo: 1 << 20,
        ..Limites::default()
    };
    let r = c.trocar(&get("http://h/n/1000000"), &limites).unwrap();
    assert_eq!(r.corpo.len(), 1_000_000);
    assert_eq!(r.corpo, corpo_de("/1000000"));
    let s = c.devolver();
    // Um `WINDOW_UPDATE` só para a corrente: até o limite do corpo e um
    // byte além, menos o que ainda havia na janela.
    let janelas = s.janelas_para(1);
    assert_eq!(janelas.len(), 1, "{janelas:?}");
}

#[test]
fn a_corrente_parada_segura_so_a_janela_dela() {
    let mut s = Servidor::novo(rotas_padrao);
    s.quadro = 4096;
    let mut c = ClienteH2::com(
        s,
        AjustesH2 {
            janela: 10_000,
            ..AjustesH2::default()
        },
    );
    let grande = c
        .enviar(&get("http://h/n/200000"), &Limites::default())
        .unwrap();
    let pequena = c
        .enviar(&get("http://h/n/10"), &Limites::default())
        .unwrap();
    // A pequena chega com a grande parada na janela dela: nada da grande é
    // reaberto enquanto ninguém a espera.
    let r = c.receber(pequena).unwrap();
    assert_eq!(r.corpo, corpo_de("/10"));
    assert!(c.fluxo().janelas_para(1).is_empty());
    let r = c.receber(grande).unwrap();
    assert_eq!(r.corpo, corpo_de("/200000"));
    assert_eq!(c.fluxo().janelas_para(1).len(), 1);
}

#[test]
fn o_corpo_do_pedido_espera_a_janela_do_servidor() {
    for pedaco in [1, 7, 4096, usize::MAX] {
        let mut s =
            Servidor::novo(rotas_padrao).com_ajustes(&[(ajuste::INITIAL_WINDOW_SIZE, 1000)]);
        s.pedaco = pedaco;
        let mut c = cliente(s);
        let corpo: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let r = c
            .trocar(&post("http://h/eco", &corpo), &Limites::default())
            .unwrap();
        assert_eq!(r.corpo, corpo, "pedaco {pedaco}");
        let s = c.devolver();
        // O servidor confere cada quadro contra as janelas dele: chegar
        // aqui é não ter passado de nenhuma.
        assert_eq!(s.recebidos[0].corpo, corpo);
    }
}

#[test]
fn o_maior_quadro_do_servidor_vale_depois_dos_ajustes() {
    let s = Servidor::novo(rotas_padrao).com_ajustes(&[(ajuste::MAX_FRAME_SIZE, 20_000)]);
    let mut c = cliente(s);
    c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    let corpo = vec![7u8; 60_000];
    c.trocar(&post("http://h/eco", &corpo), &Limites::default())
        .unwrap();
    let s = c.devolver();
    let maior = s
        .do_tipo(tipo::DATA)
        .iter()
        .map(|(c, _)| c.tamanho)
        .max()
        .unwrap();
    assert_eq!(maior, 20_000);
}

#[test]
fn as_correntes_de_quem_chama_tem_teto() {
    let mut c = ClienteH2::com(
        Servidor::novo(rotas_padrao),
        AjustesH2 {
            correntes: 2,
            ..AjustesH2::default()
        },
    );
    let a = c.enviar(&get("http://h/a"), &Limites::default()).unwrap();
    let b = c.enviar(&get("http://h/b"), &Limites::default()).unwrap();
    assert_eq!(
        c.enviar(&get("http://h/c"), &Limites::default()),
        Err(Erro::Limite(Limite::Correntes))
    );
    // Uma recebida, a vaga volta.
    c.receber(a).unwrap();
    let d = c.enviar(&get("http://h/d"), &Limites::default()).unwrap();
    c.receber(b).unwrap();
    c.receber(d).unwrap();
    assert_eq!(
        Erro::<FalhaDeTeste>::Limite(Limite::Correntes).codigo(),
        Some("HTTP_TOO_MANY_STREAMS")
    );
}

#[test]
fn o_servidor_pode_aceitar_menos_correntes() {
    let s = Servidor::novo(rotas_padrao).com_ajustes(&[(ajuste::MAX_CONCURRENT_STREAMS, 1)]);
    let mut c = cliente(s);
    // Os ajustes chegam com a primeira resposta.
    c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    let a = c.enviar(&get("http://h/a"), &Limites::default()).unwrap();
    assert_eq!(
        c.enviar(&get("http://h/b"), &Limites::default()),
        Err(Erro::Limite(Limite::Correntes))
    );
    c.receber(a).unwrap();
    c.trocar(&get("http://h/c"), &Limites::default()).unwrap();
}

#[test]
fn os_cookies_pelo_pote_e_o_cookie_nunca_indexado() {
    let mut c = cliente(Servidor::novo(|r: &Recebido| {
        let mut resposta = rota(200, b"ok");
        if r.campo(":path") == Some("/entrar") {
            resposta.cabecalhos.push((
                String::from("set-cookie"),
                String::from("sessao=abc; Path=/"),
            ));
        }
        resposta
    }));
    let mut pote = Pote::novo();
    let mut relogio = || Some(1_700_000_000);
    let r = c
        .trocar_com_pote(
            &get("http://h/entrar"),
            &Limites::default(),
            &mut pote,
            &mut relogio,
        )
        .unwrap();
    assert_eq!(r.cookies.novos, 1);
    assert_eq!(r.cabecalho("set-cookie"), None);
    let r = c
        .trocar_com_pote(
            &get("http://h/outra"),
            &Limites::default(),
            &mut pote,
            &mut relogio,
        )
        .unwrap();
    assert_eq!(r.corpo, b"ok");
    let s = c.devolver();
    assert_eq!(s.recebidos[0].campo("cookie"), None);
    assert_eq!(s.recebidos[1].campo("cookie"), Some("sessao=abc"));
    // `0001 1111` e `0x11`: nunca indexado, com o nome no 32 da estática.
    assert!(s.recebidos[1].cru.windows(2).any(|w| w == [0x1f, 0x11]));
}

#[test]
fn o_relogio_e_lido_uma_vez_por_troca_dividida() {
    let mut c = cliente(Servidor::novo(|_: &Recebido| {
        let mut resposta = rota(200, b"ok");
        resposta
            .cabecalhos
            .push((String::from("set-cookie"), String::from("a=1; Max-Age=60")));
        resposta
    }));
    let mut pote = Pote::novo();
    let mut leituras = 0;
    let mut relogio = || {
        leituras += 1;
        Some(1_700_000_000)
    };
    // A primeira troca grava um cookie com validade: o relógio, uma vez.
    let a = c
        .enviar_com_pote(
            &get("http://h/"),
            &Limites::default(),
            &mut pote,
            &mut relogio,
        )
        .unwrap();
    c.receber_com_pote(a, &mut pote, &mut relogio).unwrap();
    // A segunda o leva — lido no envio —, e a resposta reaproveita a leitura.
    let b = c
        .enviar_com_pote(
            &get("http://h/"),
            &Limites::default(),
            &mut pote,
            &mut relogio,
        )
        .unwrap();
    c.receber_com_pote(b, &mut pote, &mut relogio).unwrap();
    drop(relogio);
    assert_eq!(leituras, 2);
}

#[test]
fn o_corpo_comprimido_e_decodificado() {
    let mut c = cliente(Servidor::novo(|_: &Recebido| {
        let mut r = rota(200, &OLA_GZIP);
        r.cabecalhos
            .push((String::from("content-encoding"), String::from("gzip")));
        r
    }));
    let r = c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    assert_eq!(r.corpo, b"ola, Duke\n");
    assert_eq!(r.codificacao, Some(Codificacao::Gzip));
    assert_eq!(r.no_fio, OLA_GZIP.len());
}

#[test]
fn head_204_e_304_nao_tem_corpo() {
    let mut c = cliente(Servidor::novo(|r: &Recebido| {
        let status = match r.campo(":path") {
            Some("/204") => 204,
            Some("/304") => 304,
            _ => 200,
        };
        // O `content-length` fala da representação, e não vem corpo.
        Rota {
            status,
            cabecalhos: vec![(String::from("content-length"), String::from("100"))],
            corpo: Vec::new(),
            trailers: Vec::new(),
        }
    }));
    let mut head = get("http://h/");
    head.metodo = Metodo::Head;
    for p in [head, get("http://h/204"), get("http://h/304")] {
        let r = c.trocar(&p, &Limites::default()).unwrap();
        assert_eq!(r.corpo, b"");
        assert_eq!(r.enquadramento, Enquadramento::Nenhum);
    }
}

#[test]
fn os_trailers_sao_conferidos_e_largados() {
    let mut c = cliente(Servidor::novo(|_: &Recebido| {
        let mut r = rota(200, b"corpo");
        r.trailers = vec![(String::from("x-soma"), String::from("abc"))];
        r
    }));
    let r = c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    assert_eq!(r.corpo, b"corpo");
    assert_eq!(r.cabecalho("x-soma"), None);
}

#[test]
fn cancelar_larga_a_corrente() {
    let mut s = Servidor::novo(rotas_padrao);
    s.intercalar = true;
    s.quadro = 1000;
    let mut c = cliente(s);
    let a = c
        .enviar(&get("http://h/n/30000"), &Limites::default())
        .unwrap();
    let b = c
        .enviar(&get("http://h/n/30000"), &Limites::default())
        .unwrap();
    c.cancelar(a);
    let r = c.receber(b).unwrap();
    assert_eq!(r.corpo, corpo_de("/30000"));
    let s = c.devolver();
    // O reinício saiu antes da espera, e o servidor parou de mandar a
    // largada.
    let reinicios = s.do_tipo(tipo::RST_STREAM);
    assert_eq!(reinicios.len(), 1);
    assert_eq!(reinicios[0].0.corrente, 1);
    assert_eq!(reinicios[0].1, CodigoH2::CANCEL.0.to_be_bytes());
    assert_eq!(s.recebidos[0].reiniciado, Some(CodigoH2::CANCEL));
}

#[test]
fn fechar_manda_o_adeus_e_a_conexao_nao_abre_mais() {
    let mut c = cliente(Servidor::novo(rotas_padrao));
    c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    c.fechar().unwrap();
    assert!(!c.pronto());
    assert_eq!(
        c.enviar(&get("http://h/"), &Limites::default()),
        Err(Erro::Esgotada)
    );
    let s = c.devolver();
    let adeus = s.do_tipo(tipo::GOAWAY);
    assert_eq!(adeus.len(), 1);
    assert_eq!(adeus[0].1, [0, 0, 0, 0, 0, 0, 0, 0]);
    // A que nunca mandou nada não tem o que avisar.
    let mut c = cliente(Servidor::novo(rotas_padrao));
    c.fechar().unwrap();
    assert_eq!(c.devolver().idas, 0);
}

#[test]
fn o_pedido_que_pede_o_fecho_e_o_ultimo() {
    let mut c = cliente(Servidor::novo(rotas_padrao));
    let mut p = get("http://h/");
    p.fechar = true;
    let a = c.enviar(&p, &Limites::default()).unwrap();
    assert!(!c.pronto());
    assert_eq!(
        c.enviar(&get("http://h/"), &Limites::default()),
        Err(Erro::Esgotada)
    );
    let r = c.receber(a).unwrap();
    assert!(!r.reutilizavel);
}

#[test]
fn a_corrente_de_outra_conexao_nao_e_entregue() {
    let mut um = cliente(Servidor::novo(rotas_padrao));
    let mut outro = cliente(Servidor::novo(rotas_padrao));
    let a = um.enviar(&get("http://h/um"), &Limites::default()).unwrap();
    let b = outro
        .enviar(&get("http://h/outro"), &Limites::default())
        .unwrap();
    assert_eq!(a.numero(), b.numero());
    assert_eq!(outro.receber(a).err(), Some(Erro::Esgotada));
    assert_eq!(outro.receber(b).unwrap().corpo, b"ola");
    // A de `um` continua lá, e não foi tocada.
    assert_eq!(um.abertas(), 1);
}

// --- Os roteiros: bytes escritos à mão ---

fn ajustes_do_servidor(pares: &[(u16, u32)]) -> Vec<u8> {
    let mut q = Vec::new();
    quadro::por_ajustes(&mut q, pares);
    q
}

/// Um bloco de cabeça com os campos como vêm, sem indexar.
fn bloco(campos: &[(&str, &str)]) -> Vec<u8> {
    let mut b = Vec::new();
    for &(n, v) in campos {
        Codificador::campo(n, v.as_bytes(), Representacao::SemIndexar, &mut b);
    }
    b
}

fn cabeca(corrente: u32, bloco: &[u8], fim: bool) -> Vec<u8> {
    let mut q = Vec::new();
    quadro::por_cabecalhos(&mut q, corrente, bloco, fim, 16_384);
    q
}

fn ok_200(corrente: u32, corpo: &[u8]) -> Vec<u8> {
    let tamanho = format!("{}", corpo.len());
    let mut q = cabeca(
        corrente,
        &bloco(&[(":status", "200"), ("content-length", &tamanho)]),
        corpo.is_empty(),
    );
    if !corpo.is_empty() {
        quadro::por_dados(&mut q, corrente, corpo, true);
    }
    q
}

fn dados(corrente: u32, corpo: &[u8], fim: bool) -> Vec<u8> {
    let mut q = Vec::new();
    quadro::por_dados(&mut q, corrente, corpo, fim);
    q
}

fn cru(tamanho: usize, t: u8, bandeiras: u8, corrente: u32, carga: &[u8]) -> Vec<u8> {
    let mut q = Vec::new();
    quadro::por_cabeca(&mut q, tamanho, t, bandeiras, corrente);
    q.extend_from_slice(carga);
    q
}

/// Os quadros que o cliente mandou, depois do prefácio.
fn do_cliente(mandado: &[u8]) -> Vec<(Cabeca, Vec<u8>)> {
    assert_eq!(&mandado[..PREFACIO.len()], PREFACIO);
    let mut resto = &mandado[PREFACIO.len()..];
    let mut lidos = Vec::new();
    while !resto.is_empty() {
        let c = quadro::ler_cabeca(resto[..CABECA].try_into().unwrap());
        lidos.push((c, resto[CABECA..CABECA + c.tamanho].to_vec()));
        resto = &resto[CABECA + c.tamanho..];
    }
    lidos
}

/// O último quadro que o cliente mandou: o tipo, a corrente e o código —
/// do `RST_STREAM` ou do `GOAWAY`.
fn ultimo(mandado: &[u8]) -> (u8, u32, CodigoH2) {
    let quadros = do_cliente(mandado);
    let (c, p) = quadros.last().unwrap();
    let codigo = match c.tipo {
        tipo::RST_STREAM => u32::from_be_bytes(p[..4].try_into().unwrap()),
        tipo::GOAWAY => u32::from_be_bytes(p[4..8].try_into().unwrap()),
        _ => u32::MAX,
    };
    (c.tipo, c.corrente, CodigoH2(codigo))
}

/// Uma conexão com o roteiro `chegada` em pedaços de `pedaco`, e as
/// correntes de `n` pedidos `GET` já enviados.
fn roteiro(chegada: &[u8], pedaco: usize, n: usize) -> (ClienteH2<Roteiro>, Vec<crate::Corrente>) {
    let mut c = ClienteH2::novo(Roteiro::novo(chegada, pedaco));
    let correntes = (0..n)
        .map(|i| {
            c.enviar(&get(&format!("http://h/{i}")), &Limites::default())
                .unwrap()
        })
        .collect();
    (c, correntes)
}

type Recebida = Result<Resposta, Erro<FalhaDeTeste>>;

/// A primeira corrente com o roteiro `primeira` depois dos ajustes, e uma
/// segunda que responde direito depois: a falha da primeira é só dela, e o
/// cliente mandou `RST_STREAM` com `codigo` — ou nenhum, se o servidor já
/// tinha acabado a corrente: fechada dos dois lados, nada mais vai nela.
fn so_da_corrente(primeira: &[u8], codigo: Option<CodigoH2>) -> Erro<FalhaDeTeste> {
    let mut resultado = None;
    for pedaco in [1, 5, 4096] {
        let chegada = [
            ajustes_do_servidor(&[]),
            primeira.to_vec(),
            ok_200(3, b"segunda"),
        ]
        .concat();
        let (mut c, mut correntes) = roteiro(&chegada, pedaco, 2);
        let b = correntes.pop().unwrap();
        let a = correntes.pop().unwrap();
        let erro = c.receber(a).unwrap_err();
        assert_eq!(c.receber(b).unwrap().corpo, b"segunda", "pedaco {pedaco}");
        assert!(c.pronto());
        let reinicios: Vec<(u32, Vec<u8>)> = do_cliente(&c.fluxo().mandado)
            .into_iter()
            .filter(|(c, _)| c.tipo == tipo::RST_STREAM)
            .map(|(c, p)| (c.corrente, p))
            .collect();
        let esperados: Vec<(u32, Vec<u8>)> = codigo
            .map(|c| (1, c.0.to_be_bytes().to_vec()))
            .into_iter()
            .collect();
        assert_eq!(reinicios, esperados, "pedaco {pedaco}");
        assert!(resultado.is_none_or(|r| r == erro), "pedaco {pedaco}");
        resultado = Some(erro);
    }
    resultado.unwrap()
}

/// O roteiro `chegada` depois dos ajustes acaba com a conexão: as duas
/// correntes falham com o mesmo erro, o cliente manda `GOAWAY` com
/// `codigo`, e a conexão não abre mais.
fn da_conexao(chegada: &[u8], codigo: CodigoH2) -> Erro<FalhaDeTeste> {
    let mut resultado = None;
    for pedaco in [1, 5, 4096] {
        let chegada = [ajustes_do_servidor(&[]), chegada.to_vec()].concat();
        let (mut c, mut correntes) = roteiro(&chegada, pedaco, 2);
        let b = correntes.pop().unwrap();
        let a = correntes.pop().unwrap();
        let erro = c.receber(a).unwrap_err();
        assert_eq!(c.receber(b).unwrap_err(), erro, "pedaco {pedaco}");
        assert!(!c.pronto());
        assert_eq!(
            c.enviar(&get("http://h/"), &Limites::default()),
            Err(Erro::Esgotada)
        );
        assert_eq!(
            ultimo(&c.fluxo().mandado),
            (tipo::GOAWAY, 0, codigo),
            "pedaco {pedaco}"
        );
        assert!(resultado.is_none_or(|r| r == erro), "pedaco {pedaco}");
        resultado = Some(erro);
    }
    resultado.unwrap()
}

#[test]
fn as_respostas_malformadas_sao_so_da_corrente() {
    let p = |m| Erro::Protocolo(m);
    for (campos, esperado) in [
        (vec![("server", "x")], p(Motivo::Mensagem)),
        (
            vec![("server", "x"), (":status", "200")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), (":status", "200")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":method", "GET"), (":status", "200")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), (":path", "/")],
            p(Motivo::Mensagem),
        ),
        (vec![(":status", "20")], p(Motivo::Status)),
        (vec![(":status", "2000")], p(Motivo::Status)),
        (vec![(":status", "abc")], p(Motivo::Status)),
        (vec![(":status", "099")], p(Motivo::Status)),
        (vec![(":status", "600")], p(Motivo::Status)),
        (vec![(":status", "101")], p(Motivo::Troca)),
        (
            vec![(":status", "200"), ("Server", "x")],
            p(Motivo::Cabecalho),
        ),
        (vec![(":status", "200"), ("", "x")], p(Motivo::Cabecalho)),
        (vec![(":status", "200"), ("a b", "x")], p(Motivo::Cabecalho)),
        (vec![(":status", "200"), ("x", " v")], p(Motivo::Cabecalho)),
        (vec![(":status", "200"), ("x", "v\t")], p(Motivo::Cabecalho)),
        (
            vec![(":status", "200"), ("x", "a\r\nb")],
            p(Motivo::Cabecalho),
        ),
        (
            vec![(":status", "200"), ("x", "a\0b")],
            p(Motivo::Cabecalho),
        ),
        (
            vec![(":status", "200"), ("connection", "close")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), ("keep-alive", "1")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), ("proxy-connection", "x")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), ("transfer-encoding", "chunked")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), ("upgrade", "h2c")],
            p(Motivo::Mensagem),
        ),
        (
            vec![(":status", "200"), ("content-length", "x")],
            p(Motivo::Tamanho),
        ),
        (
            vec![(":status", "200"), ("content-length", "1, 2")],
            p(Motivo::Tamanho),
        ),
    ] {
        // Sem acabar a corrente: o cliente a reinicia.
        let erro = so_da_corrente(
            &cabeca(1, &bloco(&campos), false),
            Some(CodigoH2::PROTOCOL_ERROR),
        );
        assert_eq!(erro, esperado, "{campos:?}");
        // Acabando-a: a mesma falha, sem reinício.
        let erro = so_da_corrente(&cabeca(1, &bloco(&campos), true), None);
        assert_eq!(erro, esperado, "{campos:?}");
    }
}

#[test]
fn o_corpo_que_nao_confere_com_a_cabeca() {
    let tamanho = |n: &str| {
        cabeca(
            1,
            &bloco(&[(":status", "200"), ("content-length", n)]),
            false,
        )
    };
    // Menos que o prometido, mais que o prometido, dados antes da cabeça —
    // com o fim da corrente, sem reinício; sem ele, com.
    let reinicia = Some(CodigoH2::PROTOCOL_ERROR);
    for (chegada, reinicio, esperado) in [
        (
            [tamanho("5"), dados(1, b"abc", true)].concat(),
            None,
            Motivo::Tamanho,
        ),
        (
            [tamanho("2"), dados(1, b"abc", true)].concat(),
            None,
            Motivo::Tamanho,
        ),
        (
            [tamanho("2"), dados(1, b"abc", false)].concat(),
            reinicia,
            Motivo::Tamanho,
        ),
        (
            [tamanho("2"), dados(1, b"ab", false), dados(1, b"c", true)].concat(),
            None,
            Motivo::Tamanho,
        ),
        (dados(1, b"abc", true), None, Motivo::Mensagem),
        (dados(1, b"abc", false), reinicia, Motivo::Mensagem),
    ] {
        assert_eq!(
            so_da_corrente(&chegada, reinicio),
            Erro::Protocolo(esperado)
        );
    }
    // O tamanho certo em vários pedaços, e um `DATA` vazio no fim.
    let chegada = [
        ajustes_do_servidor(&[]),
        tamanho("3"),
        dados(1, b"ab", false),
        dados(1, b"c", false),
        dados(1, b"", true),
    ]
    .concat();
    let (mut c, mut correntes) = roteiro(&chegada, 3, 1);
    assert_eq!(c.receber(correntes.pop().unwrap()).unwrap().corpo, b"abc");
}

#[test]
fn as_informativas_passam_e_nao_acabam_a_corrente() {
    let informativa = |s: &str| cabeca(1, &bloco(&[(":status", s)]), false);
    let chegada = [
        ajustes_do_servidor(&[]),
        informativa("100"),
        informativa("103"),
        ok_200(1, b"x"),
    ]
    .concat();
    let (mut c, mut correntes) = roteiro(&chegada, 7, 1);
    let r = c.receber(correntes.pop().unwrap()).unwrap();
    assert_eq!((r.status, r.corpo.as_slice()), (200, &b"x"[..]));
    // A que acaba a corrente, e as demais.
    assert_eq!(
        so_da_corrente(&cabeca(1, &bloco(&[(":status", "100")]), true), None),
        Erro::Protocolo(Motivo::Mensagem)
    );
    let muitas: Vec<u8> = (0..9).flat_map(|_| informativa("100")).collect();
    assert_eq!(
        so_da_corrente(&muitas, Some(CodigoH2::PROTOCOL_ERROR)),
        Erro::Protocolo(Motivo::Informativas)
    );
}

#[test]
fn os_trailers_tortos() {
    let comeco = cabeca(1, &bloco(&[(":status", "200")]), false);
    for (trailers, reinicio) in [
        // Sem acabar a corrente.
        (
            cabeca(1, &bloco(&[("x", "1")]), false),
            Some(CodigoH2::PROTOCOL_ERROR),
        ),
        // Com pseudo-cabeçalho.
        (cabeca(1, &bloco(&[(":status", "200")]), true), None),
    ] {
        assert_eq!(
            so_da_corrente(
                &[comeco.clone(), dados(1, b"a", false), trailers].concat(),
                reinicio
            ),
            Erro::Protocolo(Motivo::Mensagem)
        );
    }
}

#[test]
fn a_resposta_sem_conteudo_nao_tem_dados() {
    let chegada = [
        ajustes_do_servidor(&[]),
        cabeca(1, &bloco(&[(":status", "204")]), false),
        dados(1, b"x", true),
    ]
    .concat();
    let (mut c, mut correntes) = roteiro(&chegada, 4096, 1);
    assert_eq!(
        c.receber(correntes.pop().unwrap()),
        Err(Erro::Protocolo(Motivo::Mensagem))
    );
}

#[test]
fn os_limites_da_resposta_sao_da_corrente() {
    let limites = |l: Limites| {
        move |chegada: &[u8]| -> Recebida {
            let chegada = [ajustes_do_servidor(&[]), chegada.to_vec()].concat();
            let mut c = ClienteH2::novo(Roteiro::novo(&chegada, 4096));
            let a = c.enviar(&get("http://h/"), &l).unwrap();
            let r = c.receber(a);
            let reinicios = do_cliente(&c.fluxo().mandado)
                .iter()
                .filter(|(c, _)| c.tipo == tipo::RST_STREAM)
                .map(|(c, p)| (c.corrente, p.clone()))
                .collect::<Vec<_>>();
            assert!(
                reinicios.is_empty()
                    || reinicios == [(1, CodigoH2::CANCEL.0.to_be_bytes().to_vec())],
                "{reinicios:?}"
            );
            r
        }
    };
    let corpo = limites(Limites {
        corpo: 10,
        ..Limites::default()
    });
    assert_eq!(corpo(&ok_200(1, &[1; 10])).unwrap().corpo.len(), 10);
    assert_eq!(
        corpo(&ok_200(1, &[1; 11])),
        Err(Erro::Limite(Limite::Corpo))
    );
    // O `content-length` além do limite é recusado antes do corpo.
    let grande = cabeca(
        1,
        &bloco(&[(":status", "200"), ("content-length", "11")]),
        false,
    );
    assert_eq!(corpo(&grande), Err(Erro::Limite(Limite::Corpo)));
    let cabecalhos = limites(Limites {
        cabecalhos: 2,
        ..Limites::default()
    });
    let tres = cabeca(
        1,
        &bloco(&[(":status", "200"), ("a", "1"), ("b", "2"), ("c", "3")]),
        true,
    );
    assert_eq!(cabecalhos(&tres), Err(Erro::Limite(Limite::Cabecalhos)));
    let linha = limites(Limites {
        linha: 10,
        ..Limites::default()
    });
    let longo = cabeca(1, &bloco(&[(":status", "200"), ("abc", "12345")]), true);
    assert_eq!(linha(&longo).unwrap().status, 200);
    let longo = cabeca(1, &bloco(&[(":status", "200"), ("abc", "123456")]), true);
    assert_eq!(linha(&longo), Err(Erro::Limite(Limite::Linha)));
    // A cabeça contada como o HPACK conta: `:status` e `200` (42), e `a`,
    // `1` (34).
    let cabeca_ = limites(Limites {
        cabeca: 76,
        ..Limites::default()
    });
    let dois = cabeca(1, &bloco(&[(":status", "200"), ("a", "1")]), true);
    assert_eq!(cabeca_(&dois).unwrap().status, 200);
    let tres = cabeca(1, &bloco(&[(":status", "200"), ("a", "12")]), true);
    assert_eq!(cabeca_(&tres), Err(Erro::Limite(Limite::Cabeca)));
}

#[test]
fn a_cabeca_alem_do_limite_mantem_a_tabela_certa() {
    // A primeira corrente traz um campo indexado grande demais para o
    // limite dela; a segunda aponta para ele na tabela dinâmica.
    let grande = "v".repeat(100);
    let mut b1 = bloco(&[(":status", "200")]);
    b1.extend_from_slice(&[0x40, 0x01, b'x', 100]);
    b1.extend_from_slice(grande.as_bytes());
    let b3 = [0x88, 0xbe];
    let chegada = [
        ajustes_do_servidor(&[]),
        cabeca(1, &b1, true),
        cabeca(3, &b3, true),
    ]
    .concat();
    let mut c = ClienteH2::novo(Roteiro::novo(&chegada, 4096));
    let pequeno = Limites {
        cabeca: 100,
        ..Limites::default()
    };
    let a = c.enviar(&get("http://h/a"), &pequeno).unwrap();
    let b = c.enviar(&get("http://h/b"), &Limites::default()).unwrap();
    assert_eq!(c.receber(a), Err(Erro::Limite(Limite::Cabeca)));
    let r = c.receber(b).unwrap();
    assert_eq!(r.cabecalho("x"), Some(grande.as_str()));
}

#[test]
fn o_reinicio_do_servidor() {
    for (codigo, esperado) in [
        (CodigoH2::REFUSED_STREAM, Erro::Recusada),
        (
            CodigoH2::INTERNAL_ERROR,
            Erro::Reiniciada(CodigoH2::INTERNAL_ERROR),
        ),
        (CodigoH2::NO_ERROR, Erro::Reiniciada(CodigoH2::NO_ERROR)),
        (CodigoH2(0xabc), Erro::Reiniciada(CodigoH2(0xabc))),
    ] {
        let mut reinicio = Vec::new();
        quadro::por_reinicio(&mut reinicio, 1, codigo);
        let chegada = [ajustes_do_servidor(&[]), reinicio, ok_200(3, b"b")].concat();
        let (mut c, mut correntes) = roteiro(&chegada, 3, 2);
        let b = correntes.pop().unwrap();
        let a = correntes.pop().unwrap();
        assert_eq!(c.receber(a), Err(esperado));
        assert_eq!(c.receber(b).unwrap().corpo, b"b");
        // O reinício do servidor não ganha outro do cliente.
        assert!(
            do_cliente(&c.fluxo().mandado)
                .iter()
                .all(|(c, _)| c.tipo != tipo::RST_STREAM)
        );
    }
    // Depois da resposta inteira, o reinício só para o pedido: a resposta
    // fica (RFC 9113, 8.1).
    let mut reinicio = Vec::new();
    quadro::por_reinicio(&mut reinicio, 1, CodigoH2::NO_ERROR);
    let chegada = [ajustes_do_servidor(&[]), ok_200(1, b"a"), reinicio].concat();
    let (mut c, mut correntes) = roteiro(&chegada, 4096, 1);
    assert_eq!(c.receber(correntes.pop().unwrap()).unwrap().corpo, b"a");
    assert_eq!(
        Erro::<FalhaDeTeste>::Recusada.codigo(),
        Some("HTTP_STREAM_REFUSED")
    );
    assert_eq!(
        Erro::<FalhaDeTeste>::Reiniciada(CodigoH2::CANCEL).codigo(),
        Some("HTTP_STREAM_RESET")
    );
}

#[test]
fn os_dados_alem_da_janela_da_corrente() {
    let chegada = [
        ajustes_do_servidor(&[]),
        cabeca(1, &bloco(&[(":status", "200")]), false),
        dados(1, &[0; 100], false),
        dados(1, &[0; 1], false),
        ok_200(3, b"b"),
    ]
    .concat();
    let mut c = ClienteH2::com(
        Roteiro::novo(&chegada, 4096),
        AjustesH2 {
            janela: 100,
            ..AjustesH2::default()
        },
    );
    let a = c.enviar(&get("http://h/a"), &Limites::default()).unwrap();
    let b = c.enviar(&get("http://h/b"), &Limites::default()).unwrap();
    // Esperada, a corrente teria a janela reaberta: a `b` é esperada antes,
    // e a `a` passa da dela.
    assert_eq!(c.receber(b).unwrap().corpo, b"b");
    assert_eq!(c.receber(a), Err(Erro::Protocolo(Motivo::Janela)));
    let reinicio = do_cliente(&c.fluxo().mandado)
        .into_iter()
        .find(|(c, _)| c.tipo == tipo::RST_STREAM)
        .unwrap();
    assert_eq!(
        (reinicio.0.corrente, reinicio.1),
        (1, CodigoH2::FLOW_CONTROL_ERROR.0.to_be_bytes().to_vec())
    );
}

#[test]
fn o_preenchimento_conta_na_janela_e_nao_no_corpo() {
    // `HEADERS` com preenchimento e prioridade; `DATA` com preenchimento.
    let b = bloco(&[(":status", "200"), ("content-length", "3")]);
    let mut carga = vec![2u8, 0, 0, 0, 0, 16];
    carga.extend_from_slice(&b);
    carga.extend_from_slice(&[0, 0]);
    let h = cru(
        carga.len(),
        tipo::HEADERS,
        bandeira::END_HEADERS | bandeira::PADDED | bandeira::PRIORITY,
        1,
        &carga,
    );
    let d = cru(
        14,
        tipo::DATA,
        bandeira::END_STREAM | bandeira::PADDED,
        1,
        &[10, b'a', b'b', b'c', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let chegada = [ajustes_do_servidor(&[]), h, d].concat();
    let (mut c, mut correntes) = roteiro(&chegada, 3, 1);
    assert_eq!(c.receber(correntes.pop().unwrap()).unwrap().corpo, b"abc");
}

#[test]
fn quadros_desconhecidos_prioridade_e_ping_no_meio() {
    let mut ping = Vec::new();
    quadro::por_cabeca(&mut ping, 8, tipo::PING, 0, 0);
    ping.extend_from_slice(b"12345678");
    let chegada = [
        ajustes_do_servidor(&[]),
        cru(3, 0xfa, 0xff, 1, b"abc"),
        cru(5, tipo::PRIORITY, 0, 1, &[0, 0, 0, 3, 7]),
        cru(5, tipo::PRIORITY, 0, 9, &[0, 0, 0, 3, 7]),
        ping,
        ok_200(1, b"a"),
    ]
    .concat();
    let (mut c, mut correntes) = roteiro(&chegada, 2, 1);
    assert_eq!(c.receber(correntes.pop().unwrap()).unwrap().corpo, b"a");
    // O `PING` foi respondido com os mesmos bytes.
    let resposta = do_cliente(&c.fluxo().mandado)
        .into_iter()
        .find(|(c, _)| c.tipo == tipo::PING)
        .unwrap();
    assert_eq!(resposta.0.bandeiras, bandeira::ACK);
    assert_eq!(resposta.1, b"12345678");
}

#[test]
fn a_tabela_dinamica_do_servidor_atravessa_as_correntes() {
    // As respostas da RFC 7541 (C.6), uma por corrente: cada uma depende
    // da tabela que a anterior deixou — mesmo a da corrente cancelada.
    let blocos = [
        "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
         2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
        "4883 640e ffc1 c0bf",
        "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab \
         77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
         9587 3160 65c0 03ed 4ee5 b106 3d50 07",
    ];
    let hex = crate::testes_do_hpack::hex;
    let chegada = [
        ajustes_do_servidor(&[]),
        cabeca(1, &hex(blocos[0]), true),
        cabeca(3, &hex(blocos[1]), true),
        cabeca(5, &hex(blocos[2]), true),
    ]
    .concat();
    for pedaco in [1, 4096] {
        let (mut c, mut correntes) = roteiro(&chegada, pedaco, 3);
        let quinta = correntes.pop().unwrap();
        let terceira = correntes.pop().unwrap();
        let primeira = correntes.pop().unwrap();
        c.cancelar(terceira);
        let r = c.receber(quinta).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.cabecalho("location"), Some("https://www.example.com"));
        assert_eq!(r.cabecalho("date"), Some("Mon, 21 Oct 2013 20:13:22 GMT"));
        assert_eq!(r.cabecalho("content-encoding"), Some("gzip"));
        assert_eq!(
            r.cabecalho("set-cookie"),
            Some("foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")
        );
        let r = c.receber(primeira).unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.cabecalho("cache-control"), Some("private"));
    }
}

#[test]
fn os_erros_da_conexao() {
    let mut push = Vec::new();
    quadro::por_cabeca(&mut push, 5, tipo::PUSH_PROMISE, bandeira::END_HEADERS, 1);
    push.extend_from_slice(&[0, 0, 0, 2, 0x82]);
    let meio = cru(1, tipo::HEADERS, 0, 1, &[0x88]);
    for (chegada, esperado, codigo) in [
        // Um quadro maior que o padrão, que este lado não aumenta.
        (
            cru(16_385, 0xfa, 0, 0, &[0; 16_385]),
            Motivo::Quadro,
            CodigoH2::FRAME_SIZE_ERROR,
        ),
        (push, Motivo::Empurrado, CodigoH2::PROTOCOL_ERROR),
        // O índice zero no HPACK.
        (
            cabeca(1, &[0x80], true),
            Motivo::Compressao,
            CodigoH2::COMPRESSION_ERROR,
        ),
        // O servidor não abre correntes; nem fala de uma que não existe.
        (
            cabeca(2, &[0x88], true),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            dados(5, b"x", true),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            cru(4, tipo::RST_STREAM, 0, 7, &[0, 0, 0, 8]),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            cru(4, tipo::WINDOW_UPDATE, 0, 9, &[0, 0, 0, 1]),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        // Um bloco de cabeça interrompido, e um `CONTINUATION` sem bloco.
        (
            [meio.clone(), dados(1, b"x", true)].concat(),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            [meio, cru(1, tipo::CONTINUATION, 4, 3, &[0x88])].concat(),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            cru(1, tipo::CONTINUATION, 4, 1, &[0x88]),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        // A corrente que depende de si mesma, num `HEADERS`.
        (
            cru(
                6,
                tipo::HEADERS,
                bandeira::END_HEADERS | bandeira::PRIORITY,
                1,
                &[0, 0, 0, 1, 0, 0x88],
            ),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        // Os ajustes fora da faixa.
        (
            ajustes_do_servidor(&[(ajuste::ENABLE_PUSH, 1)]),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            ajustes_do_servidor(&[(ajuste::MAX_FRAME_SIZE, 16_383)]),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            ajustes_do_servidor(&[(ajuste::MAX_FRAME_SIZE, 1 << 24)]),
            Motivo::Quadro,
            CodigoH2::PROTOCOL_ERROR,
        ),
        (
            ajustes_do_servidor(&[(ajuste::INITIAL_WINDOW_SIZE, 1 << 31)]),
            Motivo::Janela,
            CodigoH2::FLOW_CONTROL_ERROR,
        ),
        // A janela da conexão além do máximo.
        (
            cru(4, tipo::WINDOW_UPDATE, 0, 0, &[0x7f, 0xff, 0xff, 0xff]),
            Motivo::Janela,
            CodigoH2::FLOW_CONTROL_ERROR,
        ),
        // Um `PING` torto.
        (
            cru(7, tipo::PING, 0, 0, b"1234567"),
            Motivo::Quadro,
            CodigoH2::FRAME_SIZE_ERROR,
        ),
    ] {
        let erro = da_conexao(&chegada, codigo);
        assert_eq!(erro, Erro::Protocolo(esperado), "{chegada:x?}");
    }
}

#[test]
fn depois_do_fim_da_corrente_nada_dela() {
    for depois in [dados(1, b"b", true), cabeca(1, &[0x88], true)] {
        let chegada = [ajustes_do_servidor(&[]), ok_200(1, b"a"), depois].concat();
        let (mut c, mut correntes) = roteiro(&chegada, 4096, 2);
        let b = correntes.pop().unwrap();
        let a = correntes.pop().unwrap();
        // A conexão acaba; a que já tinha chegado inteira continua inteira.
        assert_eq!(c.receber(b), Err(Erro::Protocolo(Motivo::Corrente)));
        assert_eq!(c.receber(a).unwrap().corpo, b"a");
        assert_eq!(
            ultimo(&c.fluxo().mandado),
            (tipo::GOAWAY, 0, CodigoH2::STREAM_CLOSED)
        );
    }
}

#[test]
fn o_prefacio_que_nao_e_do_http2() {
    for chegada in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
        // O reconhecimento não é o prefácio.
        &[0, 0, 0, 4, 1, 0, 0, 0, 0][..],
        &ok_200(1, b"a")[..],
    ] {
        let (mut c, mut correntes) = roteiro(chegada, 4096, 1);
        assert_eq!(
            c.receber(correntes.pop().unwrap()),
            Err(Erro::Protocolo(Motivo::Prefacio))
        );
        assert_eq!(
            ultimo(&c.fluxo().mandado),
            (tipo::GOAWAY, 0, CodigoH2::PROTOCOL_ERROR)
        );
    }
}

#[test]
fn as_enxurradas() {
    let pings: Vec<u8> = (0..1100)
        .flat_map(|i: u32| {
            let mut q = Vec::new();
            quadro::por_cabeca(&mut q, 8, tipo::PING, 0, 0);
            q.extend_from_slice(&u64::from(i).to_be_bytes());
            q
        })
        .collect();
    let vazios: Vec<u8> = (0..1100).flat_map(|_| dados(1, b"", false)).collect();
    let cabeca_vazia = [
        cabeca(1, &bloco(&[(":status", "200")]), false),
        vazios.clone(),
    ]
    .concat();
    let ajustes: Vec<u8> = (0..1100).flat_map(|_| ajustes_do_servidor(&[])).collect();
    let desconhecidos: Vec<u8> = (0..1100).flat_map(|_| cru(0, 0xfa, 0, 0, &[])).collect();
    let mut continuacoes = cru(0, tipo::HEADERS, 0, 1, &[]);
    for _ in 0..65 {
        continuacoes.extend(cru(0, tipo::CONTINUATION, 0, 1, &[]));
    }
    for (chegada, esperado) in [
        (pings, Limite::Quadros),
        (cabeca_vazia, Limite::Quadros),
        (ajustes, Limite::Quadros),
        (desconhecidos, Limite::Quadros),
        (continuacoes, Limite::Quadros),
    ] {
        assert_eq!(
            da_conexao(&chegada, CodigoH2::ENHANCE_YOUR_CALM),
            Erro::Limite(esperado)
        );
    }
    // Um bloco de cabeça que chega cru com mais que o dobro da maior cabeça.
    let mut enorme = cru(16_384, tipo::HEADERS, 0, 1, &[0; 16_384]);
    enorme.extend(cru(16_384, tipo::CONTINUATION, 0, 1, &[0; 16_384]));
    enorme.extend(cru(1, tipo::CONTINUATION, 0, 1, &[0]));
    assert_eq!(
        da_conexao(&enorme, CodigoH2::ENHANCE_YOUR_CALM),
        Erro::Limite(Limite::Cabeca)
    );
    assert_eq!(
        Erro::<FalhaDeTeste>::Limite(Limite::Quadros).codigo(),
        Some("HTTP_TOO_MANY_FRAMES")
    );
}

#[test]
fn mil_pings_com_progresso_no_meio_passam() {
    let mut chegada = ajustes_do_servidor(&[]);
    for i in 0..1000u64 {
        quadro::por_cabeca(&mut chegada, 8, tipo::PING, 0, 0);
        chegada.extend_from_slice(&i.to_be_bytes());
    }
    chegada.extend(cabeca(1, &bloco(&[(":status", "200")]), false));
    for i in 0..1000u64 {
        quadro::por_cabeca(&mut chegada, 8, tipo::PING, 0, 0);
        chegada.extend_from_slice(&i.to_be_bytes());
    }
    chegada.extend(dados(1, b"ok", true));
    let (mut c, mut correntes) = roteiro(&chegada, 4096, 1);
    assert_eq!(c.receber(correntes.pop().unwrap()).unwrap().corpo, b"ok");
    let respostas = do_cliente(&c.fluxo().mandado)
        .iter()
        .filter(|(c, _)| c.tipo == tipo::PING)
        .count();
    assert_eq!(respostas, 2000);
}

#[test]
fn o_adeus_do_servidor() {
    let mut adeus = Vec::new();
    quadro::por_adeus(&mut adeus, 1, CodigoH2::NO_ERROR);
    let chegada = [ajustes_do_servidor(&[]), adeus, ok_200(1, b"a")].concat();
    let (mut c, mut correntes) = roteiro(&chegada, 4096, 2);
    let b = correntes.pop().unwrap();
    let a = correntes.pop().unwrap();
    // Acima da última, recusada — pode ir noutra conexão.
    assert_eq!(c.receber(b), Err(Erro::Recusada));
    let r = c.receber(a).unwrap();
    assert_eq!(r.corpo, b"a");
    assert!(!r.reutilizavel);
    assert!(!c.pronto());
    assert_eq!(
        c.enviar(&get("http://h/"), &Limites::default()),
        Err(Erro::Esgotada)
    );
    // Com erro, e o servidor fechando: o que não acabou, acabou com ele.
    let mut adeus = Vec::new();
    quadro::por_adeus(&mut adeus, 3, CodigoH2::ENHANCE_YOUR_CALM);
    let chegada = [
        ajustes_do_servidor(&[]),
        ok_200(1, b"a"),
        cabeca(3, &bloco(&[(":status", "200")]), false),
        adeus,
    ]
    .concat();
    let (mut c, mut correntes) = roteiro(&chegada, 4096, 2);
    let b = correntes.pop().unwrap();
    let a = correntes.pop().unwrap();
    assert_eq!(
        c.receber(b),
        Err(Erro::Encerrada(CodigoH2::ENHANCE_YOUR_CALM))
    );
    // A que já tinha chegado inteira continua inteira.
    assert_eq!(c.receber(a).unwrap().corpo, b"a");
    assert_eq!(
        Erro::<FalhaDeTeste>::Encerrada(CodigoH2::NO_ERROR).codigo(),
        Some("HTTP_CONNECTION_ENDED")
    );
}

#[test]
fn o_servidor_que_fecha_no_meio() {
    let chegada = [
        ajustes_do_servidor(&[]),
        ok_200(1, b"a"),
        cabeca(
            3,
            &bloco(&[(":status", "200"), ("content-length", "5")]),
            false,
        ),
        dados(3, b"ab", false),
    ]
    .concat();
    for pedaco in [1, 4096] {
        let (mut c, mut correntes) = roteiro(&chegada, pedaco, 2);
        let b = correntes.pop().unwrap();
        let a = correntes.pop().unwrap();
        assert_eq!(c.receber(b), Err(Erro::Fechada));
        assert_eq!(c.receber(a).unwrap().corpo, b"a");
        assert!(!c.pronto());
    }
}

#[test]
fn a_falha_de_baixo_vai_para_cada_corrente_como_veio() {
    let chegada = [
        ajustes_do_servidor(&[]),
        ok_200(1, b"a"),
        cabeca(3, &bloco(&[(":status", "200")]), false),
        dados(3, b"ab", false),
    ]
    .concat();
    let recusa = FalhaDeTeste("DENY_CONTAINED");
    for em in [chegada.len() - 5, chegada.len()] {
        let mut roteiro_ = Roteiro::novo(&chegada, 4096);
        roteiro_.falha_em = Some((em, recusa));
        let mut c = ClienteH2::novo(roteiro_);
        let a = c.enviar(&get("http://h/a"), &Limites::default()).unwrap();
        let b = c.enviar(&get("http://h/b"), &Limites::default()).unwrap();
        let d = c.enviar(&get("http://h/d"), &Limites::default()).unwrap();
        assert_eq!(c.receber(b), Err(Erro::Baixo(recusa)));
        assert_eq!(c.receber(d), Err(Erro::Baixo(recusa)));
        // O que chegou inteiro antes da recusa chegou.
        assert_eq!(c.receber(a).unwrap().corpo, b"a");
        assert_eq!(
            c.enviar(&get("http://h/"), &Limites::default()),
            Err(Erro::Esgotada)
        );
    }
    // A recusa ao mandar: o pedido não sai, e a conexão acaba.
    let mut roteiro_ = Roteiro::novo(&chegada, 4096);
    roteiro_.falha_ao_mandar = Some(FalhaDeTeste("FIREWALL_BLOCKED"));
    let mut c = ClienteH2::novo(roteiro_);
    assert_eq!(
        c.enviar(&get("http://h/"), &Limites::default()),
        Err(Erro::Baixo(FalhaDeTeste("FIREWALL_BLOCKED")))
    );
    assert_eq!(c.abertas(), 0);
    assert!(!c.pronto());
}

#[test]
fn a_janela_do_pedido_alem_do_maximo_e_da_corrente() {
    // O pedido espera as duas janelas; o servidor abre a da corrente até o
    // máximo — e a da conexão continua fechada —, e depois além dele.
    let antes = [
        ajustes_do_servidor(&[]),
        cru(4, tipo::WINDOW_UPDATE, 0, 1, &[0x7f, 0xff, 0xff, 0xff]),
        cru(4, tipo::WINDOW_UPDATE, 0, 1, &[0, 0, 0, 1]),
    ]
    .concat();
    let chegada = [antes.clone(), ok_200(3, b"b")].concat();
    let mut roteiro_ = Roteiro::novo(&chegada, 4096);
    // A resposta da segunda só depois do pedido dela, a terceira ida.
    roteiro_.rodadas = vec![antes.len(), antes.len(), chegada.len()];
    let mut c = ClienteH2::novo(roteiro_);
    let a = c
        .enviar(&post("http://h/eco", &vec![0; 70_000]), &Limites::default())
        .unwrap();
    assert_eq!(c.receber(a), Err(Erro::Protocolo(Motivo::Janela)));
    let b = c.enviar(&get("http://h/b"), &Limites::default()).unwrap();
    assert_eq!(c.receber(b).unwrap().corpo, b"b");
}

#[test]
fn a_recusa_do_servidor_no_meio_do_corpo_do_pedido() {
    // O pedido espera janela; o servidor recusa a corrente: o corpo para, e
    // a recusa chega a quem recebe.
    let mut reinicio = Vec::new();
    quadro::por_reinicio(&mut reinicio, 1, CodigoH2::REFUSED_STREAM);
    let chegada = [ajustes_do_servidor(&[]), reinicio].concat();
    let mut c = ClienteH2::novo(Roteiro::novo(&chegada, 4096));
    let a = c
        .enviar(&post("http://h/eco", &vec![0; 70_000]), &Limites::default())
        .unwrap();
    assert_eq!(c.receber(a), Err(Erro::Recusada));
    let dados_mandados: usize = do_cliente(&c.fluxo().mandado)
        .iter()
        .filter(|(c, _)| c.tipo == tipo::DATA)
        .map(|(c, _)| c.tamanho)
        .sum();
    assert_eq!(dados_mandados, 65_535);
}
