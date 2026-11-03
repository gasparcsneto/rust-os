//! A conversa: uma janela e um fluxo nos dois sentidos no mesmo laço — o
//! exemplo do SDK da janela e do fluxo.
//!
//! Duas conversas da mesma Pessoa — neste Duke, ou uma em cada, pelo
//! enlace — trocam linhas de texto. A janela tem as últimas [`LINHAS`]
//! linhas, um campo e o botão "Enviar"; o texto digitado vai pelo fluxo,
//! em mensagens do [`programas::quadro`], e o que chega aparece na janela.
//! A entrada da janela e os avisos do fluxo e do endpoint chegam no mesmo
//! canal: o processo dorme num lugar só, e nem a tecla espera o fluxo, nem
//! o fluxo espera a tecla.
//!
//! - **Começar**: escuta o laço, oferece [`INTENCAO`] com o aviso, abre a
//!   janela com a entrada no laço e diz `conversa: pronta <endpoint>
//!   <canal>`.
//! - **A primeira mensagem** acha a outra conversa — a descoberta, aqui, ou
//!   no dispositivo que [`PAR`] diz, se esse arquivo existe — e abre o
//!   fluxo; a outra aceita pelo aviso `PEDIDO`. Se as duas abrirem ao mesmo
//!   tempo, fica o fluxo aberto pela de endpoint maior: as duas fazem a
//!   mesma conta com os mesmos dois endpoints, e o outro fluxo é fechado.
//! - **Mandar**: o Enter no campo, ou o botão. O que não coube espera o
//!   `GRAVAVEL`, e a janela segue.
//! - **Receber**: cada mensagem inteira vira uma linha; `conversa: recebi
//!   <texto>`.
//!
//! O texto é entrada não confiável: a mensagem tem o teto de quem lê
//! ([`MAIOR_MENSAGEM`]), e só o que é texto aparece. O `ENCERRAR` no canal,
//! ou a caixa de fechar, encerra com [`CODIGO`].

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "conversa",
    "fabric.offer",
    "fabric.send",
    "fabric.stream",
    "fabric.remote",
    "fs.read"
);

use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::fluxo::{self, EscritaPendente, Fluxo};
use programas::janela::{Gesto, Janela};
use programas::laco::{Acontecimento, Laco};
use programas::quadro::{self, Entrada, Lido};
use programas::{malha, sistema};
use protocolo::usuario::evento::{BOTAO_ESQUERDO, Evento, tipo};
use toolkit::{Botao, Campo, Coluna, Interface, Rotulo, Widget};

/// A intenção que a conversa oferece e procura — uma das de exemplo da
/// política padrão.
const INTENCAO: &str = "imagem.compartilhar";

/// O nome que o manifesto diz, pelo qual a descoberta acha a outra.
const NOME: &str = "conversa";

/// O arquivo que diz o dispositivo da outra conversa, se ela é de outro
/// Duke: `dispositivo:<nome>`.
const PAR: &str = "/armazem/compartilhado/conversa/par";

/// Quantas linhas a janela mostra.
const LINHAS: usize = 6;

/// A maior mensagem que esta conversa aceita.
const MAIOR_MENSAGEM: usize = 512;

/// O que o campo e o botão respondem.
const ENVIAR: u32 = 1;

/// A base dos identificadores da janela na árvore.
const BASE: i64 = 3000;

/// O código de saída no fim.
const CODIGO: i64 = 59;

/// Os índices na árvore: a coluna é 0, o título 1, as linhas a seguir, e
/// depois o campo e o botão.
const PRIMEIRA_LINHA: u32 = 2;
const CAMPO: u32 = PRIMEIRA_LINHA + LINHAS as u32;

/// O fluxo da conversa, e onde ele está.
struct Ligacao {
    f: Fluxo,
    saida: EscritaPendente,
    entrada: Entrada,
    /// O endpoint da outra conversa, quando foi esta que abriu: o
    /// desempate de quando as duas abrem ao mesmo tempo.
    par: Option<String>,
    /// O fluxo já abriu: o aceito, sempre; o aberto daqui, no primeiro
    /// aviso — o da abertura. Antes dele o fluxo está pedido, e escrever
    /// seria recusado: o que se manda espera na saída.
    aberta: bool,
}

struct Conversa {
    laco: Laco,
    janela: Janela,
    endpoint: String,
    ligacao: Option<Ligacao>,
    linhas: Vec<String>,
}

impl Conversa {
    /// Põe `texto` no fim da janela.
    fn mostrar(&mut self, texto: &str) {
        if self.linhas.len() == LINHAS {
            self.linhas.remove(0);
        }
        self.linhas.push(String::from(texto));
        for (i, l) in self.linhas.iter().enumerate() {
            let indice = PRIMEIRA_LINHA + i as u32;
            self.janela
                .com_widget::<Rotulo, _>(indice, |r| r.definir_texto(l));
        }
        self.janela.redesenhar();
    }

    /// O dispositivo da outra conversa, se ela é de outro Duke.
    fn dispositivo() -> Option<String> {
        let d = sistema::abrir(PAR);
        if d < 0 {
            return None;
        }
        let mut b = [0u8; 80];
        let n = sistema::ler(d as u64, &mut b);
        sistema::fechar(d as u64);
        let texto = core::str::from_utf8(&b[..n.max(0) as usize]).ok()?.trim();
        (!texto.is_empty()).then(|| String::from(texto))
    }

    /// Acha a outra conversa e abre o fluxo, com o aviso.
    fn ligar(&mut self) -> Result<(), String> {
        let dispositivo = Conversa::dispositivo();
        let candidatos = match &dispositivo {
            Some(d) => malha::Par(d).descobrir(INTENCAO),
            None => malha::descobrir(INTENCAO),
        }
        .map_err(|f| alloc::format!("descobrir {}", f.codigo()))?;
        let outro = candidatos
            .into_iter()
            .find(|c| c.programa == NOME && c.endpoint != self.endpoint)
            .ok_or_else(|| String::from("nenhuma outra conversa"))?;
        let f = match &dispositivo {
            Some(d) => fluxo::abrir_no_par_avisando(d, &outro.endpoint, INTENCAO, &self.laco),
            None => fluxo::abrir_avisando(&outro.endpoint, INTENCAO, &self.laco),
        }
        .map_err(|e| alloc::format!("abrir {} {}", e.codigo(), e.motivo()))?;
        let _ = escreverln!("conversa: abri {}", f.numero().unwrap_or(0));
        self.ligacao = Some(Ligacao {
            f,
            saida: EscritaPendente::nova(),
            entrada: Entrada::nova(MAIOR_MENSAGEM),
            par: Some(outro.endpoint),
            aberta: false,
        });
        Ok(())
    }

    /// O texto do campo vai pelo fluxo, e o campo fica vazio.
    fn enviar(&mut self) {
        let texto = self
            .janela
            .com_widget::<Campo, _>(CAMPO, |c| String::from(c.valor()))
            .unwrap_or_default();
        if texto.is_empty() {
            return;
        }
        if self.ligacao.is_none()
            && let Err(e) = self.ligar()
        {
            let _ = escreverln!("conversa: sem a outra: {}", e);
            self.mostrar("(ninguem para conversar)");
            return;
        }
        let Some(l) = self.ligacao.as_mut() else {
            return;
        };
        if quadro::juntar(&mut l.saida, texto.as_bytes()).is_err() {
            return;
        }
        // Com o fluxo ainda pedido, a mensagem espera o aviso da abertura.
        let r = if l.aberta {
            l.saida.escoar(&l.f).map(|_| ())
        } else {
            Ok(())
        };
        self.janela.com_widget::<Campo, _>(CAMPO, |c| {
            let _ = c.definir_valor("");
        });
        let _ = escreverln!("conversa: mandei {}", texto);
        self.mostrar(&alloc::format!("> {texto}"));
        if let Err(e) = r {
            self.perdeu(e.motivo());
        }
    }

    /// O fluxo acabou: a janela diz, e a próxima mensagem liga de novo.
    fn perdeu(&mut self, motivo: &str) {
        if let Some(l) = self.ligacao.take() {
            let _ = l.f.fechar();
        }
        let _ = escreverln!("conversa: o fluxo acabou: {}", motivo);
        self.mostrar("(a outra saiu)");
    }

    /// O aviso do fluxo: escreve o que esperava, e lê as mensagens inteiras.
    fn andar(&mut self, numero: u64) {
        let Some(l) = self.ligacao.as_mut() else {
            return;
        };
        if l.f.numero() != Some(numero) {
            return;
        }
        // O primeiro aviso de um fluxo aberto daqui é o da abertura.
        l.aberta = true;
        if let Err(e) = l.saida.escoar(&l.f) {
            return self.perdeu(e.motivo());
        }
        let mut chegou = Vec::new();
        let fim = loop {
            match l.entrada.ler(&l.f) {
                Ok(Lido::Mensagem(m)) => chegou.push(m),
                Ok(Lido::Falta) => break None,
                Ok(Lido::Fim) => break Some(String::from("a outra terminou")),
                Err(e) => break Some(alloc::format!("{e:?}")),
            }
        };
        for m in chegou {
            let texto = String::from_utf8_lossy(&m).into_owned();
            let _ = escreverln!("conversa: recebi {}", texto);
            self.mostrar(&alloc::format!("< {texto}"));
        }
        if let Some(motivo) = fim {
            self.perdeu(&motivo);
        }
    }

    /// O aviso do endpoint: aceita o pedido, com o aviso. Se as duas
    /// abriram ao mesmo tempo, fica o fluxo aberto pelo endpoint maior — a
    /// outra faz a mesma conta, com os mesmos dois endpoints.
    fn aceitar(&mut self, prontidao: programas::laco::Prontidao) {
        if prontidao.entrega() {
            let _ = malha::descartar_entregas(&self.endpoint);
        }
        while let Ok(Some((f, origem))) = fluxo::aceitar_avisando(&self.endpoint, &self.laco) {
            let _ = escreverln!("conversa: aceitei de {}", origem.descrever());
            let novo = Ligacao {
                f,
                saida: EscritaPendente::nova(),
                entrada: Entrada::nova(MAIOR_MENSAGEM),
                par: None,
                aberta: true,
            };
            let par = self.ligacao.as_ref().map(|l| l.par.clone());
            match par {
                None => self.ligacao = Some(novo),
                Some(Some(par)) if self.endpoint > par => {
                    let _ = novo.f.fechar();
                }
                Some(Some(_)) => {
                    if let Some(velho) = self.ligacao.replace(novo) {
                        let _ = velho.f.fechar();
                    }
                }
                // Já havia uma, aceita: esta sobra.
                Some(None) => {
                    let _ = novo.f.fechar();
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let laco = match Laco::novo() {
        Ok(l) => l,
        Err(e) => {
            let _ = escreverln!("conversa: escutar devolveu {}", e);
            return 1;
        }
    };
    let endpoint = match malha::oferecer_avisando(INTENCAO, &laco) {
        Ok(e) => e,
        Err(f) => {
            let _ = escreverln!("conversa: oferecer {}", f.codigo());
            return 2;
        }
    };
    let mut coluna = Coluna::nova()
        .recuo(aparencia::medidas::RECUO_DO_CONTEUDO)
        .espaco(aparencia::medidas::ESPACO_DO_CONTEUDO)
        .fundo(aparencia::uso::FUNDO_DO_CONTEUDO.argb())
        .com(Rotulo::novo("titulo", "Conversa"));
    for i in 0..LINHAS {
        coluna = coluna.com(Rotulo::novo(&alloc::format!("linha {i}"), ""));
    }
    let coluna = coluna
        .com(Campo::novo("mensagem", 32, ENVIAR))
        .com(Botao::novo("Enviar", ENVIAR));
    let mut janela = match Janela::com_interface("Conversa", Interface::nova(coluna), BASE, 80, 60)
    {
        Ok(j) => j,
        Err(e) => {
            let _ = escreverln!("conversa: sem janela: {}", e);
            return 3;
        }
    };
    if janela.superficie().entrada(laco.descritor()).is_err() || janela.mostrar().is_err() {
        return 4;
    }
    // Aberta pela pessoa, a janela pede o foco: o que ela digita vai ao
    // campo, até ela escolher outra.
    let _ = janela.superficie().focar();
    let _ = escreverln!("conversa: pronta {} {}", endpoint, laco.nome());
    let mut c = Conversa {
        laco,
        janela,
        endpoint,
        ligacao: None,
        linhas: Vec::new(),
    };
    let mut botoes = 0;
    loop {
        let acontecimentos = match c.laco.esperar() {
            Ok(v) => v,
            Err(e) => {
                let _ = escreverln!("conversa: o laco falhou: {}", e);
                return 5;
            }
        };
        for a in acontecimentos {
            let gesto = match a {
                Acontecimento::Endpoint { prontidao, .. } => {
                    c.aceitar(prontidao);
                    Gesto::Nada
                }
                Acontecimento::Fluxo { numero, .. } => {
                    c.andar(numero);
                    Gesto::Nada
                }
                Acontecimento::Evento(Evento {
                    tipo: t,
                    a,
                    b,
                    c: e_c,
                }) => match t {
                    tipo::PONTEIRO => {
                        let apertou = e_c & BOTAO_ESQUERDO != 0 && botoes & BOTAO_ESQUERDO == 0;
                        botoes = e_c;
                        if apertou {
                            c.janela.apertar_em(a, b)
                        } else {
                            Gesto::Nada
                        }
                    }
                    tipo::TECLA => match u32::try_from(a).ok().and_then(char::from_u32) {
                        Some(ch) => c.janela.tecla(ch),
                        None => Gesto::Nada,
                    },
                    tipo::ACAO => c.janela.acao(a, b).unwrap_or(Gesto::Nada),
                    tipo::ENCERRAR => {
                        let _ = escreverln!("conversa: encerrada");
                        return CODIGO;
                    }
                    _ => Gesto::Nada,
                },
            };
            match gesto {
                Gesto::Acionado(ENVIAR) => c.enviar(),
                Gesto::Fechar => {
                    let _ = escreverln!("conversa: fechada");
                    return CODIGO;
                }
                _ => {}
            }
        }
    }
}
