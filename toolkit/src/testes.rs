//! Os testes do toolkit, no hospedeiro.

use alloc::vec;
use alloc::vec::Vec;

use aparencia::{medidas, texto, uso};
use protocolo::usuario::descricao::Descricao;

use crate::arvore::{self, area_de, com_widget_mut};
use crate::*;

fn r(x: u32, y: u32, largura: u32, altura: u32) -> Retangulo {
    Retangulo {
        x,
        y,
        largura,
        altura,
    }
}

const OK: u32 = 7;
const CANCELAR: u32 = 8;

/// Uma janela pequena: um título, um texto e dois botões numa linha.
fn formulario() -> Pilha {
    formulario_com("linha um\nlinha dois")
}

fn formulario_com(conteudo: &str) -> Pilha {
    Coluna::nova()
        .recuo(10)
        .espaco(8)
        .fundo(uso::FUNDO_DO_CONTEUDO.argb())
        .com(Rotulo::titulo("cabeçalho", "Duke"))
        .com(Rotulo::novo("conteudo", conteudo))
        .com(
            Linha::nova()
                .espaco(6)
                .com(Botao::novo("OK", OK))
                .com(Botao::novo("Cancelar", CANCELAR)),
        )
}

#[test]
fn a_coluna_mede_os_filhos_o_espaco_e_o_recuo() {
    let f = formulario();
    let (lc, ac) = (texto::CORPO.largura(), texto::CORPO.altura());
    let botoes = (
        2 * lc + 2 * medidas::FOLGA_DO_BOTAO,
        8 * lc + 2 * medidas::FOLGA_DO_BOTAO,
    );
    let linha = botoes.0 + 6 + botoes.1;
    let largura = [
        4 * texto::CABECALHO.largura(),
        10 * lc, // "linha dois"
        linha,
    ]
    .into_iter()
    .max()
    .unwrap();
    let altura = texto::CABECALHO.altura() + 8 + 2 * ac + 8 + medidas::ALTURA_DO_BOTAO;
    assert_eq!(f.medir(), (largura + 20, altura + 20));
}

#[test]
fn cada_filho_recebe_o_que_pede_na_ordem() {
    let f = formulario();
    let areas = f.dispor(r(100, 50, 400, 300));
    let (lc, ac) = (texto::CORPO.largura(), texto::CORPO.altura());
    assert_eq!(areas[0].x, 110);
    assert_eq!(areas[0].y, 60);
    assert_eq!(areas[1].y, 60 + texto::CABECALHO.altura() + 8);
    assert_eq!(areas[1].largura, 10 * lc);
    assert_eq!(areas[1].altura, 2 * ac);
    // A linha dos botões põe o segundo depois do primeiro, com o espaço.
    let botoes = f.filhos()[2].dispor(areas[2]);
    assert_eq!(botoes[0].x, 110);
    assert_eq!(botoes[1].x, 110 + botoes[0].largura + 6);
    assert_eq!(botoes[1].y, botoes[0].y);
}

#[test]
fn o_que_nao_cabe_e_cortado_e_nao_transborda() {
    let f = formulario();
    // Uma área menor que o texto: o filho recebe o que sobra, e não mais.
    let areas = f.dispor(r(0, 0, 60, 40));
    for a in &areas {
        assert!(a.x + a.largura <= 50, "{a:?}");
        assert!(a.y + a.altura <= 30 || a.altura == 0, "{a:?}");
    }
}

#[test]
fn a_descricao_sai_da_arvore_e_volta_pelo_leitor_do_kernel() {
    let f = formulario();
    let area = r(1, 22, 398, 200);
    let mut e = Escritor::nova("Sobre o Duke");
    arvore::descrever(&f, area, 100, &mut e);
    let d = Descricao::ler(&e.terminar().unwrap()).unwrap();
    assert_eq!(d.titulo, "Sobre o Duke");
    // A coluna e a linha não são nada na árvore; os quatro de dentro são.
    let resumo: Vec<(Tipo, i64, &str)> = d
        .elementos
        .iter()
        .map(|e| (e.tipo, e.id, e.rotulo.as_str()))
        .collect();
    assert_eq!(
        resumo,
        vec![
            (Tipo::Texto, 101, "cabeçalho"),
            (Tipo::Texto, 102, "conteudo"),
            (Tipo::Botao, 104, "OK"),
            (Tipo::Botao, 105, "Cancelar"),
        ]
    );
    assert_eq!(
        d.elementos[1].valor.as_deref(),
        Some("linha um\nlinha dois")
    );
    // E cada moldura é a área em que o widget se desenha.
    for el in &d.elementos {
        let indice = (el.id - 100) as Indice;
        assert_eq!(Some(el.moldura), area_de(&f, area, indice));
    }
}

#[test]
fn os_indices_nao_mudam_com_o_conteudo() {
    // O mesmo formulário com outro texto — mais linhas, que empurram os
    // botões para baixo: a área do OK muda, e o índice dele, não.
    let ids = |f: &Pilha| {
        let mut e = Escritor::nova("x");
        arvore::descrever(f, r(0, 0, 400, 300), 0, &mut e);
        Descricao::ler(&e.terminar().unwrap())
            .unwrap()
            .elementos
            .iter()
            .map(|e| (e.id, e.rotulo.clone()))
            .collect::<Vec<_>>()
    };
    let (curto, longo) = (formulario_com("um"), formulario_com("um\ndois\ntres"));
    assert_eq!(ids(&curto), ids(&longo));
    assert_ne!(
        area_de(&curto, r(0, 0, 400, 300), 4),
        area_de(&longo, r(0, 0, 400, 300), 4)
    );
    // E o índice chega ao widget certo para mudá-lo.
    let mut f = formulario();
    let rotulo = com_widget_mut(&mut f, 4, |w| w.semantica().map(|s| s.rotulo.len()));
    assert_eq!(rotulo, Some(Some(2)));
    assert_eq!(com_widget_mut(&mut f, 99, |_| ()), None);
}

#[test]
fn o_desenho_pinta_onde_a_descricao_diz() {
    let f = formulario();
    let (largura, altura) = (400u32, 300u32);
    let mut pixels = vec![0u32; (largura * altura) as usize];
    let mut tela = Tela {
        pixels: &mut pixels,
        largura,
    };
    let area = r(0, 0, largura, altura);
    arvore::desenhar(&f, &mut tela, area, None);

    // O fundo da coluna, no recuo.
    assert_eq!(tela.pixel(2, 2), Some(uso::FUNDO_DO_CONTEUDO.argb()));
    // O botão OK: o fundo do botão no canto, e tinta no meio do texto.
    let ok = area_de(&f, area, 4).unwrap();
    assert_eq!(tela.pixel(ok.x, ok.y), Some(uso::FUNDO_DO_BOTAO.argb()));
    let mut tinta = 0;
    for y in ok.y..ok.y + ok.altura {
        for x in ok.x..ok.x + ok.largura {
            if tela.pixel(x, y) != Some(uso::FUNDO_DO_BOTAO.argb()) {
                tinta += 1;
            }
        }
    }
    assert!(
        tinta > 20,
        "o botao nao tem texto desenhado ({tinta} pixels)"
    );
    // E fora de toda área, o que estava lá: o fundo da coluna, e nada do
    // botão depois do fim dele.
    assert_eq!(
        tela.pixel(ok.x + ok.largura + 1, ok.y + 1),
        Some(uso::FUNDO_DO_CONTEUDO.argb())
    );
}

#[test]
fn o_rotulo_corta_na_area_e_nao_desenha_fora_dela() {
    let rotulo = Rotulo::novo("t", "abcdefghijklmnopqrstuvwxyz");
    let (largura, altura) = (400u32, 40u32);
    let mut pixels = vec![0u32; (largura * altura) as usize];
    let mut tela = Tela {
        pixels: &mut pixels,
        largura,
    };
    let lc = texto::CORPO.largura();
    // Cabem cinco letras e meia: saem cinco.
    rotulo.desenhar(
        &mut tela,
        r(0, 0, 5 * lc + lc / 2, texto::CORPO.altura()),
        false,
    );
    for y in 0..altura {
        for x in 5 * lc..largura {
            assert_eq!(
                tela.pixel(x, y),
                Some(0),
                "pixel fora da area em ({x}, {y})"
            );
        }
    }
}

#[test]
fn os_widgets_tem_as_cores_da_paleta() {
    // Pela paleta, e não pelo uso: o uso é o que se confere. O texto de uma
    // janela é ardósia sobre papel, e o botão é o aço da barra do kernel.
    use aparencia::paleta;
    let (largura, altura) = (200u32, 40u32);
    let mut pixels = vec![0u32; (largura * altura) as usize];
    let mut tela = Tela {
        pixels: &mut pixels,
        largura,
    };
    Rotulo::novo("t", "H").desenhar(&mut tela, r(0, 0, 100, 20), false);
    assert_eq!(tela.pixel(0, 0), Some(paleta::PAPEL.argb()));
    // A tinta pura só aparece onde a cobertura do glifo é inteira, e o
    // `H` regular chega a 227: o que se espera é a mistura da ardósia com
    // o papel na cobertura mais alta do glifo — a conta da própria fonte.
    let mut maior = 0u8;
    tipografia::percorrer('H', aparencia::texto::CORPO, |_, _, c| maior = maior.max(c));
    let esperado = tipografia::misturar(paleta::PAPEL.argb(), paleta::ARDOSIA.argb(), maior);
    let tinta = (0..20).any(|y| (0..10).any(|x| tela.pixel(x, y) == Some(esperado)));
    assert!(tinta, "o texto nao e a ardosia");
    Botao::novo("OK", OK).desenhar(&mut tela, r(120, 0, 40, 18), false);
    assert_eq!(tela.pixel(121, 1), Some(paleta::ACO.argb()));
}

// A interação: os três caminhos até um widget.

use protocolo::usuario::evento::acao;

const AREA: Retangulo = Retangulo {
    x: 0,
    y: 0,
    largura: 400,
    altura: 300,
};

fn centro(r: Retangulo) -> (u32, u32) {
    (r.x + r.largura / 2, r.y + r.altura / 2)
}

#[test]
fn o_aperto_aciona_o_botao_debaixo_dele_e_lhe_da_o_foco() {
    let mut ui = Interface::nova(formulario());
    // O foco começa no primeiro que o recebe: o OK.
    assert_eq!(ui.foco(), Some(4));
    let cancelar = area_de(ui.raiz(), AREA, 5).unwrap();
    let (x, y) = centro(cancelar);
    assert_eq!(ui.apertar(AREA, x, y), Resposta::Acionado(CANCELAR));
    assert_eq!(ui.foco(), Some(5));
    // Um aperto no texto não aciona nada e não tira o foco do botão.
    let texto = area_de(ui.raiz(), AREA, 2).unwrap();
    let (x, y) = centro(texto);
    assert_eq!(ui.apertar(AREA, x, y), Resposta::Nada);
    assert_eq!(ui.foco(), Some(5));
    // E fora de tudo, nada.
    assert_eq!(ui.apertar(AREA, 399, 299), Resposta::Nada);
}

#[test]
fn o_tab_da_a_volta_nos_que_recebem_o_foco() {
    let mut ui = Interface::nova(formulario());
    assert_eq!(ui.focaveis(), vec![4, 5]);
    assert_eq!(ui.tecla('\t'), Resposta::Redesenhar);
    assert_eq!(ui.foco(), Some(5));
    assert_eq!(ui.tecla('\t'), Resposta::Redesenhar);
    assert_eq!(ui.foco(), Some(4));
    // O Enter e o espaço acionam o botão com o foco; uma letra, não.
    assert_eq!(ui.tecla('\n'), Resposta::Acionado(OK));
    assert_eq!(ui.tecla(' '), Resposta::Acionado(OK));
    assert_eq!(ui.tecla('x'), Resposta::Nada);
}

#[test]
fn o_agente_aciona_o_mesmo_botao_pelo_indice_da_arvore() {
    let mut ui = Interface::nova(formulario());
    // O índice é o que a descrição publicou: `base + índice` volta ao
    // programa, e ele tira a base.
    let mut e = Escritor::nova("x");
    ui.descrever(AREA, 1000, &mut e);
    let d = Descricao::ler(&e.terminar().unwrap()).unwrap();
    let cancelar = d.elementos.iter().find(|e| e.rotulo == "Cancelar").unwrap();
    let indice = (cancelar.id - 1000) as Indice;
    assert_eq!(
        ui.acao(indice, acao::PRESSIONAR),
        Resposta::Acionado(CANCELAR)
    );
    // Sem mexer no foco, e só a ação que o botão entende.
    assert_eq!(ui.foco(), Some(4));
    assert_eq!(ui.acao(indice, 99), Resposta::Nada);
    // Um texto não é acionado, e um índice que não existe não é nada.
    assert_eq!(ui.acao(2, acao::PRESSIONAR), Resposta::Nada);
    assert_eq!(ui.acao(99, acao::PRESSIONAR), Resposta::Nada);
}

#[test]
fn o_foco_se_ve() {
    // O botão com o foco tem o anel no acento; o outro, não.
    let ui = Interface::nova(formulario());
    let mut pixels = vec![0u32; (AREA.largura * AREA.altura) as usize];
    let mut tela = Tela {
        pixels: &mut pixels,
        largura: AREA.largura,
    };
    ui.desenhar(&mut tela, AREA);
    let (ok, cancelar) = (
        area_de(ui.raiz(), AREA, 4).unwrap(),
        area_de(ui.raiz(), AREA, 5).unwrap(),
    );
    let acento = aparencia::paleta::ACENTO.argb();
    assert_eq!(tela.pixel(ok.x, ok.y + ok.altura / 2), Some(acento));
    assert_eq!(
        tela.pixel(cancelar.x, cancelar.y + cancelar.altura / 2),
        Some(aparencia::paleta::ACO.argb())
    );
}

#[test]
fn a_resposta_mais_importante_vence() {
    use Resposta::*;
    assert_eq!(Nada.e(Redesenhar), Redesenhar);
    assert_eq!(Redesenhar.e(Acionado(3)), Acionado(3));
    assert_eq!(Acionado(3).e(Nada), Acionado(3));
    assert_eq!(Nada.e(Nada), Nada);
}

/// Um widget só de teste, que responde onde foi apertado, nas coordenadas
/// dele: `x * 1000 + y`.
struct Sonda;

impl Widget for Sonda {
    fn medir(&self) -> (u32, u32) {
        (50, 30)
    }

    fn tratar(&mut self, entrada: Entrada) -> Resposta {
        match entrada {
            Entrada::Aperto { x, y } => Resposta::Acionado(x * 1000 + y),
            _ => Resposta::Nada,
        }
    }
}

#[test]
fn o_aperto_chega_nas_coordenadas_do_widget() {
    // A sonda fica depois de um recuo de 10 e de um texto: o aperto em
    // (13, y) da janela é o (3, ...) dela.
    let mut ui = Interface::nova(
        Coluna::nova()
            .recuo(10)
            .com(Rotulo::novo("t", "x"))
            .com(Sonda),
    );
    let sonda = area_de(ui.raiz(), AREA, 2).unwrap();
    assert_eq!(
        ui.apertar(AREA, sonda.x + 3, sonda.y + 4),
        Resposta::Acionado(3004)
    );
}
