//! A linguagem visual do Duke: as cores, as medidas e os estilos de texto.
//!
//! # Por que um pacote
//!
//! Porque dois lados desenham para a mesma pessoa — o kernel, a barra e o
//! console; os programas, as janelas e o Terminal —, e o que cada um
//! desenhava vinha de constantes próprias. O azul-noite do console estava
//! escrito três vezes, o acento duas, e o fundo do botão da barra era o
//! título apagado das janelas com outro nome. Uma cor mudada num lugar não
//! mudava nos outros, e a primeira pessoa a perceber seria quem olhasse a
//! tela. É o defeito da fonte antes da `tipografia`, na cor.
//!
//! # Duas camadas: a paleta e o uso
//!
//! A [`paleta`] é o que existe: poucas cores, com nomes de coisa, e não de
//! lugar. O [`uso`] é onde cada uma vai: `uso::BORDA_DA_JANELA` é a
//! [`paleta::NOITE`]. Quem desenha pede pelo uso, e é no uso que se decide
//! que a borda de uma janela e o fundo do console são a mesma cor. Trocar a
//! cor de uma coisa só é trocar uma linha do uso; trocar o tom de todo o
//! sistema é trocar uma linha da paleta.
//!
//! As [`medidas`] e os estilos de [`texto`] seguem a mesma regra: o nome diz
//! para que servem.

#![cfg_attr(not(test), no_std)]

/// Uma cor opaca, `0x00RRGGBB`.
///
/// O formato é o do kernel — ver `Cor::para_u32` na tela — e o byte alto,
/// o de opacidade, fica de fora: toda cor da paleta é opaca, e quem desenha
/// numa superfície com alfa pede [`Cor::argb`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cor(u32);

impl Cor {
    pub const fn nova(r: u8, g: u8, b: u8) -> Cor {
        Cor((r as u32) << 16 | (g as u32) << 8 | b as u32)
    }

    /// `0x00RRGGBB`.
    pub const fn rgb(self) -> u32 {
        self.0
    }

    /// `0xFFRRGGBB`: opaca, para uma superfície que se mistura por alfa.
    pub const fn argb(self) -> u32 {
        0xFF00_0000 | self.0
    }

    pub const fn r(self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn g(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub const fn b(self) -> u8 {
        self.0 as u8
    }
}

/// As cores que existem.
pub mod paleta {
    use super::Cor;

    /// O azul-noite: o fundo do console e do Terminal, a borda das janelas.
    /// Escuro sem ser preto, que não cansa numa tela ligada o tempo todo.
    pub const NOITE: Cor = Cor::nova(0x10, 0x18, 0x28);
    /// Um passo acima da noite: a barra superior, e o texto sobre o claro.
    pub const ARDOSIA: Cor = Cor::nova(0x1A, 0x24, 0x36);
    /// Dois passos acima: os botões, e o que está sem foco.
    pub const ACO: Cor = Cor::nova(0x2A, 0x3C, 0x58);
    /// O acento: o que está vivo, ou com o foco.
    ///
    /// Escuro o bastante para o papel se ler sobre ele — o título da janela
    /// com o foco é papel sobre o acento —, e claro o bastante para se ver
    /// sobre a noite, onde ele é o cursor. O primeiro acento, `3A8FD0`, dava
    /// 3,2 ao título: abaixo dos 4,5 de texto de corpo.
    pub const ACENTO: Cor = Cor::nova(0x2B, 0x73, 0xB0);
    /// O texto sobre o escuro.
    pub const NEVOA: Cor = Cor::nova(0xD8, 0xDE, 0xE8);
    /// O claro: o fundo do conteúdo de uma janela, e o texto sobre o acento.
    pub const PAPEL: Cor = Cor::nova(0xF4, 0xF6, 0xFA);
    /// A falha fatal. Só a tela de falha a usa.
    pub const FALHA: Cor = Cor::nova(0x60, 0x10, 0x10);
    /// O quase-preto e o quase-branco do cursor do mouse: neutros, e não da
    /// noite e do papel, porque o cursor passa por cima de tudo e não pode
    /// sumir sobre nenhuma das cores de cima.
    pub const CARVAO: Cor = Cor::nova(0x10, 0x10, 0x10);
    pub const NEVE: Cor = Cor::nova(0xF4, 0xF4, 0xF4);
}

/// Onde cada cor vai.
pub mod uso {
    use super::Cor;
    use super::paleta::*;

    /// O console do kernel, e o Terminal, que é o mesmo console numa janela.
    pub const FUNDO_DO_CONSOLE: Cor = NOITE;
    pub const TEXTO_DO_CONSOLE: Cor = NEVOA;
    /// O cursor de texto do Terminal.
    pub const CURSOR_DE_TEXTO: Cor = ACENTO;

    /// A barra superior.
    pub const FUNDO_DA_BARRA: Cor = ARDOSIA;
    pub const TEXTO_DA_BARRA: Cor = NEVOA;
    /// A linha sob a barra, que diz que há um kernel vivo.
    pub const LINHA_DE_ACENTO: Cor = ACENTO;

    /// Um botão, na barra ou numa janela.
    pub const FUNDO_DO_BOTAO: Cor = ACO;

    /// Um campo de texto: o papel do conteúdo, com a borda do aço — e a do
    /// acento, com o foco.
    pub const BORDA_DO_CAMPO: Cor = ACO;
    pub const BORDA_COM_FOCO: Cor = ACENTO;

    /// A moldura de uma janela.
    pub const BORDA_DA_JANELA: Cor = NOITE;
    pub const TITULO_COM_FOCO: Cor = ACENTO;
    pub const TITULO_SEM_FOCO: Cor = ACO;
    pub const TEXTO_DO_TITULO: Cor = PAPEL;
    pub const CAIXA_DE_FECHAR: Cor = ACO;

    /// O conteúdo claro de uma janela, e o texto sobre ele.
    pub const FUNDO_DO_CONTEUDO: Cor = PAPEL;
    pub const TEXTO_DO_CONTEUDO: Cor = ARDOSIA;

    /// A tela de falha fatal.
    pub const FUNDO_DA_FALHA: Cor = FALHA;

    /// O cursor do mouse.
    pub const CONTORNO_DO_CURSOR: Cor = CARVAO;
    pub const MIOLO_DO_CURSOR: Cor = NEVE;
}

/// As medidas, em pixels.
pub mod medidas {
    /// A barra superior: a altura inteira, e a linha de acento embaixo.
    pub const ALTURA_DA_BARRA: u32 = 24;
    pub const ALTURA_DO_ACENTO: u32 = 2;
    /// A margem entre as coisas da barra, e da borda da tela ao console.
    pub const MARGEM: u32 = 8;
    /// Onde o texto da barra começa, na vertical: centrado nos 22 pixels
    /// acima do acento, com glifos de 16.
    pub const TEXTO_DA_BARRA_Y: u32 = 3;
    /// Um botão da barra: dois pixels de folga em cima e embaixo, e seis dos
    /// lados do texto.
    pub const BOTAO_DA_BARRA_Y: u32 = 2;
    pub const ALTURA_DO_BOTAO: u32 = 18;
    pub const FOLGA_DO_BOTAO: u32 = 6;

    /// A moldura de uma janela.
    pub const ALTURA_DO_TITULO: u32 = 22;
    pub const LADO_DO_FECHAR: u32 = 16;
    /// Da caixa de fechar à borda direita.
    pub const RECUO_DO_FECHAR: u32 = 3;
    pub const BORDA: u32 = 1;
    /// Onde o título começa, na horizontal.
    pub const RECUO_DO_TITULO: u32 = 8;

    /// O conteúdo de uma janela: o recuo em volta dos widgets, e o espaço
    /// entre um e o seguinte.
    pub const RECUO_DO_CONTEUDO: u32 = 10;
    pub const ESPACO_DO_CONTEUDO: u32 = 8;

    /// A folga entre a moldura do Terminal e a grade.
    pub const FOLGA_DA_GRADE: u32 = 4;

    /// Um campo de texto: a folga entre a borda e o texto, e a altura — a
    /// de um botão, para os dois ficarem lado a lado numa linha.
    pub const FOLGA_DO_CAMPO: u32 = 4;
    pub const ALTURA_DO_CAMPO: u32 = ALTURA_DO_BOTAO;
}

/// Os estilos de texto, pelo uso.
pub mod texto {
    pub use tipografia::Estilo;

    /// O texto de todo dia: o console, o conteúdo, os botões.
    pub const CORPO: Estilo = Estilo::TEXTO;
    /// O nome do sistema na barra.
    pub const NOME: Estilo = Estilo::NEGRITO;
    /// O título na barra de uma janela.
    pub const TITULO_DA_JANELA: Estilo = Estilo::NEGRITO;
    /// Um título grande dentro de uma janela.
    #[cfg(feature = "titulo")]
    pub const CABECALHO: Estilo = Estilo::TITULO;
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_cor_vai_e_volta() {
        let c = Cor::nova(0x12, 0x34, 0x56);
        assert_eq!(c.rgb(), 0x0012_3456);
        assert_eq!(c.argb(), 0xFF12_3456);
        assert_eq!((c.r(), c.g(), c.b()), (0x12, 0x34, 0x56));
    }

    #[test]
    fn o_texto_se_le_sobre_o_fundo() {
        // O contraste de cada par texto-fundo que o sistema desenha, pela
        // conta da WCAG. 4,5 é o mínimo para texto de corpo; uma troca de
        // cor que o derrubasse passaria despercebida até alguém tentar ler.
        fn luminancia(c: Cor) -> f64 {
            let canal = |v: u8| {
                let v = v as f64 / 255.0;
                if v <= 0.039_28 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * canal(c.r()) + 0.7152 * canal(c.g()) + 0.0722 * canal(c.b())
        }
        fn contraste(a: Cor, b: Cor) -> f64 {
            let (x, y) = (luminancia(a), luminancia(b));
            (x.max(y) + 0.05) / (x.min(y) + 0.05)
        }
        for (texto, fundo, nome) in [
            (uso::TEXTO_DO_CONSOLE, uso::FUNDO_DO_CONSOLE, "console"),
            (uso::TEXTO_DA_BARRA, uso::FUNDO_DA_BARRA, "barra"),
            (uso::TEXTO_DA_BARRA, uso::FUNDO_DO_BOTAO, "botao"),
            (
                uso::TEXTO_DO_TITULO,
                uso::TITULO_SEM_FOCO,
                "titulo sem foco",
            ),
            (
                uso::TEXTO_DO_TITULO,
                uso::TITULO_COM_FOCO,
                "titulo com foco",
            ),
            (uso::TEXTO_DO_CONTEUDO, uso::FUNDO_DO_CONTEUDO, "conteudo"),
        ] {
            let c = contraste(texto, fundo);
            assert!(c >= 4.5, "{nome}: contraste {c:.2}");
        }
        // O que não é texto, mas tem de ser visto: 3, o mínimo da WCAG para
        // um componente de interface e o indicador de foco. O cursor sobre
        // o console, a linha de acento sob a barra, e as bordas do campo
        // sobre o conteúdo — com e sem o foco.
        for (cor, fundo, nome) in [
            (uso::CURSOR_DE_TEXTO, uso::FUNDO_DO_CONSOLE, "cursor"),
            (uso::LINHA_DE_ACENTO, uso::FUNDO_DA_BARRA, "linha de acento"),
            (
                uso::BORDA_COM_FOCO,
                uso::FUNDO_DO_CONTEUDO,
                "borda com foco",
            ),
            (
                uso::BORDA_DO_CAMPO,
                uso::FUNDO_DO_CONTEUDO,
                "borda do campo",
            ),
        ] {
            let c = contraste(cor, fundo);
            assert!(c >= 3.0, "{nome}: contraste {c:.2}");
        }
    }
}
