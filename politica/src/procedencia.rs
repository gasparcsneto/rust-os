//! A procedência do código: por que um código de fora da imagem não roda.
//!
//! # A pergunta a mais
//!
//! O gate decide quem roda o quê: `process.run` sobre o caminho. O código
//! que **não** é da imagem — o gravado no armazém, o que chegou pela rede —
//! tem uma pergunta a mais, que o kernel faz depois de ler o arquivo e
//! antes de carregá-lo: quem o selou, e se o papel de quem o lança confia
//! nesse editor (ver `sigilo::codigo` e a linha `editores` da política). E
//! de novo a cada pedido do processo que ele virou: a confiança é do papel,
//! e o papel é procurado a cada decisão.
//!
//! O "não" tem quatro formas — [`Falta`] —, e cada uma vai para a auditoria
//! com o motivo daqui, para quem pediu com um código de resposta, e para a
//! explicação com o que fazer. Os textos moram aqui, num lugar só, porque
//! quatro leitores os leem: a auditoria grava, a explicação e o NSF
//! reconhecem, e quem responde escolhe o código.
//!
//! # O motivo cortado
//!
//! O detalhe de um registro tem teto (`auditoria::MAIOR_DETALHE`), e o
//! motivo vai nele depois do programa que pediu e antes da decisão citada.
//! A descrição do programa encolhe antes dele (ver
//! `auditoria::detalhe_composto`); o motivo só perde o fim quando ela já
//! encolheu toda e ainda não cabe — o nome do editor de
//! [`Falta::NaoConfiado`] no motivo, ou o fio e a decisão com muitos
//! dígitos. O corte termina numa palavra inteira, com a marca
//! (`auditoria::MARCA_DO_CORTE`, ` ?`) no lugar do que saiu: o pedaço de um
//! nome de editor seria o nome de outro. Mesmo assim o reconhecimento não
//! depende do motivo inteiro: o começo [`Falta::essencial`] já diz a falta,
//! e [`Falta::do_motivo`] tira a marca e reconhece o motivo cortado no fim
//! enquanto ele guarda esse começo — o NSF vê o código adulterado também
//! ali.
//!
//! # Não é uma segunda política
//!
//! A confiança é uma linha da mesma política, decidida no mesmo gate, com
//! o mesmo papel; o selo é só a prova de quem selou, como o aperto de mão é
//! a prova de quem fala.

use alloc::format;
use alloc::string::String;

/// O que falta a um código de fora da imagem para rodar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falta {
    /// O arquivo não traz selo.
    SemSelo,
    /// O selo não confere com o arquivo: o código, ou o selo, mudou depois
    /// de selado — ou o selo é forjado.
    NaoConfere,
    /// O selo confere, e a chave que selou não é de editor nenhum do
    /// registro.
    EditorDesconhecido,
    /// O editor é do registro, e o papel não confia nele.
    NaoConfiado,
}

impl Falta {
    /// As quatro.
    pub const TODAS: [Falta; 4] = [
        Falta::SemSelo,
        Falta::NaoConfere,
        Falta::EditorDesconhecido,
        Falta::NaoConfiado,
    ];

    /// O motivo, como a auditoria o grava — curto, porque o detalhe de um
    /// registro tem teto, e o de um processo vem depois do programa que
    /// pediu. O de [`Falta::NaoConfiado`] leva o nome do editor depois (ver
    /// [`nao_confiado`]); o papel não, que o registro já tem num campo seu.
    pub const fn motivo(self) -> &'static str {
        match self {
            Falta::SemSelo => "o codigo nao tem selo",
            Falta::NaoConfere => "o selo nao confere com o codigo",
            Falta::EditorDesconhecido => "o editor do codigo nao esta no registro",
            Falta::NaoConfiado => "o papel nao confia no editor",
        }
    }

    /// O começo do motivo que já diz a falta: o que o motivo cortado no fim
    /// precisa guardar para ainda ser reconhecido — ver o começo do módulo.
    /// Um começo de cada motivo, e nenhum é o começo do motivo de outra
    /// falta: o cortado nunca vira outra.
    pub const fn essencial(self) -> &'static str {
        match self {
            Falta::SemSelo => "o codigo nao tem selo",
            Falta::NaoConfere => "o selo nao confere",
            Falta::EditorDesconhecido => "o editor do codigo nao",
            Falta::NaoConfiado => "o papel nao confia",
        }
    }

    /// O código da resposta a quem pediu — o de uma recusa depois do gate,
    /// como o `FIREWALL_BLOCKED` do firewall. Os dois do editor são um só:
    /// para quem pede, o que importa é que não se confia em quem selou.
    pub const fn resposta(self) -> &'static str {
        match self {
            Falta::SemSelo => "CODE_UNSIGNED",
            Falta::NaoConfere => "CODE_TAMPERED",
            Falta::EditorDesconhecido | Falta::NaoConfiado => "CODE_UNTRUSTED",
        }
    }

    /// A falta que um motivo gravado diz, se diz uma: o motivo dela
    /// inteiro, com o que vier depois — o editor de [`Falta::NaoConfiado`] —,
    /// ou o motivo cortado no fim, enquanto guarda o começo
    /// [`essencial`](Falta::essencial). O corte da auditoria termina numa
    /// palavra inteira e deixa a marca no lugar do que saiu
    /// ([`crate::auditoria::MARCA_DO_CORTE`]): ela sai antes da comparação —
    /// `o papel nao confia no editor ?` é o motivo inteiro, sem o editor. Um
    /// texto que segue outro caminho depois do começo não é o motivo de
    /// falta nenhuma.
    pub fn do_motivo(motivo: &str) -> Option<Falta> {
        let motivo = motivo
            .strip_suffix(crate::auditoria::MARCA_DO_CORTE)
            .unwrap_or(motivo);
        Falta::TODAS.into_iter().find(|f| {
            motivo.starts_with(f.motivo())
                || (f.motivo().starts_with(motivo) && motivo.starts_with(f.essencial()))
        })
    }
}

/// O motivo de [`Falta::NaoConfiado`], com o editor.
pub fn nao_confiado(editor: &str) -> String {
    format!("{} {editor}", Falta::NaoConfiado.motivo())
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_motivo_volta_para_a_falta() {
        for f in [Falta::SemSelo, Falta::NaoConfere, Falta::EditorDesconhecido] {
            assert_eq!(Falta::do_motivo(f.motivo()), Some(f));
        }
        assert_eq!(
            Falta::do_motivo(&nao_confiado("outro")),
            Some(Falta::NaoConfiado)
        );
        assert_eq!(nao_confiado("outro"), "o papel nao confia no editor outro");
        // Com a decisão no fim, como a execução grava.
        assert_eq!(
            Falta::do_motivo("o selo nao confere com o codigo; decisao 12"),
            Some(Falta::NaoConfere)
        );
        // O editor que não coube, com a marca do corte no lugar.
        assert_eq!(
            Falta::do_motivo("o papel nao confia no editor ?"),
            Some(Falta::NaoConfiado)
        );
        for outro in [
            "",
            "?",
            " ?",
            "bloqueado pelo firewall, regra 3",
            "o manifesto nao declara fs.read",
            "o manifesto nao declara ?",
            "o papel operador nao permite",
        ] {
            assert_eq!(Falta::do_motivo(outro), None, "{outro}");
        }
    }

    /// O motivo cortado no fim — o detalhe da auditoria tem teto — ainda
    /// diz a falta enquanto guarda o começo essencial dela; mais curto, não
    /// diz nenhuma, e nunca diz outra. O que segue outro caminho depois do
    /// começo também não é o motivo de falta nenhuma.
    #[test]
    fn o_motivo_cortado_ainda_diz_a_falta() {
        let do_editor = nao_confiado("duke-oficial");
        for (f, motivo) in [
            (Falta::SemSelo, Falta::SemSelo.motivo()),
            (Falta::NaoConfere, Falta::NaoConfere.motivo()),
            (
                Falta::EditorDesconhecido,
                Falta::EditorDesconhecido.motivo(),
            ),
            (Falta::NaoConfiado, do_editor.as_str()),
        ] {
            assert!(f.motivo().starts_with(f.essencial()), "{f:?}");
            for n in 0..=motivo.len() {
                let cortado = &motivo[..n];
                let esperado = (n >= f.essencial().len()).then_some(f);
                assert_eq!(Falta::do_motivo(cortado), esperado, "{cortado:?}");
                // O corte da auditoria, numa palavra inteira, com a marca:
                // o mesmo reconhecimento.
                if motivo.as_bytes().get(n) == Some(&b' ') {
                    let marcado = alloc::format!("{cortado}{}", crate::auditoria::MARCA_DO_CORTE);
                    assert_eq!(Falta::do_motivo(&marcado), esperado, "{marcado:?}");
                }
            }
        }
        // Nenhum começo é o de outra falta: o cortado nunca vira outra.
        for f in Falta::TODAS {
            for g in Falta::TODAS {
                if f != g {
                    assert!(!g.motivo().starts_with(f.essencial()), "{f:?} {g:?}");
                }
            }
        }
        // O que segue outro caminho depois do começo não é motivo nenhum;
        // o motivo inteiro, com algo depois — como o editor do
        // `NaoConfiado` —, é.
        for outro in [
            "o selo nao confere com outra coisa",
            "o selo nao confere, e mais",
            "o editor do codigo nao responde",
            "o papel nao confia em ninguem",
        ] {
            assert_eq!(Falta::do_motivo(outro), None, "{outro}");
        }
        assert_eq!(
            Falta::do_motivo("o codigo nao tem selo, e mais"),
            Some(Falta::SemSelo)
        );
    }

    #[test]
    fn as_respostas() {
        assert_eq!(Falta::SemSelo.resposta(), "CODE_UNSIGNED");
        assert_eq!(Falta::NaoConfere.resposta(), "CODE_TAMPERED");
        assert_eq!(Falta::EditorDesconhecido.resposta(), "CODE_UNTRUSTED");
        assert_eq!(Falta::NaoConfiado.resposta(), "CODE_UNTRUSTED");
    }
}
