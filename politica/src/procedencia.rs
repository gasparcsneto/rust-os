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
//! três leitores os leem: a auditoria grava, a explicação reconhece, e quem
//! responde escolhe o código.
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

    /// A falta que um motivo gravado diz, se diz uma.
    pub fn do_motivo(motivo: &str) -> Option<Falta> {
        [
            Falta::SemSelo,
            Falta::NaoConfere,
            Falta::EditorDesconhecido,
            Falta::NaoConfiado,
        ]
        .into_iter()
        .find(|f| motivo.starts_with(f.motivo()))
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
        for outro in [
            "",
            "bloqueado pelo firewall, regra 3",
            "o manifesto nao declara fs.read",
            "o papel operador nao permite",
        ] {
            assert_eq!(Falta::do_motivo(outro), None, "{outro}");
        }
    }

    #[test]
    fn as_respostas() {
        assert_eq!(Falta::SemSelo.resposta(), "CODE_UNSIGNED");
        assert_eq!(Falta::NaoConfere.resposta(), "CODE_TAMPERED");
        assert_eq!(Falta::EditorDesconhecido.resposta(), "CODE_UNTRUSTED");
        assert_eq!(Falta::NaoConfiado.resposta(), "CODE_UNTRUSTED");
    }
}
