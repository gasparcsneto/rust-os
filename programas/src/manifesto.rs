//! O manifesto do programa: quem ele diz ser, e o que pretende fazer.
//!
//! Cada programa declara o seu com [`manifesto!`](macro@crate::manifesto), uma
//! vez, no arquivo dele:
//!
//! ```ignore
//! programas::manifesto!("visualizador", "fs.read", "system.read");
//! ```
//!
//! A macro monta, em tempo de compilação, a nota ELF que o kernel lê no
//! `executar` (ver `protocolo::usuario::manifesto`), e o script de ligação a
//! põe num segmento `PT_NOTE`. O processo exerce a interseção do papel de
//! quem o lançou com o que declarou: um programa sem manifesto não exerce
//! permissão nenhuma — nem abre um arquivo, nem pede um comando —, e um
//! nome fora do vocabulário recusa o executável inteiro no `executar`. O
//! formato e as regras estão em `politica::manifesto`.

/// A nota, alinhada a 4 bytes como o formato pede.
#[repr(C, align(4))]
pub struct Nota<const N: usize>(pub [u8; N]);

/// Declara o manifesto do programa: o nome e as permissões que ele
/// pretende exercer. Ver [`crate::manifesto`](mod@crate::manifesto).
#[macro_export]
macro_rules! manifesto {
    ($nome:literal $(, $permissao:literal)* $(,)?) => {
        const _: () = {
            const TEXTO: &str = concat!(
                "duke-manifesto 1\nnome ",
                $nome,
                "\npermite",
                $(" ", $permissao,)*
                "\n"
            );
            const N: usize = $crate::__protocolo::usuario::manifesto::tamanho_da_nota(TEXTO);
            #[unsafe(link_section = ".note.duke.manifesto")]
            #[used]
            static MANIFESTO: $crate::manifesto::Nota<N> = $crate::manifesto::Nota(
                $crate::__protocolo::usuario::manifesto::nota::<N>(TEXTO),
            );
        };
    };
}
