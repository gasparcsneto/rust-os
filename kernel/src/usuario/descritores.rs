//! A tabela de descritores de um processo.
//!
//! # O que um descritor é, e por que ele é um número
//!
//! Um número pequeno que o processo guarda e o kernel traduz. O processo não
//! recebe ponteiro nenhum, não sabe em que sistema de arquivos o arquivo
//! mora e não tem como forjar um descritor para algo que não abriu — o que
//! ele tem é um índice numa tabela que só o kernel alcança.
//!
//! É a mesma ideia de um *handle* em qualquer sistema operacional, e ela é
//! de segurança antes de ser de conveniência: a indireção é o que permite ao
//! kernel conferir, a cada chamada, se aquele processo tem direito àquele
//! objeto.
//!
//! # Por que a tabela é por processo
//!
//! Porque o descritor 3 de um processo não tem nada a ver com o 3 de outro.
//! Uma tabela global faria dois processos que abrissem arquivos diferentes
//! receberem números diferentes — e o segundo leria o arquivo do primeiro se
//! adivinhasse o número dele. Não é hipótese: é o que acontece quando a
//! tabela é única e a numeração é sequencial.
//!
//! Ela vive dentro do [`crate::fios::Fio`], e é de lá que vêm as duas
//! propriedades que importam sem uma linha de código: ela morre junto com o
//! processo, e `bifurcar` a duplica porque duplica o fio. Um `fork` que não
//! herdasse os descritores abertos não seria um `fork`.
//!
//! # O que ela ainda não tem
//!
//! Compartilhamento entre processos. Num Unix de verdade, `fork` faz pai e
//! filho apontarem para a **mesma** descrição de arquivo aberto: ler no pai
//! avança a posição do filho. Aqui cada um leva a própria cópia da posição,
//! que é o comportamento de quem abriu o arquivo duas vezes.
//!
//! A diferença é observável e está escrita aqui em vez de ser descoberta:
//! quem bifurcar depois de abrir e ler dos dois lados vai ler duas vezes o
//! mesmo pedaço. Compartilhar exige uma tabela de descrições com contagem de
//! referências entre a tabela e o vnode — a estrutura que o Unix chama de
//! *file table* —, e ela entra quando houver quem precise dela.

use crate::vfs::Vnode;

/// Quantos descritores um processo pode ter abertos ao mesmo tempo.
///
/// Dezesseis, e o teto é deliberado: a tabela é um campo do fio, então ela é
/// copiada a cada `bifurcar` e vive na memória do escalonador. Um teto alto
/// custaria em toda troca de contexto para servir a um processo que não
/// existe.
pub const MAX: usize = 16;

/// Os descritores que todo processo recebe abertos.
///
/// Os números são os do Unix, e isso é deliberado: não porque o Duke pretenda
/// ser POSIX, mas porque qualquer pessoa que já escreveu um programa sabe de
/// cor o que 1 e 2 significam. Inventar uma numeração própria cobraria esse
/// conhecimento de volta sem devolver nada.
pub mod padrao {
    /// Leitura. Reservado: ainda não há de onde ler, e **escrever nele é
    /// erro** — é o caso que prova que a tabela é consultada de verdade.
    pub const ENTRADA: u64 = 0;
    /// Saída comum. Vai para o log do kernel em nível `info`.
    pub const SAIDA: u64 = 1;
    /// Saída de erro. Vai para o mesmo log em nível `error`.
    pub const ERRO: u64 = 2;
}

/// O menor descritor que [`Tabela::abrir`] entrega.
///
/// # Por que não é zero, já que a vaga zero está vazia
///
/// Porque ela está vazia e **reservada**, que são coisas diferentes. Num Unix
/// de verdade, `abrir` entrega o menor número livre, e se o programa fechou a
/// entrada padrão o próximo `abrir` devolve 0 — é um comportamento conhecido,
/// e uma armadilha conhecida: um programa que depois leia "da entrada" passa
/// a ler o arquivo que alguém abriu.
///
/// Aqui a vaga zero nunca é preenchida, porque não há de onde ler ainda.
/// Entregá-la faria um `ler(0)` funcionar por acidente e parar de funcionar
/// no dia em que houver entrada de verdade.
pub const PRIMEIRO_LIVRE: usize = 3;

/// Para onde um descritor aponta.
///
/// # Onde a direção de cada um é decidida
///
/// No `match` de quem usa o descritor — em `escrever` e em `ler` —, e em
/// lugar nenhum além dele. A primeira versão tinha também dois ajudantes,
/// `escreve()` e `le()`, e eles eram a mesma regra escrita duas vezes: o
/// `match` já recusava um arquivo na escrita, então desligar o ajudante não
/// reprovava caso nenhum.
///
/// É o defeito que este projeto já pagou no VFS, com a conferência de
/// diretório escrita nos dois lados. Um `match` sem braço curinga obriga cada
/// alvo novo a ser decidido nos dois lugares — que é exatamente o que se
/// quer, porque é onde a decisão tem consequência.
#[derive(Clone, Copy, Debug)]
pub enum Alvo {
    /// Log do kernel, nível `info`.
    Registro,
    /// Log do kernel, nível `error`.
    Diagnostico,
    /// Um arquivo aberto, e onde a próxima leitura começa.
    ///
    /// A posição é do **descritor**, e não do arquivo: dois descritores para
    /// o mesmo arquivo leem cada um no seu ritmo. É o que torna a tabela
    /// estado de verdade, e não uma lista de apelidos.
    Arquivo { vnode: Vnode, posicao: u64 },
}

/// A tabela de descritores de um processo.
#[derive(Clone)]
pub struct Tabela {
    entradas: [Option<Alvo>; MAX],
}

impl Tabela {
    /// Uma tabela nova, com os três descritores que todo processo recebe.
    pub const fn nova() -> Tabela {
        let mut entradas = [const { None }; MAX];
        entradas[padrao::SAIDA as usize] = Some(Alvo::Registro);
        entradas[padrao::ERRO as usize] = Some(Alvo::Diagnostico);
        Tabela { entradas }
    }

    /// Para onde um descritor aponta, se ele existir.
    pub fn alvo(&self, descritor: u64) -> Option<Alvo> {
        // `get` em vez de indexar: o número veio do usuário e pode ser
        // qualquer coisa. Indexar entraria em pânico, e um processo não deve
        // conseguir derrubar o kernel com um inteiro grande.
        self.entradas
            .get(usize::try_from(descritor).ok()?)
            .copied()
            .flatten()
    }

    /// Guarda um arquivo aberto e devolve o descritor dele.
    ///
    /// Devolve `None` quando a tabela está cheia — que é um erro do processo
    /// (abriu demais e não fechou), e não do kernel.
    pub fn abrir(&mut self, vnode: Vnode) -> Option<u64> {
        let livre = self
            .entradas
            .iter()
            .enumerate()
            .skip(PRIMEIRO_LIVRE)
            .find(|(_, e)| e.is_none())
            .map(|(i, _)| i)?;

        self.entradas[livre] = Some(Alvo::Arquivo { vnode, posicao: 0 });
        Some(livre as u64)
    }

    /// Fecha um descritor. Devolve `false` se ele já não estava aberto.
    ///
    /// Fechar a saída padrão é permitido, e o processo que fizer isso perde a
    /// própria saída. É o que qualquer Unix faz: a tabela é do processo, e um
    /// kernel que protegesse o programa de si mesmo aqui teria de escolher
    /// quais números são sagrados — uma decisão que não é dele.
    pub fn fechar(&mut self, descritor: u64) -> bool {
        let Ok(indice) = usize::try_from(descritor) else {
            return false;
        };
        match self.entradas.get_mut(indice) {
            Some(vaga @ Some(_)) => {
                *vaga = None;
                true
            }
            _ => false,
        }
    }

    /// Avança a posição de leitura de um descritor de arquivo.
    ///
    /// Silencioso quando o descritor não é de arquivo: quem chama acabou de
    /// ler por ele, e um descritor que some entre a leitura e o avanço só
    /// acontece se o processo tiver outro fio — que não existe.
    pub fn avancar(&mut self, descritor: u64, quanto: u64) {
        let Ok(indice) = usize::try_from(descritor) else {
            return;
        };
        if let Some(Some(Alvo::Arquivo { posicao, .. })) = self.entradas.get_mut(indice) {
            *posicao = posicao.saturating_add(quanto);
        }
    }

    /// Quantos descritores estão abertos, para o relatório.
    pub fn abertos(&self) -> usize {
        self.entradas.iter().filter(|e| e.is_some()).count()
    }
}

impl Default for Tabela {
    fn default() -> Tabela {
        Tabela::nova()
    }
}

// A tabela é posicional, mas os nomes de `padrao` é que formam a ABI. Se
// alguém reordenar uma sem renumerar os outros, os dois deixam de concordar
// em silêncio e todo programa de usuário passa a escrever no lugar errado.
//
// Esta amarra é conferida em tempo de compilação, então o erro aparece no
// build e não num log estranho meses depois.
const _: () = {
    let inicial = Tabela::nova();
    assert!(inicial.entradas[padrao::ENTRADA as usize].is_none());
    assert!(inicial.entradas[padrao::SAIDA as usize].is_some());
    assert!(inicial.entradas[padrao::ERRO as usize].is_some());

    // E a vaga reservada tem de ficar de fora do que `abrir` entrega. Sem
    // isto, `PRIMEIRO_LIVRE` podia virar 0 numa edição distraída e a entrada
    // padrão passaria a ser um arquivo qualquer.
    assert!(PRIMEIRO_LIVRE > padrao::ERRO as usize);
    assert!(PRIMEIRO_LIVRE < MAX);
};
