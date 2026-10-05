//! O sistema de arquivos virtual: um nome de caminho, muitos sistemas.
//!
//! # A abstração, e de onde ela vem
//!
//! É a camada que o Unix chamou de VFS e cujas peças têm nome desde os anos
//! oitenta: o *vnode* (um objeto do sistema de arquivos, visto de memória), a
//! *montagem* (um sistema de arquivos pendurado num ponto da árvore) e a
//! tabela de operações que cada sistema preenche.
//!
//! Aqui a tabela de ponteiros de função vira um `trait`, que é a mesma
//! indireção com o compilador conferindo as assinaturas. O resto é igual de
//! propósito: quem já leu um `vnodeops` reconhece o que está aqui.
//!
//! # Por que ele existe antes de haver disco
//!
//! Porque ele é o que torna o disco uma troca e não uma reescrita. Hoje há um
//! sistema de arquivos só — os programas embutidos no binário do kernel —, e
//! `executar` os alcança por caminho. Quando o Btrfs entrar, ele entra por
//! baixo desta mesma interface, e `executar` não muda: o README já prometia
//! isso, e esta é a camada que cumpre a promessa.
//!
//! # O que não está aqui
//!
//! Escrita pelo VFS. O único sistema de arquivos gravável é o armazém
//! (`/armazem`, ver [`crate::armazem`]), e ele é escrito pelos comandos
//! `fs.write`, `fs.append` e `fs.delete` — que passam pelo gate, pela
//! coordenação e pela persistência —, e não por um `escrever` daqui: o
//! trait é o de quem lê. `abrir` e `fechar` existem agora, mas **não** como
//! métodos do trait: um sistema de arquivos somente leitura não tem nada a fazer quando
//! um descritor abre ou fecha, e o estado que essas duas operações criam — a
//! posição de leitura — é do processo, não do arquivo. Ele mora na tabela de
//! descritores, em [`crate::usuario::descritores`], e o que esta camada
//! precisou ganhar foi uma só função: [`ler_em`], que lê a partir de um
//! deslocamento.
//!
//! O dia em que houver escrita, ou um sistema de arquivos que precise saber
//! quantos descritores apontam para um nó, `abrir` e `fechar` descem para o
//! trait. Antes disso seriam métodos que todo mundo implementa como `Ok(())`.

pub mod btrfs;
pub mod programas;

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::trava::Mutex;

/// O que um nó é.
///
/// Dois, e não os quatro do Unix: não há link simbólico nem nó de dispositivo
/// para descrever. Acrescentá-los agora seria descrever o que não existe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tipo {
    Arquivo,
    Diretorio,
}

/// O que pode dar errado ao percorrer a árvore.
///
/// Um enum, e não um número: o canal do agente reporta o motivo, e um código
/// numérico obrigaria quem lê a manter a tabela de tradução.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O caminho não começa com `/`, ou tem um componente que não se entende.
    CaminhoInvalido,
    /// Não há montagem que responda por este caminho.
    SemMontagem,
    /// O nome não existe dentro do diretório.
    NaoEncontrado,
    /// Um componente do meio do caminho não é diretório.
    NaoEhDiretorio,
    /// Pediu-se o conteúdo de algo que não é arquivo.
    NaoEhArquivo,
    /// Já há um sistema de arquivos montado neste ponto.
    JaMontado,
    /// O arquivo não cabe no teto de leitura.
    GrandeDemais,
    /// O dispositivo por baixo recusou, ou o que veio dele não faz sentido.
    DoDispositivo,
    /// O caminho é de um segredo do kernel — ver [`DIRETORIO_RESERVADO`].
    Reservado,
    /// O arquivo mudou depois de resolvido: o nó que quem lê guardou é de
    /// um conteúdo que não existe mais — ver [`crate::armazem`]. Ler de
    /// novo pelo caminho dá o de agora.
    Mudou,
}

impl Erro {
    /// Uma frase curta, para o log e para o canal do agente.
    pub fn motivo(self) -> &'static str {
        match self {
            Erro::CaminhoInvalido => "caminho invalido",
            Erro::SemMontagem => "nenhuma montagem responde por este caminho",
            Erro::NaoEncontrado => "nao encontrado",
            Erro::NaoEhDiretorio => "nao e diretorio",
            Erro::NaoEhArquivo => "nao e arquivo",
            Erro::JaMontado => "ja ha algo montado neste ponto",
            Erro::GrandeDemais => "o arquivo nao cabe no teto de leitura",
            Erro::DoDispositivo => "o dispositivo recusou ou devolveu algo sem sentido",
            Erro::Reservado => "reservado ao kernel",
            Erro::Mudou => "o arquivo mudou depois de aberto",
        }
    }
}

/// Um objeto do sistema de arquivos, do ponto de vista de quem o serve.
///
/// O `id` é o que o sistema de arquivos usa para se reencontrar — um número
/// de inode, um deslocamento, um índice numa tabela. O VFS não o interpreta:
/// ele só o devolve na próxima chamada.
#[derive(Clone, Copy, Debug)]
pub struct No {
    pub tipo: Tipo,
    pub id: u64,
    pub tamanho: u64,
}

/// O mesmo objeto, do ponto de vista de quem o alcançou por um caminho.
///
/// A diferença entre [`No`] e este é de quem sabe o quê: o sistema de
/// arquivos sabe o que o objeto é, e só o VFS sabe de qual montagem ele veio.
/// Guardar a montagem dentro do [`No`] obrigaria cada sistema a conhecer o
/// próprio lugar na árvore, que é justamente o que esta camada existe para
/// ele não precisar saber.
#[derive(Clone, Copy, Debug)]
pub struct Vnode {
    pub no: No,
    montagem: usize,
}

/// Uma entrada de diretório.
pub struct Entrada {
    pub nome: String,
    pub tipo: Tipo,
}

/// O que todo sistema de arquivos precisa saber fazer.
///
/// É o `vnodeops` do Unix, com os nomes traduzidos e sem os métodos que ainda
/// não têm chamador — ver a nota no topo do módulo.
pub trait SistemaDeArquivos: Send {
    /// O diretório de onde tudo neste sistema de arquivos parte.
    fn raiz(&self) -> No;

    /// O nó de nome `nome` dentro de `dir`. É o `vop_lookup`.
    ///
    /// `dir` é sempre um diretório: quem resolve o caminho confere o tipo
    /// antes de chamar. A invariante mora lá e não aqui de propósito — com
    /// ela nos dois lugares, uma das duas conferências fica sem exercício, e
    /// foi o que aconteceu: desligar a do VFS não reprovava nenhum caso,
    /// porque a do sistema de arquivos cobria.
    fn procurar(&self, dir: &No, nome: &str) -> Result<No, Erro>;

    /// Lê até encher `destino`, a partir de `deslocamento`. É o `vop_read`.
    ///
    /// Devolve quantos bytes vieram, que pode ser menos que o pedido quando o
    /// arquivo acaba antes — e zero quando o deslocamento já passou do fim.
    fn ler(&self, no: &No, deslocamento: u64, destino: &mut [u8]) -> Result<usize, Erro>;

    /// A entrada de índice `indice` de um diretório. É o `vop_readdir`.
    ///
    /// `dir` é sempre um diretório, pela mesma razão de [`Self::procurar`].
    ///
    /// Por índice, e não por um cursor opaco, porque é o que um diretório
    /// pequeno permite e o que dispensa estado entre duas chamadas. Um
    /// sistema de arquivos com diretórios grandes vai querer trocar isto, e
    /// terá um chamador para justificar a troca.
    fn listar(&self, dir: &No, indice: usize) -> Result<Option<Entrada>, Erro>;
}

/// Um sistema de arquivos pendurado num ponto da árvore.
struct Montagem {
    /// Onde ele está, sempre começando com `/` e sem barra no fim (exceto a
    /// raiz, que é só `/`).
    em: String,
    /// Que tipo de sistema de arquivos é, para o relatório.
    tipo: &'static str,
    sistema: Box<dyn SistemaDeArquivos>,
}

/// Tudo que está montado, na ordem em que foi montado.
static MONTAGENS: Mutex<Vec<Montagem>> = Mutex::new(Vec::new());

/// Onde os programas executáveis moram.
///
/// O caminho de busca inteiro deste kernel: um diretório. Um `PATH` com
/// várias entradas existiria para resolver um problema que não temos — e a
/// primeira vez que tivermos, é aqui que ele entra.
pub const DIRETORIO_DOS_PROGRAMAS: &str = "/bin";

/// Quanto um [`ler_tudo`] pode trazer.
///
/// Um mebibyte. O maior cliente hoje é `executar`, e o maior programa
/// embutido tem algumas centenas de bytes; o teto existe para que um arquivo
/// absurdo vire erro em vez de consumir o heap inteiro.
const TETO_DE_LEITURA: u64 = 1024 * 1024;

/// Pendura um sistema de arquivos num ponto da árvore.
///
/// É o `vfs_mount`. O ponto precisa ser absoluto; montar duas coisas no mesmo
/// ponto é recusado, porque a resolução escolheria uma delas por ordem de
/// chegada e ninguém saberia qual.
pub fn montar(
    tipo: &'static str,
    em: &str,
    sistema: Box<dyn SistemaDeArquivos>,
) -> Result<(), Erro> {
    let em = normalizar(em)?;

    crate::arch::sem_interrupcoes(|| {
        let mut montagens = MONTAGENS.lock();
        if montagens.iter().any(|m| m.em == em) {
            return Err(Erro::JaMontado);
        }
        montagens.push(Montagem { em, tipo, sistema });
        Ok(())
    })
}

/// Onde moram os segredos do kernel: a chave privada do Duke.
///
/// # Por que o VFS recusa, e não quem pede
///
/// Três caminhos leem arquivos: o `open` dos processos, o `executar`, e os
/// comandos `fs.*` do agente. Uma conferência em cada um seria três lugares
/// para alguém esquecer o quarto. Aqui ela fica na única porta por onde os
/// três passam, [`resolver`]: o que está abaixo deste diretório não é
/// alcançável por caminho nenhum, e o kernel lê o que precisa por
/// [`ler_segredo`], que existe só para isso.
///
/// O disco é de quem tem a imagem, e quem tem a imagem tem a chave — é a
/// mesma condição de um servidor e o arquivo da chave dele. O que esta
/// recusa garante é outra coisa: que um processo, ou um agente com acesso ao
/// `fs.read`, não a leia de dentro da máquina.
pub const DIRETORIO_RESERVADO: &str = "/etc/duke/privado";

/// Se um caminho já normalizado é do diretório reservado. Pública porque a
/// autorização a usa também: o diretório não é recurso de papel nenhum.
pub fn reservado(normalizado: &str) -> bool {
    normalizado
        .strip_prefix(DIRETORIO_RESERVADO)
        .is_some_and(|resto| resto.is_empty() || resto.starts_with('/'))
}

/// Um caminho absoluto sem barras repetidas nem barra final.
///
/// Um `..` é recusado, e não resolvido. O Btrfs não guarda `..` — o pai é uma
/// conta do VFS no Linux —, então hoje ele já não levaria a lugar nenhum; mas
/// a conferência do [`DIRETORIO_RESERVADO`] olha o caminho **escrito**, e só
/// é sólida se o caminho escrito for o caminho percorrido. Com `..`
/// aceito, `/etc/x/../duke/privado` dependeria de um detalhe de cada sistema
/// de arquivos para continuar fechado.
///
/// A conta é a de [`politica::caminho::normalizar`]: a política limita
/// recursos por prefixo de caminho, e o caminho que ela confere precisa ser
/// o mesmo que o VFS percorre.
fn normalizar(caminho: &str) -> Result<String, Erro> {
    politica::caminho::normalizar(caminho).ok_or(Erro::CaminhoInvalido)
}

/// Qual montagem responde por um caminho, e o que sobra dele depois do ponto.
///
/// A mais longa que casar, e não a primeira: com `/` e `/bin` montados, o
/// caminho `/bin/exemplo` pertence ao segundo. Escolher pela ordem faria a
/// montagem mais específica ficar inalcançável a partir do momento em que a
/// raiz existisse.
fn dona<'c>(montagens: &[Montagem], caminho: &'c str) -> Option<(usize, &'c str)> {
    let mut escolhida: Option<(usize, &str)> = None;
    for (indice, montagem) in montagens.iter().enumerate() {
        let Some(resto) = caminho.strip_prefix(montagem.em.as_str()) else {
            continue;
        };
        // O prefixo precisa terminar numa fronteira de componente: `/bin` não
        // é dona de `/binario`.
        if !montagem.em.ends_with('/') && !resto.is_empty() && !resto.starts_with('/') {
            continue;
        }
        if escolhida.is_none_or(|(atual, _)| montagem.em.len() > montagens[atual].em.len()) {
            escolhida = Some((indice, resto));
        }
    }
    escolhida
}

/// Percorre um caminho e devolve o nó no fim dele.
///
/// É a resolução de nome do Unix, sem as partes que não existem aqui: não há
/// link simbólico para seguir, nem diretório de trabalho para caminhos
/// relativos. Um caminho precisa ser absoluto.
pub fn resolver(caminho: &str) -> Result<Vnode, Erro> {
    resolver_como(caminho, false)
}

/// [`resolver`], com o diretório reservado aberto ou não.
fn resolver_como(caminho: &str, do_kernel: bool) -> Result<Vnode, Erro> {
    let caminho = normalizar(caminho)?;
    if !do_kernel && reservado(&caminho) {
        return Err(Erro::Reservado);
    }

    crate::arch::sem_interrupcoes(|| {
        let montagens = MONTAGENS.lock();
        let (indice, resto) = dona(&montagens, &caminho).ok_or(Erro::SemMontagem)?;
        let sistema = &montagens[indice].sistema;

        let mut atual = sistema.raiz();
        for parte in resto.split('/').filter(|p| !p.is_empty() && *p != ".") {
            // Só diretório tem o que procurar dentro. Sem esta conferência, um
            // sistema de arquivos receberia `procurar` sobre um arquivo e cada
            // um responderia à sua maneira.
            if atual.tipo != Tipo::Diretorio {
                return Err(Erro::NaoEhDiretorio);
            }
            atual = sistema.procurar(&atual, parte)?;
        }

        Ok(Vnode {
            no: atual,
            montagem: indice,
        })
    })
}

/// Lê a partir de um deslocamento, por um vnode já resolvido.
///
/// # Por que ela existe, se já há `ler_tudo`
///
/// Porque `ler_tudo` responde a "me dê este arquivo", e um descritor aberto
/// responde a "me dê o próximo pedaço". São perguntas diferentes: a primeira
/// aloca o arquivo inteiro e tem um teto de um mebibyte; a segunda entrega o
/// que couber no buffer de quem chamou e não guarda nada.
///
/// É esta que um `read` de usuário precisa. Implementar `read` sobre
/// `ler_tudo` significaria ler quarenta e oito kilobytes do disco para
/// entregar sessenta e quatro bytes, e repetir isso a cada chamada.
///
/// # O vnode e a montagem que ele lembra
///
/// Um [`Vnode`] guarda o **índice** da montagem, e o índice é posicional: se
/// algo for desmontado, os que vêm depois andam para trás e um vnode antigo
/// passa a apontar para outro sistema de arquivos. Em produção isso não
/// acontece — `desmontar` só existe em modo de teste —, e o `get` abaixo é o
/// que impede a variante barata do problema: um índice além do fim.
///
/// A variante cara — o índice válido que passou a ser de outra montagem —
/// pede uma geração por montagem, e entra junto com a desmontagem de
/// verdade. Está escrito aqui para não ser descoberto depois.
pub fn ler_em(vnode: &Vnode, deslocamento: u64, destino: &mut [u8]) -> Result<usize, Erro> {
    if vnode.no.tipo != Tipo::Arquivo {
        return Err(Erro::NaoEhArquivo);
    }
    if destino.is_empty() {
        return Ok(0);
    }

    crate::arch::sem_interrupcoes(|| {
        let montagens = MONTAGENS.lock();
        let montagem = montagens.get(vnode.montagem).ok_or(Erro::SemMontagem)?;
        montagem.sistema.ler(&vnode.no, deslocamento, destino)
    })
}

/// Lê um arquivo inteiro para a memória.
///
/// Existe porque o primeiro cliente do VFS precisa da imagem inteira de uma
/// vez: um ELF é conferido campo a campo antes de virar processo, e conferir
/// por pedaços exigiria guardar estado entre as leituras.
pub fn ler_tudo(caminho: &str) -> Result<Vec<u8>, Erro> {
    ler_vnode(resolver(caminho)?)
}

/// Lê um segredo do kernel, de dentro do [`DIRETORIO_RESERVADO`].
///
/// Só aceita caminhos de lá: é a única coisa que ela faz que [`ler_tudo`]
/// não faz, e assim ela não vira um `ler_tudo` sem conferência para quem
/// estiver com pressa.
pub fn ler_segredo(caminho: &str) -> Result<Vec<u8>, Erro> {
    if !reservado(&normalizar(caminho)?) {
        return Err(Erro::CaminhoInvalido);
    }
    ler_vnode(resolver_como(caminho, true)?)
}

fn ler_vnode(vnode: Vnode) -> Result<Vec<u8>, Erro> {
    if vnode.no.tipo != Tipo::Arquivo {
        return Err(Erro::NaoEhArquivo);
    }
    if vnode.no.tamanho > TETO_DE_LEITURA {
        return Err(Erro::GrandeDemais);
    }

    let mut conteudo = alloc::vec![0u8; vnode.no.tamanho as usize];
    let mut lidos = 0usize;

    // O laço abaixo era, até o Btrfs entrar, uma promessa não falsificável:
    // os programas embutidos enchiam o buffer inteiro numa chamada, e trocar
    // o laço por uma leitura só não reprovava caso nenhum.
    //
    // Agora ele é exercitado. O `grande.txt` do disco tem quarenta e oito
    // kilobytes e o driver monta dezesseis por ida, então o Btrfs devolve a
    // leitura em três pedaços — e quem parasse no primeiro entregaria um
    // terço do arquivo dizendo que é o arquivo.

    crate::arch::sem_interrupcoes(|| {
        let montagens = MONTAGENS.lock();
        let sistema = &montagens[vnode.montagem].sistema;
        while lidos < conteudo.len() {
            let veio = sistema.ler(&vnode.no, lidos as u64, &mut conteudo[lidos..])?;
            // Zero bytes com espaço sobrando é o sistema de arquivos dizendo
            // que acabou antes do tamanho que ele mesmo declarou. Continuar
            // seria um laço infinito.
            if veio == 0 {
                break;
            }
            lidos += veio;
        }
        Ok::<(), Erro>(())
    })?;

    conteudo.truncate(lidos);
    Ok(conteudo)
}

/// Chama `f` para cada entrada de um diretório.
pub fn listar<F: FnMut(&Entrada)>(caminho: &str, mut f: F) -> Result<(), Erro> {
    let vnode = resolver(caminho)?;
    if vnode.no.tipo != Tipo::Diretorio {
        return Err(Erro::NaoEhDiretorio);
    }

    crate::arch::sem_interrupcoes(|| {
        let montagens = MONTAGENS.lock();
        let sistema = &montagens[vnode.montagem].sistema;
        let mut indice = 0;
        while let Some(entrada) = sistema.listar(&vnode.no, indice)? {
            f(&entrada);
            indice += 1;
        }
        Ok(())
    })
}

/// Chama `f` para cada montagem, com o ponto e o tipo.
pub fn com_montagens<F: FnMut(&str, &str)>(mut f: F) {
    crate::arch::sem_interrupcoes(|| {
        for montagem in MONTAGENS.lock().iter() {
            f(&montagem.em, montagem.tipo);
        }
    });
}

/// Tira um sistema de arquivos da árvore.
///
/// É o `vfs_unmount`, e não há nada dependendo dele em produção — o kernel
/// não desliga. Existe porque a suíte precisa montar uma segunda coisa para
/// exercitar a regra do prefixo mais longo e devolver a árvore ao estado
/// anterior; sem isso, o caso deixaria a montagem para os que vierem depois.
#[cfg(feature = "modo-teste")]
pub fn desmontar(em: &str) -> Result<(), Erro> {
    let em = normalizar(em)?;
    crate::arch::sem_interrupcoes(|| {
        let mut montagens = MONTAGENS.lock();
        let Some(posicao) = montagens.iter().position(|m| m.em == em) else {
            return Err(Erro::SemMontagem);
        };
        montagens.remove(posicao);
        Ok(())
    })
}

/// Destrava a tabela de montagens à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        MONTAGENS.force_unlock();
    }
}
