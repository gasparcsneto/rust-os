//! O contrato entre o iniciador UEFI e o kernel.
//!
//! # Por que um pacote, e não duas declarações iguais
//!
//! Porque duas declarações iguais são duas declarações que podem divergir. O
//! iniciador compila para `x86_64-unknown-uefi` e o kernel para
//! `x86_64-unknown-none`; são workspaces diferentes, alvos diferentes, e
//! nenhum deles depende do outro. O que os une é este pacote, que os dois
//! incluem por caminho.
//!
//! A alternativa — declarar a `struct` dos dois lados e conferir com um teste
//! — é o arranjo que este projeto usa onde ele **não tem escolha**: o padrão
//! por setor do disco, por exemplo, tem uma metade num programa do
//! hospedeiro e outra no kernel, e não há pacote que caiba nos dois. Aqui há.
//!
//! # O que acontece quando o contrato muda
//!
//! O iniciador e o kernel são compilados juntos e vão para o mesmo disco, mas
//! nada garante que o disco tenha os dois da mesma versão: uma ESP é um
//! sistema de arquivos, e alguém pode copiar um `.efi` novo sobre um kernel
//! velho. Por isso a entrega carrega três campos antes de qualquer conteúdo:
//!
//! - [`MAGICA`], que diz que o ponteiro aponta para uma entrega e não para
//!   lixo;
//! - [`VERSAO`], que muda quando o significado dos campos muda;
//! - o **tamanho**, que muda quando campos são acrescentados.
//!
//! O kernel confere os três antes de ler o resto. Sem eles, um iniciador de
//! outra versão entregaria campos deslocados — e um mapa de memória lido com
//! deslocamento errado não dá erro, dá um alocador que entrega páginas do
//! firmware.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod mapa;
pub mod usuario;

/// `DUKEBOOT`, em little-endian.
///
/// Oito bytes legíveis num despejo de memória, de propósito: quem estiver
/// olhando a entrega num depurador reconhece o começo dela sem consultar
/// nada.
pub const MAGICA: u64 = u64::from_le_bytes(*b"DUKEBOOT");

/// A versão do contrato.
///
/// Sobe quando o **significado** de um campo muda. Acrescentar um campo no
/// fim não exige subi-la: o tamanho já denuncia a diferença, e um kernel
/// novo lendo uma entrega antiga sabe que os campos novos não estão lá.
pub const VERSAO: u32 = 1;

/// O que o iniciador entrega ao kernel, no primeiro argumento.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Entrega {
    pub magica: u64,
    pub versao: u32,
    /// `size_of::<Entrega>()`, escrito por quem montou.
    pub tamanho: u32,
    /// Por onde o kernel enxerga a memória física. É o
    /// [`mapa::BASE_DA_MEMORIA_FISICA`], repetido aqui porque o kernel não
    /// deve precisar deduzir de uma constante o que a entrega pode afirmar.
    pub deslocamento_fisico: u64,
    /// Onde as regiões estão, em endereço **virtual** do kernel.
    ///
    /// Um `u64` e não um ponteiro: um ponteiro numa `struct` de ABI convida a
    /// desreferenciá-lo sem pensar, e este só é válido depois que o mapa novo
    /// estiver instalado.
    pub regioes: u64,
    pub quantas_regioes: u64,
    pub video: Video,
    /// Onde o device tree está, em endereço **físico**, ou zero quando não há.
    ///
    /// # Por que ele vem aqui, e por que só no ARM
    ///
    /// Porque no ARM o device tree é a fonte de tudo que não está no
    /// processador: onde a RAM começa, onde está o controlador de
    /// interrupções, onde está o ECAM do PCI. O protocolo de imagem crua do
    /// arm64 o entrega em `x0`, e o registrador passa a carregar a entrega —
    /// então ele precisa de outro caminho.
    ///
    /// Na UEFI ele não vem em registrador nenhum: ele é uma entrada da
    /// **tabela de configuração**, identificada por um GUID, que o iniciador
    /// procura. Passá-lo já achado poupa ao kernel percorrer a tabela, e mais
    /// que isso: depois do `ExitBootServices` a tabela do sistema pode não
    /// estar mais mapeada, e o kernel não teria onde procurar.
    ///
    /// No x86 é zero, e é a resposta certa: não há device tree numa máquina
    /// PC, e o mapa de memória vem do próprio firmware pelas regiões acima.
    ///
    /// # Por que é físico, ao contrário das regiões
    ///
    /// Porque quem o mapeia é o kernel, e ele já tem um caminho para isso —
    /// no ARM o mapa é de identidade, então o endereço físico serve direto.
    /// As regiões são virtuais porque o iniciador as escreve dentro do
    /// espaço que montou para o kernel; o device tree não é dele, é da
    /// placa.
    pub dispositivos: u64,
}

/// Quantas regiões de memória uma entrega pode carregar, no máximo.
///
/// É contrato, e não detalhe de um dos lados, porque os dois precisam do
/// mesmo número. O iniciador recusa um mapa maior que isto enquanto ainda há
/// como relatar; o kernel dimensiona a tabela dele por aqui. Quando os dois
/// eram constantes separadas — 256 de um lado, 64 do outro —, o iniciador
/// entregava as 133 regiões que o firmware do x86 descreve e o kernel
/// guardava as 64 primeiras: 28 MiB de RAM sumiam do alocador com a suíte
/// inteira passando.
///
/// Duzentas e cinquenta e seis. O firmware do emulador descreve cento e
/// trinta; o dobro é a folga para uma máquina de verdade, que tem mais
/// dispositivos.
pub const MAX_REGIOES: usize = 256;

/// O framebuffer, já mapeado pelo iniciador.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Video {
    /// Zero quando não há vídeo. Um `u32` em vez de um `bool` porque o
    /// tamanho de um `bool` em ABI é uma coisa que ninguém deveria precisar
    /// procurar.
    pub presente: u32,
    /// Ver [`formato`].
    pub formato: u32,
    /// Endereço virtual do começo do buffer.
    pub em: u64,
    pub bytes: u64,
    pub largura: u32,
    pub altura: u32,
    /// Quantos pixels cabem numa linha da memória, que pode ser mais que a
    /// largura visível.
    pub pixels_por_linha: u32,
    pub bytes_por_pixel: u32,
}

/// Os formatos de pixel que o contrato descreve.
pub mod formato {
    pub const RGB: u32 = 0;
    pub const BGR: u32 = 1;
}

/// Uma faixa de memória física, e de quem ela é.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Regiao {
    pub inicio: u64,
    /// Exclusivo.
    pub fim: u64,
    /// Ver [`tipo`].
    pub tipo: u32,
    _preenchimento: u32,
}

impl Regiao {
    pub const fn nova(inicio: u64, fim: u64, tipo: u32) -> Regiao {
        Regiao {
            inicio,
            fim,
            tipo,
            _preenchimento: 0,
        }
    }
}

/// De quem é uma região.
pub mod tipo {
    /// Livre para o kernel usar.
    pub const UTILIZAVEL: u32 = 0;
    /// Do iniciador: a imagem do kernel, as tabelas de página, a pilha, a
    /// própria entrega. O kernel não pode entregá-la ao alocador — ele está
    /// rodando dentro dela.
    pub const DO_INICIADOR: u32 = 1;
    /// Do firmware, ou de hardware. Não é para ninguém.
    pub const RESERVADA: u32 = 2;
}

// O tamanho da entrega faz parte do contrato, e mudá-lo sem querer é fácil:
// um campo acrescentado no meio empurra todos os de baixo. A asserção não
// impede a mudança — ela obriga quem a fizer a passar por aqui e subir a
// versão se o significado mudou.
const _: () = {
    assert!(size_of::<Entrega>() == 88);
    assert!(size_of::<Video>() == 40);
    assert!(size_of::<Regiao>() == 24);
};
