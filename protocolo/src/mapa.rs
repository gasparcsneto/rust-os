//! Onde cada coisa mora no espaço virtual do kernel.
//!
//! # Um lugar só
//!
//! Estas constantes já foram duas: uma no kernel e outra no iniciador, com um
//! teste do `xtask` lendo as duas fontes para exigir que batessem. Funcionava,
//! e era o arranjo que este projeto usa onde ele **não tem escolha** — o
//! padrão por setor do disco, por exemplo, tem uma metade num programa do
//! hospedeiro e não há pacote que caiba nos dois.
//!
//! Aqui há. Os dois lados incluem este pacote por caminho, e a divergência
//! deixa de ser uma coisa que um teste evita para ser uma coisa que não pode
//! acontecer. O preço de divergir era alto e mudo: um kernel mapeado num
//! endereço e ligado para outro não dá erro nem mensagem — dá uma máquina que
//! reinicia no primeiro salto, antes de haver o que a diagnostique.
//!
//! # Por que as regiões ficam tão longe umas das outras
//!
//! Porque uma tabela de tradução por processo se monta copiando as entradas
//! de topo do kernel, e uma entrada de topo cobre 512 GiB. Duas regiões do
//! kernel que dividissem uma entrada com o espaço do usuário levariam junto o
//! mapa do processo anterior — ou deixariam o kernel sem heap, conforme o
//! lado que se escolhesse. Desperdiçar espaço virtual num endereçamento de 48
//! bits não custa nada; descobrir tarde que duas regiões se encostaram custa.

/// Onde a imagem do kernel é carregada.
pub const BASE_DO_KERNEL: u64 = 0xFFFF_8000_0000_0000;

/// Por onde o kernel enxerga qualquer byte de memória física.
pub const BASE_DA_MEMORIA_FISICA: u64 = 0xFFFF_8800_0000_0000;

/// Onde a faixa de memória de dispositivo começa.
///
/// Fica **abaixo** do mapa da memória física de propósito, entre ele e a
/// imagem do kernel: são entradas de topo que ninguém mais usa. Só o kernel
/// mapeia aqui — o iniciador não fala com dispositivo nenhum além da serial,
/// que é por porta de entrada e saída.
pub const BASE_DE_MMIO: u64 = 0xFFFF_8400_0000_0000;

/// Onde o heap do kernel começa. Só o kernel mapeia aqui.
pub const BASE_DO_HEAP: u64 = 0xFFFF_9000_0000_0000;

/// Onde a área das pilhas de fio começa. Só o kernel mapeia aqui.
pub const BASE_DAS_PILHAS: u64 = 0xFFFF_9800_0000_0000;

/// Onde moram as superfícies gráficas. Só o kernel mapeia aqui.
///
/// Uma superfície é um buffer de pixels que o kernel compõe antes de mandar
/// para a tela. Ela não cabe no heap, que tem 1 MiB: uma tela de 1280x800 a
/// quatro bytes por pixel tem 4 MiB. O Redox, de onde vem o desenho desta
/// pilha, resolve isso com `mmap` em espaço de usuário; aqui a superfície sai
/// direto do alocador de frames, nesta faixa.
pub const BASE_DAS_SUPERFICIES: u64 = 0xFFFF_A800_0000_0000;

/// Onde fica o que o iniciador posiciona por conta própria.
///
/// A pilha inicial e o framebuffer. É a faixa que o kernel reserva para isso
/// justamente para não disputar espaço com o heap nem com as pilhas de fio.
pub const BASE_DO_RESTO: u64 = 0xFFFF_A000_0000_0000;

/// Onde a página de guarda da pilha inicial fica.
///
/// A pilha começa uma página adiante — ver o `carga` do iniciador sobre por que a
/// guarda é a de baixo.
pub const PILHA_EM: u64 = BASE_DO_RESTO;

/// Quanto de pilha o kernel recebe para começar.
///
/// Trinta e duas páginas, 128 KiB. Ela serve até o kernel criar as próprias
/// pilhas de fio; o que a dimensiona é a profundidade do boot, que é rasa.
pub const PAGINAS_DA_PILHA: usize = 32;

/// Onde o framebuffer é mapeado.
///
/// Dezesseis mebibytes adiante da base, com folga para uma pilha que cresça
/// e para um framebuffer de qualquer resolução plausível entre os dois.
pub const VIDEO_EM: u64 = BASE_DO_RESTO + 0x0100_0000;

/// Quanto espaço virtual uma entrada da tabela de topo cobre.
pub const COBERTURA_DA_ENTRADA_DE_TOPO: u64 = 512 * 1024 * 1024 * 1024;

/// Qual entrada da tabela de topo cobre um endereço.
const fn entrada_de_topo(endereco: u64) -> u64 {
    endereco / COBERTURA_DA_ENTRADA_DE_TOPO
}

// As regiões não podem se encostar, e a conferência é de compilação porque o
// erro é de aritmética de endereço: mover uma constante meio tebibyte para o
// lado não quebra nada visível até o kernel rodar.
const _: () = {
    // Nenhuma das cinco regiões pode dividir uma entrada de topo com outra.
    let bases = [
        BASE_DO_KERNEL,
        BASE_DE_MMIO,
        BASE_DA_MEMORIA_FISICA,
        BASE_DO_HEAP,
        BASE_DAS_PILHAS,
        BASE_DO_RESTO,
    ];
    let mut i = 0;
    while i < bases.len() {
        let mut j = i + 1;
        while j < bases.len() {
            assert!(entrada_de_topo(bases[i]) != entrada_de_topo(bases[j]));
            j += 1;
        }
        i += 1;
    }

    // E o vídeo tem de caber depois da pilha, sem encostar nela.
    assert!(VIDEO_EM > PILHA_EM + (PAGINAS_DA_PILHA as u64 + 1) * 4096);
};
