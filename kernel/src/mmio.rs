//! Como o kernel alcança a memória de um dispositivo.
//!
//! # O problema
//!
//! Um BAR de PCI guarda um endereço **físico**. O kernel roda com a MMU
//! ligada e só consegue desreferenciar endereços **virtuais**. Entre os dois
//! falta um mapeamento, e ele não aparece sozinho.
//!
//! No ARM isso ficou invisível por um tempo: o mapa de identidade do boot
//! cobre o primeiro GiB como memória de dispositivo, e é lá que as janelas do
//! barramento caem — endereço físico e virtual coincidem, e o driver parecia
//! funcionar sem mapear nada. No x86 não há identidade nenhuma, e a primeira
//! escrita num BAR derrubou o kernel com falha de página. O ARM estava certo
//! por acidente.
//!
//! # A solução
//!
//! Uma faixa de espaço virtual reservada para isto, e uma função que devolve
//! por onde um endereço físico pode ser alcançado. Nada além dela precisa
//! saber que o mapeamento existe.
//!
//! # Por que memória de *dispositivo*
//!
//! Porque um registrador não é uma variável. Ler duas vezes pode devolver
//! valores diferentes, escrever pode ter efeito sem que ninguém leia, e a
//! ordem entre dois acessos é parte do protocolo. Um mapeamento cacheável
//! autoriza o processador a servir a segunda leitura do cache, a juntar duas
//! escritas numa e a reordenar as duas — três otimizações corretas para
//! memória e catastróficas para um dispositivo.
//!
//! # Por que um alocador de incremento
//!
//! Porque nada é devolvido. Um mapeamento de MMIO dura o que o driver dura, e
//! um driver dura o que o kernel dura: não há como desligar um disco nesta
//! fase. A faixa reservada é de um espaço virtual de 48 bits, onde 512 GiB
//! custam zero — o que custaria é descobrir tarde que duas regiões se
//! encostaram.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{BASE_DE_MMIO, COBERTURA_DA_ENTRADA_DE_TOPO, Permissoes, TAMANHO_PAGINA};

/// Primeiro endereço virtual ainda livre na faixa de MMIO.
static PROXIMO: AtomicU64 = AtomicU64::new(BASE_DE_MMIO);

/// Permissões de todo mapeamento desta faixa.
///
/// Não executável e não acessível ao usuário, sempre. Buscar instruções de um
/// registrador não é algo que um kernel queira poder fazer por engano, e um
/// processo que alcançasse um BAR teria acesso direto ao hardware.
const COMO_DISPOSITIVO: Permissoes = Permissoes {
    escrita: true,
    executavel: false,
    dispositivo: true,
    usuario: false,
};

/// Devolve um endereço virtual por onde `fisico` pode ser alcançado.
///
/// O endereço devolvido preserva o deslocamento dentro da página: pedir
/// `0x1000_8004` devolve algo terminado em `004`. É o que permite passar um
/// endereço de registrador em vez de um de página e continuar fazendo
/// aritmética sobre ele.
pub fn mapear(fisico: u64, tamanho: u64) -> Result<u64, &'static str> {
    if tamanho == 0 {
        return Err("regiao de MMIO de tamanho zero");
    }

    let pagina = fisico & !(TAMANHO_PAGINA - 1);
    let dentro_da_pagina = fisico - pagina;
    let bytes = dentro_da_pagina
        .checked_add(tamanho)
        .ok_or("regiao de MMIO alem do fim do espaco fisico")?;
    let paginas = bytes.div_ceil(TAMANHO_PAGINA);

    let base = reservar(paginas * TAMANHO_PAGINA)?;

    for indice in 0..paginas {
        let deslocamento = indice * TAMANHO_PAGINA;
        // SAFETY: o endereço físico veio de um BAR ou do device tree, ou seja,
        // descreve memória de dispositivo real; o endereço virtual saiu do
        // incremento acima e portanto não está mapeado para mais nada.
        let r = unsafe {
            crate::arch::mapear_frame(base + deslocamento, pagina + deslocamento, COMO_DISPOSITIVO)
        };
        if let Err(motivo) = r {
            // Desfazer o que já foi mapeado. As páginas seguem reservadas — o
            // incremento não anda para trás —, e tudo bem: o que importa é
            // não deixar meia região traduzindo, porque uma escrita nela
            // chegaria ao dispositivo pela metade.
            for desfazer in 0..indice {
                let _ = crate::arch::desmapear(base + desfazer * TAMANHO_PAGINA);
            }
            return Err(motivo);
        }
    }

    Ok(base + dentro_da_pagina)
}

/// Reserva espaço virtual na faixa de MMIO.
fn reservar(bytes: u64) -> Result<u64, &'static str> {
    let fim_da_faixa = BASE_DE_MMIO + COBERTURA_DA_ENTRADA_DE_TOPO;

    // `try_update` em vez de ler-somar-escrever porque a reserva precisa ser
    // atômica: dois fios mapeando dispositivos ao mesmo tempo receberiam o
    // mesmo endereço, e o segundo mapeamento falharia ou sobrescreveria o
    // primeiro. Não acontece hoje — tudo isto roda no boot —, mas a alternativa
    // seria uma tranca para proteger um único `u64`.
    PROXIMO
        .try_update(Ordering::AcqRel, Ordering::Acquire, |atual| {
            let fim = atual.checked_add(bytes)?;
            (fim <= fim_da_faixa).then_some(fim)
        })
        .map_err(|_| "a faixa de MMIO do kernel acabou")
}

/// Quanto da faixa já foi entregue, em bytes. Para o relatório do agente.
pub fn reservado() -> u64 {
    PROXIMO.load(Ordering::Acquire) - BASE_DE_MMIO
}
