//! Confere `mapear` e o monte do lado de quem pede.
//!
//! A suíte do kernel confere o lado de quem atende; este programa confere o
//! que um processo vê: que o kernel recusa o que deve recusar, com o erro
//! certo, que a memória nova chega zerada e fica sendo do processo, e que o
//! monte reaproveita o que foi liberado em vez de crescer para sempre.
//!
//! Sai com [`CODIGO`] quando tudo confere. Cada conferência que falha tem o
//! seu código, de 1 em diante, para que o log do kernel diga qual foi.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use programas::sistema::{erro, mapear};
use programas::{escreverln, monte};
use protocolo::usuario::{MAPEAVEL, PAGINA};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 62;

/// Uma faixa bem acima do monte, que ele não alcança neste programa.
const LIVRE: u64 = MAPEAVEL.1 - 64 * PAGINA;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // As recusas, cada uma com o seu erro.
    let recusas: [(u64, u64, i64); 6] = [
        // Endereço fora da página.
        (LIVRE + 8, PAGINA, erro::ENDERECO_INVALIDO),
        // Tamanho zero, e tamanho fora da página.
        (LIVRE, 0, erro::TAMANHO_INVALIDO),
        (LIVRE, PAGINA + 1, erro::TAMANHO_INVALIDO),
        // Abaixo da faixa — em cima do próprio programa.
        (MAPEAVEL.0 - PAGINA, PAGINA, erro::ENDERECO_INVALIDO),
        // Começa dentro e termina fora.
        (MAPEAVEL.1 - PAGINA, 2 * PAGINA, erro::ENDERECO_INVALIDO),
        // Maior que o teto de um pedido.
        (LIVRE, 17 * 1024 * 1024, erro::TAMANHO_INVALIDO),
    ];
    for (i, (endereco, tamanho, esperado)) in recusas.into_iter().enumerate() {
        let obtido = mapear(endereco, tamanho);
        if obtido != esperado {
            escreverln!(
                "recusa {}: mapear({:#x}, {:#x}) devolveu {}, e nao {}",
                i,
                endereco,
                tamanho,
                obtido,
                esperado
            );
            return 1;
        }
    }

    // Duas páginas novas: zeradas, e deste processo.
    if mapear(LIVRE, 2 * PAGINA) != 0 {
        return 2;
    }
    let paginas = LIVRE as *mut u64;
    let palavras = (2 * PAGINA / 8) as usize;
    // SAFETY: as duas páginas acabaram de ser mapeadas, graváveis, para nós.
    unsafe {
        for i in 0..palavras {
            if paginas.add(i).read_volatile() != 0 {
                return 3;
            }
            paginas.add(i).write_volatile(i as u64 ^ 0xD0CE);
        }
        for i in 0..palavras {
            if paginas.add(i).read_volatile() != i as u64 ^ 0xD0CE {
                return 4;
            }
        }
    }

    // Mapear de novo por cima — inteiro ou em parte — é recusado, e o que
    // estava lá continua lá.
    if mapear(LIVRE, PAGINA) != erro::JA_MAPEADO
        || mapear(LIVRE + PAGINA, 2 * PAGINA) != erro::JA_MAPEADO
        || mapear(LIVRE - PAGINA, 2 * PAGINA) != erro::JA_MAPEADO
    {
        return 5;
    }
    // SAFETY: a primeira palavra é da faixa mapeada acima.
    if unsafe { paginas.read_volatile() } != 0xD0CE {
        return 6;
    }
    // E a recusa parcial não deixou a página de baixo mapeada pela metade:
    // mapeá-la sozinha dá certo.
    if mapear(LIVRE - PAGINA, PAGINA) != 0 {
        return 7;
    }

    // O monte: blocos de tamanhos e alinhamentos variados, sem sobreposição.
    let mut blocos: Vec<Box<[u8]>> = Vec::new();
    for i in 0..200usize {
        let tamanho = 1 + (i * 37) % 3000;
        blocos.push(alloc::vec![i as u8; tamanho].into_boxed_slice());
    }
    for (i, bloco) in blocos.iter().enumerate() {
        if bloco.iter().any(|&b| b != i as u8) {
            return 8;
        }
    }
    #[repr(align(4096))]
    struct Alinhado([u8; 64]);
    let alinhado = Box::new(Alinhado([9; 64]));
    if !(&*alinhado as *const Alinhado as usize).is_multiple_of(4096) || alinhado.0[63] != 9 {
        return 9;
    }
    drop(alinhado);

    // Liberar tudo e repetir: o monte reaproveita, e não pede mais nada.
    let antes = monte::mapeados();
    for _ in 0..20 {
        blocos.clear();
        for i in 0..200usize {
            let tamanho = 1 + (i * 37) % 3000;
            blocos.push(alloc::vec![i as u8; tamanho].into_boxed_slice());
        }
    }
    if monte::mapeados() != antes {
        escreverln!(
            "o monte cresceu de {} para {} bytes reaproveitando os mesmos blocos",
            antes,
            monte::mapeados()
        );
        return 10;
    }

    // A fusão: blocos lado a lado liberados fora de ordem — os pares
    // subindo, os ímpares descendo — voltam a ser um bloco só, e a lista
    // volta ao número de blocos livres que tinha antes. Sem fundir com o
    // vizinho de cima ou com o de baixo, os pedaços ficam soltos e a
    // contagem sobe. A rotação acima não pegava isso: com os mesmos
    // tamanhos, ela reaproveita exatamente os mesmos blocos, e nenhuma
    // fusão acontece.
    //
    // Antes, o monte cresce de uma vez, com um bloco grande que volta
    // inteiro: a contagem é tomada depois, e o ciclo cabe no que ele deixou
    // livre sem crescer de novo. Um ciclo de aquecimento no lugar disso não
    // servia — medido, sem a fusão com o vizinho de cima ele deixava a
    // lista fragmentada, o segundo ciclo reproduzia a mesma fragmentação, e
    // as duas contagens batiam.
    drop(alloc::vec![0u8; 256 * 1024]);
    let livres = monte::blocos_livres();
    let crescido = monte::mapeados();
    {
        let mut lado_a_lado: Vec<Option<Box<[u8; 1024]>>> =
            (0..64).map(|_| Some(Box::new([0u8; 1024]))).collect();
        for i in (0..64).step_by(2) {
            lado_a_lado[i] = None;
        }
        for i in (1..64).step_by(2).rev() {
            lado_a_lado[i] = None;
        }
    }
    if monte::mapeados() != crescido {
        return 15;
    }
    if monte::blocos_livres() != livres {
        escreverln!(
            "a lista tinha {} blocos livres e ficou com {} depois de liberar tudo",
            livres,
            monte::blocos_livres()
        );
        return 14;
    }

    // Tudo ou nada: pedidos de 16 MiB até a memória acabar. O pedido que
    // falha por falta de memória falha no meio — já tinha mapeado páginas
    // quando o alocador de frames secou —, e o kernel precisa desfazê-las.
    // Se não desfizesse, a primeira página dele continuaria mapeada, e pedir
    // só ela daria `JA_MAPEADO`.
    const BLOCO: u64 = 16 * 1024 * 1024;
    let mut pedido = MAPEAVEL.0 + 8 * 1024 * 1024;
    let mut blocos_dados = 0;
    let falhou_em = loop {
        if pedido + BLOCO > LIVRE - PAGINA {
            escreverln!("a memoria nao acabou em {} blocos de 16 MiB", blocos_dados);
            return 11;
        }
        match mapear(pedido, BLOCO) {
            0 => {
                blocos_dados += 1;
                pedido += BLOCO;
            }
            erro::SEM_MEMORIA => break pedido,
            outro => {
                escreverln!("um bloco de 16 MiB devolveu {}", outro);
                return 12;
            }
        }
    };
    if mapear(falhou_em, PAGINA) != 0 {
        return 13;
    }

    escreverln!(
        "memoria conferida: {} KiB no monte, {} pedidos recusados como deviam, a memoria acabou em {} MiB",
        monte::mapeados() / 1024,
        recusas.len(),
        blocos_dados * 16
    );
    CODIGO
}
