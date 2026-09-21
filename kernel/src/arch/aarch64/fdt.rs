//! Leitor mínimo de Flattened Device Tree (FDT).
//!
//! # Por que precisamos disto
//!
//! No x86 o bootloader entrega um mapa de memória pronto. No ARM não existe
//! esse intermediário: o firmware (aqui, o QEMU) deposita na RAM um *device
//! tree* — uma árvore binária descrevendo todo o hardware da placa — e passa
//! o endereço dela no registrador `x0`. Descobrir quanta memória a máquina
//! tem significa interpretar essa árvore.
//!
//! # Por que escrito à mão
//!
//! Existem crates de FDT prontos, mas o formato é pequeno e bem especificado,
//! e precisamos de exatamente uma coisa dele: os nós `/memory`. Escrever o
//! parser mantém o kernel sem dependências no ARM e deixa visível um formato
//! que vai voltar a importar quando formos descobrir controlador de
//! interrupções, timer e dispositivos virtio.
//!
//! # O formato, em resumo
//!
//! Um cabeçalho aponta para dois blocos: o *struct block*, que é uma sequência
//! de tokens de 32 bits descrevendo a árvore, e o *strings block*, onde os
//! nomes das propriedades são guardados uma única vez e referenciados por
//! deslocamento. Todos os inteiros são big-endian, independentemente da
//! arquitetura — herança do PowerPC, onde o formato nasceu.

/// Assinatura no início de todo device tree válido.
const MAGIC: u32 = 0xd00d_feed;

// Tokens do struct block.
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

/// Lê um `u32` big-endian no deslocamento indicado.
///
/// # Safety
/// `base + offset` precisa estar dentro do device tree.
unsafe fn be32(base: *const u8, offset: usize) -> u32 {
    // `read_unaligned` por segurança: o formato garante alinhamento de 4
    // bytes, mas nada nos garante que o *ponteiro base* recebido do firmware
    // esteja alinhado, e um acesso desalinhado no ARM pode gerar exceção.
    let valor = unsafe { core::ptr::read_unaligned(base.add(offset) as *const u32) };
    u32::from_be(valor)
}

/// Devolve a string terminada em nulo no deslocamento indicado.
///
/// # Safety
/// `base + offset` precisa apontar para uma string válida dentro do blob.
unsafe fn cstr<'a>(base: *const u8, offset: usize) -> &'a [u8] {
    let inicio = unsafe { base.add(offset) };
    let mut n = 0;
    // SAFETY: o formato garante terminação em nulo dentro do blob.
    while unsafe { *inicio.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(inicio, n) }
}

/// Arredonda para cima até o próximo múltiplo de 4.
///
/// Todo campo de tamanho variável no struct block é preenchido até uma
/// fronteira de 4 bytes, para que o token seguinte fique alinhado.
const fn alinhar4(n: usize) -> usize {
    (n + 3) & !3
}

/// Lê um endereço ou tamanho codificado em `cells` palavras de 32 bits.
///
/// O device tree não fixa a largura: o nó raiz declara, em
/// `#address-cells`/`#size-cells`, quantas palavras cada valor ocupa. Em
/// arm64 o normal é 2 (ou seja, 64 bits), mas ler a declaração em vez de
/// assumir é o que faz o parser funcionar em placas reais.
///
/// # Safety
/// A faixa lida precisa estar dentro do blob.
unsafe fn ler_celulas(base: *const u8, offset: usize, cells: u32) -> u64 {
    let mut valor = 0u64;
    for i in 0..cells as usize {
        valor = (valor << 32) | unsafe { be32(base, offset + i * 4) } as u64;
    }
    valor
}

/// Percorre o device tree e chama `f(inicio, tamanho)` para cada faixa de RAM.
///
/// # Safety
///
/// `dtb` precisa apontar para um device tree válido, ou ser nulo (caso em que
/// a função retorna erro sem desreferenciar nada).
pub unsafe fn percorrer_memoria(
    dtb: *const u8,
    mut f: impl FnMut(u64, u64),
) -> Result<(), &'static str> {
    if dtb.is_null() {
        return Err("ponteiro de device tree nulo");
    }
    // SAFETY: o chamador garantiu validade; lemos apenas o cabeçalho antes de
    // confirmar a assinatura.
    if unsafe { be32(dtb, 0) } != MAGIC {
        return Err("assinatura de device tree invalida");
    }

    let off_struct = unsafe { be32(dtb, 8) } as usize;
    let off_strings = unsafe { be32(dtb, 12) } as usize;

    let mut pos = off_struct;
    let mut profundidade = 0usize;

    // Larguras padrão segundo a especificação, usadas se a raiz não declarar.
    let mut address_cells = 2u32;
    let mut size_cells = 2u32;

    // Estamos dentro de um nó `/memory...`?
    let mut em_memoria = false;

    loop {
        let token = unsafe { be32(dtb, pos) };
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let nome = unsafe { cstr(dtb, pos) };
                pos += alinhar4(nome.len() + 1);
                profundidade += 1;

                // Os nós de memória são filhos diretos da raiz e se chamam
                // `memory@<endereço>`.
                if profundidade == 2 {
                    em_memoria = nome.starts_with(b"memory");
                }
            }

            FDT_END_NODE => {
                if profundidade == 2 {
                    em_memoria = false;
                }
                profundidade = profundidade.saturating_sub(1);
            }

            FDT_PROP => {
                let tamanho = unsafe { be32(dtb, pos) } as usize;
                pos += 4;
                let nome_off = unsafe { be32(dtb, pos) } as usize;
                pos += 4;

                let nome = unsafe { cstr(dtb, off_strings + nome_off) };
                let dados = pos;

                if profundidade == 1 {
                    // Propriedades da raiz: as larguras de célula.
                    if nome == b"#address-cells" {
                        address_cells = unsafe { be32(dtb, dados) };
                    } else if nome == b"#size-cells" {
                        size_cells = unsafe { be32(dtb, dados) };
                    }
                } else if em_memoria && nome == b"reg" {
                    // `reg` é uma lista de pares (endereço, tamanho).
                    let largura_par = (address_cells + size_cells) as usize * 4;
                    if largura_par > 0 {
                        let mut deslocamento = 0usize;
                        while deslocamento + largura_par <= tamanho {
                            let inicio =
                                unsafe { ler_celulas(dtb, dados + deslocamento, address_cells) };
                            let tam = unsafe {
                                ler_celulas(
                                    dtb,
                                    dados + deslocamento + address_cells as usize * 4,
                                    size_cells,
                                )
                            };
                            f(inicio, tam);
                            deslocamento += largura_par;
                        }
                    }
                }

                pos += alinhar4(tamanho);
            }

            // Um NOP existe para que ferramentas possam remover um nó do blob
            // sem precisar reescrever tudo depois dele.
            FDT_NOP => {}

            FDT_END => return Ok(()),

            _ => return Err("token desconhecido no device tree"),
        }
    }
}
