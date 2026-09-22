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
//! # Por que continua escrito à mão
//!
//! Existem crates de FDT prontos, e o kernel já usa crates no ARM para o que
//! vale: registradores de sistema e blocos de MMIO, onde montar bits à mão é
//! arriscado e invisível quando erra.
//!
//! Aqui o critério dá o resultado oposto. O formato é pequeno e bem
//! especificado, não há aritmética de bits contra um manual de arquitetura, e
//! precisamos de exatamente uma coisa dele: os nós `/memory`. O parser é
//! autocontido, tem teste, e deixa visível um formato que vai voltar a
//! importar quando formos descobrir dispositivos virtio. Trocá-lo por uma
//! dependência não tornaria nada mais seguro — só esconderia o formato.
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

/// Tamanho total do blob, lido do cabeçalho.
///
/// Serve para reservar a região onde o firmware o depositou: ela fica dentro
/// da RAM que o próprio device tree declara utilizável, então sem isto o
/// alocador a entregaria alegremente.
///
/// # Safety
///
/// `dtb` precisa apontar para um device tree válido, ou ser nulo.
pub unsafe fn tamanho_total(dtb: *const u8) -> Option<u64> {
    if dtb.is_null() {
        return None;
    }
    // SAFETY: o chamador garantiu validade; conferimos a assinatura antes de
    // confiar em qualquer outro campo.
    unsafe {
        if be32(dtb, 0) != MAGIC {
            return None;
        }
        Some(be32(dtb, 4) as u64)
    }
}

/// Uma propriedade encontrada durante o percurso.
pub struct Propriedade<'a> {
    /// Profundidade do nó dono: 1 para filhos da raiz, 2 para netos.
    pub profundidade: usize,
    /// Nome do nó dono, sem o `@endereço`.
    pub no: &'a [u8],
    /// Numeração do nó dono na ordem do percurso.
    ///
    /// Existe porque o nome é emprestado do blob e não sobrevive à closure,
    /// e quem procura um nó específico precisa de algo comparável que sim.
    /// Dois nós nunca compartilham este número.
    pub no_seq: u32,
    /// Nome da propriedade.
    pub nome: &'a [u8],
    /// Deslocamento dos dados dentro do blob.
    pub dados: usize,
    /// Tamanho dos dados, em bytes.
    pub tamanho: usize,
    /// Quantas células a raiz usa para endereço, e quantas para tamanho.
    ///
    /// Vêm da raiz porque é ela que as declara para os filhos. Um nó não
    /// descreve as próprias larguras — descreve as dos filhos dele.
    pub address_cells: u32,
    pub size_cells: u32,
}

/// Percorre o device tree, chamando `f` para cada propriedade encontrada.
///
/// # Por que um percurso só
///
/// Porque o formato é uma sequência de tokens sem índice: descobrir qualquer
/// coisa custa percorrer tudo desde o começo. Escrever um percurso por
/// pergunta duplicaria a máquina de estados — profundidade, larguras de
/// célula, alinhamento de quatro bytes — e o segundo divergiria do primeiro na
/// primeira correção que só um deles recebesse.
///
/// # Safety
///
/// `dtb` precisa apontar para um device tree válido, ou ser nulo (caso em que
/// a função retorna erro sem desreferenciar nada).
unsafe fn percorrer(dtb: *const u8, mut f: impl FnMut(&Propriedade)) -> Result<(), &'static str> {
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

    // O nó cujas propriedades estamos lendo. As propriedades de um nó vêm
    // antes dos filhos dele, então guardar o último nome aberto basta.
    let mut no: &[u8] = b"";
    let mut no_seq = 0u32;

    loop {
        let token = unsafe { be32(dtb, pos) };
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let nome = unsafe { cstr(dtb, pos) };
                pos += alinhar4(nome.len() + 1);
                profundidade += 1;
                no_seq = no_seq.wrapping_add(1);

                // O nome vem como `tipo@endereço`; o endereço é o mesmo que a
                // propriedade `reg` já diz, e compará-lo daria falso negativo
                // em qualquer máquina com outro mapa.
                no = match nome.iter().position(|&b| b == b'@') {
                    Some(corte) => &nome[..corte],
                    None => nome,
                };
            }

            FDT_END_NODE => {
                profundidade = profundidade.saturating_sub(1);
                no = b"";
            }

            FDT_PROP => {
                let tamanho = unsafe { be32(dtb, pos) } as usize;
                pos += 4;
                let nome_off = unsafe { be32(dtb, pos) } as usize;
                pos += 4;

                let nome = unsafe { cstr(dtb, off_strings + nome_off) };
                let dados = pos;

                // As larguras da raiz precisam ser lidas antes de qualquer
                // filho usá-las, e são: a raiz é o primeiro nó do blob.
                if profundidade == 1 {
                    if nome == b"#address-cells" {
                        address_cells = unsafe { be32(dtb, dados) };
                    } else if nome == b"#size-cells" {
                        size_cells = unsafe { be32(dtb, dados) };
                    }
                }

                f(&Propriedade {
                    profundidade,
                    no,
                    no_seq,
                    nome,
                    dados,
                    tamanho,
                    address_cells,
                    size_cells,
                });

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

/// Lê uma lista `reg` de pares (endereço, tamanho), chamando `f` para cada.
///
/// # Safety
/// `prop` precisa ter vindo de um percurso do blob `dtb`.
unsafe fn ler_reg(dtb: *const u8, prop: &Propriedade, mut f: impl FnMut(u64, u64)) {
    let largura_par = (prop.address_cells + prop.size_cells) as usize * 4;
    if largura_par == 0 {
        return;
    }
    let mut deslocamento = 0usize;
    while deslocamento + largura_par <= prop.tamanho {
        // SAFETY: delegada ao chamador; o laço confere que o par inteiro cabe.
        unsafe {
            let inicio = ler_celulas(dtb, prop.dados + deslocamento, prop.address_cells);
            let tam = ler_celulas(
                dtb,
                prop.dados + deslocamento + prop.address_cells as usize * 4,
                prop.size_cells,
            );
            f(inicio, tam);
        }
        deslocamento += largura_par;
    }
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
    // SAFETY: delegada ao chamador.
    unsafe {
        percorrer(dtb, |prop| {
            // Os nós de memória são filhos diretos da raiz e se chamam
            // `memory@<endereço>`.
            if prop.profundidade == 2 && prop.no == b"memory" && prop.nome == b"reg" {
                ler_reg(dtb, prop, &mut f);
            }
        })
    }
}

/// Onde o espaço de configuração PCI está mapeado, e quanto ele ocupa.
///
/// # Por que perguntar em vez de fixar
///
/// O endereço do ECAM é escolha da placa, não da arquitetura. A máquina
/// `virt` do QEMU o coloca num lugar, uma placa real o coloca noutro, e uma
/// versão futura do QEMU pode mudá-lo — foi para não depender disso que este
/// kernel lê o device tree desde o começo.
///
/// Procuramos pelo `compatible`, e não pelo nome do nó, porque o nome carrega
/// o endereço (`pcie@10000000`) e compará-lo seria fixar o endereço por outro
/// caminho.
///
/// # Safety
///
/// `dtb` precisa apontar para um device tree válido, ou ser nulo.
pub unsafe fn encontrar_ecam(dtb: *const u8) -> Option<(u64, u64)> {
    // Duas coisas, ambas guardadas pelo **número do nó**, e não por um
    // booleano: o que o último `reg` visto disse, e qual nó se declarou
    // compatível.
    //
    // Guardar o `reg` antes de saber se serve é o que torna a busca correta
    // numa passada só. A especificação não ordena as propriedades dentro de um
    // nó, e o QEMU de fato emite `reg` **antes** de `compatible` neste nó —
    // uma versão anterior disto só olhava o `reg` depois de ver o
    // `compatible`, e por isso não achava nada.
    let mut ultimo_reg: Option<(u32, u64, u64)> = None;
    let mut achado: Option<(u64, u64)> = None;

    let mut visitar = |prop: &Propriedade| {
        if prop.profundidade != 2 || achado.is_some() {
            return;
        }

        if prop.nome == b"reg" {
            // SAFETY: o percurso garantiu que `dados` e `tamanho` estão dentro
            // do blob.
            unsafe {
                ler_reg(dtb, prop, |inicio, tamanho| {
                    if ultimo_reg.map(|(seq, ..)| seq) != Some(prop.no_seq) {
                        ultimo_reg = Some((prop.no_seq, inicio, tamanho));
                    }
                });
            }
            return;
        }

        // `compatible` é uma lista de strings terminadas em zero, da mais
        // específica para a mais genérica.
        if prop.nome == b"compatible" {
            // SAFETY: mesma justificativa.
            let lista = unsafe { core::slice::from_raw_parts(dtb.add(prop.dados), prop.tamanho) };
            if !lista
                .split(|&b| b == 0)
                .any(|s| s == b"pci-host-ecam-generic")
            {
                return;
            }

            if let Some((seq, inicio, tamanho)) = ultimo_reg
                && seq == prop.no_seq
            {
                achado = Some((inicio, tamanho));
            }
        }
    };

    // SAFETY: delegada ao chamador.
    let _ = unsafe { percorrer(dtb, &mut visitar) };

    achado
}
