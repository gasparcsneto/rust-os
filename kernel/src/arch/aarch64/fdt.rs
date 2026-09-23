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
//! especificado, e não há aritmética de bits contra um manual de arquitetura.
//! Precisamos de três coisas dele: os nós `/memory`, o endereço do espaço de
//! configuração PCI e as janelas que o barramento encaminha. O parser é
//! autocontido, tem teste, e deixa visível um formato que o kernel consulta
//! toda vez que precisa descobrir onde algo está. Trocá-lo por uma dependência
//! não tornaria nada mais seguro — só esconderia o formato.
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

/// Maior largura de célula que este leitor aceita.
///
/// # Por que um teto
///
/// Porque `#address-cells` e `#size-cells` vêm **do blob**, e o blob vem do
/// firmware. Um valor absurdo ali não é hipótese remota: é o que se lê de um
/// device tree corrompido, e a aritmética que o consome não estava preparada.
///
/// `(address_cells + size_cells) * 4` com os dois em `0xFFFF_FFFF` transborda
/// a soma de 32 bits — pânico num build de depuração, e uma largura pequena e
/// falsa num de release, que faria o leitor interpretar lixo como endereços.
///
/// Quatro é o que a especificação admite: 128 bits de endereço. Recusar acima
/// disso transforma um blob malformado numa leitura que simplesmente não
/// encontra nada, em vez de num kernel que morre ou inventa endereços.
const MAX_CELULAS: u32 = 4;

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

/// Se uma propriedade tem ao menos uma célula de conteúdo.
///
/// `be32` lê quatro bytes; uma propriedade menor que isso faria a leitura
/// passar do fim dos dados dela e entrar na próxima.
const fn prop_cabe(tamanho: usize) -> bool {
    tamanho >= 4
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
                if profundidade == 1 && prop_cabe(tamanho) {
                    // Uma declaração fora da faixa é descartada, e o padrão da
                    // especificação continua valendo. Conferir aqui vale por
                    // todos os consumidores: é o único ponto por onde estas
                    // larguras entram no kernel.
                    if nome == b"#address-cells" {
                        let valor = unsafe { be32(dtb, dados) };
                        if valor <= MAX_CELULAS {
                            address_cells = valor;
                        }
                    } else if nome == b"#size-cells" {
                        let valor = unsafe { be32(dtb, dados) };
                        if valor <= MAX_CELULAS {
                            size_cells = valor;
                        }
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
    // Soma em `usize`, e não em `u32`: as duas larguras vêm do blob, e somá-las
    // na largura em que foram lidas transbordaria. O percurso já as limita a
    // [`MAX_CELULAS`], e esta é a segunda barreira — a que continua valendo se
    // um dia elas entrarem por outro caminho.
    let largura_par = (prop.address_cells as usize + prop.size_cells as usize) * 4;
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

/// Profundidade das propriedades de um nó que é filho direto da raiz.
///
/// # Por que a busca exige isso
///
/// Porque `Propriedade::address_cells` carrega as larguras declaradas **pela
/// raiz**, e é com elas que o endereço do lado do pai é lido, tanto no `reg`
/// quanto no `ranges`. Isso só está certo se o pai do nó *for* a raiz.
///
/// Numa placa que pendure o host bridge sob um `/soc`, quem declara as
/// larguras é o `/soc`, não a raiz. Sem esta conferência o nó seria
/// encontrado e lido com as larguras erradas — e o resultado não seria um
/// erro, seria um endereço plausível e falso, que o kernel mapearia.
///
/// Recusar o nó é a resposta certa para um caso que este leitor não sabe
/// tratar: a enumeração não acontece, o log diz que não há barramento, e
/// ninguém desreferencia um endereço inventado.
const FILHO_DA_RAIZ: usize = 2;

/// O binding PCI fixa três células de endereço para os filhos de um host
/// bridge, e duas de tamanho.
///
/// São os únicos números deste arquivo que não vêm lidos do blob, e vale
/// dizer por quê: a especificação do device tree não os deixa à escolha da
/// placa — um nó que se declara `pci-host-ecam-generic` e usasse outras
/// larguras não seria um host bridge PCI, seria um nó malformado. Ler a
/// declaração do próprio nó daria a ilusão de flexibilidade sobre algo que a
/// própria propriedade `ranges` não sabe expressar de outro jeito.
const CELULAS_DE_ENDERECO_PCI: usize = 3;
const CELULAS_DE_TAMANHO_PCI: usize = 2;

/// Código do espaço de memória de 32 bits, nos bits 25-24 da palavra alta.
///
/// A palavra alta de um endereço PCI no device tree não é endereço: é uma
/// descrição de *onde* o endereço vive. `0b00` é configuração, `0b01` é I/O,
/// `0b10` é memória de 32 bits e `0b11` é memória de 64 bits.
const ESPACO_DE_MEMORIA_32: u32 = 0b10;

/// O que o device tree diz sobre o barramento PCI desta placa.
pub struct BarramentoPci {
    /// Onde o espaço de configuração (ECAM) começa, e quanto ele ocupa.
    pub ecam: (u64, u64),
    /// A janela de memória de 32 bits, se a placa declarou uma: endereço do
    /// lado do barramento, endereço do lado da CPU, e tamanho.
    ///
    /// Os dois endereços existem porque não são a mesma coisa. O que se
    /// escreve num BAR é o endereço **do barramento**; o que a CPU
    /// desreferencia é o endereço do lado dela. A máquina `virt` os faz
    /// coincidir, mas depender disso seria depender de uma coincidência que a
    /// `ranges` existe justamente para descrever.
    pub mmio32: Option<(u64, u64, u64)>,
}

/// Lê a `ranges` de um host bridge e devolve a primeira janela de memória de
/// 32 bits que ela declarar.
///
/// Por que a de 32 bits: é a única em que um BAR de 32 bits — que é o que os
/// dispositivos virtio do QEMU pedem — consegue ser endereçado. A janela de
/// 64 bits da máquina `virt` começa em 0x80_0000_0000, muito além do que cabe
/// num BAR de 32 bits.
///
/// # Safety
/// `prop` precisa ter vindo de um percurso do blob `dtb`.
unsafe fn ler_ranges(dtb: *const u8, prop: &Propriedade) -> Option<(u64, u64, u64)> {
    // Uma entrada é endereço-filho, endereço-pai e tamanho concatenados. As
    // larguras do filho o binding fixa; a do pai é a que a raiz declarou, e é
    // por isso que `Propriedade` carrega `address_cells`.
    // Mesma razão de `ler_reg`: a largura do pai vem do blob, e a conta é
    // feita em `usize` para não transbordar.
    let celulas_do_pai = prop.address_cells as usize;
    let largura = (CELULAS_DE_ENDERECO_PCI + celulas_do_pai + CELULAS_DE_TAMANHO_PCI) * 4;

    let mut deslocamento = 0usize;
    while deslocamento + largura <= prop.tamanho {
        let entrada = prop.dados + deslocamento;

        // SAFETY: delegada ao chamador; o laço confere que a entrada inteira
        // cabe no tamanho que o percurso reportou.
        let janela = unsafe {
            let alto = be32(dtb, entrada);
            if (alto >> 24) & 0b11 != ESPACO_DE_MEMORIA_32 {
                None
            } else {
                // As duas células baixas do endereço do filho formam o
                // endereço do lado do barramento; a alta só descreve o espaço.
                let no_barramento = ler_celulas(dtb, entrada + 4, 2);
                let na_cpu = ler_celulas(
                    dtb,
                    entrada + CELULAS_DE_ENDERECO_PCI * 4,
                    celulas_do_pai as u32,
                );
                let tamanho = ler_celulas(
                    dtb,
                    entrada + (CELULAS_DE_ENDERECO_PCI + celulas_do_pai) * 4,
                    CELULAS_DE_TAMANHO_PCI as u32,
                );
                Some((no_barramento, na_cpu, tamanho))
            }
        };

        if janela.is_some() {
            return janela;
        }
        deslocamento += largura;
    }

    None
}

/// Acha o nó do host bridge PCI e devolve a numeração dele no percurso.
///
/// Procuramos pelo `compatible`, e não pelo nome do nó, porque o nome carrega
/// o endereço (`pcie@10000000`) e compará-lo seria fixar o endereço por outro
/// caminho.
///
/// A closure fica fora da chamada de propósito. Aninhá-la dentro de um bloco
/// `unsafe` faria o corpo dela herdar esse bloco, e cada desreferência lá
/// dentro deixaria de ser marcada — o `unsafe` viraria ruído em vez de
/// sinalização.
///
/// # Safety
/// `dtb` precisa apontar para um device tree válido, ou ser nulo.
unsafe fn no_do_host_bridge(dtb: *const u8) -> Option<u32> {
    let mut alvo: Option<u32> = None;
    let mut procurar = |prop: &Propriedade| {
        if alvo.is_some() || prop.profundidade != FILHO_DA_RAIZ || prop.nome != b"compatible" {
            return;
        }
        // `compatible` é uma lista de strings terminadas em zero, da mais
        // específica para a mais genérica.
        // SAFETY: o percurso garantiu que a faixa está dentro do blob.
        let lista = unsafe { core::slice::from_raw_parts(dtb.add(prop.dados), prop.tamanho) };
        if lista
            .split(|&b| b == 0)
            .any(|s| s == b"pci-host-ecam-generic")
        {
            alvo = Some(prop.no_seq);
        }
    };

    // SAFETY: delegada ao chamador.
    let _ = unsafe { percorrer(dtb, &mut procurar) };
    alvo
}

/// Descreve o barramento PCI desta placa, lendo o device tree.
///
/// # Por que perguntar em vez de fixar
///
/// O endereço do ECAM e o das janelas são escolha da placa, não da
/// arquitetura. A máquina `virt` do QEMU os coloca num lugar, uma placa real
/// noutro, e uma versão futura do QEMU pode mudá-los — foi para não depender
/// disso que este kernel lê o device tree desde o começo.
///
/// Procuramos pelo `compatible`, e não pelo nome do nó, porque o nome carrega
/// o endereço (`pcie@10000000`) e compará-lo seria fixar o endereço por outro
/// caminho.
///
/// # Por que duas passadas
///
/// Porque a especificação não ordena as propriedades dentro de um nó, e o
/// QEMU de fato emite `reg` e `ranges` **antes** de `compatible`. Uma versão
/// anterior disto tentava resolver isso lembrando o último `reg` visto; com
/// duas propriedades para recolher, essa contabilidade vira o tipo de código
/// em que um erro não aparece — ele só devolve a janela do nó errado.
///
/// A primeira passada descobre **qual** nó é o host bridge; a segunda lê as
/// propriedades dele. Percorrer o blob duas vezes custa alguns microssegundos
/// uma vez no boot, e a busca deixa de depender da ordem.
///
/// # Safety
///
/// `dtb` precisa apontar para um device tree válido, ou ser nulo.
pub unsafe fn encontrar_barramento_pci(dtb: *const u8) -> Option<BarramentoPci> {
    // SAFETY: delegada ao chamador.
    let alvo = unsafe { no_do_host_bridge(dtb)? };
    let mut ecam: Option<(u64, u64)> = None;
    let mut mmio32: Option<(u64, u64, u64)> = None;

    let mut ler_o_no = |prop: &Propriedade| {
        if prop.no_seq != alvo {
            return;
        }
        match prop.nome {
            // O `reg` de um host bridge ECAM é a janela de configuração. Só a
            // primeira entrada interessa.
            // SAFETY: `prop` veio do percurso deste mesmo blob.
            b"reg" => unsafe {
                ler_reg(dtb, prop, |inicio, tamanho| {
                    ecam.get_or_insert((inicio, tamanho));
                });
            },
            // SAFETY: mesma justificativa.
            b"ranges" => mmio32 = unsafe { ler_ranges(dtb, prop) },
            _ => {}
        }
    };

    // SAFETY: delegada ao chamador.
    let _ = unsafe { percorrer(dtb, &mut ler_o_no) };

    Some(BarramentoPci {
        ecam: ecam?,
        mmio32,
    })
}

// ---------------------------------------------------------------------------
// Roteamento de interrupção
// ---------------------------------------------------------------------------

/// Uma interrupção, como o controlador que a atende a descreve.
///
/// Os três campos são o especificador de um GIC: que classe de linha é, qual
/// o número dentro dela, e como o sinal se comporta. Quem os traduz em INTID
/// é [`super::gic`] — este arquivo lê o device tree e não sabe o que os
/// números significam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupcao {
    pub tipo: u32,
    pub numero: u32,
    pub flags: u32,
}

/// Quantas células um nó declara para os filhos dele.
#[derive(Clone, Copy)]
struct Larguras {
    endereco: u32,
    interrupcao: u32,
}

/// Quantas células um `phandle` declara, para endereço e para interrupção.
///
/// # Por que resolver em vez de fixar
///
/// Porque é o que determina o **tamanho de cada entrada** da `interrupt-map`,
/// e errar o tamanho não produz erro: produz uma leitura deslocada, que
/// devolve um número de linha plausível e errado. O kernel habilitaria a
/// interrupção de outro dispositivo e esperaria para sempre pela sua.
///
/// Na máquina `virt` o controlador declara duas células de endereço e três de
/// interrupção — dez células por entrada, contando as quatro do lado do
/// filho. Nada disso é fixo pela arquitetura.
///
/// # Safety
/// `dtb` precisa apontar para um device tree válido, ou ser nulo.
unsafe fn larguras_do_phandle(dtb: *const u8, phandle: u32) -> Option<Larguras> {
    // Primeira passada: qual nó tem este `phandle`.
    let mut alvo: Option<u32> = None;
    let mut procurar = |prop: &Propriedade| {
        if alvo.is_some() || prop.nome != b"phandle" || prop.tamanho < 4 {
            return;
        }
        // SAFETY: o percurso garantiu que `dados` está dentro do blob e que
        // há ao menos quatro bytes.
        if unsafe { be32(dtb, prop.dados) } == phandle {
            alvo = Some(prop.no_seq);
        }
    };
    // SAFETY: delegada ao chamador.
    let _ = unsafe { percorrer(dtb, &mut procurar) };
    let alvo = alvo?;

    // Segunda passada: as larguras que ele declara.
    //
    // Um controlador que não declare `#address-cells` não tem endereço do
    // lado dele nas entradas, e zero é a resposta certa — diferente do padrão
    // de dois que a especificação manda usar na raiz. Já `#interrupt-cells`
    // é obrigatório num controlador de interrupção, e a ausência dele é um
    // blob malformado, não um caso a adivinhar.
    let mut endereco = 0u32;
    let mut interrupcao: Option<u32> = None;
    let mut ler = |prop: &Propriedade| {
        if prop.no_seq != alvo || prop.tamanho < 4 {
            return;
        }
        // SAFETY: mesma justificativa.
        let valor = unsafe { be32(dtb, prop.dados) };
        if valor > MAX_CELULAS {
            // Um controlador que declare larguras absurdas não é um
            // controlador que este leitor saiba ler. Recusar aqui faz a busca
            // devolver `None`, e o kernel segue sem interrupção de PCI — em
            // vez de calcular um tamanho de entrada que percorreria a tabela
            // errada.
            return;
        }
        if prop.nome == b"#address-cells" {
            endereco = valor;
        } else if prop.nome == b"#interrupt-cells" {
            interrupcao = Some(valor);
        }
    };
    // SAFETY: delegada ao chamador.
    let _ = unsafe { percorrer(dtb, &mut ler) };

    Some(Larguras {
        endereco,
        interrupcao: interrupcao?,
    })
}

/// Descobre em que linha do controlador um dispositivo PCI interrompe.
///
/// # Como a `interrupt-map` funciona
///
/// É uma tabela de tradução, e não uma fórmula. Cada entrada diz "um
/// dispositivo *assim*, no pino *tal*, chega no controlador *aquele*, na
/// linha *tal*". O "assim" é comparado depois de passar por uma máscara que a
/// própria placa declara — na `virt`, ela deixa passar só dois bits do número
/// do slot e três do pino.
///
/// A máquina `virt` embaralha as linhas entre os slots: o slot 0 no pino 1
/// cai na SPI 3, o slot 1 no mesmo pino cai na 4, e assim por diante. É um
/// arranjo deliberado, para que quatro placas de expansão não disputem todas
/// a mesma linha. Reproduzir esse embaralhamento em código seria copiar uma
/// decisão de layout de placa para dentro do kernel; ler a tabela é o que
/// funciona também na placa seguinte.
///
/// `endereco_alto` é a primeira célula do endereço PCI do dispositivo — a que
/// carrega barramento, slot e função.
///
/// # Safety
/// `dtb` precisa apontar para um device tree válido, ou ser nulo.
pub unsafe fn interrupcao_pci(dtb: *const u8, endereco_alto: u32, pino: u8) -> Option<Interrupcao> {
    let alvo = unsafe { no_do_host_bridge(dtb)? };

    // Recolhemos as duas propriedades numa passada; qual vem primeiro no blob
    // não está especificado, e já houve um bug aqui por supor uma ordem.
    let mut mascara: Option<(usize, usize)> = None;
    let mut mapa: Option<(usize, usize)> = None;
    let mut ler = |prop: &Propriedade| {
        if prop.no_seq != alvo {
            return;
        }
        if prop.nome == b"interrupt-map-mask" {
            mascara = Some((prop.dados, prop.tamanho));
        } else if prop.nome == b"interrupt-map" {
            mapa = Some((prop.dados, prop.tamanho));
        }
    };
    // SAFETY: delegada ao chamador.
    let _ = unsafe { percorrer(dtb, &mut ler) };

    let (mascara_em, mascara_bytes) = mascara?;
    let (mapa_em, mapa_bytes) = mapa?;

    // A máscara cobre o endereço do filho e o pino: as mesmas larguras que o
    // binding PCI fixa, mais uma célula de interrupção.
    const CELULAS_DE_INTERRUPCAO_PCI: usize = 1;
    let celulas_do_filho = CELULAS_DE_ENDERECO_PCI + CELULAS_DE_INTERRUPCAO_PCI;
    if mascara_bytes < celulas_do_filho * 4 {
        return None;
    }

    // SAFETY: o percurso garantiu que a faixa está no blob, e o tamanho foi
    // conferido acima.
    let (mascara_alto, mascara_do_pino) = unsafe {
        (
            be32(dtb, mascara_em),
            be32(dtb, mascara_em + CELULAS_DE_ENDERECO_PCI * 4),
        )
    };

    // O phandle do controlador está na entrada, logo depois do pino. Ele é o
    // mesmo em todas — o que varia é a linha —, então lemos o da primeira
    // para descobrir o tamanho das demais.
    if mapa_bytes < (celulas_do_filho + 1) * 4 {
        return None;
    }
    // SAFETY: mesma justificativa.
    let phandle = unsafe { be32(dtb, mapa_em + celulas_do_filho * 4) };
    // SAFETY: delegada ao chamador.
    let larguras = unsafe { larguras_do_phandle(dtb, phandle)? };

    let por_entrada =
        celulas_do_filho + 1 + larguras.endereco as usize + larguras.interrupcao as usize;
    if larguras.interrupcao < 3 {
        // Um especificador com menos de três células não é o de um GIC, e
        // interpretá-lo como se fosse leria campos que não existem.
        return None;
    }

    let procurado_alto = endereco_alto & mascara_alto;
    let procurado_pino = pino as u32 & mascara_do_pino;

    let mut deslocamento = 0usize;
    while deslocamento + por_entrada * 4 <= mapa_bytes {
        let entrada = mapa_em + deslocamento;

        // SAFETY: o laço confere que a entrada inteira cabe no tamanho que o
        // percurso reportou.
        let combina = unsafe {
            be32(dtb, entrada) & mascara_alto == procurado_alto
                && be32(dtb, entrada + CELULAS_DE_ENDERECO_PCI * 4) & mascara_do_pino
                    == procurado_pino
        };

        if combina {
            // O especificador do pai vem depois do phandle e do endereço do
            // lado dele. As três primeiras células são as do GIC.
            let em = entrada + (celulas_do_filho + 1 + larguras.endereco as usize) * 4;
            // SAFETY: mesma justificativa do laço.
            return Some(unsafe {
                Interrupcao {
                    tipo: be32(dtb, em),
                    numero: be32(dtb, em + 4),
                    flags: be32(dtb, em + 8),
                }
            });
        }

        deslocamento += por_entrada * 4;
    }

    None
}
