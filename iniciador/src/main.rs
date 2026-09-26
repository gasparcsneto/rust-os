//! # Iniciador — a aplicação UEFI que põe o Duke de pé
//!
//! Até aqui o x86 do Duke bootava pelo crate `bootloader`: um programa de
//! outra pessoa fazia a transição para long mode, montava as tabelas de
//! página iniciais e entregava ao kernel uma `BootInfo` pronta. Funcionava, e
//! escondia exatamente a parte que um kernel escrito do zero deveria mostrar.
//!
//! Este programa é o substituto. Ele é uma **aplicação UEFI**: o firmware o
//! carrega da partição de sistema do disco — a mesma ESP que o `xtask` já
//! monta — e o executa em long mode, com paginação identidade e os serviços
//! de boot disponíveis.
//!
//! ## O que ele faz nesta etapa, e o que ainda não faz
//!
//! Ele **lê a máquina e relata**: confere as três tabelas da UEFI, imprime o
//! firmware que o carregou, conta o mapa de memória e descreve o vídeo. Não
//! carrega o kernel, não monta tabela de página nenhuma e não sai dos
//! serviços de boot — desliga a máquina no fim.
//!
//! O corte é deliberado, e é o mesmo método que o xHCI e o Btrfs seguiram
//! neste projeto: cada etapa é confirmada por um relatório antes de a
//! seguinte ser escrita. Num bootloader isso vale dobrado, porque um erro
//! aqui não produz um teste vermelho — produz uma máquina que não liga, sem
//! nada na tela e sem ninguém para perguntar.
//!
//! ## Por que o relatório sai pela serial, e não pelo console do firmware
//!
//! Ver [`serial`]. Em resumo: o console é um serviço de boot, e o trabalho
//! deste programa termina depois de `ExitBootServices`.

#![no_std]
#![no_main]

mod carga;
mod crc32;
mod efi;
mod elf;
mod mapa;
mod paginas;
mod serial;

use core::fmt::Write;
use core::panic::PanicInfo;

/// Quanto um cabeçalho de tabela pode declarar de tamanho e ainda ser
/// plausível.
///
/// Um teto explícito porque o `tamanho` vem da memória apontada por um
/// ponteiro que ainda não foi validado: se ele estiver errado, o número é
/// lixo, e calcular o CRC de quatro gigabytes de "tabela" é o primeiro
/// travamento do boot.
const MAIOR_TABELA: u32 = 4096;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(imagem: efi::Handle, sistema: *mut efi::Sistema) -> efi::Status {
    serial::init();
    relatar!("vivo, carregado pelo firmware");

    match relatorio(imagem, sistema) {
        Ok(()) => relatar!("fim do relatorio"),
        Err(motivo) => relatar!("ERRO {}", motivo),
    }

    desligar(sistema)
}

/// Confere o que o firmware entregou e descreve a máquina.
fn relatorio(imagem: efi::Handle, sistema: *mut efi::Sistema) -> Result<(), &'static str> {
    if sistema.is_null() {
        return Err("a tabela do sistema veio nula");
    }
    // SAFETY: o ponteiro veio do firmware no segundo argumento de `efi_main`,
    // que é o contrato da UEFI, e acabou de ser conferido contra nulo. A
    // validade do *conteúdo* é o que as conferências abaixo estabelecem.
    let sistema = unsafe { &*sistema };

    conferir_cabecalho(
        &sistema.cabecalho,
        efi::ASSINATURA_DO_SISTEMA,
        "a tabela do sistema",
    )?;
    relatar!(
        "tabela do sistema confere: uefi {}.{}, {} bytes",
        sistema.cabecalho.revisao >> 16,
        sistema.cabecalho.revisao & 0xFFFF,
        sistema.cabecalho.tamanho
    );

    // O nome do firmware é a primeira prova de que os deslocamentos batem:
    // ele é um ponteiro logo depois do cabeçalho, e lê-lo errado dá lixo em
    // vez de um nome.
    let mut linha = Linha::nova();
    let _ = write!(linha, "firmware `");
    escrever_utf16(&mut linha, sistema.fabricante);
    let _ = write!(linha, "` revisao {:#x}", sistema.revisao_do_firmware);
    relatar!("{}", linha.como_str());

    let boot = sistema.boot;
    if boot.is_null() {
        return Err("os servicos de boot vieram nulos");
    }
    // SAFETY: o ponteiro está na tabela que acabou de passar no CRC, e o
    // cabeçalho apontado é conferido logo abaixo antes de qualquer função ser
    // chamada.
    let boot = unsafe { &*boot };
    conferir_cabecalho(
        &boot.cabecalho,
        efi::ASSINATURA_DOS_SERVICOS_DE_BOOT,
        "os servicos de boot",
    )?;

    // SAFETY: mesma justificativa do anterior.
    let execucao =
        unsafe { sistema.execucao.as_ref() }.ok_or("os servicos de execucao vieram nulos")?;
    conferir_cabecalho(
        &execucao.cabecalho,
        efi::ASSINATURA_DOS_SERVICOS_DE_EXECUCAO,
        "os servicos de execucao",
    )?;
    relatar!("as tres tabelas conferem, por assinatura e por crc");

    let fim_da_ram = descrever_memoria(boot)?;
    let video = descrever_video(boot)?;
    descrever_kernel(imagem, boot, fim_da_ram, video)?;
    Ok(())
}

/// Confere assinatura, tamanho e CRC-32 de um cabeçalho de tabela.
///
/// # Por que o CRC é recalculado com o campo dele zerado
///
/// Porque é assim que o firmware o calculou: o campo não pode entrar na
/// própria soma. A UEFI manda zerá-lo, somar a tabela inteira e escrever o
/// resultado no lugar — então conferir é refazer exatamente isso.
fn conferir_cabecalho(
    cabecalho: &efi::Cabecalho,
    assinatura: u64,
    quem: &'static str,
) -> Result<(), &'static str> {
    if cabecalho.assinatura != assinatura {
        relatar!(
            "ERRO {} tem assinatura {:#018x}, esperava {:#018x}",
            quem,
            cabecalho.assinatura,
            assinatura
        );
        return Err("assinatura de tabela errada");
    }

    let tamanho = cabecalho.tamanho;
    if (tamanho as usize) < size_of::<efi::Cabecalho>() || tamanho > MAIOR_TABELA {
        return Err("tabela com tamanho implausivel");
    }

    // A tabela inteira, como bytes. O cabeçalho é o começo dela.
    //
    // SAFETY: o firmware declarou este tamanho no próprio cabeçalho, e o teto
    // acima impede que um número absurdo vire uma leitura de gigabytes. Se o
    // tamanho estiver errado mas plausível, o CRC é justamente o que denuncia.
    let bytes = unsafe {
        core::slice::from_raw_parts(cabecalho as *const _ as *const u8, tamanho as usize)
    };

    // O campo do CRC ocupa os bytes 16..20 do cabeçalho, e entra na conta como
    // zeros. Somar em três pedaços evita copiar a tabela para um buffer que
    // este programa ainda não tem como alocar.
    const EM: usize = 16;
    let mut soma = crc32::Parcial::nova();
    soma.somar(&bytes[..EM]);
    soma.somar(&[0, 0, 0, 0]);
    soma.somar(&bytes[EM + 4..]);

    if soma.terminar() != cabecalho.crc32 {
        relatar!(
            "ERRO {}: crc {:#010x}, calculado {:#010x}",
            quem,
            cabecalho.crc32,
            soma.terminar()
        );
        return Err("crc de tabela nao confere");
    }
    Ok(())
}

/// Pede o mapa de memória e conta o que há nele.
///
/// # A dança das duas chamadas
///
/// `GetMemoryMap` não diz de que tamanho é o mapa: ele **recusa** um buffer
/// pequeno e devolve o tamanho necessário no mesmo argumento. Então a
/// primeira chamada é feita para falhar.
///
/// E o buffer precisa de folga. Alocá-lo é um evento de memória, que pode
/// partir uma região livre em duas e fazer o mapa crescer entre a pergunta e
/// a resposta. Duas regiões de sobra cobrem isso com margem.
fn descrever_memoria(boot: &efi::ServicosDeBoot) -> Result<u64, &'static str> {
    let mut tamanho = 0usize;
    let mut chave = 0usize;
    let mut por_descritor = 0usize;
    let mut versao = 0u32;

    // SAFETY: os cinco ponteiros são para variáveis locais desta função, e o
    // buffer nulo com tamanho zero é a forma documentada de perguntar o
    // tamanho.
    let status = unsafe {
        (boot.mapa_de_memoria)(
            &mut tamanho,
            core::ptr::null_mut(),
            &mut chave,
            &mut por_descritor,
            &mut versao,
        )
    };
    if status != efi::BUFFER_PEQUENO {
        relatar!("ERRO a sondagem do mapa devolveu {:#x}", status);
        return Err("o mapa de memoria nao respondeu como esperado");
    }
    if por_descritor < size_of::<efi::Descritor>() {
        return Err("o firmware declarou descritores menores que o formato");
    }

    let folga = 2 * por_descritor;
    let tamanho_pedido = tamanho + folga;
    let mut buffer: *mut u8 = core::ptr::null_mut();
    // SAFETY: o tipo é o dos dados desta aplicação, e `buffer` é uma variável
    // local que recebe o ponteiro.
    let status = unsafe {
        (boot.alocar_pool)(
            efi::memoria::DADOS_DO_CARREGADOR,
            tamanho_pedido,
            &mut buffer,
        )
    };
    if efi::deu_errado(status) || buffer.is_null() {
        return Err("o firmware recusou alocar o buffer do mapa");
    }

    let mut tamanho = tamanho_pedido;
    // SAFETY: o buffer tem `tamanho_pedido` bytes, que é o que dizemos ao
    // firmware no primeiro argumento.
    let status = unsafe {
        (boot.mapa_de_memoria)(
            &mut tamanho,
            buffer,
            &mut chave,
            &mut por_descritor,
            &mut versao,
        )
    };
    if efi::deu_errado(status) {
        // SAFETY: o buffer veio do `alocar_pool` acima e ninguém mais o tem.
        unsafe { (boot.liberar_pool)(buffer) };
        relatar!("ERRO o mapa de memoria devolveu {:#x}", status);
        return Err("o firmware recusou entregar o mapa");
    }

    let quantos = tamanho / por_descritor;
    let mut paginas_livres = 0u64;
    let mut paginas_descritas = 0u64;
    let mut paginas_do_iniciador = 0u64;
    let mut maior = 0u64;
    let mut fim_da_ram = 0u64;

    for i in 0..quantos {
        // SAFETY: o passo é o que o firmware declarou, e `quantos` vem da
        // divisão do tamanho que ele devolveu por esse mesmo passo — então
        // nenhum descritor sai do buffer. Uma leitura não alinhada é possível
        // em teoria, e por isso é `read_unaligned`.
        let d = unsafe {
            core::ptr::read_unaligned(buffer.add(i * por_descritor) as *const efi::Descritor)
        };
        paginas_descritas += d.paginas;

        // Livre para o kernel é o que a UEFI chama de convencional mais o que
        // ela mesma devolve quando os serviços de boot saem de cena. O código
        // e os dados do iniciador **não** entram: ainda estamos rodando neles.
        let livre = matches!(
            d.tipo,
            efi::memoria::CONVENCIONAL | efi::memoria::CODIGO_DE_BOOT | efi::memoria::DADOS_DE_BOOT
        );
        if livre {
            paginas_livres += d.paginas;
            if d.paginas > maior {
                maior = d.paginas;
            }
        }

        // Até onde vai a RAM, para o mapa da memória física saber o que
        // cobrir. Só o que é memória de verdade entra: os descritores também
        // descrevem blocos de dispositivo, e mapear doze gibibytes de buraco
        // de PCI custaria tabelas para um espaço que o kernel não lê.
        if e_memoria(d.tipo) {
            fim_da_ram = fim_da_ram.max(d.fisico + d.paginas * efi::PAGINA);
        }

        // O que este programa ocupa. Sai no relatório porque é o que o kernel
        // vai poder recuperar depois de assumir a máquina — e porque um
        // número que cresce entre uma etapa e a seguinte é a forma mais
        // direta de ver o iniciador engordando.
        if matches!(
            d.tipo,
            efi::memoria::CODIGO_DO_CARREGADOR | efi::memoria::DADOS_DO_CARREGADOR
        ) {
            paginas_do_iniciador += d.paginas;
        }
    }

    // SAFETY: o buffer veio do `alocar_pool` acima, já foi lido, e ninguém
    // mais tem o ponteiro.
    unsafe { (boot.liberar_pool)(buffer) };

    let mib = |paginas: u64| paginas * efi::PAGINA / (1024 * 1024);
    relatar!(
        "memoria: {} descritores de {} bytes, {} MiB descritos, {} MiB livres, maior faixa {} MiB",
        quantos,
        por_descritor,
        mib(paginas_descritas),
        mib(paginas_livres),
        mib(maior)
    );
    relatar!(
        "o iniciador ocupa {} KiB em {} paginas, e a RAM vai ate {:#x}",
        paginas_do_iniciador * efi::PAGINA / 1024,
        paginas_do_iniciador,
        fim_da_ram
    );
    Ok(fim_da_ram)
}

/// Se um tipo de memória descreve RAM de verdade.
///
/// Tudo que não é um bloco de dispositivo nem espaço reservado pelo firmware
/// para hardware. O código e os dados do firmware entram: eles ocupam RAM, e
/// o kernel precisa alcançá-los pelo mapa da memória física mesmo sem poder
/// usá-los.
fn e_memoria(tipo: u32) -> bool {
    !matches!(
        tipo,
        efi::memoria::MAPEADA_EM_MEMORIA | efi::memoria::PORTA_MAPEADA | efi::memoria::RESERVADA
    )
}

/// Localiza o protocolo de vídeo e descreve o que ele oferece.
///
/// Sem vídeo o relatório segue: uma máquina headless é uma máquina, e o Duke
/// já sabe funcionar sem tela. O que não pode é a ausência passar calada.
fn descrever_video(boot: &efi::ServicosDeBoot) -> Result<Option<carga::Video>, &'static str> {
    let mut video: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: o GUID é uma constante nossa, o registro nulo é a forma
    // documentada de pedir a primeira instância, e o destino é uma local.
    let status = unsafe {
        (boot.localizar_protocolo)(&efi::GUID_DO_VIDEO, core::ptr::null_mut(), &mut video)
    };
    if efi::deu_errado(status) || video.is_null() {
        relatar!("video: nenhum (o firmware devolveu {:#x})", status);
        return Ok(None);
    }

    // SAFETY: o firmware devolveu este ponteiro para o GUID do protocolo de
    // vídeo, e é o contrato dele que ele aponte para essa estrutura.
    let video = unsafe { &*(video as *const efi::Video) };
    // SAFETY: `modo` é parte do protocolo e o firmware o mantém válido
    // enquanto os serviços de boot existirem.
    let modo = unsafe { video.modo.as_ref() }.ok_or("o protocolo de video veio sem modo")?;
    // SAFETY: idem.
    let info = unsafe { modo.informacao.as_ref() }.ok_or("o modo de video veio sem informacao")?;

    let formato = match info.formato {
        efi::formato::RGB => "rgb",
        efi::formato::BGR => "bgr",
        efi::formato::MASCARAS => "mascaras",
        efi::formato::SO_TRANSFERENCIA => "so-transferencia",
        _ => "desconhecido",
    };

    relatar!(
        "video: {}x{} {}, {} pixels por linha, buffer em {:#x} com {} KiB, modo {} de {}",
        info.largura,
        info.altura,
        formato,
        info.pixels_por_linha,
        modo.buffer,
        modo.tamanho_do_buffer / 1024,
        modo.modo_atual,
        modo.quantos_modos
    );

    // Um formato que este kernel não sabe desenhar não impede o boot: ele já
    // sabe funcionar sem tela. O que não pode é o iniciador mapear um
    // framebuffer e o kernel escrever nele achando que é outra coisa.
    if info.formato != efi::formato::RGB && info.formato != efi::formato::BGR {
        relatar!("video: formato que o kernel nao desenha; seguindo sem tela");
        return Ok(None);
    }

    Ok(Some(carga::Video {
        fisico: modo.buffer,
        bytes: modo.tamanho_do_buffer as u64,
    }))
}

/// Onde o kernel mora na partição de sistema.
///
/// Na raiz da ESP e com nome curto, porque o caminho é escrito em UTF-16
/// literal aqui embaixo e cada caractere é uma unidade a mais para conferir.
/// Um layout mais arrumado — `\EFI\duke\kernel.elf` — não compra nada
/// enquanto houver um kernel só.
const CAMINHO_DO_KERNEL: &[u16] = &[
    b'd' as u16,
    b'u' as u16,
    b'k' as u16,
    b'e' as u16,
    b'.' as u16,
    b'e' as u16,
    b'l' as u16,
    b'f' as u16,
    0,
];

/// Quanto o iniciador pede ao firmware por chamada de leitura.
///
/// Sessenta e quatro kibibytes. Ver o laço de leitura em [`ler_o_kernel`]
/// sobre por que a leitura é pedida em pedaços em vez de de uma vez só.
const PEDACO_DA_LEITURA: usize = 64 * 1024;

/// Maior kernel que o iniciador aceita ler.
///
/// Trinta e dois mebibytes. O kernel de depuração, com símbolos, tem sete —
/// e o teto existe porque o tamanho vem do disco: um número absurdo viraria
/// um pedido de alocação absurdo, e o firmware o recusaria com uma mensagem
/// que não diz o que aconteceu.
const MAIOR_KERNEL: u64 = 32 * 1024 * 1024;

/// Segue a corrente até o arquivo do kernel, lê, e descreve o que leu.
///
/// # Por que pelo dispositivo desta imagem, e não por um volume qualquer
///
/// Porque "a ESP" não é uma coisa só. Numa máquina com dois discos
/// bootáveis há duas, e carregar o kernel da errada é carregar o kernel de
/// outra instalação — com o iniciador de uma e o sistema de outra.
///
/// O firmware não diz "aqui está o seu disco". Ele diz qual **imagem** está
/// rodando; a imagem sabe de qual **dispositivo** veio; e o dispositivo
/// oferece o **sistema de arquivos**. Os três elos são o que amarra o kernel
/// ao iniciador que o carregou.
fn descrever_kernel(
    imagem: efi::Handle,
    boot: &efi::ServicosDeBoot,
    fim_da_ram: u64,
    video: Option<carga::Video>,
) -> Result<(), &'static str> {
    let bytes = ler_o_kernel(imagem, boot)?;
    let imagem = elf::Imagem::abrir(bytes)?;

    if imagem.maquina != elf::MAQUINA_X86_64 {
        relatar!("ERRO o kernel e para a maquina {:#x}", imagem.maquina);
        return Err("o kernel nao e desta arquitetura");
    }

    relatar!(
        "elf: {} bytes, entrada em {:#x}, {}",
        bytes.len(),
        imagem.entrada,
        if imagem.independente_de_posicao {
            "independente de posicao"
        } else {
            "endereco fixo"
        }
    );

    let mut quantos = 0;
    let mut menor = u64::MAX;
    let mut maior = 0u64;
    let mut do_arquivo = 0u64;
    let mut na_memoria = 0u64;

    for segmento in imagem.segmentos() {
        let s = segmento?;
        quantos += 1;
        menor = menor.min(s.endereco);
        maior = maior.max(s.endereco.saturating_add(s.tamanho_na_memoria));
        do_arquivo += s.tamanho_no_arquivo;
        na_memoria += s.tamanho_na_memoria;

        let mut bits = [b'-'; 3];
        if s.permissoes & elf::permissao::LER != 0 {
            bits[0] = b'r';
        }
        if s.permissoes & elf::permissao::ESCREVER != 0 {
            bits[1] = b'w';
        }
        if s.permissoes & elf::permissao::EXECUTAR != 0 {
            bits[2] = b'x';
        }
        let bits = core::str::from_utf8(&bits).unwrap_or("???");

        relatar!(
            "segmento {} em {:#x}: {} do arquivo, {} na memoria ({} zeros), {}, alinhado a {}",
            quantos,
            s.endereco,
            s.tamanho_no_arquivo,
            s.tamanho_na_memoria,
            s.zeros(),
            bits,
            s.alinhamento
        );
    }

    if quantos == 0 {
        return Err("o kernel nao tem segmento nenhum para carregar");
    }

    // A entrada tem de cair dentro do que vai ser carregado. Um `e_entry`
    // fora dos segmentos é um salto para memória que ninguém mapeou — e é o
    // que acontece quando o arquivo na ESP é de outro build.
    if imagem.entrada < menor || imagem.entrada >= maior {
        relatar!(
            "ERRO a entrada {:#x} esta fora dos segmentos {:#x}..{:#x}",
            imagem.entrada,
            menor,
            maior
        );
        return Err("a entrada do kernel nao cai em segmento nenhum");
    }

    relatar!(
        "kernel: {} segmentos, {:#x}..{:#x}, {} KiB do arquivo, {} KiB na memoria",
        quantos,
        menor,
        maior,
        do_arquivo / 1024,
        na_memoria / 1024
    );

    // O bit que torna o 63 das entradas significativo, antes de qualquer
    // tabela ser escrita com ele.
    paginas::ligar_nx();

    let carga = carga::carregar(boot, &imagem, fim_da_ram, video)?;
    relatar!(
        "carga: imagem em {:#x} fisico, {} KiB, {} bytes de bss zerados, {} relocacoes aplicadas",
        carga.base_fisica,
        carga.bytes / 1024,
        carga.zerados,
        carga.relocacoes
    );
    relatar!(
        "mapa: {} paginas de tabela, raiz em {:#x}",
        carga.tabelas.paginas_usadas(),
        carga.tabelas.raiz()
    );

    conferir_o_mapa(&carga, &imagem)?;
    Ok(())
}

/// Percorre o mapa recém-montado e confere onde cada região caiu.
///
/// # Por que conferir, se acabamos de montar
///
/// Porque este é o **último** ponto em que dá para dizer alguma coisa. Depois
/// do `mov cr3` não há relatório: ou a máquina segue, ou ela reinicia sem
/// nada na tela e sem ninguém para perguntar.
///
/// E porque a leitura é independente da escrita. O
/// [`traduzir`](paginas::Tabelas::traduzir) desce pelos índices do endereço,
/// como o processador faria, em vez de consultar uma lista do que foi
/// mapeado — uma lista concordaria com quem a preencheu.
fn conferir_o_mapa(carga: &carga::Carga, imagem: &elf::Imagem) -> Result<(), &'static str> {
    let tabelas = &carga.tabelas;

    // A base do kernel precisa cair exatamente onde a imagem foi posta.
    let base = mapa::BASE_DO_KERNEL + carga.menor;
    match tabelas.traduzir(base) {
        Some(fisico) if fisico == carga.base_fisica => {}
        outro => {
            relatar!(
                "ERRO {:#x} traduz para {:?}, esperava {:#x}",
                base,
                outro,
                carga.base_fisica
            );
            return Err("o kernel nao esta mapeado onde foi carregado");
        }
    }

    // E a entrada também, já contando o deslocamento dentro da imagem.
    let esperado = carga.base_fisica + (carga.entrada - mapa::BASE_DO_KERNEL - carga.menor);
    match tabelas.traduzir(carga.entrada) {
        Some(fisico) if fisico == esperado => {}
        outro => {
            relatar!(
                "ERRO a entrada traduz para {:?}, esperava {:#x}",
                outro,
                esperado
            );
            return Err("o ponto de entrada nao esta mapeado onde devia");
        }
    }

    // O byte que está na entrada, lido pelo mapa novo, tem de ser o mesmo que
    // está no arquivo. É o que distingue "mapeado em algum lugar" de
    // "mapeado no kernel": um mapa que apontasse para outra página daria um
    // endereço plausível e bytes de outra coisa.
    //
    // A relocação não toca no código executável, então os bytes da entrada
    // no arquivo e na memória são os mesmos.
    let em = imagem
        .no_arquivo(carga.entrada - mapa::BASE_DO_KERNEL)?
        .ok_or("a entrada do kernel nao vem do arquivo")?;
    let no_arquivo = imagem.byte(em)?;
    // SAFETY: `esperado` é físico, e a UEFI ainda mapeia a memória por
    // identidade — a tradução acima acabou de confirmar que a página está no
    // mapa novo, e esta leitura usa o mapa atual sobre o mesmo endereço.
    let na_memoria = unsafe { core::ptr::read_volatile(esperado as *const u8) };
    if no_arquivo != na_memoria {
        relatar!(
            "ERRO na entrada ha {:#04x}, e o arquivo tem {:#04x}",
            na_memoria,
            no_arquivo
        );
        return Err("os bytes da entrada nao sao os do arquivo");
    }

    // A memória física, pelo deslocamento do kernel.
    if tabelas.traduzir(mapa::BASE_DA_MEMORIA_FISICA) != Some(0) {
        return Err("o mapa da memoria fisica nao comeca no endereco zero");
    }

    // A identidade, que existe só para a troca de CR3 sobreviver. O endereço
    // conferido é o do próprio código que vai executar o `mov cr3`.
    let aqui = conferir_o_mapa as *const () as u64;
    if tabelas.traduzir(aqui) != Some(aqui) {
        relatar!(
            "ERRO o codigo do iniciador em {:#x} nao esta na identidade",
            aqui
        );
        return Err("a troca de tabelas nao sobreviveria ao proximo passo");
    }

    // A pilha: o topo não é mapeado (ele é o endereço logo acima), então
    // conferimos a última página dela e a guarda lá embaixo.
    if tabelas.traduzir(carga.topo_da_pilha - 1).is_none() {
        return Err("a pilha do kernel nao esta mapeada");
    }
    if tabelas.traduzir(mapa::PILHA_EM).is_some() {
        return Err("a pagina de guarda da pilha esta mapeada");
    }

    match carga.video {
        Some(em) => {
            if tabelas.traduzir(em).is_none() {
                return Err("o framebuffer nao esta mapeado");
            }
            relatar!("mapa confere: kernel, memoria fisica, identidade, pilha e video");
        }
        None => relatar!("mapa confere: kernel, memoria fisica, identidade e pilha"),
    }
    Ok(())
}

/// Abre o kernel na ESP desta imagem e o lê inteiro para a memória.
fn ler_o_kernel(
    imagem: efi::Handle,
    boot: &efi::ServicosDeBoot,
) -> Result<&'static [u8], &'static str> {
    // Elo 1: qual dispositivo carregou esta imagem.
    let mut carregada: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: o handle é o que o firmware passou em `efi_main`, o GUID é uma
    // constante nossa e o destino é uma local.
    let status =
        unsafe { (boot.protocolo_do_handle)(imagem, &efi::GUID_DA_IMAGEM, &mut carregada) };
    if efi::deu_errado(status) || carregada.is_null() {
        relatar!("ERRO a imagem carregada nao respondeu ({:#x})", status);
        return Err("o firmware nao descreveu a imagem em execucao");
    }
    // SAFETY: o firmware devolveu este ponteiro para o GUID do protocolo da
    // imagem carregada.
    let carregada = unsafe { &*(carregada as *const efi::ImagemCarregada) };

    // Elo 2: o sistema de arquivos daquele dispositivo.
    let mut volume: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: o handle veio do protocolo acima; o resto como antes.
    let status = unsafe {
        (boot.protocolo_do_handle)(
            carregada.dispositivo,
            &efi::GUID_DO_SISTEMA_DE_ARQUIVOS,
            &mut volume,
        )
    };
    if efi::deu_errado(status) || volume.is_null() {
        relatar!(
            "ERRO o dispositivo nao tem sistema de arquivos ({:#x})",
            status
        );
        return Err("o dispositivo de onde viemos nao e um volume");
    }
    let volume = volume as *mut efi::SistemaDeArquivos;

    // Elo 3: a raiz do volume, e o arquivo dentro dela.
    let mut raiz: *mut efi::Arquivo = core::ptr::null_mut();
    // SAFETY: o protocolo é o que o GUID pediu, e `raiz` é uma local.
    let status = unsafe { ((*volume).abrir_volume)(volume, &mut raiz) };
    if efi::deu_errado(status) || raiz.is_null() {
        return Err("nao foi possivel abrir a raiz da particao de sistema");
    }

    let mut arquivo: *mut efi::Arquivo = core::ptr::null_mut();
    // SAFETY: `raiz` é o diretório que o firmware acabou de abrir, e o
    // caminho é uma constante em UTF-16 terminada em zero.
    let status = unsafe {
        ((*raiz).abrir)(
            raiz,
            &mut arquivo,
            CAMINHO_DO_KERNEL.as_ptr(),
            efi::MODO_LEITURA,
            0,
        )
    };
    // SAFETY: a raiz não é mais necessária, aberta ou não o arquivo.
    unsafe { ((*raiz).fechar)(raiz) };
    if efi::deu_errado(status) || arquivo.is_null() {
        relatar!("ERRO `duke.elf` nao abriu na ESP ({:#x})", status);
        return Err("o kernel nao esta na particao de sistema");
    }

    // O tamanho, pelo fim: posicionar no fim, perguntar onde se está, voltar.
    let mut tamanho = 0u64;
    // SAFETY: `arquivo` está aberto e as três chamadas são do protocolo dele.
    let status = unsafe {
        let ao_fim = ((*arquivo).definir_posicao)(arquivo, efi::FIM_DO_ARQUIVO);
        let onde = ((*arquivo).posicao)(arquivo, &mut tamanho);
        let ao_comeco = ((*arquivo).definir_posicao)(arquivo, 0);
        if efi::deu_errado(ao_fim) {
            ao_fim
        } else if efi::deu_errado(onde) {
            onde
        } else {
            ao_comeco
        }
    };
    if efi::deu_errado(status) {
        return Err("nao foi possivel medir o kernel");
    }
    if tamanho == 0 || tamanho > MAIOR_KERNEL {
        relatar!("ERRO o kernel tem {} bytes", tamanho);
        return Err("o kernel tem tamanho implausivel");
    }

    // Páginas, e não pool: o kernel vai ficar na memória depois que os
    // serviços de boot saírem de cena, e o que o pool entrega o firmware
    // considera dele. É a mesma distinção que fará diferença na etapa em que
    // este buffer virar o kernel carregado.
    let paginas = tamanho.div_ceil(efi::PAGINA);
    let mut base = 0u64;
    // SAFETY: os tipos são os documentados e `base` é uma local que recebe o
    // endereço.
    let status = unsafe {
        (boot.alocar_paginas)(
            efi::ALOCAR_QUALQUER,
            efi::memoria::DADOS_DO_CARREGADOR,
            paginas as usize,
            &mut base,
        )
    };
    if efi::deu_errado(status) || base == 0 {
        relatar!(
            "ERRO o firmware recusou {} paginas ({:#x})",
            paginas,
            status
        );
        return Err("nao ha memoria para o kernel");
    }

    // SAFETY: o firmware acabou de reservar estas páginas para nós, e
    // `tamanho` cabe nelas por construção.
    let destino = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, tamanho as usize) };

    // A leitura pode voltar curta, como qualquer leitura. O laço é o que
    // separa "leu o kernel" de "leu o começo do kernel e acreditou".
    //
    // # Por que em pedaços, se o firmware entrega tudo de uma vez
    //
    // Porque com um pedido só o laço dá uma volta e nunca mais, e um laço que
    // não dá duas voltas não é um laço — é uma chamada com sintaxe de laço.
    // Foi medido: pedindo os sete mebibytes numa chamada, este firmware os
    // devolve inteiros, e trocar o laço por uma leitura só não muda nada.
    //
    // Pedindo em pedaços ele roda cento e oito vezes, e parar na primeira
    // deixa o arquivo truncado — que é o que o CRC do outro lado denuncia.
    // O custo de cento e oito idas ao firmware, num boot, é invisível.
    let mut lidos = 0usize;
    while lidos < destino.len() {
        let mut quanto = (destino.len() - lidos).min(PEDACO_DA_LEITURA);
        // SAFETY: `arquivo` está aberto, e o ponteiro aponta para dentro do
        // buffer que acabamos de reservar.
        let status =
            unsafe { ((*arquivo).ler)(arquivo, &mut quanto, destino.as_mut_ptr().add(lidos)) };
        if efi::deu_errado(status) {
            relatar!("ERRO a leitura do kernel devolveu {:#x}", status);
            return Err("o kernel nao pode ser lido inteiro");
        }
        if quanto == 0 {
            relatar!("ERRO o arquivo acabou em {} de {} bytes", lidos, tamanho);
            return Err("o kernel acabou antes do tamanho que ele mesmo declarou");
        }
        lidos += quanto;
    }

    // SAFETY: o arquivo foi lido e ninguém mais o tem.
    unsafe { ((*arquivo).fechar)(arquivo) };

    // O CRC dos bytes lidos, para que alguém de fora possa conferir.
    //
    // # Por que isto não é zelo excessivo
    //
    // Porque sem ele "leu o kernel" e "leu o começo do kernel" são
    // indistinguíveis daqui. O buffer tem o tamanho do arquivo aconteça o que
    // acontecer; uma leitura que voltasse curta deixaria o resto como o
    // firmware o entregou, e o cabeçalho ELF — que está nos primeiros
    // sessenta e quatro bytes — continuaria conferindo.
    //
    // O `xtask` calcula o mesmo CRC sobre o mesmo arquivo, no hospedeiro, e
    // compara. É a ponta de fora que transforma a leitura numa afirmação.
    let mut soma = crc32::Parcial::nova();
    soma.somar(destino);

    relatar!(
        "esp: duke.elf aberto e lido, {} bytes em {} paginas a partir de {:#x}, crc {:#010x}",
        tamanho,
        paginas,
        base,
        soma.terminar()
    );
    Ok(destino)
}

/// Desliga a máquina.
///
/// # Por que desligar, e não devolver o controle
///
/// Porque devolver faria o firmware tentar a próxima opção de boot, e o que
/// aparece depois disso é o menu dele — que não diz nada sobre este programa
/// e ainda deixa o emulador rodando. Desligar encerra a execução com um
/// desfecho que o `xtask` reconhece.
///
/// Nas etapas seguintes o fim deste programa passa a ser o salto para o
/// kernel, e este caminho fica só para o relatório de diagnóstico.
fn desligar(sistema: *mut efi::Sistema) -> ! {
    // SAFETY: o ponteiro é o que o firmware entregou. Se ele não servir, o
    // laço abaixo é o desfecho — e uma máquina parada é melhor que um salto
    // para um endereço inventado.
    if let Some(sistema) = unsafe { sistema.as_ref() }
        && let Some(execucao) = unsafe { sistema.execucao.as_ref() }
    {
        relatar!("desligando");
        // SAFETY: a tabela passou pelo CRC, então este ponteiro de função é o
        // que o firmware escreveu. A função não retorna.
        unsafe { (execucao.reiniciar)(efi::DESLIGAR, efi::SUCESSO, 0, core::ptr::null()) };
    }

    relatar!("sem como desligar; parando aqui");
    parar()
}

fn parar() -> ! {
    loop {
        // SAFETY: `hlt` só pára o núcleo até a próxima interrupção.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Escreve uma string UTF-16 terminada em zero, que é o formato de texto da
/// UEFI.
///
/// Os pontos de código fora do ASCII viram `?`: o destino é uma serial de
/// oito bits, e inventar uma codificação para o nome do firmware não vale o
/// que custaria.
fn escrever_utf16(destino: &mut impl Write, mut ponteiro: *const u16) {
    if ponteiro.is_null() {
        let _ = write!(destino, "<sem nome>");
        return;
    }
    // Um teto, porque a string vem da memória do firmware e um zero que nunca
    // chega seria um laço infinito no primeiro instante do boot.
    for _ in 0..64 {
        // SAFETY: o ponteiro veio da tabela do sistema, que passou no CRC; o
        // teto acima limita a leitura mesmo que o terminador falte.
        let unidade = unsafe { *ponteiro };
        if unidade == 0 {
            return;
        }
        let c = if (0x20..0x7F).contains(&unidade) {
            unidade as u8 as char
        } else {
            '?'
        };
        let _ = write!(destino, "{c}");
        // SAFETY: mesma justificativa.
        ponteiro = unsafe { ponteiro.add(1) };
    }
}

/// Um buffer de linha na pilha, para montar texto antes de emiti-lo.
///
/// Existe por causa de uma coisa só: o nome do firmware é escrito caractere a
/// caractere, e emitir cada um como uma linha do relatório daria sessenta
/// linhas em vez de uma.
struct Linha {
    bytes: [u8; 128],
    quantos: usize,
}

impl Linha {
    fn nova() -> Linha {
        Linha {
            bytes: [0; 128],
            quantos: 0,
        }
    }

    fn como_str(&self) -> &str {
        // O buffer só recebe o que `write!` produziu, e o corte abaixo é feito
        // em fronteira de caractere — ver `write_str`.
        core::str::from_utf8(&self.bytes[..self.quantos]).unwrap_or("<linha invalida>")
    }
}

impl Write for Linha {
    fn write_str(&mut self, texto: &str) -> core::fmt::Result {
        for c in texto.chars() {
            let mut buffer = [0u8; 4];
            let pedaco = c.encode_utf8(&mut buffer).as_bytes();
            // Cortar um caractere ao meio produziria bytes que não são UTF-8.
            // Descartar o caractere inteiro mantém a linha válida.
            if self.quantos + pedaco.len() > self.bytes.len() {
                return Ok(());
            }
            self.bytes[self.quantos..self.quantos + pedaco.len()].copy_from_slice(pedaco);
            self.quantos += pedaco.len();
        }
        Ok(())
    }
}

/// O que fazer quando o impossível acontece antes de haver kernel.
///
/// Relatar e parar. Não há log estruturado, não há canal do agente e não há
/// para onde voltar — o firmware já entregou a máquina. A linha na serial é
/// tudo que separa "o boot falhou" de "a tela ficou preta".
#[panic_handler]
fn em_panico(info: &PanicInfo) -> ! {
    relatar!("PANICO {}", info.message());
    if let Some(local) = info.location() {
        relatar!("PANICO em {}:{}", local.file(), local.line());
    }
    parar()
}
