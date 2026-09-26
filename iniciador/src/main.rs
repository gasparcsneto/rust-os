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

mod crc32;
mod efi;
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
pub extern "efiapi" fn efi_main(_imagem: efi::Handle, sistema: *mut efi::Sistema) -> efi::Status {
    serial::init();
    relatar!("vivo, carregado pelo firmware");

    match relatorio(sistema) {
        Ok(()) => relatar!("fim do relatorio"),
        Err(motivo) => relatar!("ERRO {}", motivo),
    }

    desligar(sistema)
}

/// Confere o que o firmware entregou e descreve a máquina.
fn relatorio(sistema: *mut efi::Sistema) -> Result<(), &'static str> {
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

    descrever_memoria(boot)?;
    descrever_video(boot)?;
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
fn descrever_memoria(boot: &efi::ServicosDeBoot) -> Result<(), &'static str> {
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
        "o iniciador ocupa {} KiB em {} paginas",
        paginas_do_iniciador * efi::PAGINA / 1024,
        paginas_do_iniciador
    );
    Ok(())
}

/// Localiza o protocolo de vídeo e descreve o que ele oferece.
///
/// Sem vídeo o relatório segue: uma máquina headless é uma máquina, e o Duke
/// já sabe funcionar sem tela. O que não pode é a ausência passar calada.
fn descrever_video(boot: &efi::ServicosDeBoot) -> Result<(), &'static str> {
    let mut video: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: o GUID é uma constante nossa, o registro nulo é a forma
    // documentada de pedir a primeira instância, e o destino é uma local.
    let status = unsafe {
        (boot.localizar_protocolo)(&efi::GUID_DO_VIDEO, core::ptr::null_mut(), &mut video)
    };
    if efi::deu_errado(status) || video.is_null() {
        relatar!("video: nenhum (o firmware devolveu {:#x})", status);
        return Ok(());
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
    Ok(())
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
