//! O último passo: sair dos serviços de boot e entregar a máquina ao kernel.
//!
//! # Por que este módulo é diferente de todos os outros
//!
//! Porque a partir do `ExitBootServices` **não há a quem recorrer**. O
//! console do firmware some, a alocação de memória some, o protocolo de
//! arquivos some. Se algo estiver errado daqui para a frente, a máquina
//! reinicia — e reiniciar não escreve nada em lugar nenhum.
//!
//! Tudo que pode ser conferido é conferido **antes**: o mapa foi percorrido,
//! a imagem foi confrontada com o arquivo, as relocações foram limitadas à
//! faixa carregada. O que sobra aqui é a sequência, e a ordem dela importa
//! mais que qualquer linha isolada.
//!
//! # A ordem, e por que ela é essa
//!
//! 1. **Alocar tudo que ainda falta** — a entrega e a lista de regiões.
//!    Depois do passo 2 não há mais alocação, e antes do passo 3 qualquer
//!    alocação invalida a chave.
//! 2. **Pedir o mapa de memória**, que devolve a *chave* junto. A chave é o
//!    firmware dizendo "este é o mapa que eu tenho agora"; ele só aceita sair
//!    se quem sai provar que viu a versão mais recente.
//! 3. **Sair dos serviços de boot**, com aquela chave.
//! 4. **Trocar o `CR3` e saltar**, sem nada entre as duas coisas que possa
//!    tocar em memória que o mapa novo não descreva.
//!
//! O passo 2 pode falhar com "parâmetro inválido" quando o mapa mudou entre
//! a pergunta e a saída — o próprio ato de imprimir alguma coisa pode
//! mudá-lo. A especificação manda tentar de novo com um mapa fresco, uma vez.

use crate::efi;
use crate::relatar;

/// Quantas regiões a entrega cabe.
///
/// Duzentas e cinquenta e seis. O firmware deste emulador descreve cento e
/// vinte e nove; o dobro é a folga para uma máquina de verdade, que tem mais
/// dispositivos. Estourar é um erro relatado enquanto ainda há como relatar,
/// e não uma lista truncada que o kernel usaria como se fosse completa.
const MAX_REGIOES: usize = 256;

/// Para onde o kernel vai, e como ele enxerga a memória.
///
/// # Por que a sequência é parametrizada, e não duplicada
///
/// Porque a ordem dos quatro passos abaixo é o que há de mais delicado neste
/// programa, e ela é **a mesma** nas duas arquiteturas: a especificação da
/// UEFI é uma só. O que difere é o último instante — trocar o `CR3` e saltar
/// de um lado, desligar a MMU e saltar do outro.
///
/// Duas cópias da dança da chave seriam duas chances de uma delas ganhar uma
/// correção que a outra não recebe, num lugar onde o sintoma de estar errado
/// é uma máquina que reinicia sem escrever nada.
pub struct Destino {
    /// Onde a imagem do kernel foi posta, em endereço físico.
    pub base_fisica: u64,
    /// Para onde saltar, já no espaço em que o kernel vai rodar.
    pub entrada: u64,
    /// Quanto somar a um endereço físico para chegar ao virtual do kernel.
    ///
    /// No x86 é a base do mapa da memória física, porque o kernel roda na
    /// metade alta. No ARM é zero: o mapa é de identidade, e somar seria
    /// apontar para fora do espaço de 39 bits que o kernel configura.
    pub deslocamento: u64,
    pub video: protocolo::Video,
    /// O device tree, em endereço físico, ou zero quando não há.
    pub dispositivos: u64,
}

/// Tudo que precisa estar pronto antes de o mapa de memória ser pedido.
struct Reservado {
    entrega: *mut protocolo::Entrega,
    regioes: *mut protocolo::Regiao,
    /// O buffer do mapa de memória, e quanto ele tem.
    mapa: *mut u8,
    mapa_bytes: usize,
}

/// Entrega a máquina ao kernel. Não retorna.
///
/// `partir` é o último instante, e é a única coisa que difere entre as
/// arquiteturas: ela recebe o endereço de entrada e o endereço **virtual**
/// da entrega, e não volta.
///
/// # Safety
///
/// `destino` precisa descrever uma imagem já copiada, relocada e — onde a
/// arquitetura exigir — com o mapa montado e conferido. `imagem` é o handle
/// que o firmware passou em `efi_main`, e é ele que autoriza a saída dos
/// serviços de boot.
pub unsafe fn saltar(
    imagem: efi::Handle,
    boot: &efi::ServicosDeBoot,
    destino: &Destino,
    partir: impl FnOnce(u64, u64) -> !,
) -> Result<core::convert::Infallible, &'static str> {
    let reservado = reservar(boot)?;

    // Daqui para baixo, **nada** de alocar: qualquer alocação muda o mapa e
    // invalida a chave que o `ExitBootServices` exige.
    let (chave, quantas) = ultimo_mapa(boot, &reservado, destino)?;

    let entrega = protocolo::Entrega {
        magica: protocolo::MAGICA,
        versao: protocolo::VERSAO,
        tamanho: size_of::<protocolo::Entrega>() as u32,
        deslocamento_fisico: destino.deslocamento,
        // O ponteiro que o kernel recebe é **virtual**: no x86 ele só é
        // válido depois da troca de `CR3`, e é por isso que ele é montado
        // com o deslocamento somado em vez de ser o endereço em que
        // escrevemos. No ARM o deslocamento é zero e os dois coincidem.
        regioes: destino.deslocamento + reservado.regioes as u64,
        quantas_regioes: quantas as u64,
        video: destino.video,
        dispositivos: destino.dispositivos,
    };
    // SAFETY: a página veio do firmware, está alinhada, e ninguém mais a tem.
    unsafe { reservado.entrega.write(entrega) };

    relatar!(
        "saindo dos servicos de boot: {} regioes, chave {:#x}",
        quantas,
        chave
    );

    // SAFETY: o handle é o que o firmware entregou, e a chave veio do mapa
    // que acabamos de ler sem alocar nada depois.
    let status = unsafe { (boot.sair_dos_servicos_de_boot)(imagem, chave) };
    if efi::deu_errado(status) {
        // A especificação prevê uma segunda tentativa, e uma só: o mapa pode
        // ter mudado entre a leitura e a saída. Se a segunda também falhar, o
        // firmware está dizendo que não vai sair, e insistir é laço.
        relatar!("a primeira saida devolveu {:#x}; relendo o mapa", status);
        let (chave, _) = ultimo_mapa(boot, &reservado, destino)?;
        // SAFETY: mesma justificativa, com a chave nova.
        let status = unsafe { (boot.sair_dos_servicos_de_boot)(imagem, chave) };
        if efi::deu_errado(status) {
            relatar!("ERRO a saida dos servicos de boot devolveu {:#x}", status);
            return Err("o firmware nao entrega a maquina");
        }
    }

    // A partir daqui o firmware não existe mais. Só a serial, que é nossa.
    relatar!("a maquina e do Duke; saltando para {:#x}", destino.entrada);

    partir(
        destino.entrada,
        destino.deslocamento + reservado.entrega as u64,
    )
}

/// Reserva, ainda com o firmware vivo, tudo que a entrega precisa.
fn reservar(boot: &efi::ServicosDeBoot) -> Result<Reservado, &'static str> {
    // Uma página para a entrega, e o que couber para as regiões.
    let bytes_das_regioes = MAX_REGIOES * size_of::<protocolo::Regiao>();
    let paginas = 1 + bytes_das_regioes.div_ceil(efi::PAGINA as usize);

    let mut base = 0u64;
    // SAFETY: argumentos documentados, `base` é uma local.
    let status = unsafe {
        (boot.alocar_paginas)(
            efi::ALOCAR_QUALQUER,
            efi::memoria::DADOS_DO_CARREGADOR,
            paginas,
            &mut base,
        )
    };
    if efi::deu_errado(status) || base == 0 {
        return Err("o firmware recusou as paginas da entrega");
    }
    // SAFETY: as páginas são nossas e acabaram de ser reservadas.
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, paginas * efi::PAGINA as usize) };

    // E o buffer do mapa de memória, com folga: ele é pedido duas vezes, e
    // entre uma e outra o mapa pode crescer.
    let mapa_bytes = 32 * 1024;
    let mut mapa = core::ptr::null_mut();
    // SAFETY: idem.
    let status =
        unsafe { (boot.alocar_pool)(efi::memoria::DADOS_DO_CARREGADOR, mapa_bytes, &mut mapa) };
    if efi::deu_errado(status) || mapa.is_null() {
        return Err("o firmware recusou o buffer do mapa final");
    }

    Ok(Reservado {
        entrega: base as *mut protocolo::Entrega,
        regioes: (base + efi::PAGINA) as *mut protocolo::Regiao,
        mapa,
        mapa_bytes,
    })
}

/// Lê o mapa de memória final e o traduz para as regiões da entrega.
///
/// Devolve a chave que o `ExitBootServices` exige e quantas regiões saíram.
///
/// # Por que traduzir aqui, e não depois
///
/// Porque depois não há mapa: `ExitBootServices` é o último momento em que o
/// firmware responde. O que o kernel recebe é esta tradução, e ela precisa
/// estar pronta antes da chave ser usada.
fn ultimo_mapa(
    boot: &efi::ServicosDeBoot,
    reservado: &Reservado,
    destino: &Destino,
) -> Result<(usize, usize), &'static str> {
    let mut tamanho = reservado.mapa_bytes;
    let mut chave = 0usize;
    let mut por_descritor = 0usize;
    let mut versao = 0u32;

    // SAFETY: o buffer tem `mapa_bytes`, que é o que dizemos ao firmware.
    let status = unsafe {
        (boot.mapa_de_memoria)(
            &mut tamanho,
            reservado.mapa,
            &mut chave,
            &mut por_descritor,
            &mut versao,
        )
    };
    if efi::deu_errado(status) {
        relatar!("ERRO o mapa final devolveu {:#x}", status);
        return Err("o firmware nao entregou o mapa final");
    }

    let quantos = tamanho / por_descritor;
    let mut escritas = 0usize;

    for i in 0..quantos {
        // SAFETY: o passo é o que o firmware declarou, e `quantos` vem da
        // divisão do tamanho que ele devolveu por esse mesmo passo.
        let d = unsafe {
            core::ptr::read_unaligned(reservado.mapa.add(i * por_descritor) as *const efi::Descritor)
        };

        let tipo = classificar(d.tipo);
        let inicio = d.fisico;
        let fim = d.fisico + d.paginas * efi::PAGINA;

        // O que é do iniciador o kernel não pode entregar ao alocador: ele
        // está rodando dentro disso. O firmware marca as nossas alocações
        // como dados e código do carregador, e é essa marca que vira
        // `DO_INICIADOR` — a imagem do kernel, as tabelas de página, a pilha
        // e esta própria lista.
        if escritas >= MAX_REGIOES {
            relatar!("ERRO ha mais de {} regioes de memoria", MAX_REGIOES);
            return Err("o mapa de memoria nao cabe na entrega");
        }
        // SAFETY: `escritas` está abaixo de `MAX_REGIOES`, que é o que a
        // reserva dimensionou.
        unsafe {
            reservado
                .regioes
                .add(escritas)
                .write(protocolo::Regiao::nova(inicio, fim, tipo))
        };
        escritas += 1;
    }

    // Uma conferência barata sobre o resultado: o kernel tem de estar dentro
    // de uma região que **não** seja utilizável. Se ele aparecer como livre,
    // o alocador de frames do kernel vai entregar as páginas em que ele mesmo
    // está rodando — e o defeito aparece páginas depois, em outro lugar.
    if !esta_protegido(reservado, escritas, destino.base_fisica) {
        relatar!(
            "ERRO a imagem em {:#x} consta como livre",
            destino.base_fisica
        );
        return Err("o kernel esta numa regiao que o mapa diz estar livre");
    }

    Ok((chave, escritas))
}

/// Se um endereço cai numa região que o kernel não vai tratar como livre.
fn esta_protegido(reservado: &Reservado, quantas: usize, endereco: u64) -> bool {
    for i in 0..quantas {
        // SAFETY: `i` está abaixo de `quantas`, que é o que foi escrito.
        let r = unsafe { *reservado.regioes.add(i) };
        if endereco >= r.inicio && endereco < r.fim {
            return r.tipo != protocolo::tipo::UTILIZAVEL;
        }
    }
    false
}

/// Traduz o tipo de memória da UEFI para o que o kernel entende.
///
/// O código e os dados dos **serviços de boot** viram utilizáveis: a
/// especificação diz que eles deixam de ser do firmware no instante em que
/// saímos, e são dezenas de mebibytes numa máquina de verdade. Deixá-los
/// reservados seria devolver ao kernel bem menos memória do que a máquina
/// tem.
fn classificar(tipo: u32) -> u32 {
    match tipo {
        efi::memoria::CONVENCIONAL | efi::memoria::CODIGO_DE_BOOT | efi::memoria::DADOS_DE_BOOT => {
            protocolo::tipo::UTILIZAVEL
        }
        efi::memoria::CODIGO_DO_CARREGADOR | efi::memoria::DADOS_DO_CARREGADOR => {
            protocolo::tipo::DO_INICIADOR
        }
        _ => protocolo::tipo::RESERVADA,
    }
}
