//! Pôr o kernel onde ele quer estar, e desenhar o mapa em que ele vai rodar.
//!
//! # As três coisas que acontecem aqui, nesta ordem
//!
//! 1. **Copiar.** Cada segmento vai do arquivo para memória física reservada,
//!    e o que o segmento pede além do que o arquivo traz — a `.bss` — é
//!    entregue zerado.
//! 2. **Relocar.** O kernel é um executável independente de posição: ele foi
//!    ligado a partir do zero e carrega uma lista de lugares onde a base de
//!    carga precisa ser somada. Sem essa passagem, todo ponteiro constante
//!    dele aponta para a metade baixa do espaço, onde não há nada.
//! 3. **Mapear.** Um mapa de tradução novo, com a metade alta que o Duke
//!    espera — e com a identidade da RAM, que existe só para sobreviver aos
//!    poucos ciclos entre a troca de `CR3` e o salto.
//!
//! # O que este módulo não faz
//!
//! Instalar o mapa. Ele monta e **confere** — [`crate::paginas::Tabelas::traduzir`]
//! percorre o resultado como o processador percorreria, e o relatório diz em
//! que endereço físico cada região caiu. Instalar é o passo seguinte, e é o
//! primeiro que não tem relatório: depois do `mov cr3`, ou a máquina segue ou
//! ela reinicia calada.

use crate::efi;
use crate::elf;
use crate::mapa;
use crate::paginas::{self, PAGINA, Tabelas, bit};
use crate::relatar;

/// O resultado de carregar o kernel.
pub struct Carga {
    /// Onde a imagem foi posta, em memória física.
    pub base_fisica: u64,
    /// O menor endereço virtual que a imagem ocupa, antes da base do kernel.
    pub menor: u64,
    /// Quanto ela ocupa, já arredondado para páginas.
    pub bytes: u64,
    /// O ponto de entrada, já no espaço virtual do kernel.
    pub entrada: u64,
    pub relocacoes: usize,
    /// Quantos bytes de `.bss` foram conferidos zerados.
    pub zerados: usize,
    pub tabelas: Tabelas,
    /// O topo da pilha que o kernel vai usar, em endereço virtual.
    pub topo_da_pilha: u64,
    /// Onde o framebuffer ficou, em endereço virtual, se houver.
    pub video: Option<u64>,
}

/// O que o vídeo precisa que seja mapeado.
#[derive(Clone, Copy)]
pub struct Video {
    pub fisico: u64,
    pub bytes: u64,
}

/// Copia o kernel, reloca, e monta o mapa em que ele vai rodar.
pub fn carregar(
    boot: &efi::ServicosDeBoot,
    imagem: &elf::Imagem,
    maior_ram: u64,
    video: Option<Video>,
) -> Result<Carga, &'static str> {
    let (menor, maior) = extensao(imagem)?;
    let bytes = (maior - menor).next_multiple_of(PAGINA);
    let paginas = bytes / PAGINA;

    let mut base_fisica = 0u64;
    // SAFETY: os argumentos são os documentados e `base_fisica` é uma local.
    let status = unsafe {
        (boot.alocar_paginas)(
            efi::ALOCAR_QUALQUER,
            efi::memoria::CODIGO_DO_CARREGADOR,
            paginas as usize,
            &mut base_fisica,
        )
    };
    if efi::deu_errado(status) || base_fisica == 0 {
        relatar!("ERRO o firmware recusou {} paginas para o kernel", paginas);
        return Err("nao ha memoria para a imagem do kernel");
    }

    // SAFETY: o firmware acabou de reservar estas páginas para nós, e a UEFI
    // mapeia a memória por identidade — então o endereço físico serve de
    // ponteiro enquanto estivermos sob ela.
    let destino =
        unsafe { core::slice::from_raw_parts_mut(base_fisica as *mut u8, bytes as usize) };

    // Sujar, zerar, e só então copiar.
    //
    // # Por que zerar tudo, e não só o que sobra de cada segmento
    //
    // Duas razões. A `.bss` tem de chegar zerada, e ela é a diferença entre o
    // que o arquivo traz e o que o segmento pede. E os buracos entre
    // segmentos, que segmento nenhum reivindica, ficariam com o que o dono
    // anterior da página deixou — memória do firmware, visível para o kernel.
    //
    // # Por que sujar antes
    //
    // Porque sem isso o zerar não é testável. A UEFI **não** promete páginas
    // limpas, mas este firmware as entrega limpas — então apagar o `fill(0)`
    // não muda nada aqui, e a conferência logo abaixo continuava passando.
    // Medido por mutação.
    //
    // A sujeira faz a promessa valer o que ela diz: se o zerar sumir, a
    // conferência encontra este byte e diz onde. O custo é uma passagem por
    // um mebibyte, uma vez, no boot.
    //
    // `0xA5` porque ele não aparece por acaso: não é zero, não é `0xFF`, e
    // num despejo de memória se reconhece de longe.
    const SUJEIRA: u8 = 0xA5;
    destino.fill(SUJEIRA);
    destino.fill(0);

    for segmento in imagem.segmentos() {
        let s = segmento?;
        let em = usize::try_from(s.endereco - menor).map_err(|_| "segmento longe demais")?;
        let conteudo = imagem.conteudo(&s)?;
        destino
            .get_mut(em..em + conteudo.len())
            .ok_or("um segmento nao cabe no espaco reservado")?
            .copy_from_slice(conteudo);
    }

    let zerados = conferir_zeros(imagem, destino, menor)?;
    let relocacoes = relocar(imagem, destino, menor)?;

    let mut tabelas = Tabelas::novas(boot)?;
    mapear_memoria_fisica(&mut tabelas, maior_ram)?;
    mapear_o_kernel(&mut tabelas, imagem, base_fisica, menor, maior)?;
    let topo_da_pilha = mapear_a_pilha(&mut tabelas, boot)?;
    let video = match video {
        Some(v) => Some(mapear_o_video(&mut tabelas, v)?),
        None => None,
    };

    Ok(Carga {
        base_fisica,
        menor,
        bytes,
        entrada: mapa::BASE_DO_KERNEL + imagem.entrada,
        relocacoes,
        zerados,
        tabelas,
        topo_da_pilha,
        video,
    })
}

/// Confere que tudo que o arquivo não trouxe chegou zerado.
///
/// # Por que conferir o que acabamos de fazer
///
/// Porque não é a mesma coisa. O zerar é uma escrita; isto é uma leitura do
/// resultado, sobre os bytes que a cópia **não** tocou. Apagar o `fill` faz
/// esta conferência reprovar, e foi medido: sem ela, um iniciador que não
/// zerasse passava em tudo.
///
/// E o que está em jogo é grande. A `.bss` do kernel são os globais dele —
/// contadores, travas, tabelas estáticas. Entregá-la com o que o dono
/// anterior da página deixou dá um kernel que às vezes boota, e um defeito
/// que muda de lugar a cada execução.
///
/// É a mesma exigência que o kernel já faz do próprio carregador de
/// programas de usuário, onde o exemplo sai com um código próprio se
/// encontrar lixo na `.bss` dele.
fn conferir_zeros(imagem: &elf::Imagem, destino: &[u8], menor: u64) -> Result<usize, &'static str> {
    let mut conferidos = 0usize;
    for segmento in imagem.segmentos() {
        let s = segmento?;
        let de = usize::try_from(s.endereco - menor + s.tamanho_no_arquivo)
            .map_err(|_| "segmento longe demais")?;
        let ate = usize::try_from(s.endereco - menor + s.tamanho_na_memoria)
            .map_err(|_| "segmento longe demais")?;

        let cauda = destino
            .get(de..ate)
            .ok_or("a bss de um segmento sai do espaco reservado")?;
        if let Some(posicao) = cauda.iter().position(|b| *b != 0) {
            relatar!(
                "ERRO ha {:#04x} em {:#x}, que devia ser bss zerada",
                cauda[posicao],
                menor + (de + posicao) as u64
            );
            return Err("a bss do kernel nao chegou zerada");
        }
        conferidos += cauda.len();
    }
    Ok(conferidos)
}

/// O menor e o maior endereço virtual que os segmentos ocupam.
fn extensao(imagem: &elf::Imagem) -> Result<(u64, u64), &'static str> {
    let mut menor = u64::MAX;
    let mut maior = 0u64;
    for segmento in imagem.segmentos() {
        let s = segmento?;
        menor = menor.min(s.endereco);
        maior = maior.max(
            s.endereco
                .checked_add(s.tamanho_na_memoria)
                .ok_or("um segmento transborda na memoria")?,
        );
    }
    if menor == u64::MAX {
        return Err("o kernel nao tem segmento nenhum para carregar");
    }
    // A base precisa cair numa fronteira de página: o mapeamento é por
    // página, e uma imagem que comece no meio de uma obrigaria a decidir de
    // quem é a primeira metade.
    if !menor.is_multiple_of(PAGINA) {
        return Err("o menor endereco do kernel nao esta alinhado a uma pagina");
    }
    Ok((menor, maior.next_multiple_of(PAGINA)))
}

/// Aplica as relocações da imagem já copiada.
///
/// # A conta, e por que ela tem duas bases
///
/// A relocação diz "no endereço virtual `r_offset`, escreva `base + adendo`".
/// A **base** é a virtual — é onde o kernel vai rodar. O **lugar onde
/// escrever** é físico, porque é onde a imagem está agora, e ainda estamos
/// sob o mapa de identidade do firmware.
///
/// Confundir as duas escreve o valor certo no lugar errado, ou o errado no
/// lugar certo. As duas dão um kernel que boota e falha depois.
fn relocar(imagem: &elf::Imagem, destino: &mut [u8], menor: u64) -> Result<usize, &'static str> {
    let Some(dinamica) = imagem.dinamica()? else {
        // Um executável de endereço fixo não tem o que relocar, e dizer isso
        // é melhor que somar zero em silêncio.
        if imagem.independente_de_posicao {
            return Err("o kernel e independente de posicao e nao tem secao dinamica");
        }
        return Ok(0);
    };

    let tabela = elf::relocacoes(
        destino,
        menor,
        dinamica.endereco,
        dinamica.tamanho_na_memoria,
    )?;
    if tabela.quantas == 0 {
        return Ok(0);
    }

    let base = usize::try_from(
        tabela
            .em
            .checked_sub(menor)
            .ok_or("a tabela de relocacoes esta antes da base")?,
    )
    .map_err(|_| "tabela de relocacoes longe demais")?;

    // A faixa virtual que a imagem ocupa. Toda relocação relativa de um
    // executável autocontido aponta para dentro dela — são ponteiros internos
    // do próprio kernel, e não há símbolo externo nenhum para apontar fora.
    //
    // Conferir isso é o que torna a conta verificável. A alternativa seria
    // reler o que acabamos de escrever e comparar com a mesma fórmula, que
    // concorda consigo mesma: com a base errada — física em vez de virtual —
    // todos os 3703 valores saem coerentes entre si e apontam para a metade
    // baixa do espaço, onde o kernel não está. Medido por mutação.
    let primeiro = mapa::BASE_DO_KERNEL + menor;
    let ultimo = primeiro + destino.len() as u64;

    let mut aplicadas = 0usize;
    for i in 0..tabela.quantas {
        let em = base + i * elf::TAMANHO_DA_RELOCACAO;
        let entrada = destino
            .get(em..em + elf::TAMANHO_DA_RELOCACAO)
            .ok_or("a tabela de relocacoes sai da imagem")?;

        let onde = u64::from_le_bytes(entrada[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(entrada[8..16].try_into().unwrap());
        let adendo = u64::from_le_bytes(entrada[16..24].try_into().unwrap());

        // O tipo são os 32 bits de baixo; os de cima são o índice do símbolo,
        // que uma relocação relativa não usa.
        if (info & 0xFFFF_FFFF) as u32 != elf::RELATIVA {
            relatar!(
                "ERRO relocacao de tipo {} na entrada {}",
                info & 0xFFFF_FFFF,
                i
            );
            return Err("o kernel tem relocacao que este carregador nao sabe aplicar");
        }

        let alvo = usize::try_from(
            onde.checked_sub(menor)
                .ok_or("uma relocacao aponta antes da base")?,
        )
        .map_err(|_| "relocacao longe demais")?;
        let valor = mapa::BASE_DO_KERNEL
            .checked_add(adendo)
            .ok_or("uma relocacao transborda")?;

        if valor < primeiro || valor >= ultimo {
            relatar!(
                "ERRO a relocacao {} escreveria {:#x}, fora de {:#x}..{:#x}",
                i,
                valor,
                primeiro,
                ultimo
            );
            return Err("uma relocacao aponta para fora da imagem carregada");
        }

        destino
            .get_mut(alvo..alvo + 8)
            .ok_or("uma relocacao aponta para fora da imagem")?
            .copy_from_slice(&valor.to_le_bytes());
        aplicadas += 1;
    }

    // O número relatado é o de relocações **aplicadas**, e não o que a tabela
    // diz ter. A primeira versão devolvia `tabela.quantas`, e com isso um
    // laço que parasse na primeira volta continuava relatando 3703 — o
    // relatório afirmava um trabalho que não aconteceu.
    Ok(aplicadas)
}

/// Mapeia a RAM duas vezes: por identidade e no deslocamento do kernel.
///
/// # Por que as duas, e por que na mesma tabela
///
/// A identidade é para o instante da troca de `CR3` — ver o topo de
/// [`crate::paginas`]. O deslocamento é como o kernel alcança qualquer byte
/// de memória física, inclusive as tabelas de página, cujos descritores
/// contêm endereços físicos enquanto todo acesso dele é virtual.
///
/// As duas cobrem a mesma faixa com as mesmas permissões, e as duas começam
/// no deslocamento zero da entrada de topo delas. Então a tabela de nível
/// três pode ser **a mesma**, apontada por duas entradas da raiz. É meia
/// dúzia de páginas economizadas, e uma incoerência a menos: mapas separados
/// poderiam divergir.
///
/// A RAM nunca é executável. O kernel executa a partir da imagem dele, que é
/// mapeada à parte, e um mapa da memória física que também executasse daria
/// a qualquer ponteiro corrompido um caminho para rodar dados como código.
fn mapear_memoria_fisica(tabelas: &mut Tabelas, maior_ram: u64) -> Result<(), &'static str> {
    let bytes = maior_ram.next_multiple_of(paginas::PAGINA_GRANDE);
    if bytes > mapa::COBERTURA_DA_ENTRADA_DE_TOPO {
        return Err("ha mais memoria fisica do que uma entrada de topo cobre");
    }

    let bits = bit::ESCRITA | bit::NAO_EXECUTA;
    tabelas.mapear_faixa(0, 0, bytes, bits)?;
    tabelas.mapear_faixa(mapa::BASE_DA_MEMORIA_FISICA, 0, bytes, bits)
}

/// Mapeia a imagem do kernel, com as permissões de cada segmento.
///
/// # Páginas que dois segmentos dividem
///
/// Acontecem, e este kernel tem uma: o fim do segmento somente-leitura e o
/// começo do executável moram na mesma página, porque o ligador não os
/// separou por uma fronteira. Uma página tem um conjunto de permissões só, e
/// a única resposta correta é a **união** — negar o que um dos dois precisa
/// quebraria aquele.
///
/// A união tem um limite, e ele é conferido: nenhuma página pode acabar
/// gravável **e** executável. Se um dia o ligador puser um segmento `rw-`
/// encostado num `r-x`, o carregador recusa em vez de entregar ao kernel uma
/// página onde dados viram código.
///
/// **Essa recusa não é falsificável hoje**, e está escrita aqui em vez de
/// parecer coberta: neste kernel o segmento executável acaba em `0xc36bf` e o
/// gravável começa em `0xc46c0`, páginas diferentes, então desligar a
/// conferência não reprova caso nenhum. Medido por mutação.
///
/// Ela existe porque o arranjo que a dispara depende do ligador, e não de uma
/// decisão deste projeto: basta o código crescer alguns kilobytes para os
/// dois segmentos se encostarem. O dia em que isso acontecer, a escolha é
/// entre recusar e perder o `W^X` do kernel calado.
fn mapear_o_kernel(
    tabelas: &mut Tabelas,
    imagem: &elf::Imagem,
    base_fisica: u64,
    menor: u64,
    maior: u64,
) -> Result<(), &'static str> {
    let mut pagina = menor;
    while pagina < maior {
        let fim = pagina + PAGINA;

        // As permissões desta página são as de todo segmento que a toca.
        let mut escreve = false;
        let mut executa = false;
        let mut coberta = false;
        for segmento in imagem.segmentos() {
            let s = segmento?;
            let s_fim = s.endereco + s.tamanho_na_memoria;
            if s.endereco < fim && pagina < s_fim {
                coberta = true;
                escreve |= s.permissoes & elf::permissao::ESCREVER != 0;
                executa |= s.permissoes & elf::permissao::EXECUTAR != 0;
            }
        }

        // Um buraco entre segmentos não é mapeado: deixá-lo fora é o que
        // torna um ponteiro perdido uma falha de página em vez de uma
        // leitura de memória alheia.
        if coberta {
            if escreve && executa {
                relatar!("ERRO a pagina {:#x} seria gravavel e executavel", pagina);
                return Err("dois segmentos com permissoes incompativeis dividem uma pagina");
            }
            let mut bits = 0;
            if escreve {
                bits |= bit::ESCRITA;
            }
            if !executa {
                bits |= bit::NAO_EXECUTA;
            }
            tabelas.mapear(
                mapa::BASE_DO_KERNEL + pagina,
                base_fisica + (pagina - menor),
                bits,
            )?;
        }

        pagina = fim;
    }
    Ok(())
}

/// Reserva e mapeia a pilha com que o kernel começa.
///
/// # A página de guarda, e por que ela é a de baixo
///
/// Porque a pilha cresce para baixo. Uma página não mapeada logo abaixo do
/// fundo transforma um estouro em falha de página no primeiro acesso que
/// passar do limite — em vez de uma escrita silenciosa no que estiver ali.
///
/// É a mesma ideia das pilhas de fio do kernel, e o kernel conta com ela: o
/// caso `pilha: estouro e detectado` da suíte existe justamente para provar
/// que o estouro é detectado e não corrompe.
fn mapear_a_pilha(tabelas: &mut Tabelas, boot: &efi::ServicosDeBoot) -> Result<u64, &'static str> {
    let mut fisico = 0u64;
    // SAFETY: argumentos documentados, `fisico` é uma local.
    let status = unsafe {
        (boot.alocar_paginas)(
            efi::ALOCAR_QUALQUER,
            efi::memoria::DADOS_DO_CARREGADOR,
            mapa::PAGINAS_DA_PILHA,
            &mut fisico,
        )
    };
    if efi::deu_errado(status) || fisico == 0 {
        return Err("o firmware recusou as paginas da pilha do kernel");
    }

    // A primeira página virtual da região fica **fora** do mapa: é a guarda.
    let fundo = mapa::PILHA_EM + PAGINA;
    for i in 0..mapa::PAGINAS_DA_PILHA {
        tabelas.mapear(
            fundo + (i as u64) * PAGINA,
            fisico + (i as u64) * PAGINA,
            bit::ESCRITA | bit::NAO_EXECUTA,
        )?;
    }

    // O topo é o endereço logo acima da última página: é para onde o `RSP`
    // aponta antes do primeiro `push`.
    Ok(fundo + (mapa::PAGINAS_DA_PILHA as u64) * PAGINA)
}

/// Mapeia o framebuffer num endereço que o kernel conhece.
///
/// Ele não cai no mapa da memória física porque não é memória física: é um
/// bloco de dispositivo, fora da RAM que o firmware descreveu. Mapeá-lo à
/// parte é o que torna o endereço previsível para o kernel.
fn mapear_o_video(tabelas: &mut Tabelas, video: Video) -> Result<u64, &'static str> {
    if !video.fisico.is_multiple_of(PAGINA) {
        return Err("o framebuffer nao comeca numa fronteira de pagina");
    }
    let bytes = video.bytes.next_multiple_of(PAGINA);
    tabelas.mapear_faixa(
        mapa::VIDEO_EM,
        video.fisico,
        bytes,
        bit::ESCRITA | bit::NAO_EXECUTA,
    )?;
    Ok(mapa::VIDEO_EM)
}
