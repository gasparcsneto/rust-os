//! O kernel pelos slots da atualização A/B.
//!
//! # O caminho
//!
//! Do disco de onde o iniciador veio: a partição da ESP é um nó do caminho
//! de dispositivo, e o disco é o caminho sem esse nó. No disco, a GPT; nela,
//! o controle e os dois slots, pelos tipos — ver `atualizacao::disco`.
//!
//! Do controle, o plano — ver `atualizacao::controle::planejar`: o slot
//! bom, ou uma tentativa da versão nova, com a conta descida **e gravada**
//! antes de o kernel novo ser lido. Do slot, o cabeçalho; dele, o
//! manifesto, que tem de ser o que o controle diz; do manifesto, o tamanho
//! e o resumo do kernel, que tem de bater com o que se leu.
//!
//! # O que o iniciador não confere
//!
//! A assinatura do manifesto: ver `atualizacao` (lib.rs). Quem confere é o
//! kernel, com a chave da raiz da máquina, antes de qualquer autoridade.
//!
//! # Um disco sem as partições
//!
//! É um disco de antes da atualização A/B, ou um que não a quer: o kernel
//! vem da ESP, como sempre veio. Um disco com parte delas está quebrado, e
//! o boot para — a ESP não é o caminho de volta de um disco A/B.

use crate::{efi, relatar};
use atualizacao::cabecalho::{self, KERNEL_EM, TAM_CABECALHO};
use atualizacao::controle::{self, Boot, Controle, Modo, Plano};
use atualizacao::disco::{self, COPIA_EM, Faixa, Gpt, Particoes};
use atualizacao::manifesto::{Manifesto, resumo_do_manifesto};
use atualizacao::{Arquitetura, Resumidor, Slot, TAM_RESUMO};

/// A arquitetura que este iniciador boota.
#[cfg(target_arch = "x86_64")]
const ARQUITETURA: Arquitetura = Arquitetura::X86_64;
#[cfg(target_arch = "aarch64")]
const ARQUITETURA: Arquitetura = Arquitetura::Aarch64;

/// O maior bloco de disco que o iniciador sabe usar: as cópias do controle
/// moram a 4 KiB uma da outra, e o kernel começa a 4 KiB do slot.
const MAIOR_BLOCO: u64 = 4096;

/// Quanto o iniciador lê do slot por chamada, somando o resumo enquanto
/// lê. Um mebibyte: o kernel de depuração tem mais de vinte, e uma chamada
/// só deixaria a conferência inteira para depois.
const PEDACO: usize = 1024 * 1024;

/// O kernel lido de um slot, e o que vai na entrega.
pub struct Lido {
    pub kernel: &'static [u8],
    pub arranque: protocolo::Arranque,
}

/// O disco inteiro, pelo protocolo de bloco do firmware.
struct Disco {
    bloco: *mut efi::Bloco,
    midia: u32,
    tamanho: u64,
    ultimo: u64,
}

impl Disco {
    /// Lê `destino.len()` bytes a partir do bloco `lba`. O tamanho é um
    /// múltiplo do bloco, e o buffer, de páginas do firmware.
    fn ler(&self, lba: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        // SAFETY: o protocolo veio do firmware para este disco, e o buffer é
        // nosso, alinhado a página e do tamanho pedido.
        let status = unsafe {
            ((*self.bloco).ler)(
                self.bloco,
                self.midia,
                lba,
                destino.len(),
                destino.as_mut_ptr(),
            )
        };
        if efi::deu_errado(status) {
            relatar!("ERRO leitura do bloco {} devolveu {:#x}", lba, status);
            return Err("o disco nao leu");
        }
        Ok(())
    }

    /// Escreve um bloco e descarrega: o controle só vale gravado de
    /// verdade, e não no cache do disco.
    fn escrever(&self, lba: u64, origem: &[u8]) -> Result<(), &'static str> {
        // SAFETY: como em `ler`.
        let status = unsafe {
            ((*self.bloco).escrever)(self.bloco, self.midia, lba, origem.len(), origem.as_ptr())
        };
        if efi::deu_errado(status) {
            relatar!("ERRO escrita do bloco {} devolveu {:#x}", lba, status);
            return Err("o disco nao gravou");
        }
        // SAFETY: como em `ler`.
        let status = unsafe { ((*self.bloco).descarregar)(self.bloco) };
        if efi::deu_errado(status) {
            relatar!("ERRO a descarga do disco devolveu {:#x}", status);
            return Err("o disco nao descarregou");
        }
        Ok(())
    }

    /// Se a faixa cabe no disco.
    fn cabe(&self, f: &Faixa) -> bool {
        f.blocos > 0
            && f.primeiro
                .checked_add(f.blocos - 1)
                .is_some_and(|ultimo| ultimo <= self.ultimo)
    }
}

/// Páginas do firmware, para os buffers de bloco.
fn paginas(boot: &efi::ServicosDeBoot, bytes: u64) -> Result<&'static mut [u8], &'static str> {
    let quantas = bytes.div_ceil(efi::PAGINA).max(1);
    let mut base = 0u64;
    // SAFETY: os tipos são os documentados e `base` é uma local.
    let status = unsafe {
        (boot.alocar_paginas)(
            efi::ALOCAR_QUALQUER,
            efi::memoria::DADOS_DO_CARREGADOR,
            quantas as usize,
            &mut base,
        )
    };
    if efi::deu_errado(status) || base == 0 {
        relatar!(
            "ERRO o firmware recusou {} paginas ({:#x})",
            quantas,
            status
        );
        return Err("nao ha memoria para o slot");
    }
    // SAFETY: as páginas acabaram de ser reservadas para nós.
    Ok(unsafe {
        core::slice::from_raw_parts_mut(base as *mut u8, (quantas * efi::PAGINA) as usize)
    })
}

fn devolver(boot: &efi::ServicosDeBoot, buffer: &'static mut [u8]) {
    // SAFETY: o buffer veio de `paginas`, e ninguém mais o usa.
    unsafe {
        (boot.liberar_paginas)(
            buffer.as_mut_ptr() as u64,
            buffer.len() / efi::PAGINA as usize,
        )
    };
}

/// O disco de onde veio a imagem `imagem`: o caminho da partição, sem o nó
/// da partição. `None` se o iniciador não veio de uma partição.
fn achar_o_disco(
    imagem: efi::Handle,
    boot: &efi::ServicosDeBoot,
) -> Result<Option<Disco>, &'static str> {
    let mut carregada: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: o handle é o de `efi_main`; o destino é uma local.
    let status =
        unsafe { (boot.protocolo_do_handle)(imagem, &efi::GUID_DA_IMAGEM, &mut carregada) };
    if efi::deu_errado(status) || carregada.is_null() {
        return Err("o firmware nao descreveu a imagem em execucao");
    }
    // SAFETY: o firmware devolveu o protocolo da imagem carregada.
    let particao = unsafe { (*(carregada as *const efi::ImagemCarregada)).dispositivo };

    let mut caminho: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: como acima.
    let status =
        unsafe { (boot.protocolo_do_handle)(particao, &efi::GUID_DO_CAMINHO, &mut caminho) };
    if efi::deu_errado(status) || caminho.is_null() {
        relatar!("atualizacao: o dispositivo nao tem caminho; sem slots");
        return Ok(None);
    }

    // A cópia do caminho até o nó da partição, fechada com o nó do fim.
    let copia = paginas(boot, efi::PAGINA)?;
    let mut lido = 0usize;
    let mut achou = false;
    let origem = caminho as *const u8;
    // Um teto de nós, porque o caminho vem da memória do firmware.
    for _ in 0..64 {
        // SAFETY: o nó está dentro do caminho que o firmware entregou; o
        // cabeçalho tem quatro bytes, e o tamanho é conferido antes de
        // copiar.
        let no = unsafe { core::ptr::read_unaligned(origem.add(lido) as *const efi::NoDoCaminho) };
        let tamanho = usize::from(u16::from_le_bytes(no.tamanho));
        if no.tipo == efi::NO_DO_FIM.tipo || tamanho < 4 || lido + tamanho + 4 > copia.len() {
            break;
        }
        if no.tipo == efi::NO_DE_MIDIA && no.subtipo == efi::NO_DE_PARTICAO {
            achou = true;
            break;
        }
        // SAFETY: os `tamanho` bytes do nó são do firmware; o destino cabe.
        unsafe {
            core::ptr::copy_nonoverlapping(origem.add(lido), copia.as_mut_ptr().add(lido), tamanho)
        };
        lido += tamanho;
    }
    if !achou {
        devolver(boot, copia);
        relatar!("atualizacao: o iniciador nao veio de uma particao; sem slots");
        return Ok(None);
    }
    let fim = efi::NO_DO_FIM;
    copia[lido..lido + 4].copy_from_slice(&[fim.tipo, fim.subtipo, fim.tamanho[0], fim.tamanho[1]]);

    let mut resto = copia.as_ptr() as *const efi::NoDoCaminho;
    let mut disco: efi::Handle = core::ptr::null_mut();
    // SAFETY: o caminho é a cópia, fechada; os destinos são locais.
    let status = unsafe { (boot.localizar_caminho)(&efi::GUID_DO_BLOCO, &mut resto, &mut disco) };
    // O que sobrou do caminho tem de ser só o fim: senão o dispositivo
    // achado é um pedaço do caminho, e não o disco.
    // SAFETY: o firmware deixa `resto` dentro da cópia.
    let so_o_fim = !resto.is_null() && unsafe { (*resto).tipo } == fim.tipo;
    devolver(boot, copia);
    if efi::deu_errado(status) || disco.is_null() || !so_o_fim {
        relatar!("ERRO o disco da particao nao foi achado ({:#x})", status);
        return Err("o disco de onde viemos nao tem protocolo de bloco");
    }

    let mut bloco: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: como acima.
    let status = unsafe { (boot.protocolo_do_handle)(disco, &efi::GUID_DO_BLOCO, &mut bloco) };
    if efi::deu_errado(status) || bloco.is_null() {
        return Err("o disco nao tem protocolo de bloco");
    }
    let bloco = bloco as *mut efi::Bloco;
    // SAFETY: o protocolo é o do GUID pedido; a mídia é dele.
    let midia = unsafe { (*bloco).midia.as_ref() }.ok_or("o disco nao tem midia")?;
    if midia.presente == 0 || midia.particao != 0 {
        return Err("o disco achado nao e um disco inteiro com midia");
    }
    let tamanho = u64::from(midia.tamanho_do_bloco);
    if !(512..=MAIOR_BLOCO).contains(&tamanho) || !tamanho.is_power_of_two() {
        relatar!("ERRO o disco tem blocos de {} bytes", tamanho);
        return Err("o disco tem um tamanho de bloco que o iniciador nao usa");
    }
    if u64::from(midia.alinhamento) > efi::PAGINA {
        return Err("o disco pede um alinhamento maior que uma pagina");
    }
    Ok(Some(Disco {
        bloco,
        midia: midia.id,
        tamanho,
        ultimo: midia.ultimo_bloco,
    }))
}

/// As partições da atualização, pela GPT do disco.
fn achar_as_particoes(d: &Disco, buffer: &mut [u8]) -> Result<Particoes, &'static str> {
    let b = d.tamanho as usize;
    d.ler(1, &mut buffer[..b])?;
    let gpt = Gpt::ler(&buffer[..b], d.tamanho)?;
    let t = gpt.tamanho as usize;
    let por_bloco = b / t;
    let mut p = Particoes::default();
    let mut vistas = 0u32;
    for i in 0..gpt.blocos(d.tamanho) {
        d.ler(gpt.entradas_em + i, &mut buffer[..b])?;
        for j in 0..por_bloco {
            if vistas == gpt.quantas {
                break;
            }
            vistas += 1;
            if let Some(e) = disco::entrada(&buffer[j * t..(j + 1) * t]) {
                if !d.cabe(&e.faixa) {
                    return Err("uma particao da gpt passa do fim do disco");
                }
                p.anotar(&e)?;
            }
        }
    }
    Ok(p)
}

/// O iniciador com o disco e as partições achados.
struct Slots<'b> {
    disco: Disco,
    particoes: Particoes,
    boot: &'b efi::ServicosDeBoot,
    /// Um buffer de 4 KiB para os blocos pequenos.
    buffer: &'static mut [u8],
}

impl Slots<'_> {
    /// Lê uma cópia do controle.
    fn copia(&mut self, i: usize) -> Option<Controle> {
        let controle = self.particoes.controle?;
        let lba = controle.bloco_de(COPIA_EM[i], self.disco.tamanho)?;
        let b = self.disco.tamanho as usize;
        self.disco.ler(lba, &mut self.buffer[..b]).ok()?;
        controle::ler(&self.buffer[..b])
    }

    fn controle_valido(&mut self) -> Option<(usize, Controle)> {
        controle::escolher([self.copia(0), self.copia(1)])
    }

    /// Grava `novo` na cópia que não vale, com a sequência seguinte.
    fn gravar(
        &mut self,
        vale: Option<(usize, &Controle)>,
        novo: &Controle,
    ) -> Result<Controle, &'static str> {
        let (onde, novo) = controle::proxima(vale, novo);
        let controle = self.particoes.controle.ok_or("sem controle")?;
        let lba = controle
            .bloco_de(COPIA_EM[onde], self.disco.tamanho)
            .ok_or("a copia do controle nao cabe na particao")?;
        let b = self.disco.tamanho as usize;
        self.buffer[..b].fill(0);
        self.buffer[..atualizacao::TAM_SETOR].copy_from_slice(&controle::escrever(&novo));
        self.disco.escrever(lba, &self.buffer[..b])?;
        Ok(novo)
    }

    /// O cabeçalho de um slot: o resumo e a geração do manifesto, se ele é
    /// legível.
    fn cabecalho(&mut self, s: Slot) -> Option<([u8; TAM_RESUMO], u64)> {
        let faixa = self.particoes.slot(s)?;
        let lba = faixa.bloco_de(0, self.disco.tamanho)?;
        self.disco
            .ler(lba, &mut self.buffer[..TAM_CABECALHO])
            .ok()?;
        let c = cabecalho::ler(&self.buffer[..TAM_CABECALHO]).ok()?;
        let m = Manifesto::ler(c.manifesto).ok()?;
        Some((resumo_do_manifesto(c.manifesto), m.geracao))
    }

    /// Lê e confere o kernel de um slot.
    fn carregar(&mut self, b: &Boot) -> Result<Lido, &'static str> {
        let faixa = self.particoes.slot(b.slot).ok_or("o slot nao existe")?;
        let tam = self.disco.tamanho;
        let lba = faixa.bloco_de(0, tam).ok_or("o slot e vazio")?;
        self.disco.ler(lba, &mut self.buffer[..TAM_CABECALHO])?;
        let c = cabecalho::ler(&self.buffer[..TAM_CABECALHO])?;
        let resumo = resumo_do_manifesto(c.manifesto);
        if b.manifesto.is_some_and(|m| m != resumo) {
            return Err("o manifesto do slot nao e o que o controle diz");
        }
        let m = Manifesto::ler(c.manifesto).map_err(|(_, motivo)| motivo)?;
        if m.arquitetura != ARQUITETURA {
            return Err("o manifesto do slot e de outra arquitetura");
        }
        if m.kernel.tamanho > crate::MAIOR_KERNEL {
            return Err("o kernel do slot passa do teto do iniciador");
        }
        let cabe = cabecalho::tamanho_da_imagem(&m)
            .zip(faixa.bytes(tam))
            .is_some_and(|(imagem, slot)| imagem <= slot);
        if !cabe {
            return Err("a imagem do manifesto nao cabe no slot");
        }
        let esperado = m.kernel.resumo;
        let tamanho = m.kernel.tamanho as usize;
        let inicio = faixa
            .bloco_de(KERNEL_EM, tam)
            .ok_or("o kernel nao cabe no slot")?;
        let kernel = paginas(self.boot, (tamanho as u64).next_multiple_of(tam))?;
        let mut r = Resumidor::novo();
        let mut crc = crate::crc32::Parcial::nova();
        let mut lidos = 0usize;
        let total = (tamanho as u64).next_multiple_of(tam) as usize;
        while lidos < total {
            let n = (total - lidos).min(PEDACO);
            if let Err(e) = self
                .disco
                .ler(inicio + (lidos as u64) / tam, &mut kernel[lidos..lidos + n])
            {
                devolver(self.boot, kernel);
                return Err(e);
            }
            let util = n.min(tamanho - lidos.min(tamanho));
            r.somar(&kernel[lidos..lidos + util]);
            crc.somar(&kernel[lidos..lidos + util]);
            lidos += n;
        }
        if r.terminar() != esperado {
            devolver(self.boot, kernel);
            return Err("o kernel do slot nao bate com o manifesto");
        }
        // O kernel confere com o manifesto assinado — e ainda pode não ser
        // um kernel desta máquina: o de um build quebrado, publicado assim.
        // A forma do ELF é conferida aqui, e não só depois, na carga: uma
        // tentativa que falha aqui volta para o slot bom neste mesmo boot,
        // e uma que falhasse na carga pararia a máquina até alguém ligá-la
        // de novo.
        if let Err(motivo) = crate::elf_carregavel(&kernel[..tamanho]) {
            devolver(self.boot, kernel);
            return Err(motivo);
        }
        relatar!(
            "slot {}: kernel lido, {} bytes em {} paginas a partir de {:#x}, crc {:#010x}; blake2s confere; modo {}, geracao {}, versao {}",
            b.slot.nome(),
            tamanho,
            kernel.len() / efi::PAGINA as usize,
            kernel.as_ptr() as u64,
            crc.terminar(),
            b.modo.nome(),
            m.geracao,
            m.versao
        );
        let kernel: &'static [u8] = &kernel[..tamanho];
        Ok(Lido {
            kernel,
            arranque: protocolo::Arranque {
                slot: b.slot.byte(),
                modo: b.modo.byte(),
                reservado: [0; 6],
                manifesto: resumo,
            },
        })
    }

    /// Tenta um boot; a falha vira uma linha do relatório e `None`.
    fn tentar(&mut self, b: &Boot) -> Option<Lido> {
        match self.carregar(b) {
            Ok(l) => Some(l),
            Err(motivo) => {
                relatar!(
                    "ERRO slot {} ({}): {}",
                    b.slot.nome(),
                    b.modo.nome(),
                    motivo
                );
                None
            }
        }
    }
}

fn descrever(i: usize, c: &Controle) {
    relatar!(
        "atualizacao: controle da copia {}, sequencia {}, bom {}, tentativa {}, restantes {}{}",
        i,
        c.sequencia,
        c.bom.nome(),
        c.tentativa.map_or("nenhuma", Slot::nome),
        c.restantes,
        if c.sintetizado { ", sintetizado" } else { "" }
    );
}

/// O kernel pelos slots. `Ok(None)` se o disco não tem a atualização.
pub fn carregar(
    imagem: efi::Handle,
    boot: &efi::ServicosDeBoot,
) -> Result<Option<Lido>, &'static str> {
    let Some(disco) = achar_o_disco(imagem, boot)? else {
        return Ok(None);
    };
    let buffer = paginas(boot, efi::PAGINA)?;
    let particoes = achar_as_particoes(&disco, buffer)?;
    if particoes == Particoes::default() {
        devolver(boot, buffer);
        relatar!("atualizacao: o disco nao tem as particoes; o kernel vem da esp");
        return Ok(None);
    }
    if !particoes.completas() {
        return Err("o disco tem so parte das particoes da atualizacao");
    }
    let mut s = Slots {
        disco,
        particoes,
        boot,
        buffer,
    };

    let mut valido = s.controle_valido();
    if valido.is_none() {
        let cabecalhos = [s.cabecalho(Slot::A), s.cabecalho(Slot::B)];
        relatar!("atualizacao: nenhuma copia do controle e integra; sintetizando pelos slots");
        if let Some(c) = controle::sintetizar(cabecalhos) {
            match s.gravar(None, &c) {
                Ok(_) => valido = s.controle_valido(),
                Err(motivo) => relatar!("ERRO o controle sintetizado nao gravou: {}", motivo),
            }
        }
    }

    if let Some((i, c)) = valido {
        descrever(i, &c);
        let bom = match controle::planejar(&c) {
            Plano::Tentar {
                gravar,
                tentativa,
                bom,
            } => {
                match s.gravar(Some((i, &c)), &gravar) {
                    Ok(gravado) => {
                        relatar!(
                            "atualizacao: tentativa do slot {}, restam {}",
                            tentativa.slot.nome(),
                            gravado.restantes
                        );
                        if let Some(l) = s.tentar(&tentativa) {
                            return Ok(Some(l));
                        }
                        let vale = s.controle_valido();
                        if let Some((j, atual)) = vale
                            && let Err(motivo) =
                                s.gravar(Some((j, &atual)), &controle::carga_recusada(&atual))
                        {
                            relatar!("ERRO a recusa da carga nao gravou: {}", motivo);
                        }
                    }
                    // Sem a conta gravada, nada de tentativa: um kernel novo
                    // que travasse voltaria a ser tentado para sempre.
                    Err(motivo) => relatar!("ERRO a conta da tentativa nao gravou: {}", motivo),
                }
                bom
            }
            Plano::Bootar(bom) => bom,
        };
        if let Some(l) = s.tentar(&bom) {
            return Ok(Some(l));
        }
    }

    // Nada do controle carregou: os slots, sem gravar nada — ver
    // `atualizacao::controle::Plano`.
    let geracoes = [s.cabecalho(Slot::A), s.cabecalho(Slot::B)].map(|c| c.map(|(_, g)| g));
    for slot in controle::ordem_sem_controle(geracoes).into_iter().flatten() {
        let b = Boot {
            slot,
            manifesto: None,
            modo: Modo::SemControle,
        };
        if let Some(l) = s.tentar(&b) {
            return Ok(Some(l));
        }
    }
    Err("nenhum slot carregou")
}
