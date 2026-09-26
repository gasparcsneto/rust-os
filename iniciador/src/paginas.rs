//! As tabelas de tradução que o kernel vai herdar.
//!
//! # O que o firmware deixa, e por que não serve
//!
//! A UEFI entrega a máquina com paginação ligada e **identidade**: endereço
//! virtual igual ao físico, tudo na metade baixa. O Duke não mora lá. A
//! primeira regra do mapa dele é que a metade alta é do kernel e a baixa é do
//! usuário, e ela existe para que uma tabela por processo possa ser montada
//! copiando as entradas de topo do kernel.
//!
//! Então o iniciador monta um mapa novo e o instala. O que ele precisa conter
//! está em [`crate::mapa`]; o que este módulo faz é a mecânica de escrevê-lo.
//!
//! # A armadilha da troca de `CR3`
//!
//! No instante seguinte ao `mov cr3`, o processador busca a **próxima
//! instrução** — que está no código do iniciador, num endereço baixo, porque
//! é onde o firmware o carregou. Se o mapa novo não descrever esse endereço,
//! a busca falha, e uma falha de página sem tabela de exceções instalada é
//! um triple fault: a máquina reinicia, sem nada na tela.
//!
//! Por isso o mapa novo também tem a identidade da RAM. Ela não é para o
//! kernel — é para os poucos ciclos entre a troca e o salto.
//!
//! # Por que quatro níveis escritos à mão
//!
//! Porque é a estrutura do processador, não uma abstração: quatro tabelas de
//! 512 entradas, cada nível consumindo nove bits do endereço. Escrevê-la é
//! transcrever o que o manual descreve, e é a mesma decisão que o resto deste
//! programa toma sobre as tabelas da UEFI.
//!
//! O que **não** se escreve à mão aqui é a conferência: depois de montado, o
//! mapa é percorrido pelo próprio [`Tabelas::traduzir`], e o relatório diz em
//! que endereço físico cada região caiu. Um mapa montado errado produz um
//! número errado ali, e não um reboot silencioso na etapa seguinte.

use crate::efi;

/// Quantas entradas cada tabela tem, em qualquer um dos quatro níveis.
const ENTRADAS: usize = 512;

/// Uma página, e o tamanho de cada tabela.
pub const PAGINA: u64 = 4096;

/// Uma página grande, que o nível dois pode descrever sem um nível abaixo.
pub const PAGINA_GRANDE: u64 = 2 * 1024 * 1024;

/// Os bits de uma entrada.
///
/// O bit de usuário não está aqui de propósito: tudo que este iniciador
/// mapeia é do kernel, e uma constante disponível é um convite a usá-la. Ele
/// entra no dia em que houver um mapeamento de userspace para fazer — e esse
/// dia é do kernel, não do bootloader.
pub mod bit {
    /// A entrada descreve alguma coisa. Sem ele, o resto é ignorado.
    pub const PRESENTE: u64 = 1 << 0;
    /// Escrita permitida.
    pub const ESCRITA: u64 = 1 << 1;
    /// No nível dois ou três, a entrada é uma página grande em vez de um
    /// ponteiro para a tabela de baixo.
    pub const GRANDE: u64 = 1 << 7;
    /// Execução proibida. Depende de `EFER.NXE`, ligado em [`super::ligar_nx`].
    pub const NAO_EXECUTA: u64 = 1 << 63;
}

/// A máscara que isola o endereço físico dentro de uma entrada.
///
/// Os doze bits de baixo são as permissões, e os de cima são reservados ou
/// do bit de não-execução. Somar um endereço sem alinhá-lo a uma página
/// escreveria permissões por acidente — e é por isso que cada mapeamento
/// confere o alinhamento em vez de mascará-lo.
const ENDERECO: u64 = 0x000F_FFFF_FFFF_F000;

/// Quantas páginas o iniciador reserva para as tabelas.
///
/// Cento e vinte e oito, meio mebibyte. O mapa deste kernel usa menos de
/// vinte; a folga é para não descobrir o teto no dia em que ele crescer.
/// Estourar é um erro relatado, e não um mapa pela metade.
const PAGINAS_PARA_TABELAS: usize = 128;

/// Um mapa de tradução em construção.
pub struct Tabelas {
    /// O endereço físico da tabela de topo, que vai para o `CR3`.
    raiz: u64,
    /// O bloco reservado para as tabelas, e quanto dele já saiu.
    bloco: u64,
    usadas: usize,
}

impl Tabelas {
    /// Reserva o espaço das tabelas e cria a de topo, vazia.
    pub fn novas(boot: &efi::ServicosDeBoot) -> Result<Tabelas, &'static str> {
        let mut bloco = 0u64;
        // SAFETY: os argumentos são os documentados, e `bloco` é uma local
        // que recebe o endereço.
        let status = unsafe {
            (boot.alocar_paginas)(
                efi::ALOCAR_QUALQUER,
                efi::memoria::DADOS_DO_CARREGADOR,
                PAGINAS_PARA_TABELAS,
                &mut bloco,
            )
        };
        if efi::deu_errado(status) || bloco == 0 {
            return Err("o firmware recusou as paginas das tabelas");
        }

        let mut tabelas = Tabelas {
            raiz: 0,
            bloco,
            usadas: 0,
        };
        tabelas.raiz = tabelas.pagina_zerada()?;
        Ok(tabelas)
    }

    /// O valor que vai para o `CR3`.
    pub fn raiz(&self) -> u64 {
        self.raiz
    }

    /// Quantas páginas de tabela foram usadas até agora.
    pub fn paginas_usadas(&self) -> usize {
        self.usadas
    }

    /// Tira mais uma página do bloco, já zerada.
    ///
    /// Zerar é obrigatório: uma entrada com lixo tem o bit de presença ligado
    /// por acaso metade das vezes, e aponta para um endereço qualquer.
    fn pagina_zerada(&mut self) -> Result<u64, &'static str> {
        if self.usadas >= PAGINAS_PARA_TABELAS {
            return Err("as paginas reservadas para as tabelas acabaram");
        }
        let endereco = self.bloco + (self.usadas as u64) * PAGINA;
        self.usadas += 1;

        // SAFETY: a página veio do bloco que o firmware reservou para nós, e
        // ninguém mais a tem. A UEFI mapeia a memória por identidade, então o
        // endereço físico também é o virtual enquanto estamos sob ela.
        unsafe { core::ptr::write_bytes(endereco as *mut u8, 0, PAGINA as usize) };
        Ok(endereco)
    }

    /// Lê uma entrada de uma tabela.
    ///
    /// # Safety
    /// `tabela` precisa ser o endereço de uma tabela deste mapa.
    unsafe fn ler(tabela: u64, indice: usize) -> u64 {
        // SAFETY: delegada a quem chama; o índice é sempre `& 511`.
        unsafe { core::ptr::read_volatile((tabela as *const u64).add(indice)) }
    }

    /// # Safety
    /// `tabela` precisa ser o endereço de uma tabela deste mapa.
    unsafe fn escrever(tabela: u64, indice: usize, valor: u64) {
        // SAFETY: delegada a quem chama.
        unsafe { core::ptr::write_volatile((tabela as *mut u64).add(indice), valor) }
    }

    /// Desce um nível, criando a tabela de baixo se ela não existir.
    ///
    /// As permissões de uma entrada intermediária são a **união** do que ela
    /// cobre: o processador exige que todos os níveis permitam o acesso. Por
    /// isso o caminho é sempre gravável e executável, e quem decide é a folha.
    fn descer(&mut self, tabela: u64, indice: usize) -> Result<u64, &'static str> {
        // SAFETY: `tabela` é deste mapa e `indice` cabe.
        let entrada = unsafe { Tabelas::ler(tabela, indice) };
        if entrada & bit::PRESENTE != 0 {
            if entrada & bit::GRANDE != 0 {
                // Uma página grande já ocupa esta faixa. Subdividi-la em
                // silêncio esconderia um mapa que se sobrepõe a si mesmo.
                return Err("uma pagina grande ja cobre esta faixa");
            }
            return Ok(entrada & ENDERECO);
        }

        let nova = self.pagina_zerada()?;
        // SAFETY: idem.
        unsafe { Tabelas::escrever(tabela, indice, nova | bit::PRESENTE | bit::ESCRITA) };
        Ok(nova)
    }

    /// Mapeia uma página de 4 KiB.
    pub fn mapear(&mut self, virtual_: u64, fisico: u64, bits: u64) -> Result<(), &'static str> {
        self.mapear_em(virtual_, fisico, bits, PAGINA)
    }

    /// Mapeia uma página de 2 MiB.
    ///
    /// Vale para faixas grandes e uniformes — a memória física inteira, por
    /// exemplo. Uma entrada em vez de quinhentas e doze, e uma tabela a menos
    /// por gibibyte.
    pub fn mapear_grande(
        &mut self,
        virtual_: u64,
        fisico: u64,
        bits: u64,
    ) -> Result<(), &'static str> {
        self.mapear_em(virtual_, fisico, bits, PAGINA_GRANDE)
    }

    fn mapear_em(
        &mut self,
        virtual_: u64,
        fisico: u64,
        bits: u64,
        tamanho: u64,
    ) -> Result<(), &'static str> {
        if !virtual_.is_multiple_of(tamanho) || !fisico.is_multiple_of(tamanho) {
            return Err("mapeamento desalinhado");
        }
        // Um endereço com os bits de cima em desacordo com o bit 47 não é
        // canônico, e o processador recusa até carregá-lo num registrador.
        // Recusar aqui diz onde o erro está; deixar passar dá uma exceção de
        // proteção geral três funções adiante.
        if !canonico(virtual_) {
            return Err("endereco virtual nao canonico");
        }

        let indices = [
            (virtual_ >> 39) as usize & (ENTRADAS - 1),
            (virtual_ >> 30) as usize & (ENTRADAS - 1),
            (virtual_ >> 21) as usize & (ENTRADAS - 1),
            (virtual_ >> 12) as usize & (ENTRADAS - 1),
        ];

        // Quantos níveis descer antes de escrever a folha: uma página de
        // 4 KiB mora no nível quatro, uma de 2 MiB no nível três.
        let ate = if tamanho == PAGINA { 3 } else { 2 };
        let mut tabela = self.raiz;
        for indice in indices.iter().take(ate) {
            tabela = self.descer(tabela, *indice)?;
        }

        let folha = indices[ate];
        // SAFETY: `tabela` saiu do caminho construído acima.
        let atual = unsafe { Tabelas::ler(tabela, folha) };
        if atual & bit::PRESENTE != 0 {
            // Mapear duas vezes o mesmo endereço virtual é um erro de quem
            // montou o mapa, e o segundo ganharia calado. Num bootloader isso
            // vira "o kernel às vezes boota".
            return Err("este endereco virtual ja esta mapeado");
        }

        let grande = if tamanho == PAGINA { 0 } else { bit::GRANDE };
        // SAFETY: idem.
        unsafe { Tabelas::escrever(tabela, folha, fisico | bits | grande | bit::PRESENTE) };
        Ok(())
    }

    /// Mapeia uma faixa inteira, escolhendo o tamanho de página.
    ///
    /// Usa páginas grandes onde os dois lados estão alinhados e ainda cabe
    /// uma, e de 4 KiB no resto. É o que permite mapear a memória física
    /// inteira com dezenas de entradas em vez de dezenas de milhares.
    pub fn mapear_faixa(
        &mut self,
        virtual_: u64,
        fisico: u64,
        bytes: u64,
        bits: u64,
    ) -> Result<(), &'static str> {
        let mut feito = 0u64;
        while feito < bytes {
            let v = virtual_ + feito;
            let f = fisico + feito;
            let cabe_grande = v.is_multiple_of(PAGINA_GRANDE)
                && f.is_multiple_of(PAGINA_GRANDE)
                && bytes - feito >= PAGINA_GRANDE;

            if cabe_grande {
                self.mapear_grande(v, f, bits)?;
                feito += PAGINA_GRANDE;
            } else {
                self.mapear(v, f, bits)?;
                feito += PAGINA;
            }
        }
        Ok(())
    }

    /// Percorre o mapa como o processador percorreria.
    ///
    /// # Por que isto existe
    ///
    /// Porque é a única forma de saber que o mapa está certo **antes** de
    /// instalá-lo. Depois do `mov cr3` não há relatório: ou a máquina segue,
    /// ou ela reinicia sem dizer nada.
    ///
    /// A leitura é independente da escrita de propósito — ela desce pelos
    /// índices do endereço, como o hardware faz, em vez de consultar uma
    /// lista do que foi mapeado. Uma lista concordaria com quem a preencheu.
    pub fn traduzir(&self, virtual_: u64) -> Option<u64> {
        if !canonico(virtual_) {
            return None;
        }

        let mut tabela = self.raiz;
        let deslocamentos = [39u32, 30, 21, 12];

        for (nivel, deslocamento) in deslocamentos.iter().enumerate() {
            let indice = (virtual_ >> deslocamento) as usize & (ENTRADAS - 1);
            // SAFETY: `tabela` é a raiz ou saiu de uma entrada presente.
            let entrada = unsafe { Tabelas::ler(tabela, indice) };
            if entrada & bit::PRESENTE == 0 {
                return None;
            }

            // Uma página grande encerra a descida, e o que sobra do endereço
            // é o deslocamento dentro dela.
            if nivel > 0 && entrada & bit::GRANDE != 0 {
                let tamanho = 1u64 << deslocamento;
                return Some((entrada & ENDERECO) + (virtual_ & (tamanho - 1)));
            }
            tabela = entrada & ENDERECO;
        }

        Some(tabela + (virtual_ & (PAGINA - 1)))
    }
}

/// Se um endereço virtual é canônico: os bits 63..48 iguais ao 47.
fn canonico(endereco: u64) -> bool {
    let alto = endereco >> 47;
    alto == 0 || alto == 0x1_FFFF
}

/// Liga a proibição de execução no `EFER`.
///
/// Sem este bit, o bit 63 das entradas é **reservado** — e uma entrada com um
/// bit reservado ligado não é ignorada: ela causa falha de página. O mapa
/// inteiro deixaria de funcionar por causa de uma permissão que se queria
/// mais restritiva.
///
/// O firmware costuma deixá-lo ligado, e ligar de novo não custa nada.
/// Depender de um costume é que custa.
pub fn ligar_nx() {
    const EFER: u32 = 0xC000_0080;
    const NXE: u64 = 1 << 11;

    // SAFETY: o MSR do EFER existe em todo x86_64, e ligar o NXE é a operação
    // documentada para tornar o bit 63 das entradas significativo. Rodamos em
    // núcleo único e antes de qualquer tabela nossa entrar em uso.
    unsafe {
        let (baixo, alto): (u32, u32);
        core::arch::asm!("rdmsr", in("ecx") EFER, out("eax") baixo, out("edx") alto,
                         options(nomem, nostack, preserves_flags));
        let valor = ((alto as u64) << 32 | baixo as u64) | NXE;
        core::arch::asm!("wrmsr", in("ecx") EFER, in("eax") valor as u32,
                         in("edx") (valor >> 32) as u32,
                         options(nomem, nostack, preserves_flags));
    }
}
