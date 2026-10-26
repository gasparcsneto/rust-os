//! O disco NVMe: o de uma máquina de verdade — e o de quase toda nuvem.
//!
//! Só o que é do NVMe: o controlador, as filas, os comandos. As regras de
//! todo disco (as janelas de escrita, a recusa de um disco sem descarga, a
//! conferência da faixa, a tranca) moram em [`crate::bloco`], que confere
//! antes de o pedido chegar aqui — as mesmas do virtio-blk.
//!
//! # O que este driver fala
//!
//! O NVMe pelo PCI, o conjunto de comandos NVM: um controlador com os
//! registradores no BAR 0, e dois pares de filas — o de administração e um
//! de entrada e saída —, cada par uma fila de submissão (comandos de 64
//! bytes, que o driver escreve) e uma de conclusão (entradas de 16 bytes,
//! que o controlador escreve). Um comando de cada vez, como o virtio-blk:
//! quem chama espera a resposta sob a tranca do disco, e por isso dezesseis
//! entradas por fila sobram.
//!
//! # O que ele não fala
//!
//! - Interrupção: a conclusão é esperada em laço, pelo bit de fase, como no
//!   virtio-blk e pela mesma razão — os chamadores são síncronos. O
//!   controlador fica sem interrupção de pino (o bit do comando do PCI) e
//!   com os vetores mascarados: uma linha que ele dividisse com outro
//!   dispositivo não ficaria presa a um aviso que ninguém atende.
//! - O que não é o primeiro namespace, um bloco lógico que não seja de 512
//!   bytes, metadados por bloco, várias filas: recusado ao ligar, com o
//!   motivo no log, ou não usado.
//!
//! # Durabilidade
//!
//! Um controlador com cache de escrita volátil (o `VWC` do identificar)
//! confirma a escrita antes de gravá-la: a descarga é o comando `Flush`. Um
//! sem cache volátil grava antes de confirmar, e a descarga não tem o que
//! fazer. Os dois prometem o que a camada de bloco pede. E antes de a
//! energia acabar — o `system.poweroff` e o `system.reboot` — o controlador
//! recebe o aviso de desligamento normal, como a especificação pede: sem
//! ele, a próxima vez ele conta um desligamento inseguro.

extern crate alloc;

use core::sync::atomic::{Ordering, fence};

/// A classe, a subclasse e a interface de um controlador NVMe no PCI.
const CLASSE: u8 = 0x01;
const SUBCLASSE: u8 = 0x08;
const INTERFACE: u8 = 0x02;

// Os registradores do controlador, no BAR 0.
const CAP: usize = 0x00;
const VS: usize = 0x08;
const INTMS: usize = 0x0C;
const CC: usize = 0x14;
const CSTS: usize = 0x1C;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
/// Onde começam as campainhas: a da submissão da fila `y` em
/// `PORTAS + 2y × passo`, a da conclusão em `PORTAS + (2y + 1) × passo`.
const PORTAS: usize = 0x1000;

// A configuração do controlador (CC).
const CC_LIGADO: u32 = 1;
/// O conjunto de comandos NVM (0), páginas de 4 KiB (0), arbitragem em
/// rodízio (0): os três campos em zero.
const CC_NVM_4K_RODIZIO: u32 = 0;
/// Entradas de submissão de 2⁶ = 64 bytes e de conclusão de 2⁴ = 16.
const CC_TAMANHOS_DAS_ENTRADAS: u32 = (6 << 16) | (4 << 20);
const CC_DESLIGAMENTO_NORMAL: u32 = 1 << 14;
const CC_DESLIGAMENTO_MASCARA: u32 = 3 << 14;

// O estado do controlador (CSTS).
const CSTS_PRONTO: u32 = 1;
const CSTS_FALHA_FATAL: u32 = 1 << 1;
const CSTS_DESLIGAMENTO_MASCARA: u32 = 3 << 2;
const CSTS_DESLIGAMENTO_FEITO: u32 = 2 << 2;

// Os comandos de administração.
const CRIAR_FILA_DE_SUBMISSAO: u32 = 0x01;
const CRIAR_FILA_DE_CONCLUSAO: u32 = 0x05;
const IDENTIFICAR: u32 = 0x06;
const DEFINIR_RECURSO: u32 = 0x09;
/// O recurso "número de filas", que a especificação pede antes de criar a
/// primeira fila de entrada e saída.
const RECURSO_NUMERO_DE_FILAS: u32 = 0x07;
/// O que o identificar devolve: o namespace (0) ou o controlador (1).
const IDENTIFICAR_NAMESPACE: u32 = 0;
const IDENTIFICAR_CONTROLADOR: u32 = 1;

// Os comandos de entrada e saída.
const DESCARREGAR: u32 = 0x00;
const ESCREVER: u32 = 0x01;
const LER: u32 = 0x02;

/// O namespace que este driver usa.
const NAMESPACE: u32 = 1;

/// Quantas entradas cada fila tem — ou menos, se o controlador não tiver
/// tantas. Um comando em voo de cada vez: duas bastariam, e dezesseis
/// custam o mesmo (cabem numa página).
const ENTRADAS: u16 = 16;
const BYTES_DA_SUBMISSAO: usize = 64;
const BYTES_DA_CONCLUSAO: usize = 16;
const _: () = assert!(ENTRADAS as usize * BYTES_DA_SUBMISSAO <= 4096);

/// Quantas páginas de dados um comando leva: as mesmas quatro do
/// virtio-blk, os dezesseis kibibytes da camada de bloco. A primeira vai no
/// PRP1; a segunda, sozinha, no PRP2; três ou quatro, por uma lista.
const PAGINAS_DE_DADOS: usize = 4;
const PAGINA: usize = 4096;
const _: () = assert!(PAGINAS_DE_DADOS * PAGINA == crate::bloco::MAIOR_LEITURA);

/// O tamanho do bloco lógico que este driver aceita: o setor da camada.
const BLOCO_LOGICO: usize = crate::bloco::TAMANHO_DO_SETOR;

/// Quantas voltas esperar por uma conclusão — a mesma conta do virtio-blk,
/// pela mesma razão: a espera roda com as interrupções mascaradas, sem
/// relógio, e uma descarga é um `fsync` no hospedeiro que às vezes demora
/// dezenas de milissegundos. Um tempo esgotado desliga o disco de vez.
const VOLTAS_DE_ESPERA: u32 = 400_000_000;

/// Quantas voltas valem meio segundo, a unidade do tempo de prontidão
/// (`CAP.TO`) que o controlador declara. Cada volta lê um registrador, e
/// uma leitura de registrador emulado custa da ordem de um microssegundo:
/// dois milhões delas passam do meio segundo com folga. É um teto para um
/// controlador quebrado, não uma medida.
const VOLTAS_POR_MEIO_SEGUNDO: u64 = 2_000_000;

/// Uma fila — de administração ou de entrada e saída: a submissão e a
/// conclusão, cada uma uma página.
struct Fila {
    id: u16,
    submissao: u64,
    base_da_submissao: *mut u8,
    conclusao: u64,
    base_da_conclusao: *mut u8,
    /// A próxima entrada de submissão a escrever.
    cauda: u16,
    /// A próxima entrada de conclusão a colher.
    cabeca: u16,
    /// A fase que a próxima conclusão terá: começa em um, e vira a cada
    /// volta inteira da fila — é como o driver distingue uma entrada nova
    /// de uma da volta anterior.
    fase: bool,
}

/// Qual das duas filas.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Qual {
    Administracao,
    EntradaESaida,
}

/// Um controlador NVMe pronto para uso.
struct Nvme {
    /// Onde os registradores estão, no espaço virtual.
    registradores: u64,
    /// A distância entre duas campainhas: `4 << CAP.DSTRD`.
    passo: usize,
    /// O teto das esperas por um estado do controlador.
    voltas_de_estado: u64,
    entradas: u16,
    administracao: Fila,
    entrada_e_saida: Fila,
    /// As páginas de dados, e onde o kernel as alcança.
    dados: [u64; PAGINAS_DE_DADOS],
    bases_de_dados: [*mut u8; PAGINAS_DE_DADOS],
    /// A lista de PRP de um comando de três ou quatro páginas: as páginas
    /// de dados da segunda em diante, fixas.
    lista: u64,
    /// Capacidade, em blocos lógicos de 512 bytes.
    capacidade: u64,
    /// Quantos bytes um comando leva, no máximo: os dezesseis kibibytes, ou
    /// menos, se o `MDTS` do controlador for menor — e então o pedido é
    /// partido aqui.
    maior_ida: usize,
    /// Se o controlador guarda escritas num cache volátil.
    cache_volatil: bool,
    /// Se o namespace está protegido contra escrita.
    somente_leitura: bool,
    /// Se o controlador ainda pode ser usado — ver o campo de mesmo nome do
    /// virtio-blk: um comando que estourou o tempo continua pendente, e o
    /// seguinte correria com ele.
    vivo: bool,
    /// O identificador do próximo comando.
    proximo: u16,
}

// SAFETY: os ponteiros são para frames e registradores de propriedade
// exclusiva deste controlador, alocados na construção e nunca
// compartilhados; o acesso passa pela tranca da camada de bloco. É o
// ponteiro cru que impede a derivação automática, não uma restrição real.
unsafe impl Send for Nvme {}

/// Só na suíte: um segundo NVMe, quando o disco do sistema é outro — o da
/// máquina dos testes, onde o disco do sistema é o virtio-blk. É o que os
/// casos do NVMe usam, com as regras da camada por cima.
#[cfg(feature = "modo-teste")]
static SEGUNDO: crate::trava::Mutex<Option<crate::bloco::Disco>> = crate::trava::Mutex::new(None);

impl Nvme {
    fn ler32(&self, registrador: usize) -> u32 {
        // SAFETY: o registrador está dentro do BAR 0 que `ligar` mapeou, em
        // memória de dispositivo, e é alinhado a quatro bytes.
        unsafe {
            core::ptr::read_volatile((self.registradores as usize + registrador) as *const u32)
        }
    }

    fn escrever32(&self, registrador: usize, valor: u32) {
        // SAFETY: como em `ler32`.
        unsafe {
            core::ptr::write_volatile(
                (self.registradores as usize + registrador) as *mut u32,
                valor,
            )
        }
    }

    /// Um registrador de 64 bits, como dois de 32 — a metade baixa primeiro,
    /// como a especificação permite em qualquer controlador.
    fn ler64(&self, registrador: usize) -> u64 {
        u64::from(self.ler32(registrador)) | (u64::from(self.ler32(registrador + 4)) << 32)
    }

    fn escrever64(&self, registrador: usize, valor: u64) {
        self.escrever32(registrador, valor as u32);
        self.escrever32(registrador + 4, (valor >> 32) as u32);
    }

    /// Espera o estado do controlador mostrar `valor` nos bits de
    /// `mascara`. Uma falha fatal encerra a espera na hora.
    fn esperar_estado(&self, mascara: u32, valor: u32) -> Result<(), &'static str> {
        for _ in 0..self.voltas_de_estado {
            let csts = self.ler32(CSTS);
            if csts & CSTS_FALHA_FATAL != 0 && mascara != CSTS_FALHA_FATAL {
                return Err("o controlador declarou falha fatal");
            }
            if csts & mascara == valor {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("o controlador nao mudou de estado no tempo que ele mesmo declara")
    }

    /// Liga o controlador encontrado no barramento.
    fn ligar(d: &crate::pci::Dispositivo) -> Result<Nvme, &'static str> {
        let regiao = d
            .regiao(0)
            .ok_or("o BAR 0 do controlador nao tem endereco")?;
        if regiao.tamanho < (PORTAS + 4 * 8) as u64 {
            return Err("o BAR 0 do controlador e pequeno demais para as campainhas");
        }
        let registradores = crate::mmio::mapear(regiao.base, regiao.tamanho)?;

        // Os frames: as quatro páginas das filas, a lista de PRP e as de
        // dados. Uma falha no meio devolve os que já vieram — nada foi
        // entregue ao controlador ainda.
        let mut frames = [0u64; 5 + PAGINAS_DE_DADOS];
        let mut quantos = 0;
        while quantos < frames.len() {
            let Some(frame) = crate::frames::alocar() else {
                break;
            };
            frames[quantos] = frame;
            quantos += 1;
        }
        if quantos != frames.len() {
            for frame in &frames[..quantos] {
                crate::frames::liberar(*frame);
            }
            return Err("sem frames para as filas e os dados");
        }
        for frame in &frames {
            // SAFETY: o frame acabou de vir do alocador, é deste driver, e
            // `acesso_fisico` o alcança inteiro. Zerado porque o alocador
            // não zera, e uma fila de conclusão com lixo teria fases velhas.
            unsafe { core::ptr::write_bytes(crate::arch::acesso_fisico(*frame), 0, PAGINA) };
        }
        let fila = |id: u16, submissao: u64, conclusao: u64| Fila {
            id,
            submissao,
            base_da_submissao: crate::arch::acesso_fisico(submissao),
            conclusao,
            base_da_conclusao: crate::arch::acesso_fisico(conclusao),
            cauda: 0,
            cabeca: 0,
            fase: true,
        };
        let mut dados = [0u64; PAGINAS_DE_DADOS];
        dados.copy_from_slice(&frames[5..]);
        let mut bases_de_dados = [core::ptr::null_mut(); PAGINAS_DE_DADOS];
        for (base, frame) in bases_de_dados.iter_mut().zip(&dados) {
            *base = crate::arch::acesso_fisico(*frame);
        }
        let mut nvme = Nvme {
            registradores,
            passo: 4,
            voltas_de_estado: VOLTAS_POR_MEIO_SEGUNDO,
            entradas: ENTRADAS,
            administracao: fila(0, frames[0], frames[1]),
            entrada_e_saida: fila(1, frames[2], frames[3]),
            dados,
            bases_de_dados,
            lista: frames[4],
            capacidade: 0,
            maior_ida: crate::bloco::MAIOR_LEITURA,
            cache_volatil: true,
            somente_leitura: false,
            vivo: true,
            proximo: 0,
        };

        // As capacidades: o conjunto NVM, páginas de 4 KiB, o tamanho das
        // filas, o passo das campainhas e o tempo de prontidão.
        let cap = nvme.ler64(CAP);
        if (cap >> 37) & 1 == 0 {
            return Err("o controlador nao fala o conjunto de comandos NVM");
        }
        if (cap >> 48) & 0xF != 0 {
            return Err("a menor pagina do controlador passa de 4 KiB");
        }
        let maior_fila = (cap & 0xFFFF) as u32 + 1;
        if maior_fila < 2 {
            return Err("o controlador declara filas de uma entrada");
        }
        nvme.entradas = ENTRADAS.min(maior_fila.min(u32::from(u16::MAX)) as u16);
        nvme.passo = 4 << ((cap >> 32) & 0xF);
        // A última campainha usada: a da conclusão da fila 1.
        if PORTAS + 3 * nvme.passo + 4 > regiao.tamanho as usize {
            return Err("as campainhas da fila de entrada e saida passam do BAR 0");
        }
        nvme.voltas_de_estado = (((cap >> 24) & 0xFF) + 1) * VOLTAS_POR_MEIO_SEGUNDO;

        // Desligado antes de configurar: o firmware pode tê-lo deixado
        // ligado, com filas dele.
        if nvme.ler32(CC) & CC_LIGADO != 0 {
            nvme.escrever32(CC, 0);
        }
        nvme.esperar_estado(CSTS_PRONTO, 0)?;

        let n = u32::from(nvme.entradas - 1);
        nvme.escrever32(AQA, (n << 16) | n);
        nvme.escrever64(ASQ, nvme.administracao.submissao);
        nvme.escrever64(ACQ, nvme.administracao.conclusao);

        // A mestria de barramento antes de ligar: depois do `CC.EN` o
        // controlador segue os ponteiros que acabou de receber. E sem
        // interrupção de pino — ver o cabeçalho.
        crate::pci::habilitar_mestre_por_consulta(d);

        nvme.escrever32(CC, CC_LIGADO | CC_NVM_4K_RODIZIO | CC_TAMANHOS_DAS_ENTRADAS);
        nvme.esperar_estado(CSTS_PRONTO, CSTS_PRONTO)?;
        // E os vetores mascarados, além do bit do PCI.
        nvme.escrever32(INTMS, u32::MAX);

        // O controlador: o maior comando, o cache volátil, o modelo.
        nvme.identificar(IDENTIFICAR_CONTROLADOR, 0)?;
        // Copiado da página antes de mexer no controlador: ela é dele.
        let (mdts, cache_volatil, namespaces, modelo, serie) = {
            let c = nvme.pagina_de_dados(0);
            let mut modelo = [0u8; 40];
            modelo.copy_from_slice(&c[24..64]);
            let mut serie = [0u8; 20];
            serie.copy_from_slice(&c[4..24]);
            let namespaces = u32::from_le_bytes([c[516], c[517], c[518], c[519]]);
            (c[77], c[525] & 1 != 0, namespaces, modelo, serie)
        };
        if mdts != 0 {
            let teto = PAGINA.checked_shl(u32::from(mdts)).unwrap_or(usize::MAX);
            nvme.maior_ida = nvme.maior_ida.min(teto);
        }
        nvme.cache_volatil = cache_volatil;
        if namespaces == 0 {
            return Err("o controlador nao tem namespace nenhum");
        }

        // O namespace: o tamanho, o formato do bloco e a proteção.
        nvme.identificar(IDENTIFICAR_NAMESPACE, NAMESPACE)?;
        let (tamanho, formato, formatos, lbaf, atributos) = {
            let ns = nvme.pagina_de_dados(0);
            let formato = usize::from(ns[26] & 0xF);
            let mut lbaf = [0u8; 4];
            lbaf.copy_from_slice(&ns[128 + 4 * formato..128 + 4 * formato + 4]);
            let tamanho =
                u64::from_le_bytes([ns[0], ns[1], ns[2], ns[3], ns[4], ns[5], ns[6], ns[7]]);
            (tamanho, formato, usize::from(ns[25]), lbaf, ns[99])
        };
        if tamanho == 0 {
            return Err("o namespace 1 nao esta ativo");
        }
        if formato > formatos {
            return Err("o namespace aponta um formato de bloco que nao declara");
        }
        let metadados = u16::from_le_bytes([lbaf[0], lbaf[1]]);
        if lbaf[2] != BLOCO_LOGICO.trailing_zeros() as u8 {
            return Err("o bloco logico do namespace nao e de 512 bytes");
        }
        if metadados != 0 {
            return Err("o namespace guarda metadados por bloco");
        }
        if tamanho > u64::MAX / BLOCO_LOGICO as u64 {
            return Err("capacidade que nao cabe em bytes");
        }
        nvme.capacidade = tamanho;
        // O atributo do namespace (NVMe 1.4): protegido contra escrita.
        nvme.somente_leitura = atributos & 1 != 0;

        // Uma fila de entrada e saída: o recurso pedido, a conclusão antes
        // da submissão que aponta para ela.
        let mut recurso = [0u32; 16];
        recurso[0] = DEFINIR_RECURSO;
        recurso[10] = RECURSO_NUMERO_DE_FILAS;
        recurso[11] = 0;
        if let Err(motivo) = nvme.submeter(Qual::Administracao, recurso) {
            if !nvme.vivo {
                return Err(motivo);
            }
            crate::log_warn!("nvme", "o numero de filas nao foi aceito: {}", motivo);
        }
        let mut conclusao = [0u32; 16];
        conclusao[0] = CRIAR_FILA_DE_CONCLUSAO;
        conclusao[6] = nvme.entrada_e_saida.conclusao as u32;
        conclusao[7] = (nvme.entrada_e_saida.conclusao >> 32) as u32;
        conclusao[10] = (n << 16) | u32::from(nvme.entrada_e_saida.id);
        // Contígua, e sem interrupção.
        conclusao[11] = 1;
        nvme.submeter(Qual::Administracao, conclusao)?;
        let mut submissao = [0u32; 16];
        submissao[0] = CRIAR_FILA_DE_SUBMISSAO;
        submissao[6] = nvme.entrada_e_saida.submissao as u32;
        submissao[7] = (nvme.entrada_e_saida.submissao >> 32) as u32;
        submissao[10] = (n << 16) | u32::from(nvme.entrada_e_saida.id);
        // Contígua, presa à conclusão de mesmo número.
        submissao[11] = (u32::from(nvme.entrada_e_saida.id) << 16) | 1;
        nvme.submeter(Qual::Administracao, submissao)?;

        // A lista de PRP: as páginas de dados da segunda em diante.
        let lista = crate::arch::acesso_fisico(nvme.lista) as *mut u64;
        for (i, pagina) in nvme.dados[1..].iter().enumerate() {
            // SAFETY: a lista é uma página deste driver, e três entradas de
            // oito bytes cabem nela.
            unsafe { core::ptr::write_volatile(lista.add(i), pagina.to_le()) };
        }

        let versao = nvme.ler32(VS);
        crate::log_info!(
            "nvme",
            "controlador {}.{}: {} ({}), {} KiB, bloco de 512, ida de {} KiB, cache volatil {}{}",
            versao >> 16,
            (versao >> 8) & 0xFF,
            Texto(&modelo),
            Texto(&serie),
            nvme.capacidade * BLOCO_LOGICO as u64 / 1024,
            nvme.maior_ida / 1024,
            if nvme.cache_volatil { "sim" } else { "nao" },
            if nvme.somente_leitura {
                ", protegido contra escrita"
            } else {
                ""
            }
        );
        Ok(nvme)
    }

    /// A página de dados `i`, inteira, para quem lê o que o controlador
    /// depositou.
    fn pagina_de_dados(&self, i: usize) -> &[u8] {
        // SAFETY: a página é deste driver, tem `PAGINA` bytes, e nenhum
        // comando está em voo — o anterior já foi colhido.
        unsafe { core::slice::from_raw_parts(self.bases_de_dados[i], PAGINA) }
    }

    /// O identificar, para a página de dados zero.
    fn identificar(&mut self, cns: u32, namespace: u32) -> Result<(), &'static str> {
        let mut c = [0u32; 16];
        c[0] = IDENTIFICAR;
        c[1] = namespace;
        c[6] = self.dados[0] as u32;
        c[7] = (self.dados[0] >> 32) as u32;
        c[10] = cns;
        self.submeter(Qual::Administracao, c).map(|_| ())
    }

    /// Escreve `comando` na fila `qual`, toca a campainha e espera a
    /// conclusão. Devolve a palavra zero dela.
    fn submeter(&mut self, qual: Qual, mut comando: [u32; 16]) -> Result<u32, &'static str> {
        if !self.vivo {
            return Err("o disco parou de responder e foi desligado");
        }
        let cid = self.proximo;
        self.proximo = self.proximo.wrapping_add(1);
        comando[0] |= u32::from(cid) << 16;
        let entradas = self.entradas;
        let passo = self.passo;
        let fila = match qual {
            Qual::Administracao => &mut self.administracao,
            Qual::EntradaESaida => &mut self.entrada_e_saida,
        };
        let entrada =
            fila.base_da_submissao
                .wrapping_add(usize::from(fila.cauda) * BYTES_DA_SUBMISSAO) as *mut u32;
        for (i, palavra) in comando.iter().enumerate() {
            // SAFETY: a entrada está dentro da página de submissão desta
            // fila — `cauda` é menor que `entradas`, e as entradas cabem
            // numa página.
            unsafe { core::ptr::write_volatile(entrada.add(i), palavra.to_le()) };
        }
        fila.cauda = (fila.cauda + 1) % entradas;
        let cauda = fila.cauda;
        let id = usize::from(fila.id);
        let cabeca = fila.cabeca;
        let fase = fila.fase;
        let base_da_conclusao = fila.base_da_conclusao;
        // O comando inteiro na memória antes da campainha: é ela que o
        // anuncia, e o controlador lê a entrada depois de vê-la.
        fence(Ordering::SeqCst);
        self.escrever32(PORTAS + 2 * id * passo, u32::from(cauda));

        let conclusao =
            base_da_conclusao.wrapping_add(usize::from(cabeca) * BYTES_DA_CONCLUSAO) as *const u32;
        let mut respondida = None;
        for _ in 0..VOLTAS_DE_ESPERA {
            // SAFETY: a entrada está dentro da página de conclusão desta
            // fila, pela mesma conta da submissão.
            let palavra = unsafe { core::ptr::read_volatile(conclusao.add(3)) };
            if (palavra >> 16) & 1 == u32::from(fase) {
                respondida = Some(palavra);
                break;
            }
            core::hint::spin_loop();
        }
        let Some(palavra) = respondida else {
            self.vivo = false;
            crate::log_error!(
                "nvme",
                "o controlador nao respondeu o comando {:#04x} em {} voltas (estado {:#x}); desligado",
                comando[0] & 0xFF,
                VOLTAS_DE_ESPERA,
                self.ler32(CSTS)
            );
            return Err("o dispositivo nao respondeu");
        };
        // A fase vem antes do resto da entrada: ler o resto antes de a fase
        // ter sido lida de fato devolveria a entrada da volta anterior.
        fence(Ordering::SeqCst);
        // SAFETY: como acima.
        let resultado = unsafe { core::ptr::read_volatile(conclusao) };
        let fila = match qual {
            Qual::Administracao => &mut self.administracao,
            Qual::EntradaESaida => &mut self.entrada_e_saida,
        };
        fila.cabeca = (fila.cabeca + 1) % entradas;
        if fila.cabeca == 0 {
            fila.fase = !fila.fase;
        }
        let cabeca = fila.cabeca;
        self.escrever32(PORTAS + (2 * id + 1) * passo, u32::from(cabeca));
        if palavra & 0xFFFF != u32::from(cid) {
            // O anel deixou de descrever a realidade — ver o mesmo caso no
            // virtio-blk.
            self.vivo = false;
            return Err("dispositivo respondeu um comando que nao pedimos");
        }
        let codigo = (palavra >> 17) & 0xFF;
        let tipo = (palavra >> 25) & 0x7;
        if codigo != 0 || tipo != 0 {
            crate::log_warn!(
                "nvme",
                "o comando {:#04x} voltou com o estado {}/{:#04x}",
                comando[0] & 0xFF,
                tipo,
                codigo
            );
            return Err(match (qual, comando[0] & 0xFF) {
                (Qual::Administracao, _) => "o controlador recusou o comando de administracao",
                (_, LER) => "o dispositivo recusou a leitura",
                (_, ESCREVER) => "o dispositivo recusou a escrita",
                _ => "o dispositivo recusou a descarga",
            });
        }
        Ok(resultado)
    }

    /// Um comando de leitura ou escrita de `bytes` a partir de `setor`,
    /// com as páginas de dados.
    fn ida(&mut self, codigo: u32, setor: u64, bytes: usize) -> Result<(), &'static str> {
        let paginas = bytes.div_ceil(PAGINA);
        let prp2 = match paginas {
            0 | 1 => 0,
            2 => self.dados[1],
            _ => self.lista,
        };
        let mut c = [0u32; 16];
        c[0] = codigo;
        c[1] = NAMESPACE;
        c[6] = self.dados[0] as u32;
        c[7] = (self.dados[0] >> 32) as u32;
        c[8] = prp2 as u32;
        c[9] = (prp2 >> 32) as u32;
        c[10] = setor as u32;
        c[11] = (setor >> 32) as u32;
        // Quantos blocos, contados a partir de zero.
        c[12] = (bytes / BLOCO_LOGICO) as u32 - 1;
        self.submeter(Qual::EntradaESaida, c).map(|_| ())
    }

    /// O que o controlador leu, das páginas de dados para `destino`.
    fn copiar_dos_dados(&self, destino: &mut [u8]) {
        for (pedaco, origem) in destino.chunks_mut(PAGINA).zip(&self.bases_de_dados) {
            // SAFETY: a origem é uma página de dados deste driver, que o
            // controlador acabou de preencher com pelo menos `pedaco.len()`
            // bytes; as regiões não se sobrepõem.
            unsafe { core::ptr::copy_nonoverlapping(*origem, pedaco.as_mut_ptr(), pedaco.len()) };
        }
    }

    /// O que quem chamou quer escrito, para as páginas de dados.
    fn copiar_para_os_dados(&mut self, origem: &[u8]) {
        for (pedaco, destino) in origem.chunks(PAGINA).zip(&self.bases_de_dados) {
            // SAFETY: o destino é uma página de dados deste driver, com uma
            // página inteira de espaço; nenhum comando está em voo.
            unsafe { core::ptr::copy_nonoverlapping(pedaco.as_ptr(), *destino, pedaco.len()) };
        }
    }
}

impl crate::bloco::Dispositivo for Nvme {
    fn driver(&self) -> &'static str {
        "nvme"
    }

    fn capacidade(&self) -> u64 {
        self.capacidade
    }

    fn vivo(&self) -> bool {
        self.vivo
    }

    /// Sempre: com cache volátil, o `Flush`; sem ele, a confirmação já é a
    /// gravação.
    fn descarga(&self) -> bool {
        true
    }

    fn somente_leitura(&self) -> bool {
        self.somente_leitura
    }

    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let mut feito = 0;
        while feito < destino.len() {
            let n = (destino.len() - feito).min(self.maior_ida);
            self.ida(LER, setor + (feito / BLOCO_LOGICO) as u64, n)?;
            self.copiar_dos_dados(&mut destino[feito..feito + n]);
            feito += n;
        }
        Ok(())
    }

    fn escrever(&mut self, setor: u64, origem: &[u8]) -> Result<(), &'static str> {
        let mut feito = 0;
        while feito < origem.len() {
            let n = (origem.len() - feito).min(self.maior_ida);
            self.copiar_para_os_dados(&origem[feito..feito + n]);
            self.ida(ESCREVER, setor + (feito / BLOCO_LOGICO) as u64, n)?;
            feito += n;
        }
        Ok(())
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        if !self.cache_volatil {
            return Ok(());
        }
        let mut c = [0u32; 16];
        c[0] = DESCARREGAR;
        c[1] = NAMESPACE;
        self.submeter(Qual::EntradaESaida, c).map(|_| ())
    }

    /// O desligamento normal: o controlador grava o que guarda e diz quando
    /// acabou. Depois disto ele não aceita mais comando nenhum.
    fn avisar_desligamento(&mut self) {
        let cc = self.ler32(CC);
        self.escrever32(CC, (cc & !CC_DESLIGAMENTO_MASCARA) | CC_DESLIGAMENTO_NORMAL);
        match self.esperar_estado(CSTS_DESLIGAMENTO_MASCARA, CSTS_DESLIGAMENTO_FEITO) {
            Ok(()) => {
                #[cfg(feature = "modo-teste")]
                DESLIGOU.store(true, Ordering::Release);
            }
            Err(motivo) => crate::log_warn!("nvme", "o desligamento nao terminou: {}", motivo),
        }
        self.vivo = false;
    }
}

/// Um campo de texto do identificar — ASCII preenchido com espaços —, para
/// o log.
struct Texto<'a>(&'a [u8]);

impl core::fmt::Display for Texto<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fim = self
            .0
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |i| i + 1);
        for &b in &self.0[..fim] {
            let c = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            };
            core::fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

/// Procura um controlador NVMe no barramento e o liga — como o disco do
/// sistema, se a máquina ainda não tem um.
///
/// Chamada depois do virtio-blk: numa máquina com os dois, o disco do
/// sistema é o virtio. O NVMe que sobra fica de fora — fora da suíte nem é
/// ligado; na suíte, é o segundo disco dos casos.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none() && (d.classe, d.subclasse, d.interface) == (CLASSE, SUBCLASSE, INTERFACE)
        {
            alvo = Some(*d);
        }
    });
    let Some(alvo) = alvo else {
        return;
    };
    let segundo = crate::bloco::ha_disco();
    #[cfg(not(feature = "modo-teste"))]
    if segundo {
        crate::log_info!(
            "nvme",
            "NVMe em {:02x}.{}: a maquina ja tem o disco do sistema; este fica de fora",
            alvo.dispositivo,
            alvo.funcao
        );
        return;
    }
    match Nvme::ligar(&alvo) {
        Ok(nvme) => {
            let nvme = alloc::boxed::Box::new(nvme);
            #[cfg(feature = "modo-teste")]
            if segundo {
                crate::arch::sem_interrupcoes(|| {
                    *SEGUNDO.lock() = Some(crate::bloco::Disco::novo(nvme));
                });
                return;
            }
            if let Err(motivo) = crate::bloco::instalar(nvme) {
                crate::log_error!("nvme", "disco nao instalado: {}", motivo);
            }
        }
        Err(motivo) => crate::log_error!(
            "nvme",
            "NVMe em {:02x}.{} nao pode ser ligado: {}",
            alvo.dispositivo,
            alvo.funcao,
            motivo
        ),
    }
}

/// Só na suíte: se um controlador disse que terminou o desligamento.
#[cfg(feature = "modo-teste")]
static DESLIGOU: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Só na suíte: se um controlador disse que terminou o desligamento — o
/// estado `CSTS.SHST` de desligamento feito, depois do aviso.
#[cfg(feature = "modo-teste")]
pub fn desligou_de_teste() -> bool {
    DESLIGOU.load(Ordering::Acquire)
}

/// Só na suíte: chama `f` com o segundo disco — o NVMe da máquina dos
/// testes —, se houver um.
#[cfg(feature = "modo-teste")]
pub fn com_o_segundo_de_teste<R>(f: impl FnOnce(&mut crate::bloco::Disco) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| SEGUNDO.lock().as_mut().map(f))
}

/// Só na suíte: destrava à força o segundo disco, para uso exclusivo do
/// caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
#[cfg(feature = "modo-teste")]
pub unsafe fn destravar() {
    unsafe { SEGUNDO.force_unlock() };
}
