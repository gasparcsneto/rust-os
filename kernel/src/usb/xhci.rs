//! O controlador xHCI: a porta de entrada do USB.
//!
//! # Por que xHCI, e não algo mais simples
//!
//! Porque é o único controlador que as duas máquinas do emulador têm. O x86
//! tem também o UHCI do PIIX3, que é bem mais simples — e não existe no ARM,
//! onde não há portas de I/O. Um driver para cada seria a mesma armadilha de
//! sempre: código que só uma das arquiteturas exercita.
//!
//! # O que este driver é
//!
//! O mínimo para um teclado e um mouse. O xHCI é uma máquina de anéis: um
//! anel de comandos que o driver preenche e o controlador consome, um anel de
//! eventos ao contrário, e um anel de transferência por endpoint. Tudo o que
//! este módulo faz é montar esses anéis, pedir um slot para cada dispositivo
//! nas portas da raiz, e ler o que eles entregam.
//!
//! # Um dispositivo por porta, vários por controlador
//!
//! Nasceu com um dispositivo só — a fase 3 perguntava se uma pessoa
//! consegue digitar, e um teclado respondia. O mouse trouxe o segundo, e
//! com ele o que um só não pedia: o que é de cada dispositivo (porta, slot,
//! endpoint de controle, buffer, o relatório anterior do teclado) saiu do
//! controlador para [`DispositivoUsb`], e o anel de eventos, que é um só
//! para todos, passou a ser lido pelo slot e pelo endpoint de cada evento.
//!
//! Não há detecção a quente, nem `hub`: o que estiver nas portas da raiz no
//! boot é o que há. Cada uma dessas coisas é um subsistema, e nenhuma é
//! necessária para uma pessoa digitar e apontar.

use alloc::vec::Vec;

use crate::pci::Dispositivo;

/// A classe que identifica um controlador xHCI no barramento.
///
/// Os três números juntos, e não só a classe: `0c/03` é USB, e a interface
/// distingue as gerações — `0x00` é UHCI, `0x10` OHCI, `0x20` EHCI, `0x30`
/// xHCI. Programar um EHCI com os deslocamentos do xHCI escreveria em
/// registradores de outra função.
const CLASSE: u8 = 0x0C;
const SUBCLASSE: u8 = 0x03;
const INTERFACE_XHCI: u8 = 0x30;

/// Registradores de capacidade, a partir do começo do BAR.
mod cap {
    pub const CAPLENGTH: u64 = 0x00;
    pub const HCSPARAMS1: u64 = 0x04;
    pub const HCCPARAMS1: u64 = 0x10;
    pub const DBOFF: u64 = 0x14;
    pub const RTSOFF: u64 = 0x18;
}

/// Registradores operacionais, a partir de `CAPLENGTH`.
mod op {
    pub const USBCMD: u64 = 0x00;
    pub const USBSTS: u64 = 0x04;
    pub const CRCR: u64 = 0x18;
    pub const DCBAAP: u64 = 0x30;
    pub const CONFIG: u64 = 0x38;
    /// O primeiro registrador de porta; as portas se seguem de 16 em 16.
    pub const PORTSC: u64 = 0x400;
    pub const POR_PORTA: u64 = 0x10;
}

/// Bits de `USBCMD`.
const CMD_RUN: u32 = 1 << 0;
const CMD_RESET: u32 = 1 << 1;

/// Bits de `USBSTS`.
const STS_PARADO: u32 = 1 << 0;
/// "Controller Not Ready": enquanto ligado, escrever nos registradores é
/// indefinido.
const STS_NAO_PRONTO: u32 = 1 << 11;

/// Bits de `PORTSC` que interessam.
const PORTA_CONECTADA: u32 = 1 << 0;
const PORTA_HABILITADA: u32 = 1 << 1;
const PORTA_RESET: u32 = 1 << 4;
/// Os bits que se limpam escrevendo 1 neles. Preservá-los numa escrita
/// comum os apagaria sem querer — é o erro clássico deste registrador.
const PORTA_RW1C: u32 = 0x00FE_0002;

/// Quantas voltas esperar por um bit de estado.
///
/// Não é tempo: é um número de tentativas, pela mesma razão que o disco
/// documenta — o relógio não é confiável em todo caminho que chama isto, e o
/// teto só precisa distinguir "lento" de "morto".
const VOLTAS: u32 = 1_000_000;

/// O acesso aos registradores do controlador.
pub struct Controlador {
    /// Onde começam os registradores operacionais.
    operacional: u64,
    /// Onde começa o array de campainhas.
    campainhas: u64,
    /// Onde começam os registradores de tempo de execução.
    execucao: u64,
    /// Quantos slots de dispositivo o controlador suporta.
    slots: u8,
    /// Quantas portas a raiz tem.
    portas: u8,
    /// Os contextos deste controlador têm 64 bytes, e não 32?
    contexto_grande: bool,
}

impl Controlador {
    /// Lê um registrador de 32 bits.
    ///
    /// # Safety
    ///
    /// `endereco` precisa cair dentro do BAR mapeado.
    unsafe fn ler32(&self, endereco: u64) -> u32 {
        // Volátil porque ler um registrador é um efeito: o controlador muda
        // os bits por conta própria, e o compilador não tem como saber disso.
        u32::from_le(unsafe { core::ptr::read_volatile(endereco as *const u32) })
    }

    /// # Safety
    ///
    /// Como [`Controlador::ler32`].
    unsafe fn escrever32(&self, endereco: u64, valor: u32) {
        unsafe { core::ptr::write_volatile(endereco as *mut u32, valor.to_le()) };
    }

    /// # Safety
    ///
    /// Como [`Controlador::ler32`]. O xHCI exige que endereços de 64 bits
    /// sejam escritos como um todo quando o controlador suporta isso, e o
    /// QEMU suporta.
    unsafe fn escrever64(&self, endereco: u64, valor: u64) {
        unsafe { core::ptr::write_volatile(endereco as *mut u64, valor.to_le()) };
    }

    /// Espera um bit de `USBSTS` chegar ao valor pedido.
    fn esperar_estado(&self, bit: u32, ligado: bool) -> bool {
        for _ in 0..VOLTAS {
            // SAFETY: `USBSTS` está dentro do bloco operacional, que está
            // dentro do BAR mapeado.
            let estado = unsafe { self.ler32(self.operacional + op::USBSTS) };
            if (estado & bit != 0) == ligado {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Descobre o controlador e o deixa parado e reiniciado.
    fn descobrir(d: &Dispositivo) -> Result<Controlador, &'static str> {
        let regiao = d.regiao(0).ok_or("o controlador nao tem BAR 0")?;
        let base = crate::mmio::mapear(regiao.base, regiao.tamanho)?;

        // Um controlador em construção, só para poder usar os acessadores. Os
        // deslocamentos reais vêm dos registradores de capacidade, que é o que
        // se lê primeiro.
        let mut c = Controlador {
            operacional: base,
            campainhas: base,
            execucao: base,
            slots: 0,
            portas: 0,
            contexto_grande: false,
        };

        // SAFETY: os registradores de capacidade começam no byte zero do BAR,
        // e o BAR tem pelo menos os 32 bytes que estes cinco ocupam.
        let (comprimento, hcs1, hcc1, dboff, rtsoff) = unsafe {
            (
                core::ptr::read_volatile((base + cap::CAPLENGTH) as *const u8),
                c.ler32(base + cap::HCSPARAMS1),
                c.ler32(base + cap::HCCPARAMS1),
                c.ler32(base + cap::DBOFF),
                c.ler32(base + cap::RTSOFF),
            )
        };

        c.operacional = base + u64::from(comprimento);
        // Os dois deslocamentos têm os bits baixos reservados, e eles não são
        // zero por acaso: são alinhamento. Mascarar não é paranoia, é o que a
        // especificação manda fazer antes de somar.
        c.campainhas = base + u64::from(dboff & !0x3);
        c.execucao = base + u64::from(rtsoff & !0x1F);
        c.slots = (hcs1 & 0xFF) as u8;
        c.portas = ((hcs1 >> 24) & 0xFF) as u8;
        c.contexto_grande = hcc1 & (1 << 2) != 0;

        if c.slots == 0 || c.portas == 0 {
            return Err("o controlador diz nao ter slots nem portas");
        }

        Ok(c)
    }

    /// Para o controlador e o reinicia, deixando-o pronto para configuração.
    fn reiniciar(&self) -> Result<(), &'static str> {
        // SAFETY: os registradores operacionais estão dentro do BAR.
        unsafe {
            let cmd = self.ler32(self.operacional + op::USBCMD);
            self.escrever32(self.operacional + op::USBCMD, cmd & !CMD_RUN);
        }
        if !self.esperar_estado(STS_PARADO, true) {
            return Err("o controlador nao parou");
        }

        // SAFETY: como acima.
        unsafe {
            self.escrever32(self.operacional + op::USBCMD, CMD_RESET);
        }

        // O reinício limpa o próprio bit quando termina, e só depois disso o
        // controlador aceita escrita — são duas esperas, e não uma.
        for _ in 0..VOLTAS {
            // SAFETY: como acima.
            let cmd = unsafe { self.ler32(self.operacional + op::USBCMD) };
            if cmd & CMD_RESET == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        if !self.esperar_estado(STS_NAO_PRONTO, false) {
            return Err("o controlador nao ficou pronto depois do reinicio");
        }

        Ok(())
    }

    /// O estado de uma porta da raiz. `porta` começa em 1.
    fn portsc(&self, porta: u8) -> u32 {
        let endereco = self.operacional + op::PORTSC + (u64::from(porta) - 1) * op::POR_PORTA;
        // SAFETY: `porta` é no máximo `self.portas`, e o bloco de portas vem
        // logo depois dos registradores operacionais, dentro do BAR.
        unsafe { self.ler32(endereco) }
    }

    /// Escreve numa porta sem apagar os bits que se limpam escrevendo 1.
    fn escrever_portsc(&self, porta: u8, valor: u32) {
        let endereco = self.operacional + op::PORTSC + (u64::from(porta) - 1) * op::POR_PORTA;
        // SAFETY: como em [`Controlador::portsc`].
        unsafe { self.escrever32(endereco, valor & !PORTA_RW1C) };
    }
}

// ---------------------------------------------------------------------------
// Os anéis
// ---------------------------------------------------------------------------

/// Quantos TRBs cabem num anel.
///
/// Dezesseis, que são 256 bytes — um anel inteiro cabe folgado num frame, e o
/// que o tamanho precisa cobrir é a maior sequência que submetemos de uma vez:
/// uma transferência de controle são três TRBs.
const TRBS: usize = 16;

/// Um TRB: a unidade de que todos os anéis do xHCI são feitos.
///
/// `repr(C)` porque isto é um contrato de layout com o controlador, e o layout
/// do Rust é explicitamente instável — sem ele o compilador pode reordenar os
/// campos, e o dispositivo leria o parâmetro onde está o controle.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Trb {
    parametro: u64,
    estado: u32,
    controle: u32,
}

/// Os tipos de TRB que este driver emite ou lê.
mod trb {
    pub const NORMAL: u32 = 1;
    pub const SETUP: u32 = 2;
    pub const DADOS: u32 = 3;
    pub const ESTADO: u32 = 4;
    pub const LIGACAO: u32 = 6;
    pub const HABILITAR_SLOT: u32 = 9;
    pub const ENDERECAR: u32 = 11;
    pub const CONFIGURAR_ENDPOINT: u32 = 12;
    /// Eventos, que vêm do controlador para nós.
    pub const EVENTO_DE_TRANSFERENCIA: u32 = 32;
    pub const EVENTO_DE_COMANDO: u32 = 33;
}

/// O tipo de um TRB fica nos bits 10 a 15 do campo de controle.
const fn tipo_de(controle: u32) -> u32 {
    (controle >> 10) & 0x3F
}

/// O bit de ciclo, que é como as duas pontas sabem de quem é a vez.
///
/// O anel não tem ponteiro de escrita compartilhado: quem produz alterna o bit
/// a cada volta, e quem consome para quando encontra um TRB cujo bit não bate
/// com o ciclo que ele espera. É o que permite que os dois lados andem sem
/// nenhuma trava.
const CICLO: u32 = 1 << 0;

/// Um anel que nós preenchemos e o controlador consome.
struct Anel {
    frame: u64,
    base: *mut Trb,
    proximo: usize,
    ciclo: u32,
}

impl Anel {
    fn novo() -> Option<Anel> {
        let frame = crate::frames::alocar()?;
        let base = crate::arch::acesso_fisico(frame) as *mut Trb;

        // SAFETY: o frame acabou de ser alocado e tem 4096 bytes; `TRBS` TRBs
        // de 16 bytes são 256.
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, crate::arch::TAMANHO_PAGINA as usize) };

        let anel = Anel {
            frame,
            base,
            proximo: 0,
            ciclo: 1,
        };

        // O último TRB é uma ligação de volta ao começo, com o bit de alternar
        // ciclo. Sem ela o controlador sairia do anel e leria memória alheia
        // como se fossem comandos.
        let ligacao = Trb {
            parametro: frame,
            estado: 0,
            // Bit 1 é "alternar ciclo": ao seguir a ligação, o controlador
            // inverte o ciclo que espera, que é o que faz a volta funcionar.
            controle: (trb::LIGACAO << 10) | (1 << 1) | anel.ciclo,
        };
        anel.escrever(TRBS - 1, ligacao);
        Some(anel)
    }

    fn escrever(&self, posicao: usize, valor: Trb) {
        // SAFETY: `posicao` é menor que `TRBS`, e o anel inteiro cabe no frame.
        unsafe { core::ptr::write_volatile(self.base.add(posicao), valor) };
    }

    /// Põe um TRB no anel e devolve o endereço físico dele.
    ///
    /// O endereço importa porque é como o evento de conclusão se refere ao
    /// comando: ele devolve o ponteiro do TRB que o originou.
    fn empurrar(&mut self, parametro: u64, estado: u32, controle: u32) -> u64 {
        let posicao = self.proximo;
        self.escrever(
            posicao,
            Trb {
                parametro,
                estado,
                // O bit de ciclo vai por último no valor, mas o que importa é
                // que ele seja escrito junto com o resto: é ele que autoriza o
                // controlador a ler o TRB.
                controle: controle | self.ciclo,
            },
        );

        self.proximo += 1;
        if self.proximo == TRBS - 1 {
            // Chegamos na ligação: atualizá-la com o ciclo atual, voltar ao
            // começo e alternar.
            let ligacao = Trb {
                parametro: self.frame,
                estado: 0,
                controle: (trb::LIGACAO << 10) | (1 << 1) | self.ciclo,
            };
            self.escrever(TRBS - 1, ligacao);
            self.proximo = 0;
            self.ciclo ^= 1;
        }

        self.frame + (posicao * core::mem::size_of::<Trb>()) as u64
    }

    /// O endereço do anel com o bit de ciclo inicial, como os contextos pedem.
    fn ponteiro_inicial(&self) -> u64 {
        self.frame | u64::from(self.ciclo)
    }
}

/// O anel por onde o controlador nos conta o que aconteceu.
///
/// Ao contrário dos outros, não tem TRB de ligação: quem dá a volta é o
/// controlador, e o tamanho do segmento é declarado numa tabela à parte.
struct AnelDeEventos {
    frame: u64,
    base: *mut Trb,
    proximo: usize,
    ciclo: u32,
}

impl AnelDeEventos {
    fn novo() -> Option<AnelDeEventos> {
        let frame = crate::frames::alocar()?;
        let base = crate::arch::acesso_fisico(frame) as *mut Trb;
        // SAFETY: frame recém-alocado, de 4096 bytes.
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, crate::arch::TAMANHO_PAGINA as usize) };
        Some(AnelDeEventos {
            frame,
            base,
            proximo: 0,
            ciclo: 1,
        })
    }

    /// Tira o próximo evento, se o controlador já publicou um.
    fn colher(&mut self) -> Option<Trb> {
        // SAFETY: `proximo` é menor que `TRBS`, e o anel cabe no frame.
        let evento = unsafe { core::ptr::read_volatile(self.base.add(self.proximo)) };

        // O ciclo é o que distingue um evento novo de um da volta anterior.
        if evento.controle & CICLO != self.ciclo {
            return None;
        }

        self.proximo += 1;
        if self.proximo == TRBS {
            self.proximo = 0;
            self.ciclo ^= 1;
        }
        Some(evento)
    }

    /// Onde o controlador deve parar de escrever, para lhe ser informado.
    fn ponteiro_de_leitura(&self) -> u64 {
        self.frame + (self.proximo * core::mem::size_of::<Trb>()) as u64
    }
}

// ---------------------------------------------------------------------------
// O controlador de pé
// ---------------------------------------------------------------------------

/// Registradores do interruptor zero, a partir de `RTSOFF`.
mod intr {
    /// Os interruptores começam 32 bytes depois do início do bloco.
    pub const BASE: u64 = 0x20;
    pub const ERSTSZ: u64 = 0x08;
    pub const ERSTBA: u64 = 0x10;
    pub const ERDP: u64 = 0x18;
}

/// O código de conclusão que o controlador devolve quando deu certo.
const SUCESSO: u32 = 1;

/// Quantas voltas esperar por um evento antes de desistir.
///
/// Mesma natureza do teto de [`VOLTAS`]: um número de tentativas, não um
/// tempo. Este é menor porque um comando que não responde em cem mil voltas
/// não vai responder.
const VOLTAS_DE_EVENTO: u32 = 100_000;

/// Quantos dispositivos este driver atende.
///
/// Quatro: um teclado e um mouse, com folga. O controlador precisa saber
/// quantos slots vão ser usados antes de aceitar qualquer comando, e cada
/// slot a mais custa uma entrada de tabela que ninguém lê. Um dispositivo
/// além disso fica sem slot, e o log diz em que porta.
const DISPOSITIVOS: usize = 4;

/// Tudo o que este driver precisa guardar entre uma chamada e outra.
pub struct Xhci {
    c: Controlador,
    comandos: Anel,
    eventos: AnelDeEventos,
    /// A tabela de contextos de dispositivo.
    dcbaa: u64,
    /// Os dispositivos configurados, um por slot.
    dispositivos: Vec<DispositivoUsb>,
}

/// Um dispositivo numa porta da raiz, depois de endereçado.
struct DispositivoUsb {
    /// A porta onde ele está, contada a partir de 1.
    porta: u8,
    /// A velocidade que a porta reportou depois do reinício.
    velocidade: u32,
    /// O slot que o controlador deu a ele.
    slot: u8,
    /// O contexto que **nós** preenchemos para pedir mudanças.
    entrada: u64,
    /// O anel de transferência do endpoint de controle.
    ep0: Anel,
    /// A página por onde os dados de controle e os relatórios entram.
    buffer: u64,
    /// O teclado ou o mouse, depois de configurado.
    hid: Option<Hid>,
}

// SAFETY: os ponteiros apontam para frames que este driver aloca e nunca
// devolve, e todo acesso passa pelo `Mutex` que guarda o dono.
unsafe impl Send for Xhci {}

impl Controlador {
    /// Toca a campainha de um slot. Slot zero é o anel de comandos.
    fn campainha(&self, slot: u8, valor: u32) {
        let endereco = self.campainhas + u64::from(slot) * 4;
        // SAFETY: o array de campainhas tem uma entrada por slot, e `slot` é
        // no máximo o número de slots que o controlador declarou.
        unsafe { self.escrever32(endereco, valor) };
    }

    /// Diz ao controlador até onde o anel de eventos foi lido.
    fn devolver_eventos(&self, eventos: &AnelDeEventos) {
        // SAFETY: o bloco de tempo de execução está dentro do BAR.
        unsafe {
            // Bit 3 é "handler busy", e escrevê-lo de volta é como se
            // reconhece a interrupção do interruptor.
            self.escrever64(
                self.execucao + intr::BASE + intr::ERDP,
                eventos.ponteiro_de_leitura() | (1 << 3),
            );
        }
    }
}

impl Xhci {
    /// Espera um evento do tipo pedido e devolve-o.
    ///
    /// Espera em laço porque não há mais nada para fazer: isto roda no boot,
    /// antes de haver tarefas, e um controlador que não responde é um defeito
    /// e não uma latência.
    fn esperar_evento(&mut self, tipo: u32) -> Option<Trb> {
        for _ in 0..VOLTAS_DE_EVENTO {
            while let Some(evento) = self.eventos.colher() {
                // O ponteiro de leitura é atualizado a cada evento colhido, e
                // não só no fim: é ele que diz ao controlador que há espaço.
                self.c.devolver_eventos(&self.eventos);
                if tipo_de(evento.controle) == tipo {
                    return Some(evento);
                }
                // Eventos de outro tipo — mudança de porta, sobretudo —
                // chegam no meio e são consumidos em silêncio: eles não são
                // erro, são o controlador contando o que fez. Relatórios não
                // chegam aqui: eles só são pendurados depois de todos os
                // dispositivos configurados — ver [`init`].
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Manda um comando e espera a conclusão dele.
    ///
    /// Devolve o TRB do evento, de onde saem o código de conclusão e o slot.
    fn comandar(&mut self, parametro: u64, controle: u32) -> Option<Trb> {
        self.comandos.empurrar(parametro, 0, controle);
        self.c.campainha(0, 0);
        self.esperar_evento(trb::EVENTO_DE_COMANDO)
    }

    /// Sobe o controlador: anéis, memória de contexto e o botão de ligar.
    fn subir(d: &Dispositivo) -> Result<Xhci, &'static str> {
        let c = Controlador::descobrir(d)?;
        c.reiniciar()?;

        // O controlador precisa saber quantos slots vamos usar antes de
        // aceitar qualquer comando — ver [`DISPOSITIVOS`]. O do emulador não
        // cobra: com um slot declarado, ele dá o segundo do mesmo jeito, e a
        // mutação que declara um só passa pela fumaça. O número certo está
        // aqui pela especificação, que manda o controlador recusar.
        let slots = (DISPOSITIVOS as u32).min(u32::from(c.slots));
        // SAFETY: registradores operacionais, dentro do BAR.
        unsafe { c.escrever32(c.operacional + op::CONFIG, slots) };

        // A tabela de contextos de dispositivo. O controlador escreve nela o
        // endereço do contexto de cada slot; a entrada zero é reservada para
        // outra coisa e fica em branco.
        let dcbaa = crate::frames::alocar().ok_or("sem frame para a tabela de contextos")?;
        // SAFETY: frame recém-alocado de 4096 bytes.
        unsafe {
            core::ptr::write_bytes(
                crate::arch::acesso_fisico(dcbaa),
                0,
                crate::arch::TAMANHO_PAGINA as usize,
            )
        };
        // SAFETY: como acima.
        unsafe { c.escrever64(c.operacional + op::DCBAAP, dcbaa) };

        let comandos = Anel::novo().ok_or("sem frame para o anel de comandos")?;
        // SAFETY: como acima.
        unsafe { c.escrever64(c.operacional + op::CRCR, comandos.ponteiro_inicial()) };

        let eventos = AnelDeEventos::novo().ok_or("sem frame para o anel de eventos")?;

        // A tabela que descreve os segmentos do anel de eventos. Um segmento
        // só, e a tabela inteira são dezesseis bytes — mas ela precisa do seu
        // próprio frame porque o controlador exige alinhamento de 64 bytes e
        // o alocador só entrega páginas.
        let erst = crate::frames::alocar().ok_or("sem frame para a tabela de eventos")?;
        let base_da_erst = crate::arch::acesso_fisico(erst);
        // SAFETY: frame recém-alocado; a entrada tem 16 bytes.
        unsafe {
            core::ptr::write_bytes(base_da_erst, 0, crate::arch::TAMANHO_PAGINA as usize);
            core::ptr::write_volatile(base_da_erst as *mut u64, eventos.frame.to_le());
            core::ptr::write_volatile((base_da_erst as *mut u32).add(2), (TRBS as u32).to_le());
        }

        // A ordem destes três não é livre: o tamanho e o ponteiro de leitura
        // antes do endereço da tabela, porque é a escrita do endereço que faz
        // o controlador passar a usá-la.
        // SAFETY: bloco de tempo de execução, dentro do BAR.
        unsafe {
            c.escrever32(c.execucao + intr::BASE + intr::ERSTSZ, 1);
            c.escrever64(c.execucao + intr::BASE + intr::ERDP, eventos.frame);
            c.escrever64(c.execucao + intr::BASE + intr::ERSTBA, erst);
        }

        // E o botão de ligar.
        // SAFETY: registradores operacionais.
        unsafe {
            let cmd = c.ler32(c.operacional + op::USBCMD);
            c.escrever32(c.operacional + op::USBCMD, cmd | CMD_RUN);
        }
        if !c.esperar_estado(STS_PARADO, false) {
            return Err("o controlador nao saiu do estado parado");
        }

        Ok(Xhci {
            c,
            comandos,
            eventos,
            dcbaa,
            dispositivos: Vec::new(),
        })
    }

    /// Reinicia uma porta com dispositivo, deixando-a habilitada, e devolve
    /// a velocidade que ela reportou.
    fn preparar_porta(&self, porta: u8) -> Result<u32, &'static str> {
        // O reinício da porta é o que a habilita. Escrever preservando os bits
        // de estado que se limpam com 1 é obrigatório: uma escrita ingênua
        // apagaria as mudanças que ainda não foram lidas.
        let estado = self.c.portsc(porta);
        self.c.escrever_portsc(porta, estado | PORTA_RESET);

        for _ in 0..VOLTAS {
            if self.c.portsc(porta) & PORTA_HABILITADA != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        let estado = self.c.portsc(porta);
        if estado & PORTA_HABILITADA == 0 {
            return Err("a porta nao habilitou depois do reinicio");
        }

        // A velocidade só é válida depois do reinício, e é ela que decide o
        // tamanho do pacote do endpoint de controle.
        Ok((estado >> 10) & 0xF)
    }

    /// Leva o dispositivo de uma porta de "conectado" a "falando": porta
    /// habilitada, endereço, e o teclado ou o mouse configurado.
    fn preparar_dispositivo(&mut self, porta: u8) -> Result<DispositivoUsb, &'static str> {
        let velocidade = self.preparar_porta(porta)?;
        crate::log_info!(
            "usb",
            "porta {} habilitada, velocidade {}",
            porta,
            velocidade
        );

        // E o primeiro comando de verdade, que é o que prova que os dois anéis
        // funcionam: o de comandos, que o controlador leu, e o de eventos, por
        // onde ele respondeu.
        let mut d = self.enderecar(porta, velocidade)?;
        crate::log_info!("usb", "dispositivo no slot {}, enderecado", d.slot);

        // Quem é o dispositivo, antes de configurá-lo. Não muda decisão
        // nenhuma: está aqui porque um teclado que não funciona e um
        // dispositivo que não é teclado são investigações diferentes, e esta
        // linha separa as duas.
        match self.controle(
            &mut d,
            pedido::ENTRADA_PADRAO,
            pedido::PEGAR_DESCRITOR,
            pedido::DESCRITOR_DE_DISPOSITIVO,
            0,
            18,
        ) {
            Ok(_) => crate::log_info!(
                "usb",
                "dispositivo {:04x}:{:04x}",
                u16::from(d.byte(8)) | (u16::from(d.byte(9)) << 8),
                u16::from(d.byte(10)) | (u16::from(d.byte(11)) << 8)
            ),
            Err(motivo) => crate::log_warn!("usb", "descritor do dispositivo nao veio: {}", motivo),
        }

        self.preparar_hid(&mut d)?;
        Ok(d)
    }
}

/// O controlador da máquina, se houver um.
static XHCI: crate::trava::Mutex<Option<Xhci>> = crate::trava::Mutex::new(None);

/// Procura o controlador, sobe-o e configura o que estiver nas portas.
///
/// # A ordem: todos configurados, e só então os relatórios
///
/// Configurar um dispositivo é esperar eventos de transferência do
/// endpoint de controle dele. Se o teclado já tivesse relatórios
/// pendurados enquanto o mouse é configurado, um relatório do teclado
/// poderia chegar no meio, e seria tomado pela conclusão de um pedido do
/// mouse — e consumido. Pendurar tudo no fim deixa a configuração com um
/// anel de eventos que só fala de configuração.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none()
            && d.classe == CLASSE
            && d.subclasse == SUBCLASSE
            && d.interface == INTERFACE_XHCI
        {
            alvo = Some(*d);
        }
    });

    let Some(alvo) = alvo else {
        crate::log_info!("usb", "nenhum controlador xhci no barramento");
        return;
    };

    // O controlador faz DMA para os anéis; sem mestre de barramento ele não
    // consegue ler o que escrevemos.
    crate::pci::habilitar_mestre(&alvo);

    let mut xhci = match Xhci::subir(&alvo) {
        Ok(x) => x,
        Err(motivo) => {
            crate::log_warn!("usb", "xhci nao subiu: {}", motivo);
            return;
        }
    };

    crate::log_info!(
        "usb",
        "xhci em {:02x}.{} de pe: {} slots, {} portas",
        alvo.dispositivo,
        alvo.funcao,
        xhci.c.slots,
        xhci.c.portas
    );

    // Cada porta com dispositivo, uma de cada vez. Um dispositivo que falha
    // não leva os outros junto: o log diz qual porta e por quê, e a próxima
    // é tentada.
    for porta in 1..=xhci.c.portas {
        if xhci.c.portsc(porta) & PORTA_CONECTADA == 0 {
            continue;
        }
        if xhci.dispositivos.len() == DISPOSITIVOS {
            crate::log_warn!(
                "usb",
                "porta {}: sem slot, o driver atende {}",
                porta,
                DISPOSITIVOS
            );
            continue;
        }
        match xhci.preparar_dispositivo(porta) {
            Ok(d) => xhci.dispositivos.push(d),
            Err(motivo) => crate::log_warn!("usb", "porta {}: {}", porta, motivo),
        }
    }

    if xhci.dispositivos.is_empty() {
        crate::log_warn!("usb", "nenhum teclado nem mouse nas portas");
        return;
    }

    for i in 0..xhci.dispositivos.len() {
        xhci.pendurar_relatorios(i);
    }
    *XHCI.lock() = Some(xhci);
}
// ---------------------------------------------------------------------------
// O dispositivo
// ---------------------------------------------------------------------------

/// Os tipos de endpoint, no campo do contexto.
const EP_CONTROLE: u32 = 4;
const EP_INTERRUPCAO_ENTRADA: u32 = 7;

/// Quantas vezes o controlador repete uma transferência que falha.
///
/// Três é o que a especificação sugere e o que todo driver usa. Zero
/// significaria "não repita", que num barramento com ruído é o mesmo que
/// desistir do dispositivo no primeiro contratempo.
const TENTATIVAS_DO_ENDPOINT: u32 = 3;

/// O identificador do endpoint de controle dentro de um slot.
///
/// O xHCI numera os endpoints de um jeito próprio: o de controle é 1, e os
/// demais são `numero * 2` para saída e `numero * 2 + 1` para entrada. É por
/// isso que o endpoint 1 de entrada vira 3.
const DCI_DO_CONTROLE: u8 = 1;

impl Xhci {
    /// O tamanho de um contexto nesta máquina.
    fn tamanho_do_contexto(&self) -> usize {
        if self.c.contexto_grande { 64 } else { 32 }
    }

    /// Escreve uma palavra de 32 bits num contexto.
    ///
    /// `contexto` é o índice dentro do bloco: 0 é o de controle de entrada, 1
    /// o do slot, e daí em diante um por endpoint, na ordem dos DCI.
    fn escrever_contexto(&self, frame: u64, contexto: usize, dword: usize, valor: u32) {
        let base = crate::arch::acesso_fisico(frame);
        let deslocamento = contexto * self.tamanho_do_contexto() + dword * 4;
        // SAFETY: o maior DCI que um endpoint pode ter é 31, e o contexto dele
        // é o de índice 32: 33 contextos de 64 bytes são 2112, que cabem no
        // frame de 4096.
        unsafe { core::ptr::write_volatile(base.add(deslocamento) as *mut u32, valor.to_le()) };
    }

    /// Pede um slot ao controlador e dá um endereço ao dispositivo.
    fn enderecar(&mut self, porta: u8, velocidade: u32) -> Result<DispositivoUsb, &'static str> {
        let evento = self
            .comandar(0, trb::HABILITAR_SLOT << 10)
            .ok_or("o controlador nao respondeu ao habilitar slot")?;
        if (evento.estado >> 24) & 0xFF != SUCESSO {
            return Err("habilitar slot foi recusado");
        }
        let slot = ((evento.controle >> 24) & 0xFF) as u8;

        // O contexto do dispositivo é escrito pelo **controlador**; nós só
        // damos a página e anotamos onde ela está.
        let contexto = crate::frames::alocar().ok_or("sem frame para o contexto do dispositivo")?;
        // SAFETY: frame recém-alocado de 4096 bytes; e a entrada do slot na
        // tabela, que tem uma entrada por slot que o controlador declarou.
        unsafe {
            core::ptr::write_bytes(
                crate::arch::acesso_fisico(contexto),
                0,
                crate::arch::TAMANHO_PAGINA as usize,
            );
            // A entrada do slot na tabela é como o controlador o acha.
            core::ptr::write_volatile(
                (crate::arch::acesso_fisico(self.dcbaa) as *mut u64).add(slot as usize),
                contexto.to_le(),
            );
        }

        let entrada = crate::frames::alocar().ok_or("sem frame para o contexto de entrada")?;
        // SAFETY: como acima.
        unsafe {
            core::ptr::write_bytes(
                crate::arch::acesso_fisico(entrada),
                0,
                crate::arch::TAMANHO_PAGINA as usize,
            )
        };

        let ep0 = Anel::novo().ok_or("sem frame para o anel de controle")?;
        let buffer = crate::frames::alocar().ok_or("sem frame para o buffer de controle")?;

        // Contexto de controle de entrada: quais contextos o comando deve
        // olhar. O bit 0 é o do slot, o bit 1 o do endpoint de controle.
        self.escrever_contexto(entrada, 0, 1, 0b11);

        // Contexto do slot: uma entrada de contexto (o de controle), a
        // velocidade que a porta reportou, e em que porta da raiz ele está.
        self.escrever_contexto(entrada, 1, 0, (1 << 27) | (velocidade << 20));
        self.escrever_contexto(entrada, 1, 1, u32::from(porta) << 16);

        // Contexto do endpoint de controle.
        self.escrever_contexto(
            entrada,
            2,
            1,
            (pacote_do_controle(velocidade) << 16)
                | (EP_CONTROLE << 3)
                | (TENTATIVAS_DO_ENDPOINT << 1),
        );
        let ponteiro = ep0.ponteiro_inicial();
        self.escrever_contexto(entrada, 2, 2, ponteiro as u32);
        self.escrever_contexto(entrada, 2, 3, (ponteiro >> 32) as u32);
        // Comprimento médio de um TRB deste endpoint: oito, o tamanho de um
        // pedido de controle. O controlador usa isto para planejar banda.
        self.escrever_contexto(entrada, 2, 4, 8);

        let evento = self
            .comandar(entrada, (trb::ENDERECAR << 10) | (u32::from(slot) << 24))
            .ok_or("o controlador nao respondeu ao enderecar")?;
        if (evento.estado >> 24) & 0xFF != SUCESSO {
            return Err("enderecar o dispositivo foi recusado");
        }

        Ok(DispositivoUsb {
            porta,
            velocidade,
            slot,
            entrada,
            ep0,
            buffer,
            hid: None,
        })
    }
}

/// O tamanho do pacote do endpoint de controle, que depende da velocidade.
///
/// Oito para baixa velocidade, 64 para o resto. É o que a especificação do
/// USB fixa, e errar para mais faz o dispositivo ignorar metade de cada
/// pedido — sem dizer nada.
fn pacote_do_controle(velocidade: u32) -> u32 {
    // Velocidade 2 é a baixa; 1 é a cheia, 3 a alta, 4 e 5 as super.
    if velocidade == 2 { 8 } else { 64 }
}

impl DispositivoUsb {
    /// Um byte do buffer de transferência.
    fn byte(&self, deslocamento: usize) -> u8 {
        // SAFETY: o buffer é um frame de 4096 bytes, e todo chamador daqui
        // pede deslocamentos dentro do que acabou de ser lido.
        unsafe {
            core::ptr::read_volatile(crate::arch::acesso_fisico(self.buffer).add(deslocamento))
        }
    }
}

// ---------------------------------------------------------------------------
// Transferências de controle
// ---------------------------------------------------------------------------

/// Os pedidos padrão do USB que este driver faz.
mod pedido {
    /// Para o dispositivo, lendo.
    pub const ENTRADA_PADRAO: u8 = 0x80;
    /// Para o dispositivo, escrevendo.
    pub const SAIDA_PADRAO: u8 = 0x00;
    /// Para uma interface, escrevendo, e específico da classe.
    pub const SAIDA_DE_CLASSE: u8 = 0x21;

    pub const PEGAR_DESCRITOR: u8 = 6;
    pub const DEFINIR_CONFIGURACAO: u8 = 9;
    /// Específico do HID: escolhe entre o protocolo de boot e o de relatório.
    pub const DEFINIR_PROTOCOLO: u8 = 0x0B;

    pub const DESCRITOR_DE_DISPOSITIVO: u16 = 1 << 8;
    pub const DESCRITOR_DE_CONFIGURACAO: u16 = 2 << 8;
}

/// O sentido dos dados numa transferência de controle, como o TRB o codifica.
const SENTIDO_ENTRADA: u32 = 1 << 16;

/// O tipo de transferência do estágio de preparação.
const SEM_DADOS: u32 = 0;
const DADOS_DE_SAIDA: u32 = 2;
const DADOS_DE_ENTRADA: u32 = 3;

/// "Dados imediatos": o parâmetro do TRB **é** o pedido, e não um ponteiro.
const IMEDIATO: u32 = 1 << 6;
/// "Interromper ao concluir": sem isto, nenhum evento é gerado.
const AVISAR: u32 = 1 << 5;

impl Xhci {
    /// Faz uma transferência de controle com um dispositivo e devolve quantos
    /// bytes vieram.
    ///
    /// # Por que três TRBs
    ///
    /// Porque uma transferência de controle do USB tem três estágios, e o
    /// xHCI os expõe como são: o pedido, os dados (quando há) e a confirmação.
    /// Só o último pede aviso — os outros dois concluem em silêncio, e gerar
    /// evento para cada um encheria o anel de eventos com o que ninguém lê.
    fn controle(
        &mut self,
        d: &mut DispositivoUsb,
        tipo: u8,
        requisicao: u8,
        valor: u16,
        indice: u16,
        tamanho: u16,
    ) -> Result<u32, &'static str> {
        let entrada = tipo & 0x80 != 0;

        let transferencia = match (tamanho, entrada) {
            (0, _) => SEM_DADOS,
            (_, true) => DADOS_DE_ENTRADA,
            (_, false) => DADOS_DE_SAIDA,
        };

        // O pedido cabe nos oito bytes do parâmetro, que é para isso que o
        // bit de dados imediatos existe.
        let pedido = u64::from(tipo)
            | (u64::from(requisicao) << 8)
            | (u64::from(valor) << 16)
            | (u64::from(indice) << 32)
            | (u64::from(tamanho) << 48);
        d.ep0.empurrar(
            pedido,
            8,
            (trb::SETUP << 10) | IMEDIATO | (transferencia << 16),
        );

        if tamanho > 0 {
            d.ep0.empurrar(
                d.buffer,
                u32::from(tamanho),
                (trb::DADOS << 10) | if entrada { SENTIDO_ENTRADA } else { 0 },
            );
        }

        // A confirmação anda no sentido contrário aos dados. Sem dados, ela
        // vai no sentido de entrada.
        let sentido_da_confirmacao = if tamanho > 0 && entrada {
            0
        } else {
            SENTIDO_ENTRADA
        };
        d.ep0
            .empurrar(0, 0, (trb::ESTADO << 10) | AVISAR | sentido_da_confirmacao);

        self.c.campainha(d.slot, u32::from(DCI_DO_CONTROLE));

        let evento = self
            .esperar_evento(trb::EVENTO_DE_TRANSFERENCIA)
            .ok_or("o dispositivo nao respondeu ao pedido de controle")?;

        let codigo = (evento.estado >> 24) & 0xFF;
        // "Short packet" é o código 13, e não é erro: é o dispositivo tendo
        // menos a dizer do que perguntamos, o que é comum ao ler descritores.
        if codigo != SUCESSO && codigo != 13 {
            return Err("o pedido de controle foi recusado");
        }

        // O campo de estado traz o que **faltou** transferir, e não o que foi.
        let restante = evento.estado & 0x00FF_FFFF;
        Ok(u32::from(tamanho).saturating_sub(restante))
    }
}

// ---------------------------------------------------------------------------
// O teclado e o mouse
// ---------------------------------------------------------------------------

/// Onde, dentro do buffer, ficam os relatórios.
///
/// Depois dos dados de controle, que ocupam o começo da página. Os dois
/// convivem no mesmo frame porque um descritor de configuração inteiro tem
/// dezenas de bytes e um relatório tem oito — um frame por uso seria um frame
/// desperdiçado.
const RELATORIOS_EM: usize = 256;

/// O espaço de cada relatório no buffer, e o maior que se pede.
///
/// Oito, o do teclado. O do mouse de boot tem três bytes que importam e
/// mais o que o dispositivo quiser — a roda, quase sempre —, e oito cobrem
/// os mouses de boot que existem; o que passar disso o controlador corta.
const TAMANHO_DO_RELATORIO: usize = crate::usb::hid::TAMANHO_DO_RELATORIO;

/// Quantos relatórios ficam pendurados no controlador ao mesmo tempo.
///
/// Quatro. Cada um é uma transferência que o controlador completa quando o
/// dispositivo tem algo a dizer; com a colheita a cada tique, quatro cobrem
/// quarenta milissegundos de digitação sem que nenhuma se perca.
const RELATORIOS: usize = 4;

/// Descritores que este driver reconhece ao caminhar pela configuração.
const DESCRITOR_INTERFACE: u8 = 4;
const DESCRITOR_ENDPOINT: u8 = 5;

/// A classe e a subclasse de um dispositivo que fala o protocolo de boot, e
/// os dois protocolos que ele pode falar.
const CLASSE_HID: u8 = 3;
const SUBCLASSE_BOOT: u8 = 1;
const PROTOCOLO_TECLADO: u8 = 1;
const PROTOCOLO_MOUSE: u8 = 2;

/// O que um dispositivo de boot é.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TipoHid {
    Teclado,
    Mouse,
}

impl TipoHid {
    fn nome(self) -> &'static str {
        match self {
            TipoHid::Teclado => "teclado",
            TipoHid::Mouse => "mouse",
        }
    }
}

/// O que procuramos no descritor de configuração.
struct Achado {
    tipo: TipoHid,
    configuracao: u8,
    interface: u8,
    endpoint: u8,
    pacote: u16,
    intervalo: u8,
}

impl Xhci {
    /// Lê a configuração do dispositivo e acha o teclado ou o mouse dentro
    /// dela.
    ///
    /// # Por que caminhar em vez de assumir
    ///
    /// Porque assumir funcionaria — o teclado do emulador tem uma interface e
    /// um endpoint, nos lugares óbvios. E seria a mesma escolha que o
    /// carregador de ELF deste kernel recusa: confiar num campo em vez de o
    /// conferir. Um dispositivo com duas interfaces faria a versão que assume
    /// pendurar transferências no endpoint errado, e o sintoma seria um
    /// teclado mudo sem nenhuma mensagem.
    fn achar_hid(&mut self, d: &mut DispositivoUsb) -> Result<Achado, &'static str> {
        // O cabeçalho primeiro, que é quem diz o tamanho do resto.
        self.controle(
            d,
            pedido::ENTRADA_PADRAO,
            pedido::PEGAR_DESCRITOR,
            pedido::DESCRITOR_DE_CONFIGURACAO,
            0,
            9,
        )?;
        let total = u16::from(d.byte(2)) | (u16::from(d.byte(3)) << 8);
        let configuracao = d.byte(5);

        // E um teto nosso: um descritor que se dissesse maior que a página
        // faria a leitura passar do fim do buffer.
        let total = total.min(RELATORIOS_EM as u16);
        self.controle(
            d,
            pedido::ENTRADA_PADRAO,
            pedido::PEGAR_DESCRITOR,
            pedido::DESCRITOR_DE_CONFIGURACAO,
            0,
            total,
        )?;

        let mut interface = None;
        let mut i = 0usize;
        while i + 2 <= total as usize {
            let tamanho = d.byte(i) as usize;
            let tipo = d.byte(i + 1);
            // Um descritor de tamanho zero não avança o cursor, e o laço
            // giraria para sempre lendo o mesmo byte.
            if tamanho == 0 {
                return Err("descritor de tamanho zero na configuracao");
            }

            match tipo {
                DESCRITOR_INTERFACE if tamanho >= 9 => {
                    let boot = d.byte(i + 5) == CLASSE_HID && d.byte(i + 6) == SUBCLASSE_BOOT;
                    let tipo = match d.byte(i + 7) {
                        PROTOCOLO_TECLADO => Some(TipoHid::Teclado),
                        PROTOCOLO_MOUSE => Some(TipoHid::Mouse),
                        _ => None,
                    };
                    interface = tipo.filter(|_| boot).map(|t| (d.byte(i + 2), t));
                }
                // Só os endpoints que vêm **depois** da interface certa. Um
                // endpoint pertence à última interface declarada, e é isso
                // que torna a ordem significativa.
                DESCRITOR_ENDPOINT if tamanho >= 7 => {
                    if let Some((numero_da_interface, tipo)) = interface {
                        let endereco = d.byte(i + 2);
                        let atributos = d.byte(i + 3);
                        // Bit 7 do endereço é o sentido: entrada. Os dois bits
                        // baixos dos atributos são o tipo: 3 é interrupção.
                        if endereco & 0x80 != 0 && atributos & 0x3 == 3 {
                            return Ok(Achado {
                                tipo,
                                configuracao,
                                interface: numero_da_interface,
                                endpoint: endereco & 0x0F,
                                pacote: u16::from(d.byte(i + 4)) | (u16::from(d.byte(i + 5)) << 8),
                                intervalo: d.byte(i + 6),
                            });
                        }
                    }
                }
                _ => {}
            }
            i += tamanho;
        }

        Err("nem teclado nem mouse de boot na configuracao")
    }

    /// Configura o endpoint de interrupção e põe o dispositivo para falar.
    fn preparar_hid(&mut self, d: &mut DispositivoUsb) -> Result<(), &'static str> {
        let achado = self.achar_hid(d)?;

        // O identificador do endpoint dentro do slot: entrada é ímpar.
        let dci = achado.endpoint * 2 + 1;
        let anel = Anel::novo().ok_or("sem frame para o anel de relatorios")?;
        let ponteiro = anel.ponteiro_inicial();

        // O contexto de entrada, outra vez: o do slot porque o número de
        // contextos mudou, e o do endpoint novo.
        let entrada = d.entrada;
        self.escrever_contexto(entrada, 0, 0, 0);
        self.escrever_contexto(entrada, 0, 1, 1 | (1 << dci));
        self.escrever_contexto(entrada, 1, 0, (u32::from(dci) << 27) | (d.velocidade << 20));
        self.escrever_contexto(entrada, 1, 1, u32::from(d.porta) << 16);

        let contexto_do_ep = usize::from(dci) + 1;
        self.escrever_contexto(
            entrada,
            contexto_do_ep,
            0,
            intervalo_do_xhci(d.velocidade, achado.intervalo) << 16,
        );
        self.escrever_contexto(
            entrada,
            contexto_do_ep,
            1,
            (u32::from(achado.pacote) << 16)
                | (EP_INTERRUPCAO_ENTRADA << 3)
                | (TENTATIVAS_DO_ENDPOINT << 1),
        );
        self.escrever_contexto(entrada, contexto_do_ep, 2, ponteiro as u32);
        self.escrever_contexto(entrada, contexto_do_ep, 3, (ponteiro >> 32) as u32);
        self.escrever_contexto(
            entrada,
            contexto_do_ep,
            4,
            u32::from(achado.pacote) | (u32::from(achado.pacote) << 16),
        );

        let evento = self
            .comandar(
                entrada,
                (trb::CONFIGURAR_ENDPOINT << 10) | (u32::from(d.slot) << 24),
            )
            .ok_or("o controlador nao respondeu ao configurar endpoint")?;
        if (evento.estado >> 24) & 0xFF != SUCESSO {
            return Err("configurar o endpoint foi recusado");
        }

        // Só agora o dispositivo é posto na configuração, e só depois disso
        // ele aceita o pedido de classe que escolhe o protocolo de boot.
        self.controle(
            d,
            pedido::SAIDA_PADRAO,
            pedido::DEFINIR_CONFIGURACAO,
            u16::from(achado.configuracao),
            0,
            0,
        )?;
        self.controle(
            d,
            pedido::SAIDA_DE_CLASSE,
            pedido::DEFINIR_PROTOCOLO,
            // Zero é o protocolo de boot; um é o de relatório, que exigiria
            // interpretar o descritor de relatório.
            0,
            u16::from(achado.interface),
            0,
        )?;

        crate::log_info!(
            "usb",
            "{} usb pronto na porta {}, protocolo de boot",
            achado.tipo.nome(),
            d.porta
        );
        d.hid = Some(Hid {
            tipo: achado.tipo,
            anel,
            dci,
            // O relatório inteiro, até o espaço que ele tem no buffer. Pedir
            // menos que o pacote faria o controlador cortar o relatório —
            // e, num teclado, perder teclas.
            tamanho: usize::from(achado.pacote).clamp(1, TAMANHO_DO_RELATORIO),
            submetidos: 0,
            colhidos: 0,
            anterior: [0; TAMANHO_DO_RELATORIO],
        });
        Ok(())
    }

    /// Pendura no controlador as transferências que faltam ao dispositivo
    /// `i` — só as que faltam.
    fn pendurar_relatorios(&mut self, i: usize) {
        let Some(d) = self.dispositivos.get_mut(i) else {
            return;
        };
        let Some(hid) = d.hid.as_mut() else {
            return;
        };

        let mut pendurou = false;
        while hid.submetidos - hid.colhidos < RELATORIOS as u64 {
            let endereco = d.buffer + relatorio_em((hid.submetidos % RELATORIOS as u64) as usize);
            hid.anel
                .empurrar(endereco, hid.tamanho as u32, (trb::NORMAL << 10) | AVISAR);
            hid.submetidos += 1;
            pendurou = true;
        }

        if pendurou {
            self.c.campainha(d.slot, u32::from(hid.dci));
        }
    }

    /// Lê os relatórios que chegaram e devolve as transferências.
    fn colher_relatorios(&mut self) {
        let mut colheu = [false; DISPOSITIVOS];
        while let Some(evento) = self.eventos.colher() {
            // O ponteiro de leitura é atualizado sempre, mesmo para eventos
            // que não nos interessam: é ele que diz ao controlador que há
            // espaço no anel.
            self.c.devolver_eventos(&self.eventos);

            if tipo_de(evento.controle) != trb::EVENTO_DE_TRANSFERENCIA {
                continue;
            }

            // De quem é: o evento diz o slot e o endpoint. Sem conferir os
            // dois, o relatório do mouse seria lido como uma tecla.
            let slot = (evento.controle >> 24) as u8;
            let dci = ((evento.controle >> 16) & 0x1F) as u8;
            let Some(i) = self
                .dispositivos
                .iter()
                .position(|d| d.slot == slot && d.hid.as_ref().is_some_and(|h| h.dci == dci))
            else {
                continue;
            };
            let d = &mut self.dispositivos[i];
            let hid = d.hid.as_mut().expect("conferido acima");

            // As transferências de um endpoint completam na ordem em que
            // foram penduradas, então qual delas voltou sai de um contador —
            // e não do endereço do TRB, que exigiria procurar no anel.
            let indice = (hid.colhidos % RELATORIOS as u64) as usize;
            hid.colhidos += 1;
            colheu[i] = true;

            let codigo = (evento.estado >> 24) & 0xFF;
            if codigo != SUCESSO && codigo != 13 {
                continue;
            }
            let base = crate::arch::acesso_fisico(d.buffer + relatorio_em(indice));
            // SAFETY: o endereço é de um buffer de oito bytes dentro do frame
            // que este driver alocou, e o controlador acabou de dizer que
            // terminou de escrever nele.
            let relatorio = unsafe { core::ptr::read_volatile(base as *const [u8; 8]) };
            // Quanto veio: o pedido menos o que faltou. Um mouse que manda
            // menos que os três bytes do boot não é lido — ver
            // [`crate::usb::hid::processar_mouse`].
            let veio = hid
                .tamanho
                .saturating_sub((evento.estado & 0x00FF_FFFF) as usize);
            match hid.tipo {
                TipoHid::Teclado => crate::usb::hid::processar(&mut hid.anterior, relatorio),
                TipoHid::Mouse => crate::usb::hid::processar_mouse(&relatorio[..veio]),
            }
        }

        for (i, colheu) in colheu.into_iter().enumerate() {
            if colheu {
                self.pendurar_relatorios(i);
            }
        }
    }
}

/// O intervalo do endpoint, na codificação do xHCI.
///
/// O USB conta em unidades que dependem da velocidade e o xHCI conta sempre
/// em potências de dois de 125 microssegundos. Em alta velocidade o
/// descritor já traz o expoente, e a conversão é subtrair um; em velocidade
/// cheia ele traz milissegundos, e o expoente sai do logaritmo.
fn intervalo_do_xhci(velocidade: u32, bintervalo: u8) -> u32 {
    if velocidade >= 3 {
        u32::from(bintervalo.saturating_sub(1)).min(15)
    } else {
        let milissegundos = u32::from(bintervalo).max(1);
        (milissegundos.ilog2() + 3).min(15)
    }
}

/// Onde, dentro do buffer de um dispositivo, fica o relatório `i`.
fn relatorio_em(i: usize) -> u64 {
    (RELATORIOS_EM + i * TAMANHO_DO_RELATORIO) as u64
}

/// O teclado ou o mouse, depois de configurado.
struct Hid {
    tipo: TipoHid,
    anel: Anel,
    /// O identificador do endpoint dentro do slot.
    dci: u8,
    /// Quantos bytes cada relatório pede.
    tamanho: usize,
    /// Quantas transferências já foram entregues ao controlador.
    submetidos: u64,
    /// Quantas já voltaram.
    ///
    /// # Por que dois contadores, e não um índice
    ///
    /// Porque a diferença entre eles é quantas estão **com o dispositivo**, e
    /// era isso que faltava. A primeira versão pendurava quatro
    /// transferências a cada colheita, sem saber quantas tinham voltado: com
    /// uma só de volta, o anel passava a ter sete pendentes apontando para
    /// quatro buffers, dois a dois. O dispositivo escrevia dois relatórios no
    /// mesmo lugar e a conta de qual buffer voltou saía errada dali em
    /// diante.
    ///
    /// Com três teclas não aparecia — quatro buffers cobriam a rajada inteira
    /// antes de qualquer recolocação. Apareceu na sonda do interpretador, que
    /// digita doze: `agent.ping` chegava truncado, e o comando nunca
    /// executava. É o mesmo defeito que a placa de rede documenta, pela mesma
    /// razão: entregar o mesmo buffer duas vezes não deixa marca no que se lê.
    colhidos: u64,
    /// O relatório anterior, para um teclado deduzir o que mudou — ver
    /// [`crate::usb::hid::processar`]. Um mouse não usa.
    anterior: [u8; TAMANHO_DO_RELATORIO],
}

/// Recolhe o que o teclado e o mouse USB tiverem entregue.
pub fn colher() {
    crate::arch::sem_interrupcoes(|| {
        if let Some(xhci) = XHCI.lock().as_mut() {
            xhci.colher_relatorios();
        }
    });
}

/// Destrava o controlador xHCI à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        XHCI.force_unlock();
    }
}
