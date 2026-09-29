//! A entrada do ARM, por virtio: o teclado e o tablet.
//!
//! # Por que virtio e não PS/2
//!
//! Porque a máquina `virt` não tem um controlador 8042: ele é uma peça do PC,
//! e o ARM não é um PC. O que ela tem é o barramento PCI, e sobre ele um
//! `virtio-input` — um dispositivo que entrega eventos de entrada no mesmo
//! formato que o Linux usa internamente.
//!
//! # Um driver, dois dispositivos
//!
//! O teclado e o tablet são o mesmo `virtio-input`, e o que chega dos dois
//! é o mesmo evento do Linux: tipo, código e valor. Então há um driver só,
//! que atende até dois deles, e o que decide o destino é o tipo do evento —
//! tecla vai para o teclado; botão, eixo e movimento vão para o ponteiro.
//!
//! # O que ele pergunta ao dispositivo
//!
//! Só o alcance dos eixos absolutos. Um tablet diz onde o ponteiro está numa
//! escala dele — a do QEMU vai de 0 a 32767 —, e sem saber o máximo não há
//! como passar para pixels. O resto do espaço de configuração — o nome, as
//! teclas que existem — não muda o que fazemos: um código que não
//! conhecemos é ignorado.
//!
//! Também não usa a fila de status, por onde se acenderiam os LEDs de
//! `caps lock` e companhia. Não há o que acender.

use spin::Mutex;

use super::fila::Fila;
use super::transporte::{FABRICANTE, Transporte, VERSAO_1};
use crate::pci::Dispositivo;

/// O identificador PCI do `virtio-input` moderno.
///
/// Um só, e não um par como na rede e no disco: o `virtio-input` nasceu
/// depois da versão 1 do padrão, então nunca teve a forma transicional que
/// os dispositivos antigos carregam para os drivers anteriores a ela.
const MODELO: u16 = 0x1052;

/// A fila por onde os eventos chegam.
const FILA_DE_EVENTOS: u16 = 0;

/// Um evento tem oito bytes: dois de tipo, dois de código, quatro de valor.
const TAMANHO_DO_EVENTO: u32 = 8;

/// Quantos eventos podem estar pendurados no dispositivo ao mesmo tempo.
///
/// O teto é o número de descritores da fila. Uma tecla produz dois eventos —
/// o de tecla e o de sincronismo —, então oito buffers são quatro teclas
/// entre duas colheitas. Com a colheita a cada tique do relógio, isso são
/// quatro teclas em dez milissegundos: quatrocentas por segundo, umas vinte
/// vezes mais rápido do que alguém digita.
const BUFFERS: usize = super::fila::DESCRITORES as usize;

/// Os tipos de evento que interessam, na numeração do Linux.
///
/// O sincronismo fecha um lote de eventos do mesmo instante: é nele que o
/// cursor anda, e não a cada eixo, para não andar em escada.
const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;

/// Os códigos do ponteiro.
const BTN_LEFT: u16 = 0x110;
const EIXO_X: u16 = 0;
const EIXO_Y: u16 = 1;

/// O pedido de configuração que devolve o alcance de um eixo.
const CFG_ABS_INFO: u8 = 0x12;

/// Quantos dispositivos de entrada o driver atende: um teclado e um tablet.
const MAX_DISPOSITIVOS: usize = 2;

/// Os dispositivos de entrada da máquina.
static TECLADO: Mutex<[Option<Teclado>; MAX_DISPOSITIVOS]> = Mutex::new([None, None]);

pub struct Teclado {
    transporte: Transporte,
    eventos: Fila,
    /// O frame que hospeda os buffers, e por onde a CPU o alcança.
    frame: u64,
    base: *mut u8,
    /// Quantos eventos chegaram, de qualquer tipo.
    recebidos: u64,
    /// O máximo de cada eixo absoluto, se o dispositivo é um tablet; zero
    /// num teclado.
    maximo: (u32, u32),
    /// A última posição absoluta, eixo a eixo: os dois chegam em eventos
    /// separados.
    posicao: (u32, u32),
}

// SAFETY: o ponteiro é para um frame que este driver aloca e nunca devolve, e
// todo acesso a ele passa pelo `Mutex` que guarda o dono. É a mesma razão
// pela qual a placa de rede é `Send`.
unsafe impl Send for Teclado {}

impl Teclado {
    fn novo(d: &Dispositivo) -> Result<Teclado, &'static str> {
        let transporte = Transporte::descobrir(d)?;
        transporte.iniciar(VERSAO_1)?;

        let eventos = Fila::nova(&transporte, FILA_DE_EVENTOS)?;
        let maximo = (alcance(&transporte, EIXO_X), alcance(&transporte, EIXO_Y));

        let Some(frame) = crate::frames::alocar() else {
            transporte.abortar();
            return Err("sem frame para os buffers de entrada");
        };

        let mut teclado = Teclado {
            transporte,
            eventos,
            frame,
            base: crate::arch::acesso_fisico(frame),
            recebidos: 0,
            maximo,
            posicao: (0, 0),
        };

        // Os buffers antes do `DRIVER_OK`, pela mesma razão que a rede: a
        // partir dele o dispositivo pode entregar, e precisa ter onde pôr.
        crate::pci::habilitar_mestre(d);
        teclado.pendurar();
        teclado.transporte.liberar();
        teclado.eventos.notificar(&teclado.transporte);

        super::ligar_interrupcao(d, &teclado.transporte, super::NOME_TECLADO);

        Ok(teclado)
    }

    /// O endereço físico do buffer de índice `i`.
    fn buffer(&self, i: usize) -> u64 {
        self.frame + i as u64 * TAMANHO_DO_EVENTO as u64
    }

    /// Este buffer já está com o dispositivo?
    ///
    /// A pergunta sai da tabela de descritores, e não de uma cópia nossa —
    /// pela mesma razão que a rede documenta: duas cópias da mesma informação
    /// divergem, e a que diverge aqui entrega o mesmo buffer duas vezes.
    fn ja_pendurado(&self, i: usize) -> bool {
        let endereco = self.buffer(i);
        (0..super::fila::DESCRITORES).any(|posicao| {
            self.eventos.em_uso(posicao)
                && self.eventos.endereco_do_descritor(posicao) == Some(endereco)
        })
    }

    /// Entrega ao dispositivo todo buffer que ainda não está com ele.
    fn pendurar(&mut self) {
        for i in 0..BUFFERS {
            if self.ja_pendurado(i) {
                continue;
            }
            // Escrita pelo dispositivo: é ele quem preenche o evento.
            if self
                .eventos
                .submeter(&[(self.buffer(i), TAMANHO_DO_EVENTO, true)])
                .is_err()
            {
                // Sem descritor livre não há o que fazer além de parar: os que
                // estão em uso voltam na próxima colheita.
                break;
            }
        }
    }

    /// Lê os eventos que chegaram e devolve os buffers ao dispositivo.
    fn colher(&mut self) {
        let mut colhidos = 0;

        while let Some((cabeca, escritos)) = self.eventos.colher() {
            colhidos += 1;
            self.recebidos += 1;

            // Um relato menor que um evento é o dispositivo dizendo algo
            // impossível. Ler assim mesmo montaria um evento com metade dos
            // campos vindos do buffer anterior.
            if escritos >= TAMANHO_DO_EVENTO
                && let Some(endereco) = self.eventos.endereco_do_descritor(cabeca)
            {
                let deslocamento = endereco.saturating_sub(self.frame) as usize;
                // SAFETY: o endereço veio de um descritor que este driver
                // submeteu, e todos apontam para dentro do frame que ele
                // alocou; o evento tem oito bytes e o frame tem quatro mil.
                let bruto = unsafe {
                    core::ptr::read_volatile(self.base.add(deslocamento) as *const [u8; 8])
                };
                self.traduzir(bruto);
            }
        }

        if colhidos > 0 {
            self.pendurar();
            self.eventos.notificar(&self.transporte);
        }
    }
}

impl Teclado {
    fn traduzir(&mut self, bruto: [u8; 8]) {
        traduzir(&mut self.posicao, self.maximo, bruto);
    }
}

/// Leva um evento do dispositivo a quem ele interessa: a tecla ao teclado, o
/// botão e o movimento ao ponteiro.
///
/// `posicao` é a última posição absoluta do dispositivo, eixo a eixo — os
/// dois chegam em eventos separados —, e `maximo` o alcance dos eixos dele.
/// Uma função, e não só um método, para a suíte alcançá-la com eventos
/// montados à mão: sem isso, só a fumaça, com um tablet de verdade,
/// exercitaria a tradução.
///
/// Os campos são little-endian no fio, como todo o virtio.
pub fn traduzir(posicao: &mut (u32, u32), maximo: (u32, u32), bruto: [u8; 8]) {
    let tipo = u16::from_le_bytes([bruto[0], bruto[1]]);
    let codigo = u16::from_le_bytes([bruto[2], bruto[3]]);
    let valor = u32::from_le_bytes([bruto[4], bruto[5], bruto[6], bruto[7]]);

    match tipo {
        EV_KEY if codigo == BTN_LEFT => crate::ponteiro::botao(valor != 0),
        EV_KEY => {
            // Códigos acima de 255 existem — teclas de multimídia, os outros
            // botões do mouse — e nenhum deles produz texto.
            let Ok(codigo) = u8::try_from(codigo) else {
                return;
            };
            // Valor 1 é pressionar e 2 é repetição automática; as duas
            // produzem caractere, que é o que uma pessoa segurando uma tecla
            // espera. Zero é soltar, e importa para o shift.
            crate::teclado::evento(codigo, valor != 0);
        }
        // Cada eixo na hora em que chega, e não só no sincronismo: um clique
        // que viesse no mesmo lote cairia na posição anterior.
        EV_ABS if codigo == EIXO_X || codigo == EIXO_Y => {
            if codigo == EIXO_X {
                posicao.0 = valor;
            } else {
                posicao.1 = valor;
            }
            crate::ponteiro::absoluto(posicao.0, posicao.1, maximo.0, maximo.1);
        }
        // O valor de um eixo relativo é um inteiro com sinal.
        EV_REL if codigo == EIXO_X => crate::ponteiro::relativo(valor as i32, 0),
        EV_REL if codigo == EIXO_Y => crate::ponteiro::relativo(0, valor as i32),
        EV_SYN => crate::ponteiro::sincronizar(),
        _ => {}
    }
}

/// Um evento no formato do fio: tipo, código e valor. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn evento(tipo: u16, codigo: u16, valor: u32) -> [u8; 8] {
    let mut bruto = [0u8; 8];
    bruto[0..2].copy_from_slice(&tipo.to_le_bytes());
    bruto[2..4].copy_from_slice(&codigo.to_le_bytes());
    bruto[4..8].copy_from_slice(&valor.to_le_bytes());
    bruto
}

/// O máximo de um eixo absoluto, pelo espaço de configuração; zero se o
/// dispositivo não tem o eixo — um teclado.
///
/// O pedido é escrever o seletor e o eixo nos dois primeiros bytes; a
/// resposta vem no terceiro, o tamanho, e a partir do oitavo, a estrutura
/// `virtio_input_absinfo`: mínimo, máximo, e três campos que não usamos.
fn alcance(transporte: &Transporte, eixo: u16) -> u32 {
    let Some(config) = transporte.configuracao() else {
        return 0;
    };
    if !config.escrever_u8(0, CFG_ABS_INFO) || !config.escrever_u8(1, eixo as u8) {
        return 0;
    }
    match config.ler_u8(2) {
        Some(tamanho) if tamanho >= 8 => config.ler_u32(12).unwrap_or(0),
        _ => 0,
    }
}

/// Procura os dispositivos de entrada no barramento e os põe de pé.
pub fn init() {
    let mut alvos = [None; MAX_DISPOSITIVOS];
    let mut achados = 0;
    crate::pci::com_dispositivos(|d| {
        if d.fabricante == FABRICANTE && d.modelo == MODELO && achados < MAX_DISPOSITIVOS {
            alvos[achados] = Some(*d);
            achados += 1;
        }
    });

    if achados == 0 {
        crate::log_info!("virtio", "nenhuma entrada virtio no barramento");
        return;
    }

    for (i, alvo) in alvos.iter().enumerate() {
        let Some(alvo) = alvo else {
            continue;
        };
        match Teclado::novo(alvo) {
            Ok(dispositivo) => {
                let (x, y) = dispositivo.maximo;
                if x > 0 && y > 0 {
                    crate::log_info!(
                        "virtio",
                        "tablet em {:02x}.{} pronto, eixos ate {}x{}",
                        alvo.dispositivo,
                        alvo.funcao,
                        x,
                        y
                    );
                } else {
                    crate::log_info!(
                        "virtio",
                        "teclado em {:02x}.{} pronto, {} buffers de evento",
                        alvo.dispositivo,
                        alvo.funcao,
                        BUFFERS
                    );
                }
                crate::arch::sem_interrupcoes(|| TECLADO.lock()[i] = Some(dispositivo));
            }
            Err(motivo) => crate::log_warn!("virtio", "entrada nao inicializada: {}", motivo),
        }
    }
}

/// Recolhe o que os dispositivos tiverem entregue.
///
/// Chamada a cada tique do relógio. Ver a nota em [`crate::tempo`] sobre por
/// que não é por interrupção.
pub fn colher() {
    crate::arch::sem_interrupcoes(|| {
        for dispositivo in TECLADO.lock().iter_mut().flatten() {
            dispositivo.colher();
        }
    });
}

/// Quantos eventos os dispositivos entregaram. Para o relatório do agente.
pub fn recebidos() -> Option<u64> {
    crate::arch::sem_interrupcoes(|| {
        let dispositivos = TECLADO.lock();
        let mut algum = false;
        let mut total = 0;
        for d in dispositivos.iter().flatten() {
            algum = true;
            total += d.recebidos;
        }
        algum.then_some(total)
    })
}

/// Destrava o teclado virtio à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TECLADO.force_unlock();
    }
}
