//! O teclado do ARM, por virtio.
//!
//! # Por que virtio e não PS/2
//!
//! Porque a máquina `virt` não tem um controlador 8042: ele é uma peça do PC,
//! e o ARM não é um PC. O que ela tem é o barramento PCI, e sobre ele um
//! `virtio-input` — um dispositivo que entrega eventos de entrada no mesmo
//! formato que o Linux usa internamente.
//!
//! # O que este driver não faz
//!
//! Não lê a descrição do dispositivo. O espaço de configuração do
//! `virtio-input` permite perguntar o nome, os eixos e quais teclas existem,
//! e nada disso muda o que fazemos: os eventos que chegam são traduzidos
//! pelo código, e um código que não conhecemos é ignorado. Perguntar antes
//! seria cerimônia sem consequência.
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

/// O tipo de evento que interessa: tecla.
///
/// Os outros que o dispositivo emite — sincronismo, sobretudo — chegam e são
/// ignorados. Ignorar é o comportamento certo e não uma lacuna: o
/// sincronismo agrupa eventos de um mesmo instante, o que importa para um
/// mouse, onde x e y de um movimento precisam ser lidos juntos.
const EV_KEY: u16 = 1;

/// O teclado da máquina, se houver um.
static TECLADO: Mutex<Option<Teclado>> = Mutex::new(None);

pub struct Teclado {
    transporte: Transporte,
    eventos: Fila,
    /// O frame que hospeda os buffers, e por onde a CPU o alcança.
    frame: u64,
    base: *mut u8,
    /// Quantos eventos chegaram, de qualquer tipo.
    recebidos: u64,
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
                traduzir(bruto);
            }
        }

        if colhidos > 0 {
            self.pendurar();
            self.eventos.notificar(&self.transporte);
        }
    }
}

/// Converte um evento do dispositivo numa tecla, se for uma.
///
/// Os campos são little-endian no fio, como todo o virtio.
fn traduzir(bruto: [u8; 8]) {
    let tipo = u16::from_le_bytes([bruto[0], bruto[1]]);
    let codigo = u16::from_le_bytes([bruto[2], bruto[3]]);
    let valor = u32::from_le_bytes([bruto[4], bruto[5], bruto[6], bruto[7]]);

    if tipo != EV_KEY {
        return;
    }

    // Códigos acima de 255 existem — teclas de multimídia, botões de mouse —
    // e nenhum deles produz texto.
    let Ok(codigo) = u8::try_from(codigo) else {
        return;
    };

    // Valor 1 é pressionar e 2 é repetição automática; as duas produzem
    // caractere, que é o que uma pessoa segurando uma tecla espera. Zero é
    // soltar, e importa para o shift.
    crate::teclado::evento(codigo, valor != 0);
}

/// Procura o teclado no barramento e o põe de pé.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none() && d.fabricante == FABRICANTE && d.modelo == MODELO {
            alvo = Some(*d);
        }
    });

    let Some(alvo) = alvo else {
        crate::log_info!("virtio", "nenhum teclado virtio no barramento");
        return;
    };

    match Teclado::novo(&alvo) {
        Ok(teclado) => {
            crate::log_info!(
                "virtio",
                "teclado em {:02x}.{} pronto, {} buffers de evento",
                alvo.dispositivo,
                alvo.funcao,
                BUFFERS
            );
            *TECLADO.lock() = Some(teclado);
        }
        Err(motivo) => crate::log_warn!("virtio", "teclado nao inicializado: {}", motivo),
    }
}

/// Recolhe o que o teclado tiver entregue.
///
/// Chamada a cada tique do relógio. Ver a nota em [`crate::tempo`] sobre por
/// que não é por interrupção.
pub fn colher() {
    crate::arch::sem_interrupcoes(|| {
        if let Some(teclado) = TECLADO.lock().as_mut() {
            teclado.colher();
        }
    });
}

/// Quantos eventos o teclado entregou. Para o relatório do agente.
pub fn recebidos() -> Option<u64> {
    crate::arch::sem_interrupcoes(|| TECLADO.lock().as_ref().map(|t| t.recebidos))
}
