//! O disco.
//!
//! # Como um pedido se parece
//!
//! Um pedido de bloco no virtio são três buffers encadeados, e a divisão em
//! três não é arbitrária — ela segue quem escreve em quê:
//!
//! 1. O **cabeçalho**: o que se quer (ler ou escrever) e de qual setor. Nós
//!    escrevemos, o dispositivo lê.
//! 2. Os **dados**: numa leitura, o dispositivo escreve; numa escrita, lê.
//! 3. O **estado**: um byte com o resultado. Só o dispositivo escreve.
//!
//! Poderiam ser dois, com o estado no fim dos dados. São três porque a direção
//! é uma propriedade do descritor: o buffer de estado precisa ser gravável
//! pelo dispositivo mesmo quando o de dados não é, e um descritor não tem como
//! dizer "leitura até aqui, escrita daqui para frente".
//!
//! # Por que espera em laço, e não interrupção
//!
//! Porque interrupção de dispositivo PCI exige rotear a linha — MSI-X, ou o
//! mapeamento de INTx que o device tree descreve no ARM e a ACPI no x86 —, e
//! isso é um subsistema inteiro que ainda não existe aqui. Esperar em laço é o
//! que torna o disco utilizável **antes** dele, e o custo é real mas contido:
//! uma leitura de um setor num dispositivo emulado volta em microssegundos, e
//! quem chama é o boot ou o canal do agente, não um caminho quente.
//!
//! O laço tem teto. Um dispositivo que não responde vira um erro, não um
//! kernel parado — que é a diferença entre um bug diagnosticável e um boot que
//! trava sem dizer nada.

use spin::Mutex;

use super::fila::Fila;
use super::transporte::{FABRICANTE, Mmio, Transporte, VERSAO_1};
use crate::pci::Dispositivo;

/// Os modelos de dispositivo de bloco do virtio.
///
/// Dois porque a especificação renumerou: os dispositivos *transicionais*, que
/// falam tanto o legado quanto o moderno, mantiveram o número antigo para não
/// quebrar drivers existentes, e os puramente modernos ganharam um novo. O
/// QEMU entrega o transicional por padrão, mas aceitar os dois custa uma
/// comparação.
const MODELO_TRANSICIONAL: u16 = 0x1001;
const MODELO_MODERNO: u16 = 0x1042;

/// A fila de pedidos. O virtio-blk tem uma só.
const FILA_DE_PEDIDOS: u16 = 0;

/// Quanto mede um setor, no vocabulário do virtio-blk.
///
/// Fixo em 512 pela especificação, independentemente do tamanho de bloco do
/// dispositivo real por baixo: a capacidade é contada nesta unidade e os
/// pedidos são endereçados nela.
pub const TAMANHO_DO_SETOR: usize = 512;

/// Tipos de pedido.
const LER: u32 = 0;

/// Valores do byte de estado.
const OK: u8 = 0;

/// Onde a capacidade está, na configuração específica do dispositivo.
const CONFIG_CAPACIDADE: u64 = 0;

/// O cabeçalho de um pedido, como o dispositivo espera lê-lo.
///
/// `repr(C)` porque isto é um contrato de layout com software que não é nosso.
#[repr(C)]
#[derive(Clone, Copy)]
struct Cabecalho {
    tipo: u32,
    reservado: u32,
    setor: u64,
}

// Deslocamentos dos três buffers dentro do frame de trabalho. Um frame só,
// pelo mesmo motivo da fila: os buffers precisam ser fisicamente contíguos, e
// um frame é a menor unidade que garante isso.
const CABECALHO_EM: u64 = 0;
const DADOS_EM: u64 = 16;
const ESTADO_EM: u64 = DADOS_EM + TAMANHO_DO_SETOR as u64;

const _: () = assert!(ESTADO_EM < crate::arch::TAMANHO_PAGINA);
const _: () = assert!(core::mem::size_of::<Cabecalho>() as u64 == DADOS_EM - CABECALHO_EM);

/// Quantas voltas esperar por uma resposta antes de desistir.
///
/// Não é um tempo: é um número de tentativas, porque aqui ainda não há relógio
/// confiável em todo caminho que chama o disco. A ordem de grandeza é
/// deliberadamente folgada — um dispositivo emulado responde em algumas
/// dezenas de voltas, e o teto só precisa distinguir "lento" de "morto".
const VOLTAS_DE_ESPERA: u32 = 5_000_000;

/// Um disco virtio pronto para uso.
pub struct Disco {
    transporte: Transporte,
    fila: Fila,
    /// Frame físico com o cabeçalho, os dados e o byte de estado.
    trabalho: u64,
    /// Endereço virtual do mesmo frame.
    base: *mut u8,
    /// Capacidade, em setores de 512 bytes.
    capacidade: u64,
}

// SAFETY: o ponteiro é para um frame de propriedade exclusiva deste disco,
// alocado na construção e nunca compartilhado. É o ponteiro cru que impede a
// derivação automática, não uma restrição real.
unsafe impl Send for Disco {}

/// O disco da máquina, se houver um.
///
/// Um só: a máquina de testes tem um disco, e uma tabela de discos com uma
/// entrada seria generalidade sem cliente. Quando houver o segundo, o tipo
/// [`Disco`] já é o que precisa ser multiplicado — nada aqui assume unicidade
/// além deste `static`.
static DISCO: Mutex<Option<Disco>> = Mutex::new(None);

impl Disco {
    /// Liga um dispositivo de bloco encontrado no barramento.
    fn ligar(d: &Dispositivo) -> Result<Disco, &'static str> {
        let transporte = Transporte::descobrir(d)?;

        // Nada além do virtio 1.0. Cada recurso extra é um contrato a mais a
        // honrar — descritores indiretos mudam o formato da cadeia, o índice
        // de eventos muda quando notificar — e nenhum deles compra algo que
        // este driver precise.
        let recursos = transporte.iniciar(VERSAO_1)?;
        debug_assert_eq!(recursos, VERSAO_1);

        if transporte.filas() == 0 {
            transporte.abortar();
            return Err("dispositivo de bloco sem filas");
        }

        let capacidade = transporte
            .configuracao()
            .and_then(|config: Mmio| config.ler_u64(CONFIG_CAPACIDADE))
            .ok_or("dispositivo nao publica capacidade")?;

        let fila = match Fila::nova(&transporte, FILA_DE_PEDIDOS) {
            Ok(fila) => fila,
            Err(motivo) => {
                transporte.abortar();
                return Err(motivo);
            }
        };

        let Some(trabalho) = crate::frames::alocar() else {
            transporte.abortar();
            return Err("sem frame para os buffers de pedido");
        };
        let base = crate::arch::acesso_fisico(trabalho);

        // Só agora: o dispositivo pode começar a trabalhar a partir desta
        // escrita, e antes dela a fila não existia para ele.
        transporte.liberar();

        // Ligar a mestria de barramento é o último passo, e é o que de fato
        // autoriza o dispositivo a ler e escrever na nossa memória. Tudo até
        // aqui foi conversa por registradores; daqui para frente ele segue
        // ponteiros. Ver `pci::habilitar_mestre` para por que isso não é feito
        // na varredura.
        crate::pci::habilitar_mestre(d);

        Ok(Disco {
            transporte,
            fila,
            trabalho,
            base,
            capacidade,
        })
    }

    /// Quantos setores o disco tem.
    pub fn capacidade(&self) -> u64 {
        self.capacidade
    }

    /// Lê um setor para `destino`.
    ///
    /// `destino` precisa ter exatamente [`TAMANHO_DO_SETOR`] bytes: um pedido
    /// de bloco não tem como devolver meio setor, e aceitar uma fatia menor só
    /// esconderia de quem chama que o resto foi lido e descartado.
    pub fn ler_setor(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        if destino.len() != TAMANHO_DO_SETOR {
            return Err("o destino precisa ter um setor");
        }
        if setor >= self.capacidade {
            return Err("setor alem da capacidade do disco");
        }

        // SAFETY: o frame é deste disco, os três deslocamentos vêm das
        // constantes de layout, e a asserção de compilação garante que cabem.
        unsafe {
            core::ptr::write_volatile(
                self.base.add(CABECALHO_EM as usize) as *mut Cabecalho,
                Cabecalho {
                    tipo: LER.to_le(),
                    reservado: 0,
                    setor: setor.to_le(),
                },
            );
            // O byte de estado é preenchido com algo que não é `OK`. Sem isso,
            // um dispositivo que não escrevesse nada deixaria o zero do frame
            // anterior passar por sucesso — e o teste que lê um setor com
            // conteúdo conhecido é justamente o que não perceberia.
            core::ptr::write_volatile(self.base.add(ESTADO_EM as usize), 0xFF);
        }

        let cabeca = self.fila.submeter(&[
            (self.trabalho + CABECALHO_EM, DADOS_EM as u32, false),
            (self.trabalho + DADOS_EM, TAMANHO_DO_SETOR as u32, true),
            (self.trabalho + ESTADO_EM, 1, true),
        ])?;
        self.fila.notificar(&self.transporte);

        let (respondido, _) = self.esperar()?;
        if respondido != cabeca {
            return Err("dispositivo respondeu uma cadeia que nao pedimos");
        }

        // SAFETY: o dispositivo terminou (foi o que a colheita significou), e
        // os dois acessos ficam dentro do frame pelas constantes de layout.
        let estado = unsafe { core::ptr::read_volatile(self.base.add(ESTADO_EM as usize)) };
        if estado != OK {
            return Err("o dispositivo recusou a leitura");
        }

        // SAFETY: a origem é o frame de trabalho, o destino tem exatamente o
        // tamanho conferido acima, e as duas regiões não se sobrepõem — o
        // frame é do kernel e `destino` é de quem chamou.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.base.add(DADOS_EM as usize),
                destino.as_mut_ptr(),
                TAMANHO_DO_SETOR,
            )
        };

        Ok(())
    }

    /// Espera a fila devolver alguma coisa.
    fn esperar(&mut self) -> Result<(u16, u32), &'static str> {
        for _ in 0..VOLTAS_DE_ESPERA {
            if let Some(resposta) = self.fila.colher() {
                return Ok(resposta);
            }
            core::hint::spin_loop();
        }
        Err("o dispositivo nao respondeu")
    }
}

/// Procura um disco virtio no barramento e o liga.
///
/// Chamada depois da enumeração do PCI, que é o que preenche o inventário e
/// dá endereço aos BARs.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none()
            && d.fabricante == FABRICANTE
            && (d.modelo == MODELO_TRANSICIONAL || d.modelo == MODELO_MODERNO)
        {
            alvo = Some(*d);
        }
    });

    let Some(alvo) = alvo else {
        crate::log_info!("virtio", "nenhum disco no barramento");
        return;
    };

    match Disco::ligar(&alvo) {
        Ok(disco) => {
            crate::log_info!(
                "virtio",
                "disco em {:02x}.{}: {} KiB",
                alvo.dispositivo,
                alvo.funcao,
                disco.capacidade() * TAMANHO_DO_SETOR as u64 / 1024
            );
            *DISCO.lock() = Some(disco);
        }
        Err(motivo) => crate::log_error!("virtio", "disco nao pode ser ligado: {}", motivo),
    }
}

/// Chama `f` com o disco da máquina, se houver um.
///
/// O acesso passa por aqui, e não por um `&'static mut`, porque um pedido de
/// bloco não é reentrante: o frame de trabalho é um só, e duas leituras
/// simultâneas escreveriam o cabeçalho uma por cima da outra. A tranca é o que
/// torna isso impossível em vez de improvável.
pub fn com_o_disco<R>(f: impl FnOnce(&mut Disco) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| DISCO.lock().as_mut().map(f))
}
