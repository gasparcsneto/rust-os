//! O adaptador de vídeo virtio: uma tela que só mostra o que se manda mostrar.
//!
//! # Por que ele existe, se já há um framebuffer linear
//!
//! Porque há máquinas que não têm outro. Uma máquina virtual ARM de nuvem, ou
//! a que um programa como o UTM monta no macOS, costuma ter **só** um
//! `virtio-gpu`: sem VGA, sem `bochs-display`, sem um modo de vídeo que o
//! firmware deixe pronto para o kernel adotar. Numa máquina assim, até este
//! driver existir, o Duke subia sem tela — medido, com a `virt` do ARM levando
//! só um `virtio-gpu-pci`: "nenhum framebuffer nesta maquina". Quem estivesse
//! na frente dela não via nada.
//!
//! # A diferença que define este driver
//!
//! Num framebuffer linear, o que o kernel escreve na memória aparece na tela:
//! o dispositivo varre aquela memória sozinho. Aqui não. O kernel escreve na
//! **memória de apoio** de um recurso — RAM comum, que o dispositivo lê quando
//! mandado —, e só o que for transferido (`TRANSFER_TO_HOST_2D`) e depois
//! descarregado (`RESOURCE_FLUSH`) chega à tela.
//!
//! Isso é um custo e é o ganho. O custo: alguém precisa mandar. O ganho: o
//! que se manda é um retângulo, e só ele atravessa. É o que um compositor
//! quer — dizer "mudou isto" em vez de mandar a tela inteira.
//!
//! # De onde vem o desenho
//!
//! O protocolo é o da especificação virtio 1.x, seção do dispositivo de GPU.
//! As estruturas conferem com as do `virtio-gpud` do Redox (MIT, ver
//! `THIRD_PARTY.md`), e o que mudou em relação a ele está escrito onde mudou:
//!
//! - **O dano chega ao dispositivo.** O `update_plane` do Redox transfere o
//!   quadro inteiro — `(0, 0, largura, altura)` — qualquer que seja o dano
//!   recebido, e descarrega o dano recortado pelo `Damage::clip` que dá a
//!   volta. Aqui a transferência e a descarga são do retângulo, recortado sem
//!   transbordo.
//! - **Uma resposta de erro é um erro.** O Redox confere cada resposta com
//!   `assert_eq!`, e um dispositivo que recuse um comando derruba o daemon.
//!   Aqui derrubaria o kernel; a recusa volta para quem pediu, com o nome
//!   que a especificação dá a ela.
//! - **A espera tem teto.** Um dispositivo que não responde desliga o driver
//!   e vira uma linha no log, como no disco.
//!
//! # Por que a espera é em laço
//!
//! Pela mesma razão do disco: quem pede — a escrita no console, o caminho de
//! falha fatal — é síncrono e não pode dormir. A interrupção é registrada
//! mesmo assim, porque ela existe: sem alguém para reconhecê-la, uma linha
//! compartilhada ficaria acesa para sempre.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::trava::Mutex;

use super::fila::Fila;
use super::transporte::{FABRICANTE, Transporte, VERSAO_1};
use crate::grafico::memoria::Memoria;
use crate::pci::Dispositivo;

/// O modelo PCI de um `virtio-gpu`: `0x1040` mais o tipo 16. Ao contrário do
/// disco e da rede, não existe versão transicional — o dispositivo nasceu
/// depois da interface legada.
const MODELO: u16 = 0x1050;

/// A fila de controle. A de cursor (1) não é usada: não há ponteiro de mouse.
const FILA_DE_CONTROLE: u16 = 0;

/// Onde, no frame de trabalho, mora o pedido e onde mora a resposta.
///
/// Os dois no mesmo frame porque os dois são pequenos: o maior pedido tem 56
/// bytes, a maior resposta 408. As entradas de memória de um anexo, que podem
/// ser muitas, vão em frames à parte — ver [`Gpu::anexar`].
const PEDIDO_EM: u64 = 0;
const RESPOSTA_EM: u64 = 1024;

/// Quantas voltas esperar por uma resposta antes de desistir.
///
/// Dez vezes o teto do disco. Uma transferência de tela cheia são quatro
/// mebibytes copiados pelo hospedeiro, e isso leva ordens de grandeza a mais
/// que um setor.
const VOLTAS_DE_ESPERA: u32 = 50_000_000;

/// Quantas páginas de entradas um anexo pode usar.
///
/// Cada página leva 256 entradas; quatro levam 1024, que cobrem uma tela de
/// quatro mebibytes mesmo no pior caso, em que nenhuma página física é
/// vizinha da seguinte. Cabem na fila com o cabeçalho e a resposta: seis dos
/// oito descritores.
const PAGINAS_DE_ENTRADAS: usize = 4;
const ENTRADAS_POR_PAGINA: usize = 256;

const _: () = assert!(PAGINAS_DE_ENTRADAS + 2 <= super::fila::DESCRITORES as usize);

/// O identificador do recurso da tela. O zero é reservado pela especificação
/// para "nenhum recurso".
pub const RECURSO_DA_TELA: u32 = 1;

// ---------------------------------------------------------------------------
// O protocolo
// ---------------------------------------------------------------------------

/// Os tipos de comando e de resposta, como a especificação os numera.
mod tipo {
    pub const INFO_DAS_TELAS: u32 = 0x0100;
    pub const CRIAR_RECURSO_2D: u32 = 0x0101;
    pub const DESFAZER_RECURSO: u32 = 0x0102;
    pub const DEFINIR_VARREDURA: u32 = 0x0103;
    pub const DESCARREGAR: u32 = 0x0104;
    pub const TRANSFERIR_2D: u32 = 0x0105;
    pub const ANEXAR_MEMORIA: u32 = 0x0106;
    pub const DESANEXAR_MEMORIA: u32 = 0x0107;

    pub const OK_SEM_DADOS: u32 = 0x1100;
    pub const OK_INFO_DAS_TELAS: u32 = 0x1101;
}

/// O nome que a especificação dá a uma resposta, para o erro dizer o que o
/// dispositivo disse em vez de "falhou".
fn nome_da_resposta(tipo: u32) -> &'static str {
    match tipo {
        0 => "o dispositivo nao escreveu resposta",
        0x1200 => "o dispositivo recusou o comando (ERR_UNSPEC)",
        0x1201 => "o dispositivo ficou sem memoria (ERR_OUT_OF_MEMORY)",
        0x1202 => "tela inexistente (ERR_INVALID_SCANOUT_ID)",
        0x1203 => "recurso inexistente (ERR_INVALID_RESOURCE_ID)",
        0x1204 => "contexto inexistente (ERR_INVALID_CONTEXT_ID)",
        0x1205 => "parametro invalido (ERR_INVALID_PARAMETER)",
        _ => "o dispositivo respondeu com um tipo inesperado",
    }
}

/// B8G8R8X8: azul, verde, vermelho e um byte ignorado, nessa ordem na
/// memória. É exatamente um pixel `0x00RRGGBB` num little-endian — o formato
/// de [`crate::tela::Cor::para_u32`] e o `Bgr` de quatro bytes da tela.
const FORMATO_BGRX: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Cabecalho {
    tipo: u32,
    flags: u32,
    cerca: u64,
    contexto: u32,
    anel: u8,
    _preenchimento: [u8; 3],
}

impl Cabecalho {
    fn de(tipo: u32) -> Cabecalho {
        Cabecalho {
            tipo: tipo.to_le(),
            ..Cabecalho::default()
        }
    }
}

/// Um retângulo, como o protocolo o escreve.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Retangulo {
    pub x: u32,
    pub y: u32,
    pub largura: u32,
    pub altura: u32,
}

impl Retangulo {
    fn le(self) -> Retangulo {
        Retangulo {
            x: self.x.to_le(),
            y: self.y.to_le(),
            largura: self.largura.to_le(),
            altura: self.altura.to_le(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CriarRecurso2d {
    cabecalho: Cabecalho,
    recurso: u32,
    formato: u32,
    largura: u32,
    altura: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AnexarMemoria {
    cabecalho: Cabecalho,
    recurso: u32,
    entradas: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EntradaDeMemoria {
    endereco: u64,
    tamanho: u32,
    _preenchimento: u32,
}

/// Desanexar e desfazer têm a mesma forma: um recurso e um enchimento.
#[repr(C)]
#[derive(Clone, Copy)]
struct SobreRecurso {
    cabecalho: Cabecalho,
    recurso: u32,
    _preenchimento: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DefinirVarredura {
    cabecalho: Cabecalho,
    retangulo: Retangulo,
    varredura: u32,
    recurso: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Descarregar {
    cabecalho: Cabecalho,
    retangulo: Retangulo,
    recurso: u32,
    _preenchimento: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Transferir2d {
    cabecalho: Cabecalho,
    retangulo: Retangulo,
    deslocamento: u64,
    recurso: u32,
    _preenchimento: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ModoDeTela {
    retangulo: Retangulo,
    habilitada: u32,
    flags: u32,
}

/// Quantas telas a resposta de `GET_DISPLAY_INFO` sempre descreve.
const MAX_TELAS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct InfoDasTelas {
    cabecalho: Cabecalho,
    modos: [ModoDeTela; MAX_TELAS],
}

// Os tamanhos são os da especificação. Um campo a mais ou a menos não dá erro
// de compilação nem de dispositivo: dá um comando lido com os campos
// deslocados, e uma resposta de "parâmetro inválido" sem dizer qual.
const _: () = {
    assert!(core::mem::size_of::<Cabecalho>() == 24);
    assert!(core::mem::size_of::<CriarRecurso2d>() == 40);
    assert!(core::mem::size_of::<AnexarMemoria>() == 32);
    assert!(core::mem::size_of::<EntradaDeMemoria>() == 16);
    assert!(core::mem::size_of::<SobreRecurso>() == 32);
    assert!(core::mem::size_of::<DefinirVarredura>() == 48);
    assert!(core::mem::size_of::<Descarregar>() == 48);
    assert!(core::mem::size_of::<Transferir2d>() == 56);
    assert!(core::mem::size_of::<InfoDasTelas>() == 408);
    assert!(RESPOSTA_EM + core::mem::size_of::<InfoDasTelas>() as u64 <= 4096);
    assert!(PEDIDO_EM + core::mem::size_of::<Transferir2d>() as u64 <= RESPOSTA_EM);
};

// ---------------------------------------------------------------------------
// O que o agente e a suíte enxergam, sem tomar a trava
// ---------------------------------------------------------------------------

static COMANDOS: AtomicU64 = AtomicU64::new(0);
static DESCARGAS: AtomicU64 = AtomicU64::new(0);
static RECUSAS: AtomicU64 = AtomicU64::new(0);
/// O último retângulo transferido, empacotado como em `grafico`.
static ULTIMA_TRANSFERENCIA: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

fn guardar_transferencia(r: Retangulo) {
    ULTIMA_TRANSFERENCIA[0].store((r.x as u64) << 32 | r.y as u64, Ordering::Relaxed);
    ULTIMA_TRANSFERENCIA[1].store(
        (r.largura as u64) << 32 | r.altura as u64,
        Ordering::Relaxed,
    );
}

/// Comandos mandados, descargas feitas e respostas de erro, desde o boot.
pub fn contadores() -> (u64, u64, u64) {
    (
        COMANDOS.load(Ordering::Relaxed),
        DESCARGAS.load(Ordering::Relaxed),
        RECUSAS.load(Ordering::Relaxed),
    )
}

/// O último retângulo que atravessou para o dispositivo.
pub fn ultima_transferencia() -> Retangulo {
    let origem = ULTIMA_TRANSFERENCIA[0].load(Ordering::Relaxed);
    let medida = ULTIMA_TRANSFERENCIA[1].load(Ordering::Relaxed);
    Retangulo {
        x: (origem >> 32) as u32,
        y: origem as u32,
        largura: (medida >> 32) as u32,
        altura: medida as u32,
    }
}

// ---------------------------------------------------------------------------
// O dispositivo
// ---------------------------------------------------------------------------

/// A tela que o kernel pôs sobre este dispositivo.
struct Tela {
    memoria: Memoria,
    largura: u32,
    altura: u32,
}

pub struct Gpu {
    transporte: Transporte,
    fila: Fila,
    /// O frame de pedido e resposta, em endereço físico e pelo caminho que o
    /// kernel o alcança.
    trabalho: u64,
    base: *mut u8,
    /// A primeira tela que o dispositivo descreve como habilitada.
    modo: Retangulo,
    tela: Option<Tela>,
    /// Que recurso a tela 0 está mostrando agora.
    na_varredura: u32,
    proximo_recurso: u32,
    vivo: bool,
}

// SAFETY: `base` aponta para o frame de trabalho, que é deste dispositivo, e
// todo acesso a ele passa pela trava de [`GPU`].
unsafe impl Send for Gpu {}

static GPU: Mutex<Option<Gpu>> = Mutex::new(None);

impl Gpu {
    fn ligar(d: &Dispositivo) -> Result<Gpu, &'static str> {
        let transporte = Transporte::descobrir(d)?;

        // Nada além do virtio 1.0: sem 3D, sem EDID, sem recursos "blob".
        // Cada um é um contrato a mais, e nenhum compra o que um console e
        // um compositor 2D precisam.
        transporte.iniciar(VERSAO_1)?;

        if transporte.filas() == 0 {
            transporte.abortar();
            return Err("dispositivo de video sem filas");
        }
        let fila = match Fila::nova(&transporte, FILA_DE_CONTROLE) {
            Ok(fila) => fila,
            Err(motivo) => {
                transporte.abortar();
                return Err(motivo);
            }
        };
        let Some(trabalho) = crate::frames::alocar() else {
            // A fila fica com o frame dela, pelo motivo escrito no disco: o
            // dispositivo já pode lê-la.
            transporte.abortar();
            return Err("sem frame para os pedidos de video");
        };
        let base = crate::arch::acesso_fisico(trabalho);

        crate::pci::habilitar_mestre(d);
        // O dono se registra antes do `DRIVER_OK` — ver
        // [`super::ligar_interrupcao`] sobre por que a ordem importa.
        super::ligar_interrupcao(d, &transporte, super::NOME_VIDEO);
        transporte.liberar();

        let mut gpu = Gpu {
            transporte,
            fila,
            trabalho,
            base,
            modo: Retangulo::default(),
            tela: None,
            na_varredura: 0,
            proximo_recurso: RECURSO_DA_TELA,
            vivo: true,
        };
        gpu.modo = gpu.info_das_telas()?;
        Ok(gpu)
    }

    /// Manda um comando e espera a resposta.
    ///
    /// `extras` são buffers que vão entre o pedido e a resposta — as páginas
    /// de entradas de um anexo. Devolve o tipo da resposta, já conferido
    /// contra o `esperado`.
    fn pedir<P: Copy>(
        &mut self,
        pedido: &P,
        extras: &[(u64, u32)],
        tamanho_da_resposta: usize,
        esperado: u32,
    ) -> Result<(), &'static str> {
        if !self.vivo {
            return Err("o video parou de responder e foi desligado");
        }

        // SAFETY: o frame é deste dispositivo e as duas regiões cabem nele —
        // as asserções de compilação conferem os tamanhos contra os
        // deslocamentos.
        unsafe {
            core::ptr::write_volatile(self.base.add(PEDIDO_EM as usize) as *mut P, *pedido);
            // Uma resposta que o dispositivo não escrever tem de ler como
            // "sem resposta", e não como o `OK` que o frame guardava do
            // comando anterior.
            core::ptr::write_volatile(self.base.add(RESPOSTA_EM as usize) as *mut u32, 0);
        }

        let mut cadeia = [(0u64, 0u32, false); PAGINAS_DE_ENTRADAS + 2];
        cadeia[0] = (
            self.trabalho + PEDIDO_EM,
            core::mem::size_of::<P>() as u32,
            false,
        );
        let mut partes = 1;
        for &(endereco, tamanho) in extras {
            cadeia[partes] = (endereco, tamanho, false);
            partes += 1;
        }
        cadeia[partes] = (
            self.trabalho + RESPOSTA_EM,
            tamanho_da_resposta as u32,
            true,
        );
        partes += 1;

        let cabeca = self.fila.submeter(&cadeia[..partes])?;
        self.fila.notificar(&self.transporte);
        COMANDOS.fetch_add(1, Ordering::Relaxed);

        let mut resposta = None;
        for _ in 0..VOLTAS_DE_ESPERA {
            if let Some(r) = self.fila.colher() {
                resposta = Some(r);
                break;
            }
            core::hint::spin_loop();
        }
        let Some((respondido, _)) = resposta else {
            self.vivo = false;
            crate::log_error!(
                "virtio",
                "o video nao respondeu em {} voltas; desligado",
                VOLTAS_DE_ESPERA
            );
            return Err("o video nao respondeu");
        };
        if respondido != cabeca {
            self.vivo = false;
            return Err("o video respondeu uma cadeia que nao pedimos");
        }

        // SAFETY: o dispositivo terminou, e o cabeçalho da resposta está no
        // frame pelo deslocamento de layout.
        let tipo = u32::from_le(unsafe {
            core::ptr::read_volatile(self.base.add(RESPOSTA_EM as usize) as *const u32)
        });
        if tipo != esperado {
            RECUSAS.fetch_add(1, Ordering::Relaxed);
            return Err(nome_da_resposta(tipo));
        }
        Ok(())
    }

    /// A primeira tela habilitada, como o dispositivo a descreve.
    fn info_das_telas(&mut self) -> Result<Retangulo, &'static str> {
        self.pedir(
            &Cabecalho::de(tipo::INFO_DAS_TELAS),
            &[],
            core::mem::size_of::<InfoDasTelas>(),
            tipo::OK_INFO_DAS_TELAS,
        )?;
        // SAFETY: a resposta cabe no frame (asserção de compilação) e o
        // dispositivo acabou de escrevê-la.
        let info = unsafe {
            core::ptr::read_volatile(self.base.add(RESPOSTA_EM as usize) as *const InfoDasTelas)
        };
        info.modos
            .iter()
            .find(|m| u32::from_le(m.habilitada) != 0)
            .map(|m| Retangulo {
                x: 0,
                y: 0,
                largura: u32::from_le(m.retangulo.largura),
                altura: u32::from_le(m.retangulo.altura),
            })
            .filter(|r| r.largura > 0 && r.altura > 0)
            .ok_or("o dispositivo nao descreve nenhuma tela habilitada")
    }

    /// Cria um recurso 2D com esta memória de apoio.
    fn criar_recurso(
        &mut self,
        largura: u32,
        altura: u32,
        memoria: &Memoria,
        fundir: bool,
    ) -> Result<u32, &'static str> {
        let recurso = self.proximo_recurso;
        self.proximo_recurso = recurso
            .checked_add(1)
            .ok_or("recursos de video esgotados")?;

        self.pedir(
            &CriarRecurso2d {
                cabecalho: Cabecalho::de(tipo::CRIAR_RECURSO_2D),
                recurso: recurso.to_le(),
                formato: FORMATO_BGRX.to_le(),
                largura: largura.to_le(),
                altura: altura.to_le(),
            },
            &[],
            core::mem::size_of::<Cabecalho>(),
            tipo::OK_SEM_DADOS,
        )?;
        if let Err(motivo) = self.anexar(recurso, memoria, fundir) {
            let _ = self.sobre_recurso(tipo::DESFAZER_RECURSO, recurso);
            return Err(motivo);
        }
        Ok(recurso)
    }

    /// Anexa a memória como apoio do recurso.
    ///
    /// # Por que as entradas vão em frames à parte
    ///
    /// Porque o dispositivo quer uma entrada por faixa **física** contígua, e
    /// a memória de uma superfície é contígua só no espaço virtual: cada
    /// página vem do alocador de frames, onde a vizinha pode ser de outro
    /// dono. Uma tela de quatro mebibytes são mil páginas, e no pior caso mil
    /// entradas — dezesseis kilobytes que não cabem no frame de trabalho.
    ///
    /// `fundir` junta páginas fisicamente vizinhas numa entrada só, que é o
    /// caso comum logo depois do boot e cabe numa página de entradas. Sem
    /// fundir, cada página é uma entrada: é o pior caso, e a suíte o pede de
    /// propósito para exercitar mais de uma página de entradas.
    fn anexar(
        &mut self,
        recurso: u32,
        memoria: &Memoria,
        fundir: bool,
    ) -> Result<(), &'static str> {
        let pagina = crate::arch::TAMANHO_PAGINA;
        let paginas = memoria.bytes() / pagina;

        let mut frames = [0u64; PAGINAS_DE_ENTRADAS];
        let mut usados = 0usize;
        let mut entradas = 0usize;
        let mut atual: Option<(u64, u64)> = None;

        let resultado = (|| -> Result<(), &'static str> {
            let emitir = |frames: &mut [u64; PAGINAS_DE_ENTRADAS],
                          usados: &mut usize,
                          entradas: &mut usize,
                          faixa: (u64, u64)|
             -> Result<(), &'static str> {
                let pagina_da_entrada = *entradas / ENTRADAS_POR_PAGINA;
                if pagina_da_entrada >= PAGINAS_DE_ENTRADAS {
                    return Err("a memoria da superficie esta fragmentada demais para anexar");
                }
                if pagina_da_entrada == *usados {
                    frames[*usados] =
                        crate::frames::alocar().ok_or("sem frame para as entradas do anexo")?;
                    *usados += 1;
                }
                let em = crate::arch::acesso_fisico(frames[pagina_da_entrada]);
                let tamanho =
                    u32::try_from(faixa.1).map_err(|_| "uma faixa de memoria grande demais")?;
                // SAFETY: o frame acabou de vir do alocador e é deste anexo;
                // o índice dentro dele é menor que `ENTRADAS_POR_PAGINA`, e
                // 256 entradas de 16 bytes são exatamente uma página.
                unsafe {
                    core::ptr::write_volatile(
                        (em as *mut EntradaDeMemoria).add(*entradas % ENTRADAS_POR_PAGINA),
                        EntradaDeMemoria {
                            endereco: faixa.0.to_le(),
                            tamanho: tamanho.to_le(),
                            _preenchimento: 0,
                        },
                    );
                }
                *entradas += 1;
                Ok(())
            };

            for indice in 0..paginas {
                let fisico = crate::arch::traduzir(memoria.inicio() + indice * pagina)
                    .ok_or("uma pagina da superficie nao esta mapeada")?;
                atual = match atual {
                    Some((inicio, tamanho)) if fundir && inicio + tamanho == fisico => {
                        Some((inicio, tamanho + pagina))
                    }
                    Some(faixa) => {
                        emitir(&mut frames, &mut usados, &mut entradas, faixa)?;
                        Some((fisico, pagina))
                    }
                    None => Some((fisico, pagina)),
                };
            }
            if let Some(faixa) = atual {
                emitir(&mut frames, &mut usados, &mut entradas, faixa)?;
            }

            let mut extras = [(0u64, 0u32); PAGINAS_DE_ENTRADAS];
            for (i, extra) in extras.iter_mut().enumerate().take(usados) {
                let nesta = (entradas - i * ENTRADAS_POR_PAGINA).min(ENTRADAS_POR_PAGINA);
                *extra = (
                    frames[i],
                    (nesta * core::mem::size_of::<EntradaDeMemoria>()) as u32,
                );
            }
            self.pedir(
                &AnexarMemoria {
                    cabecalho: Cabecalho::de(tipo::ANEXAR_MEMORIA),
                    recurso: recurso.to_le(),
                    entradas: (entradas as u32).to_le(),
                },
                &extras[..usados],
                core::mem::size_of::<Cabecalho>(),
                tipo::OK_SEM_DADOS,
            )
        })();

        // As entradas só servem durante o comando: o dispositivo as copia
        // para dentro dele ao anexar. Voltam ao alocador com sucesso ou sem.
        //
        // Com uma exceção: se o dispositivo parou de responder, ele pode ainda
        // estar lendo. O frame fica preso, pelo mesmo motivo do da fila.
        if self.vivo {
            for frame in &frames[..usados] {
                crate::frames::liberar(*frame);
            }
        }
        if resultado.is_ok() {
            ENTRADAS_DO_ULTIMO_ANEXO.store(entradas as u64, Ordering::Relaxed);
        }
        resultado
    }

    fn sobre_recurso(&mut self, qual: u32, recurso: u32) -> Result<(), &'static str> {
        self.pedir(
            &SobreRecurso {
                cabecalho: Cabecalho::de(qual),
                recurso: recurso.to_le(),
                _preenchimento: 0,
            },
            &[],
            core::mem::size_of::<Cabecalho>(),
            tipo::OK_SEM_DADOS,
        )
    }

    /// Põe o recurso na tela 0.
    fn mostrar(&mut self, recurso: u32, largura: u32, altura: u32) -> Result<(), &'static str> {
        self.pedir(
            &DefinirVarredura {
                cabecalho: Cabecalho::de(tipo::DEFINIR_VARREDURA),
                retangulo: Retangulo {
                    x: 0,
                    y: 0,
                    largura,
                    altura,
                }
                .le(),
                varredura: 0,
                recurso: recurso.to_le(),
            },
            &[],
            core::mem::size_of::<Cabecalho>(),
            tipo::OK_SEM_DADOS,
        )?;
        self.na_varredura = recurso;
        Ok(())
    }

    /// Leva à tela o retângulo `r` do recurso, cuja memória tem linhas de
    /// `largura` pixels.
    ///
    /// Duas idas: a transferência copia os bytes da memória de apoio para o
    /// dispositivo, e a descarga diz a ele que aquela região da tela mudou.
    /// Só o retângulo nas duas — é a diferença para o Redox, que transfere o
    /// quadro inteiro a cada atualização.
    fn levar(&mut self, recurso: u32, largura: u32, r: Retangulo) -> Result<(), &'static str> {
        if r.largura == 0 || r.altura == 0 {
            return Ok(());
        }
        // Em bytes: o primeiro pixel do retângulo na memória de apoio. As
        // contas são em `u64` porque `y * largura * 4` passa de 32 bits numa
        // tela de mais de mil linhas de quatro mil pixels.
        let deslocamento = (r.y as u64 * largura as u64 + r.x as u64) * 4;
        self.pedir(
            &Transferir2d {
                cabecalho: Cabecalho::de(tipo::TRANSFERIR_2D),
                retangulo: r.le(),
                deslocamento: deslocamento.to_le(),
                recurso: recurso.to_le(),
                _preenchimento: 0,
            },
            &[],
            core::mem::size_of::<Cabecalho>(),
            tipo::OK_SEM_DADOS,
        )?;
        guardar_transferencia(r);
        self.pedir(
            &Descarregar {
                cabecalho: Cabecalho::de(tipo::DESCARREGAR),
                retangulo: r.le(),
                recurso: recurso.to_le(),
                _preenchimento: 0,
            },
            &[],
            core::mem::size_of::<Cabecalho>(),
            tipo::OK_SEM_DADOS,
        )?;
        DESCARGAS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Quantas entradas o último anexo bem-sucedido mandou. Para a suíte, que
/// precisa saber se exercitou uma ou várias páginas de entradas.
static ENTRADAS_DO_ULTIMO_ANEXO: AtomicU64 = AtomicU64::new(0);

pub fn entradas_do_ultimo_anexo() -> u64 {
    ENTRADAS_DO_ULTIMO_ANEXO.load(Ordering::Relaxed)
}

fn com_gpu<R>(f: impl FnOnce(&mut Gpu) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| GPU.lock().as_mut().map(f))
}

// ---------------------------------------------------------------------------
// A tela
// ---------------------------------------------------------------------------

/// Liga o virtio-gpu e põe a tela do kernel sobre ele, se esta máquina tem um.
///
/// Só é chamado quando nenhum outro caminho produziu uma tela — nem a entrega
/// do iniciador, nem o `bochs-display`. Numa máquina que tenha as duas coisas,
/// o framebuffer linear ganha: ele é varrido sozinho pelo dispositivo, e o
/// caminho de falha fatal continua desenhando nele sem mandar nada a
/// ninguém.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none() && d.fabricante == FABRICANTE && d.modelo == MODELO {
            alvo = Some(*d);
        }
    });
    let Some(alvo) = alvo else {
        crate::log_info!("virtio", "nenhum video virtio no barramento");
        return;
    };

    let mut gpu = match Gpu::ligar(&alvo) {
        Ok(gpu) => gpu,
        Err(motivo) => {
            crate::log_error!("virtio", "video nao pode ser ligado: {}", motivo);
            return;
        }
    };

    let (largura, altura) = (gpu.modo.largura, gpu.modo.altura);
    let preparada = (|| -> Result<Tela, &'static str> {
        let memoria = Memoria::nova(largura as u64 * altura as u64 * 4)?;
        let recurso = gpu.criar_recurso(largura, altura, &memoria, true)?;
        debug_assert_eq!(recurso, RECURSO_DA_TELA);
        gpu.mostrar(recurso, largura, altura)?;
        Ok(Tela {
            memoria,
            largura,
            altura,
        })
    })();

    match preparada {
        Ok(tela) => {
            let base = tela.memoria.inicio();
            gpu.tela = Some(tela);
            crate::log_info!(
                "virtio",
                "video em {:02x}.{}: tela {}x{} sobre o recurso {}, em {} faixa(s) de memoria",
                alvo.dispositivo,
                alvo.funcao,
                largura,
                altura,
                RECURSO_DA_TELA,
                entradas_do_ultimo_anexo()
            );
            crate::arch::sem_interrupcoes(|| *GPU.lock() = Some(gpu));
            // SAFETY: a memória é da tela guardada em `GPU`, que vive até o
            // fim do kernel; ela tem exatamente `largura * altura * 4` bytes
            // mapeados e graváveis, com linhas de `largura` pixels.
            unsafe {
                crate::tela::registrar(
                    base,
                    largura,
                    altura,
                    largura,
                    4,
                    crate::tela::Formato::Bgr,
                );
            }
            crate::tela::descarregar_por(Descarregador::Virtio);
        }
        Err(motivo) => {
            crate::log_error!(
                "virtio",
                "a tela nao pode ser posta sobre o video: {}",
                motivo
            );
            // O dispositivo fica ligado e sem tela: a pilha gráfica ainda pode
            // usá-lo, e o relatório diz por que ninguém vê nada.
            crate::arch::sem_interrupcoes(|| *GPU.lock() = Some(gpu));
        }
    }
}

/// Quem leva a tela ao dispositivo, quando alguém precisa levar.
///
/// Um enum com uma variante, e não uma função guardada: a tela não pode
/// guardar um ponteiro de função num atômico sem `unsafe`, e o dia em que
/// houver um segundo dispositivo desta família ele entra aqui.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Descarregador {
    Virtio,
}

/// Leva ao monitor um retângulo da tela do kernel.
///
/// Quem chama é o compositor, depois de montar o retângulo na tela — ou a
/// própria tela, antes de haver compositor e depois de uma falha fatal.
/// Devolve falso se não pôde — a trava estava tomada, outra superfície está
/// na varredura, ou o dispositivo recusou. Quem chama guarda o retângulo
/// para a próxima vez.
///
/// # Por que `try_lock`
///
/// Porque os dois chamadores rodam de dentro de uma escrita no console, e a
/// escrita no console acontece em qualquer lugar — inclusive de dentro deste
/// módulo, quando um comando falha e registra no log. Esperar pela trava ali
/// seria esperar por si mesmo. Não conseguir agora não perde nada: o
/// retângulo fica guardado, e vai junto com a próxima escrita.
pub fn descarregar_tela(r: Retangulo) -> bool {
    crate::arch::sem_interrupcoes(|| {
        let Some(mut guarda) = GPU.try_lock() else {
            return false;
        };
        let Some(gpu) = guarda.as_mut() else {
            return false;
        };
        let Some(tela) = gpu.tela.as_ref() else {
            return false;
        };
        let largura = tela.largura;
        // Se uma superfície tomou a tela, o que a tela do kernel escreveu não
        // está sendo mostrado, e levar agora seria trabalho que ninguém vê. O
        // retângulo fica sujo, e [`restaurar_tela`] leva a tela inteira quando
        // ela voltar.
        if gpu.na_varredura != RECURSO_DA_TELA {
            return false;
        }
        gpu.levar(RECURSO_DA_TELA, largura, r).is_ok()
    })
}

// ---------------------------------------------------------------------------
// O que a pilha gráfica usa
// ---------------------------------------------------------------------------

/// A tela que o dispositivo descreve, se ele está ligado.
pub fn tamanho_da_tela() -> Option<(u32, u32)> {
    com_gpu(|g| (g.modo.largura, g.modo.altura))
}

/// Este dispositivo carrega a tela do kernel?
pub fn tem_a_tela() -> bool {
    com_gpu(|g| g.tela.is_some()).unwrap_or(false)
}

/// Onde mora a memória da tela, e a geometria dela: o que o compositor usa
/// como quadro. `None` se este dispositivo não carrega a tela.
pub fn memoria_da_tela() -> Option<(u64, u32, u32)> {
    com_gpu(|g| {
        g.tela
            .as_ref()
            .map(|t| (t.memoria.inicio(), t.largura, t.altura))
    })
    .flatten()
}

/// Cria um recurso com a memória de uma superfície.
pub fn criar_recurso(
    largura: u32,
    altura: u32,
    memoria: &Memoria,
    fundir: bool,
) -> Result<u32, &'static str> {
    com_gpu(|g| g.criar_recurso(largura, altura, memoria, fundir))
        .unwrap_or(Err("nao ha video virtio ligado"))
}

/// Leva o retângulo `r` de um recurso à tela, pondo-o na varredura se ele
/// ainda não estiver.
///
/// Trocar o recurso da varredura é a troca de página sem rasgo: o dispositivo
/// passa a mostrar a outra memória de uma vez, entre um quadro e outro.
///
/// `largura_da_linha` é quantos pixels a memória do recurso tem por linha — o
/// passo com que a transferência anda nela. `visivel` é o que vai para a
/// tela, que pode ser menor. Uma largura só para as duas coisas leria as
/// linhas de uma superfície mais larga que a tela com o passo errado.
pub fn apresentar(
    recurso: u32,
    largura_da_linha: u32,
    visivel: (u32, u32),
    r: Retangulo,
) -> Result<(), &'static str> {
    com_gpu(|g| {
        if g.na_varredura != recurso {
            g.mostrar(recurso, visivel.0, visivel.1)?;
        }
        g.levar(recurso, largura_da_linha, r)
    })
    .unwrap_or(Err("nao ha video virtio ligado"))
}

/// Devolve a tela 0 à tela do kernel, e a leva inteira.
///
/// Inteira porque, enquanto outro recurso estava na varredura, o console pode
/// ter escrito — e essas escritas não foram levadas, de propósito, para não
/// pintar por baixo da superfície.
pub fn restaurar_tela() -> Result<(), &'static str> {
    com_gpu(|g| {
        let Some((largura, altura)) = g.tela.as_ref().map(|t| (t.largura, t.altura)) else {
            return Ok(());
        };
        g.mostrar(RECURSO_DA_TELA, largura, altura)?;
        g.levar(
            RECURSO_DA_TELA,
            largura,
            Retangulo {
                x: 0,
                y: 0,
                largura,
                altura,
            },
        )
    })
    .unwrap_or(Err("nao ha video virtio ligado"))
}

/// Desfaz um recurso: devolve a tela ao kernel se ele estava nela, solta a
/// memória de apoio e o destrói no dispositivo.
///
/// Nessa ordem. Destruir um recurso na varredura deixaria a tela sem nada; e
/// soltar a memória antes de desanexá-la deixaria o dispositivo com o direito
/// de ler páginas que o alocador já pode ter entregado a outro dono.
pub fn desfazer_recurso(recurso: u32) -> Result<(), &'static str> {
    let estava_na_tela = com_gpu(|g| g.na_varredura == recurso).unwrap_or(false);
    if estava_na_tela {
        restaurar_tela()?;
    }
    com_gpu(|g| {
        g.sobre_recurso(tipo::DESANEXAR_MEMORIA, recurso)?;
        g.sobre_recurso(tipo::DESFAZER_RECURSO, recurso)
    })
    .unwrap_or(Err("nao ha video virtio ligado"))
}

/// Que recurso a tela 0 está mostrando, se o dispositivo está ligado. Para a
/// suíte, que confere que a tela voltou ao kernel depois de uma superfície.
#[cfg(feature = "modo-teste")]
pub fn na_varredura() -> Option<u32> {
    com_gpu(|g| g.na_varredura)
}

/// Transfere um retângulo de um recurso que pode não existir, sem pôr nada na
/// varredura. Para a suíte, que confere que uma recusa do dispositivo volta
/// como erro e não como pânico.
#[cfg(feature = "modo-teste")]
pub fn transferir_sem_conferir(recurso: u32, r: Retangulo) -> Result<(), &'static str> {
    com_gpu(|g| g.levar(recurso, r.largura, r)).unwrap_or(Err("nao ha video virtio ligado"))
}

/// Destrava o dispositivo à força, para uso exclusivo do caminho de falha
/// fatal — que precisa dele para levar a tela de falha ao monitor.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { GPU.force_unlock() };
}
