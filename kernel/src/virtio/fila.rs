//! A virtqueue no formato *split* — o canal por onde os pedidos passam.
//!
//! # As três estruturas, e por que são três
//!
//! Uma fila não é um buffer com dois ponteiros. São três estruturas com donos
//! diferentes:
//!
//! - A **tabela de descritores** diz onde estão os buffers: endereço, tamanho
//!   e se o dispositivo pode escrever neles. Nós escrevemos, ele lê.
//! - O **anel de disponíveis** diz quais descritores têm trabalho pendente.
//!   Nós escrevemos, ele lê.
//! - O **anel de usados** diz quais terminaram. Ele escreve, nós lemos.
//!
//! A separação é o que torna o canal seguro sem tranca nenhuma. Cada estrutura
//! tem um escritor só, e o único ponto de sincronização é um contador que o
//! escritor incrementa **depois** de o resto estar no lugar. É a mesma ideia
//! de um ring buffer de produtor-consumidor, com a diferença de que o
//! consumidor está do outro lado de uma fronteira que a MMU não atravessa.
//!
//! # Por que endereços físicos
//!
//! O dispositivo não passa pela MMU. Um endereço escrito num descritor é
//! seguido pelo hardware (ou pelo hospedeiro, aqui) sem tradução nenhuma —
//! então tem de ser físico. É a característica que separa este arquivo do
//! resto do kernel: aqui um `u64` que parece endereço **não** pode ser
//! desreferenciado, e o caminho de volta ao mundo dos ponteiros é
//! [`crate::arch::acesso_fisico`].
//!
//! # Por que uma fila cabe num frame
//!
//! Com o teto de descritores deste kernel, as três estruturas somam algumas
//! centenas de bytes. Um frame de 4 KiB as acomoda com folga, e usar um só
//! resolve de graça o requisito mais chato do formato: cada estrutura precisa
//! ser fisicamente contígua. Um alocador que entrega frames avulsos não
//! garante isso; um frame garante.

use core::sync::atomic::{Ordering, fence};

use super::transporte::Transporte;
use crate::arch::TAMANHO_PAGINA;

/// Quantos descritores uma fila deste kernel tem.
///
/// # Por que oito
///
/// Porque o driver de bloco submete um pedido por vez e espera por ele. Com
/// uma requisição em voo, três descritores bastariam; oito dá margem para um
/// segundo cliente sem custar nada, e mantém tudo dentro de um frame.
///
/// Precisa ser potência de dois: os índices dos anéis crescem para sempre e
/// são reduzidos ao anel por resto, e o formato assume que esse resto é uma
/// máscara de bits.
pub const DESCRITORES: u16 = 8;

/// Um descritor: onde está um buffer e o que o dispositivo pode fazer com ele.
///
/// `repr(C)` não é detalhe de estilo. Este tipo é um contrato de layout com
/// software que não é nosso, e o layout do Rust é explicitamente instável —
/// sem `repr(C)` o compilador tem o direito de reordenar os campos.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Descritor {
    /// Endereço **físico** do buffer.
    endereco: u64,
    tamanho: u32,
    flags: u16,
    /// Próximo descritor da cadeia, quando `SEGUE` está aceso.
    proximo: u16,
}

/// A cadeia continua no descritor indicado por `proximo`.
const SEGUE: u16 = 1;
/// O dispositivo **escreve** neste buffer. Sem este bit, ele só lê.
const ESCRITA_DO_DISPOSITIVO: u16 = 2;

/// Um elemento do anel de usados: qual cadeia terminou e quanto foi escrito.
#[repr(C)]
#[derive(Clone, Copy)]
struct Usado {
    /// Índice do primeiro descritor da cadeia que terminou.
    id: u32,
    /// Quantos bytes o dispositivo escreveu nos buffers da cadeia.
    tamanho: u32,
}

// Deslocamentos dentro do frame. Calculados aqui, em tempo de compilação, para
// que a conta que o kernel usa e a conferência que o teste faz sejam a mesma.
//
// Os alinhamentos são os que a especificação exige de cada estrutura: 16 para
// os descritores, 2 para o anel de disponíveis, 4 para o de usados.
const DESC_EM: u64 = 0;
const DESC_BYTES: u64 = 16 * DESCRITORES as u64;

const DISP_EM: u64 = alinhar(DESC_EM + DESC_BYTES, 2);
/// `flags` + `idx` + o anel + o campo de evento que fecha a estrutura.
const DISP_BYTES: u64 = 2 + 2 + 2 * DESCRITORES as u64 + 2;

const USADOS_EM: u64 = alinhar(DISP_EM + DISP_BYTES, 4);
const USADOS_BYTES: u64 = 2 + 2 + 8 * DESCRITORES as u64 + 2;

/// Deslocamentos dentro do anel de disponíveis.
const DISP_FLAGS: u64 = 0;
const DISP_IDX: u64 = 2;
const DISP_ANEL: u64 = 4;

/// Pede ao dispositivo que não interrompa ao consumir um buffer.
///
/// Este driver espera pelo resultado em laço, e nenhuma linha de interrupção
/// do virtio está ligada a handler nenhum. Sem este bit o dispositivo
/// sinalizaria a cada pedido, numa linha que ninguém atende — barulho no
/// melhor caso, e no pior uma interrupção que o kernel não sabe reconhecer.
const SEM_INTERROMPER: u16 = 1;

/// Deslocamentos dentro do anel de usados.
const USADOS_IDX: u64 = 2;
const USADOS_ANEL: u64 = 4;

const fn alinhar(valor: u64, a: u64) -> u64 {
    (valor + a - 1) & !(a - 1)
}

// Que tudo caiba num frame é premissa do arquivo inteiro, não sorte. Se um dia
// `DESCRITORES` crescer além do que cabe, a compilação para aqui em vez de o
// kernel corromper o frame seguinte em tempo de execução.
const _: () = assert!(USADOS_EM + USADOS_BYTES <= TAMANHO_PAGINA);
const _: () = assert!(DESCRITORES.is_power_of_two());

/// Uma virtqueue montada e ligada ao dispositivo.
///
/// # Por que não há `Drop`
///
/// Porque desmontar uma fila corretamente exige falar com o dispositivo —
/// desabilitá-la antes de devolver o frame, ou o alocador entregaria a outro
/// dono um endereço que o dispositivo ainda tem escrito num registrador. A
/// `Fila` não guarda o transporte, e guardá-lo só para um caminho que nunca
/// roda seria carregar uma referência para nada.
///
/// A alternativa honesta é a invariante: uma fila montada vive enquanto o
/// kernel viver. O disco não é desligado, e não há hot-plug nesta fase. O
/// único ponto em que um frame podia vazar era a falha no meio da construção,
/// e [`Fila::nova`] o devolve explicitamente.
pub struct Fila {
    /// Qual fila do dispositivo esta é.
    indice: u16,
    /// Onde o dispositivo quer ser notificado sobre ela.
    notificacao: u16,
    /// Endereço virtual do frame que contém as três estruturas.
    ///
    /// O endereço **físico** dele não é guardado: ele foi entregue ao
    /// dispositivo na construção e nunca mais é consultado deste lado. Guardá
    /// -lo seria manter à mão, ao lado do ponteiro, um inteiro que se parece
    /// com um ponteiro e não é — que é exatamente a confusão mais fácil de
    /// cometer neste arquivo.
    base: *mut u8,
    /// Quantos descritores da cadeia já foram publicados.
    ///
    /// Cresce para sempre e transborda de propósito: o formato define a
    /// comparação entre índices módulo 2^16, e um `u16` que dá a volta é
    /// exatamente isso.
    proximo_disponivel: u16,
    /// Até onde já consumimos o anel de usados.
    ultimo_usado: u16,
}

// SAFETY: o ponteiro que o tipo guarda aponta para um frame de propriedade
// exclusiva desta fila, alocado na construção e nunca compartilhado. O que
// torna `Fila` não-`Send` automaticamente é o ponteiro cru, não uma restrição
// real — e o driver precisa guardá-la num `static` protegido por `Mutex`.
unsafe impl Send for Fila {}

impl Fila {
    /// Monta a fila `indice` do dispositivo e a entrega a ele.
    pub fn nova(transporte: &Transporte, indice: u16) -> Result<Fila, &'static str> {
        let capacidade = transporte.tamanho_da_fila(indice);
        if capacidade == 0 {
            return Err("dispositivo nao tem essa fila");
        }
        // O dispositivo publica quantos descritores ele suporta, e o driver
        // pode pedir menos — mas nunca mais. Pedir mais não dá erro na
        // escrita: dá descritores que o dispositivo nunca vai ler.
        if capacidade < DESCRITORES {
            return Err("fila do dispositivo e menor que a minima deste kernel");
        }

        let frame = crate::frames::alocar().ok_or("sem frame para a fila")?;
        let base = crate::arch::acesso_fisico(frame);

        // Zerar é obrigatório, não higiene. O anel de disponíveis e o de
        // usados começam pelos contadores, e um contador herdado do uso
        // anterior daquele frame faria o dispositivo achar que há trabalho
        // pendente antes de existir qualquer descritor.
        // SAFETY: o frame acabou de ser alocado, então esta fila é a única
        // dona, e `acesso_fisico` devolve um ponteiro válido para ele.
        unsafe { core::ptr::write_bytes(base, 0, TAMANHO_PAGINA as usize) };

        // Antes de entregar a fila ao dispositivo, e não depois: a partir da
        // habilitação ele pode ler o anel, e o pedido de não interromper
        // precisa já estar lá.
        // SAFETY: o frame é desta fila, e o deslocamento é o do campo de flags
        // do anel de disponíveis.
        unsafe {
            core::ptr::write_volatile(
                base.add((DISP_EM + DISP_FLAGS) as usize) as *mut u16,
                SEM_INTERROMPER.to_le(),
            )
        };

        let notificacao = match transporte.configurar_fila(
            indice,
            DESCRITORES,
            frame + DESC_EM,
            frame + DISP_EM,
            frame + USADOS_EM,
        ) {
            Ok(notificacao) => notificacao,
            Err(motivo) => {
                // O dispositivo não ficou com o endereço — a falha aconteceu
                // antes da habilitação —, então o frame pode voltar ao
                // alocador com segurança.
                crate::frames::liberar(frame);
                return Err(motivo);
            }
        };

        Ok(Fila {
            indice,
            notificacao,
            base,
            proximo_disponivel: 0,
            ultimo_usado: 0,
        })
    }

    /// Escreve um descritor na posição indicada.
    ///
    /// A conversão para little-endian acontece aqui, e não em quem monta o
    /// descritor, para que o resto do arquivo manipule números e não
    /// representações. É o mesmo contrato dos acessadores de MMIO: o formato
    /// é little-endian por especificação, em qualquer arquitetura, e nos dois
    /// alvos deste kernel a conversão não gera instrução nenhuma.
    ///
    /// Ela estava faltando: a leitura do anel de usados já era explícita, a
    /// escrita do descritor não. Num arquivo cujo assunto inteiro é um
    /// contrato de representação com software que não é nosso, meia
    /// explicitação é pior que nenhuma — ela sugere que o outro lado foi
    /// considerado.
    fn escrever_descritor(&self, posicao: u16, descritor: Descritor) {
        let bruto = Descritor {
            endereco: descritor.endereco.to_le(),
            tamanho: descritor.tamanho.to_le(),
            flags: descritor.flags.to_le(),
            proximo: descritor.proximo.to_le(),
        };

        // SAFETY: `posicao` é sempre menor que `DESCRITORES`, e a asserção de
        // compilação no topo garante que a tabela inteira cabe no frame.
        unsafe {
            let ponteiro =
                self.base.add((DESC_EM + 16 * posicao as u64) as usize) as *mut Descritor;
            core::ptr::write_volatile(ponteiro, bruto);
        }
    }

    /// Lê um `u16` de um deslocamento dentro do frame da fila.
    fn ler_u16(&self, deslocamento: u64) -> u16 {
        // SAFETY: todos os chamadores usam deslocamentos derivados das
        // constantes de layout, que a asserção de compilação confina ao frame.
        u16::from_le(unsafe {
            core::ptr::read_volatile(self.base.add(deslocamento as usize) as *const u16)
        })
    }

    fn escrever_u16(&self, deslocamento: u64, valor: u16) {
        // SAFETY: mesma justificativa da leitura.
        unsafe {
            core::ptr::write_volatile(
                self.base.add(deslocamento as usize) as *mut u16,
                valor.to_le(),
            )
        };
    }

    /// Publica uma cadeia de buffers e avisa o dispositivo.
    ///
    /// Cada entrada de `cadeia` é `(endereço físico, tamanho, o dispositivo
    /// escreve nele)`. A ordem importa: é a ordem em que o dispositivo vai
    /// consumir os buffers, e para um pedido de bloco ela é cabeçalho, dados,
    /// estado.
    ///
    /// Devolve o índice do primeiro descritor — é por ele que o dispositivo
    /// vai identificar a cadeia quando terminar.
    pub fn submeter(&mut self, cadeia: &[(u64, u32, bool)]) -> Result<u16, &'static str> {
        if cadeia.is_empty() {
            return Err("cadeia vazia");
        }
        if cadeia.len() > DESCRITORES as usize {
            return Err("cadeia maior que a fila");
        }

        // Este driver tem um pedido em voo por vez, então a cadeia sempre
        // começa em zero. Não há alocador de descritores porque não há
        // concorrência a arbitrar — e um alocador que nunca vê dois clientes é
        // um alocador sem teste.
        let cabeca = 0u16;

        for (posicao, &(endereco, tamanho, escrita)) in cadeia.iter().enumerate() {
            let ultimo = posicao + 1 == cadeia.len();
            let mut flags = 0;
            if !ultimo {
                flags |= SEGUE;
            }
            if escrita {
                flags |= ESCRITA_DO_DISPOSITIVO;
            }

            // `proximo` só tem significado quando `SEGUE` está aceso; no
            // último descritor ele vai zerado em vez de apontar para uma
            // posição que não existe. O dispositivo ignoraria o valor de
            // qualquer forma — mas um índice fora da tabela escrito na
            // tabela é o tipo de coisa que engana quem lê um despejo dela.
            let proximo = if ultimo {
                0
            } else {
                cabeca + posicao as u16 + 1
            };

            self.escrever_descritor(
                cabeca + posicao as u16,
                Descritor {
                    endereco,
                    tamanho,
                    flags,
                    proximo,
                },
            );
        }

        // O anel é indexado pelo contador reduzido ao tamanho da fila; o
        // contador em si não é reduzido, e é essa diferença que permite
        // distinguir "vazio" de "cheio" sem um bit extra.
        let posicao_no_anel = self.proximo_disponivel % DESCRITORES;
        self.escrever_u16(DISP_EM + DISP_ANEL + 2 * posicao_no_anel as u64, cabeca);

        // A barreira é o contrato inteiro deste arquivo em uma linha.
        //
        // Os descritores e a entrada do anel precisam estar visíveis para o
        // outro lado **antes** do contador que os anuncia. Sem isto, o
        // dispositivo pode ver o contador novo e descritores velhos — e a
        // janela é tão pequena que o bug só aparece sob carga, na máquina de
        // outra pessoa.
        fence(Ordering::SeqCst);

        self.proximo_disponivel = self.proximo_disponivel.wrapping_add(1);
        self.escrever_u16(DISP_EM + DISP_IDX, self.proximo_disponivel);

        // E de novo antes de notificar, pela mesma razão: a notificação é uma
        // escrita em MMIO, e não há motivo para o processador mantê-la depois
        // da atualização do contador se nada disser que precisa.
        fence(Ordering::SeqCst);

        Ok(cabeca)
    }

    /// Avisa o dispositivo de que há trabalho.
    pub fn notificar(&self, transporte: &Transporte) {
        transporte.notificar(self.notificacao, self.indice);
    }

    /// Colhe a próxima cadeia terminada, se houver.
    ///
    /// Devolve `(índice do primeiro descritor, bytes escritos pelo
    /// dispositivo)`.
    pub fn colher(&mut self) -> Option<(u16, u32)> {
        let publicados = self.ler_u16(USADOS_EM + USADOS_IDX);
        if publicados == self.ultimo_usado {
            return None;
        }

        // Simétrica à da submissão: o contador é o que anuncia a entrada, e
        // ler a entrada antes de a leitura do contador ter acontecido de fato
        // devolveria lixo do ciclo anterior.
        fence(Ordering::SeqCst);

        let posicao = (self.ultimo_usado % DESCRITORES) as u64;
        // SAFETY: `posicao` é menor que `DESCRITORES`, e o anel inteiro cabe
        // no frame pela asserção de compilação.
        let usado = unsafe {
            core::ptr::read_volatile(
                self.base
                    .add((USADOS_EM + USADOS_ANEL + 8 * posicao) as usize)
                    as *const Usado,
            )
        };

        self.ultimo_usado = self.ultimo_usado.wrapping_add(1);
        Some((u32::from_le(usado.id) as u16, u32::from_le(usado.tamanho)))
    }
}
