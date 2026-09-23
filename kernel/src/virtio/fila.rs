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

/// Pedir ao dispositivo que **não** interrompa ao consumir um buffer.
///
/// Era o que esta fila fazia enquanto nenhuma linha de interrupção do virtio
/// estava ligada a handler nenhum: sem o bit, o dispositivo sinalizaria a cada
/// pedido numa linha que ninguém atende.
///
/// A premissa deixou de valer. Com o roteamento no ar, o bit passa a ser
/// exatamente o que impede a interrupção de chegar — e um driver que registra
/// um handler e depois pede para não ser chamado é a contradição mais difícil
/// de enxergar num despejo de registradores, porque os dois lados parecem
/// certos isoladamente.
///
/// Fica nomeado, e apagado: o valor escrito é zero. Quando houver motivo para
/// suprimir interrupções numa fila específica — a de transmissão é a
/// candidata óbvia, já que a conclusão dela não interessa a ninguém —, o bit
/// está aqui e a decisão será por fila, não por falta de handler.
#[allow(dead_code)]
const SEM_INTERROMPER: u16 = 1;

/// O que de fato vai no campo de flags do anel de disponíveis.
const AVISAR_SEMPRE: u16 = 0;

/// Deslocamentos dentro do anel de usados.
const USADOS_IDX: u64 = 2;
const USADOS_ANEL: u64 = 4;

const fn alinhar(valor: u64, a: u64) -> u64 {
    (valor + a - 1) & !(a - 1)
}

/// O bitmap de descritores livres quando a fila está vazia.
///
/// Um bit por descritor, e é por isso que [`DESCRITORES`] não pode passar de
/// oito sem trocar o tipo. A asserção abaixo transforma esse acoplamento num
/// erro de compilação em vez de num bug.
const TODOS_LIVRES: u8 = u8::MAX;

const _: () = assert!(DESCRITORES as u32 <= u8::BITS);

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
    /// Quais descritores estão livres, um bit por posição.
    ///
    /// # Por que agora há um alocador
    ///
    /// A primeira versão desta fila não tinha: o driver de bloco submete um
    /// pedido e espera por ele, então a cadeia sempre começava em zero. Está
    /// escrito no commit que a introduziu que um alocador sem dois clientes
    /// seria um alocador sem teste.
    ///
    /// A placa de rede é o segundo cliente, e ela muda a forma do problema. A
    /// fila de recepção precisa de vários buffers postados **antes** de
    /// chegar qualquer pacote — o dispositivo escreve neles quando quiser, e
    /// um buffer só não recebe nada enquanto o anterior não for colhido.
    ///
    /// Um bitmap, e não uma lista encadeada pelo campo `proximo` dos
    /// descritores livres, que é a técnica clássica: a lista mora na memória
    /// que o dispositivo também enxerga, e um `u8` aqui do lado do kernel não.
    livres: u8,
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
        // habilitação ele pode ler o anel, e o que temos a dizer sobre
        // interrupções precisa já estar lá.
        //
        // Escrever zero é redundante com a limpeza do frame acima, e está
        // aqui de propósito: o valor deste campo é uma decisão, e uma decisão
        // que depende de o frame ter sido zerado é uma decisão invisível.
        // SAFETY: o frame é desta fila, e o deslocamento é o do campo de flags
        // do anel de disponíveis.
        unsafe {
            core::ptr::write_volatile(
                base.add((DISP_EM + DISP_FLAGS) as usize) as *mut u16,
                AVISAR_SEMPRE.to_le(),
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
                // O frame pode voltar ao alocador, mas **não** porque o
                // dispositivo não tenha o endereço: ele pode muito bem ter —
                // `configurar_fila` escreve os três endereços antes do passo
                // que pode falhar por último, a habilitação.
                //
                // O que torna a devolução segura é a habilitação não ter
                // acontecido. Uma fila com `queue_enable` em zero é uma fila
                // que o dispositivo está proibido de tocar, tenha ele o
                // endereço ou não.
                //
                // A distinção importa porque as duas levam à mesma linha de
                // código e a raciocínios opostos sobre o próximo caso: quem
                // acreditasse na primeira versão concluiria que basta não
                // escrever o endereço, e liberaria um frame de uma fila já
                // habilitada.
                crate::frames::liberar(frame);
                return Err(motivo);
            }
        };

        Ok(Fila {
            indice,
            notificacao,
            base,
            livres: TODOS_LIVRES,
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

    /// Lê um descritor de volta da tabela.
    ///
    /// Usado só para percorrer uma cadeia que terminou, em
    /// [`Fila::liberar_cadeia`]. Os campos vêm em little-endian, como foram
    /// escritos.
    fn ler_descritor(&self, posicao: u16) -> Descritor {
        // SAFETY: o chamador confere que `posicao` é menor que `DESCRITORES`
        // antes de chamar, e a asserção de compilação garante que a tabela
        // inteira cabe no frame.
        let bruto = unsafe {
            core::ptr::read_volatile(
                self.base.add((DESC_EM + 16 * posicao as u64) as usize) as *const Descritor
            )
        };

        Descritor {
            endereco: u64::from_le(bruto.endereco),
            tamanho: u32::from_le(bruto.tamanho),
            flags: u16::from_le(bruto.flags),
            proximo: u16::from_le(bruto.proximo),
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

    /// Reserva `quantos` descritores, ou `None` se não há tantos livres.
    ///
    /// Devolve as posições em ordem crescente do bitmap, o que não é nada
    /// além de determinismo: uma fila que entrega sempre as mesmas posições
    /// para a mesma sequência de pedidos é uma fila cujo despejo se lê.
    fn reservar(&mut self, quantos: usize, posicoes: &mut [u16]) -> Option<()> {
        if quantos > posicoes.len() || (self.livres.count_ones() as usize) < quantos {
            return None;
        }

        let mut achados = 0;
        for posicao in 0..DESCRITORES {
            if achados == quantos {
                break;
            }
            if self.livres & (1 << posicao) != 0 {
                posicoes[achados] = posicao;
                achados += 1;
            }
        }

        // Só marcamos como ocupados depois de saber que todos couberam, para
        // que uma reserva que falha não deixe descritores perdidos.
        for &posicao in &posicoes[..quantos] {
            self.livres &= !(1 << posicao);
        }
        Some(())
    }

    /// Devolve ao bitmap a cadeia que começa em `cabeca`.
    ///
    /// A cadeia é percorrida pelos próprios descritores, seguindo `proximo`
    /// enquanto `SEGUE` estiver aceso. É a mesma travessia que o dispositivo
    /// fez, o que significa que não precisamos guardar o comprimento de cada
    /// cadeia em lugar nenhum — a resposta já está escrita na tabela.
    ///
    /// O teto de voltas existe porque a tabela é memória que o dispositivo
    /// também enxerga. Um `proximo` corrompido — por defeito ou por malícia —
    /// faria um ciclo, e um laço infinito dentro de uma seção com
    /// interrupções mascaradas é um kernel travado sem diagnóstico.
    fn liberar_cadeia(&mut self, cabeca: u16) {
        let mut posicao = cabeca;
        for _ in 0..DESCRITORES {
            if posicao >= DESCRITORES {
                crate::log_warn!("virtio", "cadeia aponta para o descritor {}", posicao);
                return;
            }

            let descritor = self.ler_descritor(posicao);
            self.livres |= 1 << posicao;

            if descritor.flags & SEGUE == 0 {
                return;
            }
            posicao = descritor.proximo;
        }
        crate::log_warn!("virtio", "cadeia sem fim a partir do descritor {}", cabeca);
    }

    /// O endereço físico que o descritor `posicao` guarda.
    ///
    /// Serve a quem precisa saber **de qual buffer** veio uma cadeia colhida.
    /// A alternativa seria uma tabela paralela do índice da cadeia para o
    /// buffer, mantida pelo driver — e duas cópias da mesma informação são
    /// duas coisas que podem divergir.
    pub fn endereco_do_descritor(&self, posicao: u16) -> Option<u64> {
        (posicao < DESCRITORES).then(|| self.ler_descritor(posicao).endereco)
    }

    /// Este descritor está com o dispositivo agora?
    ///
    /// A pergunta importa a quem precise saber o que já entregou: o endereço
    /// que [`Fila::endereco_do_descritor`] devolve continua lá depois de a
    /// cadeia ser colhida, porque liberar um descritor só apaga o bit do
    /// bitmap. Sem esta distinção, um endereço velho passa por entrega viva.
    pub fn em_uso(&self, posicao: u16) -> bool {
        posicao < DESCRITORES && self.livres & (1 << posicao) == 0
    }

    /// Quantos descritores estão livres agora.
    pub fn disponiveis(&self) -> usize {
        self.livres.count_ones() as usize
    }

    /// Publica uma cadeia de buffers e avisa o dispositivo.
    ///
    /// Cada entrada de `cadeia` é `(endereço físico, tamanho, o dispositivo
    /// escreve nele)`. A ordem importa: é a ordem em que o dispositivo vai
    /// consumir os buffers, e para um pedido de bloco ela é cabeçalho, dados,
    /// estado.
    ///
    /// Devolve o índice do primeiro descritor — é por ele que o dispositivo
    /// vai identificar a cadeia quando terminar, e é ele que [`Fila::colher`]
    /// devolve para que os descritores voltem ao bitmap.
    pub fn submeter(&mut self, cadeia: &[(u64, u32, bool)]) -> Result<u16, &'static str> {
        if cadeia.is_empty() {
            return Err("cadeia vazia");
        }

        let mut posicoes = [0u16; DESCRITORES as usize];
        if cadeia.len() > posicoes.len() {
            return Err("cadeia maior que a fila");
        }
        if self.reservar(cadeia.len(), &mut posicoes).is_none() {
            return Err("sem descritores livres na fila");
        }

        let cabeca = posicoes[0];

        for (indice, &(endereco, tamanho, escrita)) in cadeia.iter().enumerate() {
            let ultimo = indice + 1 == cadeia.len();
            let mut flags = 0;
            if !ultimo {
                flags |= SEGUE;
            }
            if escrita {
                flags |= ESCRITA_DO_DISPOSITIVO;
            }

            // `proximo` só tem significado quando `SEGUE` está aceso; no
            // último descritor ele vai zerado em vez de apontar para uma
            // posição que a cadeia não usa.
            let proximo = if ultimo { 0 } else { posicoes[indice + 1] };

            self.escrever_descritor(
                posicoes[indice],
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
        //
        // # Nenhum teste protege esta linha, e isso foi medido
        //
        // Removendo as três barreiras deste arquivo, a suíte inteira passa —
        // noventa e oito de noventa e oito. Não é descuido de quem escreveu os
        // casos: é que a reordenação contra a qual elas defendem não acontece
        // aqui. O dispositivo do QEMU é coerente, o hóspede tem um núcleo só,
        // e nada neste ambiente produz a janela.
        //
        // Ou seja: apagar esta linha não custa nada hoje e custa tudo no dia em
        // que o kernel rodar em hardware de verdade ou em mais de um núcleo. É
        // a única garantia deste driver cuja ausência a suíte não denuncia, e
        // por isso ela está escrita aqui, onde quem for apagá-la vai ler.
        //
        // O que se pode conferir é que a instrução sai mesmo. Em release,
        // `cargo xtask asm --release submeter` mostra `dmb ish` no aarch64 e o
        // prefixo `lock` no x86_64; em debug a barreira aparece como uma
        // chamada a `core::sync::atomic::fence`, que não é inlinada.
        //
        // # Uma ressalva de domínio, para quando sair do emulador
        //
        // `fence(SeqCst)` compila para `dmb ish` — *inner shareable*. Um
        // dispositivo que faça DMA de fora desse domínio exigiria `osh` ou um
        // `dsb`. Não é o caso do virtio do QEMU, que é coerente com o hóspede,
        // e por isso não há inline assembly aqui: seria trocar uma linha
        // portátil por uma específica para resolver um problema que esta
        // máquina não tem. Fica registrado porque a primeira placa real o terá.
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

        let cabeca = u32::from_le(usado.id) as u16;

        // Os descritores voltam ao bitmap aqui, e não em quem chamou. Deixar
        // isso para o chamador seria a mesma decisão que obriga a lembrar de
        // um `free` — e a fila de recepção submete muito mais vezes do que o
        // disco, então esquecer uma vez a esgotaria em silêncio.
        self.liberar_cadeia(cabeca);

        Some((cabeca, u32::from_le(usado.tamanho)))
    }
}
