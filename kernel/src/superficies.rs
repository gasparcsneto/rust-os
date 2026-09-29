//! As superfícies do compositor que pertencem a processos.
//!
//! # O que um processo recebe
//!
//! Uma camada do compositor, e os pixels dela mapeados no próprio espaço —
//! os **mesmos** frames que o compositor lê ao compor. O processo desenha
//! escrevendo na memória, e diz onde escreveu; o compositor recompõe esse
//! retângulo. Nada é copiado entre os dois lados. É o arranjo do Orbital,
//! o compositor do Redox, e é o que o servidor de janelas vai usar para
//! cada janela: a partir dele, desenhar uma janela não passa pelo kernel.
//!
//! A ABI está em [`protocolo::usuario::superficie`]; aqui mora o lado do
//! kernel: a tabela de quem é dono de qual camada.
//!
//! # A camada é de quem a criou
//!
//! Cada vaga guarda o fio que criou a superfície, e toda operação confere.
//! Um filho de `fork` herda o descritor — a tabela de descritores é copiada
//! inteira — e não herda nem a camada nem a memória: `controlar` pelo
//! descritor herdado é recusado, e as páginas nem chegam ao espaço dele
//! (ver `Espaco::clonar_o_ativo`). É a mesma regra do ouvinte de um canal
//! de eventos, pelo mesmo motivo.
//!
//! # Quando o dono some
//!
//! Um processo que morre não fecha os descritores. O coletor de fios passa
//! por aqui a cada volta e tira da tela as camadas de dono morto — ver
//! [`recolher_orfas`]. Esperar alguém procurar a vaga, como os canais
//! fazem, não serviria: uma camada órfã não é procurada por ninguém, e
//! ficaria na tela, por cima do que viesse depois, até a próxima criação.
//!
//! # Os frames, dos dois lados
//!
//! Cada frame da superfície tem dois donos contados: a memória da camada,
//! no kernel, e o espaço do processo. Cada lado solta o seu — o `Drop` da
//! memória num, a destruição do espaço no outro —, e o frame volta ao
//! alocador com o último, em qualquer ordem. Uma camada fechada pelo
//! processo tira também o mapeamento dele: uma janela aberta e fechada mil
//! vezes não pode custar mil superfícies de memória até o processo sair.
//!
//! # A ordem das travas
//!
//! Superfícies, depois o compositor — é o que uma operação faz, com a vaga
//! na mão, para mexer na camada. O compositor nunca pergunta nada aqui.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use crate::arch::TAMANHO_PAGINA;
use crate::grafico::compositor::{Camada, Mistura, NaoCriada};
use protocolo::usuario::superficie::{self, operacao};

/// Quantas superfícies de processo podem existir ao mesmo tempo, somando
/// todos os processos.
pub const MAX: usize = 16;

/// O nome das camadas de processo, no relatório das camadas.
pub const NOME_DA_CAMADA: &str = "superficie";

/// O que um descritor guarda para achar a sua superfície: a vaga, e qual
/// das superfícies que já passaram por ela.
///
/// # Por que a vaga não basta
///
/// Porque ela é reaproveitada, e um descritor pode sobreviver à superfície
/// para a qual apontava: o filho de um `fork` herda o descritor do pai, o
/// pai fecha a superfície, e a vaga fica livre. Se o filho criar uma
/// superfície própria que caia na mesma vaga, o descritor herdado — que
/// apontava para a do pai — passaria a alcançar a nova, porque ela é do
/// filho. Fechá-lo fecharia a janela nova sem ninguém ter pedido.
///
/// A geração é um número que nenhuma outra superfície recebe: o descritor
/// velho continua apontando para a vaga, e é recusado porque a geração não
/// confere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chave {
    pub vaga: usize,
    pub geracao: u64,
}

struct Vaga {
    /// O fio que criou a superfície.
    dono: u64,
    geracao: u64,
    camada: Camada,
    largura: u32,
    altura: u32,
    /// Onde os pixels estão no espaço do dono, e quantas páginas.
    endereco: u64,
    paginas: u64,
}

// Tomada sempre por `sem_interrupcoes`, como toda tranca deste kernel, e
// solta no caminho fatal.
static VAGAS: Mutex<[Option<Vaga>; MAX]> = Mutex::new([const { None }; MAX]);

/// Quantas vagas estão ocupadas: o coletor passa por aqui a cada tique, e
/// sem superfície nenhuma ele não precisa tomar a tranca.
static OCUPADAS: AtomicU64 = AtomicU64::new(0);
/// Quantas superfícies já foram criadas, e quantas o coletor tirou de
/// donos mortos.
static CRIADAS: AtomicU64 = AtomicU64::new(0);
/// A geração da próxima superfície — ver [`Chave`].
static PROXIMA_GERACAO: AtomicU64 = AtomicU64::new(1);

/// A geração da superfície que tem o foco do teclado, ou zero.
///
/// A geração, e não a vaga: é o que nenhuma outra superfície recebe, então
/// uma que feche e dê lugar a outra na mesma vaga não herda o foco.
static FOCO: AtomicU64 = AtomicU64::new(0);
static RECOLHIDAS: AtomicU64 = AtomicU64::new(0);

fn com_vagas<R>(f: impl FnOnce(&mut [Option<Vaga>; MAX]) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut VAGAS.lock()))
}

/// Por que uma superfície não foi criada, ou uma operação não foi feita.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recusa {
    /// Largura ou altura zero, ou grandes demais.
    Tamanho,
    /// Não há compositor.
    SemTela,
    /// Não há memória, ou vaga na tabela.
    SemMemoria,
    /// A vaga não é uma superfície deste dono.
    NaoEhSua,
    /// A operação não existe, ou o argumento não serve.
    Argumento,
}

/// O tamanho em bytes de uma superfície de `largura` por `altura`, se ela
/// estiver dentro dos limites da ABI.
pub fn bytes_de(largura: u32, altura: u32) -> Option<u64> {
    if largura == 0
        || altura == 0
        || largura > superficie::MAIOR_LADO
        || altura > superficie::MAIOR_LADO
    {
        return None;
    }
    let bytes = largura as u64 * altura as u64 * 4;
    (bytes <= superficie::MAIOR_TAMANHO).then_some(bytes)
}

/// Cria uma superfície de `largura` por `altura` para `dono`, e a mapeia no
/// espaço **ativo** a partir de `endereco`. Devolve a chave dela.
///
/// Quem chama já conferiu que a faixa é do processo e está livre; aqui
/// mora o que só existe com a camada: os frames dela. Tudo ou nada — no
/// erro, nem camada nem página.
pub fn criar(dono: u64, largura: u32, altura: u32, endereco: u64) -> Result<Chave, Recusa> {
    bytes_de(largura, altura).ok_or(Recusa::Tamanho)?;
    let camada = Camada::nova_oculta(NOME_DA_CAMADA, largura, altura).map_err(|e| match e {
        NaoCriada::SemCompositor => Recusa::SemTela,
        NaoCriada::Recusada(_) => Recusa::SemMemoria,
    })?;
    let (origem, bytes) = camada.memoria().ok_or(Recusa::SemMemoria)?;
    let paginas = bytes / TAMANHO_PAGINA;
    crate::paginacao::espelhar_no_usuario(origem, endereco, paginas).map_err(|motivo| {
        crate::log_warn!(
            "superficies",
            "superficie nao mapeada no processo: {}",
            motivo
        );
        Recusa::SemMemoria
    })?;

    let geracao = PROXIMA_GERACAO.fetch_add(1, Ordering::Relaxed);
    let vaga = Vaga {
        dono,
        geracao,
        camada,
        largura,
        altura,
        endereco,
        paginas,
    };
    let guardada = com_vagas(|vagas| {
        let i = vagas.iter().position(Option::is_none)?;
        vagas[i] = Some(vaga);
        Some(i)
    });
    match guardada {
        Some(i) => {
            OCUPADAS.fetch_add(1, Ordering::Relaxed);
            CRIADAS.fetch_add(1, Ordering::Relaxed);
            Ok(Chave { vaga: i, geracao })
        }
        // Sem vaga, desfaz na ordem inversa: o mapeamento do processo, e a
        // camada quando o valor sai de escopo.
        None => {
            crate::paginacao::desfazer_espelho(origem, endereco, paginas);
            Err(Recusa::SemMemoria)
        }
    }
}

/// A vaga guarda a superfície da `chave`, e ela é de `dono`?
fn confere(v: &Vaga, chave: Chave, dono: u64) -> bool {
    v.geracao == chave.geracao && v.dono == dono
}

/// Faz a operação `op` com `argumento` na superfície da `chave`, se ela for
/// de `dono`.
pub fn controlar(chave: Chave, dono: u64, op: u64, argumento: u64) -> Result<(), Recusa> {
    com_vagas(|vagas| {
        let Some(v) = vagas.get(chave.vaga).and_then(Option::as_ref) else {
            return Err(Recusa::NaoEhSua);
        };
        if !confere(v, chave, dono) {
            return Err(Recusa::NaoEhSua);
        }
        let camada = &v.camada;
        // Uma camada que o compositor recusou mexer não é erro do processo:
        // a operação foi aceita, e o que não pôde ser composto agora fica
        // pendente no compositor.
        let _ = match op {
            operacao::MOVER => {
                let (x, y) = superficie::de_posicao(argumento);
                camada.mover(x, y)
            }
            operacao::DANO => {
                let (x, y, largura, altura) = superficie::de_retangulo(argumento);
                let (x, y, largura, altura) = (x as u32, y as u32, largura as u32, altura as u32);
                // O retângulo precisa caber na superfície. Recortar em
                // silêncio esconderia do processo um erro de conta dele —
                // e o pedaço que ficou de fora nunca apareceria.
                if x + largura > v.largura || y + altura > v.altura {
                    return Err(Recusa::Argumento);
                }
                camada.recompor(x, y, largura, altura)
            }
            operacao::FRENTE => camada.trazer_para_frente(),
            operacao::OPACIDADE => {
                let opacidade = u8::try_from(argumento).map_err(|_| Recusa::Argumento)?;
                camada.definir_opacidade(opacidade)
            }
            operacao::FOCO => {
                match argumento {
                    1 => FOCO.store(v.geracao, Ordering::Relaxed),
                    0 => {
                        let _ = FOCO.compare_exchange(
                            v.geracao,
                            0,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    }
                    _ => return Err(Recusa::Argumento),
                }
                return Ok(());
            }
            operacao::MISTURA => camada.definir_mistura(match argumento {
                operacao::OPACA => Mistura::Opaca,
                operacao::ALFA => Mistura::Alfa,
                _ => return Err(Recusa::Argumento),
            }),
            _ => return Err(Recusa::Argumento),
        };
        Ok(())
    })
}

/// Fecha a superfície da `chave`, se ela for de `dono`: tira a camada da
/// tela, e os pixels do espaço **ativo** — que é o do dono, porque é ele
/// quem chama.
///
/// De outro fio — o filho que herdou o descritor —, não faz nada: a camada
/// não é dele.
pub fn largar(chave: Chave, dono: u64) {
    let Some(v) = com_vagas(|vagas| {
        let v = vagas.get_mut(chave.vaga)?;
        if v.as_ref().is_some_and(|v| confere(v, chave, dono)) {
            v.take()
        } else {
            None
        }
    }) else {
        return;
    };
    OCUPADAS.fetch_sub(1, Ordering::Relaxed);
    soltar_o_foco(v.geracao);
    // O mapeamento do processo sai antes da camada, e só onde ele ainda é
    // o da camada: depois de um `exec`, o mesmo endereço pode ser memória
    // do programa novo, e `desfazer_espelho` confere frame a frame.
    if let Some((origem, _)) = v.camada.memoria() {
        crate::paginacao::desfazer_espelho(origem, v.endereco, v.paginas);
    }
    drop(v);
}

/// Tira da tela as camadas cujo dono morreu. Devolve quantas.
///
/// Chamada pelo coletor de fios, depois de ele largar os mortos. A memória
/// do processo não é desfeita aqui — o espaço dele já foi, ou vai com ele —,
/// só a camada, e com ela a parte do compositor nos frames.
///
/// As camadas saem **fora** da tranca: tirar uma da tela recompõe o que ela
/// cobria, e isso não precisa acontecer com a tabela inteira parada.
pub fn recolher_orfas() -> usize {
    if OCUPADAS.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let mut orfas: [Option<Vaga>; MAX] = [const { None }; MAX];
    let quantas = com_vagas(|vagas| {
        let mut n = 0;
        for v in vagas.iter_mut() {
            if v.as_ref().is_some_and(|v| !crate::fios::vivo(v.dono)) {
                if let Some(v) = v.as_ref() {
                    soltar_o_foco(v.geracao);
                }
                orfas[n] = v.take();
                n += 1;
            }
        }
        n
    });
    drop(orfas);
    if quantas > 0 {
        OCUPADAS.fetch_sub(quantas as u64, Ordering::Relaxed);
        RECOLHIDAS.fetch_add(quantas as u64, Ordering::Relaxed);
    }
    quantas
}

/// Tira o foco da superfície `geracao`, se for dela.
fn soltar_o_foco(geracao: u64) {
    let _ = FOCO.compare_exchange(geracao, 0, Ordering::Relaxed, Ordering::Relaxed);
}

/// Alguma superfície tem o foco do teclado? As teclas vão para o canal das
/// janelas enquanto tiver.
pub fn foco_ativo() -> bool {
    FOCO.load(Ordering::Relaxed) != 0
}

/// Devolve o foco ao kernel. Verdadeiro se alguma superfície o tinha — e
/// então o dono precisa saber.
pub fn devolver_foco() -> bool {
    FOCO.swap(0, Ordering::Relaxed) != 0
}

/// `(vivas, criadas, recolhidas de donos mortos)`.
pub fn estatisticas() -> (u64, u64, u64) {
    (
        OCUPADAS.load(Ordering::Relaxed),
        CRIADAS.load(Ordering::Relaxed),
        RECOLHIDAS.load(Ordering::Relaxed),
    )
}

/// Destrava a tabela à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { VAGAS.force_unlock() };
}
