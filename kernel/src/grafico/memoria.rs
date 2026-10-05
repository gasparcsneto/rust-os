//! A memória de uma superfície: páginas próprias, fora do heap.
//!
//! # Por que não o heap
//!
//! Porque ele tem 1 MiB e uma tela inteira tem 4. O Redox não tem esse
//! problema — os drivers dele vivem em espaço de usuário e pedem memória com
//! `mmap` —, e este é o ponto em que o porte não pode ser literal: aqui a
//! superfície sai direto do alocador de frames, mapeada numa faixa virtual
//! reservada para isso em cada arquitetura
//! ([`crate::arch::BASE_DAS_SUPERFICIES`]).
//!
//! # Por que a faixa é devolvida, e não só reservada
//!
//! Porque um compositor cria e solta uma superfície a cada janela. A reserva
//! era um incremento que nunca andava para trás — o arranjo de
//! [`crate::mmio`], onde o que se mapeia fica para sempre —, e no ARM a faixa
//! é uma entrada de topo, 1 GiB: telas de 4 MiB a esgotavam depois de umas
//! duzentas e cinquenta criações, **com a memória sobrando**, porque os
//! frames sempre voltaram ao alocador no `Drop`. O que acabava era o espaço
//! virtual.
//!
//! Agora o `Drop` devolve também o endereço. A faixa guarda os trechos
//! livres abaixo do topo, em ordem e já fundidos com os vizinhos, e a
//! reserva pega o primeiro que caiba antes de subir o topo. Um trecho
//! devolvido que encosta no topo faz o topo descer, em vez de virar um
//! trecho livre — é o caso comum, o da superfície que nasce e morre em
//! seguida.
//!
//! # Por que reaproveitar um endereço é seguro
//!
//! Porque desmapear invalida a tradução no TLB, nas duas arquiteturas, antes
//! de o frame voltar ao alocador. A superfície seguinte que cair no mesmo
//! endereço não enxerga as páginas da anterior — em **nenhum** núcleo: a
//! faixa é memória do kernel, que todo núcleo traduz, e desmapear uma página
//! do kernel avisa os outros antes de o frame voltar (no x86, por NMI; no
//! ARM, a invalidação já é difundida pelo hardware — ver
//! [`crate::arch`]). O caso "smp: desmapear do kernel vale em todo nucleo"
//! confere.
//!
//! # Por que uma tabela fixa de trechos
//!
//! Porque ela não pode depender do heap, que tem 4 MiB e que uma falha de
//! alocação no meio de um `Drop` não teria como devolver. E porque o tamanho
//! dela tem um teto que se calcula: cada trecho livre abaixo do topo tem uma
//! superfície viva logo acima, então há no máximo tantos trechos quantas
//! superfícies vivas. [`MAX_TRECHOS`] trechos cobrem 256 superfícies vivas
//! ao mesmo tempo — no ARM, a faixa inteira em telas de 4 MiB. Passar disso
//! perde endereço virtual, e não memória, e fica no log e em
//! [`perdidos`].
//!
//! Esgotar não corrompe nada: a reserva recusa, e a criação da superfície
//! falha com um erro que diz o quê.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::trava::Mutex;

use crate::arch::{BASE_DAS_SUPERFICIES, COBERTURA_DA_ENTRADA_DE_TOPO, Permissoes, TAMANHO_PAGINA};

/// Quantos trechos livres a faixa acompanha. Ver o cabeçalho do módulo.
pub const MAX_TRECHOS: usize = 256;

/// O espaço virtual das superfícies: o que está livre abaixo do topo, e o
/// topo.
static FAIXA: Mutex<Faixa> = Mutex::new(Faixa::nova(
    BASE_DAS_SUPERFICIES,
    BASE_DAS_SUPERFICIES + COBERTURA_DA_ENTRADA_DE_TOPO,
));

/// Quantos bytes de endereço virtual se perderam por falta de vaga na tabela
/// de trechos.
static PERDIDOS: AtomicU64 = AtomicU64::new(0);

/// Quantas superfícies estão vivas, e quantos bytes elas seguram.
///
/// Para o relatório do agente: é o número que diz se alguém está criando
/// superfícies e esquecendo de largá-las, antes de a memória acabar.
static VIVAS: AtomicU64 = AtomicU64::new(0);
static BYTES_VIVOS: AtomicU64 = AtomicU64::new(0);

/// Uma faixa de páginas mapeadas, que devolve os frames quando some.
pub struct Memoria {
    inicio: u64,
    paginas: u64,
}

impl Memoria {
    /// Reserva, mapeia e zera páginas que cubram `bytes`.
    ///
    /// Tudo ou nada: se o alocador de frames falhar no meio, as páginas já
    /// mapeadas são devolvidas antes de o erro subir. Uma superfície pela
    /// metade seria memória presa sem dono — o mesmo raciocínio do desfazer
    /// de [`crate::mmio::mapear`], e com um caso que o prova do mesmo jeito.
    pub fn nova(bytes: u64) -> Result<Memoria, &'static str> {
        let paginas = bytes.div_ceil(TAMANHO_PAGINA);
        if paginas == 0 {
            return Err("superficie de tamanho zero");
        }
        let inicio = reservar(paginas * TAMANHO_PAGINA)?;

        for indice in 0..paginas {
            let pagina = inicio + indice * TAMANHO_PAGINA;
            if let Err(motivo) = crate::paginacao::mapear_novo(pagina, Permissoes::DADOS) {
                let mut todas_sairam = true;
                for desfazer in 0..indice {
                    let pagina = inicio + desfazer * TAMANHO_PAGINA;
                    if let Err(porque) = crate::paginacao::desmapear_e_liberar(pagina) {
                        todas_sairam = false;
                        crate::log_error!(
                            "grafico",
                            "a pagina {:#x} ficou presa depois de uma superficie que falhou: {}",
                            pagina,
                            porque
                        );
                    }
                }
                // O endereço volta junto, e só se nada ficou mapeado nele: a
                // próxima superfície que o recebesse tentaria mapear por cima
                // de uma página que ainda está lá.
                if todas_sairam {
                    devolver(inicio, paginas * TAMANHO_PAGINA);
                }
                return Err(motivo);
            }
        }

        VIVAS.fetch_add(1, Ordering::Relaxed);
        BYTES_VIVOS.fetch_add(paginas * TAMANHO_PAGINA, Ordering::Relaxed);
        Ok(Memoria { inicio, paginas })
    }

    /// O endereço virtual da primeira página.
    ///
    /// Quem pergunta é quem precisa tratar a memória como endereço: a tela do
    /// kernel quando ela mora sobre um `virtio-gpu`, o driver dele para achar
    /// as páginas físicas, e a suíte para montar uma tela sintética por cima.
    pub fn inicio(&self) -> u64 {
        self.inicio
    }

    /// Quantos bytes estão mapeados — o pedido, arredondado para página.
    pub fn bytes(&self) -> u64 {
        self.paginas * TAMANHO_PAGINA
    }

    /// A memória como pixels de 32 bits.
    pub fn pixels(&self) -> &[u32] {
        // SAFETY: as páginas foram mapeadas por `nova`, são desta estrutura
        // enquanto ela viver, e o início é alinhado a página — logo a 32
        // bits. O comprimento cabe no que foi mapeado.
        unsafe { core::slice::from_raw_parts(self.inicio as *const u32, self.quantos_u32()) }
    }

    /// A memória como pixels de 32 bits, para escrever.
    pub fn pixels_mut(&mut self) -> &mut [u32] {
        // SAFETY: as de `pixels`, e o `&mut self` garante que não há outra
        // referência viva para a mesma faixa.
        unsafe { core::slice::from_raw_parts_mut(self.inicio as *mut u32, self.quantos_u32()) }
    }

    /// A memória como blocos de 1 KiB do Argon2id: a memória de trabalho de
    /// conferir uma senha, que não cabe no heap — ver [`crate::pessoas`].
    pub fn blocos_mut(&mut self) -> &mut [sigilo::credencial::Block] {
        use sigilo::credencial::Block;
        const {
            assert!(core::mem::size_of::<Block>() == 1024);
            assert!(core::mem::align_of::<Block>() <= TAMANHO_PAGINA as usize);
        }
        // SAFETY: as de `pixels_mut`; o início é alinhado a página, que é
        // mais que o alinhamento de um bloco, e um bloco é um arranjo de
        // `u64`, para o qual qualquer padrão de bits — os zeros de `nova`,
        // inclusive — é válido.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.inicio as *mut Block,
                (self.bytes() / 1024) as usize,
            )
        }
    }

    fn quantos_u32(&self) -> usize {
        (self.bytes() / 4) as usize
    }
}

impl Drop for Memoria {
    fn drop(&mut self) {
        let mut todas_sairam = true;
        for indice in 0..self.paginas {
            let pagina = self.inicio + indice * TAMANHO_PAGINA;
            // Soltar, e não liberar: a superfície de um processo tem os
            // mesmos frames mapeados no espaço dele — ver
            // `paginacao::espelhar_no_usuario` —, e o processo pode ainda
            // estar desenhando neles. O frame volta ao alocador com o último
            // dos dois donos; numa superfície do kernel, que tem um só, soltar
            // é liberar.
            if let Err(porque) = crate::arch::desmapear(pagina).map(crate::frames::soltar) {
                todas_sairam = false;
                crate::log_error!(
                    "grafico",
                    "a pagina {:#x} de uma superficie nao voltou ao alocador: {}",
                    pagina,
                    porque
                );
            }
        }
        // Como no desfazer de `nova`: uma página que não saiu ainda está
        // mapeada, e o endereço dela não pode ir para outra superfície.
        if todas_sairam {
            devolver(self.inicio, self.bytes());
        }
        VIVAS.fetch_sub(1, Ordering::Relaxed);
        BYTES_VIVOS.fetch_sub(self.bytes(), Ordering::Relaxed);
    }
}

/// Onde uma superfície de `bytes` cairia se fosse criada agora.
///
/// Só para a suíte: é o que permite a um caso saber que páginas conferir
/// depois de uma criação que falhou, e a outro conferir que um endereço
/// devolvido é o que a próxima reserva recebe.
#[cfg(feature = "modo-teste")]
pub fn onde_cairia(bytes: u64) -> Option<u64> {
    let bytes = bytes.div_ceil(TAMANHO_PAGINA) * TAMANHO_PAGINA;
    crate::arch::sem_interrupcoes(|| FAIXA.lock().onde_cairia(bytes))
}

/// O topo da faixa: acima dele, nada foi reservado. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn topo() -> u64 {
    crate::arch::sem_interrupcoes(|| FAIXA.lock().topo)
}

/// Quantos bytes de endereço virtual se perderam por falta de vaga na tabela
/// de trechos. Zero, enquanto houver menos superfícies vivas que
/// [`MAX_TRECHOS`].
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn perdidos() -> u64 {
    PERDIDOS.load(Ordering::Relaxed)
}

/// Quantas superfícies estão vivas, e quantos bytes elas seguram.
pub fn vivas() -> (u64, u64) {
    (
        VIVAS.load(Ordering::Relaxed),
        BYTES_VIVOS.load(Ordering::Relaxed),
    )
}

/// Reserva espaço virtual na faixa das superfícies.
///
/// Com as interrupções mascaradas, como toda trava que o caminho fatal
/// solta: um fio preemptado segurando esta deixaria qualquer outra criação
/// de superfície girando.
fn reservar(bytes: u64) -> Result<u64, &'static str> {
    crate::arch::sem_interrupcoes(|| FAIXA.lock().reservar(bytes))
        .ok_or("a faixa das superficies se esgotou")
}

/// Devolve à faixa o endereço de uma superfície que saiu.
fn devolver(inicio: u64, bytes: u64) {
    if !crate::arch::sem_interrupcoes(|| FAIXA.lock().devolver(inicio, bytes)) {
        PERDIDOS.fetch_add(bytes, Ordering::Relaxed);
        crate::log_error!(
            "grafico",
            "{} KiB de endereco virtual em {:#x} se perderam: a tabela de trechos livres encheu",
            bytes / 1024,
            inicio
        );
    }
}

/// Solta a trava da faixa.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        FAIXA.force_unlock();
    }
}

/// O espaço virtual de uma faixa: os trechos livres abaixo do topo, e o topo.
///
/// Separada da trava e dos endereços de verdade para a suíte poder
/// exercitá-la com uma faixa de mentira — os casos que importam aqui são
/// de aritmética, e nenhum precisa mapear página nenhuma.
pub struct Faixa {
    /// Os trechos livres, `(início, bytes)`, em ordem de endereço e sem
    /// dois vizinhos: dois trechos que se tocam são um só.
    trechos: [(u64, u64); MAX_TRECHOS],
    quantos: usize,
    /// Acima dele, nada foi reservado.
    topo: u64,
    fim: u64,
}

impl Faixa {
    pub const fn nova(inicio: u64, fim: u64) -> Self {
        Faixa {
            trechos: [(0, 0); MAX_TRECHOS],
            quantos: 0,
            topo: inicio,
            fim,
        }
    }

    /// O primeiro trecho livre em que `bytes` cabem; senão, o topo, se couber
    /// antes do fim.
    ///
    /// O primeiro, e não o de tamanho mais próximo: com superfícies de poucos
    /// tamanhos — a tela, as janelas —, os trechos tendem a ser do tamanho do
    /// que saiu, e o primeiro que cabe costuma ser exato. Procurar o melhor
    /// custaria percorrer a tabela inteira a cada criação.
    pub fn onde_cairia(&self, bytes: u64) -> Option<u64> {
        if bytes == 0 {
            return None;
        }
        self.trechos[..self.quantos]
            .iter()
            .find(|&&(_, tamanho)| tamanho >= bytes)
            .map(|&(inicio, _)| inicio)
            .or_else(|| {
                let fim = self.topo.checked_add(bytes)?;
                (fim <= self.fim).then_some(self.topo)
            })
    }

    pub fn reservar(&mut self, bytes: u64) -> Option<u64> {
        let inicio = self.onde_cairia(bytes)?;
        // Nenhum trecho livre começa no topo: estão todos abaixo dele.
        if inicio == self.topo {
            self.topo += bytes;
            return Some(inicio);
        }
        let i = self.trechos[..self.quantos]
            .iter()
            .position(|&(outro, _)| outro == inicio)?;
        let tamanho = self.trechos[i].1;
        if tamanho == bytes {
            self.remover(i);
        } else {
            self.trechos[i] = (inicio + bytes, tamanho - bytes);
        }
        Some(inicio)
    }

    /// Devolve um trecho. `false` se ele não coube na tabela — o endereço se
    /// perde, e quem chamou registra.
    pub fn devolver(&mut self, inicio: u64, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        // O caso comum: a última superfície a nascer é a primeira a morrer.
        // O topo desce, e desce mais se o trecho livre de baixo encostar.
        if inicio + bytes == self.topo {
            self.topo = inicio;
            if self.quantos > 0 {
                let (ultimo, tamanho) = self.trechos[self.quantos - 1];
                if ultimo + tamanho == self.topo {
                    self.topo = ultimo;
                    self.quantos -= 1;
                }
            }
            return true;
        }

        // Onde ele entra na ordem: antes do primeiro trecho que começa
        // depois dele.
        let i = self.trechos[..self.quantos]
            .iter()
            .position(|&(outro, _)| outro > inicio)
            .unwrap_or(self.quantos);
        let funde_antes = i > 0 && {
            let (anterior, tamanho) = self.trechos[i - 1];
            anterior + tamanho == inicio
        };
        let funde_depois = i < self.quantos && inicio + bytes == self.trechos[i].0;

        match (funde_antes, funde_depois) {
            (true, true) => {
                let (_, depois) = self.trechos[i];
                self.trechos[i - 1].1 += bytes + depois;
                self.remover(i);
            }
            (true, false) => self.trechos[i - 1].1 += bytes,
            (false, true) => self.trechos[i] = (inicio, bytes + self.trechos[i].1),
            (false, false) => {
                if self.quantos == MAX_TRECHOS {
                    return false;
                }
                self.trechos.copy_within(i..self.quantos, i + 1);
                self.trechos[i] = (inicio, bytes);
                self.quantos += 1;
            }
        }
        true
    }

    /// Quantos trechos livres há abaixo do topo.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub fn trechos(&self) -> usize {
        self.quantos
    }

    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub fn topo(&self) -> u64 {
        self.topo
    }

    fn remover(&mut self, i: usize) {
        self.trechos.copy_within(i + 1..self.quantos, i);
        self.quantos -= 1;
    }
}
