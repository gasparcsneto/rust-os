//! O disco da máquina, de qualquer driver: as janelas de escrita, a
//! descarga, a faixa e a tranca — o que vale para todo disco.
//!
//! # Por que uma camada
//!
//! As regras que protegem o resto do disco moravam no driver do virtio-blk:
//! as janelas de escrita — só a partição de estado e a do armazém recebem
//! escrita —, a recusa de escrever num disco que não promete durabilidade,
//! a conferência da faixa. Um segundo driver as repetiria, e a primeira que
//! ele esquecesse deixaria a ESP e a raiz ao alcance de uma conta errada.
//! Aqui elas valem para qualquer [`Dispositivo`]: o driver só sabe ler,
//! escrever e descarregar setores; onde se escreve, quem decide é esta
//! camada — e ela confere antes de o pedido chegar ao driver.
//!
//! # Um disco
//!
//! A máquina tem um disco do sistema: o primeiro que um driver liga — o
//! virtio-blk, se houver um; senão, o NVMe. Uma tabela de discos com uma
//! entrada seria generalidade sem cliente; o tipo [`Disco`] é o que se
//! multiplicaria quando houver o segundo.

extern crate alloc;

use alloc::boxed::Box;

use crate::trava::Mutex;

/// Quanto mede um setor: a unidade em que esta camada conta e endereça, em
/// qualquer driver. Um dispositivo cujo bloco lógico seja outro é recusado
/// pelo driver dele.
pub const TAMANHO_DO_SETOR: usize = 512;

/// O maior pedido, em bytes: dezesseis kibibytes, um nó de Btrfs numa ida
/// ao dispositivo — a conta medida está no driver do virtio-blk. Um driver
/// que leve menos por ida parte o pedido por dentro; um pedido maior é
/// recusado aqui, e não partido: quem monta um sistema de arquivos precisa
/// saber quantas idas ao disco um bloco custa.
pub const MAIOR_LEITURA: usize = 16 * 1024;

/// O que um driver de disco sabe fazer — e só isso: nada de janelas, nada
/// de faixas. Quando [`Disco`] chama `ler` ou `escrever`, o pedido já foi
/// conferido: o dispositivo está vivo, o buffer é um múltiplo de setor e
/// cabe em [`MAIOR_LEITURA`], e a faixa inteira está dentro do disco.
pub trait Dispositivo: Send {
    /// O nome do driver, para o relatório: `virtio-blk`, `nvme`.
    fn driver(&self) -> &'static str;

    /// Quantos setores de [`TAMANHO_DO_SETOR`] o disco tem. Cabe em bytes:
    /// o driver recusa, ao ligar, uma capacidade que não caiba.
    fn capacidade(&self) -> u64;

    /// Se o dispositivo ainda responde. Um tempo esgotado o desliga de vez —
    /// o pedido que estourou continua pendente nele, e o próximo correria
    /// com ele.
    fn vivo(&self) -> bool;

    /// Se uma escrita confirmada pode ser tornada durável: o dispositivo
    /// aceita a descarga — ou não guarda escrita nenhuma num cache volátil,
    /// e a confirmação já é a gravação.
    fn descarga(&self) -> bool;

    /// Se o dispositivo se declarou só de leitura.
    fn somente_leitura(&self) -> bool;

    /// Lê `destino.len()` bytes a partir de `setor`.
    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str>;

    /// Escreve `origem` a partir de `setor`. Uma escrita respondida está
    /// aceita, não gravada: é a descarga que a grava.
    fn escrever(&mut self, setor: u64, origem: &[u8]) -> Result<(), &'static str>;

    /// Põe no meio permanente tudo o que já foi confirmado como escrito.
    fn descarregar(&mut self) -> Result<(), &'static str>;

    /// A máquina vai perder a energia: o dispositivo põe no meio o que
    /// guarda e se prepara. Depois disto nada mais se pede a ele. O padrão
    /// é nada — o virtio-blk não tem o que avisar.
    fn avisar_desligamento(&mut self) {}
}

/// O disco do sistema: um [`Dispositivo`] e as regras de todo disco.
pub struct Disco {
    dispositivo: Box<dyn Dispositivo>,
    /// Os setores em que este kernel pode escrever: o primeiro e quantos.
    ///
    /// # Por que a camada guarda isto, e não quem escreve
    ///
    /// Porque o disco tem a ESP de onde a máquina boota e a raiz de onde os
    /// programas saem, e uma escrita que caísse nelas por um setor errado
    /// não teria volta. A regra de que só a partição de estado e a do
    /// armazém são graváveis poderia morar no journal e no volume, que são
    /// quem escreve — e valeria enquanto ninguém mais escrevesse, nem um
    /// deles errasse uma conta. Aqui ela vale para qualquer chamador, contra
    /// os dois, e em qualquer driver.
    ///
    /// Fixadas uma vez, no boot, pela tabela de partições — ver
    /// [`fixar_janela_de_escrita`] —, e nunca mais mudadas. Sem elas, nada se
    /// escreve.
    ///
    /// São duas, e cada uma tem um nome ([`Janela`]): quem escreve diz em
    /// qual, e o setor é conferido contra **aquela** janela — o volume do
    /// armazém não alcança o estado por uma conta errada, e o journal não
    /// alcança o volume.
    janelas: [Option<(u64, u64)>; 2],
    /// Quantas escritas e quantas descargas o dispositivo confirmou. Só
    /// para os casos e para o relatório: é o que mostra de dentro que a
    /// descarga aconteceu.
    escritas: u64,
    descargas: u64,
    /// Só na suíte: as últimas escritas confirmadas — ver [`Rastro`].
    #[cfg(feature = "modo-teste")]
    rastro: Rastro,
}

/// Só na suíte: as últimas [`RASTRO`] escritas que o dispositivo confirmou,
/// cada uma com o número dela, o setor, quantos setores e um resumo do que
/// foi escrito — nada do conteúdo. É para o diagnóstico de um bloco do
/// armazém que não abre: quem mais escreveu nos setores dele, e se o que
/// se lê é o que se escreveu por último.
#[cfg(feature = "modo-teste")]
struct Rastro {
    escritas: alloc::vec::Vec<(u64, u64, u32, u64)>,
    proxima: u64,
}

/// Quantas escritas o rastro guarda: 192 KiB de heap, e mais que as de um
/// caso inteiro do gestor — o módulo de 8 MiB são 2 049 blocos.
#[cfg(feature = "modo-teste")]
const RASTRO: usize = 8192;

/// Um resumo de 64 bits do que se leu ou escreveu: FNV-1a, só para comparar
/// — não é proteção de nada.
#[cfg(feature = "modo-teste")]
pub fn resumo(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// O disco do sistema, se um driver ligou um.
static DISCO: Mutex<Option<Disco>> = Mutex::new(None);

impl Disco {
    /// O disco sobre `dispositivo`, sem janela nenhuma: até uma ser fixada,
    /// nada se escreve.
    pub fn novo(dispositivo: Box<dyn Dispositivo>) -> Disco {
        Disco {
            dispositivo,
            janelas: [None, None],
            escritas: 0,
            descargas: 0,
            #[cfg(feature = "modo-teste")]
            rastro: Rastro {
                escritas: alloc::vec::Vec::with_capacity(RASTRO),
                proxima: 0,
            },
        }
    }

    /// O driver por baixo.
    pub fn driver(&self) -> &'static str {
        self.dispositivo.driver()
    }

    /// Se uma escrita durável é possível neste disco: ele responde, aceita
    /// escrita e a promete gravada depois da descarga. É o que a
    /// persistência pergunta antes de se declarar disponível.
    pub fn duravel(&self) -> bool {
        self.dispositivo.vivo()
            && self.dispositivo.descarga()
            && !self.dispositivo.somente_leitura()
    }

    /// Uma janela de escrita: o primeiro setor e quantos, se já foi fixada.
    pub fn janela(&self, qual: Janela) -> Option<(u64, u64)> {
        self.janelas[qual as usize]
    }

    /// Quantas escritas e quantas descargas o dispositivo confirmou.
    pub fn contadores(&self) -> (u64, u64) {
        (self.escritas, self.descargas)
    }

    /// Só na suíte: as escritas do rastro que tocaram `[setor, setor +
    /// setores)`, da mais velha para a mais nova — o número, o setor,
    /// quantos e o resumo —, e quantas escritas o disco confirmou ao todo.
    #[cfg(feature = "modo-teste")]
    pub fn escritas_em(
        &self,
        setor: u64,
        setores: u64,
    ) -> (alloc::vec::Vec<(u64, u64, u32, u64)>, u64) {
        let mut tocaram: alloc::vec::Vec<(u64, u64, u32, u64)> = self
            .rastro
            .escritas
            .iter()
            .copied()
            .filter(|&(_, s, n, _)| s < setor + setores && setor < s + u64::from(n))
            .collect();
        tocaram.sort_unstable_by_key(|e| e.0);
        (tocaram, self.rastro.proxima)
    }

    /// Quantos setores o disco tem. Multiplicar por [`TAMANHO_DO_SETOR`] é
    /// seguro em qualquer chamador: o driver recusou, ao ligar, a
    /// capacidade que não coubesse em bytes.
    pub fn capacidade(&self) -> u64 {
        self.dispositivo.capacidade()
    }

    /// Lê um setor.
    ///
    /// Existe porque quem lê um setor só não deveria precisar montar uma
    /// fatia: é o caso do relatório do agente e da tabela de partições. Por
    /// dentro é [`Disco::ler`] com um setor.
    pub fn ler_setor(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        if destino.len() != TAMANHO_DO_SETOR {
            return Err("o destino precisa ter um setor");
        }
        self.ler(setor, destino)
    }

    /// Lê setores consecutivos numa ida ao dispositivo — no driver, que
    /// parte por dentro se a ida dele for menor.
    ///
    /// `destino` precisa ser um múltiplo de setor e caber em
    /// [`MAIOR_LEITURA`].
    pub fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        self.conferir_faixa(setor, destino.len())?;
        self.dispositivo.ler(setor, destino)
    }

    /// Escreve setores consecutivos — e só dentro da janela de escrita.
    ///
    /// Uma escrita respondida **não está gravada**: está aceita. Quem
    /// precisa dela no disco chama [`Disco::descarregar_disco`] depois, e
    /// só então a considera feita. Separar as duas coisas é o que deixa o
    /// journal juntar várias escritas sob uma descarga só, sem que isso
    /// mude o que cada uma promete.
    ///
    /// Recusada inteira, sem tocar o dispositivo, se o disco não aceita
    /// descarga: uma escrita que nunca pode ser tornada durável é uma
    /// escrita que mente para quem a pediu.
    pub fn gravar_setores(
        &mut self,
        qual: Janela,
        setor: u64,
        origem: &[u8],
    ) -> Result<(), &'static str> {
        self.conferir_faixa(setor, origem.len())?;
        if self.dispositivo.somente_leitura() {
            return Err("o disco e so de leitura");
        }
        if !self.dispositivo.descarga() {
            return Err("o disco nao aceita descarga, e uma escrita nao seria duravel");
        }
        let Some((primeiro, setores)) = self.janelas[qual as usize] else {
            return Err("essa janela de escrita nao foi fixada");
        };
        let quantos = (origem.len() / TAMANHO_DO_SETOR) as u64;
        // As duas pontas: começar dentro e terminar dentro. Somas saturadas,
        // pela mesma razão de [`Disco::conferir_faixa`]: um setor absurdo
        // não pode dar a volta e cair dentro.
        if setor < primeiro || setor.saturating_add(quantos) > primeiro.saturating_add(setores) {
            return Err("escrita fora da janela de escrita");
        }
        self.dispositivo.escrever(setor, origem)?;
        self.escritas += 1;
        #[cfg(feature = "modo-teste")]
        {
            let e = (self.rastro.proxima, setor, quantos as u32, resumo(origem));
            let i = (self.rastro.proxima % RASTRO as u64) as usize;
            if self.rastro.escritas.len() < RASTRO {
                self.rastro.escritas.push(e);
            } else {
                self.rastro.escritas[i] = e;
            }
            self.rastro.proxima += 1;
        }
        Ok(())
    }

    /// Pede ao dispositivo que ponha no meio permanente tudo o que ele já
    /// confirmou como escrito.
    pub fn descarregar_disco(&mut self) -> Result<(), &'static str> {
        if !self.dispositivo.vivo() {
            return Err("o disco parou de responder e foi desligado");
        }
        if !self.dispositivo.descarga() {
            return Err("o disco nao aceita descarga");
        }
        self.dispositivo.descarregar()?;
        self.descargas += 1;
        Ok(())
    }

    /// A máquina vai parar: ver [`Dispositivo::avisar_desligamento`]. Só
    /// quem para as gravações chama, com elas paradas e o disco descarregado
    /// — `crate::persistencia::parar_as_gravacoes`.
    pub fn avisar_desligamento(&mut self) {
        if self.dispositivo.vivo() {
            self.dispositivo.avisar_desligamento();
        }
    }

    /// As regras comuns a ler e escrever: disco vivo, múltiplo de setor,
    /// cabe numa ida, cabe no disco.
    fn conferir_faixa(&self, setor: u64, bytes: usize) -> Result<(), &'static str> {
        if !self.dispositivo.vivo() {
            return Err("o disco parou de responder e foi desligado");
        }
        if bytes == 0 || !bytes.is_multiple_of(TAMANHO_DO_SETOR) {
            return Err("o destino precisa ser um multiplo de setor");
        }
        if bytes > MAIOR_LEITURA {
            return Err("o pedido passa do maior que o driver monta");
        }
        let setores = (bytes / TAMANHO_DO_SETOR) as u64;
        // A soma satura para que um setor absurdo não dê a volta e caia dentro
        // da capacidade.
        if setor.saturating_add(setores) > self.dispositivo.capacidade() {
            return Err("setor alem da capacidade do disco");
        }
        Ok(())
    }
}

/// Põe `dispositivo` como o disco do sistema — se ainda não há um. O
/// segundo é recusado: o disco do sistema é o primeiro que um driver ligou.
pub fn instalar(dispositivo: Box<dyn Dispositivo>) -> Result<(), &'static str> {
    crate::arch::sem_interrupcoes(|| {
        let mut disco = DISCO.lock();
        if disco.is_some() {
            return Err("a maquina ja tem um disco do sistema");
        }
        *disco = Some(Disco::novo(dispositivo));
        Ok(())
    })
}

/// Se a máquina já tem um disco do sistema.
pub fn ha_disco() -> bool {
    crate::arch::sem_interrupcoes(|| DISCO.lock().is_some())
}

/// As janelas de escrita, pelo nome — ver [`Disco::gravar_setores`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Janela {
    /// A partição de estado: o journal da persistência.
    Estado = 0,
    /// A partição do armazém: o volume dele.
    Armazem = 1,
}

impl Disco {
    /// Fixa uma janela de escrita deste disco — ver
    /// [`fixar_janela_de_escrita`], que é quem o boot chama.
    pub fn fixar_janela(
        &mut self,
        qual: Janela,
        primeiro: u64,
        setores: u64,
    ) -> Result<(), &'static str> {
        if self.janelas[qual as usize].is_some() {
            return Err("a janela de escrita ja foi fixada");
        }
        if setores == 0 || primeiro.saturating_add(setores) > self.dispositivo.capacidade() {
            return Err("janela de escrita fora do disco");
        }
        let fim = primeiro + setores;
        if self
            .janelas
            .iter()
            .flatten()
            .any(|&(p, n)| primeiro < p + n && p < fim)
        {
            return Err("a janela de escrita cruza a outra");
        }
        self.janelas[qual as usize] = Some((primeiro, setores));
        Ok(())
    }
}

/// Fixa uma janela de escrita do disco do sistema: setores em que este
/// kernel pode escrever, daqui até o fim, só por quem diz o nome dela.
///
/// Chamada uma vez por janela, no boot, com a partição que a tabela trouxe.
/// Uma segunda chamada para a mesma janela é recusada, mesmo que com a
/// mesma faixa: a janela não é algo que um caminho de execução possa
/// redesenhar depois que o sistema subiu, e uma função que aceitasse ser
/// chamada de novo seria exatamente isso. Uma janela que cruze a outra
/// também: o estado e o armazém nunca dividem um setor.
pub fn fixar_janela_de_escrita(
    qual: Janela,
    primeiro: u64,
    setores: u64,
) -> Result<(), &'static str> {
    com_o_disco(|d| d.fixar_janela(qual, primeiro, setores))
        .unwrap_or(Err("nao ha disco nesta maquina"))
}

/// Chama `f` com o disco do sistema, se houver um.
///
/// O acesso passa por aqui, e não por um `&'static mut`, porque um pedido de
/// bloco não é reentrante: os buffers de um driver são um só jogo, e duas
/// leituras simultâneas escreveriam o pedido uma por cima da outra. A
/// tranca é o que torna isso impossível em vez de improvável.
pub fn com_o_disco<R>(f: impl FnOnce(&mut Disco) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| DISCO.lock().as_mut().map(f))
}

/// Destrava a tranca do disco à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { DISCO.force_unlock() };
}
