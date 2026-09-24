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

// Deslocamentos do cabeçalho e do byte de estado dentro do frame de trabalho.
// Os dados não moram aqui: eles têm frames próprios, ver [`PAGINAS_DE_DADOS`].
const CABECALHO_EM: u64 = 0;
const ESTADO_EM: u64 = 16;

const _: () = assert!(ESTADO_EM < crate::arch::TAMANHO_PAGINA);
const _: () = assert!(core::mem::size_of::<Cabecalho>() as u64 <= ESTADO_EM);

/// Quantas páginas de dados uma leitura pode preencher de uma vez.
///
/// # Por que mais de uma, e por que quatro
///
/// Porque o custo de ler do disco é **por requisição**, e não por byte.
/// Medido, lendo mil setores um a um: 100 ms no ARM e 110 no x86, com 234
/// voltas de espera por leitura — cem microssegundos por ida ao dispositivo,
/// seja ela de meio kilobyte ou de dezesseis.
///
/// O comentário que estava aqui dizia "a resposta vem em microssegundos", e
/// isso era uma estimativa que ninguém tinha medido. São cem, o que não muda
/// nada para quem lê um setor no boot e muda tudo para um sistema de
/// arquivos: um nó de Btrfs tem 16 KiB, e lê-lo setor a setor eram trinta e
/// duas idas de cem microssegundos cada.
///
/// Quatro páginas são exatamente esses 16 KiB. O teto não é o número de
/// páginas, é o de descritores: a cadeia leva o cabeçalho, uma entrada por
/// página e o byte de estado, e a fila tem oito.
const PAGINAS_DE_DADOS: usize = 4;

/// O maior pedido, em bytes.
pub const MAIOR_LEITURA: usize = PAGINAS_DE_DADOS * crate::arch::TAMANHO_PAGINA as usize;

const _: () = assert!(PAGINAS_DE_DADOS + 2 <= super::fila::DESCRITORES as usize);

/// Quantas voltas esperar por uma resposta antes de desistir.
///
/// Não é um tempo: é um número de tentativas, porque aqui ainda não há relógio
/// confiável em todo caminho que chama o disco. A ordem de grandeza é
/// deliberadamente folgada — um dispositivo emulado responde em algumas
/// dezenas de voltas, e o teto só precisa distinguir "lento" de "morto".
///
/// # O que esperar custa
///
/// O acesso ao disco passa por [`com_o_disco`], que mascara interrupções — é a
/// disciplina que este kernel aplica a toda tranca compartilhada. Enquanto a
/// espera roda, então, o timer não conta e o escalonador não troca de fio.
///
/// No caminho normal isso é irrelevante: a resposta vem em microssegundos. No
/// caminho ruim seriam dezenas de milissegundos de kernel parado — e o que
/// torna isso aceitável não é o número, é o campo `vivo`. Um tempo esgotado
/// desliga o disco, então a espera longa acontece **no máximo uma vez** na
/// vida do kernel. Sem aquele campo, cada leitura seguinte pagaria o mesmo
/// preço, para sempre.
const VOLTAS_DE_ESPERA: u32 = 5_000_000;

/// Um disco virtio pronto para uso.
pub struct Disco {
    transporte: Transporte,
    fila: Fila,
    /// Frame físico com o cabeçalho e o byte de estado.
    trabalho: u64,
    /// Endereço virtual do mesmo frame.
    base: *mut u8,
    /// Os frames onde o dispositivo deposita o que foi lido.
    ///
    /// Separados do de trabalho, e um por página, porque um descritor descreve
    /// uma faixa contígua e o alocador entrega uma página por vez. Juntá-los
    /// exigiria um alocador de faixas contíguas — que não existe, e que só
    /// valeria a pena se houvesse um segundo cliente para ele.
    dados: [u64; PAGINAS_DE_DADOS],
    bases_de_dados: [*mut u8; PAGINAS_DE_DADOS],
    /// Capacidade, em setores de 512 bytes.
    capacidade: u64,
    /// Se o disco ainda pode ser usado.
    ///
    /// # Por que um tempo esgotado e definitivo
    ///
    /// Porque a requisicao que estourou o tempo **continua pendente no
    /// dispositivo**. Ele nao desistiu — nos e que paramos de esperar. O frame
    /// de trabalho continua sendo dele: ele pode escrever a resposta ali a
    /// qualquer momento, e a conclusao dela ainda vai aparecer no anel de
    /// usados.
    ///
    /// Sem este campo, a leitura seguinte faria duas coisas erradas de uma vez.
    /// Sobrescreveria o cabecalho e o byte de estado enquanto o dispositivo
    /// pode estar lendo um e escrevendo o outro — uma corrida de DMA, que e
    /// indefinida por construcao. E colheria do anel a conclusao **atrasada**,
    /// nao a da requisicao nova, porque o indice da cadeia e sempre zero neste
    /// driver e as duas sao indistinguiveis.
    ///
    /// O que se observa depois disso depende de quem chegou primeiro: um
    /// "dispositivo recusou a leitura" espurio, um setor trocado, ou um acerto
    /// por acaso. Um defeito cujo sintoma muda a cada execucao e pior que um
    /// erro, e e por isso que o primeiro tempo esgotado encerra o assunto.
    vivo: bool,
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

        // O `?` aqui seria o unico caminho de erro desta funcao a sair sem
        // abortar, e deixaria o dispositivo parado em `DRIVER` — que e
        // exatamente o estado que `abortar` existe para distinguir de um
        // driver que travou no meio.
        let capacidade = match transporte
            .configuracao()
            .and_then(|config: Mmio| config.ler_u64(CONFIG_CAPACIDADE))
        {
            Some(capacidade) => capacidade,
            None => {
                transporte.abortar();
                return Err("dispositivo nao publica capacidade");
            }
        };

        // A capacidade vem em setores e é usada em bytes — no log logo abaixo,
        // em `disk.info`, e em qualquer conta que venha depois. A conversão é
        // uma multiplicação por 512, e ela transborda para qualquer capacidade
        // a partir de 2^55 setores.
        //
        // Recusamos aqui, e não em cada lugar que multiplica, porque o que
        // transborda não é a conta: é o número. Um disco de 2^55 setores são
        // dezesseis exabytes, que nenhum disco tem e nenhum emulador oferece —
        // é o dispositivo dizendo algo impossível. Deixar o valor entrar
        // obrigaria todo caminho que o usa a se defender dele, e bastaria um
        // esquecer para o kernel entrar em pânico ao **responder uma
        // pergunta** sobre o disco, ou para relatar um tamanho que deu a volta.
        if capacidade > u64::MAX / TAMANHO_DO_SETOR as u64 {
            transporte.abortar();
            return Err("capacidade que nao cabe em bytes");
        }

        let fila = match Fila::nova(&transporte, FILA_DE_PEDIDOS) {
            Ok(fila) => fila,
            Err(motivo) => {
                transporte.abortar();
                return Err(motivo);
            }
        };

        let Some(trabalho) = crate::frames::alocar() else {
            // A fila montada acima fica com o frame dela, e de proposito: ela
            // ja foi habilitada no dispositivo, que portanto pode le-la. Sair
            // daqui devolvendo aquele frame ao alocador seria entregar a outro
            // dono uma pagina que o dispositivo tem o direito de varrer.
            //
            // `abortar` marca o dispositivo como falho, o que o obriga a
            // parar — mas o frame nao volta mesmo assim. Vazar um frame num
            // caminho de boot que so roda uma vez e o preco de nao depender
            // de o dispositivo respeitar o estado.
            transporte.abortar();
            return Err("sem frame para os buffers de pedido");
        };
        let base = crate::arch::acesso_fisico(trabalho);

        // E as páginas de dados. Uma falha no meio devolve as que já vieram:
        // elas ainda não foram entregues a descritor nenhum, então o
        // dispositivo não tem direito sobre elas — ao contrário do frame da
        // fila, que fica onde está pela razão documentada acima.
        let mut dados = [0u64; PAGINAS_DE_DADOS];
        let mut quantas = 0;
        while quantas < PAGINAS_DE_DADOS {
            let Some(frame) = crate::frames::alocar() else {
                break;
            };
            dados[quantas] = frame;
            quantas += 1;
        }
        if quantas != PAGINAS_DE_DADOS {
            for frame in &dados[..quantas] {
                crate::frames::liberar(*frame);
            }
            crate::frames::liberar(trabalho);
            transporte.abortar();
            return Err("sem frames para os buffers de dados");
        }
        let mut bases_de_dados = [core::ptr::null_mut(); PAGINAS_DE_DADOS];
        for (base, frame) in bases_de_dados.iter_mut().zip(&dados) {
            *base = crate::arch::acesso_fisico(*frame);
        }

        // A mestria de barramento vem **antes** de liberar o dispositivo, e a
        // ordem não é indiferente. Ela é o que de fato o autoriza a ler e
        // escrever na nossa memória: tudo até aqui foi conversa por
        // registradores, daqui para frente ele segue ponteiros. Liberar
        // primeiro seria dizer "pode trabalhar" a quem ainda não pode tocar na
        // fila que acabamos de lhe entregar.
        //
        // Ver `pci::habilitar_mestre` para por que isso não é feito na
        // varredura do barramento.
        crate::pci::habilitar_mestre(d);

        // E só agora o dispositivo pode começar a trabalhar. Antes desta
        // escrita a fila não existia para ele.
        transporte.liberar();

        super::ligar_interrupcao(d, &transporte, super::NOME_DISCO);

        Ok(Disco {
            transporte,
            fila,
            trabalho,
            base,
            dados,
            bases_de_dados,
            capacidade,
            vivo: true,
        })
    }

    /// Quantos setores o disco tem.
    ///
    /// Cabe em bytes: [`Disco::ligar`] recusa um dispositivo cuja capacidade
    /// não caiba, então multiplicar por [`TAMANHO_DO_SETOR`] é seguro em
    /// qualquer chamador.
    pub fn capacidade(&self) -> u64 {
        self.capacidade
    }

    /// Lê um setor.
    ///
    /// Continua existindo porque quem lê um setor só não deveria precisar
    /// montar uma fatia: é o caso do relatório do agente e dos testes de
    /// leitura. Por dentro é [`Disco::ler`] com um setor.
    pub fn ler_setor(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        if destino.len() != TAMANHO_DO_SETOR {
            return Err("o destino precisa ter um setor");
        }
        self.ler(setor, destino)
    }

    /// Lê setores consecutivos numa única ida ao dispositivo.
    ///
    /// # Por que numa ida só
    ///
    /// Porque o custo é por requisição. Medido antes disto, lendo mil setores
    /// um a um: 100 ms no ARM e 110 no x86 — cem microssegundos por leitura,
    /// dos quais 234 voltas de espera. Um pedido de dezesseis kilobytes custa
    /// o mesmo que um de meio, e é a diferença entre um nó de Btrfs custar
    /// cem microssegundos ou três milissegundos e meio.
    ///
    /// `destino` precisa ser um múltiplo de setor e caber em
    /// [`MAIOR_LEITURA`]. Um pedido maior é recusado em vez de partido em
    /// dois: partir aqui esconderia de quem chamou que houve mais de uma ida
    /// ao disco, e quem monta um sistema de arquivos precisa saber disso para
    /// decidir o tamanho dos próprios blocos.
    pub fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        if !self.vivo {
            return Err("o disco parou de responder e foi desligado");
        }
        if destino.is_empty() || !destino.len().is_multiple_of(TAMANHO_DO_SETOR) {
            return Err("o destino precisa ser um multiplo de setor");
        }
        if destino.len() > MAIOR_LEITURA {
            return Err("o pedido passa do maior que o driver monta");
        }

        let setores = (destino.len() / TAMANHO_DO_SETOR) as u64;
        // A soma satura para que um setor absurdo não dê a volta e caia dentro
        // da capacidade.
        if setor.saturating_add(setores) > self.capacidade {
            return Err("setor alem da capacidade do disco");
        }

        // SAFETY: o frame é deste disco, os dois deslocamentos vêm das
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

        // A cadeia: o cabeçalho, uma entrada por página de dados que o pedido
        // alcança, e o byte de estado. As do meio são escritas pelo
        // dispositivo; as das pontas, não e sim, nessa ordem.
        let mut cadeia = [(0u64, 0u32, false); PAGINAS_DE_DADOS + 2];
        let mut partes = 1;
        cadeia[0] = (
            // O comprimento do cabeçalho é o tamanho dele, e não o
            // deslocamento do que vem depois: os dois são iguais hoje, e
            // escrever um pelo outro seria depender disso sem dizer que
            // depende.
            self.trabalho + CABECALHO_EM,
            core::mem::size_of::<Cabecalho>() as u32,
            false,
        );

        let pagina = crate::arch::TAMANHO_PAGINA as usize;
        let mut restante = destino.len();
        let mut indice = 0;
        while restante > 0 {
            let quanto = restante.min(pagina);
            cadeia[partes] = (self.dados[indice], quanto as u32, true);
            partes += 1;
            restante -= quanto;
            indice += 1;
        }

        cadeia[partes] = (self.trabalho + ESTADO_EM, 1, true);
        partes += 1;

        let cabeca = self.fila.submeter(&cadeia[..partes])?;
        self.fila.notificar(&self.transporte);

        let (respondido, _) = self.esperar()?;
        if respondido != cabeca {
            // O anel deixou de descrever a realidade. Nao ha como voltar disso
            // sem reiniciar o dispositivo, e insistir leria buffers que nao
            // sabemos de quem sao.
            self.vivo = false;
            return Err("dispositivo respondeu uma cadeia que nao pedimos");
        }

        // SAFETY: o dispositivo terminou (foi o que a colheita significou), e
        // o acesso fica dentro do frame pela constante de layout.
        let estado = unsafe { core::ptr::read_volatile(self.base.add(ESTADO_EM as usize)) };
        if estado != OK {
            return Err("o dispositivo recusou a leitura");
        }

        // E o conteúdo, página a página, para onde quem chamou pediu.
        let mut copiados = 0;
        for origem in &self.bases_de_dados {
            if copiados == destino.len() {
                break;
            }
            let quanto = (destino.len() - copiados).min(pagina);
            // SAFETY: a origem é uma das páginas de dados, que o
            // dispositivo acabou de preencher com pelo menos `quanto` bytes; o
            // destino tem espaço porque `copiados + quanto` é no máximo o
            // comprimento dele; e as duas regiões não se sobrepõem — as
            // páginas são do kernel e `destino` é de quem chamou.
            unsafe {
                core::ptr::copy_nonoverlapping(*origem, destino.as_mut_ptr().add(copiados), quanto);
            }
            copiados += quanto;
        }

        Ok(())
    }

    fn esperar(&mut self) -> Result<(u16, u32), &'static str> {
        for _ in 0..VOLTAS_DE_ESPERA {
            if let Some(resposta) = self.fila.colher() {
                return Ok(resposta);
            }
            core::hint::spin_loop();
        }

        self.vivo = false;
        crate::log_error!(
            "virtio",
            "o disco nao respondeu em {} voltas; desligado",
            VOLTAS_DE_ESPERA
        );
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
        // "virtio", e não "disco": a máquina pode muito bem ter um, e o
        // relatório do agente mostra que às vezes tem. Sem o disco virtio o
        // `pci.list` de uma máquina x86 comum ainda traz um controlador IDE
        // com `role: "disco-ide"`, e as duas linhas se contradiziam — uma
        // dizendo que não há disco, a outra mostrando um.
        //
        // O que falta é um dispositivo que **este driver** saiba dirigir, e a
        // mensagem passa a dizer isso.
        crate::log_info!("virtio", "nenhum disco virtio no barramento");
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

/// Destrava a tranca do disco à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { DISCO.force_unlock() };
}
