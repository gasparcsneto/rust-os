//! Dispositivos virtio.
//!
//! # O que virtio resolve
//!
//! Um driver de disco SATA existe para falar com um controlador SATA, que é
//! uma peça de silício com décadas de compatibilidade retroativa dentro. Numa
//! máquina virtual, do outro lado desse controlador não há silício nenhum —
//! há um programa emulando uma peça de silício para que o driver reconheça o
//! que espera. É trabalho dobrado: o hóspede finge que há hardware, o
//! hospedeiro finge que é hardware.
//!
//! O virtio corta os dois fingimentos. É uma interface desenhada para o caso
//! em que os dois lados são software e sabem disso: em vez de registradores
//! que imitam um chip, um anel de descritores em memória compartilhada, e uma
//! escrita num endereço para avisar que há trabalho.
//!
//! # Moderno, e não legado
//!
//! Um dispositivo virtio do QEMU costuma ser *transicional*: responde tanto à
//! interface legada quanto à moderna (a de virtio 1.0). As duas funcionam, e a
//! escolha aqui não é sobre elegância.
//!
//! A interface legada vive numa região de **I/O**. No x86 isso é o par de
//! instruções `in`/`out`, que a arquitetura tem. No ARM não existe I/O como
//! espaço separado: a janela de I/O do barramento PCI é uma faixa de memória
//! que a ponte traduz, e alcançá-la significaria um segundo mecanismo de
//! acesso, só para o ARM, para chegar aos mesmos registradores.
//!
//! A interface moderna vive em memória mapeada, que funciona igual nas duas.
//! Um caminho só, testado nas duas arquiteturas pelo mesmo código — que é
//! exatamente o critério que este kernel usa em todo lugar.
//!
//! # O que está aqui
//!
//! - [`transporte`]: como achar os registradores do dispositivo e como fazer o
//!   aperto de mão que o liga.
//! - [`fila`]: a virtqueue, que é o canal por onde os pedidos passam.
//! - [`blk`]: o disco.
//! - [`net`]: a placa de rede.
//! - [`teclado`]: o teclado do ARM, por `virtio-input`.
//! - [`gpu`]: o adaptador de vídeo, que só mostra o que se manda mostrar.
//! - [`console`]: o canal local dos agentes, uma porta por agente.

pub mod blk;
pub mod console;
pub mod fila;
pub mod gpu;
pub mod net;
pub mod teclado;
pub mod transporte;

// ---------------------------------------------------------------------------
// Interrupções
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Quantos dispositivos virtio podem pedir para ser avisados.
///
/// Quatro hoje — disco, rede, teclado e vídeo —, e o teto existe para que a
/// tabela seja um `static` de tamanho fixo em vez de depender do heap. Oito
/// deixa folga: com quatro, o vídeo teria sido o último a caber. Um handler de
/// interrupção não é lugar de alocar.
const MAX_REGISTROS: usize = 8;

/// Nenhuma linha. `u32::MAX` porque zero é uma linha válida no PIC.
const SEM_LINHA: u32 = u32::MAX;

/// Vaga tomada, mas ainda sem os dados dela.
///
/// Existe porque `linha` faz dois papéis — é a ficha que reserva a vaga e é a
/// chave pela qual o handler reconhece o dono — e os dois querem coisas
/// opostas: a ficha precisa ser escrita **antes** do resto, a chave precisa
/// ser escrita **depois**. Um valor intermediário separa os dois momentos.
///
/// Nenhuma linha real vale isto, então o handler o descarta pela mesma
/// comparação que já fazia, sem uma condição a mais.
const RESERVADO: u32 = u32::MAX - 1;

/// O que o handler precisa saber sobre um dispositivo.
///
/// # Por que isto fica fora da tranca do driver
///
/// Porque um handler de interrupção não pode esperar por um spinlock. Ele
/// roda no meio do que estiver executando, e se esse código já segurasse a
/// tranca do driver, o handler giraria para sempre esperando por alguém que
/// só continua quando ele terminar — o deadlock clássico.
///
/// Hoje o kernel tem um núcleo só e o acesso ao driver mascara interrupções,
/// então a situação não ocorre. Depender disso seria depender de duas coisas
/// que mudam: o número de núcleos e a disciplina de quem escrever o próximo
/// driver.
///
/// O que o handler faz com atômicos é tudo o que ele precisa: reconhecer a
/// interrupção no dispositivo e contá-la.
struct Registro {
    /// Em que linha do controlador este dispositivo interrompe.
    linha: AtomicU32,
    /// Endereço virtual do registrador de estado de interrupção do
    /// dispositivo, ou zero se ele não publicou um.
    isr: AtomicU64,
    /// Quantas vezes este dispositivo interrompeu.
    ///
    /// **Este**, e não "a linha dele". A distinção nasceu de olhar o
    /// relatório: no x86 o disco e a rede caem os dois na IRQ 11, e uma versão
    /// anterior contava uma entrega para os dois, sempre. O número existia,
    /// era plausível, e não respondia a pergunta que o nome dele fazia.
    avisos: AtomicU64,
    /// Um nome para o relatório do agente.
    nome: AtomicU32,
}

/// Os nomes possíveis, como números, porque um `&'static str` não cabe num
/// atômico. São dois, e a tabela é a tradução.
const NOME_NENHUM: u32 = 0;
const NOME_DISCO: u32 = 1;
const NOME_REDE: u32 = 2;
const NOME_TECLADO: u32 = 3;
const NOME_VIDEO: u32 = 4;
const NOME_CONSOLE: u32 = 5;

fn nome_de(codigo: u32) -> &'static str {
    match codigo {
        NOME_DISCO => "disco",
        NOME_REDE => "rede",
        NOME_TECLADO => "teclado",
        NOME_VIDEO => "video",
        NOME_CONSOLE => "console",
        _ => "?",
    }
}

impl Registro {
    /// A linha deste registro, se ele já está publicado.
    ///
    /// Há dois jeitos de não haver o que ler numa vaga — livre
    /// ([`SEM_LINHA`]) ou tomada com o conteúdo ainda por escrever
    /// ([`RESERVADO`]) —, e quem lê não deveria precisar saber que são dois.
    /// Sem isto, cada leitor repetiria a distinção e algum a esqueceria: o
    /// relatório do agente esqueceu, e mostraria a vaga em transição como um
    /// dispositivo sem nome numa linha de quatro bilhões.
    fn linha_publicada(&self) -> Option<u32> {
        match self.linha.load(Ordering::Acquire) {
            SEM_LINHA | RESERVADO => None,
            linha => Some(linha),
        }
    }
}

#[allow(clippy::declare_interior_mutable_const)]
const REGISTRO_VAZIO: Registro = Registro {
    linha: AtomicU32::new(SEM_LINHA),
    isr: AtomicU64::new(0),
    avisos: AtomicU64::new(0),
    nome: AtomicU32::new(NOME_NENHUM),
};

static REGISTROS: [Registro; MAX_REGISTROS] = [REGISTRO_VAZIO; MAX_REGISTROS];

/// Liga a interrupção de um dispositivo: registra o dono e libera a linha.
///
/// Os drivers fazem exatamente isto, e a ordem importa — registrar **antes**
/// de liberar. Uma linha liberada sem dono registrado entrega uma
/// interrupção que ninguém reconhece no dispositivo, e uma linha que ninguém
/// reconhece ou dispara de novo para sempre, ou nunca mais — conforme o
/// controlador a receba por nível ou por borda; ver [`atender_interrupcao`].
///
/// # E antes do `DRIVER_OK`, não só antes de liberar a linha
///
/// "Registrar antes de liberar a linha" só protege o **primeiro** dono dela.
/// Numa linha compartilhada, o segundo chega com ela já liberada pelo
/// primeiro, e o que o protege é outra ordem: registrar-se antes de o
/// dispositivo poder interromper — antes de [`transporte::Transporte::liberar`].
/// Depois dele o dispositivo trabalha, e uma interrupção sua que chegue antes
/// do registro encontra só o outro dono: o registrador do recém-chegado fica
/// sem ler, e ele segue segurando a linha.
///
/// Os drivers registravam depois do `DRIVER_OK`, e o defeito dormiu enquanto
/// nenhum segundo dono interrompia cedo. O `virtio-console` interrompe, e as
/// duas formas apareceram, medidas:
///
/// - no ARM com teclado USB, console e disco caem no INTID 36. O GIC recebe
///   por nível: o registrador de pendentes e o de ativos mostravam o 36 nos
///   dois ao mesmo tempo, e o processador não saía do handler — o kernel
///   nunca terminou de subir, e a fumaça só viu o canal mudo;
/// - no x86 com vídeo virtio, os dois caem na linha 10, e o PIC recebe por
///   borda: a linha foi entregue uma vez, nenhum dos dois foi creditado, e
///   nunca mais.
///
/// Registrar antes de o dispositivo existir para o barramento não custa
/// nada: ler o registrador de estado de quem ainda não trabalha dá zero.
///
/// Só a ordem do console tem quem a proteja — medido: devolvê-la para depois
/// do `DRIVER_OK` derruba os dois casos de `irq` no x86 com vídeo virtio e a
/// fumaça do ARM com teclado USB. Nos outros drivers a inversão passa (na
/// rede, medido), porque nenhum deles interrompe antes de receber trabalho.
/// A ordem é a mesma nos cinco para que o próximo driver copie a certa.
///
/// Nada disto é obrigatório para o driver funcionar: os dois esperam em laço
/// e leem o anel de usados, que não depende de interrupção nenhuma. Falhar
/// aqui custa a visibilidade, não o disco nem a rede — e é por isso que o
/// retorno é um log, e não um erro que aborta a construção.
fn ligar_interrupcao(d: &crate::pci::Dispositivo, transporte: &transporte::Transporte, nome: u32) {
    let Some(linha) = d.interrupcao else {
        crate::log_info!(
            "virtio",
            "{} em {:02x}.{} nao tem linha de interrupcao; segue por consulta",
            nome_de(nome),
            d.dispositivo,
            d.funcao
        );
        return;
    };

    if !registrar(linha, transporte.endereco_do_isr(), nome) {
        crate::log_warn!(
            "virtio",
            "tabela de interrupcoes cheia; {} fica de fora",
            nome_de(nome)
        );
        return;
    }

    // A linha recebe um nome genérico, e não o do dispositivo. Dois
    // dispositivos na mesma linha se sobrescreveriam, e o relatório mostraria
    // a IRQ 11 chamada de "rede" só porque a rede foi registrada por último.
    // Qual dos dois interrompeu está nos contadores por dispositivo, que é
    // onde a pergunta tem resposta.
    crate::irq::nomear(linha as usize, "virtio-pci");

    // SAFETY: o registro acima garante que há quem reconheça a interrupção no
    // dispositivo, que é a pré-condição de liberar a linha.
    unsafe { crate::arch::pci::habilitar_interrupcao(linha) };

    crate::log_info!(
        "virtio",
        "{} interrompe na linha {} (pino {})",
        nome_de(nome),
        linha,
        d.pino
    );
}

/// Pede para ser avisado quando `linha` disparar.
///
/// `isr` é o endereço virtual do registrador de estado de interrupção do
/// dispositivo. Ele importa mais do que parece: ver [`atender_interrupcao`].
///
/// Devolve `false` se a tabela estiver cheia — caso em que o driver continua
/// funcionando, só que sem ser avisado.
fn registrar(linha: u32, isr: Option<u64>, nome: u32) -> bool {
    for registro in &REGISTROS {
        if registro
            .linha
            .compare_exchange(SEM_LINHA, RESERVADO, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }

        // O conteúdo primeiro, a chave por último.
        //
        // A versão anterior escrevia a linha na própria troca e só depois o
        // endereço do ISR. Entre uma coisa e outra o registro anunciava ser o
        // dono da linha carregando um ISR zerado — e [`atender_interrupcao`]
        // descarta um registro assim, porque zero quer dizer "este
        // dispositivo não publicou registrador de estado".
        //
        // A janela é de duas instruções, e seria inofensiva se a linha ainda
        // estivesse mascarada. Não está, e é o caso que este arquivo mais
        // documenta que a abre: numa linha **compartilhada**, quem registra
        // por último chega quando o primeiro já liberou a linha no
        // controlador. No x86 é exatamente isso — disco e rede caem os dois
        // na IRQ 11, e a rede se registra depois.
        //
        // Uma interrupção nessa janela é entregue, o handler não encontra
        // quem a reconheça, e o dispositivo segue segurando o sinal. Num
        // controlador que recebe a linha por nível ele entrega de novo,
        // imediatamente, e o kernel para de progredir sem uma linha de log;
        // num que a recebe por borda, como o PIC do x86, a linha emudece —
        // ver [`atender_interrupcao`].
        //
        // As duas escritas abaixo podem ser `Relaxed`: quem as ordena é a
        // publicação da linha, que é `Release`, e o handler lê a linha com
        // `Acquire`. É o par que torna a ordem observável do outro lado.
        //
        // # Nenhum teste protege esta ordem, e isso foi medido
        //
        // Invertendo os dois passos de volta — publicar a linha na própria
        // troca e escrever o ISR depois —, a suíte inteira passa. Não é falha
        // dos casos: a janela dura duas instruções, e para atravessá-la seria
        // preciso uma interrupção caindo exatamente entre elas, o que nenhum
        // caso consegue provocar. O que se conseguiu foi uma sonda dentro da
        // janela, que mostrou o estado publicado — `linha = 11, isr = 0` — e
        // essa sonda não é um teste, é uma medição que se faz uma vez.
        //
        // É a segunda garantia deste diretório nessa condição; a outra é a
        // barreira de memória de `fila.rs`, e pelo mesmo tipo de razão. As
        // duas estão escritas onde quem for mexer vai ler, porque é a única
        // defesa que sobra quando a suíte não é uma.
        registro.isr.store(isr.unwrap_or(0), Ordering::Relaxed);
        registro.nome.store(nome, Ordering::Relaxed);
        registro.linha.store(linha, Ordering::Release);
        return true;
    }
    false
}

/// Atende uma interrupção que não é de nenhum periférico da placa.
///
/// # Por que ler o registrador de estado é obrigatório
///
/// O dispositivo mantém o sinal ativo até ser atendido, e não manda um
/// pulso. A leitura do registrador de estado é o que faz o dispositivo
/// soltar a linha, e ela **limpa o registrador ao ser lida** — é o
/// mecanismo, não um efeito colateral.
///
/// O que acontece quando ninguém lê depende de como o controlador recebe a
/// linha. **Por nível**, ele entrega de novo, e de novo, para sempre — o
/// sistema para de progredir sem uma linha de log. **Por borda**, o defeito
/// é o avesso, e mais quieto: a linha fica alta, não há borda nova, e nada
/// mais chega por ela.
///
/// O PIC do x86 recebe estas linhas por borda: o registrador que escolheria
/// nível para elas (o ELCR, nas portas `0x4D0` e `0x4D1`) está zerado quando
/// o kernel chega — medido, lido de dentro de um caso da suíte.
///
/// # Por que todos os registros, e não o primeiro que combinar
///
/// Porque uma linha de PCI é compartilhada por construção: quatro pinos para
/// quantos dispositivos a placa tiver. Dois dispositivos na mesma linha que
/// interrompam juntos produzem uma única entrega, e atender só um deixaria o
/// outro segurando o sinal.
///
/// # Por que repetir até uma volta quieta
///
/// Por causa da borda. Com os donos `A` e `B` lidos nessa ordem, `A` pode
/// interromper logo depois de ser lido, enquanto `B` ainda segura a linha:
/// ela não desce, e a interrupção de `A` não faz borda. Ler `B` em seguida
/// não resolve — `A` continua segurando, e ninguém volta a ler `A`.
///
/// Uma volta em que **todos** leem zero fecha a janela: nela ninguém segurava
/// a linha na hora de ser lido, e só a leitura faz um dispositivo soltá-la.
/// Então quem interromper depois dessa leitura sobe uma linha que estava
/// baixa, e isso é uma borda — outra entrega, e outra passagem por aqui.
///
/// O teto de voltas existe para um dispositivo que interrompa sem parar não
/// prender o processador no handler. Atingi-lo pode perder uma entrega;
/// ficar aqui para sempre perderia todas.
///
/// Nenhum teste protege as voltas, e isso foi medido: com uma volta só, a
/// suíte inteira passa, também no x86 com vídeo virtio, onde a linha é
/// dividida. A janela é a de um dispositivo interromper entre duas leituras
/// do mesmo handler, e nenhum caso consegue pô-lo lá.
pub fn atender_interrupcao(linha: u32) {
    for _ in 0..MAX_VOLTAS_NO_HANDLER {
        if !uma_volta(linha) {
            return;
        }
    }
}

/// Quantas voltas [`atender_interrupcao`] dá, no máximo, numa entrega.
const MAX_VOLTAS_NO_HANDLER: usize = 16;

/// Lê o registrador de estado de todos os donos de `linha`. Verdadeiro se
/// algum deles tinha interrompido.
fn uma_volta(linha: u32) -> bool {
    let mut alguem = false;
    for registro in &REGISTROS {
        if registro.linha_publicada() != Some(linha) {
            continue;
        }

        let isr = registro.isr.load(Ordering::Acquire);
        if isr == 0 {
            // Sem registrador de estado não há como saber se foi ele, nem como
            // fazê-lo soltar a linha. Contar seria inventar.
            continue;
        }

        // SAFETY: o endereço foi registrado por um driver a partir de uma
        // região que `mmio::mapear` mapeou como memória de dispositivo, e
        // continua mapeada porque nada neste kernel desmapeia MMIO.
        let estado = unsafe { core::ptr::read_volatile(isr as *const u8) };

        // A leitura precisa acontecer para **todos** os registros da linha,
        // seja qual for o resultado: é ela que faz cada dispositivo soltar o
        // sinal. Só a contagem depende do que veio — zero quer dizer "não fui
        // eu", e é a resposta esperada do outro dispositivo da linha.
        if estado != 0 {
            registro.avisos.fetch_add(1, Ordering::Relaxed);
            alguem = true;
        }
    }
    alguem
}

/// Quantas interrupções os dispositivos virtio já receberam, ao todo.
///
/// Só a suíte pergunta isto. O canal do agente lê os contadores por
/// dispositivo, via [`com_interrupcoes`], que é a resposta útil quando dois
/// deles dividem a mesma linha; o total só serve para o teste detectar que
/// *alguma* chegou.
#[cfg(feature = "modo-teste")]
pub fn total_de_avisos() -> u64 {
    REGISTROS
        .iter()
        .map(|registro| registro.avisos.load(Ordering::Relaxed))
        .sum()
}

/// Quantas interrupções um dispositivo recebeu, pelo nome.
#[cfg(feature = "modo-teste")]
pub fn avisos_de(nome: &str) -> Option<u64> {
    REGISTROS
        .iter()
        .find(|registro| {
            registro.linha_publicada().is_some()
                && nome_de(registro.nome.load(Ordering::Acquire)) == nome
        })
        .map(|registro| registro.avisos.load(Ordering::Relaxed))
}

/// Percorre os dispositivos registrados: nome, linha e quantos avisos.
pub fn com_interrupcoes<F: FnMut(&'static str, u32, u64)>(mut f: F) {
    for registro in &REGISTROS {
        let Some(linha) = registro.linha_publicada() else {
            continue;
        };
        f(
            nome_de(registro.nome.load(Ordering::Acquire)),
            linha,
            registro.avisos.load(Ordering::Relaxed),
        );
    }
}
