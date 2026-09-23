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

pub mod blk;
pub mod fila;
pub mod net;
pub mod transporte;

// ---------------------------------------------------------------------------
// Interrupções
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Quantos dispositivos virtio podem pedir para ser avisados.
///
/// Dois hoje — disco e rede —, e o teto existe para que a tabela seja um
/// `static` de tamanho fixo em vez de depender do heap. Um handler de
/// interrupção não é lugar de alocar.
const MAX_REGISTROS: usize = 4;

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

fn nome_de(codigo: u32) -> &'static str {
    match codigo {
        NOME_DISCO => "disco",
        NOME_REDE => "rede",
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
/// Os dois drivers fazem exatamente isto, e a ordem importa — registrar
/// **antes** de liberar. Uma linha liberada sem dono registrado entrega uma
/// interrupção que ninguém reconhece no dispositivo, e uma linha de nível que
/// ninguém reconhece dispara de novo imediatamente, para sempre.
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
        // quem a reconheça, e a linha é de **nível**: o dispositivo segue
        // segurando o sinal e o controlador entrega de novo, imediatamente.
        // O kernel para de progredir sem uma linha de log.
        //
        // As duas escritas abaixo podem ser `Relaxed`: quem as ordena é a
        // publicação da linha, que é `Release`, e o handler lê a linha com
        // `Acquire`. É o par que torna a ordem observável do outro lado.
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
/// Uma interrupção de PCI por linha é **de nível**: o dispositivo mantém o
/// sinal ativo até ser atendido, e não manda um pulso. Reconhecê-la no
/// controlador não basta — enquanto o dispositivo mantiver a linha baixa, o
/// controlador entrega outra, e outra, para sempre. O sistema não trava com
/// uma mensagem de erro; ele para de progredir porque nunca sai do handler.
///
/// A leitura do registrador de estado é o que faz o dispositivo soltar a
/// linha, e ela **limpa o registrador ao ser lida** — é o mecanismo, não um
/// efeito colateral.
///
/// # Por que todos os registros, e não o primeiro que combinar
///
/// Porque uma linha de PCI é compartilhada por construção: quatro pinos para
/// quantos dispositivos a placa tiver. Dois dispositivos na mesma linha que
/// interrompam juntos produzem uma única entrega, e atender só um deixaria o
/// outro segurando o sinal.
pub fn atender_interrupcao(linha: u32) {
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
        }
    }
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
