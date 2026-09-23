//! A placa de rede.
//!
//! # Duas filas, e por que isso muda tudo
//!
//! O disco tem uma fila e um padrão simples: pede-se, espera-se, chega. A
//! rede tem duas, e a de **recepção** funciona ao contrário de tudo o que
//! veio antes.
//!
//! Num disco, o kernel sabe quando quer dados. Numa rede, não: o pacote chega
//! quando o outro lado resolve mandar. Não há como "pedir" um pacote. O que
//! se faz é o oposto — entregar ao dispositivo buffers **vazios**, de
//! antemão, e deixar que ele os preencha quando algo chegar.
//!
//! É isso que obrigou a fila a ganhar um alocador de descritores. Com um
//! pedido de cada vez, a cadeia podia sempre começar na posição zero; com
//! vários buffers de recepção pendurados ao mesmo tempo, cada um precisa da
//! sua, e alguém precisa saber quais estão em uso.
//!
//! # O cabeçalho que não é do pacote
//!
//! Todo quadro, nos dois sentidos, é precedido de um cabeçalho do virtio —
//! não do Ethernet. Ele descreve o que o dispositivo pode fazer pelo driver:
//! calcular somas de verificação, segmentar um bloco grande em vários
//! pacotes. Este driver não pede nada disso, então o cabeçalho que ele
//! escreve é todo zeros. Mas ele **tem que estar lá**: o dispositivo lê
//! aqueles bytes antes de chegar ao quadro, e sem eles o primeiro byte do
//! endereço de destino seria interpretado como um campo de opções.
//!
//! # O que este driver não faz
//!
//! Não há pilha de rede. Não há IP, não há TCP, não há sequer uma tabela ARP.
//! O que existe é o transporte de quadros: entregar um, receber os que
//! chegarem. É a camada sobre a qual uma pilha se constrói, e separá-la é o
//! que permite testá-la sem ter uma.

use spin::Mutex;

use super::fila::Fila;
use super::transporte::{FABRICANTE, Mmio, Transporte, VERSAO_1};
use crate::pci::Dispositivo;

/// Os modelos de placa de rede do virtio: o transicional e o moderno.
const MODELO_TRANSICIONAL: u16 = 0x1000;
const MODELO_MODERNO: u16 = 0x1041;

/// A fila por onde os pacotes chegam.
const FILA_DE_RECEPCAO: u16 = 0;
/// A fila por onde os pacotes saem.
const FILA_DE_TRANSMISSAO: u16 = 1;

/// O dispositivo publica o endereço MAC dele na configuração.
///
/// Sem este recurso o endereço teria de ser inventado pelo driver, e dois
/// hóspedes que inventassem o mesmo colidiriam na mesma rede. Pedimos porque
/// o QEMU oferece; se não oferecesse, seguiríamos sem — o transporte de
/// quadros não depende de saber o próprio endereço.
const RECURSO_MAC: u64 = 1 << 5;

/// Quanto mede o endereço de uma placa Ethernet.
pub const TAMANHO_DO_MAC: usize = 6;

/// Quanto mede o cabeçalho do virtio-net na versão 1.0.
///
/// Doze bytes, e o último campo (`num_buffers`) só existe a partir dela — no
/// legado eram dez. É mais uma razão para este kernel só falar a interface
/// moderna: o tamanho do cabeçalho deixa de depender de quais recursos foram
/// negociados.
const CABECALHO: usize = 12;

/// O maior quadro que este driver transporta.
///
/// 1514 é o Ethernet clássico: 14 de cabeçalho e 1500 de carga. Não há jumbo
/// frames aqui, e não há fragmentação — um pacote maior que isto seria
/// recusado na transmissão e truncado na recepção, e as duas coisas são
/// visíveis em vez de silenciosas.
pub const MAIOR_QUADRO: usize = 1514;

/// Quanto cada buffer ocupa: o cabeçalho do virtio mais o quadro.
const BUFFER: usize = CABECALHO + MAIOR_QUADRO;

/// Quantos buffers de recepção ficam pendurados no dispositivo.
///
/// # Por que quatro, e por que um frame cada
///
/// Quatro porque o número só precisa cobrir a rajada que chega entre duas
/// colheitas, e este driver é consultado pelo canal do agente, não por uma
/// pilha de rede — as colheitas são frequentes e as rajadas, curtas.
///
/// Um frame inteiro para cada, gastando 1526 bytes dos 4096, porque o frame é
/// a unidade que o alocador entrega e a única que garante contiguidade
/// física. A primeira versão disto tentou empacotar os quatro num frame só, e
/// a asserção de compilação logo abaixo recusou a compilar: quatro buffers de
/// 1526 bytes são 6104. Desperdiçar dez KiB de RAM numa máquina com centenas
/// de MiB é mais barato que um cálculo de deslocamento que precisa estar
/// certo.
///
/// Um buffer por cadeia, e não cabeçalho e quadro em descritores separados: o
/// dispositivo aceita os dois no mesmo, e uma cadeia de um descritor é uma a
/// menos para alocar por pacote.
pub const BUFFERS_DE_RECEPCAO: usize = 4;

/// Onde o endereço MAC está, na configuração específica do dispositivo.
const CONFIG_MAC: u64 = 0;

/// Uma placa de rede virtio pronta para uso.
pub struct Placa {
    transporte: Transporte,
    recepcao: Fila,
    transmissao: Fila,
    /// Um frame por buffer de recepção, e por onde o kernel enxerga cada um.
    frames_de_recepcao: [u64; BUFFERS_DE_RECEPCAO],
    bases_de_recepcao: [*mut u8; BUFFERS_DE_RECEPCAO],
    /// Frame com o buffer de transmissão. Um só: este driver transmite um
    /// quadro por vez e espera por ele, como o disco faz.
    frame_de_transmissao: u64,
    base_de_transmissao: *mut u8,
    /// O endereço desta placa, se o dispositivo o publicou.
    mac: Option<[u8; TAMANHO_DO_MAC]>,
    /// Quantos quadros saíram e quantos entraram, para o relatório do agente.
    transmitidos: u64,
    recebidos: u64,
    /// Se a placa ainda pode ser usada.
    ///
    /// Pelo mesmo motivo do disco, e o motivo vale repetir porque o buffer de
    /// transmissão é um só: uma transmissão que estourou o tempo continua
    /// pendente no dispositivo, que ainda pode estar **lendo** aquele buffer.
    /// Reescrevê-lo para o quadro seguinte é uma corrida de DMA.
    ///
    /// A recepção sobreviveria — os buffers dela são outros —, mas separar as
    /// duas metades significaria dois estados onde um basta, para manter viva
    /// metade de uma placa cuja outra metade parou de responder.
    vivo: bool,
}

// SAFETY: os dois ponteiros são para frames de propriedade exclusiva desta
// placa, alocados na construção e nunca compartilhados.
unsafe impl Send for Placa {}

/// Que um buffer caiba num frame é premissa, não sorte.
const _: () = assert!(
    BUFFER as u64 <= crate::arch::TAMANHO_PAGINA,
    "um buffer de rede nao cabe num frame"
);

/// A placa da máquina, se houver uma.
static PLACA: Mutex<Option<Placa>> = Mutex::new(None);

impl Placa {
    /// Liga uma placa de rede encontrada no barramento.
    fn ligar(d: &Dispositivo) -> Result<Placa, &'static str> {
        let transporte = Transporte::descobrir(d)?;

        // O MAC é pedido, não exigido. Se o dispositivo não o oferecer, o
        // transporte de quadros continua funcionando — só não sabemos dizer
        // qual é o nosso endereço, e quem montar um quadro terá de escolher
        // um.
        let aceitos = transporte.iniciar(VERSAO_1 | RECURSO_MAC)?;

        if transporte.filas() < 2 {
            transporte.abortar();
            return Err("placa de rede sem as duas filas");
        }

        let mac = (aceitos & RECURSO_MAC != 0)
            .then(|| transporte.configuracao().and_then(ler_mac))
            .flatten();

        let recepcao = match Fila::nova(&transporte, FILA_DE_RECEPCAO) {
            Ok(fila) => fila,
            Err(motivo) => {
                transporte.abortar();
                return Err(motivo);
            }
        };
        let transmissao = match Fila::nova(&transporte, FILA_DE_TRANSMISSAO) {
            Ok(fila) => fila,
            Err(motivo) => {
                transporte.abortar();
                return Err(motivo);
            }
        };

        // Os frames são pedidos de uma vez, e a falha no meio devolve os que
        // já vieram. Sem isso, uma máquina sem memória deixaria frames presos
        // a um driver que não existe.
        let mut frames_de_recepcao = [0u64; BUFFERS_DE_RECEPCAO];
        let mut quantos = 0;
        while quantos < BUFFERS_DE_RECEPCAO {
            match crate::frames::alocar() {
                Some(frame) => {
                    frames_de_recepcao[quantos] = frame;
                    quantos += 1;
                }
                None => break,
            }
        }

        let frame_de_transmissao = crate::frames::alocar();

        let (true, Some(frame_de_transmissao)) =
            (quantos == BUFFERS_DE_RECEPCAO, frame_de_transmissao)
        else {
            for frame in &frames_de_recepcao[..quantos] {
                crate::frames::liberar(*frame);
            }
            // O de transmissão também, quando veio. Hoje ele não vem sem os
            // outros virem — o alocador só falha quando esgota, e nada devolve
            // frames entre os dois pedidos —, mas o comentário acima promete
            // que a falha no meio devolve o que já veio, e uma promessa que
            // depende do comportamento de outro módulo é uma promessa que
            // alguém vai quebrar sem perceber.
            if let Some(frame) = frame_de_transmissao {
                crate::frames::liberar(frame);
            }

            // As duas filas ficam com os frames delas, e de propósito — a
            // mesma razão que o disco documenta. Elas já foram habilitadas no
            // dispositivo, que portanto tem o direito de varrê-las; devolvê-las
            // ao alocador seria entregar a outro dono uma página que o
            // dispositivo pode ler a qualquer momento.
            //
            // `abortar` o marca como falho, o que o obriga a parar, mas os
            // frames não voltam mesmo assim: não dependemos de o dispositivo
            // respeitar o estado. Dois frames vazados num caminho de boot que
            // roda uma vez é o preço.
            transporte.abortar();
            return Err("sem frames para os buffers de rede");
        };

        let mut bases_de_recepcao = [core::ptr::null_mut(); BUFFERS_DE_RECEPCAO];
        for (base, frame) in bases_de_recepcao.iter_mut().zip(&frames_de_recepcao) {
            *base = crate::arch::acesso_fisico(*frame);
        }

        let mut placa = Placa {
            transporte,
            recepcao,
            transmissao,
            frames_de_recepcao,
            bases_de_recepcao,
            frame_de_transmissao,
            base_de_transmissao: crate::arch::acesso_fisico(frame_de_transmissao),
            mac,
            transmitidos: 0,
            recebidos: 0,
            vivo: true,
        };

        // Antes de liberar o dispositivo, e não depois: a partir do
        // `DRIVER_OK` ele pode começar a entregar pacotes, e precisa ter onde
        // pô-los. Pendurar os buffers depois seria descartar tudo o que
        // chegasse na janela entre as duas coisas.
        crate::pci::habilitar_mestre(d);
        placa.pendurar_buffers();
        placa.transporte.liberar();
        placa.recepcao.notificar(&placa.transporte);

        super::ligar_interrupcao(d, &placa.transporte, super::NOME_REDE);

        Ok(placa)
    }

    /// Este buffer está agora com o dispositivo?
    ///
    /// A resposta sai da tabela de descritores: um descritor **em uso** que
    /// aponta para o frame deste buffer é o dispositivo tendo-o em mãos. É a
    /// mesma escolha de [`Placa::indice_do_buffer`], e pelo mesmo motivo —
    /// duas cópias da mesma informação são duas coisas que podem divergir, e
    /// aqui a cópia paralela teria de ser mantida certa em todo caminho de
    /// erro, inclusive nos que desligam a placa.
    fn ja_pendurado(&self, indice: usize) -> bool {
        let frame = self.frames_de_recepcao[indice];
        (0..super::fila::DESCRITORES).any(|posicao| {
            self.recepcao.em_uso(posicao)
                && self.recepcao.endereco_do_descritor(posicao) == Some(frame)
        })
    }

    /// Entrega ao dispositivo os buffers de recepção que ainda não estão com
    /// ele.
    ///
    /// Chamada na construção e depois de cada colheita.
    ///
    /// # O que `ja_pendurado` conserta
    ///
    /// Esta função se dizia idempotente e não era. Ela percorria os quatro
    /// índices e pendurava cada um enquanto houvesse descritor livre, sem
    /// nenhuma forma de saber quais já estavam com o dispositivo.
    ///
    /// O efeito era o mesmo buffer entregue duas vezes ao mesmo tempo. Duas
    /// cadeias apontando para a mesma memória: o dispositivo escreve um pacote
    /// em cada uma, o segundo por cima do primeiro, e as duas colheitas
    /// devolvem o mesmo conteúdo. Um pacote perdido e um duplicado, os dois
    /// em silêncio.
    ///
    /// E o desperdício era mensurável. Com quatro buffers e oito descritores,
    /// os livres caíam de quatro para **um** na primeira colheita e para
    /// **zero** na segunda; daí em diante cada descritor que uma colheita
    /// liberava era gasto numa duplicata do buffer zero. A fila de recepção
    /// de quatro pacotes que este driver anuncia deixava de existir a partir
    /// do segundo pacote.
    ///
    /// O estado estável agora é o pretendido: quatro descritores em uso, um
    /// por buffer, e quatro livres.
    fn pendurar_buffers(&mut self) {
        for indice in 0..BUFFERS_DE_RECEPCAO {
            if self.ja_pendurado(indice) {
                continue;
            }
            if self.recepcao.disponiveis() == 0 {
                break;
            }

            let onde = self.frames_de_recepcao[indice];

            // `true`: é o dispositivo quem escreve. É a diferença entre um
            // buffer de recepção e um de transmissão, e o dispositivo a
            // respeita — um buffer marcado como somente leitura nunca
            // receberia pacote nenhum.
            match self.recepcao.submeter(&[(onde, BUFFER as u32, true)]) {
                Ok(_) => {}
                // Sem descritores livres não é erro: quer dizer que os buffers
                // que já estão pendurados dão conta. Os outros voltam quando
                // uma colheita os liberar.
                Err(_) => break,
            }
        }
    }

    /// O endereço desta placa.
    pub fn mac(&self) -> Option<[u8; TAMANHO_DO_MAC]> {
        self.mac
    }

    /// Quantos quadros saíram e quantos entraram.
    pub fn contadores(&self) -> (u64, u64) {
        (self.transmitidos, self.recebidos)
    }

    /// Transmite um quadro Ethernet.
    ///
    /// `quadro` é o quadro inteiro, a partir do endereço de destino — o
    /// cabeçalho do virtio é montado aqui, e quem chama não precisa saber que
    /// ele existe.
    pub fn transmitir(&mut self, quadro: &[u8]) -> Result<(), &'static str> {
        if !self.vivo {
            return Err("a placa parou de responder e foi desligada");
        }
        if quadro.is_empty() {
            return Err("quadro vazio");
        }
        if quadro.len() > MAIOR_QUADRO {
            return Err("quadro maior que o maximo deste driver");
        }

        // SAFETY: o frame é desta placa, e `CABECALHO + quadro.len()` cabe
        // nele pela conferência acima e pela asserção de compilação.
        unsafe {
            // Zeros: não pedimos soma de verificação nem segmentação, e o
            // formato diz que um cabeçalho zerado significa exatamente isso.
            core::ptr::write_bytes(self.base_de_transmissao, 0, CABECALHO);
            core::ptr::copy_nonoverlapping(
                quadro.as_ptr(),
                self.base_de_transmissao.add(CABECALHO),
                quadro.len(),
            );
        }

        let cabeca = self.transmissao.submeter(&[(
            self.frame_de_transmissao,
            (CABECALHO + quadro.len()) as u32,
            false,
        )])?;
        self.transmissao.notificar(&self.transporte);

        // Esperar a conclusão não é sobre saber se o pacote chegou — nada no
        // virtio diz isso. É sobre o buffer: ele é um só, e reescrevê-lo
        // enquanto o dispositivo ainda o lê seria a mesma corrida de DMA que o
        // disco tem documentada.
        match self.esperar(true) {
            Some(respondido) if respondido == cabeca => {
                self.transmitidos += 1;
                Ok(())
            }
            // Nos dois casos ruins o buffer continua sendo do dispositivo, e
            // nao ha como saber quando deixa de ser. Reescreve-lo para o
            // quadro seguinte seria a corrida que `vivo` existe para impedir.
            Some(_) => {
                self.vivo = false;
                Err("a placa respondeu uma cadeia que nao pedimos")
            }
            None => {
                self.vivo = false;
                crate::log_error!(
                    "virtio",
                    "a placa nao confirmou uma transmissao em {} voltas; desligada",
                    VOLTAS_DE_ESPERA
                );
                Err("a placa nao confirmou a transmissao")
            }
        }
    }

    /// Colhe um quadro recebido, se houver algum.
    ///
    /// Devolve quantos bytes do quadro foram copiados para `destino`. O
    /// cabeçalho do virtio é descartado aqui: quem chama recebe o quadro
    /// Ethernet a partir do endereço de destino.
    pub fn receber(&mut self, destino: &mut [u8]) -> Option<usize> {
        if !self.vivo {
            return None;
        }
        let (cabeca, escritos) = self.recepcao.colher()?;

        // O que o dispositivo escreveu inclui o cabeçalho. Um relato menor que
        // ele é o dispositivo dizendo algo impossível, e prosseguir seria
        // subtrair e obter um tamanho enorme.
        let bytes_do_quadro = (escritos as usize).saturating_sub(CABECALHO);
        let copiados = bytes_do_quadro.min(destino.len()).min(MAIOR_QUADRO);

        // De qual buffer veio, antes de copiar coisa alguma. Uma cadeia que
        // não corresponde a buffer nenhum é o anel dizendo algo impossível, e
        // a placa para aqui — pelo mesmo motivo que o disco e a transmissão
        // param quando o anel responde uma cadeia que não pediram.
        let Some(indice) = self.indice_do_buffer(cabeca) else {
            self.vivo = false;
            crate::log_error!(
                "virtio",
                "a placa devolveu a cadeia {}, que nao e de nenhum buffer de recepcao; desligada",
                cabeca
            );
            return None;
        };

        if copiados > 0 {
            // SAFETY: `indice` é menor que `BUFFERS_DE_RECEPCAO`, e
            // `copiados` é no máximo o tamanho útil de um buffer — as duas
            // coisas confinam a leitura ao frame daquele buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.bases_de_recepcao[indice].add(CABECALHO),
                    destino.as_mut_ptr(),
                    copiados,
                );
            }
            self.recebidos += 1;
        }

        // O buffer que acabou de ser colhido volta para o dispositivo. Sem
        // isto, a fila de recepção se esvaziaria em quatro pacotes e a placa
        // ficaria surda em silêncio.
        self.pendurar_buffers();
        self.recepcao.notificar(&self.transporte);

        Some(copiados)
    }

    /// De qual buffer veio a cadeia que começa em `cabeca`, se de algum.
    ///
    /// A resposta sai do endereço que o descritor guarda, e não de uma tabela
    /// paralela: o descritor já sabe onde o buffer está, e manter a mesma
    /// informação em dois lugares é convidar os dois a divergirem.
    ///
    /// # Por que `None` em vez de um palpite
    ///
    /// Porque a versão anterior desta função caía no buffer zero quando não
    /// reconhecia a cadeia, e as duas consequências disso eram piores do que
    /// a falha que ela escondia.
    ///
    /// A primeira é que o quadro devolvido não veio de lugar nenhum: é o
    /// conteúdo de outro buffer, entregue como pacote recebido e contado como
    /// tal. Um valor plausível e errado é pior que um erro.
    ///
    /// A segunda é pior ainda: o buffer zero, quando não foi ele que o
    /// dispositivo devolveu, é um buffer que **continua pendurado** — ou
    /// seja, que o dispositivo pode estar escrevendo neste instante. Lê-lo é
    /// a mesma corrida de DMA que `vivo` existe para impedir no disco e na
    /// transmissão.
    fn indice_do_buffer(&self, cabeca: u16) -> Option<usize> {
        let endereco = self.recepcao.endereco_do_descritor(cabeca)?;
        self.frames_de_recepcao
            .iter()
            .position(|frame| *frame == endereco)
    }

    /// Faz a placa deixar de reconhecer os próprios buffers de recepção.
    ///
    /// Existe para um teste só, e um que não teria outra forma de existir:
    /// provar que uma cadeia colhida que não corresponde a buffer nenhum
    /// desliga a placa, em vez de devolver o conteúdo de outro buffer como se
    /// fosse um pacote. O dispositivo do QEMU nunca devolve uma cadeia
    /// dessas — é o defeito que a checagem existe para pegar, não um caso que
    /// se provoque de fora.
    ///
    /// Trocar os endereços registrados é a injeção mais fiel que há: ela
    /// atinge exatamente a comparação de [`Placa::indice_do_buffer`], e nada
    /// mais. O dispositivo continua com os buffers de verdade e continua
    /// escrevendo neles; quem deixa de reconhecê-los é o driver.
    ///
    /// Devolve os endereços verdadeiros, para [`Placa::restaurar_buffers`].
    #[cfg(feature = "modo-teste")]
    pub fn desfigurar_buffers(&mut self) -> [u64; BUFFERS_DE_RECEPCAO] {
        let verdadeiros = self.frames_de_recepcao;
        for frame in self.frames_de_recepcao.iter_mut() {
            // Um endereço que nenhum frame pode ter: o alocador só entrega
            // frames alinhados, e todos os uns não é alinhado a nada.
            *frame = u64::MAX;
        }
        verdadeiros
    }

    /// Desfaz [`Placa::desfigurar_buffers`] e devolve a placa ao ar.
    ///
    /// Repor os endereços não basta: a colheita que falhou liberou os
    /// descritores daquele buffer e voltou sem pendurá-lo de novo, porque o
    /// caminho que o penduraria é o que a falha interrompeu. Sem esta parte,
    /// a placa ficaria viva e surda — que é o estado que
    /// [`Placa::pendurar_buffers`] existe para evitar.
    #[cfg(feature = "modo-teste")]
    pub fn restaurar_buffers(&mut self, verdadeiros: [u64; BUFFERS_DE_RECEPCAO]) {
        self.frames_de_recepcao = verdadeiros;
        self.vivo = true;
        self.pendurar_buffers();
        self.recepcao.notificar(&self.transporte);
    }

    /// A placa ainda está no ar?
    #[cfg(feature = "modo-teste")]
    pub fn vivo(&self) -> bool {
        self.vivo
    }

    /// Quantos descritores da fila de recepção estão com o dispositivo.
    ///
    /// O número que a suíte confere: com um buffer por cadeia, ele tem de
    /// ser igual ao de buffers pendurados, e qualquer excesso é o mesmo
    /// buffer entregue mais de uma vez.
    #[cfg(feature = "modo-teste")]
    pub fn descritores_de_recepcao_em_uso(&self) -> usize {
        super::fila::DESCRITORES as usize - self.recepcao.disponiveis()
    }

    /// Espera uma das filas devolver alguma coisa.
    fn esperar(&mut self, transmissao: bool) -> Option<u16> {
        for _ in 0..VOLTAS_DE_ESPERA {
            let colhido = if transmissao {
                self.transmissao.colher()
            } else {
                self.recepcao.colher()
            };
            if let Some((cabeca, _)) = colhido {
                return Some(cabeca);
            }
            core::hint::spin_loop();
        }
        None
    }
}

/// Quantas voltas esperar pela confirmação de uma transmissão.
///
/// Muito menor que o teto do disco, e por um motivo: aqui a espera é pela
/// confirmação de que o dispositivo **leu** o buffer, não por dados vindos de
/// fora. Um dispositivo emulado consome um buffer de transmissão
/// imediatamente; se não consumiu em cem mil voltas, não vai consumir.
const VOLTAS_DE_ESPERA: u32 = 100_000;

/// Lê o endereço MAC da configuração do dispositivo.
///
/// Byte a byte, e não como um inteiro: os seis bytes de um MAC são uma
/// sequência, não um número. Lê-los como um `u64` truncado obrigaria a pensar
/// na ordem dos bytes, que é exatamente a confusão que produz endereços
/// invertidos.
fn ler_mac(config: Mmio) -> Option<[u8; TAMANHO_DO_MAC]> {
    let mut mac = [0u8; TAMANHO_DO_MAC];
    for (indice, byte) in mac.iter_mut().enumerate() {
        *byte = config.ler_u8(CONFIG_MAC + indice as u64)?;
    }
    Some(mac)
}

/// Procura uma placa de rede virtio no barramento e a liga.
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
        crate::log_info!("virtio", "nenhuma placa de rede no barramento");
        return;
    };

    match Placa::ligar(&alvo) {
        Ok(placa) => {
            match placa.mac() {
                Some(mac) => crate::log_info!(
                    "virtio",
                    "rede em {:02x}.{}: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    alvo.dispositivo,
                    alvo.funcao,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                ),
                None => crate::log_info!(
                    "virtio",
                    "rede em {:02x}.{}: sem endereco publicado",
                    alvo.dispositivo,
                    alvo.funcao
                ),
            }
            *PLACA.lock() = Some(placa);
        }
        Err(motivo) => crate::log_error!("virtio", "rede nao pode ser ligada: {}", motivo),
    }
}

/// Chama `f` com a placa da máquina, se houver uma.
///
/// Como no disco, o acesso passa por aqui porque os buffers são poucos e
/// compartilhados: duas transmissões simultâneas escreveriam uma por cima da
/// outra.
pub fn com_a_placa<R>(f: impl FnOnce(&mut Placa) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| PLACA.lock().as_mut().map(f))
}
