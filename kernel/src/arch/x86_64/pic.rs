//! Controlador de interrupções 8259 (PIC) e timer 8253/8254 (PIT).
//!
//! # Por que ainda usamos hardware dos anos 1980
//!
//! O x86 moderno tem o APIC, em duas metades. O **local**, um por núcleo, já
//! é usado aqui como timer — ver [`super::apic`]; o endereço dele vem de um
//! MSR. O de **E/S**, que roteia as linhas dos dispositivos, é outra
//! história: onde ele está só a tabela MADT da ACPI diz, e ler ACPI é um
//! projeto em si. O PIC está sempre nos mesmos endereços e funciona em
//! qualquer máquina x86 já feita.
//!
//! Então as linhas de dispositivo continuam passando por ele, e o PIT
//! continua ligado no boot como o relógio de referência que calibra o APIC.
//!
//! Com vários núcleos, o PIC continua entregando tudo ao primeiro: as
//! interrupções de dispositivo — teclado, disco, rede, o canal do agente —
//! são do núcleo 0, e os outros têm só o timer do APIC deles e os avisos
//! entre núcleos (ver [`crate::nucleos`]). Distribuí-las exigiria o APIC de
//! E/S, e o ganho seria vazão de E/S, que esta bancada não mede; o custo é
//! que um núcleo 0 travado com as interrupções mascaradas cala os
//! dispositivos — uma limitação registrada no README.
//!
//! # A remapeação obrigatória
//!
//! Por padrão o PIC entrega as IRQs nos vetores 0 a 15. Isso colide de frente
//! com as exceções do processador, que ocupam justamente 0 a 31: uma
//! interrupção de teclado chegaria como "falha de proteção geral".
//!
//! Na época do DOS isso não incomodava. Hoje é inaceitável, e a remapeação é
//! o primeiro passo de qualquer kernel x86 — movemos as IRQs para 32 e 40,
//! logo acima da última exceção.

use x86_64::instructions::port::Port;

/// Vetor onde a primeira IRQ do PIC mestre passa a chegar.
///
/// 32 é o primeiro vetor livre: 0-31 são reservados às exceções do
/// processador.
pub const OFFSET_MESTRE: u8 = 32;
/// Vetor onde a primeira IRQ do PIC escravo passa a chegar.
pub const OFFSET_ESCRAVO: u8 = OFFSET_MESTRE + 8;

/// Número da linha do PIT.
///
/// Exposto porque a conferência do timer do APIC precisa contar os disparos
/// **do PIT em si**, e não os tiques do relógio do kernel — que a essa altura
/// já estão sendo alimentados pelos dois.
pub const IRQ_TIMER: u8 = 0;

/// Número da linha da COM2, onde vive o canal do agente.
///
/// No barramento ISA, COM1 e COM3 compartilham a IRQ 4 e COM2 e COM4
/// compartilham a IRQ 3. Como só usamos COM1 e COM2, cada uma fica com a sua.
pub const IRQ_SERIAL_AGENTE: u8 = 3;

/// A linha do PIC mestre onde o escravo está pendurado.
///
/// Uma interrupção do escravo chega ao processador **através** dela. Se ela
/// ficar mascarada, nenhuma das oito linhas do escravo chega — e é para lá
/// que o BIOS costuma rotear os dispositivos PCI.
const IRQ_CASCATA: u8 = 2;

const CMD_MESTRE: u16 = 0x20;
const DADOS_MESTRE: u16 = 0x21;
const CMD_ESCRAVO: u16 = 0xA0;
const DADOS_ESCRAVO: u16 = 0xA1;

/// Fim de interrupção: avisa ao PIC que o handler terminou.
const EOI: u8 = 0x20;

/// Frequência base do PIT, em Hz. É um valor de hardware, herdado do cristal
/// original do IBM PC (1,193182 MHz).
const FREQUENCIA_BASE_PIT: u32 = 1_193_182;

const PIT_CANAL0: u16 = 0x40;
const PIT_COMANDO: u16 = 0x43;

/// Pequena pausa entre escritas de configuração.
///
/// O 8259 é lento em relação a um processador moderno e pode perder palavras
/// de inicialização enviadas em sequência rápida. Escrever na porta 0x80
/// (usada para códigos de diagnóstico do POST e inofensiva) gasta um ciclo de
/// barramento, que é tempo suficiente. É o truque padrão desde o DOS.
fn espera_io() {
    // SAFETY: a porta 0x80 não controla nada em hardware moderno; escrever
    // nela apenas consome tempo de barramento.
    unsafe { Port::new(0x80).write(0u8) }
}

/// Remapeia o PIC e habilita apenas as linhas que sabemos tratar.
///
/// # Safety
///
/// Precisa ser chamada com as interrupções desabilitadas e uma IDT já
/// instalada: se uma interrupção chegasse no meio da reconfiguração, ela
/// seria entregue num vetor indefinido.
pub unsafe fn init() {
    // SAFETY: a sequência abaixo é o protocolo de inicialização documentado
    // do 8259, e o chamador garantiu que não há interrupções em voo.
    unsafe {
        let mut cmd_mestre = Port::<u8>::new(CMD_MESTRE);
        let mut dados_mestre = Port::<u8>::new(DADOS_MESTRE);
        let mut cmd_escravo = Port::<u8>::new(CMD_ESCRAVO);
        let mut dados_escravo = Port::<u8>::new(DADOS_ESCRAVO);

        // ICW1: inicia a sequência e avisa que haverá uma quarta palavra.
        cmd_mestre.write(0x11);
        espera_io();
        cmd_escravo.write(0x11);
        espera_io();

        // ICW2: o vetor base de cada controlador — a remapeação em si.
        dados_mestre.write(OFFSET_MESTRE);
        espera_io();
        dados_escravo.write(OFFSET_ESCRAVO);
        espera_io();

        // ICW3: como os dois estão ligados. O escravo pendura na linha 2 do
        // mestre, então o mestre recebe uma máscara de bits (1 << 2) e o
        // escravo recebe o número da linha.
        dados_mestre.write(0b0000_0100);
        espera_io();
        dados_escravo.write(2);
        espera_io();

        // ICW4: modo 8086. Sem isto o PIC opera no modo do 8080, obsoleto
        // desde antes do 386.
        dados_mestre.write(0x01);
        espera_io();
        dados_escravo.write(0x01);
        espera_io();

        // Máscara: bit ligado significa linha *desabilitada*. Deixamos
        // passar apenas IRQ 0 (timer) e IRQ 1 (teclado); tudo que ainda não
        // sabemos tratar fica bloqueado, porque uma interrupção sem handler
        // adequado é pior que interrupção nenhuma.
        //
        // A IRQ 3 (COM2) continua bloqueada aqui de propósito: ela só é
        // liberada por `desmascarar` quando o canal do agente estiver
        // realmente pronto para consumir bytes.
        dados_mestre.write(0b1111_1100);
        espera_io();
        dados_escravo.write(0b1111_1111);
    }
}

/// Libera uma linha do PIC mestre.
///
/// Desmascarar é uma operação de leitura-modificação-escrita sobre a máscara
/// inteira: ler o valor atual antes de mexer é o que impede que habilitar uma
/// linha reabilite silenciosamente todas as outras.
///
/// # Safety
///
/// Só pode ser chamada quando já existe um handler instalado para o vetor
/// correspondente.
pub unsafe fn desmascarar(linha: u8) {
    if linha >= 16 {
        return;
    }

    // SAFETY: portas de dados dos dois PICs; o chamador garantiu que há
    // handler para a linha.
    unsafe {
        if linha < 8 {
            let mut dados_mestre = Port::<u8>::new(DADOS_MESTRE);
            let atual: u8 = dados_mestre.read();
            dados_mestre.write(atual & !(1 << linha));
            return;
        }

        // Uma linha do escravo exige duas liberações. A do escravo é óbvia; a
        // da cascata não, e esquecê-la produz o sintoma mais confuso possível
        // — a linha está habilitada nos dois lugares que se costuma olhar, e
        // a interrupção nunca chega, porque o caminho dela até o processador
        // passa por uma terceira que continua fechada.
        let mut dados_escravo = Port::<u8>::new(DADOS_ESCRAVO);
        let atual: u8 = dados_escravo.read();
        dados_escravo.write(atual & !(1 << (linha - 8)));

        let mut dados_mestre = Port::<u8>::new(DADOS_MESTRE);
        let atual: u8 = dados_mestre.read();
        dados_mestre.write(atual & !(1 << IRQ_CASCATA));
    }
}

/// Bloqueia uma linha do PIC.
///
/// O inverso de [`desmascarar`], e pela mesma razão uma leitura-modificação-
/// escrita: mexer numa linha sem preservar as outras as reabilitaria em
/// silêncio.
///
/// # Safety
///
/// Bloquear uma linha que alguém ainda espera deixa o sistema sem aquele
/// evento, sem aviso nenhum.
pub unsafe fn mascarar(linha: u8) {
    if linha >= 8 {
        return;
    }
    // SAFETY: porta de dados do PIC mestre; a consequência de bloquear a
    // linha é do chamador.
    unsafe {
        let mut dados_mestre = Port::<u8>::new(DADOS_MESTRE);
        let atual: u8 = dados_mestre.read();
        dados_mestre.write(atual | (1 << linha));
    }
}

/// Programa o timer PIT para disparar na frequência pedida.
///
/// Devolve a frequência efetivamente obtida, que difere um pouco da pedida
/// porque o divisor é inteiro. Reportar o valor real em vez do pedido é o que
/// mantém honesto o cálculo de uptime.
///
/// # Safety
///
/// Escreve em portas de I/O do timer; exige acesso exclusivo ao PIT.
pub unsafe fn programar_timer(hz_desejado: u32) -> u32 {
    // O PIT conta de `divisor` até zero e dispara; divisor 0 significa 65536.
    let divisor = (FREQUENCIA_BASE_PIT / hz_desejado).clamp(1, 65535) as u16;

    // SAFETY: portas do PIT, com acesso exclusivo garantido pelo chamador.
    unsafe {
        // Canal 0, acesso em dois bytes (baixo depois alto), modo 3 (onda
        // quadrada), contagem binária.
        Port::<u8>::new(PIT_COMANDO).write(0x36);
        espera_io();

        let mut canal = Port::<u8>::new(PIT_CANAL0);
        canal.write((divisor & 0xFF) as u8);
        espera_io();
        canal.write((divisor >> 8) as u8);
    }

    FREQUENCIA_BASE_PIT / divisor as u32
}

/// O canal 2 do PIT: o do alto-falante. O canal 0 é o timer; o 2 não tem
/// outro dono neste kernel, e mede o contador de ciclos — ver
/// [`calibrar_ciclos`].
const PIT_CANAL2: u16 = 0x42;

/// A porta B do controlador do sistema: o bit 0 deixa o canal 2 contar (o
/// "gate"), o 1 liga o alto-falante ao canal.
const PORTA_B: u16 = 0x61;

/// Quantos clocks do PIT uma medida cobre: um décimo de segundo.
const CLOCKS_DA_MEDIDA: u64 = FREQUENCIA_BASE_PIT as u64 / 10;

/// A maior lacuna entre duas leituras do canal 2, em clocks do PIT. O
/// contador tem 16 bits e dá a volta a cada 65536 clocks (55 ms): uma
/// lacuna desse tamanho — o fio preemptado, o processador emulado sem vez
/// no hospedeiro — esconde uma volta inteira, e a medida sai errada sem
/// aviso. Com o teto em 20000, toda lacuna que pode ter escondido uma volta
/// é recusada (ver [`medir_os_ciclos`]).
const MAIOR_LACUNA: u64 = 20_000;

/// O maior erro de uma medida que vale, em partes por milhão.
const MAIOR_ERRO_PPM: u64 = 200;

/// Uma leitura do canal 2: a contagem travada, e o contador de ciclos
/// logo antes e logo depois da trava.
#[derive(Clone, Copy)]
struct LeituraDoCanal2 {
    antes: u64,
    depois: u64,
    contagem: u16,
}

impl LeituraDoCanal2 {
    fn meio(&self) -> u64 {
        self.antes + self.largura() / 2
    }

    fn largura(&self) -> u64 {
        self.depois.saturating_sub(self.antes)
    }
}

/// # Safety
///
/// Portas do PIT, com o canal 2 programado por [`calibrar_ciclos`].
unsafe fn ler_o_canal2() -> LeituraDoCanal2 {
    // SAFETY: as portas do PIT; a garantia é de quem chama.
    unsafe {
        let antes = super::ciclos();
        // Trava a contagem do canal 2 (comando `10 00 0000`): os dois bytes
        // lidos depois são os do instante da trava, e não um de cada
        // instante.
        Port::<u8>::new(PIT_COMANDO).write(0x80);
        let depois = super::ciclos();
        let mut canal = Port::<u8>::new(PIT_CANAL2);
        let baixo: u8 = canal.read();
        let alto: u8 = canal.read();
        LeituraDoCanal2 {
            antes,
            depois,
            contagem: u16::from_le_bytes([baixo, alto]),
        }
    }
}

/// Uma medida: a frequência do contador de ciclos e o erro máximo dela, em
/// ppm. `None` se uma lacuna pode ter escondido uma volta do canal 2, ou
/// se ele não conta.
///
/// # Safety
///
/// Como [`ler_o_canal2`].
unsafe fn medir_os_ciclos() -> Option<(u64, u64)> {
    /// Quantas leituras disputam cada ponta: vale a mais estreita.
    const PONTAS: usize = 8;
    // SAFETY: a garantia de quem chama.
    let ler = || unsafe { ler_o_canal2() };
    // A partida: a mais estreita de algumas leituras. As que vêm depois
    // dela entram na conta pela diferença de contagem, como qualquer outra.
    let mut inicio = ler();
    for _ in 1..PONTAS {
        let l = ler();
        if l.largura() < inicio.largura() {
            inicio = l;
        }
    }
    let mut anterior = inicio;
    let mut menor_largura = inicio.largura();
    let mut clocks = 0u64;
    let mut maior_lacuna = 0u64;
    let mut leituras = 0u64;
    // Até cobrir a medida, e então até uma leitura tão estreita quanto a
    // melhor já vista — com um teto, para uma ponta larga não segurar o
    // boot.
    let mut extras = 0;
    loop {
        let l = ler();
        maior_lacuna = maior_lacuna.max(l.antes.saturating_sub(anterior.depois));
        // O canal conta para baixo, e dá a volta: a diferença módulo 2^16
        // é o que ele andou, desde que nenhuma lacuna esconda uma volta.
        clocks += u64::from(anterior.contagem.wrapping_sub(l.contagem));
        anterior = l;
        leituras += 1;
        if leituras > 100_000_000 {
            // O canal 2 não conta: nenhuma medida.
            return None;
        }
        if clocks < CLOCKS_DA_MEDIDA {
            menor_largura = menor_largura.min(l.largura());
            continue;
        }
        if l.largura() <= menor_largura.saturating_mul(2) || extras >= 64 {
            break;
        }
        extras += 1;
    }
    let fim = anterior;
    let ciclos = fim.meio().checked_sub(inicio.meio())?;
    if ciclos == 0 || clocks == 0 {
        return None;
    }
    // A maior lacuna, em clocks do PIT, pela razão medida: acima do teto
    // ela pode ter escondido uma volta. Uma que escondeu uma volta faz a
    // razão sair errada para menos clocks, e ainda assim passa do teto —
    // a conta está no comentário de `MAIOR_LACUNA`.
    if u128::from(maior_lacuna) * u128::from(clocks) > u128::from(MAIOR_LACUNA) * u128::from(ciclos)
    {
        return None;
    }
    let hz = u128::from(ciclos) * u128::from(FREQUENCIA_BASE_PIT) / u128::from(clocks);
    let hz = u64::try_from(hz).ok().filter(|&h| h > 0)?;
    // O erro: o instante de cada ponta está dentro da largura dela, e a
    // contagem do PIT é inteira — um clock de cada lado.
    let um_clock = hz.div_ceil(u64::from(FREQUENCIA_BASE_PIT));
    let incerteza = (inicio.largura() + fim.largura()).div_ceil(2) + 2 * um_clock;
    let erro_ppm = (u128::from(incerteza) * 1_000_000).div_ceil(u128::from(ciclos));
    Some((hz, u64::try_from(erro_ppm).unwrap_or(u64::MAX)))
}

/// A frequência do contador de ciclos (o TSC), medida contra o canal 2 do
/// PIT — o mesmo cristal que calibra o APIC —, e o erro máximo da medida,
/// em ppm. É a régua do relógio civil: ver `crate::hora::contador`.
///
/// # Por que o canal 2, e não os tiques
///
/// Porque os tiques se perdem: o emulador junta interrupções do timer
/// quando o processador emulado fica sem vez no hospedeiro, e o relógio do
/// kernel anda devagar sem dizer nada. O contador do PIT não perde
/// contagem — ele é lido, não interrompe —, e cada leitura fica entre duas
/// leituras do TSC: o instante dela está naquela largura.
///
/// Uma medida de um décimo de segundo; até cinco tentativas, e vale a
/// primeira com erro de até [`MAIOR_ERRO_PPM`]. `None` sem nenhuma — o
/// civil cai para os tiques, com a deriva deles.
pub fn calibrar_ciclos() -> Option<(u64, u64)> {
    const TENTATIVAS: usize = 5;
    // SAFETY: as portas do PIT e a porta B. O canal 2 e o alto-falante não
    // têm outro dono neste kernel, e a calibração roda no boot, com um
    // núcleo só; o canal 0, o do timer, não é tocado — o comando de
    // programação e o de trava nomeiam o canal 2.
    unsafe {
        let mut b = Port::<u8>::new(PORTA_B);
        let antes: u8 = b.read();
        // O canal 2 conta; o alto-falante, desligado.
        b.write((antes & !0x02) | 0x01);
        espera_io();
        // Canal 2, dois bytes (baixo e alto), modo 2 (o contador desce e
        // recarrega), contagem binária — e a contagem 0, que é 65536.
        Port::<u8>::new(PIT_COMANDO).write(0xB4);
        espera_io();
        let mut canal = Port::<u8>::new(PIT_CANAL2);
        canal.write(0);
        espera_io();
        canal.write(0);
        let mut melhor: Option<(u64, u64)> = None;
        for _ in 0..TENTATIVAS {
            let Some(m) = medir_os_ciclos() else {
                continue;
            };
            if melhor.is_none_or(|(_, e)| m.1 < e) {
                melhor = Some(m);
            }
            if m.1 <= MAIOR_ERRO_PPM {
                break;
            }
        }
        b.write(antes);
        melhor.filter(|&(_, erro)| erro <= MAIOR_ERRO_PPM)
    }
}

/// Sinaliza fim de interrupção para o PIC.
///
/// Obrigatório: sem este aviso o controlador considera a interrupção ainda em
/// atendimento e **nunca mais** entrega outra daquela linha. O sintoma é o
/// timer disparar exatamente uma vez e o sistema parecer congelado.
///
/// # Safety
///
/// Só deve ser chamada de dentro do handler da interrupção correspondente.
pub unsafe fn fim_de_interrupcao(vetor: u8) {
    // SAFETY: escrita do comando EOI nas portas de comando do PIC.
    unsafe {
        // Interrupções do escravo precisam ser confirmadas nos dois
        // controladores: o mestre só sabe que a linha 2 foi atendida depois
        // que o escravo confirma.
        if vetor >= OFFSET_ESCRAVO {
            Port::<u8>::new(CMD_ESCRAVO).write(EOI);
        }
        Port::<u8>::new(CMD_MESTRE).write(EOI);
    }
}
