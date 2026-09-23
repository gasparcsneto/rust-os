//! Controlador de interrupções 8259 (PIC) e timer 8253/8254 (PIT).
//!
//! # Por que ainda usamos hardware dos anos 1980
//!
//! O x86 moderno tem o APIC, bem mais capaz: mais linhas, roteamento por
//! núcleo, prioridades. Mas ele exige descobrir tabelas ACPI para saber onde
//! está mapeado, o que é um projeto em si. O PIC está sempre nos mesmos
//! endereços e funciona em qualquer máquina x86 já feita.
//!
//! Começar pelo PIC deixa o caminho de interrupções funcionando *hoje*,
//! com o custo de trocá-lo pelo APIC quando houver múltiplos núcleos.
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
