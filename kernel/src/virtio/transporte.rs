//! Como achar os registradores de um dispositivo virtio, e como ligá-lo.
//!
//! # A indireção das capabilities
//!
//! Um dispositivo PCI comum diz "meus registradores estão no BAR 0". Um
//! dispositivo virtio moderno não: ele publica, na lista de *capabilities* do
//! espaço de configuração, uma entrada por região, e cada entrada diz em que
//! BAR a região está e em que deslocamento dentro dele.
//!
//! A indireção existe porque as quatro regiões — configuração comum,
//! notificação, interrupção e configuração específica do dispositivo — não
//! têm tamanho fixo nem ordem fixa, e cabem todas num BAR só. Um layout fixo
//! obrigaria a reservar espaço para o pior caso de todo dispositivo virtio que
//! venha a existir.
//!
//! Custa uma varredura de lista encadeada no boot, e em troca nada aqui
//! depende de onde o QEMU resolveu pôr as coisas nesta versão.

use pci_types::capability::PciCapability;
use pci_types::{ConfigRegionAccess, EndpointHeader, PciAddress, PciHeader};

use crate::pci::{BARS, Dispositivo};

/// Quem fabrica todo dispositivo virtio, no vocabulário do PCI.
pub const FABRICANTE: u16 = 0x1AF4;

// ---------------------------------------------------------------------------
// Acesso a uma região de MMIO
// ---------------------------------------------------------------------------

/// Uma janela de memória mapeada, com o limite conferido a cada acesso.
///
/// # Por que conferir
///
/// Porque os deslocamentos não são nossos. Eles vêm das capabilities, que o
/// dispositivo escreveu — e um deslocamento maior do que a região significaria
/// ler ou escrever no BAR do vizinho. Conferir é uma comparação; não conferir
/// é uma classe de bug que só aparece na máquina de outra pessoa.
///
/// Guardamos o endereço como inteiro, e não como ponteiro, porque o driver
/// vive num `static` compartilhado e um ponteiro cru não atravessa isso.
#[derive(Clone, Copy, Debug)]
pub struct Mmio {
    base: u64,
    /// Quantos bytes a janela cobre. Legível porque quem a recebe pode precisar
    /// exigir um tamanho mínimo — ver [`TAMANHO_MINIMO_DA_CONFIG_COMUM`].
    tamanho: u64,
}

impl Mmio {
    /// Uma janela sobre `base`, de `tamanho` bytes.
    ///
    /// # Safety
    ///
    /// A faixa precisa estar mapeada como memória de dispositivo e pertencer a
    /// um dispositivo que este kernel esteja dirigindo.
    pub const unsafe fn nova(base: u64, tamanho: u64) -> Self {
        Self { base, tamanho }
    }

    /// Uma sub-janela, para quando uma capability aponta para dentro desta.
    pub fn fatia(&self, deslocamento: u64, tamanho: u64) -> Option<Mmio> {
        let fim = deslocamento.checked_add(tamanho)?;
        (fim <= self.tamanho).then_some(Mmio {
            base: self.base + deslocamento,
            tamanho,
        })
    }

    /// Onde um registrador está, se ele couber e estiver alinhado.
    ///
    /// O alinhamento não é preciosismo: no ARM um acesso desalinhado a memória
    /// de dispositivo gera exceção, não um acesso lento. E um registrador de
    /// dispositivo precisa ser lido na largura certa de qualquer jeito — ler
    /// dois registradores de 16 bits como um de 32 pode disparar efeitos
    /// colaterais que o manual atribui a um deles só.
    ///
    /// A conferência é do endereço **final**, e não do deslocamento dentro da
    /// janela. A diferença importa porque a janela nem sempre começa alinhada:
    /// a base dela vem do `offset` de uma capability, que é o dispositivo quem
    /// escreve. Conferir só o deslocamento deixaria o campo em `0x20` de uma
    /// janela que começa em `+2` passar como alinhado, que é exatamente o caso
    /// contra o qual esta função existe.
    fn registrador<T>(&self, deslocamento: u64) -> Option<*mut T> {
        let largura = core::mem::size_of::<T>() as u64;
        let fim = deslocamento.checked_add(largura)?;
        if fim > self.tamanho {
            return None;
        }
        let endereco = self.base.checked_add(deslocamento)?;
        if !endereco.is_multiple_of(largura) {
            return None;
        }
        Some(endereco as *mut T)
    }
}

/// Gera o par de acessadores de cada largura.
///
/// Os quatro pares são o mesmo corpo com um tipo diferente, e escrevê-los à
/// mão seria convidar a divergência entre eles — foi por isso que a macro
/// entrou. O que ela **não** faz é esconder a largura: ela continua no nome de
/// cada função, que é onde quem lê o driver precisa vê-la.
macro_rules! acessadores {
    ($($ler:ident / $escrever:ident : $t:ty),* $(,)?) => {
        impl Mmio {
            $(
                #[doc = concat!("Lê um registrador de ", stringify!($t), ".")]
                pub fn $ler(&self, deslocamento: u64) -> Option<$t> {
                    let ponteiro = self.registrador::<$t>(deslocamento)?;
                    // SAFETY: a construção da janela garantiu que a faixa é
                    // memória de dispositivo mapeada, e `registrador` conferiu
                    // que este acesso cabe nela e está alinhado.
                    //
                    // `read_volatile` porque ler um registrador é um efeito
                    // observável: o compilador não pode repetir, remover nem
                    // reordenar esta leitura por achar que o valor não mudou.
                    let cru = unsafe { core::ptr::read_volatile(ponteiro) };
                    Some(<$t>::from_le(cru))
                }

                #[doc = concat!("Escreve um registrador de ", stringify!($t), ".")]
                #[doc = ""]
                #[doc = "Devolve `false` se o deslocamento não couber na janela."]
                #[must_use]
                pub fn $escrever(&self, deslocamento: u64, valor: $t) -> bool {
                    let Some(ponteiro) = self.registrador::<$t>(deslocamento) else {
                        return false;
                    };
                    // SAFETY: mesma justificativa da leitura.
                    unsafe { core::ptr::write_volatile(ponteiro, valor.to_le()) };
                    true
                }
            )*
        }
    };
}

// Os campos do virtio são little-endian por especificação, em qualquer
// arquitetura. As duas que este kernel suporta já são, então o `from_le`/
// `to_le` dos acessadores não gera instrução nenhuma — ele documenta o
// contrato e o faz valer se um dia houver um alvo big-endian.
acessadores! {
    ler_u8 / escrever_u8: u8,
    ler_u16 / escrever_u16: u16,
    ler_u32 / escrever_u32: u32,
    ler_u64 / escrever_u64: u64,
}

// ---------------------------------------------------------------------------
// As capabilities
// ---------------------------------------------------------------------------

// Tipos de região, no campo `cfg_type` da capability.
const CFG_COMUM: u8 = 1;
const CFG_NOTIFICACAO: u8 = 2;
/// A região que diz **por que** uma interrupção chegou.
const CFG_ISR: u8 = 3;
const CFG_DO_DISPOSITIVO: u8 = 4;

// Campos da capability virtio, em bytes a partir do começo dela. Os três
// primeiros (`cap_vndr`, `cap_next`, `cap_len`) são do PCI e a lista encadeada
// já os consumiu; daqui para a frente é virtio.
const CAP_TIPO: u16 = 3;
const CAP_BAR: u16 = 4;
const CAP_DESLOCAMENTO: u16 = 8;
const CAP_TAMANHO: u16 = 12;
const CAP_MULTIPLICADOR: u16 = 16;

/// Lê um byte do espaço de configuração.
///
/// A janela de acesso do PCI é de 32 bits alinhados — nos dois mecanismos,
/// pelas duas razões que cada backend explica. Pegar um byte é ler a palavra
/// que o contém e recortar, e os campos da capability virtio que interessam
/// (`cfg_type`, `bar`) são de um byte.
///
/// # Safety
/// `endereco` precisa ser o de um dispositivo presente no barramento.
unsafe fn ler_byte(
    acesso: &impl ConfigRegionAccess,
    endereco: PciAddress,
    deslocamento: u16,
) -> u8 {
    // SAFETY: delegada ao chamador; os backends já descartam os dois bits
    // baixos, e o recorte aqui é o inverso dessa operação.
    let palavra = unsafe { acesso.read(endereco, deslocamento) };
    (palavra >> ((deslocamento & 3) * 8)) as u8
}

/// Onde cada pedaço da interface do dispositivo está.
#[derive(Clone, Copy, Debug)]
pub struct Transporte {
    /// A configuração comum: estado, recursos e as filas. É a única região
    /// sem a qual não há dispositivo.
    comum: Mmio,
    /// A região onde se escreve para avisar o dispositivo de que há trabalho.
    notificacao: Mmio,
    /// Quantos bytes separam a notificação de uma fila da da fila seguinte.
    ///
    /// Zero quer dizer que todas as filas compartilham o mesmo endereço e se
    /// distinguem pelo valor escrito. Um valor maior dá a cada fila um
    /// endereço próprio, o que permite ao hospedeiro saber qual fila foi
    /// notificada sem ler nada.
    multiplicador_de_notificacao: u32,
    /// A configuração específica do tipo de dispositivo — a capacidade do
    /// disco, o endereço MAC da placa de rede. Opcional: nem todo dispositivo
    /// tem.
    do_dispositivo: Option<Mmio>,
    /// O registrador que diz **por que** uma interrupção chegou.
    ///
    /// Passou a importar quando as interrupções passaram a ser entregues: uma
    /// linha de PCI é de nível, e é a leitura deste registrador que faz o
    /// dispositivo soltá-la. Ver [`crate::virtio::atender_interrupcao`].
    isr: Option<Mmio>,
}

/// Quanto a configuração comum precisa ter para conter tudo o que lemos dela.
///
/// # Por que conferir uma vez, e não a cada acesso
///
/// Porque os acessadores devolvem `Option`, e todo chamador aqui dentro acaba
/// dando um `unwrap_or` nela. Isso conflata duas coisas: `estado()` devolvendo
/// zero pode significar "o dispositivo está reiniciado" ou "não consegui ler o
/// registrador" — e [`Transporte::reiniciar`], que espera pelo zero, trataria
/// a segunda como sucesso.
///
/// Conferir o tamanho na construção torna essa confusão impossível em vez de
/// improvável: ou a região comporta todos os campos, e nenhum acesso a ela
/// pode falhar por limite, ou o dispositivo é recusado com uma mensagem que
/// diz o que houve.
///
/// O valor é o fim do último campo que este driver toca: `queue_device`, em
/// `0x30`, com oito bytes.
const TAMANHO_MINIMO_DA_CONFIG_COMUM: u64 = comum::USADOS + 8;

/// E quanto a região de notificação precisa ter para caber uma escrita.
const TAMANHO_MINIMO_DA_NOTIFICACAO: u64 = 2;

// Campos da configuração comum, em bytes a partir do começo dela.
mod comum {
    pub const SELETOR_DE_RECURSOS_DO_DISPOSITIVO: u64 = 0x00;
    pub const RECURSOS_DO_DISPOSITIVO: u64 = 0x04;
    pub const SELETOR_DE_RECURSOS_DO_DRIVER: u64 = 0x08;
    pub const RECURSOS_DO_DRIVER: u64 = 0x0C;
    pub const NUMERO_DE_FILAS: u64 = 0x12;
    pub const ESTADO: u64 = 0x14;
    pub const SELETOR_DE_FILA: u64 = 0x16;
    pub const TAMANHO_DA_FILA: u64 = 0x18;
    pub const VETOR_MSIX_DA_FILA: u64 = 0x1A;
    pub const FILA_HABILITADA: u64 = 0x1C;
    pub const DESLOCAMENTO_DE_NOTIFICACAO: u64 = 0x1E;
    pub const DESCRITORES: u64 = 0x20;
    pub const DISPONIVEIS: u64 = 0x28;
    pub const USADOS: u64 = 0x30;
}

// Bits do registrador de estado. A ordem em que são acesos é o protocolo de
// inicialização do virtio, e a especificação a exige literalmente.
const RECONHECIDO: u8 = 1;
const DRIVER: u8 = 2;
const PRONTO: u8 = 4;
const RECURSOS_ACEITOS: u8 = 8;
const FALHOU: u8 = 128;

/// O recurso que separa virtio 1.0 do legado.
///
/// Aceitá-lo é o que diz ao dispositivo "fale a interface moderna comigo". Um
/// dispositivo transicional que não o veja aceso continua esperando os
/// registradores legados, e nada do que está neste arquivo faria sentido para
/// ele.
pub const VERSAO_1: u64 = 1 << 32;

/// Indica que o MSI-X desta fila não está em uso.
///
/// O dispositivo precisa de um vetor de interrupção por fila, e este valor é o
/// "nenhum" do protocolo. Escrevê-lo explicitamente importa: o registrador não
/// nasce necessariamente zerado, e um vetor herdado de um driver anterior
/// faria o dispositivo sinalizar para um lugar que não existe.
const SEM_VETOR: u16 = 0xFFFF;

impl Transporte {
    /// Percorre as capabilities do dispositivo e monta o transporte.
    pub fn descobrir(d: &Dispositivo) -> Result<Transporte, &'static str> {
        let Some(acesso) = crate::arch::pci::acesso() else {
            return Err("sem acesso a configuracao PCI");
        };
        let endereco = PciAddress::new(0, d.barramento, d.dispositivo, d.funcao);
        let Some(ponta) = EndpointHeader::from_header(PciHeader::new(endereco), acesso) else {
            return Err("dispositivo nao tem cabecalho de ponta");
        };

        let mut comum = None;
        let mut notificacao = None;
        let mut multiplicador = 0u32;
        let mut do_dispositivo = None;
        let mut isr = None;

        // Um BAR é mapeado no máximo uma vez, e é por isso que há um cache em
        // vez de uma chamada direta: as três regiões que interessam moram, no
        // QEMU, todas no mesmo BAR. Mapeá-lo a cada capability produziria três
        // traduções para a mesma página — a segunda falharia, ou pior, não.
        let mut mapeados: [Option<Mmio>; BARS] = [None; BARS];

        // A lista de capabilities é percorrida com interrupções mascaradas
        // porque, no x86, cada leitura é um par de acessos ao chipset que
        // compartilha estado — ver `arch::x86_64::pci`. Uma máscara para a
        // varredura inteira custa menos que uma por acesso.
        crate::arch::sem_interrupcoes(|| {
            for capacidade in ponta.capabilities(acesso) {
                // O virtio se descreve com capabilities do tipo "específica do
                // fabricante". Qualquer outro tipo na lista é assunto de outro
                // subsistema — MSI-X, por exemplo — e não nosso aqui.
                let PciCapability::Vendor(endereco_da_cap) = capacidade else {
                    continue;
                };

                let base = endereco_da_cap.offset;

                // SAFETY: o endereço veio da própria lista encadeada do
                // dispositivo, e os deslocamentos são os do cabeçalho da
                // capability virtio.
                let (tipo, bar, deslocamento, tamanho) = unsafe {
                    (
                        ler_byte(&acesso, endereco, base + CAP_TIPO),
                        ler_byte(&acesso, endereco, base + CAP_BAR),
                        acesso.read(endereco, base + CAP_DESLOCAMENTO),
                        acesso.read(endereco, base + CAP_TAMANHO),
                    )
                };

                // A região do BAR só é procurada para os tipos que este
                // driver usa. Um dispositivo transicional publica também a
                // capability de acesso alternativo (`PCI_CFG`), que aponta
                // para o BAR de I/O legado — o que este kernel deliberadamente
                // não atribui. Resolvê-la para depois descartá-la só produzia
                // um aviso sobre algo que está certo.
                if !matches!(
                    tipo,
                    CFG_COMUM | CFG_NOTIFICACAO | CFG_DO_DISPOSITIVO | CFG_ISR
                ) {
                    continue;
                }

                let janela = match mapeados.get(bar as usize).copied().flatten() {
                    Some(janela) => janela,
                    None => {
                        let Some(regiao) = d.regiao(bar) else {
                            crate::log_warn!(
                                "virtio",
                                "capability do tipo {} aponta para o BAR {}, que nao tem regiao",
                                tipo,
                                bar
                            );
                            continue;
                        };

                        // O endereço da região é físico; o kernel só alcança
                        // endereços virtuais. Ver [`crate::mmio`] — foi a
                        // ausência deste passo que derrubou o x86 com falha de
                        // página na primeira escrita num BAR.
                        let onde = match crate::mmio::mapear(regiao.base, regiao.tamanho) {
                            Ok(onde) => onde,
                            Err(motivo) => {
                                crate::log_warn!(
                                    "virtio",
                                    "BAR {} nao pode ser mapeado: {}",
                                    bar,
                                    motivo
                                );
                                continue;
                            }
                        };

                        // SAFETY: `mmio::mapear` acabou de mapear esta faixa
                        // como memória de dispositivo, com o tamanho que a
                        // varredura do PCI mediu no BAR.
                        let janela = unsafe { Mmio::nova(onde, regiao.tamanho) };
                        mapeados[bar as usize] = Some(janela);
                        janela
                    }
                };

                let Some(fatia) = janela.fatia(deslocamento as u64, tamanho as u64) else {
                    crate::log_warn!(
                        "virtio",
                        "capability do tipo {} aponta para fora do BAR {}",
                        tipo,
                        bar
                    );
                    continue;
                };

                match tipo {
                    CFG_COMUM => comum = Some(fatia),
                    CFG_NOTIFICACAO => {
                        // Só a capability de notificação tem um quinto campo.
                        // SAFETY: mesma justificativa dos anteriores.
                        multiplicador = unsafe { acesso.read(endereco, base + CAP_MULTIPLICADOR) };
                        notificacao = Some(fatia);
                    }
                    CFG_DO_DISPOSITIVO => do_dispositivo = Some(fatia),
                    CFG_ISR => isr = Some(fatia),
                    // O filtro acima já garantiu que não chegamos aqui.
                    _ => {}
                }
            }
        });

        let comum = comum.ok_or("dispositivo sem configuracao comum")?;
        if comum.tamanho < TAMANHO_MINIMO_DA_CONFIG_COMUM {
            return Err("configuracao comum menor que os campos do protocolo");
        }

        let notificacao = notificacao.ok_or("dispositivo sem regiao de notificacao")?;
        if notificacao.tamanho < TAMANHO_MINIMO_DA_NOTIFICACAO {
            return Err("regiao de notificacao pequena demais para uma escrita");
        }

        Ok(Transporte {
            comum,
            notificacao,
            multiplicador_de_notificacao: multiplicador,
            do_dispositivo,
            isr,
        })
    }

    /// A configuração específica do tipo de dispositivo, se houver.
    pub fn configuracao(&self) -> Option<Mmio> {
        self.do_dispositivo
    }

    /// Endereço do registrador de estado de interrupção, para o handler.
    ///
    /// Entregue como número, e não como [`Mmio`], porque quem o usa é um
    /// handler de interrupção que precisa guardá-lo num atômico. Um tipo com
    /// invariantes não caberia lá, e afrouxar as invariantes para caber seria
    /// pior que entregar o número cru.
    pub fn endereco_do_isr(&self) -> Option<u64> {
        self.isr.map(|regiao| regiao.base)
    }

    /// Quantas filas o dispositivo oferece.
    pub fn filas(&self) -> u16 {
        self.comum.ler_u16(comum::NUMERO_DE_FILAS).unwrap_or(0)
    }

    /// O registrador de estado.
    ///
    /// O `unwrap_or` não esconde nada: [`Transporte::descobrir`] recusa uma
    /// configuração comum que não comporte todos os campos, então uma leitura
    /// aqui não tem como falhar por limite. Sem aquela conferência, este zero
    /// seria indistinguível do zero que significa "dispositivo reiniciado".
    fn estado(&self) -> u8 {
        self.comum.ler_u8(comum::ESTADO).unwrap_or(0)
    }

    fn acender(&self, bit: u8) {
        let _ = self.comum.escrever_u8(comum::ESTADO, self.estado() | bit);
    }

    /// Devolve o dispositivo ao estado de recém-ligado.
    ///
    /// Não é higiene opcional. O dispositivo pode ter sido deixado a meio
    /// caminho por um driver anterior — um kexec, um boot que falhou depois de
    /// configurar filas — e um aperto de mão que comece de um estado
    /// desconhecido termina num estado desconhecido.
    ///
    /// A espera pela leitura de zero é exigência da especificação: escrever
    /// zero **pede** o reinício, e só a leitura confirma que ele terminou.
    fn reiniciar(&self) -> Result<(), &'static str> {
        if !self.comum.escrever_u8(comum::ESTADO, 0) {
            return Err("registrador de estado fora da regiao comum");
        }

        // O teto existe para que um dispositivo quebrado vire um erro em vez
        // de um kernel travado no boot. O reinício de um dispositivo emulado é
        // imediato; qualquer valor aqui é generoso.
        for _ in 0..100_000 {
            if self.estado() == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("dispositivo nao reiniciou")
    }

    /// Faz o aperto de mão que liga o dispositivo, até a aceitação de recursos.
    ///
    /// Devolve os recursos que ficaram valendo — a interseção do que o
    /// dispositivo oferece com o que pedimos.
    ///
    /// # A ordem é o protocolo
    ///
    /// Reiniciar, dizer que o vimos (`RECONHECIDO`), dizer que sabemos dirigi
    /// -lo (`DRIVER`), negociar recursos, e só então declarar os recursos
    /// aceitos. Cada passo habilita o seguinte, e o dispositivo tem o direito
    /// de recusar em qualquer um deles.
    ///
    /// `PRONTO` fica de fora de propósito: ele diz "pode começar a trabalhar",
    /// e dizê-lo antes de as filas existirem seria autorizar o dispositivo a
    /// ler descritores que ainda não escrevemos. Ver [`Transporte::liberar`].
    pub fn iniciar(&self, desejados: u64) -> Result<u64, &'static str> {
        self.reiniciar()?;
        self.acender(RECONHECIDO);
        self.acender(DRIVER);

        let oferecidos = self.recursos_oferecidos();
        let aceitos = oferecidos & desejados;

        if aceitos & VERSAO_1 == 0 {
            self.abortar();
            return Err("dispositivo nao fala virtio 1.0");
        }

        self.escrever_recursos(aceitos);
        self.acender(RECURSOS_ACEITOS);

        // A releitura não é paranoia: é o único jeito de o dispositivo dizer
        // "não aceito esse conjunto". Ele apaga o bit, e a especificação manda
        // conferir antes de prosseguir.
        if self.estado() & RECURSOS_ACEITOS == 0 {
            self.abortar();
            return Err("dispositivo recusou os recursos");
        }

        Ok(aceitos)
    }

    /// Autoriza o dispositivo a começar a trabalhar.
    ///
    /// Só depois de as filas estarem montadas e habilitadas.
    pub fn liberar(&self) {
        self.acender(PRONTO);
    }

    /// Diz ao dispositivo que desistimos dele.
    ///
    /// Vale a escrita mesmo quando vamos embora: um dispositivo que ficou em
    /// `DRIVER` sem nunca chegar a `PRONTO` é indistinguível de um driver que
    /// travou no meio. `FALHOU` é a diferença entre as duas coisas, e quem lê
    /// isso é o hospedeiro ou o próximo driver.
    pub fn abortar(&self) {
        self.acender(FALHOU);
    }

    /// Os 64 bits de recursos que o dispositivo oferece.
    ///
    /// São lidos em duas metades porque o registrador tem 32 bits: escreve-se
    /// qual metade se quer num seletor, e lê-se. É o mesmo padrão de "janela
    /// deslizante" do par de portas do PCI, e pela mesma razão — o espaço de
    /// recursos cresceu depois que a largura do registrador já estava fixada.
    fn recursos_oferecidos(&self) -> u64 {
        let mut valor = 0u64;
        for metade in 0..2u32 {
            if !self
                .comum
                .escrever_u32(comum::SELETOR_DE_RECURSOS_DO_DISPOSITIVO, metade)
            {
                return 0;
            }
            let parte = self
                .comum
                .ler_u32(comum::RECURSOS_DO_DISPOSITIVO)
                .unwrap_or(0);
            valor |= (parte as u64) << (metade * 32);
        }
        valor
    }

    fn escrever_recursos(&self, valor: u64) {
        for metade in 0..2u32 {
            let _ = self
                .comum
                .escrever_u32(comum::SELETOR_DE_RECURSOS_DO_DRIVER, metade);
            let _ = self
                .comum
                .escrever_u32(comum::RECURSOS_DO_DRIVER, (valor >> (metade * 32)) as u32);
        }
    }

    /// Quantos descritores a fila `indice` comporta, ou zero se ela não existe.
    pub fn tamanho_da_fila(&self, indice: u16) -> u16 {
        if !self.comum.escrever_u16(comum::SELETOR_DE_FILA, indice) {
            return 0;
        }
        self.comum.ler_u16(comum::TAMANHO_DA_FILA).unwrap_or(0)
    }

    /// Entrega ao dispositivo os endereços físicos das três estruturas da fila
    /// e a liga.
    ///
    /// Devolve o deslocamento de notificação que o dispositivo atribuiu a ela.
    ///
    /// Os endereços são **físicos** porque quem vai segui-los é o dispositivo,
    /// e ele não passa pela MMU do processador. É a distinção que torna um
    /// driver de DMA diferente de todo o resto do kernel: aqui um `u64` que
    /// parece um endereço não pode ser desreferenciado.
    pub fn configurar_fila(
        &self,
        indice: u16,
        tamanho: u16,
        descritores: u64,
        disponiveis: u64,
        usados: u64,
    ) -> Result<u16, &'static str> {
        if !self.comum.escrever_u16(comum::SELETOR_DE_FILA, indice) {
            return Err("seletor de fila fora da regiao comum");
        }

        let escritas = self.comum.escrever_u16(comum::TAMANHO_DA_FILA, tamanho)
            && self
                .comum
                .escrever_u16(comum::VETOR_MSIX_DA_FILA, SEM_VETOR)
            && self.comum.escrever_u64(comum::DESCRITORES, descritores)
            && self.comum.escrever_u64(comum::DISPONIVEIS, disponiveis)
            && self.comum.escrever_u64(comum::USADOS, usados);
        if !escritas {
            return Err("configuracao de fila fora da regiao comum");
        }

        let notificacao = self
            .comum
            .ler_u16(comum::DESLOCAMENTO_DE_NOTIFICACAO)
            .ok_or("deslocamento de notificacao fora da regiao comum")?;

        // Por último, e só depois de os endereços estarem escritos: a partir
        // daqui o dispositivo pode ler a fila.
        if !self.comum.escrever_u16(comum::FILA_HABILITADA, 1) {
            return Err("habilitacao de fila fora da regiao comum");
        }

        Ok(notificacao)
    }

    /// Avisa o dispositivo de que há trabalho na fila.
    pub fn notificar(&self, deslocamento_da_fila: u16, indice_da_fila: u16) {
        let onde = deslocamento_da_fila as u64 * self.multiplicador_de_notificacao as u64;
        // O valor escrito é o número da fila. Quando cada fila tem endereço
        // próprio o dispositivo já sabe qual é e o ignora; quando todas
        // compartilham um endereço, é ele que distingue.
        let _ = self.notificacao.escrever_u16(onde, indice_da_fila);
    }
}
