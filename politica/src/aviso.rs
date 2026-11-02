//! O aviso da malha (DS-1): a conta pura de **quando** o kernel avisa um
//! processo, no canal de eventos dele, que um objeto da malha dele ficou
//! pronto.
//!
//! # O que é
//!
//! Um processo do Duke tem um fio só. Um pedido que espera — `stream.read`,
//! `stream.accept`, `fabric.recv` com `wait` — espera **um** objeto, e um
//! fio parado nele não vê o resto: a tecla, o outro fluxo, o pedido novo no
//! endpoint. O pseudo-terminal e as janelas já resolveram isso do mesmo
//! jeito: a espera é uma só, no canal de eventos do processo, e o kernel
//! avisa ali que há o que fazer. O aviso da malha põe os endpoints e as
//! pontas de fluxo no mesmo lugar.
//!
//! O processo pede o aviso no mesmo pedido que cria ou aceita o objeto —
//! `fabric.offer`, `stream.open`, `stream.accept`, com `notify` —, decidido
//! pelo gate como sempre. Daí em diante, quando o objeto fica pronto, o
//! kernel publica no canal um evento que diz **só** o tipo do objeto, o
//! número dele e os bits de prontidão. Ler, escrever, aceitar e receber
//! continuam sendo pedidos ao gate: o aviso não é dado, não é autoridade e
//! não é promessa — o pedido que segue pode ser recusado, ou não achar nada.
//!
//! # A conta
//!
//! Cada designação é uma máquina pequena, [`Designacao`]:
//!
//! - **borda com rearme pela operação**: um objeto tem no máximo um aviso
//!   não consumido ([`Situacao::Avisado`]); qualquer operação do dono sobre
//!   ele o consome ([`Designacao::operou`]), e o próximo nível pronto avisa
//!   de novo. É o que impede a enxurrada e o despertar perdido;
//! - **o espaço só para quem o quer**: o nível de uma ponta quase sempre tem
//!   espaço para escrever, e avisar disso a cada operação seria acordar o
//!   processo à toa. `GRAVAVEL` só vale para quem esbarrou no cheio — a
//!   escrita que não coube inteira — e para quem abriu, até a abertura;
//! - **o fim, uma vez**: `FIM` é o último aviso de um objeto; depois dele, a
//!   designação acabou ([`Situacao::Dito`]);
//! - **o canal cheio** deixa o aviso devido ([`Situacao::Devido`]), com os
//!   bits que se juntarem enquanto isso, e a nova tentativa o entrega uma
//!   vez só.
//!
//! O nível — o que o objeto tem agora — é do kernel: os buffers do fluxo,
//! os pedidos e as entregas do endpoint. Aqui só se decide, a partir dele, o
//! que dizer e quando.
//!
//! # Por que é puro
//!
//! Pelo mesmo motivo do resto deste pacote: a conta é testada no
//! hospedeiro, transição por transição, e o kernel só lhe dá o nível e
//! publica o que ela manda.

/// Os bits de prontidão de um aviso, no campo `c` do evento — os mesmos de
/// `protocolo::usuario::evento::malha`, conferidos pelo kernel na
/// compilação.
pub mod bits {
    /// Ponta: há dado para ler, ou o fim do sentido que ainda não foi lido.
    pub const LEGIVEL: u8 = 1 << 0;
    /// Ponta: há espaço para escrever — para quem esbarrou no cheio —, ou a
    /// abertura, para quem abriu.
    pub const GRAVAVEL: u8 = 1 << 1;
    /// O objeto acabou: a próxima operação diz o motivo.
    pub const FIM: u8 = 1 << 2;
    /// Endpoint: um pedido de fluxo esperando o aceite.
    pub const PEDIDO: u8 = 1 << 3;
    /// Endpoint: uma entrega pendente, que ninguém leu ainda.
    pub const ENTREGA: u8 = 1 << 4;
    /// Os bits que uma ponta de fluxo diz.
    pub const DA_PONTA: u8 = LEGIVEL | GRAVAVEL | FIM;
    /// Os bits que um endpoint diz.
    pub const DO_ENDPOINT: u8 = PEDIDO | ENTREGA | FIM;
    /// Todos os bits que esta versão conhece.
    pub const CONHECIDOS: u8 = DA_PONTA | DO_ENDPOINT;
}

/// O tipo do objeto, no campo `a` do evento: um endpoint.
pub const ENDPOINT: i64 = 1;
/// O tipo do objeto, no campo `a` do evento: uma ponta de fluxo.
pub const PONTA: i64 = 2;

/// Onde está a designação de um objeto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Situacao {
    /// Nenhum aviso no canal: o próximo nível pronto avisa.
    Livre,
    /// Há um aviso no canal que o dono ainda não consumiu.
    Avisado,
    /// O canal estava cheio: estes bits esperam a próxima tentativa.
    Devido(u8),
    /// O `FIM` foi dito, ou o canal sumiu: nada mais.
    Dito,
}

/// Um aviso que a conta mandou publicar: os bits, e a geração da
/// designação quando ele nasceu — a operação do dono que vier antes de quem
/// publica dizer o desfecho já o consumiu, e o desfecho dele não mexe mais
/// em nada ([`Designacao::publicado`], [`Designacao::cheio`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aviso {
    /// Os bits de prontidão.
    pub bits: u8,
    geracao: u32,
}

/// A designação de um objeto da malha: o que o kernel já disse ao dono, e o
/// que ele quer saber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Designacao {
    situacao: Situacao,
    /// Quer saber do espaço para escrever: quem abriu, até a abertura, e
    /// quem esbarrou no cheio, até o aviso.
    quer_gravar: bool,
    /// Os bits que este tipo de objeto diz.
    mascara: u8,
    /// Quantas operações do dono já houve: o aviso de uma geração anterior
    /// já foi consumido.
    geracao: u32,
}

impl Designacao {
    /// A designação de uma ponta de fluxo. A de quem abriu quer saber da
    /// abertura — o primeiro `GRAVAVEL`; a de quem aceitou já pode escrever.
    pub const fn da_ponta(quem_abriu: bool) -> Designacao {
        Designacao {
            situacao: Situacao::Livre,
            quer_gravar: quem_abriu,
            mascara: bits::DA_PONTA,
            geracao: 0,
        }
    }

    /// A designação de um endpoint: pedidos de fluxo, entregas e o fim.
    pub const fn do_endpoint() -> Designacao {
        Designacao {
            situacao: Situacao::Livre,
            quer_gravar: false,
            mascara: bits::DO_ENDPOINT,
            geracao: 0,
        }
    }

    /// Onde ela está.
    pub const fn situacao(&self) -> Situacao {
        self.situacao
    }

    /// Se ela quer saber do espaço para escrever.
    pub const fn quer_gravar(&self) -> bool {
        self.quer_gravar
    }

    /// O que o nível `nivel` diz a este dono: só os bits do tipo dele, e o
    /// espaço só se ele o quer. Zero é nada a dizer.
    pub const fn diria(&self, nivel: u8) -> u8 {
        let mut b = nivel & self.mascara;
        if !self.quer_gravar {
            b &= !bits::GRAVAVEL;
        }
        b
    }

    /// O objeto mudou, e o nível dele agora é `nivel`. Devolve os bits a
    /// publicar, se é hora — e a designação passa a [`Situacao::Avisado`]:
    /// quem publica diz depois se o aviso coube ([`Designacao::publicado`])
    /// ou não ([`Designacao::cheio`]).
    ///
    /// Nada, com um aviso no canal ainda não consumido: o dono vai operar, e
    /// a operação rearma. Com um aviso devido, os bits se juntam a ele.
    pub fn mudou(&mut self, nivel: u8) -> Option<Aviso> {
        let b = self.diria(nivel);
        match self.situacao {
            Situacao::Dito | Situacao::Avisado => None,
            Situacao::Devido(d) => {
                self.situacao = Situacao::Devido(d | b);
                None
            }
            Situacao::Livre if b == 0 => None,
            Situacao::Livre => {
                self.situacao = Situacao::Avisado;
                Some(Aviso {
                    bits: b,
                    geracao: self.geracao,
                })
            }
        }
    }

    /// O dono operou sobre o objeto — leu, escreveu, aceitou, recebeu, viu o
    /// estado —, pelo gate: o aviso que havia está consumido, e o devido
    /// também. `esbarrou` diz que a escrita não coube inteira: o dono quer
    /// saber quando houver espaço.
    pub fn operou(&mut self, esbarrou: bool) {
        if self.situacao == Situacao::Dito {
            return;
        }
        self.quer_gravar |= esbarrou && self.mascara & bits::GRAVAVEL != 0;
        self.situacao = Situacao::Livre;
        self.geracao = self.geracao.wrapping_add(1);
    }

    /// O aviso `a` foi publicado. O fim dito acaba a designação, sempre. O
    /// espaço dito não é mais querido até a próxima escrita que esbarrar —
    /// se nenhuma operação veio depois dele: a escrita que esbarrou depois
    /// do aviso quer o próximo.
    pub fn publicado(&mut self, a: Aviso) {
        if a.bits & bits::FIM != 0 {
            self.situacao = Situacao::Dito;
            return;
        }
        if a.geracao == self.geracao && a.bits & bits::GRAVAVEL != 0 {
            self.quer_gravar = false;
        }
    }

    /// O canal estava cheio: o aviso `a` fica devido — se nenhuma operação
    /// veio depois dele. Com uma, ele já foi consumido, e a operação já
    /// rearmou.
    pub fn cheio(&mut self, a: Aviso) {
        if self.situacao == Situacao::Dito || a.geracao != self.geracao {
            return;
        }
        self.situacao = Situacao::Devido(match self.situacao {
            Situacao::Devido(d) => d | a.bits,
            _ => a.bits,
        });
    }

    /// A nova tentativa do aviso devido: o que publicar, e a designação
    /// volta a [`Situacao::Avisado`] — quem publica diz se coube.
    pub fn retentar(&mut self) -> Option<Aviso> {
        match self.situacao {
            Situacao::Devido(d) if d != 0 => {
                self.situacao = Situacao::Avisado;
                Some(Aviso {
                    bits: d,
                    geracao: self.geracao,
                })
            }
            Situacao::Devido(_) => {
                self.situacao = Situacao::Livre;
                None
            }
            _ => None,
        }
    }

    /// O canal sumiu — o dono o fechou, ou morreu —, ou o objeto acabou de
    /// outro jeito: nada mais.
    pub fn largada(&mut self) {
        self.situacao = Situacao::Dito;
    }

    /// Se não há mais nada a dizer: a designação pode sair.
    pub const fn acabou(&self) -> bool {
        matches!(self.situacao, Situacao::Dito)
    }
}

/// Os três campos do evento de um aviso: o tipo do objeto, o número dele e
/// os bits. Nada mais cabe aqui — nem byte, nem motivo, nem quem.
pub const fn campos(tipo: i64, numero: u64, b: u8) -> (i64, i64, i64) {
    (
        tipo,
        (numero & (i64::MAX as u64)) as i64,
        (b & bits::CONHECIDOS) as i64,
    )
}

/// O que um programa lê dos campos de um evento de aviso: o tipo, o número
/// e os bits que esta versão conhece — os outros, ignorados. `None` com um
/// tipo de objeto desconhecido ou um número negativo.
pub const fn ler_campos(a: i64, b: i64, c: i64) -> Option<(i64, u64, u8)> {
    if (a != ENDPOINT && a != PONTA) || b < 0 {
        return None;
    }
    Some((a, b as u64, (c as u8) & bits::CONHECIDOS))
}

/// O número de um id da malha, `<época>:<n>` — o mesmo que o aviso leva no
/// campo `b`.
pub fn numero_do_id(id: &str) -> Option<u64> {
    let (_, n) = id.rsplit_once(':')?;
    if n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

#[cfg(test)]
mod testes {
    use super::bits::*;
    use super::*;

    /// Os bits de um aviso, se a conta mandou publicar.
    fn b(a: Option<Aviso>) -> Option<u8> {
        a.map(|a| a.bits)
    }

    /// NH01: a borda — de nada a dado publica uma vez; mais dado com o
    /// aviso não consumido não publica.
    #[test]
    fn nh01_a_borda_publica_uma_vez() {
        let mut d = Designacao::da_ponta(false);
        assert_eq!(d.mudou(0), None);
        assert_eq!(d.situacao(), Situacao::Livre);
        let a = d.mudou(LEGIVEL).expect("o primeiro dado avisa");
        assert_eq!(a.bits, LEGIVEL);
        assert_eq!(d.situacao(), Situacao::Avisado);
        d.publicado(a);
        assert_eq!(d.mudou(LEGIVEL), None);
        assert_eq!(d.mudou(LEGIVEL | FIM), None);
        assert_eq!(d.situacao(), Situacao::Avisado);
        // O que ele diria é o que importa para as medidas.
        assert_eq!(d.diria(LEGIVEL | GRAVAVEL), LEGIVEL);
    }

    /// NH02: o rearme — a operação consome o aviso; pronto ainda, o próximo
    /// nível avisa de novo; nada pronto, nada.
    #[test]
    fn nh02_a_operacao_rearma() {
        let mut d = Designacao::da_ponta(false);
        let a = d.mudou(LEGIVEL).expect("avisa");
        d.publicado(a);
        d.operou(false);
        assert_eq!(d.situacao(), Situacao::Livre);
        // Ainda pronto — a leitura não esvaziou —: avisa de novo.
        let a = d.mudou(LEGIVEL).expect("avisa de novo");
        d.publicado(a);
        d.operou(false);
        // Nada pronto: nada.
        assert_eq!(d.mudou(0), None);
        assert_eq!(d.situacao(), Situacao::Livre);
        // O dado seguinte avisa.
        let a = d.mudou(LEGIVEL).expect("o dado seguinte avisa");
        // A operação consome também o aviso devido — e o desfecho do aviso
        // de antes dela não o faz voltar.
        d.cheio(a);
        assert_eq!(d.situacao(), Situacao::Devido(LEGIVEL));
        d.operou(false);
        assert_eq!(d.situacao(), Situacao::Livre);
        assert_eq!(d.retentar(), None);
        let a = d.mudou(LEGIVEL).expect("avisa");
        d.operou(false);
        d.cheio(a);
        assert_eq!(d.situacao(), Situacao::Livre);
    }

    /// NH03: `GRAVAVEL` só depois da escrita que esbarrou no cheio, e na
    /// abertura para quem abriu; uma vez por esbarrão — e o esbarrão que
    /// vem depois do aviso quer o próximo.
    #[test]
    fn nh03_o_espaco_so_para_quem_o_quer() {
        // Quem aceitou: o espaço sozinho não avisa.
        let mut d = Designacao::da_ponta(false);
        assert_eq!(d.mudou(GRAVAVEL), None);
        let a = d.mudou(GRAVAVEL | LEGIVEL).expect("o dado avisa");
        assert_eq!(a.bits, LEGIVEL);
        d.publicado(a);
        // A escrita esbarrou: o espaço que volta avisa, uma vez.
        d.operou(true);
        assert!(d.quer_gravar());
        assert_eq!(d.mudou(0), None);
        let a = d.mudou(GRAVAVEL).expect("o espaco avisa");
        assert_eq!(a.bits, GRAVAVEL);
        d.publicado(a);
        assert!(!d.quer_gravar());
        d.operou(false);
        assert_eq!(d.mudou(GRAVAVEL), None);
        // O esbarrão entre o aviso e o desfecho dele: o desfecho não apaga
        // o querer de agora.
        d.operou(true);
        let a = d.mudou(GRAVAVEL).expect("o espaco avisa");
        d.operou(true);
        d.publicado(a);
        assert!(d.quer_gravar());
        assert_eq!(b(d.mudou(GRAVAVEL)), Some(GRAVAVEL));
        // Quem abriu: a abertura avisa.
        let mut x = Designacao::da_ponta(true);
        assert_eq!(x.mudou(0), None);
        let a = x.mudou(GRAVAVEL).expect("a abertura avisa");
        x.publicado(a);
        x.operou(false);
        assert_eq!(x.mudou(GRAVAVEL), None);
        // O endpoint não diz espaço, nem quando a operação diria esbarrão.
        let mut e = Designacao::do_endpoint();
        e.operou(true);
        assert!(!e.quer_gravar());
        assert_eq!(e.mudou(GRAVAVEL | LEGIVEL), None);
        assert_eq!(b(e.mudou(PEDIDO | ENTREGA)), Some(PEDIDO | ENTREGA));
    }

    /// NH04: o `FIM` sempre, uma vez, com os bits ainda não publicados; e
    /// depois dele, nada.
    #[test]
    fn nh04_o_fim_uma_vez() {
        let mut d = Designacao::da_ponta(false);
        let a = d.mudou(LEGIVEL).expect("avisa");
        d.cheio(a);
        assert_eq!(d.mudou(FIM), None);
        assert_eq!(d.situacao(), Situacao::Devido(LEGIVEL | FIM));
        let a = d.retentar().expect("o devido sai");
        assert_eq!(a.bits, LEGIVEL | FIM);
        d.publicado(a);
        assert!(d.acabou());
        d.operou(true);
        assert!(d.acabou());
        assert_eq!(d.mudou(LEGIVEL | GRAVAVEL | FIM), None);
        assert_eq!(d.retentar(), None);
        // O fim de quem não esperava nada também avisa — e acaba mesmo com
        // uma operação no meio.
        let mut e = Designacao::do_endpoint();
        let a = e.mudou(FIM).expect("o fim avisa");
        e.operou(false);
        e.publicado(a);
        assert!(e.acabou());
    }

    /// NH05: o canal cheio — o aviso fica devido, junta os bits que vierem,
    /// e a nova tentativa o entrega uma vez só.
    #[test]
    fn nh05_o_canal_cheio() {
        let mut d = Designacao::do_endpoint();
        let a = d.mudou(PEDIDO).expect("avisa");
        d.cheio(a);
        assert_eq!(d.situacao(), Situacao::Devido(PEDIDO));
        assert_eq!(d.mudou(ENTREGA), None);
        // Cheio de novo: continua devido, com tudo.
        let a = d.retentar().expect("tenta de novo");
        assert_eq!(a.bits, PEDIDO | ENTREGA);
        d.cheio(a);
        assert_eq!(d.situacao(), Situacao::Devido(PEDIDO | ENTREGA));
        let a = d.retentar().expect("tenta de novo");
        assert_eq!(a.bits, PEDIDO | ENTREGA);
        d.publicado(a);
        assert_eq!(d.situacao(), Situacao::Avisado);
        assert_eq!(d.retentar(), None);
        assert_eq!(d.mudou(PEDIDO), None);
    }

    /// NH06: sem ouvinte, a designação cai, e nada tenta para sempre.
    #[test]
    fn nh06_sem_ouvinte_cai() {
        let mut d = Designacao::da_ponta(true);
        assert_eq!(b(d.mudou(GRAVAVEL)), Some(GRAVAVEL));
        d.largada();
        assert!(d.acabou());
        assert_eq!(d.retentar(), None);
        assert_eq!(d.mudou(LEGIVEL | FIM), None);
        let mut e = Designacao::do_endpoint();
        let a = e.mudou(PEDIDO).expect("avisa");
        e.cheio(a);
        e.largada();
        assert_eq!(e.retentar(), None);
        e.cheio(a);
        assert!(e.acabou());
    }

    /// NH07: a codificação vai e volta; quem lê ignora o bit e recusa o tipo
    /// que não conhece; o número do id é o do aviso.
    #[test]
    fn nh07_a_codificacao() {
        for tipo in [ENDPOINT, PONTA] {
            for n in [0u64, 1, 42, 1 << 40] {
                for x in 0..=CONHECIDOS {
                    let (a, bb, c) = campos(tipo, n, x);
                    assert_eq!(ler_campos(a, bb, c), Some((tipo, n, x & CONHECIDOS)));
                }
            }
        }
        // Um bit desconhecido — de uma versão mais nova — é ignorado.
        assert_eq!(
            ler_campos(PONTA, 7, (LEGIVEL | 1 << 7) as i64),
            Some((PONTA, 7, LEGIVEL))
        );
        assert_eq!(ler_campos(PONTA, 7, 1 << 9), Some((PONTA, 7, 0)));
        // Um tipo desconhecido, ou um número negativo, não é aviso.
        assert_eq!(ler_campos(3, 7, 1), None);
        assert_eq!(ler_campos(0, 7, 1), None);
        assert_eq!(ler_campos(PONTA, -1, 1), None);
        // O número do id.
        assert_eq!(numero_do_id("00aa11bb22cc33dd:17"), Some(17));
        assert_eq!(numero_do_id("x:0"), Some(0));
        assert_eq!(numero_do_id("17"), None);
        assert_eq!(numero_do_id("x:"), None);
        assert_eq!(numero_do_id("x:-1"), None);
        assert_eq!(numero_do_id("x:1a"), None);
    }

    /// NH08: o evento só tem o tipo, o número e os bits — nenhum campo vem
    /// de fora da conta: os bits fora do vocabulário não passam, e o número
    /// não fica negativo.
    #[test]
    fn nh08_o_evento_so_tem_tipo_numero_e_bits() {
        let (a, bb, c) = campos(PONTA, u64::MAX, u8::MAX);
        assert_eq!(a, PONTA);
        assert!(bb >= 0);
        assert_eq!(c, CONHECIDOS as i64);
        // A designação nunca devolve bits fora do tipo dela.
        let mut p = Designacao::da_ponta(true);
        let mut e = Designacao::do_endpoint();
        for nivel in 0..=u8::MAX {
            p.operou(true);
            if let Some(x) = p.mudou(nivel) {
                assert_eq!(x.bits & !DA_PONTA, 0);
            }
            e.operou(false);
            if let Some(x) = e.mudou(nivel) {
                assert_eq!(x.bits & !DO_ENDPOINT, 0);
            }
        }
    }
}
