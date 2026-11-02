//! O quadro do SDK: mensagens sobre os bytes de um fluxo da malha.
//!
//! Um fluxo leva bytes, na ordem, sem fronteira nenhuma: duas escritas podem
//! chegar numa leitura, e uma escrita em duas. Quem conversa por mensagens
//! precisa de onde uma acaba e a outra começa. O quadro é o mais simples
//! possível: **4 bytes de comprimento, little-endian, e o corpo**.
//!
//! - **Sem número de canal, sem subcanais.** Um diálogo por fluxo: o quadro
//!   não multiplexa conversas dentro de um fluxo — quem quer duas abre dois,
//!   cada um decidido pelo gate, dentro dos tetos de sempre.
//! - **O teto é de quem lê.** O [`Leitor`] recusa a mensagem maior que o teto
//!   dele antes de juntar os bytes dela, até [`MAIOR_CORPO`]: o outro lado
//!   não decide quanto da memória daqui ele ocupa.
//! - **O corte se acusa.** O fim do fluxo no meio de uma mensagem é um erro
//!   ([`Erro::Cortado`]), e não uma mensagem menor.
//!
//! O conteúdo continua sendo entrada não confiável: o quadro só diz onde ela
//! começa e acaba. Mora aqui, e não no runtime, para ser testado no
//! hospedeiro; o runtime (`programas::quadro`) o leva ao fluxo.

use alloc::vec::Vec;

/// O tamanho do cabeçalho: o comprimento do corpo, em 4 bytes LE.
pub const CABECALHO: usize = 4;

/// O maior corpo que um quadro leva: 64 KiB.
pub const MAIOR_CORPO: usize = 64 * 1024;

/// Por que um quadro não se monta, ou não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O corpo passa do teto — o de [`MAIOR_CORPO`] para quem escreve, o de
    /// quem lê para o [`Leitor`]. O comprimento que veio.
    Grande(usize),
    /// O fluxo acabou no meio de um quadro.
    Cortado,
}

/// O quadro de `corpo`: o cabeçalho e o corpo, prontos para escrever.
pub fn quadro(corpo: &[u8]) -> Result<Vec<u8>, Erro> {
    if corpo.len() > MAIOR_CORPO {
        return Err(Erro::Grande(corpo.len()));
    }
    let mut q = Vec::with_capacity(CABECALHO + corpo.len());
    q.extend_from_slice(&(corpo.len() as u32).to_le_bytes());
    q.extend_from_slice(corpo);
    Ok(q)
}

/// Quem lê quadros: junta o que o fluxo entrega, em pedaços de qualquer
/// tamanho, e devolve mensagens inteiras.
#[derive(Clone, Debug)]
pub struct Leitor {
    juntado: Vec<u8>,
    teto: usize,
}

impl Leitor {
    /// Um leitor que aceita corpos até `teto` bytes — no máximo
    /// [`MAIOR_CORPO`].
    pub fn novo(teto: usize) -> Leitor {
        Leitor {
            juntado: Vec::new(),
            teto: teto.min(MAIOR_CORPO),
        }
    }

    /// Junta `bytes`, como o fluxo os entregou.
    pub fn juntar(&mut self, bytes: &[u8]) {
        self.juntado.extend_from_slice(bytes);
    }

    /// A próxima mensagem inteira, se já chegou: `Ok(None)` enquanto falta
    /// um pedaço dela; `Err` com o comprimento que passa do teto — e então o
    /// leitor não serve mais: o fluxo deve ser fechado.
    pub fn proximo(&mut self) -> Result<Option<Vec<u8>>, Erro> {
        if self.juntado.len() < CABECALHO {
            return Ok(None);
        }
        let mut c = [0u8; CABECALHO];
        c.copy_from_slice(&self.juntado[..CABECALHO]);
        let n = u32::from_le_bytes(c) as usize;
        if n > self.teto {
            return Err(Erro::Grande(n));
        }
        if self.juntado.len() < CABECALHO + n {
            return Ok(None);
        }
        let corpo = self.juntado[CABECALHO..CABECALHO + n].to_vec();
        self.juntado.drain(..CABECALHO + n);
        Ok(Some(corpo))
    }

    /// O fluxo acabou: `Ok` se nada ficou pela metade.
    pub fn fim(&self) -> Result<(), Erro> {
        if self.juntado.is_empty() {
            Ok(())
        } else {
            Err(Erro::Cortado)
        }
    }

    /// Quantos bytes esperam o resto da mensagem.
    pub fn pendentes(&self) -> usize {
        self.juntado.len()
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// NH09: ida e volta; leituras parciais, de um byte; a mensagem no teto;
    /// a maior que o teto recusada antes de juntar; o corte no fim acusado.
    #[test]
    fn nh09_o_quadro() {
        // Ida e volta, várias mensagens num pedaço só.
        let a = quadro(b"ola").unwrap();
        let b = quadro(b"").unwrap();
        let c = quadro(&[7u8; 1000]).unwrap();
        assert_eq!(&a[..CABECALHO], &3u32.to_le_bytes());
        let mut tudo = Vec::new();
        for q in [&a, &b, &c] {
            tudo.extend_from_slice(q);
        }
        let mut l = Leitor::novo(MAIOR_CORPO);
        l.juntar(&tudo);
        assert_eq!(l.proximo(), Ok(Some(b"ola".to_vec())));
        assert_eq!(l.proximo(), Ok(Some(Vec::new())));
        assert_eq!(l.proximo(), Ok(Some(alloc::vec![7u8; 1000])));
        assert_eq!(l.proximo(), Ok(None));
        assert_eq!(l.fim(), Ok(()));
        // Byte a byte: só a mensagem inteira sai.
        let mut l = Leitor::novo(16);
        let q = quadro(b"partido").unwrap();
        for (i, x) in q.iter().enumerate() {
            assert_eq!(l.proximo(), Ok(None), "saiu antes do byte {i}");
            assert_eq!(l.fim(), if i == 0 { Ok(()) } else { Err(Erro::Cortado) });
            l.juntar(&[*x]);
        }
        assert_eq!(l.proximo(), Ok(Some(b"partido".to_vec())));
        // O teto de quem lê: a mensagem exatamente no teto passa; a maior é
        // recusada pelo cabeçalho, sem esperar o corpo.
        let mut l = Leitor::novo(8);
        l.juntar(&quadro(&[1u8; 8]).unwrap());
        assert_eq!(l.proximo(), Ok(Some(alloc::vec![1u8; 8])));
        l.juntar(&9u32.to_le_bytes());
        assert_eq!(l.proximo(), Err(Erro::Grande(9)));
        // O teto do leitor não passa do maior corpo.
        let mut l = Leitor::novo(usize::MAX);
        l.juntar(&((MAIOR_CORPO + 1) as u32).to_le_bytes());
        assert_eq!(l.proximo(), Err(Erro::Grande(MAIOR_CORPO + 1)));
        // Quem escreve também tem o teto.
        assert_eq!(
            quadro(&alloc::vec![0u8; MAIOR_CORPO]).unwrap().len(),
            CABECALHO + MAIOR_CORPO
        );
        assert_eq!(
            quadro(&alloc::vec![0u8; MAIOR_CORPO + 1]),
            Err(Erro::Grande(MAIOR_CORPO + 1))
        );
        // O corte no fim: o cabeçalho sem o corpo inteiro.
        let mut l = Leitor::novo(64);
        l.juntar(&quadro(b"abcdef").unwrap()[..7]);
        assert_eq!(l.proximo(), Ok(None));
        assert_eq!(l.pendentes(), 7);
        assert_eq!(l.fim(), Err(Erro::Cortado));
    }
}
