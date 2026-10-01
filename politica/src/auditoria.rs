//! A auditoria encadeada.
//!
//! # O que um registro diz
//!
//! Quem (sessão, agente, chave pública, papel), o quê (método e recurso),
//! o desfecho (o resultado em uma palavra e o código), quando (sequência e
//! milissegundos desde o boot), um BLAKE2s dos parâmetros e um detalhe curto.
//! Os parâmetros não entram por inteiro: podem trazer o que um agente
//! escreveu num campo, ou uma prova administrativa. O resumo prova o que foi
//! pedido para quem tem o pedido, e não o revela para quem só tem a
//! auditoria.
//!
//! # A cadeia
//!
//! Cada registro carrega o elo do anterior, e o seu elo é o BLAKE2s do elo
//! anterior com a codificação do registro:
//!
//! ```text
//! elo(n) = BLAKE2s("Duke auditoria v1" || elo(n-1) || codificacao(n))
//! ```
//!
//! Mudar, tirar ou reordenar um registro muda todos os elos dali para a
//! frente. A cabeça — o elo do último — é o que se ancora fora da máquina:
//! quem guardou a cabeça de ontem confere que a cadeia de hoje a contém.
//!
//! # Memória, e não disco
//!
//! O disco é só leitura. A cadeia mora num anel de tamanho fixo; quando um
//! registro sai pela ponta, o elo dele fica guardado como **âncora**, e a
//! janela que sobra continua verificável a partir dela.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};

use crate::codigo::Codigo;

/// O rótulo do elo, para ele nunca coincidir com outro resumo do sistema.
const ROTULO: &[u8] = b"Duke auditoria v1";

/// O elo antes do primeiro registro.
pub const GENESE: [u8; 32] = [0; 32];

/// O maior detalhe, em bytes.
pub const MAIOR_DETALHE: usize = 96;

/// O que um registro diz, antes de entrar na cadeia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evento {
    pub ts_ms: u64,
    pub sessao: u8,
    pub agente: String,
    pub chave: Option<[u8; 32]>,
    pub papel: String,
    pub metodo: String,
    pub recurso: String,
    pub codigo: Codigo,
    pub parametros: [u8; 32],
    pub detalhe: String,
}

/// Um registro na cadeia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registro {
    pub seq: u64,
    pub evento: Evento,
    /// O elo do registro anterior.
    pub anterior: [u8; 32],
    /// O elo deste.
    pub elo: [u8; 32],
}

/// O BLAKE2s dos parâmetros de um pedido.
pub fn resumo_dos_parametros(parametros: &[u8]) -> [u8; 32] {
    Blake2s256::digest(parametros).into()
}

fn campo(h: &mut Blake2s256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_le_bytes());
    h.update(bytes);
}

/// O elo de um registro, dado o anterior.
///
/// A codificação é a mesma de [`crate::Politica`] para os dois lados: cada
/// campo variável com o tamanho na frente, para dois registros diferentes
/// nunca virarem os mesmos bytes.
pub fn elo(anterior: &[u8; 32], seq: u64, e: &Evento) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(ROTULO);
    h.update(anterior);
    h.update(seq.to_le_bytes());
    h.update(e.ts_ms.to_le_bytes());
    h.update([e.sessao]);
    campo(&mut h, e.agente.as_bytes());
    match &e.chave {
        Some(k) => {
            h.update([1]);
            h.update(k);
        }
        None => h.update([0]),
    }
    campo(&mut h, e.papel.as_bytes());
    campo(&mut h, e.metodo.as_bytes());
    campo(&mut h, e.recurso.as_bytes());
    h.update([e.codigo as u8]);
    h.update(e.parametros);
    campo(&mut h, e.detalhe.as_bytes());
    h.finalize().into()
}

/// A cadeia, num anel.
pub struct Cadeia {
    registros: VecDeque<Registro>,
    capacidade: usize,
    /// O elo do último que saiu pela ponta; [`GENESE`] enquanto nenhum saiu.
    ancora: [u8; 32],
    proximo_seq: u64,
}

impl Cadeia {
    /// Uma cadeia vazia que guarda até `capacidade` registros.
    pub fn nova(capacidade: usize) -> Cadeia {
        Cadeia {
            registros: VecDeque::new(),
            capacidade: capacidade.max(1),
            ancora: GENESE,
            proximo_seq: 1,
        }
    }

    /// A cabeça: o elo do último registro.
    pub fn cabeca(&self) -> [u8; 32] {
        self.registros.back().map_or(self.ancora, |r| r.elo)
    }

    /// O número do último registro, zero sem nenhum.
    pub fn ultima_seq(&self) -> u64 {
        self.proximo_seq - 1
    }

    /// O elo de onde a janela guardada parte.
    pub fn ancora(&self) -> [u8; 32] {
        self.ancora
    }

    /// Acrescenta um registro e devolve o número dele.
    pub fn anexar(&mut self, mut evento: Evento) -> u64 {
        // O detalhe tem teto, cortado numa fronteira de caractere.
        if evento.detalhe.len() > MAIOR_DETALHE {
            let mut fim = MAIOR_DETALHE;
            while !evento.detalhe.is_char_boundary(fim) {
                fim -= 1;
            }
            evento.detalhe.truncate(fim);
        }
        let anterior = self.cabeca();
        let seq = self.proximo_seq;
        let elo = elo(&anterior, seq, &evento);
        if self.registros.len() == self.capacidade
            && let Some(saiu) = self.registros.pop_front()
        {
            self.ancora = saiu.elo;
        }
        self.registros.push_back(Registro {
            seq,
            evento,
            anterior,
            elo,
        });
        self.proximo_seq += 1;
        seq
    }

    /// Os últimos `n` registros, do mais antigo ao mais novo.
    pub fn ultimos(&self, n: usize) -> impl Iterator<Item = &Registro> {
        let pular = self.registros.len().saturating_sub(n);
        self.registros.iter().skip(pular)
    }

    /// Quantos registros a janela guarda.
    pub fn guardados(&self) -> usize {
        self.registros.len()
    }

    /// Refaz a cadeia guardada a partir da âncora. Devolve a cabeça, ou o
    /// número do primeiro registro que não confere.
    pub fn verificar(&self) -> Result<[u8; 32], u64> {
        verificar(self.ancora, self.registros.iter())
    }
}

/// Refaz uma sequência de registros a partir de um elo. É a conta que o
/// `xtask` faz do lado de fora, com os registros que o kernel mostrou.
pub fn verificar<'a>(
    ancora: [u8; 32],
    registros: impl Iterator<Item = &'a Registro>,
) -> Result<[u8; 32], u64> {
    let mut anterior = ancora;
    let mut seq_esperada: Option<u64> = None;
    for r in registros {
        if r.anterior != anterior || seq_esperada.is_some_and(|s| s != r.seq) {
            return Err(r.seq);
        }
        if elo(&anterior, r.seq, &r.evento) != r.elo {
            return Err(r.seq);
        }
        anterior = r.elo;
        seq_esperada = Some(r.seq + 1);
    }
    Ok(anterior)
}

/// Os registros, para quem precisa de uma cópia.
pub fn copiar<'a>(registros: impl Iterator<Item = &'a Registro>) -> Vec<Registro> {
    registros.cloned().collect()
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::string::ToString;

    fn evento(i: u64) -> Evento {
        Evento {
            ts_ms: i * 10,
            sessao: 2,
            agente: "agente-2".to_string(),
            chave: Some([7; 32]),
            papel: "operador".to_string(),
            metodo: "fs.read".to_string(),
            recurso: "/dados/x".to_string(),
            codigo: Codigo::Allow,
            parametros: resumo_dos_parametros(b"{}"),
            detalhe: String::new(),
        }
    }

    #[test]
    fn cadeia_inteira_confere() {
        let mut c = Cadeia::nova(100);
        for i in 0..10 {
            c.anexar(evento(i));
        }
        assert_eq!(c.verificar(), Ok(c.cabeca()));
        assert_eq!(c.ultima_seq(), 10);
    }

    /// Cada campo, mudado sozinho num registro do meio, quebra a cadeia
    /// ali.
    #[test]
    fn qualquer_mudanca_quebra() {
        let mut c = Cadeia::nova(100);
        for i in 0..5 {
            c.anexar(evento(i));
        }
        let original: Vec<Registro> = copiar(c.ultimos(5));
        let mudancas: [fn(&mut Evento); 8] = [
            |e| e.ts_ms += 1,
            |e| e.sessao = 3,
            |e| e.agente.push('x'),
            |e| e.chave = None,
            |e| e.papel = "sistema".to_string(),
            |e| e.codigo = Codigo::DenyPermission,
            |e| e.parametros[0] ^= 1,
            |e| e.detalhe.push('x'),
        ];
        for (i, mudar) in mudancas.iter().enumerate() {
            let mut copia = original.clone();
            mudar(&mut copia[2].evento);
            assert_eq!(verificar(GENESE, copia.iter()), Err(3), "mudanca {i}");
        }
        // Tirar um registro do meio também.
        let mut sem = original.clone();
        sem.remove(2);
        assert!(verificar(GENESE, sem.iter()).is_err());
    }

    /// Com o anel cheio, os mais velhos saem e a janela que sobra confere a
    /// partir da âncora.
    #[test]
    fn anel_guarda_a_ancora() {
        let mut c = Cadeia::nova(4);
        for i in 0..10 {
            c.anexar(evento(i));
        }
        assert_eq!(c.guardados(), 4);
        assert_ne!(c.ancora(), GENESE);
        assert_eq!(c.verificar(), Ok(c.cabeca()));
        assert_eq!(c.ultimos(10).next().map(|r| r.seq), Some(7));
    }

    #[test]
    fn detalhe_tem_teto() {
        let mut c = Cadeia::nova(4);
        let mut e = evento(0);
        e.detalhe = "é".repeat(100);
        c.anexar(e);
        let d = &c.ultimos(1).next().unwrap().evento.detalhe;
        assert!(d.len() <= MAIOR_DETALHE);
    }
}
