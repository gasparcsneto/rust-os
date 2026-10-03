//! A auditoria encadeada.
//!
//! # O que um registro diz
//!
//! Quem (que tipo de titular, sessão, identificador, chave pública, papel),
//! o quê (método e recurso),
//! o desfecho (o resultado em uma palavra e o código), quando (sequência e
//! milissegundos desde o boot), um BLAKE2s dos parâmetros e um detalhe curto.
//! Os parâmetros não entram por inteiro: podem trazer o que um agente
//! escreveu num campo, ou uma prova administrativa. O resumo prova o que foi
//! pedido para quem tem o pedido, e não o revela para quem só tem a
//! auditoria.
//!
//! # Pessoa não é agente
//!
//! O [`Titular`] diz que tipo de identidade agiu, e entra no elo: um
//! registro de pessoa não vira um de agente trocando o texto do nome. O
//! identificador de uma pessoa é `pessoa:<16 hex>` — com um `:` que nenhum
//! nome de agente tem — e a sessão dela, sorteada no login, vai no campo
//! próprio: a mesma pessoa em dois consoles são duas sessões, e duas
//! pessoas no mesmo console, uma depois da outra, também.
//!
//! # A cadeia
//!
//! Cada registro carrega o elo do anterior, e o seu elo é o BLAKE2s do elo
//! anterior com a codificação do registro:
//!
//! ```text
//! elo(n) = BLAKE2s("Duke auditoria v2" || elo(n-1) || codificacao(n))
//! ```
//!
//! Mudar, tirar ou reordenar um registro muda todos os elos dali para a
//! frente. A cabeça — o elo do último — é o que se ancora fora da máquina:
//! quem guardou a cabeça de ontem confere que a cadeia de hoje a contém.
//!
//! # A memória e o disco
//!
//! A cadeia mora num anel de tamanho fixo; quando um registro sai pela
//! ponta, o elo dele fica guardado como **âncora**, e a janela que sobra
//! continua verificável a partir dela.
//!
//! Com a persistência, cada registro vai também para o journal — ver
//! [`codificar`] e [`Cadeia::a_gravar`] —, e o boot refaz a cadeia a partir
//! dele com [`Cadeia::repor`]: a mesma sequência, os mesmos elos, e a
//! cadeia continua de onde parou. O que saiu do anel antes de chegar ao
//! journal não some em silêncio: vira uma **lacuna**, com a primeira e a
//! última sequência perdidas e o elo da última — ver [`Cadeia::pular`].
//! A cadeia continua verificável depois dela, como depois da âncora do
//! anel, e a lacuna diz exatamente o que falta.
//!
//! # O tempo não volta
//!
//! O tempo de um registro nunca é menor que o do anterior: o anel o sobe
//! até lá, se for preciso. Com o tempo lógico da persistência — o RTC com o
//! piso do journal — isso só acontece com os registros de um boot feitos
//! antes de o journal ser lido, e garante que uma cadeia que atravessa
//! boots nunca anda para trás no tempo. A reposição recusa um tempo que
//! volte: ele não sai de um journal autêntico.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};

use crate::codigo::Codigo;

/// O rótulo do elo, para ele nunca coincidir com outro resumo do sistema.
///
/// A v2 acrescentou o titular e a sessão de pessoa: um elo da v1 não é
/// refeito pela conta da v2, e nem deve ser.
const ROTULO: &[u8] = b"Duke auditoria v2";

/// O elo antes do primeiro registro.
pub const GENESE: [u8; 32] = [0; 32];

/// O maior detalhe, em bytes.
pub const MAIOR_DETALHE: usize = 96;

/// Que tipo de identidade agiu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Titular {
    /// O próprio kernel, no boot: carregar a chave, o registro e a política.
    Kernel = 0,
    /// Um processo do sistema — o servidor de janelas, o Terminal.
    Sistema = 1,
    /// A serial: o canal de controle e emergência, sem identidade de pessoa.
    Serial = 2,
    /// Um agente, pela chave que provou o aperto.
    Agente = 3,
    /// Uma pessoa do registro, pela sessão que abriu com a credencial dela.
    Pessoa = 4,
    /// Um administrador, pela prova de uma operação administrativa.
    Administrador = 5,
    /// Ninguém ainda: uma porta sem aperto, um console sem login.
    Anonimo = 6,
}

impl Titular {
    /// Todos, na ordem do número.
    pub const TODOS: [Titular; 7] = [
        Titular::Kernel,
        Titular::Sistema,
        Titular::Serial,
        Titular::Agente,
        Titular::Pessoa,
        Titular::Administrador,
        Titular::Anonimo,
    ];

    /// O nome, como `audit.tail` o escreve.
    pub const fn nome(self) -> &'static str {
        match self {
            Titular::Kernel => "kernel",
            Titular::Sistema => "system",
            Titular::Serial => "serial",
            Titular::Agente => "agent",
            Titular::Pessoa => "person",
            Titular::Administrador => "admin",
            Titular::Anonimo => "anonymous",
        }
    }

    /// O caminho de volta de [`Titular::nome`].
    pub fn de_nome(nome: &str) -> Option<Titular> {
        Titular::TODOS.into_iter().find(|t| t.nome() == nome)
    }
}

/// O que um registro diz, antes de entrar na cadeia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evento {
    pub ts_ms: u64,
    pub titular: Titular,
    /// A sessão do canal: a serial, uma porta, ou a da autoridade local.
    pub sessao: u8,
    /// A sessão de pessoa, sorteada no login. Só para [`Titular::Pessoa`],
    /// e para o login recusado de um console, que diz qual console era.
    pub sessao_de_pessoa: Option<[u8; 8]>,
    /// O identificador de quem agiu: o nome do agente ou do administrador,
    /// `pessoa:<16 hex>`, `serial`, `kernel`.
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

/// Um registro como vai para o journal: a sequência e o evento, campo a
/// campo, os variáveis com dois bytes de tamanho. O elo não vai: quem lê
/// refaz a conta, e um elo gravado seria só mais um campo a conferir.
pub fn codificar(seq: u64, e: &Evento) -> Vec<u8> {
    // Os textos do kernel têm teto bem abaixo disso; o corte, se um dia
    // acontecer, fica numa fronteira de caractere, para o registro
    // continuar se lendo.
    fn texto(v: &mut Vec<u8>, t: &str) {
        let mut n = t.len().min(u16::MAX as usize);
        while !t.is_char_boundary(n) {
            n -= 1;
        }
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v.extend_from_slice(&t.as_bytes()[..n]);
    }
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&e.ts_ms.to_le_bytes());
    v.push(e.titular as u8);
    v.push(e.sessao);
    match &e.sessao_de_pessoa {
        Some(s) => {
            v.push(1);
            v.extend_from_slice(s);
        }
        None => v.push(0),
    }
    match &e.chave {
        Some(k) => {
            v.push(1);
            v.extend_from_slice(k);
        }
        None => v.push(0),
    }
    v.push(e.codigo as u8);
    v.extend_from_slice(&e.parametros);
    texto(&mut v, &e.agente);
    texto(&mut v, &e.papel);
    texto(&mut v, &e.metodo);
    texto(&mut v, &e.recurso);
    texto(&mut v, &e.detalhe);
    v
}

/// O caminho de volta de [`codificar`]. Recusa o que não termina
/// exatamente no fim, um titular ou um código que não existem, uma marca
/// de presença que não é 0 nem 1, e texto que não é UTF-8.
pub fn decodificar(b: &[u8]) -> Result<(u64, Evento), &'static str> {
    struct Leitor<'a>(&'a [u8]);
    impl<'a> Leitor<'a> {
        fn bytes(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
            if self.0.len() < n {
                return Err("registro da auditoria cortado");
            }
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            Ok(a)
        }
        fn u8(&mut self) -> Result<u8, &'static str> {
            Ok(self.bytes(1)?[0])
        }
        fn u64(&mut self) -> Result<u64, &'static str> {
            let mut a = [0u8; 8];
            a.copy_from_slice(self.bytes(8)?);
            Ok(u64::from_le_bytes(a))
        }
        fn opcional<const N: usize>(&mut self) -> Result<Option<[u8; N]>, &'static str> {
            match self.u8()? {
                0 => Ok(None),
                1 => {
                    let mut a = [0u8; N];
                    a.copy_from_slice(self.bytes(N)?);
                    Ok(Some(a))
                }
                _ => Err("marca de presenca invalida no registro da auditoria"),
            }
        }
        fn texto(&mut self) -> Result<String, &'static str> {
            let n = self.bytes(2)?;
            let n = u16::from_le_bytes([n[0], n[1]]) as usize;
            let t = core::str::from_utf8(self.bytes(n)?)
                .map_err(|_| "texto que nao e UTF-8 no registro da auditoria")?;
            Ok(String::from(t))
        }
    }
    let mut l = Leitor(b);
    let seq = l.u64()?;
    let ts_ms = l.u64()?;
    let titular = *Titular::TODOS
        .get(l.u8()? as usize)
        .ok_or("titular desconhecido no registro da auditoria")?;
    let sessao = l.u8()?;
    let sessao_de_pessoa = l.opcional::<8>()?;
    let chave = l.opcional::<32>()?;
    let codigo = *Codigo::TODOS
        .get(l.u8()? as usize)
        .ok_or("codigo desconhecido no registro da auditoria")?;
    let mut parametros = [0u8; 32];
    parametros.copy_from_slice(l.bytes(32)?);
    let evento = Evento {
        ts_ms,
        titular,
        sessao,
        sessao_de_pessoa,
        agente: l.texto()?,
        chave,
        papel: l.texto()?,
        metodo: l.texto()?,
        recurso: l.texto()?,
        codigo,
        parametros,
        detalhe: l.texto()?,
    };
    if !l.0.is_empty() {
        return Err("bytes sobrando no registro da auditoria");
    }
    Ok((seq, evento))
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
    h.update([e.titular as u8]);
    h.update([e.sessao]);
    match &e.sessao_de_pessoa {
        Some(s) => {
            h.update([1]);
            h.update(s);
        }
        None => h.update([0]),
    }
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

/// Os registros que perderam o anel antes de chegar ao journal: da
/// sequência `primeira` à `ultima`, e o elo da última.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lacuna {
    pub primeira: u64,
    pub ultima: u64,
    pub elo: [u8; 32],
}

/// O que falta gravar: a lacuna, se o anel perdeu algum registro antes de
/// ele ser gravado, e os registros que ainda estão no anel, em ordem.
pub struct AGravar<'a> {
    pub lacuna: Option<Lacuna>,
    pub registros: alloc::vec::Vec<&'a Registro>,
}

/// A cadeia, num anel.
pub struct Cadeia {
    registros: VecDeque<Registro>,
    capacidade: usize,
    /// O elo do último que saiu pela ponta; [`GENESE`] enquanto nenhum saiu.
    ancora: [u8; 32],
    proximo_seq: u64,
    /// O tempo do último registro, mesmo que ele tenha saído do anel.
    ultimo_ts: u64,
}

impl Cadeia {
    /// Uma cadeia vazia que guarda até `capacidade` registros.
    pub fn nova(capacidade: usize) -> Cadeia {
        Cadeia {
            registros: VecDeque::new(),
            capacidade: capacidade.max(1),
            ancora: GENESE,
            proximo_seq: 1,
            ultimo_ts: 0,
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
        // O tempo não volta: um registro feito antes de o piso do relógio
        // ser conhecido sobe até o do anterior.
        evento.ts_ms = evento.ts_ms.max(self.ultimo_ts);
        self.ultimo_ts = evento.ts_ms;
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

    /// Repõe um registro lido do journal, no boot: a sequência tem de ser a
    /// seguinte, o tempo não pode voltar, e o detalhe cabe no teto. Um
    /// journal autêntico nunca traz outra coisa — a cadeia foi gravada por
    /// [`Cadeia::anexar`] —, e o que não confere é recusado, e não
    /// consertado: consertar daria outro elo.
    pub fn repor(&mut self, seq: u64, evento: Evento) -> Result<(), &'static str> {
        if seq != self.proximo_seq {
            return Err("registro da auditoria fora de sequencia");
        }
        if evento.ts_ms < self.ultimo_ts {
            return Err("registro da auditoria com o tempo voltando");
        }
        if evento.detalhe.len() > MAIOR_DETALHE {
            return Err("registro da auditoria com detalhe maior que o teto");
        }
        self.anexar(evento);
        Ok(())
    }

    /// Repõe uma lacuna lida do journal: os registros de `l.primeira` a
    /// `l.ultima` não foram gravados, e a cadeia continua do elo do último
    /// deles. A janela recomeça ali, como depois da âncora do anel.
    pub fn pular(&mut self, l: Lacuna) -> Result<(), &'static str> {
        if l.primeira != self.proximo_seq || l.ultima < l.primeira {
            return Err("lacuna da auditoria fora de sequencia");
        }
        self.registros.clear();
        self.ancora = l.elo;
        self.proximo_seq = l.ultima + 1;
        Ok(())
    }

    /// O que falta gravar depois da sequência `gravada`: uma lacuna, se o
    /// anel já perdeu registros posteriores a ela, e os que ele ainda tem.
    pub fn a_gravar(&self, gravada: u64) -> AGravar<'_> {
        let primeira_no_anel = self.registros.front().map_or(self.proximo_seq, |r| r.seq);
        let lacuna = (gravada + 1 < primeira_no_anel).then_some(Lacuna {
            primeira: gravada + 1,
            ultima: primeira_no_anel - 1,
            elo: self.ancora,
        });
        AGravar {
            lacuna,
            registros: self.registros.iter().filter(|r| r.seq > gravada).collect(),
        }
    }

    /// Acrescenta, nesta cadeia, os eventos que a `outra` tem no anel, na
    /// ordem: cada um ganha a sequência, o elo e o tempo daqui. É o boot
    /// que continua a cadeia do journal com o que ele mesmo registrou antes
    /// de ler o journal.
    pub fn continuar_com(&mut self, outra: &Cadeia) {
        for r in &outra.registros {
            self.anexar(r.evento.clone());
        }
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
            titular: Titular::Agente,
            sessao: 2,
            sessao_de_pessoa: None,
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
        let mudancas: [fn(&mut Evento); 10] = [
            |e| e.ts_ms += 1,
            |e| e.titular = Titular::Pessoa,
            |e| e.sessao = 3,
            |e| e.sessao_de_pessoa = Some([0; 8]),
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

    /// O nome do titular vai e volta, e o número de cada um é a posição
    /// dele: é o número que entra no elo.
    #[test]
    fn titular_vai_e_volta() {
        for (i, t) in Titular::TODOS.into_iter().enumerate() {
            assert_eq!(t as usize, i);
            assert_eq!(Titular::de_nome(t.nome()), Some(t));
        }
        assert_eq!(Titular::de_nome("pessoa"), None);
    }

    fn variado(i: u64) -> Evento {
        let mut e = evento(i);
        if i.is_multiple_of(2) {
            e.titular = Titular::Pessoa;
            e.sessao_de_pessoa = Some([i as u8; 8]);
            e.chave = None;
            e.agente = "pessoa:00112233aabbccdd".to_string();
        }
        if i.is_multiple_of(3) {
            e.codigo = Codigo::TODOS[(i as usize) % Codigo::TODOS.len()];
            e.detalhe = "ação recusada é".to_string();
            e.recurso = String::new();
        }
        e
    }

    /// Um registro vai ao journal e volta igual, com cada campo opcional
    /// presente e ausente, e texto que não é ASCII.
    #[test]
    fn o_registro_vai_e_volta() {
        for i in 0..12 {
            let e = variado(i);
            let b = codificar(i + 40, &e);
            assert_eq!(decodificar(&b), Ok((i + 40, e)), "registro {i}");
        }
    }

    /// Cortado em qualquer ponto, ou com um byte a mais, não se lê. Um
    /// titular, um código ou uma marca de presença que não existem, e
    /// texto que não é UTF-8, também não.
    #[test]
    fn o_registro_estragado_nao_se_le() {
        let e = variado(6);
        let b = codificar(9, &e);
        for n in 0..b.len() {
            assert!(decodificar(&b[..n]).is_err(), "cortado em {n}");
        }
        let mut mais = b.clone();
        mais.push(0);
        assert!(decodificar(&mais).is_err());

        // Os deslocamentos: seq 8, ts 8, titular, sessão, marca da sessão
        // de pessoa.
        let mut b2 = b.clone();
        b2[16] = Titular::TODOS.len() as u8;
        assert!(decodificar(&b2).is_err(), "titular");
        let mut b2 = b.clone();
        b2[18] = 2;
        assert!(decodificar(&b2).is_err(), "marca");
        // Sem sessão de pessoa e sem chave, o código vem logo depois das
        // duas marcas.
        let mut e3 = evento(1);
        e3.chave = None;
        let b3 = codificar(1, &e3);
        let mut b4 = b3.clone();
        b4[20] = Codigo::TODOS.len() as u8;
        assert!(decodificar(&b4).is_err(), "codigo");
        let mut b4 = b3.clone();
        b4[19] = 7;
        assert!(decodificar(&b4).is_err(), "marca da chave");
        // O primeiro byte do nome do agente, trocado por um que não abre
        // caractere UTF-8.
        let mut b4 = b3.clone();
        b4[21 + 32 + 2] = 0xFF;
        assert!(decodificar(&b4).is_err(), "utf-8");
        assert!(decodificar(&b3).is_ok());
    }

    /// O journal refaz a mesma cadeia: a mesma sequência, os mesmos elos,
    /// e o registro seguinte ganha o mesmo elo dos dois lados.
    #[test]
    fn a_cadeia_reposta_e_a_mesma() {
        let mut a = Cadeia::nova(100);
        for i in 0..10 {
            a.anexar(variado(i));
        }
        let gravado: Vec<Vec<u8>> = a.ultimos(10).map(|r| codificar(r.seq, &r.evento)).collect();
        let mut b = Cadeia::nova(100);
        for g in &gravado {
            let (seq, e) = decodificar(g).unwrap();
            b.repor(seq, e).unwrap();
        }
        assert_eq!(b.cabeca(), a.cabeca());
        assert_eq!(b.ultima_seq(), a.ultima_seq());
        assert_eq!(a.anexar(evento(99)), b.anexar(evento(99)));
        assert_eq!(a.cabeca(), b.cabeca());
    }

    /// A reposição recusa o que um journal autêntico não traz: a sequência
    /// pulada ou repetida, o tempo que volta, o detalhe acima do teto.
    #[test]
    fn repor_fora_da_regra_e_recusado() {
        let mut c = Cadeia::nova(10);
        c.repor(1, evento(5)).unwrap();
        assert!(c.repor(1, evento(6)).is_err(), "repetida");
        assert!(c.repor(3, evento(6)).is_err(), "pulada");
        assert!(c.repor(2, evento(4)).is_err(), "tempo voltando");
        let mut longo = evento(6);
        longo.detalhe = "x".repeat(MAIOR_DETALHE + 1);
        assert!(c.repor(2, longo).is_err(), "detalhe");
        let mut no_teto = evento(6);
        no_teto.detalhe = "x".repeat(MAIOR_DETALHE);
        c.repor(2, no_teto).unwrap();
        // O mesmo tempo do anterior vale.
        c.repor(3, evento(6)).unwrap();
        assert_eq!(c.ultima_seq(), 3);
    }

    /// O tempo de um registro nunca fica abaixo do anterior, nem depois de
    /// o anterior sair do anel.
    #[test]
    fn o_tempo_nao_volta() {
        let mut c = Cadeia::nova(1);
        c.anexar(evento(10));
        c.anexar(evento(3));
        assert_eq!(c.ultimos(1).next().unwrap().evento.ts_ms, 100);
        c.anexar(evento(20));
        assert_eq!(c.ultimos(1).next().unwrap().evento.ts_ms, 200);
    }

    /// O que sai do anel antes de ser gravado vira uma lacuna, com o elo
    /// do último perdido; o journal com a lacuna refaz a mesma cabeça.
    #[test]
    fn o_anel_que_perde_deixa_uma_lacuna() {
        let mut a = Cadeia::nova(4);
        for i in 0..10 {
            a.anexar(variado(i));
        }
        // Gravados até a 2: a 3 a 6 saíram do anel sem chegar ao journal.
        let falta = a.a_gravar(2);
        let lacuna = falta.lacuna.unwrap();
        assert_eq!((lacuna.primeira, lacuna.ultima), (3, 6));
        assert_eq!(lacuna.elo, a.ancora());
        let seqs: Vec<u64> = falta.registros.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, [7, 8, 9, 10]);

        let mut b = Cadeia::nova(4);
        for i in 0..2 {
            b.repor(i + 1, variado(i)).unwrap();
        }
        assert!(
            b.pular(Lacuna {
                primeira: 4,
                ..lacuna
            })
            .is_err(),
            "fora de sequencia"
        );
        assert!(
            b.pular(Lacuna {
                ultima: 2,
                ..lacuna
            })
            .is_err(),
            "ao contrario"
        );
        b.pular(lacuna).unwrap();
        for r in &falta.registros {
            b.repor(r.seq, r.evento.clone()).unwrap();
        }
        assert_eq!(b.cabeca(), a.cabeca());
        assert_eq!(b.verificar(), Ok(a.cabeca()));

        // Sem nada perdido, não há lacuna; com tudo gravado, nada falta.
        assert!(a.a_gravar(6).lacuna.is_none());
        assert_eq!(a.a_gravar(6).registros.len(), 4);
        assert!(a.a_gravar(10).registros.is_empty());
        assert!(a.a_gravar(10).lacuna.is_none());
    }

    /// O boot continua a cadeia do journal com o que registrou antes de
    /// lê-lo: as sequências seguem, e o tempo sobe ao do journal.
    #[test]
    fn continuar_com_o_que_veio_antes() {
        let mut journal = Cadeia::nova(10);
        for i in 0..3 {
            journal.anexar(evento(i + 50));
        }
        let mut boot = Cadeia::nova(10);
        boot.anexar(evento(1));
        boot.anexar(evento(2));
        journal.continuar_com(&boot);
        assert_eq!(journal.ultima_seq(), 5);
        let ultimos: Vec<&Registro> = journal.ultimos(2).collect();
        assert_eq!(ultimos[0].evento.metodo, "fs.read");
        assert!(ultimos.iter().all(|r| r.evento.ts_ms == 520));
        assert_eq!(journal.verificar(), Ok(journal.cabeca()));
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
