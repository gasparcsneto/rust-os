//! Os dispositivos relacionados, como conta pura: quem são, a que pessoa
//! desta máquina cada um se relaciona, com que papel, e quem foi revogado.
//!
//! # O que é um dispositivo relacionado
//!
//! Outro Duke, identificado pela **chave** dele — a estática X25519 que
//! nasceu na instalação dele, selada no TPM dele, e que ele prova no aperto
//! do enlace. Não é um agente: um agente é um operador de fora, com uma
//! sessão de comandos; um dispositivo só pede, pelo enlace, o conjunto
//! fechado de operações da malha. E não é uma pessoa: a chave de uma
//! máquina nunca autentica uma pessoa.
//!
//! # A relação
//!
//! Um dispositivo entra no registro por uma **relação** com uma pessoa
//! **desta** máquina — o identificador local dela, de 8 bytes —, e o que
//! ele pode pedir aqui é decidido pelo gate pelo papel dessa pessoa, pelo
//! papel da relação e pelo teto `remoto` da política, os três. Uma relação
//! ativa não dá nada sozinha: só permite pedir.
//!
//! - **Várias pessoas por dispositivo**: o tablet da família tem uma
//!   relação com cada pessoa; cada uma tem o seu identificador de 16 bytes,
//!   sorteado por quem registra primeiro e o mesmo nos dois dispositivos.
//!   Uma pessoa tem no máximo uma relação com cada dispositivo.
//! - **Vários dispositivos por pessoa**: uma relação por dispositivo.
//! - **O nome** é local, de quem registra — nunca o que o par diz —, e é do
//!   dispositivo: as relações dele têm o mesmo. Nome e chave são uma
//!   bijeção neste registro: `dispositivo:<nome>` diz sempre a mesma chave.
//! - **O endereço**, opcional, é onde alcançar o par — `tcp:<ipv4>:<porta>`,
//!   escrito por quem registra, como as fontes de hora. Nada é anunciado.
//!
//! # A revogação
//!
//! Revogar é o dispositivo inteiro: as relações saem, e a chave ganha uma
//! **lápide** — permanente, sem desrevogar: a mesma chave não volta a este
//! registro, e o kernel não a aceita nem como agente. A máquina recuperada
//! volta com uma instalação nova, e outra chave.
//!
//! # A desfeita
//!
//! Esquecer é **uma** relação — a da Pessoa que esquece: as das outras
//! ficam. Se era a última do dispositivo, ele sai do registro junto, e
//! **sem lápide**: a mesma chave pode voltar por uma relação nova, com
//! outro identificador.
//!
//! # O que este módulo não faz
//!
//! Não decide nada: o gate decide, pela política. Não sabe dos agentes, dos
//! administradores nem da chave deste Duke — o kernel confere essas, em
//! volta desta conta. E não persiste: o journal grava o resultado de cada
//! mudança, como a linha de [`linha`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::arquivo::nome_valido;

/// Quantos dispositivos o registro guarda.
pub const MAIS_DISPOSITIVOS: usize = 32;

/// Quantas relações um dispositivo tem — uma por pessoa.
pub const RELACOES_POR_DISPOSITIVO: usize = 8;

/// Quantas relações o registro guarda, somando os dispositivos.
pub const MAIS_RELACOES: usize = 64;

/// O tamanho do identificador de uma relação.
pub const TAM_ID: usize = 16;

/// Uma relação: um dispositivo, uma pessoa desta máquina, o papel que é o
/// teto do que ele pede em nome dela, e onde alcançá-lo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relacao {
    /// Sorteado por quem registra primeiro; o mesmo nos dois dispositivos.
    pub id: [u8; TAM_ID],
    /// A pessoa **desta** máquina — o identificador do registro de pessoas.
    pub pessoa: [u8; 8],
    /// Um papel da política: o que o dispositivo pode pedir aqui por esta
    /// relação, intersectado com o papel da pessoa e com o teto `remoto`.
    pub papel: String,
    /// Onde alcançar o dispositivo, `tcp:<ipv4>:<porta>` na forma normal.
    pub endereco: Option<String>,
}

/// Um dispositivo do registro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispositivo {
    /// A chave do Duke dele — a identidade.
    pub chave: [u8; 32],
    /// O nome local.
    pub nome: String,
    /// As relações dele, uma por pessoa.
    pub relacoes: Vec<Relacao>,
}

impl Dispositivo {
    /// A relação de `id`.
    pub fn relacao(&self, id: &[u8; TAM_ID]) -> Option<&Relacao> {
        self.relacoes.iter().find(|r| r.id == *id)
    }

    /// A relação com a pessoa `pessoa`.
    pub fn relacao_da_pessoa(&self, pessoa: &[u8; 8]) -> Option<&Relacao> {
        self.relacoes.iter().find(|r| r.pessoa == *pessoa)
    }
}

/// Por que uma mudança do registro foi recusada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O nome não segue a regra dos nomes.
    Nome,
    /// O papel não segue a regra dos nomes.
    Papel,
    /// O endereço não é `tcp:<ipv4>:<porta>` na forma normal.
    Endereco,
    /// O nome já é de outra chave.
    NomeDeOutro,
    /// A chave já está no registro com outro nome.
    ChaveComOutroNome,
    /// A pessoa já tem uma relação com este dispositivo.
    PessoaRepetida,
    /// O identificador já é de outra relação.
    IdRepetido,
    /// A chave tem lápide: foi revogada, e não volta.
    Revogada,
    /// O registro, ou o dispositivo, está no teto.
    Cheio,
    /// Não há dispositivo com esta chave, ou com este nome.
    Desconhecido,
}

impl Recusa {
    /// O motivo, para quem pediu e para a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Nome => "nome de dispositivo fora da regra",
            Recusa::Papel => "papel fora da regra",
            Recusa::Endereco => "endereco invalido: so `tcp:<ipv4>:<porta>`, na forma normal",
            Recusa::NomeDeOutro => "o nome ja e de outro dispositivo",
            Recusa::ChaveComOutroNome => "o dispositivo ja esta no registro com outro nome",
            Recusa::PessoaRepetida => "a pessoa ja tem uma relacao com este dispositivo",
            Recusa::IdRepetido => "o identificador ja e de outra relacao",
            Recusa::Revogada => "a chave foi revogada: a lapide nao se desfaz",
            Recusa::Cheio => "registro de dispositivos cheio",
            Recusa::Desconhecido => "dispositivo desconhecido",
        }
    }
}

/// O registro: os dispositivos, com as relações, e as lápides.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registro {
    dispositivos: Vec<Dispositivo>,
    /// As chaves revogadas, em ordem de revogação. Permanentes.
    lapides: Vec<[u8; 32]>,
}

/// O endereço na forma normal, se é um destino TCP: o enlace é por TCP.
fn endereco_normal(texto: &str) -> Option<String> {
    let normal = crate::endereco::normalizar(texto).filter(|n| n == texto)?;
    normal.starts_with("tcp:").then_some(normal)
}

impl Registro {
    pub const fn novo() -> Registro {
        Registro {
            dispositivos: Vec::new(),
            lapides: Vec::new(),
        }
    }

    /// Registra a relação `relacao` do dispositivo de chave `chave` e nome
    /// `nome`: o dispositivo entra, se não estava, ou ganha mais uma
    /// relação. Tudo conferido antes de mudar qualquer coisa.
    pub fn registrar(
        &mut self,
        chave: [u8; 32],
        nome: &str,
        relacao: Relacao,
    ) -> Result<(), Recusa> {
        if !nome_valido(nome) {
            return Err(Recusa::Nome);
        }
        if !nome_valido(&relacao.papel) {
            return Err(Recusa::Papel);
        }
        if let Some(e) = &relacao.endereco
            && endereco_normal(e).as_deref() != Some(e.as_str())
        {
            return Err(Recusa::Endereco);
        }
        if self.lapides.contains(&chave) {
            return Err(Recusa::Revogada);
        }
        if self
            .dispositivos
            .iter()
            .any(|d| d.nome == nome && d.chave != chave)
        {
            return Err(Recusa::NomeDeOutro);
        }
        if self
            .dispositivos
            .iter()
            .flat_map(|d| d.relacoes.iter())
            .any(|r| r.id == relacao.id)
        {
            return Err(Recusa::IdRepetido);
        }
        if self.quantas_relacoes() >= MAIS_RELACOES {
            return Err(Recusa::Cheio);
        }
        let cheio = self.dispositivos.len() >= MAIS_DISPOSITIVOS;
        match self.dispositivos.iter_mut().find(|d| d.chave == chave) {
            Some(d) if d.nome != nome => Err(Recusa::ChaveComOutroNome),
            Some(d) if d.relacoes.iter().any(|r| r.pessoa == relacao.pessoa) => {
                Err(Recusa::PessoaRepetida)
            }
            Some(d) if d.relacoes.len() >= RELACOES_POR_DISPOSITIVO => Err(Recusa::Cheio),
            Some(d) => {
                d.relacoes.push(relacao);
                Ok(())
            }
            None if cheio => Err(Recusa::Cheio),
            None => {
                self.dispositivos.push(Dispositivo {
                    chave,
                    nome: nome.to_string(),
                    relacoes: alloc::vec![relacao],
                });
                Ok(())
            }
        }
    }

    /// Revoga o dispositivo de chave `chave`: ele sai, com as relações, e a
    /// chave ganha a lápide. Devolve o que saiu.
    pub fn revogar(&mut self, chave: &[u8; 32]) -> Result<Dispositivo, Recusa> {
        let i = self
            .dispositivos
            .iter()
            .position(|d| d.chave == *chave)
            .ok_or(Recusa::Desconhecido)?;
        let d = self.dispositivos.remove(i);
        if !self.lapides.contains(chave) {
            self.lapides.push(*chave);
        }
        Ok(d)
    }

    /// Aplica a lápide de `chave` — a reposição do journal: o dispositivo
    /// sai, se estava, e a chave não volta. Idempotente.
    pub fn aplicar_lapide(&mut self, chave: &[u8; 32]) {
        self.dispositivos.retain(|d| d.chave != *chave);
        if !self.lapides.contains(chave) {
            self.lapides.push(*chave);
        }
    }

    /// Desfaz a relação `id` do dispositivo de chave `chave`: só ela sai.
    /// Se era a última dele, o dispositivo sai junto — sem lápide. Devolve a
    /// relação que saiu e se o dispositivo saiu com ela.
    ///
    /// O identificador de uma relação de outro dispositivo não é dele:
    /// `Desconhecido`, e nada muda.
    pub fn esquecer(
        &mut self,
        chave: &[u8; 32],
        id: &[u8; TAM_ID],
    ) -> Result<(Relacao, bool), Recusa> {
        let i = self
            .dispositivos
            .iter()
            .position(|d| d.chave == *chave)
            .ok_or(Recusa::Desconhecido)?;
        let d = &mut self.dispositivos[i];
        let j = d
            .relacoes
            .iter()
            .position(|r| r.id == *id)
            .ok_or(Recusa::Desconhecido)?;
        let r = d.relacoes.remove(j);
        let saiu = d.relacoes.is_empty();
        if saiu {
            self.dispositivos.remove(i);
        }
        Ok((r, saiu))
    }

    /// Aplica a desfeita da relação `id` de `chave` — a reposição do
    /// journal: a relação sai, se estava; o dispositivo sai com a última.
    /// Idempotente, e nunca põe lápide.
    pub fn aplicar_desfeita(&mut self, chave: &[u8; 32], id: &[u8; TAM_ID]) {
        let _ = self.esquecer(chave, id);
    }

    /// Se a chave tem lápide.
    pub fn revogada(&self, chave: &[u8; 32]) -> bool {
        self.lapides.contains(chave)
    }

    /// As lápides, em ordem.
    pub fn lapides(&self) -> &[[u8; 32]] {
        &self.lapides
    }

    /// Os dispositivos, em ordem de registro.
    pub fn dispositivos(&self) -> &[Dispositivo] {
        &self.dispositivos
    }

    /// O dispositivo de chave `chave`.
    pub fn dispositivo(&self, chave: &[u8; 32]) -> Option<&Dispositivo> {
        self.dispositivos.iter().find(|d| d.chave == *chave)
    }

    /// O dispositivo de nome `nome`.
    pub fn por_nome(&self, nome: &str) -> Option<&Dispositivo> {
        self.dispositivos.iter().find(|d| d.nome == nome)
    }

    /// A relação `id` do dispositivo `chave` — só entre as relações dele: o
    /// identificador de uma relação de outro dispositivo não é dele.
    pub fn relacao(&self, chave: &[u8; 32], id: &[u8; TAM_ID]) -> Option<&Relacao> {
        self.dispositivo(chave)?.relacao(id)
    }

    /// O dispositivo de nome `nome` e a relação dele com a pessoa
    /// `pessoa` — o nome resolvido no espaço dela: o dispositivo de outra
    /// pessoa responde o mesmo que um que não existe.
    pub fn da_pessoa(&self, nome: &str, pessoa: &[u8; 8]) -> Option<(&Dispositivo, &Relacao)> {
        let d = self.por_nome(nome)?;
        Some((d, d.relacao_da_pessoa(pessoa)?))
    }

    /// Quantas relações, somando os dispositivos.
    pub fn quantas_relacoes(&self) -> usize {
        self.dispositivos.iter().map(|d| d.relacoes.len()).sum()
    }

    /// As regras que o registro nunca quebra: nomes e chaves únicos, e uma
    /// bijeção entre eles; identificadores de relação únicos; uma relação
    /// por pessoa em cada dispositivo; todo dispositivo com uma relação ao
    /// menos; nenhuma chave com lápide no registro; os tetos.
    pub fn coerente(&self) -> bool {
        let ds = &self.dispositivos;
        let unicos = ds.iter().enumerate().all(|(i, d)| {
            ds[..i]
                .iter()
                .all(|o| o.chave != d.chave && o.nome != d.nome)
        });
        let ids: Vec<&[u8; TAM_ID]> = ds
            .iter()
            .flat_map(|d| d.relacoes.iter().map(|r| &r.id))
            .collect();
        let ids_unicos = ids
            .iter()
            .enumerate()
            .all(|(i, id)| ids[..i].iter().all(|o| o != id));
        let por_pessoa = ds.iter().all(|d| {
            !d.relacoes.is_empty()
                && d.relacoes.len() <= RELACOES_POR_DISPOSITIVO
                && d.relacoes
                    .iter()
                    .enumerate()
                    .all(|(i, r)| d.relacoes[..i].iter().all(|o| o.pessoa != r.pessoa))
        });
        let sem_lapide = ds.iter().all(|d| !self.lapides.contains(&d.chave));
        let lapides_unicas = self
            .lapides
            .iter()
            .enumerate()
            .all(|(i, k)| !self.lapides[..i].contains(k));
        unicos
            && ids_unicos
            && por_pessoa
            && sem_lapide
            && lapides_unicas
            && ds.len() <= MAIS_DISPOSITIVOS
            && self.quantas_relacoes() <= MAIS_RELACOES
    }
}

/// O texto de um identificador de relação: 32 dígitos hexadecimais.
pub fn id_texto(id: &[u8; TAM_ID]) -> String {
    let mut t = String::with_capacity(2 * TAM_ID);
    for b in id {
        let _ = core::fmt::Write::write_fmt(&mut t, format_args!("{b:02x}"));
    }
    t
}

/// O identificador de relação de um texto de 32 dígitos hexadecimais.
pub fn ler_id(texto: &str) -> Option<[u8; TAM_ID]> {
    let mut id = [0u8; TAM_ID];
    ler_hex(texto, &mut id).then_some(id)
}

fn ler_hex(texto: &str, destino: &mut [u8]) -> bool {
    let b = texto.as_bytes();
    if b.len() != 2 * destino.len() {
        return false;
    }
    let digito = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    for (i, d) in destino.iter_mut().enumerate() {
        match (digito(b[2 * i]), digito(b[2 * i + 1])) {
            (Some(a), Some(z)) => *d = (a << 4) | z,
            _ => return false,
        }
    }
    true
}

fn hex(bytes: &[u8]) -> String {
    let mut t = String::with_capacity(2 * bytes.len());
    for b in bytes {
        let _ = core::fmt::Write::write_fmt(&mut t, format_args!("{b:02x}"));
    }
    t
}

/// Uma relação como linha: `<chave> <nome> <relação> <pessoa> <papel>
/// <endereço|->`, a chave e os identificadores em hexadecimal minúsculo. É
/// o que o journal grava de um registro — o resultado, inteiro —, e o que
/// [`ler_linha`] lê de volta igual.
pub fn linha(chave: &[u8; 32], nome: &str, r: &Relacao) -> String {
    alloc::format!(
        "{} {nome} {} {} {} {}",
        hex(chave),
        id_texto(&r.id),
        hex(&r.pessoa),
        r.papel,
        r.endereco.as_deref().unwrap_or("-")
    )
}

/// A linha de [`linha`], de volta: a chave, o nome e a relação. Estrita:
/// seis campos, cada um na forma; o que não está nela é recusado.
pub fn ler_linha(texto: &str) -> Result<([u8; 32], String, Relacao), Recusa> {
    let campos: Vec<&str> = texto.split(' ').collect();
    let [chave, nome, id, pessoa, papel, endereco] = campos[..] else {
        return Err(Recusa::Desconhecido);
    };
    let mut k = [0u8; 32];
    if !ler_hex(chave, &mut k) {
        return Err(Recusa::Desconhecido);
    }
    if !nome_valido(nome) {
        return Err(Recusa::Nome);
    }
    let id = ler_id(id).ok_or(Recusa::Desconhecido)?;
    let mut p = [0u8; 8];
    if !ler_hex(pessoa, &mut p) {
        return Err(Recusa::Desconhecido);
    }
    if !nome_valido(papel) {
        return Err(Recusa::Papel);
    }
    let endereco = match endereco {
        "-" => None,
        e => Some(endereco_normal(e).ok_or(Recusa::Endereco)?),
    };
    Ok((
        k,
        nome.to_string(),
        Relacao {
            id,
            pessoa: p,
            papel: papel.to_string(),
            endereco,
        },
    ))
}

#[cfg(test)]
mod testes {
    use super::*;

    const BIA: [u8; 8] = [1; 8];
    const CAIO: [u8; 8] = [2; 8];
    const K1: [u8; 32] = [0x11; 32];
    const K2: [u8; 32] = [0x22; 32];

    fn relacao(id: u8, pessoa: [u8; 8]) -> Relacao {
        Relacao {
            id: [id; TAM_ID],
            pessoa,
            papel: "dispositivo".to_string(),
            endereco: Some("tcp:10.0.2.100:7071".to_string()),
        }
    }

    #[test]
    fn registra_e_resolve_no_espaco_da_pessoa() {
        let mut r = Registro::novo();
        r.registrar(K1, "tablet", relacao(1, BIA)).unwrap();
        // A outra pessoa, no mesmo dispositivo: outra relação, o mesmo nome.
        r.registrar(K1, "tablet", relacao(2, CAIO)).unwrap();
        assert_eq!(r.dispositivos().len(), 1);
        assert_eq!(r.quantas_relacoes(), 2);
        let (d, rel) = r.da_pessoa("tablet", &BIA).unwrap();
        assert_eq!((d.chave, rel.id), (K1, [1; TAM_ID]));
        assert_eq!(r.da_pessoa("tablet", &CAIO).unwrap().1.id, [2; TAM_ID]);
        // A pessoa sem relação com ele, e o nome que não existe, dão o
        // mesmo nada.
        assert!(r.da_pessoa("tablet", &[3; 8]).is_none());
        assert!(r.da_pessoa("telefone", &BIA).is_none());
        // A relação de um dispositivo só se acha entre as dele.
        assert!(r.relacao(&K1, &[1; TAM_ID]).is_some());
        assert!(r.relacao(&K2, &[1; TAM_ID]).is_none());
        assert!(r.coerente());
    }

    #[test]
    fn as_recusas_do_registro() {
        let mut r = Registro::novo();
        r.registrar(K1, "tablet", relacao(1, BIA)).unwrap();
        let antes = r.clone();
        // O nome de outro, a chave com outro nome, a pessoa de novo, o id
        // de novo — e nada muda em nenhuma.
        assert_eq!(
            r.registrar(K2, "tablet", relacao(2, BIA)),
            Err(Recusa::NomeDeOutro)
        );
        assert_eq!(
            r.registrar(K1, "outro", relacao(2, CAIO)),
            Err(Recusa::ChaveComOutroNome)
        );
        assert_eq!(
            r.registrar(K1, "tablet", relacao(2, BIA)),
            Err(Recusa::PessoaRepetida)
        );
        assert_eq!(
            r.registrar(K2, "telefone", relacao(1, CAIO)),
            Err(Recusa::IdRepetido)
        );
        for nome in ["", "Tablet", "tab*", "um nome", &"x".repeat(33)] {
            assert_eq!(
                r.registrar(K2, nome, relacao(3, BIA)),
                Err(Recusa::Nome),
                "{nome}"
            );
        }
        let mut sem_papel = relacao(3, BIA);
        sem_papel.papel = "*".to_string();
        assert_eq!(r.registrar(K2, "telefone", sem_papel), Err(Recusa::Papel));
        for endereco in [
            "udp:10.0.2.2:69",
            "tcp:10.0.2.100",
            "tcp:010.0.2.100:7071",
            "tcp:*:7071",
            "10.0.2.100:7071",
        ] {
            let mut rel = relacao(3, BIA);
            rel.endereco = Some(endereco.to_string());
            assert_eq!(
                r.registrar(K2, "telefone", rel),
                Err(Recusa::Endereco),
                "{endereco}"
            );
        }
        assert_eq!(r, antes);
        // Sem endereço vale: o par alcança este, e não o contrário.
        let mut sem_endereco = relacao(3, BIA);
        sem_endereco.endereco = None;
        r.registrar(K2, "telefone", sem_endereco).unwrap();
        assert!(r.coerente());
    }

    #[test]
    fn a_lapide_e_permanente() {
        let mut r = Registro::novo();
        r.registrar(K1, "tablet", relacao(1, BIA)).unwrap();
        r.registrar(K1, "tablet", relacao(2, CAIO)).unwrap();
        r.registrar(K2, "telefone", relacao(3, BIA)).unwrap();
        let saiu = r.revogar(&K1).unwrap();
        // O dispositivo inteiro, com as duas relações — e só ele.
        assert_eq!(saiu.relacoes.len(), 2);
        assert!(r.dispositivo(&K1).is_none() && r.revogada(&K1));
        assert!(r.dispositivo(&K2).is_some() && !r.revogada(&K2));
        // Não volta: nem com outro nome, nem com outra pessoa, nem com outro
        // identificador.
        assert_eq!(
            r.registrar(K1, "tablet", relacao(4, BIA)),
            Err(Recusa::Revogada)
        );
        assert_eq!(
            r.registrar(K1, "novo", relacao(5, CAIO)),
            Err(Recusa::Revogada)
        );
        assert_eq!(r.revogar(&K1), Err(Recusa::Desconhecido));
        // A reposição da lápide é idempotente, e tira o que a imagem
        // trouxesse de novo.
        r.aplicar_lapide(&K1);
        r.aplicar_lapide(&K2);
        r.aplicar_lapide(&K2);
        assert!(r.dispositivos().is_empty());
        assert_eq!(r.lapides(), &[K1, K2]);
        assert!(r.coerente());
    }

    // H06: esquecer é a relação da Pessoa, e só ela.
    #[test]
    fn esquecer_tira_so_a_relacao() {
        let mut r = Registro::novo();
        r.registrar(K1, "tablet", relacao(1, BIA)).unwrap();
        r.registrar(K1, "tablet", relacao(2, CAIO)).unwrap();
        r.registrar(K2, "telefone", relacao(3, BIA)).unwrap();
        // A da Bia com o tablet sai; a do Caio com ele, e a da Bia com o
        // telefone, ficam.
        let (saiu, dispositivo_saiu) = r.esquecer(&K1, &[1; TAM_ID]).unwrap();
        assert_eq!(saiu, relacao(1, BIA));
        assert!(!dispositivo_saiu);
        assert!(r.da_pessoa("tablet", &BIA).is_none());
        assert_eq!(r.da_pessoa("tablet", &CAIO).unwrap().1.id, [2; TAM_ID]);
        assert_eq!(r.da_pessoa("telefone", &BIA).unwrap().1.id, [3; TAM_ID]);
        assert_eq!(r.quantas_relacoes(), 2);
        assert!(r.coerente());
        // O identificador de uma relação de outro dispositivo não é dele, e
        // o que já saiu não sai de novo: nada muda.
        let antes = r.clone();
        assert_eq!(r.esquecer(&K2, &[2; TAM_ID]), Err(Recusa::Desconhecido));
        assert_eq!(r.esquecer(&K1, &[1; TAM_ID]), Err(Recusa::Desconhecido));
        assert_eq!(
            r.esquecer(&[0x33; 32], &[2; TAM_ID]),
            Err(Recusa::Desconhecido)
        );
        assert_eq!(r, antes);
    }

    #[test]
    fn o_dispositivo_sai_com_a_ultima_e_sem_lapide() {
        let mut r = Registro::novo();
        r.registrar(K1, "tablet", relacao(1, BIA)).unwrap();
        r.registrar(K1, "tablet", relacao(2, CAIO)).unwrap();
        assert_eq!(r.esquecer(&K1, &[1; TAM_ID]).map(|x| x.1), Ok(false));
        assert_eq!(r.esquecer(&K1, &[2; TAM_ID]).map(|x| x.1), Ok(true));
        // O dispositivo saiu inteiro, sem lápide: o nome está livre.
        assert!(r.dispositivo(&K1).is_none() && r.por_nome("tablet").is_none());
        assert!(!r.revogada(&K1) && r.lapides().is_empty());
        assert!(r.coerente());
        // Parear de novo depois: a mesma chave volta, por uma relação nova —
        // com outro identificador, e até com outro nome.
        r.registrar(K1, "laptop", relacao(9, BIA)).unwrap();
        assert_eq!(r.da_pessoa("laptop", &BIA).unwrap().1.id, [9; TAM_ID]);
        assert!(r.coerente());
    }

    #[test]
    fn a_desfeita_reposta_e_idempotente_e_a_lapide_ainda_barra() {
        let mut r = Registro::novo();
        r.registrar(K1, "tablet", relacao(1, BIA)).unwrap();
        r.registrar(K1, "tablet", relacao(2, CAIO)).unwrap();
        // A reposição do journal: uma, duas vezes, e a de uma relação que
        // não existe — o mesmo registro.
        r.aplicar_desfeita(&K1, &[1; TAM_ID]);
        let depois = r.clone();
        r.aplicar_desfeita(&K1, &[1; TAM_ID]);
        r.aplicar_desfeita(&K2, &[7; TAM_ID]);
        assert_eq!(r, depois);
        assert_eq!(r.quantas_relacoes(), 1);
        assert!(!r.revogada(&K1));
        // A lápide do administrador continua por cima: esquecer não a tira,
        // e a chave com lápide não volta.
        r.revogar(&K1).unwrap();
        assert_eq!(r.esquecer(&K1, &[2; TAM_ID]), Err(Recusa::Desconhecido));
        r.aplicar_desfeita(&K1, &[2; TAM_ID]);
        assert!(r.revogada(&K1));
        assert_eq!(
            r.registrar(K1, "tablet", relacao(3, BIA)),
            Err(Recusa::Revogada)
        );
        assert!(r.coerente());
    }

    #[test]
    fn esquecer_devolve_o_lugar_nos_tetos() {
        let mut r = Registro::novo();
        for p in 0..RELACOES_POR_DISPOSITIVO as u8 {
            r.registrar(K1, "tablet", relacao(p, [p; 8])).unwrap();
        }
        assert_eq!(
            r.registrar(K1, "tablet", relacao(200, [200; 8])),
            Err(Recusa::Cheio)
        );
        r.esquecer(&K1, &[3; TAM_ID]).unwrap();
        r.registrar(K1, "tablet", relacao(200, [200; 8])).unwrap();
        let mut r = Registro::novo();
        for i in 0..MAIS_DISPOSITIVOS as u8 {
            let mut k = [0u8; 32];
            k[0] = i;
            let nome = alloc::format!("d{i}");
            r.registrar(k, &nome, relacao(i, BIA)).unwrap();
        }
        assert_eq!(
            r.registrar([0xFF; 32], "mais", relacao(250, BIA)),
            Err(Recusa::Cheio)
        );
        let mut k0 = [0u8; 32];
        k0[0] = 5;
        r.esquecer(&k0, &[5; TAM_ID]).unwrap();
        r.registrar([0xFF; 32], "mais", relacao(250, BIA)).unwrap();
        assert!(r.coerente());
    }

    #[test]
    fn os_tetos() {
        let mut r = Registro::novo();
        for p in 0..RELACOES_POR_DISPOSITIVO as u8 {
            r.registrar(K1, "tablet", relacao(p, [p; 8])).unwrap();
        }
        assert_eq!(
            r.registrar(K1, "tablet", relacao(200, [200; 8])),
            Err(Recusa::Cheio)
        );
        let mut r = Registro::novo();
        for i in 0..MAIS_DISPOSITIVOS as u8 {
            let mut k = [0u8; 32];
            k[0] = i;
            let nome = alloc::format!("d{i}");
            r.registrar(k, &nome, relacao(i, BIA)).unwrap();
        }
        assert_eq!(
            r.registrar([0xFF; 32], "mais", relacao(250, BIA)),
            Err(Recusa::Cheio)
        );
        assert!(r.coerente());
    }

    #[test]
    fn a_linha_vai_e_volta() {
        let rel = relacao(7, BIA);
        let l = linha(&K1, "tablet", &rel);
        assert_eq!(
            l,
            alloc::format!(
                "{} tablet {} {} dispositivo tcp:10.0.2.100:7071",
                "11".repeat(32),
                "07".repeat(16),
                "01".repeat(8)
            )
        );
        assert_eq!(
            ler_linha(&l).unwrap(),
            (K1, "tablet".to_string(), rel.clone())
        );
        let mut sem = rel.clone();
        sem.endereco = None;
        let l = linha(&K1, "tablet", &sem);
        assert!(l.ends_with(" -"));
        assert_eq!(ler_linha(&l).unwrap().2, sem);
        // O que não está na forma é recusado, e não lido como outra coisa.
        for ruim in [
            "",
            "tablet",
            &l.replace(" -", ""),
            &alloc::format!("{l} sobra"),
            &l.replacen("11", "1G", 1),
            &l.replace("tablet", "Tablet"),
            &l.replace(" -", " udp:10.0.2.2:69"),
            &l.replace(" -", " tcp:010.0.2.100:7071"),
        ] {
            assert!(ler_linha(ruim).is_err(), "{ruim}");
        }
        assert_eq!(ler_id(&id_texto(&[0xAB; TAM_ID])), Some([0xAB; TAM_ID]));
        assert_eq!(ler_id(&"AB".repeat(16)), None);
        assert_eq!(ler_id("ab"), None);
    }

    /// Operações sorteadas: o registro nunca quebra as regras dele.
    #[test]
    fn coerente_sob_operacoes_sorteadas() {
        let mut estado = 0x2545_F491_4F6C_DD1Du64;
        let mut sorteio = move |n: u64| {
            estado ^= estado << 13;
            estado ^= estado >> 7;
            estado ^= estado << 17;
            estado % n
        };
        let mut r = Registro::novo();
        for _ in 0..4000 {
            let k = [sorteio(12) as u8; 32];
            let nome = alloc::format!("d{}", sorteio(14));
            match sorteio(10) {
                0..=6 => {
                    let rel = Relacao {
                        id: [sorteio(90) as u8; TAM_ID],
                        pessoa: [sorteio(6) as u8; 8],
                        papel: "dispositivo".to_string(),
                        endereco: None,
                    };
                    let antes = r.clone();
                    if r.registrar(k, &nome, rel).is_err() {
                        assert_eq!(r, antes);
                    }
                }
                7 => {
                    let tinha = r.dispositivo(&k).is_some();
                    assert_eq!(r.revogar(&k).is_ok(), tinha);
                    if tinha {
                        assert!(r.revogada(&k) && r.dispositivo(&k).is_none());
                    }
                }
                8 => {
                    let id = [sorteio(90) as u8; TAM_ID];
                    let lapides = r.lapides().to_vec();
                    let tinha = r.relacao(&k, &id).is_some();
                    let outras = r.dispositivo(&k).map_or(0, |d| d.relacoes.len());
                    match r.esquecer(&k, &id) {
                        Ok((saiu, sem_relacao)) => {
                            assert!(tinha && saiu.id == id);
                            assert_eq!(sem_relacao, outras == 1);
                            assert_eq!(r.dispositivo(&k).is_none(), sem_relacao);
                        }
                        Err(e) => assert!(!tinha && e == Recusa::Desconhecido),
                    }
                    // Esquecer nunca põe nem tira lápide.
                    assert_eq!(r.lapides(), &lapides[..]);
                }
                _ => r.aplicar_lapide(&k),
            }
            assert!(r.coerente());
            for l in r.lapides() {
                assert!(r.dispositivo(l).is_none());
            }
        }
    }
}
