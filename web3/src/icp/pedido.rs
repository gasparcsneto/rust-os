//! Os pedidos: a consulta (*query*), a chamada (*update*, `call`) e a
//! leitura de estado (`read_state`), o id de cada um e o envelope em que
//! vão.
//!
//! **Especificação** (*Request: Query call*, *Request: Call*, *Request:
//! Read state*, *Authentication*, *Request ids*): o corpo HTTP é
//! `55799({"content": {…}, ? "sender_pubkey", ? "sender_sig"})`. O
//! conteúdo traz `request_type`, `sender`, `ingress_expiry` e, conforme o
//! tipo, `canister_id`, `method_name` e `arg`, ou `paths`; o `nonce` é
//! opcional. O id do pedido é o hash independente de representação do
//! conteúdo ([`super::resumo`]).
//!
//! # Quem pede
//!
//! O anônimo pede sem assinar: sem `sender_pubkey`, `sender_sig` nem
//! `sender_delegation`, que a especificação manda omitir para ele. Quem
//! tem chave manda a pública, em DER, e a assinatura de
//! `domain_sep("ic-request") · id` ([`SEPARADOR_DO_PEDIDO`]) — a
//! [`Autenticacao`] —, e o remetente é o Principal auto-autenticado
//! daquela pública: um envelope assinado cujo remetente não é o da chave
//! não se monta. Quem assina não é este módulo: ele dá o id, e recebe a
//! assinatura feita — no Duke, pelo kernel, que guarda a privada. Sem
//! delegação: a cadeia de delegações do IC não existe aqui.
//!
//! A consulta também vai dos dois jeitos: a do anônimo pelo
//! [`Consulta::id`] e pelo [`Consulta::envelope`], que não aceitam outro
//! remetente; a de quem tem chave pelo [`Consulta::id_assinada`] e pelo
//! [`Consulta::envelope_assinado`], com a regra da chamada — o remetente é
//! o Principal da chave, ou nada se monta. O id leva o remetente: a mesma
//! consulta, do anônimo e assinada, são dois pedidos.
//!
//! # O nonce da consulta
//!
//! A consulta leva um nonce de quem chama (no programa, do `random.read`).
//! Sem ele, duas consultas iguais no mesmo minuto teriam o mesmo id — o
//! `ic-agent` arredonda o vencimento ao minuto e não põe nonce em
//! consulta —, e a assinatura de uma resposta antiga, ainda fresca, valeria
//! para a nova. Com ele, a assinatura do nó fica presa a este pedido.
//! A leitura de estado não precisa: o certificado fala do estado, não do
//! pedido (**referência**: o `ic-agent` também não põe).

use alloc::vec::Vec;

use super::cbor::Escritor;
use super::principal::Principal;
use super::resumo::{self, Hash};

/// O maior nonce — **especificação**: "at most 32 bytes".
pub const MAIOR_NONCE: usize = 32;

/// O nome do domínio em que um pedido assinado vai: a assinatura é a de
/// `domain_sep("ic-request") · id` — **especificação** (*Authentication*).
/// É também o nome do domínio no registro de domínios do Duke: o programa
/// pede ao kernel a assinatura neste domínio, e o kernel só conhece o nome
/// e os bytes do registro.
pub const DOMINIO_DO_PEDIDO: &str = "ic-request";

/// O separador de domínio do pedido: o tamanho do nome, num byte, e o nome
/// — **especificação**: `domain_sep(s) = byte(|s|) · s`.
pub const SEPARADOR_DO_PEDIDO: &[u8; 11] = b"\x0Aic-request";

/// O conteúdo de uma consulta.
#[derive(Clone, Copy, Debug)]
pub struct Consulta<'a> {
    /// O canister chamado.
    pub canister: Principal,
    /// O método.
    pub metodo: &'a str,
    /// O argumento, em Candid.
    pub arg: &'a [u8],
    /// Quem pede: o anônimo, ou o Principal da chave que assina.
    pub remetente: Principal,
    /// Até quando o pedido vale, em nanossegundos desde 1970.
    pub vencimento_ns: u64,
    /// O nonce, de até [`MAIOR_NONCE`] bytes.
    pub nonce: Option<&'a [u8]>,
}

/// O conteúdo de uma chamada (*update*): o que a consulta tem, com
/// `request_type` `call`. Ela muda o estado do canister, passa pelo
/// consenso, e a resposta fica certificada no estado da sub-rede.
#[derive(Clone, Copy, Debug)]
pub struct Chamada<'a> {
    /// O canister chamado.
    pub canister: Principal,
    /// O método.
    pub metodo: &'a str,
    /// O argumento, em Candid.
    pub arg: &'a [u8],
    /// Quem pede: o anônimo, ou o Principal da chave que assina.
    pub remetente: Principal,
    /// Até quando o pedido vale, em nanossegundos desde 1970.
    pub vencimento_ns: u64,
    /// O nonce, de até [`MAIOR_NONCE`] bytes: duas chamadas iguais no
    /// mesmo minuto seriam o mesmo pedido, e o IC executaria uma só.
    pub nonce: Option<&'a [u8]>,
}

/// O conteúdo de uma leitura de estado.
#[derive(Clone, Copy, Debug)]
pub struct LeituraDeEstado<'a> {
    /// Os caminhos pedidos: cada um, uma sequência de rótulos.
    pub caminhos: &'a [&'a [&'a [u8]]],
    /// Quem pede: o anônimo, ou — para ler a situação de uma chamada
    /// assinada, que só o remetente dela lê — o Principal da chave.
    pub remetente: Principal,
    /// Até quando o pedido vale, em nanossegundos desde 1970.
    pub vencimento_ns: u64,
}

/// A autenticação de quem tem chave — **especificação**,
/// *Authentication*: a pública, em DER (`sender_pubkey`), e a assinatura
/// de `domain_sep("ic-request") · id` com ela (`sender_sig`).
#[derive(Clone, Copy, Debug)]
pub struct Autenticacao<'a> {
    /// A chave pública, em DER: o remetente é o Principal
    /// auto-autenticado dela.
    pub chave_der: &'a [u8],
    /// A assinatura do id do pedido.
    pub assinatura: &'a [u8],
}

/// A chave pública Ed25519 crua em DER — RFC 8410, como a
/// especificação a quer em `sender_pubkey`: o prefixo fixo e os 32 bytes.
pub fn der_ed25519(publica: &[u8; 32]) -> [u8; 44] {
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&super::certificado::PREFIXO_DER_ED25519);
    der[12..].copy_from_slice(publica);
    der
}

/// O que se assina por um pedido: `domain_sep("ic-request") · id`. No
/// Duke, é o que o kernel assina no domínio [`DOMINIO_DO_PEDIDO`] com o
/// id como resumo — o mesmo prefixo, que o registro de domínios da imagem
/// tem.
pub fn assinavel(id: &Hash) -> [u8; 43] {
    let mut m = [0u8; 43];
    m[..11].copy_from_slice(SEPARADOR_DO_PEDIDO);
    m[11..].copy_from_slice(id);
    m
}

/// Por que um pedido não se monta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O nonce passa de [`MAIOR_NONCE`] bytes.
    NonceLongo,
    /// Um remetente que não é o anônimo num pedido sem assinatura.
    RemetenteNaoAnonimo,
    /// Um pedido assinado cujo remetente não é o Principal da chave.
    RemetenteNaoEDaChave,
}

impl core::fmt::Display for Erro {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Erro::NonceLongo => "nonce com mais de 32 bytes",
            Erro::RemetenteNaoAnonimo => "so o remetente anonimo pede sem assinar",
            Erro::RemetenteNaoEDaChave => "o remetente nao e o principal da chave que assina",
        })
    }
}

/// Confere quem pede contra a autenticação: sem ela, só o anônimo; com
/// ela, só o Principal da chave.
fn conferir_remetente(
    remetente: &Principal,
    autenticacao: Option<&Autenticacao<'_>>,
) -> Result<(), Erro> {
    match autenticacao {
        None if *remetente != Principal::ANONIMO => Err(Erro::RemetenteNaoAnonimo),
        Some(a) if *remetente != Principal::auto_autenticado(a.chave_der) => {
            Err(Erro::RemetenteNaoEDaChave)
        }
        _ => Ok(()),
    }
}

/// O envelope: `55799({"content": …, ? "sender_pubkey", ? "sender_sig"})`,
/// com o conteúdo que `conteudo` escreve.
fn envelope_com(
    autenticacao: Option<&Autenticacao<'_>>,
    conteudo: impl FnOnce(&mut Escritor),
) -> Vec<u8> {
    let mut e = Escritor::novo();
    e.autodescrita();
    e.mapa(if autenticacao.is_some() { 3 } else { 1 });
    e.texto("content");
    conteudo(&mut e);
    if let Some(a) = autenticacao {
        e.texto("sender_pubkey");
        e.bytes(a.chave_der);
        e.texto("sender_sig");
        e.bytes(a.assinatura);
    }
    e.terminar()
}

/// O que a consulta e a chamada têm em comum: o conteúdo de um pedido a
/// um método de canister, que só difere no `request_type`.
struct AoCanister<'a> {
    tipo: &'static str,
    canister: &'a Principal,
    metodo: &'a str,
    arg: &'a [u8],
    remetente: &'a Principal,
    vencimento_ns: u64,
    nonce: Option<&'a [u8]>,
}

impl AoCanister<'_> {
    fn conferir(&self) -> Result<(), Erro> {
        if self.nonce.is_some_and(|n| n.len() > MAIOR_NONCE) {
            return Err(Erro::NonceLongo);
        }
        Ok(())
    }

    /// O id: o hash do conteúdo.
    fn id(&self) -> Hash {
        let mut campos = Vec::with_capacity(7);
        campos.push((
            resumo::de_texto("request_type"),
            resumo::de_texto(self.tipo),
        ));
        campos.push((
            resumo::de_texto("canister_id"),
            resumo::de_bytes(self.canister.bytes()),
        ));
        campos.push((
            resumo::de_texto("method_name"),
            resumo::de_texto(self.metodo),
        ));
        campos.push((resumo::de_texto("arg"), resumo::de_bytes(self.arg)));
        campos.push((
            resumo::de_texto("sender"),
            resumo::de_bytes(self.remetente.bytes()),
        ));
        campos.push((
            resumo::de_texto("ingress_expiry"),
            resumo::de_nat(self.vencimento_ns),
        ));
        if let Some(n) = self.nonce {
            campos.push((resumo::de_texto("nonce"), resumo::de_bytes(n)));
        }
        resumo::de_mapa(&campos)
    }

    /// O conteúdo, em CBOR.
    fn escrever(&self, e: &mut Escritor) {
        e.mapa(if self.nonce.is_some() { 7 } else { 6 });
        e.texto("request_type");
        e.texto(self.tipo);
        e.texto("canister_id");
        e.bytes(self.canister.bytes());
        e.texto("method_name");
        e.texto(self.metodo);
        e.texto("arg");
        e.bytes(self.arg);
        e.texto("sender");
        e.bytes(self.remetente.bytes());
        e.texto("ingress_expiry");
        e.nat(self.vencimento_ns);
        if let Some(n) = self.nonce {
            e.texto("nonce");
            e.bytes(n);
        }
    }
}

impl Consulta<'_> {
    fn conteudo(&self) -> Result<AoCanister<'_>, Erro> {
        let c = AoCanister {
            tipo: "query",
            canister: &self.canister,
            metodo: self.metodo,
            arg: self.arg,
            remetente: &self.remetente,
            vencimento_ns: self.vencimento_ns,
            nonce: self.nonce,
        };
        c.conferir()?;
        if self.remetente != Principal::ANONIMO {
            return Err(Erro::RemetenteNaoAnonimo);
        }
        Ok(c)
    }

    /// O id do pedido: o hash do conteúdo.
    pub fn id(&self) -> Result<Hash, Erro> {
        Ok(self.conteudo()?.id())
    }

    /// O corpo HTTP: o envelope, em CBOR.
    pub fn envelope(&self) -> Result<Vec<u8>, Erro> {
        let c = self.conteudo()?;
        Ok(envelope_com(None, |e| c.escrever(e)))
    }

    /// O conteúdo da consulta assinada pela chave `chave_der`: o
    /// remetente tem de ser o Principal dela.
    fn conteudo_assinado(&self, chave_der: &[u8]) -> Result<AoCanister<'_>, Erro> {
        let c = AoCanister {
            tipo: "query",
            canister: &self.canister,
            metodo: self.metodo,
            arg: self.arg,
            remetente: &self.remetente,
            vencimento_ns: self.vencimento_ns,
            nonce: self.nonce,
        };
        c.conferir()?;
        if self.remetente != Principal::auto_autenticado(chave_der) {
            return Err(Erro::RemetenteNaoEDaChave);
        }
        Ok(c)
    }

    /// O id da consulta assinada pela chave `chave_der` — a pública, em
    /// DER: o hash do conteúdo, o que se assina. Um remetente que não é o
    /// Principal da chave não tem id, e nada se assina por ele.
    pub fn id_assinada(&self, chave_der: &[u8]) -> Result<Hash, Erro> {
        Ok(self.conteudo_assinado(chave_der)?.id())
    }

    /// O corpo HTTP da consulta assinada: o envelope, em CBOR, com a
    /// pública e a assinatura do [`Consulta::id_assinada`].
    pub fn envelope_assinado(&self, autenticacao: &Autenticacao<'_>) -> Result<Vec<u8>, Erro> {
        let c = self.conteudo_assinado(autenticacao.chave_der)?;
        Ok(envelope_com(Some(autenticacao), |e| c.escrever(e)))
    }
}

impl Chamada<'_> {
    fn conteudo(&self) -> Result<AoCanister<'_>, Erro> {
        let c = AoCanister {
            tipo: "call",
            canister: &self.canister,
            metodo: self.metodo,
            arg: self.arg,
            remetente: &self.remetente,
            vencimento_ns: self.vencimento_ns,
            nonce: self.nonce,
        };
        c.conferir()?;
        Ok(c)
    }

    /// O id do pedido: o hash do conteúdo — o que se assina.
    pub fn id(&self) -> Result<Hash, Erro> {
        Ok(self.conteudo()?.id())
    }

    /// O corpo HTTP: o envelope, em CBOR — do anônimo, sem `autenticacao`,
    /// ou de quem assinou o [`Chamada::id`].
    pub fn envelope(&self, autenticacao: Option<&Autenticacao<'_>>) -> Result<Vec<u8>, Erro> {
        let c = self.conteudo()?;
        conferir_remetente(&self.remetente, autenticacao)?;
        Ok(envelope_com(autenticacao, |e| c.escrever(e)))
    }
}

impl LeituraDeEstado<'_> {
    /// O id do pedido: o hash do conteúdo. Os caminhos são uma lista de
    /// listas de rótulos.
    pub fn id(&self) -> Result<Hash, Erro> {
        let caminhos = resumo::de_lista(
            self.caminhos
                .iter()
                .map(|c| resumo::de_lista(c.iter().map(|r| resumo::de_bytes(r)))),
        );
        Ok(resumo::de_mapa(&[
            (
                resumo::de_texto("request_type"),
                resumo::de_texto("read_state"),
            ),
            (resumo::de_texto("paths"), caminhos),
            (
                resumo::de_texto("sender"),
                resumo::de_bytes(self.remetente.bytes()),
            ),
            (
                resumo::de_texto("ingress_expiry"),
                resumo::de_nat(self.vencimento_ns),
            ),
        ]))
    }

    /// O corpo HTTP do anônimo: o envelope, em CBOR.
    pub fn envelope(&self) -> Result<Vec<u8>, Erro> {
        self.envelope_assinado(None)
    }

    /// O corpo HTTP: o envelope, em CBOR — do anônimo, sem
    /// `autenticacao`, ou de quem assinou o [`LeituraDeEstado::id`].
    pub fn envelope_assinado(
        &self,
        autenticacao: Option<&Autenticacao<'_>>,
    ) -> Result<Vec<u8>, Erro> {
        conferir_remetente(&self.remetente, autenticacao)?;
        Ok(envelope_com(autenticacao, |e| {
            e.mapa(4);
            e.texto("request_type");
            e.texto("read_state");
            e.texto("paths");
            e.lista(self.caminhos.len());
            for caminho in self.caminhos {
                e.lista(caminho.len());
                for rotulo in *caminho {
                    e.bytes(rotulo);
                }
            }
            e.texto("sender");
            e.bytes(self.remetente.bytes());
            e.texto("ingress_expiry");
            e.nat(self.vencimento_ns);
        }))
    }
}

#[cfg(test)]
mod separador {
    use super::*;

    /// O separador é o tamanho do nome e o nome.
    #[test]
    fn o_separador_e_o_do_nome() {
        assert_eq!(usize::from(SEPARADOR_DO_PEDIDO[0]), DOMINIO_DO_PEDIDO.len());
        assert_eq!(&SEPARADOR_DO_PEDIDO[1..], DOMINIO_DO_PEDIDO.as_bytes());
    }
}

#[cfg(test)]
mod testes;
