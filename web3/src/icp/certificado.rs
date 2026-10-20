//! O certificado: a árvore, a assinatura BLS e a delegação —
//! **especificação**, *Certification*, *Delegation* e *Request: Query
//! call* (`verify_response`).
//!
//! Um certificado vale para um canister quando:
//!
//! 1. sem delegação, a assinatura confere com a chave da raiz, e a
//!    sub-rede é a raiz: o Principal auto-autenticado da chave dela, cujas
//!    faixas (`/subnet/<raiz>/canister_ranges`) estão no próprio
//!    certificado e contêm o canister;
//! 2. com delegação, o certificado da delegação **não tem outra**
//!    delegação, confere com a chave da raiz, traz a chave da sub-rede
//!    (`/subnet/<sub-rede>/public_key`) e as faixas dela
//!    (`/canister_ranges/<sub-rede>/…`) contendo o canister; e a
//!    assinatura do certificado confere com essa chave;
//! 3. o tempo dele (`/time`) dista da hora de quem verifica no máximo
//!    [`super::TOLERANCIA_NS`], para trás ou para a frente.
//!
//! Escolhas onde a especificação deixa ao cliente, e de onde vêm:
//!
//! - o tempo do certificado da delegação não é conferido: o IC só renova
//!   a delegação nas atualizações das réplicas (**especificação**: "at
//!   least a week"), e as duas implementações oficiais também não
//!   conferem;
//! - um certificado do futuro além da tolerância é recusado, como no
//!   `ic-certificate-verification`; o `ic-agent` aceita (o lado que
//!   recusa, aqui);
//! - as faixas de uma sub-rede delegada são as da forma fragmentada que a
//!   especificação manda conferir na v3; a forma antiga
//!   (`/subnet/<sub-rede>/canister_ranges` na delegação), que as
//!   implementações oficiais ainda aceitam por compatibilidade, não vale
//!   aqui;
//! - um fragmento de faixas podado não esconde nada que importe: ele só
//!   poderia conter faixas, e uma faixa a menos só pode recusar. Um
//!   canister está numa sub-rede quando um fragmento **achado** o contém.
//!
//! Nada aqui é autorização: um certificado válido prova o que a sub-rede
//! disse, e não dá permissão nenhuma no Duke.

use core::fmt;

use super::TOLERANCIA_NS;
use super::arvore::{self, Arvore, Procura, Sub};
use super::cbor::{self, Valor};
use super::principal::Principal;

/// O separador de domínio da assinatura da raiz da árvore —
/// **especificação**: `domain_sep("ic-state-root")`.
pub const SEPARADOR_DA_RAIZ: &[u8; 14] = b"\x0Dic-state-root";

/// O prefixo DER de uma chave BLS12-381 do IC — **especificação**: RFC
/// 5480 com os OIDs 1.3.6.1.4.1.44668.5.3.1.2.1 (algoritmo) e
/// 1.3.6.1.4.1.44668.5.3.2.1 (curva); **referência**: o mesmo prefixo de
/// 37 bytes nas duas implementações oficiais.
pub const PREFIXO_DER_BLS: [u8; 37] = [
    0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05,
    0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03,
    0x02, 0x01, 0x03, 0x61, 0x00,
];

/// Uma chave BLS12-381 crua: um ponto de G2 comprimido.
pub const CHAVE_BLS: usize = 96;

/// Uma chave BLS em DER: o prefixo e a chave crua.
pub const CHAVE_BLS_DER: usize = PREFIXO_DER_BLS.len() + CHAVE_BLS;

/// O prefixo DER de uma chave Ed25519 de nó — RFC 8410; **referência**:
/// o `ic-agent` confere estes 12 bytes e o tamanho, 44.
pub const PREFIXO_DER_ED25519: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];

/// Por que um certificado não vale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O CBOR não se lê.
    Cbor(cbor::Erro),
    /// A árvore não se lê, ou é mal formada.
    Arvore(arvore::Erro),
    /// O mapa do certificado sem `tree` ou `signature`, ou com um campo
    /// do tipo errado.
    Forma,
    /// O certificado da delegação tem outra delegação.
    DelegacaoAninhada,
    /// O certificado da delegação não confere com a chave da raiz.
    AssinaturaDaDelegacao,
    /// A delegação não traz a chave da sub-rede.
    ChaveDaSubRedeAusente,
    /// Uma chave BLS em DER sem o tamanho ou sem o prefixo.
    ChaveDer,
    /// A assinatura do certificado não confere.
    Assinatura,
    /// Sem `/time`.
    SemTempo,
    /// Um `/time` que não é um LEB128 de 64 bits.
    TempoForaDaForma,
    /// O tempo do certificado é mais velho que a tolerância.
    Velho {
        /// O tempo do certificado.
        tempo_ns: u64,
        /// A hora de quem verificou.
        agora_ns: u64,
    },
    /// O tempo do certificado está à frente da tolerância.
    Futuro {
        /// O tempo do certificado.
        tempo_ns: u64,
        /// A hora de quem verificou.
        agora_ns: u64,
    },
    /// As faixas da sub-rede não estão no certificado.
    FaixasAusentes,
    /// Faixas fora da forma `[[principal, principal], …]`.
    FaixasForaDaForma,
    /// O canister não está nas faixas da sub-rede que assinou.
    ForaDasFaixas,
    /// A chave de um nó fora da forma DER de 44 bytes.
    ChaveDoNo,
    /// O certificado de uma chamada é de outra sub-rede que a da leitura
    /// separada das faixas — ver [`verificar_na_sub_rede`].
    OutraSubRede,
}

impl From<cbor::Erro> for Erro {
    fn from(e: cbor::Erro) -> Erro {
        Erro::Cbor(e)
    }
}

impl From<arvore::Erro> for Erro {
    fn from(e: arvore::Erro) -> Erro {
        Erro::Arvore(e)
    }
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::Cbor(e) => write!(f, "certificado: {e}"),
            Erro::Arvore(e) => write!(f, "certificado: {e}"),
            Erro::Forma => f.write_str("certificado fora da forma"),
            Erro::DelegacaoAninhada => f.write_str("delegacao aninhada"),
            Erro::AssinaturaDaDelegacao => {
                f.write_str("a delegacao nao confere com a chave da raiz")
            }
            Erro::ChaveDaSubRedeAusente => f.write_str("a delegacao nao traz a chave da sub-rede"),
            Erro::ChaveDer => f.write_str("chave BLS fora da forma DER"),
            Erro::Assinatura => f.write_str("a assinatura BLS do certificado nao confere"),
            Erro::SemTempo => f.write_str("certificado sem /time"),
            Erro::TempoForaDaForma => f.write_str("/time fora da forma"),
            Erro::Velho { tempo_ns, agora_ns } => write!(
                f,
                "certificado velho: {} s antes da hora",
                (agora_ns - tempo_ns) / 1_000_000_000
            ),
            Erro::Futuro { tempo_ns, agora_ns } => write!(
                f,
                "certificado do futuro: {} s depois da hora",
                (tempo_ns - agora_ns) / 1_000_000_000
            ),
            Erro::FaixasAusentes => f.write_str("as faixas da sub-rede nao estao no certificado"),
            Erro::FaixasForaDaForma => f.write_str("faixas de canister fora da forma"),
            Erro::ForaDasFaixas => f.write_str("o canister nao esta nas faixas da sub-rede"),
            Erro::ChaveDoNo => f.write_str("chave de no fora da forma DER"),
            Erro::OutraSubRede => {
                f.write_str("o certificado e de outra sub-rede que a da leitura das faixas")
            }
        }
    }
}

/// A delegação de um certificado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delegacao<'a> {
    /// A sub-rede a que a raiz delegou.
    pub sub_rede: Principal,
    /// O certificado da raiz que a prova, ainda em CBOR.
    pub certificado: &'a [u8],
}

/// Um certificado lido, ainda não conferido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificado<'a> {
    /// A árvore, bem formada.
    pub arvore: Arvore<'a>,
    /// A assinatura BLS da raiz da árvore.
    pub assinatura: &'a [u8],
    /// A delegação, se não foi a raiz quem assinou.
    pub delegacao: Option<Delegacao<'a>>,
}

impl<'a> Certificado<'a> {
    /// Lê um certificado — **especificação**, *Encoding of certificates*:
    /// `55799({tree, signature, ? delegation: {subnet_id, certificate}})`.
    /// Campos a mais são ignorados, como nas implementações oficiais: não
    /// mudam nada do que se confere.
    pub fn ler(bytes: &'a [u8]) -> Result<Certificado<'a>, Erro> {
        let Valor::Mapa(pares) = cbor::ler(bytes)? else {
            return Err(Erro::Forma);
        };
        let (mut arvore, mut assinatura, mut delegacao) = (None, None, None);
        for (chave, valor) in pares {
            match chave {
                "tree" => arvore = Some(Arvore::de_cbor(valor)?),
                "signature" => assinatura = Some(valor.bytes().ok_or(Erro::Forma)?),
                "delegation" => {
                    let sub_rede = valor
                        .campo("subnet_id")
                        .and_then(Valor::bytes)
                        .ok_or(Erro::Forma)?;
                    let certificado = valor
                        .campo("certificate")
                        .and_then(Valor::bytes)
                        .ok_or(Erro::Forma)?;
                    delegacao = Some(Delegacao {
                        sub_rede: Principal::de_bytes(sub_rede).map_err(|_| Erro::Forma)?,
                        certificado,
                    });
                }
                _ => {}
            }
        }
        Ok(Certificado {
            arvore: arvore.ok_or(Erro::Forma)?,
            assinatura: assinatura.ok_or(Erro::Forma)?,
            delegacao,
        })
    }

    /// Se a assinatura confere com esta chave BLS crua: a raiz da árvore,
    /// precedida do separador, assinada — **especificação**,
    /// `verify_cert`; a conta é a da `ic-verify-bls-signature`.
    pub fn assinado_por(&self, chave: &[u8; CHAVE_BLS]) -> bool {
        let mut mensagem = [0u8; 14 + 32];
        mensagem[..14].copy_from_slice(SEPARADOR_DA_RAIZ);
        mensagem[14..].copy_from_slice(&self.arvore.raiz());
        ic_verify_bls_signature::verify_bls_signature(self.assinatura, &mensagem, chave).is_ok()
    }

    /// O tempo do certificado, em nanossegundos desde 1970.
    pub fn tempo_ns(&self) -> Result<u64, Erro> {
        match self.arvore.procurar(&[b"time"]) {
            Procura::Achou(v) => ler_leb128(v).ok_or(Erro::TempoForaDaForma),
            _ => Err(Erro::SemTempo),
        }
    }
}

/// A chave crua de uma chave BLS em DER — **especificação**,
/// `extract_der`; **referência**: o tamanho e o prefixo exatos.
///
/// A chave no infinito é recusada: com ela, a assinatura no infinito
/// confere qualquer mensagem (os dois pareamentos dão 1). O bit de
/// infinito é o segundo do primeiro byte da forma comprimida.
pub fn extrair_der(der: &[u8]) -> Result<[u8; CHAVE_BLS], Erro> {
    if der.len() != CHAVE_BLS_DER || der[..PREFIXO_DER_BLS.len()] != PREFIXO_DER_BLS {
        return Err(Erro::ChaveDer);
    }
    let mut chave = [0u8; CHAVE_BLS];
    chave.copy_from_slice(&der[PREFIXO_DER_BLS.len()..]);
    if chave[0] & 0x40 != 0 {
        return Err(Erro::ChaveDer);
    }
    Ok(chave)
}

/// A raiz de confiança de uma rede do IC: a chave BLS da sub-rede raiz,
/// conhecida antes — **especificação**, *Root of trust*. Vem de um arquivo
/// da imagem (ver [`super::registro`]), nunca da rede.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Raiz {
    der: [u8; CHAVE_BLS_DER],
}

impl fmt::Debug for Raiz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Raiz({})", self.sub_rede())
    }
}

impl Raiz {
    /// A raiz desta chave em DER. A chave tem de ser um ponto de G2, no
    /// subgrupo e fora do infinito: uma que não é se descobre aqui, ao ler
    /// o arquivo de redes, e não na primeira resposta que não confere.
    pub fn de_der(der: &[u8]) -> Result<Raiz, Erro> {
        let chave = extrair_der(der)?;
        if ic_verify_bls_signature::PublicKey::deserialize(&chave).is_err() {
            return Err(Erro::ChaveDer);
        }
        let mut raiz = [0u8; CHAVE_BLS_DER];
        raiz.copy_from_slice(der);
        Ok(Raiz { der: raiz })
    }

    /// A chave em DER.
    pub fn der(&self) -> &[u8; CHAVE_BLS_DER] {
        &self.der
    }

    /// A chave crua.
    pub fn chave(&self) -> [u8; CHAVE_BLS] {
        let mut chave = [0u8; CHAVE_BLS];
        chave.copy_from_slice(&self.der[PREFIXO_DER_BLS.len()..]);
        chave
    }

    /// O id da sub-rede raiz: o Principal auto-autenticado da chave —
    /// **especificação**, `RootSubnetId`; **referência**: o `ic-agent`
    /// chega à sub-rede de um certificado sem delegação assim.
    pub fn sub_rede(&self) -> Principal {
        Principal::auto_autenticado(&self.der)
    }
}

/// O que um certificado conferido prova.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Autoridade {
    /// A sub-rede que assinou, e que hospeda o canister.
    pub sub_rede: Principal,
    /// Se assinou por delegação da raiz.
    pub delegada: bool,
    /// O tempo do certificado.
    pub tempo_ns: u64,
}

/// A sub-rede que assina o certificado e a chave dela: a raiz, sem
/// delegação; com ela, a sub-rede delegada, depois de conferir a
/// delegação — de um nível só, assinada pela raiz, com a chave da
/// sub-rede e as faixas dela contendo o canister.
fn quem_assina(
    cert: &Certificado<'_>,
    raiz: &Raiz,
    canister: &Principal,
) -> Result<(Principal, [u8; CHAVE_BLS]), Erro> {
    let Some(d) = &cert.delegacao else {
        return Ok((raiz.sub_rede(), raiz.chave()));
    };
    let dc = Certificado::ler(d.certificado)?;
    if dc.delegacao.is_some() {
        return Err(Erro::DelegacaoAninhada);
    }
    if !dc.assinado_por(&raiz.chave()) {
        return Err(Erro::AssinaturaDaDelegacao);
    }
    let der = match dc
        .arvore
        .procurar(&[b"subnet", d.sub_rede.bytes(), b"public_key"])
    {
        Procura::Achou(der) => der,
        _ => return Err(Erro::ChaveDaSubRedeAusente),
    };
    let chave = extrair_der(der)?;
    match dc
        .arvore
        .subarvore(&[b"canister_ranges", d.sub_rede.bytes()])
    {
        Sub::Achou(fragmentos) => {
            if !fragmentos_contem(fragmentos, canister)? {
                return Err(Erro::ForaDasFaixas);
            }
        }
        Sub::Ausente | Sub::Desconhecida => return Err(Erro::FaixasAusentes),
    }
    Ok((d.sub_rede, chave))
}

/// A assinatura do certificado com a chave de quem assina, e o tempo dele
/// na janela de [`TOLERANCIA_NS`] em volta de `agora_ns`. Devolve o tempo.
fn assinado_e_no_tempo(
    cert: &Certificado<'_>,
    chave: &[u8; CHAVE_BLS],
    agora_ns: u64,
) -> Result<u64, Erro> {
    if !cert.assinado_por(chave) {
        return Err(Erro::Assinatura);
    }
    let tempo_ns = cert.tempo_ns()?;
    if tempo_ns.saturating_add(TOLERANCIA_NS) < agora_ns {
        return Err(Erro::Velho { tempo_ns, agora_ns });
    }
    if tempo_ns > agora_ns.saturating_add(TOLERANCIA_NS) {
        return Err(Erro::Futuro { tempo_ns, agora_ns });
    }
    Ok(tempo_ns)
}

/// Confere um certificado de uma leitura de estado no escopo de um
/// canister (`/api/v3/canister/<canister>/read_state`): a cadeia até a
/// raiz, as faixas e o tempo.
pub fn verificar(
    cert: &Certificado<'_>,
    raiz: &Raiz,
    canister: &Principal,
    agora_ns: u64,
) -> Result<Autoridade, Erro> {
    let (sub_rede, chave) = quem_assina(cert, raiz, canister)?;
    let tempo_ns = assinado_e_no_tempo(cert, &chave, agora_ns)?;
    if cert.delegacao.is_none() {
        match cert
            .arvore
            .procurar(&[b"subnet", sub_rede.bytes(), b"canister_ranges"])
        {
            Procura::Achou(faixas) => {
                if !faixas_contem(faixas, canister)? {
                    return Err(Erro::ForaDasFaixas);
                }
            }
            _ => return Err(Erro::FaixasAusentes),
        }
    }
    Ok(Autoridade {
        sub_rede,
        delegada: cert.delegacao.is_some(),
        tempo_ns,
    })
}

/// Confere o certificado de uma chamada — o do corpo da chamada
/// síncrona, ou o de uma leitura do `request_status` dela: a cadeia até a
/// raiz e o tempo, como [`verificar`], **na sub-rede que a leitura
/// separada das faixas já provou ser a do canister** — `faixas`, a
/// [`Autoridade`] de um `read_state` de `["subnet"]` conferido por
/// [`verificar`].
///
/// Com delegação, o certificado traz as faixas da sub-rede, conferidas
/// como em [`verificar`], e a sub-rede tem de ser a da leitura separada.
/// Sem delegação, quem assina é a raiz: o canister é da sub-rede raiz, e o
/// certificado de uma chamada não traz as faixas dela — elas vêm da
/// leitura separada, que tem de ter sido da raiz também. Se o certificado
/// traz as faixas, elas são conferidas do mesmo jeito.
///
/// **Referência**: sem delegação, o `ic-agent` aceita o certificado da
/// raiz para qualquer canister. Este lado recusa sem a prova das faixas —
/// o lado que recusa.
pub fn verificar_na_sub_rede(
    cert: &Certificado<'_>,
    raiz: &Raiz,
    canister: &Principal,
    agora_ns: u64,
    faixas: &Autoridade,
) -> Result<Autoridade, Erro> {
    let (sub_rede, chave) = quem_assina(cert, raiz, canister)?;
    if sub_rede != faixas.sub_rede || cert.delegacao.is_some() != faixas.delegada {
        return Err(Erro::OutraSubRede);
    }
    let tempo_ns = assinado_e_no_tempo(cert, &chave, agora_ns)?;
    if cert.delegacao.is_none()
        && let Procura::Achou(faixas) =
            cert.arvore
                .procurar(&[b"subnet", sub_rede.bytes(), b"canister_ranges"])
        && !faixas_contem(faixas, canister)?
    {
        return Err(Erro::ForaDasFaixas);
    }
    Ok(Autoridade {
        sub_rede,
        delegada: cert.delegacao.is_some(),
        tempo_ns,
    })
}

/// Se um fragmento achado sob `/canister_ranges/<sub-rede>` contém o
/// canister. Cada fragmento é uma folha sob o rótulo do canister com que
/// começa; um galho podado só esconde faixas, e é pulado.
fn fragmentos_contem(fragmentos: &Arvore<'_>, canister: &Principal) -> Result<bool, Erro> {
    for arvore in fragmentos.floresta() {
        match arvore {
            Arvore::Rotulada(_, sub) => match **sub {
                Arvore::Folha(faixas) => {
                    if faixas_contem(faixas, canister)? {
                        return Ok(true);
                    }
                }
                Arvore::Podada(_) => {}
                _ => return Err(Erro::FaixasForaDaForma),
            },
            Arvore::Podada(_) => {}
            _ => return Err(Erro::FaixasForaDaForma),
        }
    }
    Ok(false)
}

/// Se uma lista de faixas contém o canister — **especificação**:
/// `tagged<[*[principal principal]]>`, intervalos fechados na ordem
/// lexicográfica dos bytes.
///
/// As implementações oficiais comparam com a ordem do `ic_principal`, que
/// põe o tamanho na frente ([`Principal::ordem_oficial`]). As duas só
/// discordam entre Principals de tamanhos diferentes — os canisters e as
/// faixas do IC têm todos 10 bytes —, e aqui o canister tem de estar na
/// faixa pelas **duas**: o lado que recusa.
pub fn faixas_contem(faixas: &[u8], canister: &Principal) -> Result<bool, Erro> {
    let Valor::Lista(lista) = cbor::ler(faixas).map_err(|_| Erro::FaixasForaDaForma)? else {
        return Err(Erro::FaixasForaDaForma);
    };
    let mut contem = false;
    for faixa in &lista {
        let [baixo, alto] = faixa.lista().ok_or(Erro::FaixasForaDaForma)? else {
            return Err(Erro::FaixasForaDaForma);
        };
        let principal = |v: &Valor<'_>| {
            v.bytes()
                .and_then(|b| Principal::de_bytes(b).ok())
                .ok_or(Erro::FaixasForaDaForma)
        };
        let (baixo, alto) = (principal(baixo)?, principal(alto)?);
        let lexicografica = baixo <= *canister && *canister <= alto;
        let oficial =
            baixo.ordem_oficial(canister).is_le() && canister.ordem_oficial(&alto).is_le();
        if lexicografica && oficial {
            contem = true;
        }
    }
    Ok(contem)
}

/// A chave Ed25519 crua de um nó da sub-rede, pelo certificado —
/// **especificação**: `lookup(["subnet", SubnetId, "node", NodeId,
/// "public_key"], Cert) = Found PK`. `None` quando o nó não está (ou está
/// podado): um nó que o certificado não mostra não assina nada aqui.
pub fn chave_do_no(
    cert: &Certificado<'_>,
    sub_rede: &Principal,
    no: &Principal,
) -> Result<Option<[u8; 32]>, Erro> {
    let der = match cert.arvore.procurar(&[
        b"subnet",
        sub_rede.bytes(),
        b"node",
        no.bytes(),
        b"public_key",
    ]) {
        Procura::Achou(der) => der,
        _ => return Ok(None),
    };
    if der.len() != 44 || der[..12] != PREFIXO_DER_ED25519 {
        return Err(Erro::ChaveDoNo);
    }
    let mut chave = [0u8; 32];
    chave.copy_from_slice(&der[12..]);
    Ok(Some(chave))
}

/// Quantos nós da sub-rede o certificado mostra com chave — o teto de
/// assinaturas de uma resposta (**referência**: o `ic-agent` recusa mais
/// assinaturas que nós).
pub fn nos_com_chave(cert: &Certificado<'_>, sub_rede: &Principal) -> usize {
    match cert
        .arvore
        .subarvore(&[b"subnet", sub_rede.bytes(), b"node"])
    {
        Sub::Achou(nos) => nos
            .floresta()
            .iter()
            .filter(|no| match no {
                Arvore::Rotulada(_, sub) => {
                    matches!(sub.procurar(&[b"public_key"]), Procura::Achou(_))
                }
                _ => false,
            })
            .count(),
        _ => 0,
    }
}

/// Um LEB128 sem sinal que ocupa os bytes inteiros e cabe em 64 bits.
pub fn ler_leb128(bytes: &[u8]) -> Option<u64> {
    let mut valor: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        let parte = u64::from(b & 0x7f);
        let deslocamento = 7 * i as u32;
        if deslocamento >= 64 || (deslocamento == 63 && parte > 1) {
            return None;
        }
        valor |= parte << deslocamento;
        if b & 0x80 == 0 {
            return (i + 1 == bytes.len()).then_some(valor);
        }
    }
    None
}

#[cfg(test)]
mod testes;
