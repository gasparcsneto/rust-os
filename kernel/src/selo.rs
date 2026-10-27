//! O selo da identidade: a chave do Duke deste boot — da imagem, do selo
//! no TPM, ou nascida numa instalação nova.
//!
//! Não é o selo de código dos editores (`sigilo::codigo`): este é o objeto
//! selado no TPM que guarda a chave privada da identidade — ver
//! `ancora::identidade` e `ancora::cofre`.
//!
//! # De onde vem a chave
//!
//! - **Da imagem**, se a raiz traz `/etc/duke/privado/chave`: a imagem da
//!   bancada, e as máquinas de produção provisionadas antes do selo, que
//!   seguem iguais — ver [`crate::identidade::carregar`]. A área do selo
//!   fica sem uso.
//! - **Do selo**, sem o arquivo: a área no começo da reserva do fim da
//!   partição de estado, aberta pelo TPM em que a identidade nasceu. A EK
//!   da área é conferida na conexão, antes de qualquer sessão; a chave
//!   aberta, com a pública da área.
//! - **Nascida**, numa instalação nova — nenhum selo, nenhum journal,
//!   nenhum índice do Duke no TPM: sorteada aqui, selada, aberta de volta e
//!   conferida, e gravada nas duas cópias antes de entrar em uso.
//!
//! O que decide entre o selo e o nascimento é `ancora::identidade::decidir`,
//! testado no hospedeiro com a tabela inteira. A origem é a presença do
//! arquivo, e não a marca da imagem: a marca só diz, nunca decide — ver
//! [`crate::imagem`].
//!
//! # A ordem no boot
//!
//! Depois da raiz montada, da janela da partição de estado, do TPM e do
//! gerador; antes da persistência, que deriva da chave a cifra do journal,
//! a senha da âncora, a do índice de geração e as do armazém. Sem
//! identidade, a persistência não abre — recusada, se a partição tem
//! journal, porque o que ele guarda pode ser uma revogação, e então as
//! credenciais fecham —, e as portas dos agentes recusam o aperto. A
//! serial continua, com o papel dela: o motivo está no `system.info`.
//!
//! # A conexão com o TPM
//!
//! A da identidade é própria e curta: a EK, a sessão salgada, o primário do
//! cofre, o selado carregado e aberto — e tudo sai do TPM antes de a
//! persistência conectar a dela. Ela não toca índice nenhum: a senha da
//! âncora deriva da identidade, e a conexão leva uma zerada que nenhum
//! comando usa. Quem fala com o cofre é a persistência, como para as
//! chaves de assinatura; este módulo decide e pede.
//!
//! # As quedas
//!
//! O nascimento é selar e conferir, gravar a primeira cópia e descarregar,
//! gravar a segunda e descarregar. Uma queda antes da primeira cópia deixa
//! a área como estava, e o boot seguinte nasce de novo: nada dependia da
//! chave sorteada. Uma queda depois dela deixa uma cópia inteira, que o
//! boot seguinte abre, e com ela repara a outra. Um setor cortado no meio
//! da escrita é uma cópia estragada: a outra decide. A bancada derruba a
//! energia em cada um desses pontos — ver `kernel/src/quedas.rs`.
//!
//! # A auditoria
//!
//! O nascimento, o reparo de uma cópia e a recusa vão para a auditoria,
//! pelo kernel, como `system.identity`, depois do `policy.load` do boot. A
//! abertura de todo boot não: é o que todo boot faz, e a persistência
//! aberta já diz que a identidade abriu.

use alloc::format;

use ancora::identidade::{Area, Decisao, Leitura};
use politica::Codigo;
use sigilo::zeroize::Zeroize;

use crate::identidade::{self, OrigemDaChave, SituacaoDaChave};
use crate::persistencia;

/// O método da auditoria.
const METODO: &str = "system.identity";

/// A cópia que não era igual à aberta, e se a reescrita dela deu certo.
type Reparo = Option<(usize, Result<(), &'static str>)>;

/// A identidade estabelecida pelo selo.
struct Estabelecida {
    chave: [u8; 32],
    origem: OrigemDaChave,
    reparo: Reparo,
}

/// Estabelece a identidade do Duke deste boot — ver o cabeçalho do módulo.
/// No boot, antes da persistência, e uma vez.
pub fn estabelecer() {
    match identidade::situacao_da_chave() {
        SituacaoDaChave::Em(OrigemDaChave::Imagem) => {
            if let Some(p) = identidade::publica_do_duke() {
                crate::log_info!(
                    "identidade",
                    "identidade do Duke {}: a chave da imagem",
                    sigilo::hex(&p)
                );
            }
            // Um selo inteiro ao lado da chave da imagem é um disco que já
            // teve uma identidade nascida aqui: a chave da imagem vence, e
            // o journal daquela, se houver, não abre com ela.
            if let Ok(copias) = persistencia::ler_a_area_da_identidade()
                && copias.iter().any(|c| matches!(c, Leitura::Valida(_)))
            {
                crate::log_warn!(
                    "identidade",
                    "a imagem traz a chave do Duke, e o disco tem um selo de identidade: o selo fica sem uso"
                );
            }
            return;
        }
        SituacaoDaChave::Em(_) => return,
        SituacaoDaChave::Sem(motivo) => {
            recusar(motivo);
            return;
        }
        SituacaoDaChave::Pendente => {}
    }
    #[cfg(feature = "quedas")]
    persistencia::carregar_o_plano_de_quedas();
    let inicio = crate::tempo::uptime_ms();
    let Estabelecida {
        mut chave,
        origem,
        reparo,
    } = match pelo_selo() {
        Ok(e) => e,
        Err(motivo) => {
            recusar(motivo);
            return;
        }
    };
    let ms = crate::tempo::uptime_ms().saturating_sub(inicio);
    let publica = sigilo::hex(&sigilo::publica_de(&chave));
    let adotada = identidade::adotar_a_chave(chave, origem);
    chave.zeroize();
    if let Err(motivo) = adotada {
        recusar(motivo);
        return;
    }
    match origem {
        OrigemDaChave::Nascida => {
            crate::log_warn!(
                "identidade",
                "identidade do Duke {}: nascida neste boot e selada no TPM, em {} ms",
                publica,
                ms
            );
            crate::autorizacao::auditar_do_kernel(
                METODO,
                &publica,
                Codigo::Allow,
                "nascida: selada no TPM, as duas copias da area gravadas",
            );
        }
        _ => crate::log_info!(
            "identidade",
            "identidade do Duke {}: aberta do selo no TPM em {} ms",
            publica,
            ms
        ),
    }
    if let Some((copia, r)) = reparo {
        let (codigo, detalhe) = match r {
            Ok(()) => (
                Codigo::Allow,
                format!("a copia {copia} da area do selo nao era a aberta: reescrita"),
            ),
            Err(m) => (
                Codigo::Error,
                format!(
                    "a copia {copia} da area do selo nao era a aberta, e nao foi reescrita: {m}"
                ),
            ),
        };
        crate::log_warn!("identidade", "{}", detalhe);
        crate::autorizacao::auditar_do_kernel(METODO, &publica, codigo, &detalhe);
    }
}

/// Nenhuma identidade neste boot: o log, a auditoria, e o motivo, que a
/// persistência e o `system.info` dizem.
fn recusar(motivo: &'static str) {
    identidade::ficar_sem_chave(motivo);
    crate::log_error!(
        "identidade",
        "sem identidade do Duke: {} — a persistencia nao abre, e as portas dos agentes recusam o aperto",
        motivo
    );
    crate::autorizacao::auditar_do_kernel(METODO, "", Codigo::Error, motivo);
}

/// A identidade pelo selo: a área, o journal e o TPM, a decisão, e o que
/// ela manda.
fn pelo_selo() -> Result<Estabelecida, &'static str> {
    let copias = persistencia::ler_a_area_da_identidade()?;
    let journal = persistencia::ha_journal()?;
    let tpm = if crate::tpm::presente() {
        Some(persistencia::indices_do_duke_no_tpm().map_err(|e| e.motivo())?)
    } else {
        None
    };
    match ancora::identidade::decidir(&copias, journal, tpm) {
        Decisao::Recusar(r) => Err(r.motivo()),
        Decisao::Abrir { copia, reparar } => {
            let Leitura::Valida(area) = &copias[copia] else {
                return Err("a decisao abriu uma copia que nao e inteira");
            };
            let chave = abrir(area)?;
            let reparo = reparar.then(|| {
                let outra = 1 - copia;
                (
                    outra,
                    persistencia::gravar_a_area_da_identidade(outra, &area.em_bytes()),
                )
            });
            Ok(Estabelecida {
                chave,
                origem: OrigemDaChave::Selada,
                reparo,
            })
        }
        Decisao::Nascer => Ok(Estabelecida {
            chave: nascer()?,
            origem: OrigemDaChave::Nascida,
            reparo: None,
        }),
    }
}

/// Abre o selo de `area` no TPM da EK dela, e confere a chave aberta com a
/// pública da área.
fn abrir(area: &Area) -> Result<[u8; 32], &'static str> {
    let mut chave = *persistencia::abrir_a_identidade(&area.ek, &area.selado)
        .map_err(|e| match e {
            ancora::Erro::ChaveDoTpmTrocada => {
                "o TPM nao e o do nascimento da identidade: outra chave de endosso"
            }
            ancora::Erro::Codigo(ancora::codigo::INTEGRIDADE) => {
                "o selo da identidade nao abre neste TPM: limpo depois do nascimento, ou o selo foi mexido"
            }
            outro => outro.motivo(),
        })?
        .como_bytes();
    if sigilo::publica_de(&chave) != area.publica {
        chave.zeroize();
        return Err("a chave aberta do selo nao e a publica da area");
    }
    Ok(chave)
}

/// Uma instalação nova: a chave sorteada, selada e aberta de volta — o
/// selo que o disco vai guardar abre esta chave —, e as duas cópias
/// gravadas, cada uma descarregada antes da seguinte. A chave só volta
/// depois da primeira cópia durável.
fn nascer() -> Result<[u8; 32], &'static str> {
    let mut chave =
        crate::aleatorio::chave().map_err(|_| "sem entropia: a identidade nao nasce")?;
    let r = gravar_o_nascimento(&chave);
    if r.is_err() {
        chave.zeroize();
    }
    r.map(|()| chave)
}

fn gravar_o_nascimento(chave: &[u8; 32]) -> Result<(), &'static str> {
    let (ek, selado) = persistencia::selar_a_identidade(chave).map_err(|e| match e {
        ancora::Erro::SeladoEstranho => "o TPM nao selou a identidade como o Duke pede",
        outro => outro.motivo(),
    })?;
    let area = Area {
        ek,
        publica: sigilo::publica_de(chave),
        selado,
    };
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::IdentidadeSelada);
    let bytes = area.em_bytes();
    persistencia::gravar_a_area_da_identidade(0, &bytes).inspect_err(|_| {
        crate::log_error!(
            "identidade",
            "a primeira copia da area do selo nao foi gravada: a identidade nao nasce"
        );
    })?;
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::PrimeiraCopia);
    // A primeira cópia é durável: a identidade existe. Sem a segunda, o
    // boot seguinte abre a primeira e a repara.
    if let Err(m) = persistencia::gravar_a_area_da_identidade(1, &bytes) {
        crate::log_error!(
            "identidade",
            "a segunda copia da area do selo nao foi gravada ({}): o proximo boot a repara",
            m
        );
    }
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::IdentidadeGravada);
    Ok(())
}

/// Só para a suíte: o caminho do selo inteiro — a área, o journal e o TPM,
/// a decisão, a abertura e o reparo, ou o nascimento —, sem adotar a
/// chave: a pública dela, a origem e o reparo.
#[cfg(feature = "modo-teste")]
pub fn pelo_selo_de_teste() -> Result<([u8; 32], OrigemDaChave, Reparo), &'static str> {
    let Estabelecida {
        mut chave,
        origem,
        reparo,
    } = pelo_selo()?;
    let publica = sigilo::publica_de(&chave);
    chave.zeroize();
    Ok((publica, origem, reparo))
}

/// Só para a suíte: o nascimento fora da decisão — a chave sorteada,
/// selada, conferida e gravada nas duas cópias —, sem adotá-la. A pública
/// dela.
#[cfg(feature = "modo-teste")]
pub fn nascer_de_teste() -> Result<[u8; 32], &'static str> {
    let mut chave = nascer()?;
    let publica = sigilo::publica_de(&chave);
    chave.zeroize();
    Ok(publica)
}
