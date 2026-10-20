//! As chaves de assinatura das identidades.
//!
//! # O que é
//!
//! Uma chave Ed25519 de uma **identidade durável** do Duke — `pessoa:<id>`,
//! `agente:<hex>`, `servico:<nome>` —, que o kernel cria com o gerador
//! dele e guarda: a privada nunca sai daqui. Nenhum comando a devolve, nem
//! a recebe: não há exportação nem importação. A chave não é da sessão,
//! nem do processo, nem da credencial: a pessoa que troca a senha continua
//! com as chaves dela, e a sessão que acaba não leva nenhuma. Pessoa e
//! agente seguem o mesmo caminho: o dono é a identidade que
//! [`crate::autorizacao::dono_duravel`] diz, e nada aqui pergunta qual dos
//! dois ela é.
//!
//! # O que o kernel sabe, e o que não sabe
//!
//! Sabe a chave, o dono, o algoritmo, o domínio registrado, o estado, o
//! resumo de 32 bytes e a assinatura. Não sabe para que a assinatura
//! serve: o que o resumo resume, a quem ela vai e que protocolo a pede são
//! do programa. O domínio é um nome do registro de domínios da imagem
//! (`/etc/duke/dominios`, ver `sigilo::chaves`), e quem assina diz o nome,
//! nunca os bytes.
//!
//! # O nome é do dono
//!
//! O recurso que o gate decide é `chave:<nome>`, e o nome se resolve no
//! espaço da identidade de quem pede — sempre. Não há parâmetro de dono:
//! saber o nome da chave de outro não dá nada, e pedir um nome que não é
//! seu responde o mesmo que pedir um que ninguém tem.
//!
//! # Lápide
//!
//! Destruída pelo dono (`key.destroy`), ou anulada — por `key.revoke`, com
//! prova, ou pela revogação do dono —, a chave perde a privada, que é
//! apagada da memória, e o nome fica marcado para sempre: não se cria outra
//! com ele, nem depois de o dono ser registrado de novo. A pública fica,
//! para a história e para a auditoria.
//!
//! # A assinatura
//!
//! Uma decisão do gate por assinatura; e no ponto de commit, com a ordem
//! das gravações na mão, tudo de novo: a autoridade e a contenção
//! (`autorizacao::reconfirmar`), a chave viva, o domínio dela e o papel que
//! o usa. Depois, o registro da execução vai para a auditoria e para o
//! journal — e só então a assinatura é feita e sai. Uma revogação, uma
//! destruição ou uma política nova gravam com a mesma ordem: ou a
//! assinatura as vê e é recusada, ou elas vêm depois dela inteira.
//!
//! # Etapa A: em memória
//!
//! As chaves desta etapa vivem só na memória do kernel e não sobrevivem ao
//! boot: um boot novo começa sem chave nenhuma, e sem lápide nenhuma.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use politica::Codigo;
use sigilo::chaves::{Dominio, Dominios, Privada, TAM_PUBLICA};

use crate::trava::Mutex;

/// Onde está o registro de domínios.
pub const CAMINHO_DOS_DOMINIOS: &str = "/etc/duke/dominios";

/// O algoritmo de toda chave desta etapa.
pub const ALGORITMO: &str = "ed25519";

/// Quantas chaves vivas uma identidade tem, no máximo.
pub const MAIS_VIVAS_POR_DONO: usize = 8;

/// Quantas chaves vivas a tabela tem, somando os donos.
pub const MAIS_VIVAS: usize = 64;

/// Quantas entradas a tabela tem, vivas e lápides. A lápide não sai: com a
/// tabela cheia, nenhuma chave se cria — o nome de uma lápide esquecida
/// poderia voltar.
pub const MAIS_CHAVES: usize = 1024;

/// O estado de uma chave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Assina.
    Ativa,
    /// Destruída pelo dono: a privada foi apagada, e o nome não volta.
    Destruida,
    /// Anulada por um administrador, ou pela revogação do dono: a privada
    /// foi apagada, e o nome não volta.
    Anulada,
}

impl Estado {
    /// O nome, como as respostas e a auditoria o escrevem.
    pub const fn como_str(self) -> &'static str {
        match self {
            Estado::Ativa => "active",
            Estado::Destruida => "destroyed",
            Estado::Anulada => "annulled",
        }
    }
}

/// Onde a privada mora.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Custodia {
    /// Na memória do kernel.
    Kernel,
    /// No TPM. Nenhuma chave desta etapa é criada assim: o campo existe
    /// para a custódia não ser presumida.
    #[allow(dead_code)]
    Tpm,
}

impl Custodia {
    pub const fn como_str(self) -> &'static str {
        match self {
            Custodia::Kernel => "kernel",
            Custodia::Tpm => "tpm",
        }
    }
}

/// Uma chave na tabela.
struct Chave {
    dono: String,
    nome: String,
    dominio: String,
    custodia: Custodia,
    publica: [u8; TAM_PUBLICA],
    /// A privada, enquanto a chave vive. Num `Arc` para quem assina a usar
    /// fora da trava da tabela — e só com a ordem das gravações na mão,
    /// que a destruição e a anulação também tomam: ninguém a apaga no meio
    /// de uma assinatura, e ela é apagada quando a última referência sai.
    privada: Option<Arc<Privada>>,
    estado: Estado,
    criada_ms: u64,
}

/// O que se diz de uma chave: tudo, menos a privada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vista {
    pub nome: String,
    pub dominio: String,
    pub custodia: Custodia,
    pub estado: Estado,
    pub publica: [u8; TAM_PUBLICA],
    pub criada_ms: u64,
}

impl Vista {
    /// A impressão da pública, em hexadecimal: o que a auditoria grava.
    pub fn impressao(&self) -> String {
        sigilo::hex_de(&sigilo::chaves::impressao(&self.publica))
    }
}

impl Chave {
    fn vista(&self) -> Vista {
        Vista {
            nome: self.nome.clone(),
            dominio: self.dominio.clone(),
            custodia: self.custodia,
            estado: self.estado,
            publica: self.publica,
            criada_ms: self.criada_ms,
        }
    }
}

/// Por que uma operação de chave não aconteceu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O domínio não está no registro de domínios.
    DominioDesconhecido,
    /// O papel de quem pede não usa o domínio.
    DominioNaoUsado,
    /// A chave é de outro domínio.
    OutroDominio,
    /// A chave já existe, viva.
    JaExiste,
    /// O nome é de uma lápide: não volta.
    NomeDeLapide,
    /// Não há chave com esse nome para esse dono.
    Inexistente,
    /// A chave foi destruída ou anulada.
    Morta(Estado),
    /// O limite de chaves vivas — do dono ou da tabela —, ou a tabela
    /// cheia de lápides.
    Limite,
    /// Sem fonte de entropia: nenhuma chave nasce de semente fraca.
    SemEntropia,
    /// Quem pede não é uma identidade.
    SemDono,
}

impl Falha {
    /// O código da resposta e da auditoria.
    pub const fn codigo(self) -> Codigo {
        match self {
            Falha::DominioNaoUsado => Codigo::DenyPolicy,
            Falha::JaExiste => Codigo::Conflict,
            Falha::Limite => Codigo::DenyQuota,
            Falha::SemEntropia | Falha::SemDono => Codigo::Error,
            Falha::DominioDesconhecido
            | Falha::OutroDominio
            | Falha::NomeDeLapide
            | Falha::Inexistente
            | Falha::Morta(_) => Codigo::InvalidArgument,
        }
    }

    /// Uma frase, para a resposta e para a auditoria. A de uma chave que não
    /// existe é a mesma para todo nome: não diz se outro dono tem um igual.
    pub const fn motivo(self) -> &'static str {
        match self {
            Falha::DominioDesconhecido => "dominio fora do registro de dominios",
            Falha::DominioNaoUsado => "o papel nao usa o dominio",
            Falha::OutroDominio => "a chave e de outro dominio",
            Falha::JaExiste => "a chave ja existe",
            Falha::NomeDeLapide => "o nome foi de uma chave destruida ou anulada, e nao volta",
            Falha::Inexistente => "nao ha chave com esse nome para quem pede",
            Falha::Morta(Estado::Anulada) => "a chave foi anulada",
            Falha::Morta(_) => "a chave foi destruida",
            Falha::Limite => "o limite de chaves foi atingido",
            Falha::SemEntropia => "sem fonte de entropia: nenhuma chave nasce",
            Falha::SemDono => "quem pede nao e uma identidade",
        }
    }
}

struct Chaves {
    tabela: Vec<Chave>,
    /// O registro de domínios da imagem: todo, ou nenhum.
    dominios: Option<Dominios>,
}

static CHAVES: Mutex<Chaves> = Mutex::new(Chaves {
    tabela: Vec::new(),
    dominios: None,
});

fn com<R>(f: impl FnOnce(&mut Chaves) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut CHAVES.lock()))
}

/// Lê o registro de domínios do disco. No boot, depois da raiz montada.
pub fn carregar() {
    let dominios = ler_dominios();
    com(|c| c.dominios = dominios);
}

/// O registro de domínios da imagem. Como o das fontes de hora, uma linha
/// errada recusa o registro inteiro: um domínio é a forma do que uma chave
/// assina, e um registro meio lido seria uma assinatura que ninguém
/// escreveu. Ausente ou recusado: nenhum domínio, e nenhuma assinatura.
fn ler_dominios() -> Option<Dominios> {
    let Ok(bytes) = crate::vfs::ler_tudo(CAMINHO_DOS_DOMINIOS) else {
        crate::log_info!(
            "chaves",
            "{} nao existe: nenhum dominio, nenhuma assinatura",
            CAMINHO_DOS_DOMINIOS
        );
        return None;
    };
    let Ok(texto) = core::str::from_utf8(&bytes) else {
        crate::log_error!(
            "chaves",
            "{} nao e texto: nenhum dominio",
            CAMINHO_DOS_DOMINIOS
        );
        return None;
    };
    match Dominios::ler(texto) {
        Ok(d) => {
            crate::log_info!("chaves", "{} dominios de assinatura", d.todos().len());
            Some(d)
        }
        Err(e) => {
            crate::log_error!(
                "chaves",
                "{}: {}; registro recusado inteiro, nenhum dominio",
                CAMINHO_DOS_DOMINIOS,
                e
            );
            None
        }
    }
}

/// O domínio registrado com este nome.
pub fn dominio(nome: &str) -> Option<Dominio> {
    com(|c| c.dominios.as_ref().and_then(|d| d.dominio(nome)).cloned())
}

/// O nome está livre para `dono`, e cabe uma chave viva a mais — dele e da
/// tabela.
fn conferir_o_nome(c: &Chaves, dono: &str, nome: &str) -> Result<(), Falha> {
    if let Some(k) = c.tabela.iter().find(|k| k.dono == dono && k.nome == nome) {
        return Err(if k.estado == Estado::Ativa {
            Falha::JaExiste
        } else {
            Falha::NomeDeLapide
        });
    }
    let vivas = c.tabela.iter().filter(|k| k.estado == Estado::Ativa);
    let do_dono = vivas.clone().filter(|k| k.dono == dono).count();
    if c.tabela.len() >= MAIS_CHAVES
        || vivas.count() >= MAIS_VIVAS
        || do_dono >= MAIS_VIVAS_POR_DONO
    {
        return Err(Falha::Limite);
    }
    Ok(())
}

/// Cria uma chave de `dono`, com o nome `nome`, no domínio registrado
/// `dominio`. Se o papel de quem pede usa o domínio, quem chama já
/// perguntou; o registro, esta confere.
pub fn criar(dono: &str, nome: &str, dominio: &str) -> Result<Vista, Falha> {
    let registrado = com(|c| {
        c.dominios
            .as_ref()
            .is_some_and(|d| d.dominio(dominio).is_some())
    });
    if !registrado {
        return Err(Falha::DominioDesconhecido);
    }
    // Antes de gastar o gerador; e de novo junto com a inserção, que é o
    // que vale.
    com(|c| conferir_o_nome(c, dono, nome))?;
    let mut semente = crate::aleatorio::chave().map_err(|_| Falha::SemEntropia)?;
    let privada = Arc::new(Privada::de_semente(semente));
    sigilo::zeroize::Zeroize::zeroize(&mut semente);
    let publica = privada.publica();
    let criada_ms = crate::persistencia::agora_ms();
    com(|c| {
        conferir_o_nome(c, dono, nome)?;
        let chave = Chave {
            dono: String::from(dono),
            nome: String::from(nome),
            dominio: String::from(dominio),
            custodia: Custodia::Kernel,
            publica,
            privada: Some(privada),
            estado: Estado::Ativa,
            criada_ms,
        };
        let vista = chave.vista();
        c.tabela.push(chave);
        Ok(vista)
    })
}

/// O que é público da chave `nome` de `dono` — viva ou lápide.
pub fn ler(dono: &str, nome: &str) -> Result<Vista, Falha> {
    com(|c| {
        c.tabela
            .iter()
            .find(|k| k.dono == dono && k.nome == nome)
            .map(Chave::vista)
            .ok_or(Falha::Inexistente)
    })
}

/// O que uma assinatura precisa, conferido agora: a chave viva `nome` de
/// `dono`, cujo domínio é `dominio`, com o domínio no registro.
///
/// A privada sai daqui só como a referência que quem assina usa e larga —
/// e só quem tem a ordem das gravações a pede: a destruição e a anulação
/// também a tomam, e não apagam a chave no meio da assinatura.
pub fn para_assinar(
    dono: &str,
    nome: &str,
    dominio: &str,
) -> Result<(Arc<Privada>, Vista, Dominio), Falha> {
    com(|c| {
        let k = c
            .tabela
            .iter()
            .find(|k| k.dono == dono && k.nome == nome)
            .ok_or(Falha::Inexistente)?;
        if k.estado != Estado::Ativa {
            return Err(Falha::Morta(k.estado));
        }
        if k.dominio != dominio {
            return Err(Falha::OutroDominio);
        }
        let d = c
            .dominios
            .as_ref()
            .and_then(|d| d.dominio(dominio))
            .cloned()
            .ok_or(Falha::DominioDesconhecido)?;
        let privada = k.privada.clone().ok_or(Falha::Morta(k.estado))?;
        Ok((privada, k.vista(), d))
    })
}

/// Mata a chave `nome` de `dono`: o estado passa a `como`, e a privada sai
/// da tabela — e é apagada aqui, fora da trava, quando a última referência
/// a ela sai.
fn matar(dono: &str, nome: &str, como: Estado) -> Result<Vista, Falha> {
    let (privada, vista) = com(|c| {
        let k = c
            .tabela
            .iter_mut()
            .find(|k| k.dono == dono && k.nome == nome)
            .ok_or(Falha::Inexistente)?;
        if k.estado != Estado::Ativa {
            return Err(Falha::Morta(k.estado));
        }
        k.estado = como;
        Ok((k.privada.take(), k.vista()))
    })?;
    drop(privada);
    Ok(vista)
}

/// Destrói a chave `nome` de `dono`, a pedido dele.
pub fn destruir(dono: &str, nome: &str) -> Result<Vista, Falha> {
    matar(dono, nome, Estado::Destruida)
}

/// Anula a chave `nome` de `dono`: a operação administrativa, com prova.
pub fn anular(dono: &str, nome: &str) -> Result<Vista, Falha> {
    matar(dono, nome, Estado::Anulada)
}

/// A identidade `dono` foi revogada: as chaves vivas dela são anuladas,
/// com a lápide, e cada uma vai para a auditoria — em nome do kernel, que
/// é quem anula. Uma identidade registrada de novo com a mesma chave não
/// as recupera, e não cria outras com os mesmos nomes.
pub fn identidade_revogada(dono: &str) {
    crate::persistencia::em_ordem(|| {
        let (privadas, vistas): (Vec<_>, Vec<_>) = com(|c| {
            c.tabela
                .iter_mut()
                .filter(|k| k.dono == dono && k.estado == Estado::Ativa)
                .map(|k| {
                    k.estado = Estado::Anulada;
                    (k.privada.take(), k.vista())
                })
                .unzip()
        });
        drop(privadas);
        for v in vistas {
            crate::autorizacao::auditar_do_kernel(
                "key.annul",
                &alloc::format!("{dono} {}{}", politica::arquivo::PREFIXO_DE_CHAVE, v.nome),
                Codigo::Allow,
                &alloc::format!("anulada {ALGORITMO} {}: o dono foi revogado", v.impressao()),
            );
        }
    });
}

/// Só para a suíte: quantas chaves a tabela tem — as vivas, e todas.
#[cfg(feature = "modo-teste")]
pub fn contagem_de_teste() -> (usize, usize) {
    com(|c| {
        (
            c.tabela
                .iter()
                .filter(|k| k.estado == Estado::Ativa)
                .count(),
            c.tabela.len(),
        )
    })
}

/// Só para a suíte: a tabela vazia, como num boot novo — o registro de
/// domínios fica.
#[cfg(feature = "modo-teste")]
pub fn esquecer_de_teste() {
    let tabela = com(|c| core::mem::take(&mut c.tabela));
    drop(tabela);
}

/// Só para a suíte: troca o registro de domínios, e devolve o de antes.
#[cfg(feature = "modo-teste")]
pub fn trocar_dominios_de_teste(dominios: Option<Dominios>) -> Option<Dominios> {
    com(|c| core::mem::replace(&mut c.dominios, dominios))
}

/// Destrava a tabela, no caminho fatal.
///
/// # Safety
///
/// Só no caminho fatal, com os outros núcleos parados.
pub unsafe fn destravar() {
    unsafe {
        CHAVES.force_unlock();
    }
}
